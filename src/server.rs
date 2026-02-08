//! SMB2 server: connection handling, state management, and command dispatch.
//!
//! Each TCP connection runs as an independent async task. State includes
//! the negotiated dialect, authenticated sessions, tree connects (mounted
//! shares), and open file handles.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use bytes::BytesMut;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::smb2::header::{Smb2Header, SMB2_HEADER_SIZE};
use crate::smb2::status::NtStatus;
use crate::smb2::{self, Smb2Command};
use crate::transport;
use crate::auth::{self, AuthState, UserCredential};
use crate::vfs;
use crate::error::{self, ServerError, build_error_response_body};

// ---- Public types ----

/// Shared, immutable server state (one per server process).
pub struct ServerState {
    pub config: Config,
    pub server_guid: [u8; 16],
}

impl ServerState {
    pub fn new(config: Config) -> Self {
        let mut guid = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut guid);
        ServerState { config, server_guid: guid }
    }
}

// ---- Per-connection state ----

/// Phase of the connection lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnPhase {
    /// Waiting for the initial Negotiate request.
    #[allow(dead_code)] // Set as initial state, checked implicitly via transitions
    AwaitNegotiate,
    Negotiated,
    Active,
}

/// Per-connection mutable state, owned by the connection task.
struct ConnectionState {
    phase: ConnPhase,
    dialect: u16,
    sessions: HashMap<u64, SessionState>,
    next_session_id: u64,
}

struct SessionState {
    username: String,
    /// Session key from authentication; retained for future signing support.
    #[allow(dead_code)]
    session_key: Vec<u8>,
    auth_state: AuthState,
    trees: HashMap<u32, TreeState>,
    next_tree_id: u32,
}

struct TreeState {
    /// Human-readable share name; retained for diagnostics/logging.
    #[allow(dead_code)]
    share_name: String,
    share_path: PathBuf,
    open_files: HashMap<u64, OpenFile>,
    next_file_id: u64,
}

struct OpenFile {
    handle: Option<tokio::fs::File>,
    path: PathBuf,
    is_directory: bool,
    dir_enumerated: bool,
}

impl ConnectionState {
    fn new() -> Self {
        ConnectionState {
            phase: ConnPhase::AwaitNegotiate,
            dialect: 0,
            sessions: HashMap::new(),
            next_session_id: 1,
        }
    }
}

// ---- Connection entrypoint ----

/// Handle a single SMB2 client connection.
///
/// Reads frames in a loop, dispatches each to the appropriate handler,
/// and writes the response. Exits on connection close or fatal error.
pub async fn handle_connection(
    mut stream: TcpStream,
    server: Arc<ServerState>,
) -> Result<(), ServerError> {
    let mut conn = ConnectionState::new();

    loop {
        // Read next NetBIOS-framed SMB2 message
        let frame = match transport::read_frame(&mut stream).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("Client disconnected");
                return Ok(());
            }
            Err(e) => {
                return Err(ServerError::Io(e));
            }
        };

        if frame.len() < SMB2_HEADER_SIZE {
            warn!("Frame too small ({} bytes), dropping", frame.len());
            return Ok(());
        }

        // Handle SMB1 multi-protocol negotiate by responding with
        // an SMB2 negotiate response (dialect 0x02FF) that tells the
        // client to retry using SMB2.  macOS sends SMB1 negotiate first.
        if frame.len() >= 4 && frame[0] == 0xFF && &frame[1..4] == b"SMB" {
            info!("SMB1 negotiate received, responding with SMB2 wildcard dialect");
            let smb2_resp = build_smb1_to_smb2_negotiate_response(&server);
            transport::write_frame(&mut stream, &smb2_resp).await?;
            continue;
        }

        let header = match Smb2Header::parse(&frame) {
            Some(h) => h,
            None => {
                warn!("Invalid SMB2 header");
                return Ok(());
            }
        };

        // Handle compound (chained) requests: walk the frame using next_command
        // offsets, dispatch each, and send all responses in a single compound frame.
        let mut messages: Vec<(Smb2Header, &[u8])> = Vec::new();
        let mut offset = 0usize;
        loop {
            if offset + SMB2_HEADER_SIZE > frame.len() {
                break;
            }
            let msg_slice = &frame[offset..];
            let hdr = match Smb2Header::parse(msg_slice) {
                Some(h) => h,
                None => break,
            };
            let next = hdr.next_command;
            let msg_end = if next > 0 {
                (next as usize).min(msg_slice.len())
            } else {
                msg_slice.len()
            };
            let body = if SMB2_HEADER_SIZE < msg_end {
                &msg_slice[SMB2_HEADER_SIZE..msg_end]
            } else {
                &[]
            };
            messages.push((hdr, body));
            if next == 0 {
                break;
            }
            offset += next as usize;
        }

        // If we couldn't parse any messages, fall back to the single header we parsed above
        if messages.is_empty() {
            let body = &frame[SMB2_HEADER_SIZE..];
            messages.push((header, body));
        }

        let msg_count = messages.len();
        let mut resp_buf = BytesMut::with_capacity(256 * msg_count);

        // For related compound requests, carry session_id/tree_id/file_id forward
        let mut last_session_id: u64 = 0;
        let mut last_tree_id: u32 = 0;
        let mut compound_file_id: Option<u64> = None;

        for (i, (mut msg_header, body)) in messages.into_iter().enumerate() {
            // SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004
            let is_related = (msg_header.flags & 0x0000_0004) != 0;
            if is_related {
                if msg_header.session_id == 0 {
                    msg_header.session_id = last_session_id;
                }
                if msg_header.tree_id == 0 {
                    msg_header.tree_id = last_tree_id;
                }
            }

            // For related compound operations, replace sentinel file_id
            // (0xFFFFFFFF_FFFFFFFF) with the file_id from the preceding Create.
            let body_owned;
            let dispatch_body: &[u8] = if is_related {
                if let Some(fid) = compound_file_id {
                    let sentinel = 0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes();
                    let replacement = fid.to_le_bytes();
                    let mut patched = body.to_vec();
                    // Replace all occurrences of the 8-byte sentinel in the body
                    for pos in 0..patched.len().saturating_sub(7) {
                        if patched[pos..pos + 8] == sentinel {
                            patched[pos..pos + 8].copy_from_slice(&replacement);
                        }
                    }
                    body_owned = patched;
                    &body_owned
                } else {
                    body
                }
            } else {
                body
            };

            debug!(
                command = ?Smb2Command::from_u16(msg_header.command),
                message_id = msg_header.message_id,
                session_id = msg_header.session_id,
                tree_id = msg_header.tree_id,
                compound_index = i,
                compound_total = msg_count,
                "Received request"
            );

            let (resp_header, resp_body) =
                dispatch(&mut conn, &server, &msg_header, dispatch_body).await;

            last_session_id = resp_header.session_id;
            last_tree_id = resp_header.tree_id;

            // If this was a successful Create, extract the file_id for subsequent
            // related operations (QueryInfo, Close, etc.)
            if msg_header.command == Smb2Command::Create as u16
                && resp_header.status == NtStatus::Success
                && resp_body.len() >= 80
            {
                // CreateResponse: file_id_persistent at offset 64, file_id_volatile at offset 72
                let fid = u64::from_le_bytes(
                    resp_body[72..80].try_into().unwrap_or([0u8; 8]),
                );
                compound_file_id = Some(fid);
            }

            last_session_id = resp_header.session_id;
            last_tree_id = resp_header.tree_id;

            let resp_msg_len = SMB2_HEADER_SIZE + resp_body.len();
            // Pad to 8-byte alignment for all but the last response in a compound
            let padded_len = if i + 1 < msg_count {
                (resp_msg_len + 7) & !7
            } else {
                resp_msg_len
            };

            let start = resp_buf.len();
            // Write header, we'll fix next_command after
            let mut rh = resp_header;
            rh.next_command = if i + 1 < msg_count { padded_len as u32 } else { 0 };
            rh.serialize(&mut resp_buf);
            resp_buf.extend_from_slice(&resp_body);
            // Pad if needed
            let padding = padded_len - resp_msg_len;
            if padding > 0 {
                resp_buf.extend_from_slice(&vec![0u8; padding]);
            }
        }

        transport::write_frame(&mut stream, &resp_buf).await?;
    }
}

// ---- Dispatch ----

async fn dispatch(
    conn: &mut ConnectionState,
    server: &Arc<ServerState>,
    header: &Smb2Header,
    body: &[u8],
) -> (Smb2Header, Vec<u8>) {
    let result = match Smb2Command::from_u16(header.command) {
        Some(Smb2Command::Negotiate) =>
            handle_negotiate(conn, server, header, body).await,
        Some(Smb2Command::SessionSetup) =>
            handle_session_setup(conn, server, header, body).await,
        Some(Smb2Command::Logoff) =>
            handle_logoff(conn, header).await,
        Some(Smb2Command::TreeConnect) =>
            handle_tree_connect(conn, server, header, body).await,
        Some(Smb2Command::TreeDisconnect) =>
            handle_tree_disconnect(conn, header).await,
        Some(Smb2Command::Create) =>
            handle_create(conn, header, body).await,
        Some(Smb2Command::Close) =>
            handle_close(conn, header, body).await,
        Some(Smb2Command::Flush) =>
            handle_flush(conn, header, body).await,
        Some(Smb2Command::Read) =>
            handle_read(conn, header, body).await,
        Some(Smb2Command::Write) =>
            handle_write(conn, header, body).await,
        Some(Smb2Command::QueryDirectory) =>
            handle_query_directory(conn, header, body).await,
        Some(Smb2Command::QueryInfo) =>
            handle_query_info(conn, header, body).await,
        Some(Smb2Command::SetInfo) =>
            handle_set_info(conn, header, body).await,
        Some(Smb2Command::Echo) =>
            handle_echo(header).await,
        Some(Smb2Command::Cancel) =>
            Ok((Smb2Header::new_response(header, NtStatus::Success), vec![])),
        Some(Smb2Command::ChangeNotify) | Some(Smb2Command::Lock)
        | Some(Smb2Command::Ioctl) =>
            Ok((
                Smb2Header::new_response(header, NtStatus::NotSupported),
                build_error_response_body(),
            )),
        None => Ok((
            Smb2Header::new_response(header, NtStatus::InvalidParameter),
            build_error_response_body(),
        )),
    };

    match result {
        Ok(pair) => pair,
        Err(status) => (
            Smb2Header::new_response(header, status),
            build_error_response_body(),
        ),
    }
}

// ---- Helpers ----

type HandlerResult = Result<(Smb2Header, Vec<u8>), NtStatus>;

fn get_tree<'a>(
    conn: &'a mut ConnectionState,
    session_id: u64,
    tree_id: u32,
) -> Result<&'a mut TreeState, NtStatus> {
    let session = conn
        .sessions
        .get_mut(&session_id)
        .ok_or(NtStatus::Other(0xC000_0203))?; // STATUS_USER_SESSION_DELETED
    let tree = session
        .trees
        .get_mut(&tree_id)
        .ok_or(NtStatus::Other(0xC000_00C9))?; // STATUS_NETWORK_NAME_DELETED
    Ok(tree)
}

fn serialize_body<F>(header: &Smb2Header, status: NtStatus, f: F) -> HandlerResult
where
    F: FnOnce(&mut BytesMut),
{
    let mut buf = BytesMut::with_capacity(256);
    f(&mut buf);
    Ok((Smb2Header::new_response(header, status), buf.to_vec()))
}

/// Build an SMB2 Negotiate response to an SMB1 multi-protocol negotiate.
///
/// When a client (e.g. macOS) sends an SMB1 negotiate listing SMB2/3 dialects,
/// we respond with a full SMB2 Negotiate response using dialect 0x02FF
/// ("SMB 2.???"), which tells the client to restart negotiation using SMB2.
fn build_smb1_to_smb2_negotiate_response(server: &Arc<ServerState>) -> Vec<u8> {
    use bytes::BufMut;

    let security_buffer = auth::build_spnego_init();

    // Build the SMB2 Negotiate response body
    let resp = smb2::negotiate::NegotiateResponse {
        security_mode: 0x01,
        dialect: 0x02FF,  // SMB 2.??? wildcard — client must re-negotiate
        server_guid: server.server_guid,
        capabilities: 0,
        max_transact_size: 1_048_576,
        max_read_size: 1_048_576,
        max_write_size: 1_048_576,
        security_buffer,
    };

    // Build a minimal SMB2 header for the negotiate response
    let mut hdr = Smb2Header::new_response(
        &Smb2Header {
            credit_charge: 0,
            status: NtStatus::Success,
            command: 0, // NEGOTIATE
            credits_requested: 1,
            flags: 0,
            next_command: 0,
            message_id: 0,
            async_id: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0u8; 16],
        },
        NtStatus::Success,
    );
    hdr.credits_requested = 1;

    let mut out = BytesMut::with_capacity(256);
    hdr.serialize(&mut out);
    resp.serialize(&mut out);
    out.to_vec()
}

// ---- Command handlers ----

async fn handle_negotiate(
    conn: &mut ConnectionState,
    server: &Arc<ServerState>,
    header: &Smb2Header,
    body: &[u8],
) -> HandlerResult {
    let req = smb2::negotiate::NegotiateRequest::parse(body)
        .ok_or(NtStatus::InvalidParameter)?;

    // Pick highest supported dialect.  We genuinely implement SMB 2.x semantics,
    // but many modern clients (macOS, Windows 10+) only offer SMB 3.x dialects.
    // We accept SMB 3.0/3.0.2 and negotiate them – the wire format is compatible
    // enough for our basic feature set (no encryption, no secure negotiate, no
    // multi-channel).  SMB 3.1.1 requires negotiate contexts we don't implement,
    // so we avoid it.
    let dialect = if req.dialects.contains(&0x0302) {
        0x0302 // SMB 3.0.2
    } else if req.dialects.contains(&0x0300) {
        0x0300 // SMB 3.0
    } else if req.dialects.contains(&0x0210) {
        0x0210 // SMB 2.1
    } else if req.dialects.contains(&0x0202) {
        0x0202 // SMB 2.0.2
    } else {
        return Err(NtStatus::NotSupported);
    };

    conn.dialect = dialect;
    conn.phase = ConnPhase::Negotiated;

    let security_buffer = auth::build_spnego_init();

    let resp = smb2::negotiate::NegotiateResponse {
        security_mode: 0x01,
        dialect,
        server_guid: server.server_guid,
        capabilities: 0,
        max_transact_size: 1_048_576,
        max_read_size: 1_048_576,
        max_write_size: 1_048_576,
        security_buffer,
    };

    let resp_header = Smb2Header::new_response(header, NtStatus::Success);
    let mut buf = BytesMut::with_capacity(128);
    resp.serialize(&mut buf);
    info!(dialect = format!("0x{:04x}", dialect), "Negotiated");
    Ok((resp_header, buf.to_vec()))
}

async fn handle_session_setup(
    conn: &mut ConnectionState,
    server: &Arc<ServerState>,
    header: &Smb2Header,
    body: &[u8],
) -> HandlerResult {
    let req = smb2::session::SessionSetupRequest::parse(body)
        .ok_or(NtStatus::InvalidParameter)?;

    debug!(security_buffer_len = req.security_buffer.len(),
           session_id = header.session_id,
           "SessionSetup request received");

    // Find or create session
    let session_id = if header.session_id == 0 {
        let id = conn.next_session_id;
        conn.next_session_id += 1;
        conn.sessions.insert(id, SessionState {
            username: String::new(),
            session_key: vec![],
            auth_state: AuthState::Initial,
            trees: HashMap::new(),
            next_tree_id: 1,
        });
        id
    } else {
        header.session_id
    };

    // Build user credentials list from config
    let users: Vec<UserCredential> = server.config.users.iter().map(|u| {
        UserCredential {
            username: u.username.clone(),
            password: u.password.clone(),
        }
    }).collect();

    let guest_ok = server.config.shares.iter().any(|s| s.guest_ok);

    // Scope the mutable borrow of session so we can assign conn.phase afterwards
    let (resp_token, complete, authenticated_info) = {
        let session = conn.sessions.get_mut(&session_id)
            .ok_or(NtStatus::InvalidParameter)?;

        let (resp_token, complete) = auth::process_auth(
            &mut session.auth_state,
            &req.security_buffer,
            &users,
            guest_ok,
        )?;

        let authenticated_info = if complete {
            if let AuthState::Authenticated { ref username, ref session_key } = session.auth_state {
                session.username = username.clone();
                session.session_key = session_key.clone();
                Some(username.clone())
            } else {
                None
            }
        } else {
            None
        };

        (resp_token, complete, authenticated_info)
    };

    if let Some(ref username) = authenticated_info {
        conn.phase = ConnPhase::Active;
        info!(user = %username, session_id, "Session established");
    }

    let status = if complete {
        NtStatus::Success
    } else {
        NtStatus::MoreProcessingRequired
    };

    let mut resp_header = Smb2Header::new_response(header, status);
    resp_header.session_id = session_id;

    // Flag guest sessions so the client knows not to expect signing
    let session_flags = if complete && guest_ok {
        0x0001 // SMB2_SESSION_FLAG_IS_GUEST
    } else {
        0
    };

    let resp = smb2::session::SessionSetupResponse {
        session_flags,
        security_buffer: resp_token,
    };

    let mut buf = BytesMut::with_capacity(64);
    resp.serialize(&mut buf);
    Ok((resp_header, buf.to_vec()))
}

async fn handle_logoff(
    conn: &mut ConnectionState,
    header: &Smb2Header,
) -> HandlerResult {
    info!(session_id = header.session_id, "Logoff");
    conn.sessions.remove(&header.session_id);
    serialize_body(header, NtStatus::Success, |buf| {
        smb2::session::LogoffResponse.serialize(buf);
    })
}

async fn handle_tree_connect(
    conn: &mut ConnectionState,
    server: &Arc<ServerState>,
    header: &Smb2Header,
    body: &[u8],
) -> HandlerResult {
    let req = smb2::tree::TreeConnectRequest::parse(body)
        .ok_or(NtStatus::InvalidParameter)?;

    // Extract share name from \\server\share path
    let share_name = req.path
        .trim_end_matches('\0')
        .rsplit('\\')
        .next()
        .unwrap_or(&req.path)
        .to_string();

    debug!(path = %req.path, share_name = %share_name, "TreeConnect path parsed");

    // Handle IPC$ as a virtual named-pipe share (some clients probe for it)
    if share_name.eq_ignore_ascii_case("IPC$") {
        let session = conn.sessions.get_mut(&header.session_id)
            .ok_or(NtStatus::AccessDenied)?;
        let tree_id = session.next_tree_id;
        session.next_tree_id += 1;
        session.trees.insert(tree_id, TreeState {
            share_name: "IPC$".to_string(),
            share_path: PathBuf::new(),
            open_files: HashMap::new(),
            next_file_id: 1,
        });
        info!(share = "IPC$", tree_id, "Tree connected (IPC)");
        let mut resp_header = Smb2Header::new_response(header, NtStatus::Success);
        resp_header.tree_id = tree_id;
        let resp = smb2::tree::TreeConnectResponse {
            share_type: smb2::tree::SHARE_TYPE_PIPE,
            share_flags: 0,
            capabilities: 0,
            maximal_access: 0x001F_01FF,
        };
        let mut buf = BytesMut::with_capacity(16);
        resp.serialize(&mut buf);
        return Ok((resp_header, buf.to_vec()));
    }

    let share = server.config.shares.iter()
        .find(|s| s.name.eq_ignore_ascii_case(&share_name))
        .ok_or_else(|| {
            warn!(share_name = %share_name, available = ?server.config.shares.iter().map(|s| &s.name).collect::<Vec<_>>(), "Share not found");
            NtStatus::BadNetworkName
        })?;

    let session = conn.sessions.get_mut(&header.session_id)
        .ok_or(NtStatus::AccessDenied)?;

    let tree_id = session.next_tree_id;
    session.next_tree_id += 1;
    session.trees.insert(tree_id, TreeState {
        share_name: share.name.clone(),
        share_path: share.path.clone(),
        open_files: HashMap::new(),
        next_file_id: 1,
    });

    info!(share = %share_name, tree_id, "Tree connected");

    let mut resp_header = Smb2Header::new_response(header, NtStatus::Success);
    resp_header.tree_id = tree_id;

    let resp = smb2::tree::TreeConnectResponse {
        share_type: smb2::tree::SHARE_TYPE_DISK,
        share_flags: 0,
        capabilities: 0,
        maximal_access: 0x001F_01FF, // FILE_ALL_ACCESS
    };

    let mut buf = BytesMut::with_capacity(16);
    resp.serialize(&mut buf);
    Ok((resp_header, buf.to_vec()))
}

async fn handle_tree_disconnect(
    conn: &mut ConnectionState,
    header: &Smb2Header,
) -> HandlerResult {
    if let Some(session) = conn.sessions.get_mut(&header.session_id) {
        session.trees.remove(&header.tree_id);
    }
    serialize_body(header, NtStatus::Success, |buf| {
        smb2::tree::TreeDisconnectResponse.serialize(buf);
    })
}

async fn handle_create(
    conn: &mut ConnectionState,
    header: &Smb2Header,
    body: &[u8],
) -> HandlerResult {
    let req = smb2::create::CreateRequest::parse(body)
        .ok_or(NtStatus::InvalidParameter)?;

    let tree = get_tree(conn, header.session_id, header.tree_id)?;

    let full_path = vfs::safe_resolve(&tree.share_path, &req.filename)
        .ok_or(NtStatus::ObjectPathNotFound)?;

    let is_dir = req.is_directory_request()
        || (full_path.exists() && full_path.is_dir())
        || req.filename.is_empty(); // root of share

    let (handle, created) = vfs::open_file(&full_path, req.create_disposition, is_dir)
        .await
        .map_err(|e| error::io_to_ntstatus(&e))?;

    let info = vfs::stat(&full_path).await.map_err(|e| error::io_to_ntstatus(&e))?;

    let file_id = tree.next_file_id;
    tree.next_file_id += 1;

    tree.open_files.insert(file_id, OpenFile {
        handle: Some(handle),
        path: full_path,
        is_directory: info.is_directory,
        dir_enumerated: false,
    });

    let create_action = if created {
        smb2::create::FILE_CREATED
    } else {
        smb2::create::FILE_OPENED
    };

    debug!(file_id, path = %req.filename, action = create_action, "File opened");

    let resp = smb2::create::CreateResponse {
        oplock_level: 0,
        create_action,
        creation_time: info.creation_time,
        last_access_time: info.last_access_time,
        last_write_time: info.last_write_time,
        change_time: info.change_time,
        allocation_size: info.allocation_size,
        end_of_file: info.end_of_file,
        file_attributes: info.file_attributes,
        file_id_persistent: file_id,
        file_id_volatile: file_id,
    };

    let mut buf = BytesMut::with_capacity(96);
    resp.serialize(&mut buf);
    Ok((Smb2Header::new_response(header, NtStatus::Success), buf.to_vec()))
}

async fn handle_close(
    conn: &mut ConnectionState,
    header: &Smb2Header,
    body: &[u8],
) -> HandlerResult {
    let req = smb2::close::CloseRequest::parse(body)
        .ok_or(NtStatus::InvalidParameter)?;

    let file_id = req.file_id_volatile;
    let tree = get_tree(conn, header.session_id, header.tree_id)?;

    let open = tree.open_files.remove(&file_id);

    let resp = if let Some(open) = &open {
        if req.wants_post_query() {
            match vfs::stat(&open.path).await {
                Ok(info) => smb2::close::CloseResponse {
                    flags: smb2::close::CLOSE_FLAG_POSTQUERY_ATTRIB,
                    creation_time: info.creation_time,
                    last_access_time: info.last_access_time,
                    last_write_time: info.last_write_time,
                    change_time: info.change_time,
                    allocation_size: info.allocation_size,
                    end_of_file: info.end_of_file,
                    file_attributes: info.file_attributes,
                },
                Err(_) => smb2::close::CloseResponse::empty(),
            }
        } else {
            smb2::close::CloseResponse::empty()
        }
    } else {
        smb2::close::CloseResponse::empty()
    };

    debug!(file_id, "File closed");
    serialize_body(header, NtStatus::Success, |buf| resp.serialize(buf))
}

async fn handle_flush(
    conn: &mut ConnectionState,
    header: &Smb2Header,
    body: &[u8],
) -> HandlerResult {
    let req = smb2::flush::FlushRequest::parse(body)
        .ok_or(NtStatus::InvalidParameter)?;

    let file_id = req.file_id_volatile;
    let tree = get_tree(conn, header.session_id, header.tree_id)?;

    if let Some(open) = tree.open_files.get(&file_id) {
        if let Some(ref handle) = open.handle {
            vfs::flush_file(handle).await.map_err(|e| error::io_to_ntstatus(&e))?;
        }
    }

    serialize_body(header, NtStatus::Success, |buf| {
        smb2::flush::FlushResponse.serialize(buf);
    })
}

async fn handle_read(
    conn: &mut ConnectionState,
    header: &Smb2Header,
    body: &[u8],
) -> HandlerResult {
    let req = smb2::read::ReadRequest::parse(body)
        .ok_or(NtStatus::InvalidParameter)?;

    let file_id = req.file_id_volatile;
    let tree = get_tree(conn, header.session_id, header.tree_id)?;

    let open = tree.open_files.get(&file_id)
        .ok_or(NtStatus::InvalidParameter)?;

    let handle = open.handle.as_ref()
        .ok_or(NtStatus::InvalidDeviceRequest)?;

    let data = vfs::read_file(handle, req.offset, req.length)
        .await
        .map_err(|e| error::io_to_ntstatus(&e))?;

    if data.is_empty() {
        return Err(NtStatus::EndOfFile);
    }

    let resp = smb2::read::ReadResponse { data: &data };
    let mut buf = BytesMut::with_capacity(16 + data.len());
    resp.serialize(&mut buf);
    Ok((Smb2Header::new_response(header, NtStatus::Success), buf.to_vec()))
}

async fn handle_write(
    conn: &mut ConnectionState,
    header: &Smb2Header,
    body: &[u8],
) -> HandlerResult {
    let req = smb2::write::WriteRequest::parse(body)
        .ok_or(NtStatus::InvalidParameter)?;

    let file_id = req.file_id_volatile;
    let tree = get_tree(conn, header.session_id, header.tree_id)?;

    let open = tree.open_files.get(&file_id)
        .ok_or(NtStatus::InvalidParameter)?;

    let handle = open.handle.as_ref()
        .ok_or(NtStatus::InvalidDeviceRequest)?;

    let count = vfs::write_file(handle, req.offset, req.data)
        .await
        .map_err(|e| error::io_to_ntstatus(&e))?;

    let resp = smb2::write::WriteResponse { count };
    serialize_body(header, NtStatus::Success, |buf| resp.serialize(buf))
}

async fn handle_query_directory(
    conn: &mut ConnectionState,
    header: &Smb2Header,
    body: &[u8],
) -> HandlerResult {
    let req = smb2::query::QueryDirectoryRequest::parse(body)
        .ok_or(NtStatus::InvalidParameter)?;

    let file_id = req.file_id_volatile;
    let tree = get_tree(conn, header.session_id, header.tree_id)?;

    debug!(file_id, 
           file_info_class = req.file_information_class,
           pattern = %req.file_name_pattern,
           restart = req.restart_scan(),
           "QueryDirectory request");

    let open = tree.open_files.get_mut(&file_id)
        .ok_or(NtStatus::InvalidParameter)?;

    if !open.is_directory {
        return Err(NtStatus::InvalidParameter);
    }

    // If not restarting and already enumerated, return NO_MORE_FILES
    if open.dir_enumerated && !req.restart_scan() {
        return Err(NtStatus::NoMoreFiles);
    }

    // Clone path before the async call so we don't hold a borrow across await
    let dir_path = open.path.clone();

    let entries = vfs::list_directory(&dir_path, &req.file_name_pattern)
        .await
        .map_err(|e| error::io_to_ntstatus(&e))?;

    if entries.is_empty() {
        return Err(NtStatus::NoSuchFile);
    }

    open.dir_enumerated = true;

    let data = match req.file_information_class {
        smb2::query::FILE_ID_BOTH_DIRECTORY_INFORMATION =>
            smb2::query::serialize_file_id_both_dir_info(&entries),
        _ =>
            smb2::query::serialize_file_both_dir_info(&entries),
    };

    debug!(file_id, entry_count = entries.len(), data_len = data.len(),
           first_entry = %entries.first().map(|e| e.name.as_str()).unwrap_or(""),
           "QueryDirectory response");

    let resp = smb2::query::QueryDirectoryResponse { data };
    let mut buf = BytesMut::with_capacity(resp.data.len() + 8);
    resp.serialize(&mut buf);
    Ok((Smb2Header::new_response(header, NtStatus::Success), buf.to_vec()))
}

async fn handle_query_info(
    conn: &mut ConnectionState,
    header: &Smb2Header,
    body: &[u8],
) -> HandlerResult {
    let req = smb2::query::QueryInfoRequest::parse(body)
        .ok_or(NtStatus::InvalidParameter)?;

    let file_id = req.file_id_volatile;
    let tree = get_tree(conn, header.session_id, header.tree_id)?;

    let open = tree.open_files.get(&file_id)
        .ok_or(NtStatus::InvalidParameter)?;

    let info = vfs::stat(&open.path).await.map_err(|e| error::io_to_ntstatus(&e))?;

    let data = match (req.info_type, req.file_info_class) {
        (smb2::query::SMB2_0_INFO_FILE, smb2::query::FILE_BASIC_INFORMATION) =>
            smb2::query::serialize_file_basic_info(&info),
        (smb2::query::SMB2_0_INFO_FILE, smb2::query::FILE_STANDARD_INFORMATION) =>
            smb2::query::serialize_file_standard_info(&info),
        (smb2::query::SMB2_0_INFO_FILE, smb2::query::FILE_INTERNAL_INFORMATION) =>
            smb2::query::serialize_file_internal_info(&info),
        (smb2::query::SMB2_0_INFO_FILE, smb2::query::FILE_EA_INFORMATION) =>
            smb2::query::serialize_file_ea_info(),
        (smb2::query::SMB2_0_INFO_FILE, smb2::query::FILE_NETWORK_OPEN_INFORMATION) =>
            smb2::query::serialize_file_network_open_info(&info),
        (smb2::query::SMB2_0_INFO_FILE, smb2::query::FILE_ATTRIBUTE_TAG_INFORMATION) =>
            smb2::query::serialize_file_attribute_tag_info(&info),
        (smb2::query::SMB2_0_INFO_FILE, smb2::query::FILE_STREAM_INFORMATION) =>
            smb2::query::serialize_file_stream_info(&info),
        (smb2::query::SMB2_0_INFO_FILE, smb2::query::FILE_ALL_INFORMATION) => {
            // FileAllInformation = Basic + Standard + Internal + EA + Access + Position + Mode + Alignment + Name
            let mut all = Vec::new();
            all.extend_from_slice(&smb2::query::serialize_file_basic_info(&info));
            all.extend_from_slice(&smb2::query::serialize_file_standard_info(&info));
            all.extend_from_slice(&smb2::query::serialize_file_internal_info(&info));
            all.extend_from_slice(&smb2::query::serialize_file_ea_info());
            all.extend_from_slice(&[0u8; 4]);  // AccessInformation
            all.extend_from_slice(&[0u8; 8]);  // PositionInformation
            all.extend_from_slice(&[0u8; 4]);  // ModeInformation
            all.extend_from_slice(&[0u8; 4]);  // AlignmentInformation
            // NameInformation: name length (4) + name bytes
            let name_utf16 = smb2::string_to_utf16le(&info.name);
            all.extend_from_slice(&(name_utf16.len() as u32).to_le_bytes());
            all.extend_from_slice(&name_utf16);
            all
        }
        (smb2::query::SMB2_0_INFO_FILESYSTEM, smb2::query::FILE_FS_VOLUME_INFORMATION) =>
            smb2::query::serialize_fs_volume_info("RustSMB2"),
        (smb2::query::SMB2_0_INFO_FILESYSTEM, smb2::query::FILE_FS_SIZE_INFORMATION) =>
            smb2::query::serialize_fs_size_info(),
        (smb2::query::SMB2_0_INFO_FILESYSTEM, smb2::query::FILE_FS_FULL_SIZE_INFORMATION) =>
            smb2::query::serialize_fs_full_size_info(),
        (smb2::query::SMB2_0_INFO_FILESYSTEM, smb2::query::FILE_FS_ATTRIBUTE_INFORMATION) =>
            smb2::query::serialize_fs_attribute_info(),
        (smb2::query::SMB2_0_INFO_FILESYSTEM, smb2::query::FILE_FS_DEVICE_INFORMATION) =>
            smb2::query::serialize_fs_device_info(),
        _ => {
            debug!(info_type = req.info_type, class = req.file_info_class, "Unsupported QueryInfo");
            return Err(NtStatus::NotSupported);
        }
    };

    let resp = smb2::query::QueryInfoResponse { data };
    let mut buf = BytesMut::with_capacity(resp.data.len() + 8);
    resp.serialize(&mut buf);
    Ok((Smb2Header::new_response(header, NtStatus::Success), buf.to_vec()))
}

async fn handle_set_info(
    conn: &mut ConnectionState,
    header: &Smb2Header,
    body: &[u8],
) -> HandlerResult {
    let req = smb2::query::SetInfoRequest::parse(body)
        .ok_or(NtStatus::InvalidParameter)?;

    let file_id = req.file_id_volatile;
    let tree = get_tree(conn, header.session_id, header.tree_id)?;

    let open = tree.open_files.get(&file_id)
        .ok_or(NtStatus::InvalidParameter)?;

    // Clone what we need so we can release the borrow on `tree`
    let open_path = open.path.clone();
    let share_path = tree.share_path.clone();

    // Handle FileDispositionInformation (class 13) — delete on close
    if req.info_type == smb2::query::SMB2_0_INFO_FILE && req.file_info_class == 13 {
        if !req.buffer.is_empty() && req.buffer[0] != 0 {
            // Mark for deletion
            debug!(file_id, "Marked for delete-on-close");
            vfs::delete_path(&open_path).await.map_err(|e| error::io_to_ntstatus(&e))?;
        }
    }

    // Handle FileRenameInformation (class 10)
    if req.info_type == smb2::query::SMB2_0_INFO_FILE && req.file_info_class == 10 {
        if req.buffer.len() >= 24 {
            // [0] ReplaceIfExists, [8..16] RootDirectory, [16..20] FileNameLength, [20..] FileName
            let name_len = u32::from_le_bytes(
                req.buffer[16..20].try_into().unwrap_or([0; 4])
            ) as usize;
            if 20 + name_len <= req.buffer.len() {
                let new_name = smb2::utf16le_to_string(&req.buffer[20..20 + name_len]);
                let new_path = vfs::safe_resolve(&share_path, &new_name)
                    .ok_or(NtStatus::ObjectPathNotFound)?;
                vfs::rename_path(&open_path, &new_path)
                    .await
                    .map_err(|e| error::io_to_ntstatus(&e))?;
                debug!(from = %open_path.display(), to = %new_path.display(), "File renamed");
            }
        }
    }

    serialize_body(header, NtStatus::Success, |buf| {
        smb2::query::SetInfoResponse.serialize(buf);
    })
}

async fn handle_echo(header: &Smb2Header) -> HandlerResult {
    serialize_body(header, NtStatus::Success, |buf| {
        smb2::echo::EchoResponse.serialize(buf);
    })
}
