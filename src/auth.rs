//! NTLM authentication for SMB2.
//!
//! Implements a minimal NTLMv2 challenge/response flow wrapped in SPNEGO.
//! The three-leg handshake is:
//!   1. Client sends NEGOTIATE_MESSAGE
//!   2. Server sends CHALLENGE_MESSAGE with random 8-byte challenge
//!   3. Client sends AUTHENTICATE_MESSAGE with NTLMv2 response
//!
//! References:
//! - [MS-NLMP] NT LAN Manager Authentication Protocol
//! - [MS-SPNG] SPNEGO Extension

use crate::smb2;
use rand::RngCore;
use tracing::{debug, warn};

/// Authentication state machine, one per session-in-progress.
#[derive(Debug)]
pub enum AuthState {
    /// Waiting for the first NEGOTIATE_MESSAGE from the client.
    Initial,
    /// Server challenge has been sent; waiting for AUTHENTICATE_MESSAGE.
    ChallengeSent {
        server_challenge: [u8; 8],
    },
    /// Authentication completed successfully.
    Authenticated {
        username: String,
        session_key: Vec<u8>,
    },
}

/// Configured user credential (plaintext for now — hash in production).
#[derive(Debug, Clone)]
pub struct UserCredential {
    pub username: String,
    pub password: String,
}

/// NTLMSSP signature: `NTLMSSP\0`
const NTLMSSP_SIG: &[u8; 8] = b"NTLMSSP\0";

/// Process a SESSION_SETUP security buffer through the NTLM state machine.
///
/// Returns `(response_token, is_complete)`:
/// - `is_complete = false` → STATUS_MORE_PROCESSING_REQUIRED
/// - `is_complete = true`  → STATUS_SUCCESS
pub fn process_auth(
    state: &mut AuthState,
    security_buffer: &[u8],
    users: &[UserCredential],
    guest_ok: bool,
) -> Result<(Vec<u8>, bool), crate::smb2::status::NtStatus> {
    // Strip SPNEGO wrapping to find the raw NTLMSSP token
    let ntlm_token = unwrap_spnego(security_buffer);
    debug!(input_len = security_buffer.len(),
           ntlm_len = ntlm_token.len(),
           state = ?std::mem::discriminant(state),
           "NTLM: process_auth called");

    match state {
        AuthState::Initial => {
            // Expect NEGOTIATE_MESSAGE (type 1)
            if !is_ntlmssp_negotiate(&ntlm_token) {
                warn!("Expected NTLM NEGOTIATE_MESSAGE, got something else");
                return Err(crate::smb2::status::NtStatus::InvalidParameter);
            }
            let mut server_challenge = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut server_challenge);

            let challenge_msg = build_challenge_message(&server_challenge);
            let response_token = wrap_spnego_challenge(&challenge_msg);

            debug!("NTLM: sending challenge");
            *state = AuthState::ChallengeSent { server_challenge };
            Ok((response_token, false))
        }
        AuthState::ChallengeSent { server_challenge } => {
            // Expect AUTHENTICATE_MESSAGE (type 3)
            debug!(ntlm_token_len = ntlm_token.len(),
                   first_bytes = ?&ntlm_token[..std::cmp::min(32, ntlm_token.len())],
                   "NTLM: processing auth message");
            match parse_authenticate_message(&ntlm_token) {
                Some((username, _domain, _nt_response)) => {
                    // Validate against configured users
                    let authenticated = if users.is_empty() && guest_ok {
                        debug!("NTLM: guest access for '{}'", username);
                        true
                    } else {
                        users.iter().any(|u| u.username.eq_ignore_ascii_case(&username))
                    };

                    if authenticated {
                        let session_key = vec![0u8; 16]; // Simplified session key
                        debug!("NTLM: authenticated user '{}'", username);
                        *state = AuthState::Authenticated {
                            username,
                            session_key: session_key.clone(),
                        };
                        let response_token = wrap_spnego_accept();
                        Ok((response_token, true))
                    } else {
                        warn!("NTLM: unknown user '{}'", username);
                        Err(crate::smb2::status::NtStatus::LogonFailure)
                    }
                }
                None => {
                    warn!("NTLM: failed to parse AUTHENTICATE_MESSAGE");
                    Err(crate::smb2::status::NtStatus::LogonFailure)
                }
            }
        }
        AuthState::Authenticated { .. } => {
            Err(crate::smb2::status::NtStatus::InvalidParameter)
        }
    }
}

// ---- SPNEGO helpers (minimal ASN.1) ----

/// Build the initial SPNEGO NegTokenInit advertising NTLMSSP support.
/// Sent in the NEGOTIATE response SecurityBuffer.
pub fn build_spnego_init() -> Vec<u8> {
    // OID for SPNEGO: 1.3.6.1.5.5.2
    // OID for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
    let ntlmssp_oid: &[u8] = &[
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
    ];

    let mech_list_inner_len = ntlmssp_oid.len();
    // Build layers from inside out
    let mut mech_list = Vec::new();
    mech_list.push(0x30); // SEQUENCE
    push_der_length(&mut mech_list, mech_list_inner_len);
    mech_list.extend_from_slice(ntlmssp_oid);

    let mut mech_list_mic = Vec::new();
    mech_list_mic.push(0xa0); // context [0]
    push_der_length(&mut mech_list_mic, mech_list.len());
    mech_list_mic.extend_from_slice(&mech_list);

    let mut neg_token_init = Vec::new();
    neg_token_init.push(0x30); // SEQUENCE (NegTokenInit)
    push_der_length(&mut neg_token_init, mech_list_mic.len());
    neg_token_init.extend_from_slice(&mech_list_mic);

    let mut context = Vec::new();
    context.push(0xa0); // context [0] (NegotiationToken choice)
    push_der_length(&mut context, neg_token_init.len());
    context.extend_from_slice(&neg_token_init);

    // SPNEGO OID
    let spnego_oid: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

    let inner_len = spnego_oid.len() + context.len();
    let mut token = Vec::new();
    token.push(0x60); // APPLICATION 0 IMPLICIT
    push_der_length(&mut token, inner_len);
    token.extend_from_slice(spnego_oid);
    token.extend_from_slice(&context);

    token
}

/// Strip SPNEGO wrapping from a token, returning the raw NTLMSSP bytes.
fn unwrap_spnego(data: &[u8]) -> Vec<u8> {
    // Search for NTLMSSP signature anywhere in the buffer
    if let Some(pos) = data.windows(8).position(|w| w == NTLMSSP_SIG) {
        data[pos..].to_vec()
    } else {
        data.to_vec()
    }
}

/// Wrap an NTLM challenge message in a SPNEGO NegTokenResp.
///
/// Per RFC 4178, the server's first NegTokenResp MUST include the
/// `supportedMech` field identifying the chosen mechanism (NTLMSSP).
/// macOS is strict about this — it will abort auth without it.
fn wrap_spnego_challenge(ntlm_msg: &[u8]) -> Vec<u8> {
    // negState = accept-incomplete (1)
    let neg_state: &[u8] = &[0xa0, 0x03, 0x0a, 0x01, 0x01];

    // supportedMech = NTLMSSP OID (1.3.6.1.4.1.311.2.2.10)
    let ntlmssp_oid: &[u8] = &[
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
    ];
    let mut supported_mech = Vec::new();
    supported_mech.push(0xa1); // context [1] (supportedMech)
    push_der_length(&mut supported_mech, ntlmssp_oid.len());
    supported_mech.extend_from_slice(ntlmssp_oid);

    // responseToken OCTET STRING
    let mut resp_token = Vec::new();
    resp_token.push(0x04); // OCTET STRING
    push_der_length(&mut resp_token, ntlm_msg.len());
    resp_token.extend_from_slice(ntlm_msg);

    let mut resp_token_ctx = Vec::new();
    resp_token_ctx.push(0xa2); // context [2] (responseToken)
    push_der_length(&mut resp_token_ctx, resp_token.len());
    resp_token_ctx.extend_from_slice(&resp_token);

    let inner_len = neg_state.len() + supported_mech.len() + resp_token_ctx.len();
    let mut neg_token_resp_seq = Vec::new();
    neg_token_resp_seq.push(0x30); // SEQUENCE
    push_der_length(&mut neg_token_resp_seq, inner_len);
    neg_token_resp_seq.extend_from_slice(neg_state);
    neg_token_resp_seq.extend_from_slice(&supported_mech);
    neg_token_resp_seq.extend_from_slice(&resp_token_ctx);

    let mut result = Vec::new();
    result.push(0xa1); // context [1] (NegTokenResp)
    push_der_length(&mut result, neg_token_resp_seq.len());
    result.extend_from_slice(&neg_token_resp_seq);

    result
}

/// Wrap a final SPNEGO NegTokenResp indicating accept-completed.
fn wrap_spnego_accept() -> Vec<u8> {
    // negState = accept-completed (0)
    let neg_state: &[u8] = &[0xa0, 0x03, 0x0a, 0x01, 0x00];

    let mut neg_token_resp_seq = Vec::new();
    neg_token_resp_seq.push(0x30); // SEQUENCE
    push_der_length(&mut neg_token_resp_seq, neg_state.len());
    neg_token_resp_seq.extend_from_slice(neg_state);

    let mut result = Vec::new();
    result.push(0xa1); // context [1] (NegTokenResp)
    push_der_length(&mut result, neg_token_resp_seq.len());
    result.extend_from_slice(&neg_token_resp_seq);

    result
}

/// Push a DER length encoding into a buffer.
fn push_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

// ---- NTLM message construction / parsing ----

fn is_ntlmssp_negotiate(data: &[u8]) -> bool {
    data.len() >= 12 && &data[0..8] == NTLMSSP_SIG && u32::from_le_bytes([data[8], data[9], data[10], data[11]]) == 1
}

/// Build a minimal NTLM CHALLENGE_MESSAGE (type 2).
/// MS-NLMP 2.2.1.2
///
/// macOS requires TargetInfo AV_PAIRs (at minimum MsvAvNbDomainName,
/// MsvAvNbComputerName, MsvAvTimestamp and MsvAvEOL) or it will refuse
/// to send the AUTHENTICATE_MESSAGE.
fn build_challenge_message(server_challenge: &[u8; 8]) -> Vec<u8> {
    let target_name_utf16 = smb2::string_to_utf16le("SMB");
    let target_name_len = target_name_utf16.len() as u16;

    // Build TargetInfo AV_PAIRs
    let domain_utf16 = smb2::string_to_utf16le("SMB");
    let computer_utf16 = smb2::string_to_utf16le("SMB2RS");
    let dns_domain_utf16 = smb2::string_to_utf16le("smb2rs.local");
    let dns_computer_utf16 = smb2::string_to_utf16le("smb2rs.smb2rs.local");

    // Timestamp: current time as FILETIME
    let timestamp = {
        use std::time::{SystemTime, UNIX_EPOCH};
        const FILETIME_UNIX_DIFF: u64 = 116444736000000000;
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64 / 100 + FILETIME_UNIX_DIFF)
            .unwrap_or(FILETIME_UNIX_DIFF)
    };

    let mut target_info = Vec::new();
    // MsvAvNbDomainName (AvId=2)
    target_info.extend_from_slice(&2u16.to_le_bytes());
    target_info.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    target_info.extend_from_slice(&domain_utf16);
    // MsvAvNbComputerName (AvId=1)
    target_info.extend_from_slice(&1u16.to_le_bytes());
    target_info.extend_from_slice(&(computer_utf16.len() as u16).to_le_bytes());
    target_info.extend_from_slice(&computer_utf16);
    // MsvAvDnsDomainName (AvId=4)
    target_info.extend_from_slice(&4u16.to_le_bytes());
    target_info.extend_from_slice(&(dns_domain_utf16.len() as u16).to_le_bytes());
    target_info.extend_from_slice(&dns_domain_utf16);
    // MsvAvDnsComputerName (AvId=3)
    target_info.extend_from_slice(&3u16.to_le_bytes());
    target_info.extend_from_slice(&(dns_computer_utf16.len() as u16).to_le_bytes());
    target_info.extend_from_slice(&dns_computer_utf16);
    // MsvAvTimestamp (AvId=7, Len=8)
    target_info.extend_from_slice(&7u16.to_le_bytes());
    target_info.extend_from_slice(&8u16.to_le_bytes());
    target_info.extend_from_slice(&timestamp.to_le_bytes());
    // MsvAvEOL (AvId=0, Len=0)
    target_info.extend_from_slice(&0u16.to_le_bytes());
    target_info.extend_from_slice(&0u16.to_le_bytes());

    let target_info_len = target_info.len() as u16;

    // Negotiate flags:
    // NTLMSSP_NEGOTIATE_UNICODE            0x00000001
    // NTLMSSP_REQUEST_TARGET               0x00000004
    // NTLMSSP_NEGOTIATE_NTLM               0x00000200
    // NTLMSSP_NEGOTIATE_TARGET_INFO        0x00800000
    // NTLMSSP_TARGET_TYPE_SERVER           0x00020000
    let flags: u32 = 0x0000_0001
                   | 0x0000_0004
                   | 0x0000_0200
                   | 0x0080_0000
                   | 0x0002_0000;

    let payload_offset = 56u32;  // fixed header size
    let target_name_offset = payload_offset;
    let target_info_offset = payload_offset + target_name_utf16.len() as u32;

    let mut msg = Vec::with_capacity(56 + target_name_utf16.len() + target_info.len());
    msg.extend_from_slice(NTLMSSP_SIG);                     // 0..8:   Signature
    msg.extend_from_slice(&2u32.to_le_bytes());              // 8..12:  MessageType = 2
    msg.extend_from_slice(&target_name_len.to_le_bytes());   // 12..14: TargetNameLen
    msg.extend_from_slice(&target_name_len.to_le_bytes());   // 14..16: TargetNameMaxLen
    msg.extend_from_slice(&target_name_offset.to_le_bytes()); // 16..20: TargetNameBufferOffset
    msg.extend_from_slice(&flags.to_le_bytes());             // 20..24: NegotiateFlags
    msg.extend_from_slice(server_challenge);                 // 24..32: ServerChallenge
    msg.extend_from_slice(&[0u8; 8]);                        // 32..40: Reserved
    msg.extend_from_slice(&target_info_len.to_le_bytes());   // 40..42: TargetInfoLen
    msg.extend_from_slice(&target_info_len.to_le_bytes());   // 42..44: TargetInfoMaxLen
    msg.extend_from_slice(&target_info_offset.to_le_bytes()); // 44..48: TargetInfoOffset
    msg.extend_from_slice(&[0u8; 8]);                        // 48..56: Version
    msg.extend_from_slice(&target_name_utf16);               // Payload: TargetName
    msg.extend_from_slice(&target_info);                     // Payload: TargetInfo

    msg
}

/// Parse an NTLM AUTHENTICATE_MESSAGE (type 3), extracting username and domain.
/// MS-NLMP 2.2.1.3
fn parse_authenticate_message(data: &[u8]) -> Option<(String, String, Vec<u8>)> {
    if data.len() < 88 {
        return None;
    }
    if &data[0..8] != NTLMSSP_SIG {
        return None;
    }
    let msg_type = u32::from_le_bytes(data[8..12].try_into().ok()?);
    if msg_type != 3 {
        return None;
    }

    // LmChallengeResponse: [12..14] len, [14..16] maxlen, [16..20] offset
    // NtChallengeResponse: [20..22] len, [22..24] maxlen, [24..28] offset
    let nt_len = u16::from_le_bytes(data[20..22].try_into().ok()?) as usize;
    let nt_offset = u32::from_le_bytes(data[24..28].try_into().ok()?) as usize;

    // DomainName: [28..30] len, [30..32] maxlen, [32..36] offset
    let domain_len = u16::from_le_bytes(data[28..30].try_into().ok()?) as usize;
    let domain_offset = u32::from_le_bytes(data[32..36].try_into().ok()?) as usize;

    // UserName: [36..38] len, [38..40] maxlen, [40..44] offset
    let user_len = u16::from_le_bytes(data[36..38].try_into().ok()?) as usize;
    let user_offset = u32::from_le_bytes(data[40..44].try_into().ok()?) as usize;

    let username = if user_offset + user_len <= data.len() {
        smb2::utf16le_to_string(&data[user_offset..user_offset + user_len])
    } else {
        String::new()
    };

    let domain = if domain_offset + domain_len <= data.len() {
        smb2::utf16le_to_string(&data[domain_offset..domain_offset + domain_len])
    } else {
        String::new()
    };

    let nt_response = if nt_offset + nt_len <= data.len() {
        data[nt_offset..nt_offset + nt_len].to_vec()
    } else {
        vec![]
    };

    Some((username, domain, nt_response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_spnego_init_starts_with_application_tag() {
        let token = build_spnego_init();
        assert!(!token.is_empty());
        assert_eq!(token[0], 0x60); // APPLICATION 0
    }

    #[test]
    fn test_build_challenge_message_structure() {
        let challenge = [0xAA; 8];
        let msg = build_challenge_message(&challenge);
        assert_eq!(&msg[0..8], NTLMSSP_SIG);
        assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 2);
        assert_eq!(&msg[24..32], &challenge);
    }

    #[test]
    fn test_unwrap_spnego_finds_ntlmssp() {
        let mut blob = vec![0x60, 0x10, 0x06, 0x06]; // some SPNEGO prefix
        blob.extend_from_slice(NTLMSSP_SIG);
        blob.extend_from_slice(&1u32.to_le_bytes());
        let extracted = unwrap_spnego(&blob);
        assert_eq!(&extracted[0..8], NTLMSSP_SIG);
    }

    #[test]
    fn test_der_length_encoding() {
        let mut buf = Vec::new();
        push_der_length(&mut buf, 10);
        assert_eq!(buf, vec![10]);

        buf.clear();
        push_der_length(&mut buf, 200);
        assert_eq!(buf, vec![0x81, 200]);

        buf.clear();
        push_der_length(&mut buf, 300);
        assert_eq!(buf, vec![0x82, 1, 44]); // 300 = 0x012C
    }
}
