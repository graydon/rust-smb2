//! SMB2 protocol types: headers, commands, and status codes.
//!
//! Implements parsing and serialization for SMB2.1 dialect.
//! Reference: [MS-SMB2] — Server Message Block Protocol Versions 2 and 3

pub mod header;
pub mod negotiate;
pub mod session;
pub mod tree;
pub mod create;
pub mod close;
pub mod flush;
pub mod read;
pub mod write;
pub mod query;
pub mod echo;
pub mod status;

/// SMB2 command codes.
/// MS-SMB2 Section 2.2.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Smb2Command {
    Negotiate = 0,
    SessionSetup = 1,
    Logoff = 2,
    TreeConnect = 3,
    TreeDisconnect = 4,
    Create = 5,
    Close = 6,
    Flush = 7,
    Read = 8,
    Write = 9,
    Lock = 10,
    Ioctl = 11,
    Cancel = 12,
    Echo = 13,
    QueryDirectory = 14,
    ChangeNotify = 15,
    QueryInfo = 16,
    SetInfo = 17,
}

impl Smb2Command {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0 => Some(Self::Negotiate),
            1 => Some(Self::SessionSetup),
            2 => Some(Self::Logoff),
            3 => Some(Self::TreeConnect),
            4 => Some(Self::TreeDisconnect),
            5 => Some(Self::Create),
            6 => Some(Self::Close),
            7 => Some(Self::Flush),
            8 => Some(Self::Read),
            9 => Some(Self::Write),
            10 => Some(Self::Lock),
            11 => Some(Self::Ioctl),
            12 => Some(Self::Cancel),
            13 => Some(Self::Echo),
            14 => Some(Self::QueryDirectory),
            15 => Some(Self::ChangeNotify),
            16 => Some(Self::QueryInfo),
            17 => Some(Self::SetInfo),
            _ => None,
        }
    }
}

/// Decode a UTF-16LE byte slice into a Rust String.
pub fn utf16le_to_string(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s).trim_end_matches('\0').to_string()
}

/// Encode a Rust string as UTF-16LE bytes.
pub fn string_to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect()
}
