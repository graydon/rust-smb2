//! SMB2 TREE_CONNECT and TREE_DISCONNECT commands.
//! MS-SMB2 Section 2.2.9-2.2.12

use bytes::{BytesMut, BufMut};
use crate::smb2;

/// Share type constants.
pub const SHARE_TYPE_DISK: u8 = 0x01;
pub const SHARE_TYPE_PIPE: u8 = 0x02;

/// Parsed TREE_CONNECT request.
#[derive(Debug)]
pub struct TreeConnectRequest {
    pub path: String,
}

impl TreeConnectRequest {
    /// Parse from body bytes.
    /// The path field is UTF-16LE, e.g. `\\server\share`.
    pub fn parse(input: &[u8]) -> Option<Self> {
        if input.len() < 8 {
            return None;
        }
        // [0..2] StructureSize = 9
        // [2..4] Reserved / Flags
        let path_offset = u16::from_le_bytes([input[4], input[5]]) as usize;
        let path_length = u16::from_le_bytes([input[6], input[7]]) as usize;

        // path_offset is from start of header (64 bytes)
        let local_offset = path_offset.saturating_sub(64);
        if local_offset + path_length > input.len() {
            return None;
        }
        let path_bytes = &input[local_offset..local_offset + path_length];
        let path = smb2::utf16le_to_string(path_bytes);

        Some(TreeConnectRequest { path })
    }
}

/// TREE_CONNECT response.
#[derive(Debug)]
pub struct TreeConnectResponse {
    pub share_type: u8,
    pub share_flags: u32,
    pub capabilities: u32,
    pub maximal_access: u32,
}

impl TreeConnectResponse {
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u16_le(16);                // StructureSize
        buf.put_u8(self.share_type);       // ShareType
        buf.put_u8(0);                     // Reserved
        buf.put_u32_le(self.share_flags);  // ShareFlags
        buf.put_u32_le(self.capabilities); // Capabilities
        buf.put_u32_le(self.maximal_access); // MaximalAccess
    }
}

/// TREE_DISCONNECT response.
pub struct TreeDisconnectResponse;

impl TreeDisconnectResponse {
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u16_le(4); // StructureSize
        buf.put_u16_le(0); // Reserved
    }
}
