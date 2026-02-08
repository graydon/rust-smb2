//! SMB2 Packet Header.
//! MS-SMB2 Section 2.2.1

use bytes::{BytesMut, BufMut};
use crate::smb2::status::NtStatus;

/// Size of the SMB2 header in bytes.
pub const SMB2_HEADER_SIZE: usize = 64;

/// SMB2 protocol magic: 0xFE 'S' 'M' 'B'
pub const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];

/// Flags: response (server to client)
pub const FLAGS_SERVER_TO_REDIR: u32 = 0x00000001;
/// Flags: message is signed
// Used when message signing is implemented; part of the SMB2 protocol spec.
#[allow(dead_code)]
pub const FLAGS_SIGNED: u32 = 0x00000008;

/// Parsed SMB2 header.
#[derive(Debug, Clone)]
pub struct Smb2Header {
    pub credit_charge: u16,
    pub status: NtStatus,
    pub command: u16,
    pub credits_requested: u16,
    pub flags: u32,
    /// Byte offset to the next compounded command; 0 if none.
    /// Not yet used — compounding is not implemented.
    pub next_command: u32,
    pub message_id: u64,
    /// Async id for async responses; not yet used — async commands are not implemented.
    pub async_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
    /// Message signature; not yet used — signing is not implemented.
    pub signature: [u8; 16],
}

impl Smb2Header {
    /// Parse an SMB2 header from a byte slice.
    /// Returns None if the slice is too short or magic doesn't match.
    pub fn parse(input: &[u8]) -> Option<Self> {
        if input.len() < SMB2_HEADER_SIZE {
            return None;
        }
        if input[0..4] != SMB2_MAGIC {
            return None;
        }
        // StructureSize at [4..6] should be 64
        let structure_size = u16::from_le_bytes([input[4], input[5]]);
        if structure_size != 64 {
            return None;
        }

        let credit_charge = u16::from_le_bytes([input[6], input[7]]);
        let status = NtStatus::from_u32(u32::from_le_bytes([
            input[8], input[9], input[10], input[11],
        ]));
        let command = u16::from_le_bytes([input[12], input[13]]);
        let credits_requested = u16::from_le_bytes([input[14], input[15]]);
        let flags = u32::from_le_bytes([input[16], input[17], input[18], input[19]]);
        let next_command = u32::from_le_bytes([input[20], input[21], input[22], input[23]]);
        let message_id = u64::from_le_bytes([
            input[24], input[25], input[26], input[27],
            input[28], input[29], input[30], input[31],
        ]);

        // Bytes 32..40: For sync requests, [32..36] = reserved, [36..40] = TreeId
        // For async, [32..40] = AsyncId
        let is_async = (flags & 0x00000002) != 0;
        let (async_id, tree_id) = if is_async {
            let async_id = u64::from_le_bytes([
                input[32], input[33], input[34], input[35],
                input[36], input[37], input[38], input[39],
            ]);
            (async_id, 0)
        } else {
            let tree_id = u32::from_le_bytes([input[36], input[37], input[38], input[39]]);
            (0, tree_id)
        };

        let session_id = u64::from_le_bytes([
            input[40], input[41], input[42], input[43],
            input[44], input[45], input[46], input[47],
        ]);

        let mut signature = [0u8; 16];
        signature.copy_from_slice(&input[48..64]);

        Some(Smb2Header {
            credit_charge,
            status,
            command,
            credits_requested,
            flags,
            next_command,
            message_id,
            async_id,
            tree_id,
            session_id,
            signature,
        })
    }

    /// Serialize this header into the buffer.
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_slice(&SMB2_MAGIC);               // 0..4
        buf.put_u16_le(64);                        // 4..6: StructureSize
        buf.put_u16_le(self.credit_charge);        // 6..8
        buf.put_u32_le(self.status.as_u32());      // 8..12
        buf.put_u16_le(self.command);              // 12..14
        buf.put_u16_le(self.credits_requested);    // 14..16
        buf.put_u32_le(self.flags);                // 16..20
        buf.put_u32_le(self.next_command);         // 20..24
        buf.put_u64_le(self.message_id);           // 24..32
        if (self.flags & 0x00000002) != 0 {
            buf.put_u64_le(self.async_id);         // 32..40
        } else {
            buf.put_u32_le(0);                     // 32..36: Reserved
            buf.put_u32_le(self.tree_id);          // 36..40
        }
        buf.put_u64_le(self.session_id);           // 40..48
        buf.put_slice(&self.signature);            // 48..64
    }

    /// Create a response header corresponding to a request header.
    pub fn new_response(req: &Smb2Header, status: NtStatus) -> Self {
        Smb2Header {
            credit_charge: req.credit_charge.max(1),
            status,
            command: req.command,
            credits_requested: 256, // Grant generous credits
            flags: req.flags | FLAGS_SERVER_TO_REDIR,
            next_command: 0,
            message_id: req.message_id,
            async_id: 0,
            tree_id: req.tree_id,
            session_id: req.session_id,
            signature: [0; 16],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let original = Smb2Header {
            credit_charge: 1,
            status: NtStatus::Success,
            command: 5,
            credits_requested: 128,
            flags: FLAGS_SERVER_TO_REDIR,
            next_command: 0,
            message_id: 42,
            async_id: 0,
            tree_id: 3,
            session_id: 7,
            signature: [0xAA; 16],
        };

        let mut buf = BytesMut::with_capacity(64);
        original.serialize(&mut buf);
        assert_eq!(buf.len(), 64);

        let parsed = Smb2Header::parse(&buf).expect("should parse");
        assert_eq!(parsed.credit_charge, 1);
        assert_eq!(parsed.status, NtStatus::Success);
        assert_eq!(parsed.command, 5);
        assert_eq!(parsed.credits_requested, 128);
        assert_eq!(parsed.flags, FLAGS_SERVER_TO_REDIR);
        assert_eq!(parsed.message_id, 42);
        assert_eq!(parsed.tree_id, 3);
        assert_eq!(parsed.session_id, 7);
        assert_eq!(parsed.signature, [0xAA; 16]);
    }

    #[test]
    fn test_header_too_short() {
        assert!(Smb2Header::parse(&[0; 63]).is_none());
    }

    #[test]
    fn test_header_bad_magic() {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(b"\xffSMB");
        assert!(Smb2Header::parse(&data).is_none());
    }
}
