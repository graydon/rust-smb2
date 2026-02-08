//! SMB2 CLOSE command.
//! MS-SMB2 Section 2.2.15 (Request) and 2.2.16 (Response)

use bytes::{BytesMut, BufMut};

/// Flag: request post-close attribute query.
pub const CLOSE_FLAG_POSTQUERY_ATTRIB: u16 = 0x0001;

/// Parsed CLOSE request.
#[derive(Debug)]
pub struct CloseRequest {
    pub flags: u16,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
}

impl CloseRequest {
    /// Parse from body bytes (24 bytes fixed).
    /// MS-SMB2 2.2.15: StructureSize(2) + Flags(2) + Reserved(4) + FileId(16)
    pub fn parse(input: &[u8]) -> Option<Self> {
        if input.len() < 24 {
            return None;
        }
        let flags = u16::from_le_bytes([input[2], input[3]]);
        // [4..8] Reserved
        let file_id_persistent = u64::from_le_bytes(input[8..16].try_into().ok()?);
        let file_id_volatile = u64::from_le_bytes(input[16..24].try_into().ok()?);

        Some(CloseRequest {
            flags,
            file_id_persistent,
            file_id_volatile,
        })
    }

    /// Whether the client wants file attributes back in the response.
    pub fn wants_post_query(&self) -> bool {
        (self.flags & CLOSE_FLAG_POSTQUERY_ATTRIB) != 0
    }
}

/// CLOSE response.
#[derive(Debug)]
pub struct CloseResponse {
    pub flags: u16,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32,
}

impl CloseResponse {
    /// Empty response (no post-query).
    pub fn empty() -> Self {
        CloseResponse {
            flags: 0,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: 0,
        }
    }

    /// Serialize the CLOSE response body (60 bytes).
    /// MS-SMB2 2.2.16
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u16_le(60);                       // StructureSize
        buf.put_u16_le(self.flags);               // Flags
        buf.put_u32_le(0);                        // Reserved
        buf.put_u64_le(self.creation_time);       // CreationTime
        buf.put_u64_le(self.last_access_time);    // LastAccessTime
        buf.put_u64_le(self.last_write_time);     // LastWriteTime
        buf.put_u64_le(self.change_time);         // ChangeTime
        buf.put_u64_le(self.allocation_size);     // AllocationSize
        buf.put_u64_le(self.end_of_file);         // EndOfFile
        buf.put_u32_le(self.file_attributes);     // FileAttributes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_close_response_size() {
        let mut buf = BytesMut::new();
        CloseResponse::empty().serialize(&mut buf);
        assert_eq!(buf.len(), 60);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 60);
    }

    #[test]
    fn test_close_request_parse() {
        let mut data = vec![0u8; 24];
        data[0..2].copy_from_slice(&24u16.to_le_bytes()); // StructureSize
        data[2..4].copy_from_slice(&CLOSE_FLAG_POSTQUERY_ATTRIB.to_le_bytes());
        data[8..16].copy_from_slice(&42u64.to_le_bytes());
        data[16..24].copy_from_slice(&99u64.to_le_bytes());
        let req = CloseRequest::parse(&data).unwrap();
        assert!(req.wants_post_query());
        assert_eq!(req.file_id_persistent, 42);
        assert_eq!(req.file_id_volatile, 99);
    }
}
