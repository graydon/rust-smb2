//! SMB2 FLUSH command.
//! MS-SMB2 Section 2.2.17 (Request) and 2.2.18 (Response)

use bytes::{BytesMut, BufMut};

/// Parsed FLUSH request.
#[derive(Debug)]
pub struct FlushRequest {
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
}

impl FlushRequest {
    /// Parse from body bytes (24 bytes).
    /// MS-SMB2 2.2.17: StructureSize(2) + Reserved1(2) + Reserved2(4) + FileId(16)
    pub fn parse(input: &[u8]) -> Option<Self> {
        if input.len() < 24 {
            return None;
        }
        let file_id_persistent = u64::from_le_bytes(input[8..16].try_into().ok()?);
        let file_id_volatile = u64::from_le_bytes(input[16..24].try_into().ok()?);
        Some(FlushRequest {
            file_id_persistent,
            file_id_volatile,
        })
    }
}

/// FLUSH response.
pub struct FlushResponse;

impl FlushResponse {
    /// Serialize: StructureSize(2) + Reserved(2) = 4 bytes.
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u16_le(4);  // StructureSize
        buf.put_u16_le(0);  // Reserved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flush_request_parse() {
        let mut data = vec![0u8; 24];
        data[0..2].copy_from_slice(&24u16.to_le_bytes());
        data[8..16].copy_from_slice(&7u64.to_le_bytes());
        data[16..24].copy_from_slice(&8u64.to_le_bytes());
        let req = FlushRequest::parse(&data).unwrap();
        assert_eq!(req.file_id_persistent, 7);
        assert_eq!(req.file_id_volatile, 8);
    }

    #[test]
    fn test_flush_response_serialize() {
        let mut buf = BytesMut::new();
        FlushResponse.serialize(&mut buf);
        assert_eq!(buf.len(), 4);
    }
}
