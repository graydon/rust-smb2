//! SMB2 WRITE command.
//! MS-SMB2 Section 2.2.21 (Request) and 2.2.22 (Response)

use bytes::{BytesMut, BufMut};

/// Parsed WRITE request.
#[derive(Debug)]
pub struct WriteRequest<'a> {
    pub offset: u64,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    pub data: &'a [u8],
    pub flags: u32,
}

impl<'a> WriteRequest<'a> {
    /// Parse from body bytes.
    /// MS-SMB2 2.2.21: StructureSize(2) + DataOffset(2) + Length(4) +
    /// Offset(8) + FileId(16) + Channel(4) + RemainingBytes(4) +
    /// WriteChannelInfoOffset(2) + WriteChannelInfoLength(2) + Flags(4) + Buffer(variable)
    /// Fixed = 48 bytes before data.
    pub fn parse(input: &'a [u8]) -> Option<Self> {
        if input.len() < 48 {
            return None;
        }
        // [0..2]  StructureSize = 49
        let data_offset = u16::from_le_bytes([input[2], input[3]]) as usize;
        let data_length = u32::from_le_bytes(input[4..8].try_into().ok()?) as usize;
        let offset = u64::from_le_bytes(input[8..16].try_into().ok()?);
        let file_id_persistent = u64::from_le_bytes(input[16..24].try_into().ok()?);
        let file_id_volatile = u64::from_le_bytes(input[24..32].try_into().ok()?);
        // [32..36] Channel
        // [36..40] RemainingBytes
        // [40..42] WriteChannelInfoOffset
        // [42..44] WriteChannelInfoLength
        let flags = u32::from_le_bytes(input[44..48].try_into().ok()?);

        // data_offset is from start of SMB2 header
        let body_data_offset = data_offset.saturating_sub(64);
        let data = if body_data_offset + data_length <= input.len() {
            &input[body_data_offset..body_data_offset + data_length]
        } else if 48 + data_length <= input.len() {
            // Fallback: data immediately follows fixed fields
            &input[48..48 + data_length]
        } else {
            return None;
        };

        Some(WriteRequest {
            offset,
            file_id_persistent,
            file_id_volatile,
            data,
            flags,
        })
    }
}

/// WRITE response.
#[derive(Debug)]
pub struct WriteResponse {
    pub count: u32,
}

impl WriteResponse {
    /// Serialize the WRITE response body (16 bytes).
    /// MS-SMB2 2.2.22: StructureSize(2) + Reserved(2) + Count(4) +
    /// Remaining(4) + WriteChannelInfoOffset(2) + WriteChannelInfoLength(2)
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u16_le(17);             // StructureSize
        buf.put_u16_le(0);              // Reserved
        buf.put_u32_le(self.count);     // Count
        buf.put_u32_le(0);              // Remaining
        buf.put_u16_le(0);              // WriteChannelInfoOffset
        buf.put_u16_le(0);              // WriteChannelInfoLength
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_response_serialize() {
        let resp = WriteResponse { count: 4096 };
        let mut buf = BytesMut::new();
        resp.serialize(&mut buf);
        assert_eq!(buf.len(), 16);
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 4096);
    }

    #[test]
    fn test_write_request_parse() {
        let payload = b"test data";
        let mut data = vec![0u8; 48 + payload.len()];
        data[0..2].copy_from_slice(&49u16.to_le_bytes());
        // data_offset = 64 + 48 = 112
        data[2..4].copy_from_slice(&112u16.to_le_bytes());
        data[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        data[8..16].copy_from_slice(&0u64.to_le_bytes()); // offset
        data[16..24].copy_from_slice(&1u64.to_le_bytes());
        data[24..32].copy_from_slice(&2u64.to_le_bytes());
        data[48..48 + payload.len()].copy_from_slice(payload);
        let req = WriteRequest::parse(&data).unwrap();
        assert_eq!(req.data, payload);
        assert_eq!(req.file_id_persistent, 1);
        assert_eq!(req.file_id_volatile, 2);
    }
}
