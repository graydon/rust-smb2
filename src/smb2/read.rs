//! SMB2 READ command.
//! MS-SMB2 Section 2.2.19 (Request) and 2.2.20 (Response)

use bytes::{BytesMut, BufMut};

/// Parsed READ request.
#[derive(Debug)]
pub struct ReadRequest {
    pub length: u32,
    pub offset: u64,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    pub minimum_count: u32,
}

impl ReadRequest {
    /// Parse from body bytes.
    /// MS-SMB2 2.2.19: StructureSize(2) + Padding(1) + Flags(1) + Length(4) +
    /// Offset(8) + FileId(16) + MinimumCount(4) + Channel(4) + RemainingBytes(4) +
    /// ReadChannelInfoOffset(2) + ReadChannelInfoLength(2) + Buffer(1) = 49 bytes
    pub fn parse(input: &[u8]) -> Option<Self> {
        if input.len() < 48 {
            return None;
        }
        // [0..2]  StructureSize = 49
        // [2]     Padding
        // [3]     Flags
        let length = u32::from_le_bytes(input[4..8].try_into().ok()?);
        let offset = u64::from_le_bytes(input[8..16].try_into().ok()?);
        let file_id_persistent = u64::from_le_bytes(input[16..24].try_into().ok()?);
        let file_id_volatile = u64::from_le_bytes(input[24..32].try_into().ok()?);
        let minimum_count = u32::from_le_bytes(input[32..36].try_into().ok()?);
        // [36..40] Channel
        // [40..44] RemainingBytes
        // [44..46] ReadChannelInfoOffset
        // [46..48] ReadChannelInfoLength

        Some(ReadRequest {
            length,
            offset,
            file_id_persistent,
            file_id_volatile,
            minimum_count,
        })
    }
}

/// READ response.
#[derive(Debug)]
pub struct ReadResponse<'a> {
    pub data: &'a [u8],
}

impl<'a> ReadResponse<'a> {
    /// Serialize the READ response body.
    /// MS-SMB2 2.2.20: StructureSize(2) + DataOffset(1) + Reserved(1) +
    /// DataLength(4) + DataRemaining(4) + Reserved2(4) + Buffer(variable)
    /// Fixed part = 16 bytes, then data.
    pub fn serialize(&self, buf: &mut BytesMut) {
        let data_offset: u8 = 80; // 64 (header) + 16 (fixed body)
        buf.put_u16_le(17);                           // StructureSize
        buf.put_u8(data_offset);                      // DataOffset
        buf.put_u8(0);                                // Reserved
        buf.put_u32_le(self.data.len() as u32);       // DataLength
        buf.put_u32_le(0);                            // DataRemaining
        buf.put_u32_le(0);                            // Reserved2
        buf.put_slice(self.data);                     // Buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_request_parse() {
        let mut data = vec![0u8; 49];
        data[0..2].copy_from_slice(&49u16.to_le_bytes());
        data[4..8].copy_from_slice(&1024u32.to_le_bytes());
        data[8..16].copy_from_slice(&512u64.to_le_bytes());
        data[16..24].copy_from_slice(&1u64.to_le_bytes());
        data[24..32].copy_from_slice(&2u64.to_le_bytes());
        data[32..36].copy_from_slice(&0u32.to_le_bytes());
        let req = ReadRequest::parse(&data).unwrap();
        assert_eq!(req.length, 1024);
        assert_eq!(req.offset, 512);
        assert_eq!(req.file_id_persistent, 1);
        assert_eq!(req.file_id_volatile, 2);
    }

    #[test]
    fn test_read_response_serialize() {
        let payload = b"hello world";
        let resp = ReadResponse { data: payload };
        let mut buf = BytesMut::new();
        resp.serialize(&mut buf);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 17);
        let data_len = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(data_len, payload.len() as u32);
        assert_eq!(&buf[16..16 + payload.len()], payload);
    }
}
