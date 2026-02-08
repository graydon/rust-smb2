//! SMB2 ECHO command.
//! MS-SMB2 Section 2.2.28 (Request) and 2.2.29 (Response)

use bytes::{BytesMut, BufMut};

/// ECHO request (no fields beyond StructureSize).
pub struct EchoRequest;

impl EchoRequest {
    pub fn parse(input: &[u8]) -> Option<Self> {
        if input.len() < 4 {
            return None;
        }
        Some(EchoRequest)
    }
}

/// ECHO response.
pub struct EchoResponse;

impl EchoResponse {
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
    fn test_echo_roundtrip() {
        let data = [4, 0, 0, 0];
        assert!(EchoRequest::parse(&data).is_some());

        let mut buf = BytesMut::new();
        EchoResponse.serialize(&mut buf);
        assert_eq!(buf.len(), 4);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 4);
    }
}
