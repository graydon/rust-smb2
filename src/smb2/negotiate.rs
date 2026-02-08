//! SMB2 NEGOTIATE command.
//! MS-SMB2 Section 2.2.3 (Request) and 2.2.4 (Response)

use bytes::{BytesMut, BufMut};
use std::time::{SystemTime, UNIX_EPOCH};

/// Windows FILETIME epoch offset from Unix epoch (100-ns intervals).
const FILETIME_UNIX_DIFF: u64 = 116444736000000000;

fn now_as_filetime() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64 / 100 + FILETIME_UNIX_DIFF)
        .unwrap_or(FILETIME_UNIX_DIFF)
}

/// Parsed NEGOTIATE request.
#[derive(Debug)]
pub struct NegotiateRequest {
    pub structure_size: u16,
    pub dialect_count: u16,
    pub security_mode: u16,
    pub capabilities: u32,
    pub client_guid: [u8; 16],
    pub dialects: Vec<u16>,
}

impl NegotiateRequest {
    /// Parse from the body bytes (after the 64-byte SMB2 header).
    pub fn parse(input: &[u8]) -> Option<Self> {
        if input.len() < 36 {
            return None;
        }
        let structure_size = u16::from_le_bytes([input[0], input[1]]);
        let dialect_count = u16::from_le_bytes([input[2], input[3]]);
        let security_mode = u16::from_le_bytes([input[4], input[5]]);
        // [6..8] reserved
        let capabilities = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);
        let mut client_guid = [0u8; 16];
        client_guid.copy_from_slice(&input[12..28]);
        // [28..36] client start time or negotiate contexts

        let mut dialects = Vec::with_capacity(dialect_count as usize);
        for i in 0..dialect_count as usize {
            let offset = 36 + i * 2;
            if offset + 2 > input.len() {
                break;
            }
            dialects.push(u16::from_le_bytes([input[offset], input[offset + 1]]));
        }

        Some(NegotiateRequest {
            structure_size,
            dialect_count,
            security_mode,
            capabilities,
            client_guid,
            dialects,
        })
    }
}

/// NEGOTIATE response to serialize and send.
#[derive(Debug)]
pub struct NegotiateResponse {
    pub security_mode: u16,
    pub dialect: u16,
    pub server_guid: [u8; 16],
    pub capabilities: u32,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub security_buffer: Vec<u8>,
}

impl NegotiateResponse {
    /// Serialize the NEGOTIATE response body.
    /// The security buffer offset is relative to the start of the SMB2 header.
    pub fn serialize(&self, buf: &mut BytesMut) {
        let body_fixed_size: usize = 64; // Fixed part of negotiate response body
        let sec_offset = (64 + body_fixed_size) as u16; // header + fixed body

        buf.put_u16_le(65);                        // StructureSize (65 per spec)
        buf.put_u16_le(self.security_mode);        // SecurityMode
        buf.put_u16_le(self.dialect);              // DialectRevision
        buf.put_u16_le(0);                         // NegotiateContextCount (0 for SMB 2.1)
        buf.put_slice(&self.server_guid);          // ServerGuid (16 bytes)
        buf.put_u32_le(self.capabilities);         // Capabilities
        buf.put_u32_le(self.max_transact_size);    // MaxTransactSize
        buf.put_u32_le(self.max_read_size);        // MaxReadSize
        buf.put_u32_le(self.max_write_size);       // MaxWriteSize
        buf.put_u64_le(now_as_filetime());         // SystemTime
        buf.put_u64_le(now_as_filetime());         // ServerStartTime
        buf.put_u16_le(sec_offset);                // SecurityBufferOffset
        buf.put_u16_le(self.security_buffer.len() as u16); // SecurityBufferLength
        buf.put_u32_le(0);                         // NegotiateContextOffset (0 for 2.1)
        buf.put_slice(&self.security_buffer);      // SecurityBuffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiate_request_parse() {
        let mut data = vec![0u8; 40];
        // StructureSize = 36
        data[0] = 36;
        data[1] = 0;
        // DialectCount = 2
        data[2] = 2;
        data[3] = 0;
        // SecurityMode = 1
        data[4] = 1;
        // Dialects at offset 36
        data[36] = 0x02; data[37] = 0x02; // 0x0202 = SMB 2.0.2
        data[38] = 0x10; data[39] = 0x02; // 0x0210 = SMB 2.1

        let req = NegotiateRequest::parse(&data).unwrap();
        assert_eq!(req.dialect_count, 2);
        assert_eq!(req.dialects, vec![0x0202, 0x0210]);
    }

    #[test]
    fn test_negotiate_response_serialize() {
        let resp = NegotiateResponse {
            security_mode: 1,
            dialect: 0x0210,
            server_guid: [0xAA; 16],
            capabilities: 0,
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
            security_buffer: vec![1, 2, 3],
        };
        let mut buf = BytesMut::new();
        resp.serialize(&mut buf);
        // StructureSize at offset 0 should be 65
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 65);
        // Dialect at offset 4 should be 0x0210
        assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 0x0210);
        // SecurityBufferLength near the end
        let sec_len = u16::from_le_bytes([buf[58], buf[59]]);
        assert_eq!(sec_len, 3);
    }
}
