//! SMB2 SESSION_SETUP command.
//! MS-SMB2 Section 2.2.5 (Request) and 2.2.6 (Response)

use bytes::{BytesMut, BufMut};

/// Parsed SESSION_SETUP request.
#[derive(Debug)]
pub struct SessionSetupRequest {
    pub flags: u8,
    pub security_mode: u8,
    pub capabilities: u32,
    pub channel: u32,
    pub previous_session_id: u64,
    pub security_buffer: Vec<u8>,
}

impl SessionSetupRequest {
    /// Parse from body bytes (after 64-byte header).
    pub fn parse(input: &[u8]) -> Option<Self> {
        if input.len() < 24 {
            return None;
        }
        // [0..2] StructureSize = 25
        let flags = input[2];
        let security_mode = input[3];
        let capabilities = u32::from_le_bytes([input[4], input[5], input[6], input[7]]);
        let channel = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);

        // SecurityBufferOffset is from start of SMB2 header
        let sec_buf_offset = u16::from_le_bytes([input[12], input[13]]) as usize;
        let sec_buf_length = u16::from_le_bytes([input[14], input[15]]) as usize;

        let previous_session_id = u64::from_le_bytes([
            input[16], input[17], input[18], input[19],
            input[20], input[21], input[22], input[23],
        ]);

        // The offset is from start of the full packet (header + body).
        // Body starts at offset 64, so local offset in body = sec_buf_offset - 64
        let local_offset = sec_buf_offset.saturating_sub(64);
        let security_buffer = if local_offset + sec_buf_length <= input.len() {
            input[local_offset..local_offset + sec_buf_length].to_vec()
        } else if sec_buf_length > 0 && 24 + sec_buf_length <= input.len() {
            // Fallback: data immediately follows fixed fields
            input[24..24 + sec_buf_length].to_vec()
        } else {
            vec![]
        };

        Some(SessionSetupRequest {
            flags,
            security_mode,
            capabilities,
            channel,
            previous_session_id,
            security_buffer,
        })
    }
}

/// SESSION_SETUP response to serialize.
#[derive(Debug)]
pub struct SessionSetupResponse {
    pub session_flags: u16,
    pub security_buffer: Vec<u8>,
}

impl SessionSetupResponse {
    /// Serialize the SESSION_SETUP response body.
    pub fn serialize(&self, buf: &mut BytesMut) {
        // Offset from start of header to security buffer
        let sec_offset = (64 + 8) as u16; // header + fixed body fields
        buf.put_u16_le(9);                             // StructureSize
        buf.put_u16_le(self.session_flags);            // SessionFlags
        buf.put_u16_le(sec_offset);                    // SecurityBufferOffset
        buf.put_u16_le(self.security_buffer.len() as u16); // SecurityBufferLength
        buf.put_slice(&self.security_buffer);          // SecurityBuffer
    }
}

/// LOGOFF response body (trivial).
pub struct LogoffResponse;

impl LogoffResponse {
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u16_le(4); // StructureSize
        buf.put_u16_le(0); // Reserved
    }
}
