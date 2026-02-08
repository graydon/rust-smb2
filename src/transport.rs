//! NetBIOS Session Service framing for SMB2 over TCP.
//!
//! Each message is prefixed with a 4-byte big-endian length.
//! The top byte is the message type (0x00 = session message).
//!
//! MS-SMB2 Section 2.1: Transport

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Maximum frame size we'll accept (8 MB).
const MAX_FRAME_SIZE: u32 = 8 * 1024 * 1024;

/// Read a single NetBIOS-framed SMB2 message from the stream.
pub async fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;

    // NetBIOS header: first byte is type (0 = session message), bytes 1-3 are length
    let len = u32::from_be_bytes(len_buf) & 0x00FFFFFF;

    if len > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Frame too large: {} bytes", len),
        ));
    }

    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Write a single NetBIOS-framed SMB2 message to the stream.
pub async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    let len = data.len() as u32;
    // Type byte 0x00 (session message) is already 0 in the top byte
    let len_bytes = len.to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_frame_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let payload = b"Hello, SMB2!";

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let frame = read_frame(&mut stream).await.unwrap();
            assert_eq!(&frame, payload);
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        write_frame(&mut client, payload).await.unwrap();

        server.await.unwrap();
    }
}
