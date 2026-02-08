//! Error types for the SMB2 server.
//!
//! Maps Rust I/O errors and internal errors to NT status codes
//! that can be returned in SMB2 response headers.

use crate::smb2::status::NtStatus;
use std::fmt;

/// Top-level server error type.
#[derive(Debug)]
pub enum ServerError {
    /// An I/O error from the underlying filesystem.
    Io(std::io::Error),
    /// A protocol-level error with a specific NT status code.
    Protocol(NtStatus),
    /// Authentication failure.
    AuthFailed(String),
    /// Path traversal attempt detected.
    PathTraversal,
    /// Connection closed by peer.
    ConnectionClosed,
    /// Parse error in an incoming PDU.
    ParseError(String),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Protocol(s) => write!(f, "Protocol error: {:?}", s),
            Self::AuthFailed(msg) => write!(f, "Auth failed: {}", msg),
            Self::PathTraversal => write!(f, "Path traversal attempt"),
            Self::ConnectionClosed => write!(f, "Connection closed"),
            Self::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        ServerError::Io(e)
    }
}

/// Map an `std::io::Error` to the most appropriate NT status code.
pub fn io_to_ntstatus(e: &std::io::Error) -> NtStatus {
    match e.kind() {
        std::io::ErrorKind::NotFound => NtStatus::ObjectNameNotFound,
        std::io::ErrorKind::PermissionDenied => NtStatus::AccessDenied,
        std::io::ErrorKind::AlreadyExists => NtStatus::ObjectNameCollision,
        std::io::ErrorKind::InvalidInput => NtStatus::InvalidParameter,
        std::io::ErrorKind::UnexpectedEof => NtStatus::EndOfFile,
        std::io::ErrorKind::DirectoryNotEmpty => NtStatus::DirectoryNotEmpty,
        _ => NtStatus::Other(0xC000_0001), // STATUS_UNSUCCESSFUL
    }
}

/// Map a `ServerError` to an NT status code for the SMB2 response.
pub fn error_to_ntstatus(e: &ServerError) -> NtStatus {
    match e {
        ServerError::Io(io_err) => io_to_ntstatus(io_err),
        ServerError::Protocol(s) => *s,
        ServerError::AuthFailed(_) => NtStatus::LogonFailure,
        ServerError::PathTraversal => NtStatus::AccessDenied,
        ServerError::ConnectionClosed => NtStatus::Other(0xC000_0001),
        ServerError::ParseError(_) => NtStatus::InvalidParameter,
    }
}

/// Build the 9-byte SMB2 error response body (no error data).
/// MS-SMB2 2.2.2
pub fn build_error_response_body() -> Vec<u8> {
    let mut buf = vec![0u8; 9];
    buf[0] = 9; // StructureSize low byte
    buf[1] = 0; // StructureSize high byte
    // [2] ErrorContextCount = 0
    // [3] Reserved = 0
    // [4..8] ByteCount = 0
    // [8] ErrorData = 0 (1 byte minimum)
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_to_ntstatus() {
        let e = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        assert_eq!(io_to_ntstatus(&e), NtStatus::ObjectNameNotFound);

        let e = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no");
        assert_eq!(io_to_ntstatus(&e), NtStatus::AccessDenied);
    }

    #[test]
    fn test_error_response_body_size() {
        let body = build_error_response_body();
        assert_eq!(body.len(), 9);
        assert_eq!(u16::from_le_bytes([body[0], body[1]]), 9);
    }
}
