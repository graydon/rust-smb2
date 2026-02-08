//! NT_STATUS codes for SMB2 responses.
//! Reference: [MS-ERREF] Section 2.3

/// NT Status codes used by SMB2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtStatus {
    Success,
    MoreProcessingRequired,
    InvalidParameter,
    AccessDenied,
    ObjectNameNotFound,
    ObjectPathNotFound,
    LogonFailure,
    BadNetworkName,
    NotSupported,
    EndOfFile,
    NoSuchFile,
    ObjectNameCollision,
    InvalidDeviceRequest,
    NotADirectory,
    FileClosed,
    NoMoreFiles,
    DirectoryNotEmpty,
    BufferOverflow,
    Other(u32),
}

impl NtStatus {
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::Success => 0x0000_0000,
            Self::MoreProcessingRequired => 0xC000_0016,
            Self::InvalidParameter => 0xC000_000D,
            Self::NoSuchFile => 0xC000_000F,
            Self::InvalidDeviceRequest => 0xC000_0010,
            Self::EndOfFile => 0xC000_0011,
            Self::AccessDenied => 0xC000_0022,
            Self::ObjectNameNotFound => 0xC000_0034,
            Self::ObjectNameCollision => 0xC000_0035,
            Self::ObjectPathNotFound => 0xC000_003A,
            Self::LogonFailure => 0xC000_006D,
            Self::NotSupported => 0xC000_00BB,
            Self::BadNetworkName => 0xC000_00CC,
            Self::NotADirectory => 0xC000_0103,
            Self::FileClosed => 0xC000_0128,
            Self::DirectoryNotEmpty => 0xC000_0101,
            Self::NoMoreFiles => 0x8000_0006,
            Self::BufferOverflow => 0x8000_0005,
            Self::Other(v) => *v,
        }
    }

    pub fn from_u32(v: u32) -> Self {
        match v {
            0x0000_0000 => Self::Success,
            0xC000_0016 => Self::MoreProcessingRequired,
            0xC000_000D => Self::InvalidParameter,
            0xC000_000F => Self::NoSuchFile,
            0xC000_0010 => Self::InvalidDeviceRequest,
            0xC000_0011 => Self::EndOfFile,
            0xC000_0022 => Self::AccessDenied,
            0xC000_0034 => Self::ObjectNameNotFound,
            0xC000_0035 => Self::ObjectNameCollision,
            0xC000_003A => Self::ObjectPathNotFound,
            0xC000_006D => Self::LogonFailure,
            0xC000_00BB => Self::NotSupported,
            0xC000_00CC => Self::BadNetworkName,
            0xC000_0101 => Self::DirectoryNotEmpty,
            0xC000_0103 => Self::NotADirectory,
            0xC000_0128 => Self::FileClosed,
            0x8000_0006 => Self::NoMoreFiles,
            0x8000_0005 => Self::BufferOverflow,
            v => Self::Other(v),
        }
    }

    pub fn is_error(&self) -> bool {
        (self.as_u32() >> 30) == 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let codes = [
            NtStatus::Success,
            NtStatus::MoreProcessingRequired,
            NtStatus::AccessDenied,
            NtStatus::ObjectNameNotFound,
            NtStatus::NoMoreFiles,
            NtStatus::DirectoryNotEmpty,
        ];
        for code in &codes {
            assert_eq!(NtStatus::from_u32(code.as_u32()), *code);
        }
    }

    #[test]
    fn test_is_error() {
        assert!(!NtStatus::Success.is_error());
        assert!(NtStatus::AccessDenied.is_error());
        assert!(!NtStatus::NoMoreFiles.is_error());
    }
}
