//! SMB2 CREATE command (open or create a file/directory).
//! MS-SMB2 Section 2.2.13 (Request) and 2.2.14 (Response)

use bytes::{BytesMut, BufMut};
use crate::smb2;

// Create disposition values (MS-SMB2 2.2.13)
pub const FILE_SUPERSEDE: u32 = 0;
pub const FILE_OPEN: u32 = 1;
pub const FILE_CREATE: u32 = 2;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_OVERWRITE: u32 = 4;
pub const FILE_OVERWRITE_IF: u32 = 5;

// Create options flags
pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
pub const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
pub const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

// Create action values (response)
pub const FILE_SUPERSEDED: u32 = 0;
pub const FILE_OPENED: u32 = 1;
pub const FILE_CREATED: u32 = 2;
pub const FILE_OVERWRITTEN: u32 = 3;

// Desired access flags
pub const FILE_READ_DATA: u32 = 0x0000_0001;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_READ_EA: u32 = 0x0000_0008;
pub const FILE_WRITE_EA: u32 = 0x0000_0010;
pub const FILE_EXECUTE: u32 = 0x0000_0020;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

// Share access flags
pub const FILE_SHARE_READ: u32 = 0x0000_0001;
pub const FILE_SHARE_WRITE: u32 = 0x0000_0002;
pub const FILE_SHARE_DELETE: u32 = 0x0000_0004;

// File attributes
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

/// Parsed CREATE request.
#[derive(Debug)]
pub struct CreateRequest {
    pub requested_oplock_level: u8,
    pub impersonation_level: u32,
    pub desired_access: u32,
    pub file_attributes: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub filename: String,
}

impl CreateRequest {
    /// Parse from body bytes (after 64-byte SMB2 header).
    /// MS-SMB2 2.2.13: StructureSize(2) + SecurityFlags(1) + RequestedOplockLevel(1) +
    /// ImpersonationLevel(4) + SmbCreateFlags(8) + Reserved(8) + DesiredAccess(4) +
    /// FileAttributes(4) + ShareAccess(4) + CreateDisposition(4) + CreateOptions(4) +
    /// NameOffset(2) + NameLength(2) + CreateContextsOffset(4) + CreateContextsLength(4) = 56 bytes fixed
    pub fn parse(input: &[u8]) -> Option<Self> {
        if input.len() < 56 {
            return None;
        }
        // [0..2]  StructureSize = 57
        // [2]     SecurityFlags
        let requested_oplock_level = input[3];
        let impersonation_level = u32::from_le_bytes([input[4], input[5], input[6], input[7]]);
        // [8..16]  SmbCreateFlags
        // [16..24] Reserved
        let desired_access = u32::from_le_bytes([input[24], input[25], input[26], input[27]]);
        let file_attributes = u32::from_le_bytes([input[28], input[29], input[30], input[31]]);
        let share_access = u32::from_le_bytes([input[32], input[33], input[34], input[35]]);
        let create_disposition = u32::from_le_bytes([input[36], input[37], input[38], input[39]]);
        let create_options = u32::from_le_bytes([input[40], input[41], input[42], input[43]]);
        let name_offset = u16::from_le_bytes([input[44], input[45]]) as usize;
        let name_length = u16::from_le_bytes([input[46], input[47]]) as usize;
        // [48..52] CreateContextsOffset
        // [52..56] CreateContextsLength

        // name_offset is from start of SMB2 header (64 bytes before body)
        let body_offset = name_offset.saturating_sub(64);
        let filename = if name_length > 0 && body_offset + name_length <= input.len() {
            smb2::utf16le_to_string(&input[body_offset..body_offset + name_length])
        } else {
            String::new() // root of share
        };

        Some(CreateRequest {
            requested_oplock_level,
            impersonation_level,
            desired_access,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            filename,
        })
    }

    /// Returns true if the caller is requesting a directory open.
    pub fn is_directory_request(&self) -> bool {
        (self.create_options & FILE_DIRECTORY_FILE) != 0
    }

    /// Returns true if the caller wants to create or overwrite.
    pub fn wants_create(&self) -> bool {
        matches!(
            self.create_disposition,
            FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF | FILE_SUPERSEDE
        )
    }

    /// Returns true if the caller wants write access.
    pub fn wants_write(&self) -> bool {
        (self.desired_access
            & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA
                | FILE_WRITE_ATTRIBUTES | GENERIC_WRITE | GENERIC_ALL | DELETE))
            != 0
    }
}

/// CREATE response to serialize and send.
#[derive(Debug)]
pub struct CreateResponse {
    pub oplock_level: u8,
    pub create_action: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub allocation_size: u64,
    pub end_of_file: u64,
    pub file_attributes: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
}

impl CreateResponse {
    /// Serialize the CREATE response body (89 bytes fixed).
    /// MS-SMB2 2.2.14
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u16_le(89);                          // StructureSize
        buf.put_u8(self.oplock_level);                // OplockLevel
        buf.put_u8(0);                                // Flags
        buf.put_u32_le(self.create_action);           // CreateAction
        buf.put_u64_le(self.creation_time);           // CreationTime
        buf.put_u64_le(self.last_access_time);        // LastAccessTime
        buf.put_u64_le(self.last_write_time);         // LastWriteTime
        buf.put_u64_le(self.change_time);             // ChangeTime
        buf.put_u64_le(self.allocation_size);         // AllocationSize
        buf.put_u64_le(self.end_of_file);             // EndOfFile
        buf.put_u32_le(self.file_attributes);         // FileAttributes
        buf.put_u32_le(0);                            // Reserved2
        buf.put_u64_le(self.file_id_persistent);      // FileId.Persistent
        buf.put_u64_le(self.file_id_volatile);        // FileId.Volatile
        buf.put_u32_le(0);                            // CreateContextsOffset
        buf.put_u32_le(0);                            // CreateContextsLength
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_create_response_serialize_size() {
        let resp = CreateResponse {
            oplock_level: 0,
            create_action: FILE_OPENED,
            creation_time: 0,
            last_access_time: 0,
            last_write_time: 0,
            change_time: 0,
            allocation_size: 4096,
            end_of_file: 100,
            file_attributes: FILE_ATTRIBUTE_NORMAL,
            file_id_persistent: 1,
            file_id_volatile: 1,
        };
        let mut buf = BytesMut::new();
        resp.serialize(&mut buf);
        // StructureSize says 89, actual serialized is 88 bytes
        // (StructureSize includes the required single byte of variable part)
        assert_eq!(buf.len(), 88);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 89);
    }

    #[test]
    fn test_create_request_flags() {
        let req = CreateRequest {
            requested_oplock_level: 0,
            impersonation_level: 2,
            desired_access: FILE_READ_DATA | FILE_WRITE_DATA,
            file_attributes: FILE_ATTRIBUTE_NORMAL,
            share_access: FILE_SHARE_READ,
            create_disposition: FILE_OPEN_IF,
            create_options: FILE_DIRECTORY_FILE,
            filename: "test".into(),
        };
        assert!(req.is_directory_request());
        assert!(req.wants_create());
        assert!(req.wants_write());
    }
}
