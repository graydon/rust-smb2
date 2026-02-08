//! SMB2 QUERY_DIRECTORY, QUERY_INFO, and SET_INFO commands.
//! MS-SMB2 Sections 2.2.33-2.2.40

use bytes::{BytesMut, BufMut};
use crate::smb2;

// File information classes (MS-FSCC 2.4)
pub const FILE_DIRECTORY_INFORMATION: u8 = 1;
pub const FILE_FULL_DIRECTORY_INFORMATION: u8 = 2;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u8 = 3;
pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 37;
pub const FILE_ID_FULL_DIRECTORY_INFORMATION: u8 = 38;

// QueryInfo info type (SMB2_0_INFO_*)
pub const SMB2_0_INFO_FILE: u8 = 1;
pub const SMB2_0_INFO_FILESYSTEM: u8 = 2;
pub const SMB2_0_INFO_SECURITY: u8 = 3;

// File info classes for QueryInfo
pub const FILE_BASIC_INFORMATION: u8 = 4;
pub const FILE_STANDARD_INFORMATION: u8 = 5;
pub const FILE_INTERNAL_INFORMATION: u8 = 6;
pub const FILE_EA_INFORMATION: u8 = 7;
pub const FILE_ALL_INFORMATION: u8 = 18;
pub const FILE_NETWORK_OPEN_INFORMATION: u8 = 34;
pub const FILE_ATTRIBUTE_TAG_INFORMATION: u8 = 35;
pub const FILE_STREAM_INFORMATION: u8 = 22;

// Filesystem info classes
pub const FILE_FS_VOLUME_INFORMATION: u8 = 1;
pub const FILE_FS_SIZE_INFORMATION: u8 = 3;
pub const FILE_FS_DEVICE_INFORMATION: u8 = 4;
pub const FILE_FS_ATTRIBUTE_INFORMATION: u8 = 5;
pub const FILE_FS_FULL_SIZE_INFORMATION: u8 = 7;
pub const FILE_FS_SECTOR_SIZE_INFORMATION: u8 = 11;

// QueryDirectory flags
pub const SL_RESTART_SCAN: u8 = 0x01;
pub const SL_RETURN_SINGLE_ENTRY: u8 = 0x02;
pub const SL_INDEX_SPECIFIED: u8 = 0x04;

// ---- QUERY_DIRECTORY ----

/// Parsed QUERY_DIRECTORY request.
#[derive(Debug)]
pub struct QueryDirectoryRequest {
    pub file_information_class: u8,
    pub flags: u8,
    pub file_index: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    pub file_name_pattern: String,
    pub output_buffer_length: u32,
}

impl QueryDirectoryRequest {
    /// Parse from body bytes (32 bytes fixed + variable filename).
    /// MS-SMB2 2.2.33
    pub fn parse(input: &[u8]) -> Option<Self> {
        if input.len() < 32 {
            return None;
        }
        // [0..2]  StructureSize = 33
        let file_information_class = input[2];
        let flags = input[3];
        let file_index = u32::from_le_bytes(input[4..8].try_into().ok()?);
        let file_id_persistent = u64::from_le_bytes(input[8..16].try_into().ok()?);
        let file_id_volatile = u64::from_le_bytes(input[16..24].try_into().ok()?);
        let fn_offset = u16::from_le_bytes([input[24], input[25]]) as usize;
        let fn_length = u16::from_le_bytes([input[26], input[27]]) as usize;
        let output_buffer_length = u32::from_le_bytes(input[28..32].try_into().ok()?);

        let body_offset = fn_offset.saturating_sub(64);
        let file_name_pattern = if fn_length > 0 && body_offset + fn_length <= input.len() {
            smb2::utf16le_to_string(&input[body_offset..body_offset + fn_length])
        } else {
            "*".to_string()
        };

        Some(QueryDirectoryRequest {
            file_information_class,
            flags,
            file_index,
            file_id_persistent,
            file_id_volatile,
            file_name_pattern,
            output_buffer_length,
        })
    }

    pub fn restart_scan(&self) -> bool {
        (self.flags & SL_RESTART_SCAN) != 0
    }

    pub fn single_entry(&self) -> bool {
        (self.flags & SL_RETURN_SINGLE_ENTRY) != 0
    }
}

/// QUERY_DIRECTORY response.
#[derive(Debug)]
pub struct QueryDirectoryResponse {
    pub data: Vec<u8>, // Pre-serialized directory entry buffer
}

impl QueryDirectoryResponse {
    /// MS-SMB2 2.2.34
    pub fn serialize(&self, buf: &mut BytesMut) {
        let output_offset = 72u16; // 64 (header) + 8 (fixed body)
        buf.put_u16_le(9);                                // StructureSize
        buf.put_u16_le(output_offset);                    // OutputBufferOffset
        buf.put_u32_le(self.data.len() as u32);           // OutputBufferLength
        buf.put_slice(&self.data);                        // OutputBuffer
    }
}

// ---- QUERY_INFO ----

/// Parsed QUERY_INFO request.
#[derive(Debug)]
pub struct QueryInfoRequest {
    pub info_type: u8,
    pub file_info_class: u8,
    pub output_buffer_length: u32,
    pub additional_information: u32,
    pub flags: u32,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
}

impl QueryInfoRequest {
    /// Parse from body bytes (40 bytes fixed).
    /// MS-SMB2 2.2.37
    pub fn parse(input: &[u8]) -> Option<Self> {
        if input.len() < 40 {
            return None;
        }
        // [0..2]  StructureSize = 41
        let info_type = input[2];
        let file_info_class = input[3];
        let output_buffer_length = u32::from_le_bytes(input[4..8].try_into().ok()?);
        // [8..10]  InputBufferOffset
        // [10..12] Reserved
        // [12..16] InputBufferLength
        let additional_information = u32::from_le_bytes(input[16..20].try_into().ok()?);
        let flags = u32::from_le_bytes(input[20..24].try_into().ok()?);
        let file_id_persistent = u64::from_le_bytes(input[24..32].try_into().ok()?);
        let file_id_volatile = u64::from_le_bytes(input[32..40].try_into().ok()?);

        Some(QueryInfoRequest {
            info_type,
            file_info_class,
            output_buffer_length,
            additional_information,
            flags,
            file_id_persistent,
            file_id_volatile,
        })
    }
}

/// QUERY_INFO response.
#[derive(Debug)]
pub struct QueryInfoResponse {
    pub data: Vec<u8>, // Pre-serialized info buffer
}

impl QueryInfoResponse {
    /// MS-SMB2 2.2.38
    pub fn serialize(&self, buf: &mut BytesMut) {
        let output_offset = 72u16; // 64 (header) + 8 (fixed body)
        buf.put_u16_le(9);                                // StructureSize
        buf.put_u16_le(output_offset);                    // OutputBufferOffset
        buf.put_u32_le(self.data.len() as u32);           // OutputBufferLength
        buf.put_slice(&self.data);                        // OutputBuffer
    }
}

// ---- SET_INFO ----

/// Parsed SET_INFO request.
#[derive(Debug)]
pub struct SetInfoRequest<'a> {
    pub info_type: u8,
    pub file_info_class: u8,
    pub file_id_persistent: u64,
    pub file_id_volatile: u64,
    pub buffer: &'a [u8],
}

impl<'a> SetInfoRequest<'a> {
    /// Parse from body bytes (32 bytes fixed + variable buffer).
    /// MS-SMB2 2.2.39
    pub fn parse(input: &'a [u8]) -> Option<Self> {
        if input.len() < 32 {
            return None;
        }
        // [0..2]  StructureSize = 33
        let info_type = input[2];
        let file_info_class = input[3];
        let buffer_length = u32::from_le_bytes(input[4..8].try_into().ok()?) as usize;
        let buffer_offset = u16::from_le_bytes([input[8], input[9]]) as usize;
        // [10..12] Reserved
        // [12..16] AdditionalInformation
        let file_id_persistent = u64::from_le_bytes(input[16..24].try_into().ok()?);
        let file_id_volatile = u64::from_le_bytes(input[24..32].try_into().ok()?);

        let body_offset = buffer_offset.saturating_sub(64);
        let buffer = if buffer_length > 0 && body_offset + buffer_length <= input.len() {
            &input[body_offset..body_offset + buffer_length]
        } else {
            &[]
        };

        Some(SetInfoRequest {
            info_type,
            file_info_class,
            file_id_persistent,
            file_id_volatile,
            buffer,
        })
    }
}

/// SET_INFO response (empty body).
pub struct SetInfoResponse;

impl SetInfoResponse {
    /// MS-SMB2 2.2.40
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u16_le(2); // StructureSize
    }
}

// ---- Directory entry serialization helpers ----

use crate::vfs::FileInfo;

/// Serialize a list of FileInfo into FileBothDirectoryInformation entries.
/// MS-FSCC 2.4.8
pub fn serialize_file_both_dir_info(entries: &[FileInfo]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    let count = entries.len();
    for (i, entry) in entries.iter().enumerate() {
        let name_utf16 = smb2::string_to_utf16le(&entry.name);
        let name_len = name_utf16.len();
        // Fixed fields = 94 bytes, then filename
        let entry_size = 94 + name_len;
        let padded = (entry_size + 7) & !7; // 8-byte align

        let next_offset = if i < count - 1 { padded as u32 } else { 0 };
        buf.put_u32_le(next_offset);                 // NextEntryOffset
        buf.put_u32_le(i as u32);                    // FileIndex
        buf.put_u64_le(entry.creation_time);         // CreationTime
        buf.put_u64_le(entry.last_access_time);      // LastAccessTime
        buf.put_u64_le(entry.last_write_time);       // LastWriteTime
        buf.put_u64_le(entry.change_time);           // ChangeTime
        buf.put_u64_le(entry.end_of_file);           // EndOfFile
        buf.put_u64_le(entry.allocation_size);       // AllocationSize
        buf.put_u32_le(entry.file_attributes);       // FileAttributes
        buf.put_u32_le(name_len as u32);             // FileNameLength
        buf.put_u32_le(0);                           // EaSize
        buf.put_u8(0);                               // ShortNameLength
        buf.put_u8(0);                               // Reserved
        buf.put_slice(&[0u8; 24]);                   // ShortName (24 bytes)
        buf.put_slice(&name_utf16);                  // FileName

        // Pad to 8-byte alignment
        let padding = padded - entry_size;
        if padding > 0 {
            buf.put_slice(&vec![0u8; padding]);
        }
    }
    buf.to_vec()
}

/// Serialize FileBasicInformation (MS-FSCC 2.4.7): 40 bytes.
pub fn serialize_file_basic_info(info: &FileInfo) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(40);
    buf.put_u64_le(info.creation_time);
    buf.put_u64_le(info.last_access_time);
    buf.put_u64_le(info.last_write_time);
    buf.put_u64_le(info.change_time);
    buf.put_u32_le(info.file_attributes);
    buf.put_u32_le(0); // Reserved
    buf.to_vec()
}

/// Serialize FileStandardInformation (MS-FSCC 2.4.41): 24 bytes.
pub fn serialize_file_standard_info(info: &FileInfo) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(24);
    buf.put_u64_le(info.allocation_size);
    buf.put_u64_le(info.end_of_file);
    buf.put_u32_le(1);  // NumberOfLinks
    buf.put_u8(0);      // DeletePending
    buf.put_u8(if info.is_directory { 1 } else { 0 });
    buf.put_u16_le(0);  // Reserved
    buf.to_vec()
}

/// Serialize FileInternalInformation (MS-FSCC 2.4.20): 8 bytes.
pub fn serialize_file_internal_info(_info: &FileInfo) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(8);
    buf.put_u64_le(0); // IndexNumber
    buf.to_vec()
}

/// Serialize FileNetworkOpenInformation (MS-FSCC 2.4.29): 56 bytes.
pub fn serialize_file_network_open_info(info: &FileInfo) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(56);
    buf.put_u64_le(info.creation_time);
    buf.put_u64_le(info.last_access_time);
    buf.put_u64_le(info.last_write_time);
    buf.put_u64_le(info.change_time);
    buf.put_u64_le(info.allocation_size);
    buf.put_u64_le(info.end_of_file);
    buf.put_u32_le(info.file_attributes);
    buf.put_u32_le(0); // Reserved
    buf.to_vec()
}

/// Serialize FileAttributeTagInformation (MS-FSCC 2.4.6): 8 bytes.
pub fn serialize_file_attribute_tag_info(info: &FileInfo) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(8);
    buf.put_u32_le(info.file_attributes);
    buf.put_u32_le(0); // ReparseTag
    buf.to_vec()
}

/// Serialize FileFsVolumeInformation (MS-FSCC 2.5.9).
pub fn serialize_fs_volume_info(label: &str) -> Vec<u8> {
    let label_utf16 = smb2::string_to_utf16le(label);
    let mut buf = BytesMut::with_capacity(18 + label_utf16.len());
    buf.put_u64_le(0);                                   // VolumeCreationTime
    buf.put_u32_le(0x12345678);                           // VolumeSerialNumber
    buf.put_u32_le(label_utf16.len() as u32);             // VolumeLabelLength
    buf.put_u8(0);                                        // SupportsObjects
    buf.put_u8(0);                                        // Reserved
    buf.put_slice(&label_utf16);
    buf.to_vec()
}

/// Serialize FileFsSizeInformation (MS-FSCC 2.5.8): 24 bytes.
pub fn serialize_fs_size_info() -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(24);
    buf.put_u64_le(1024 * 1024);  // TotalAllocationUnits
    buf.put_u64_le(512 * 1024);   // AvailableAllocationUnits
    buf.put_u32_le(1);            // SectorsPerAllocationUnit
    buf.put_u32_le(4096);         // BytesPerSector
    buf.to_vec()
}

/// Serialize FileFsFullSizeInformation (MS-FSCC 2.5.4): 32 bytes.
pub fn serialize_fs_full_size_info() -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(32);
    buf.put_u64_le(1024 * 1024);  // TotalAllocationUnits
    buf.put_u64_le(512 * 1024);   // CallerAvailableAllocationUnits
    buf.put_u64_le(512 * 1024);   // ActualAvailableAllocationUnits
    buf.put_u32_le(1);            // SectorsPerAllocationUnit
    buf.put_u32_le(4096);         // BytesPerSector
    buf.to_vec()
}

/// Serialize FileFsAttributeInformation (MS-FSCC 2.5.1).
pub fn serialize_fs_attribute_info() -> Vec<u8> {
    let fs_name = smb2::string_to_utf16le("NTFS");
    let mut buf = BytesMut::with_capacity(12 + fs_name.len());
    buf.put_u32_le(0x0000_000F); // Attributes (case-sensitive, case-preserving, unicode, persistent ACLs)
    buf.put_u32_le(255);         // MaximumComponentNameLength
    buf.put_u32_le(fs_name.len() as u32); // FileSystemNameLength
    buf.put_slice(&fs_name);
    buf.to_vec()
}

/// Serialize FileFsDeviceInformation (MS-FSCC 2.5.10): 8 bytes.
pub fn serialize_fs_device_info() -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(8);
    buf.put_u32_le(0x07);  // DeviceType = FILE_DEVICE_DISK
    buf.put_u32_le(0x20);  // Characteristics = FILE_DEVICE_IS_MOUNTED
    buf.to_vec()
}

/// Serialize FileEaInformation (MS-FSCC 2.4.12): 4 bytes.
pub fn serialize_file_ea_info() -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(4);
    buf.put_u32_le(0); // EaSize
    buf.to_vec()
}

/// Serialize FileStreamInformation (MS-FSCC 2.4.43) — single default stream.
pub fn serialize_file_stream_info(info: &FileInfo) -> Vec<u8> {
    let stream_name = smb2::string_to_utf16le("::$DATA");
    let mut buf = BytesMut::with_capacity(24 + stream_name.len());
    buf.put_u32_le(0);                           // NextEntryOffset (none)
    buf.put_u32_le(stream_name.len() as u32);    // StreamNameLength
    buf.put_u64_le(info.end_of_file);            // StreamSize
    buf.put_u64_le(info.allocation_size);        // StreamAllocationSize
    buf.put_slice(&stream_name);
    buf.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_info_response_serialize() {
        let resp = QueryInfoResponse { data: vec![1, 2, 3, 4] };
        let mut buf = BytesMut::new();
        resp.serialize(&mut buf);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 9);
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 4);
    }

    #[test]
    fn test_set_info_response_serialize() {
        let mut buf = BytesMut::new();
        SetInfoResponse.serialize(&mut buf);
        assert_eq!(buf.len(), 2);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 2);
    }

    #[test]
    fn test_serialize_fs_attribute_info() {
        let data = serialize_fs_attribute_info();
        let max_name = u32::from_le_bytes(data[4..8].try_into().unwrap());
        assert_eq!(max_name, 255);
    }
}
