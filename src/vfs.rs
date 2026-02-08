//! Virtual Filesystem layer.
//!
//! Maps SMB2 file operations to POSIX filesystem calls via `tokio::fs`.
//! All path resolution includes traversal protection: resolved paths
//! must remain within the share root.
//!
//! Timestamps are converted to Windows FILETIME format (100-nanosecond
//! intervals since January 1, 1601).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tracing::{debug, warn};

use crate::smb2::create;

/// Windows FILETIME epoch offset from Unix epoch (100-ns intervals).
const FILETIME_UNIX_DIFF: u64 = 116_444_736_000_000_000;

/// File attributes
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

/// Metadata about a file or directory, using Windows FILETIME timestamps
/// and NT file attributes.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub name: String,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub file_attributes: u32,
    pub is_directory: bool,
}

/// Convert a `SystemTime` to a Windows FILETIME value.
pub fn system_time_to_filetime(t: SystemTime) -> u64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as u64 / 100 + FILETIME_UNIX_DIFF,
        Err(_) => FILETIME_UNIX_DIFF,
    }
}

/// Safely resolve a relative SMB path within a share root.
///
/// Converts backslashes to forward slashes, strips leading separators,
/// canonicalizes via the filesystem, and verifies the result is inside `root`.
/// Returns `None` if the path escapes the root (traversal attack).
pub fn safe_resolve(root: &Path, relative: &str) -> Option<PathBuf> {
    let cleaned = relative.replace('\\', "/");
    let cleaned = cleaned.trim_start_matches('/');

    // Reject paths containing `..` components before even touching the filesystem
    for component in cleaned.split('/') {
        if component == ".." {
            return None;
        }
    }

    let candidate = if cleaned.is_empty() {
        root.to_path_buf()
    } else {
        root.join(cleaned)
    };

    // For existing paths, canonicalize and check prefix
    if candidate.exists() {
        match candidate.canonicalize() {
            Ok(canon) => {
                let root_canon = root.canonicalize().ok()?;
                if canon.starts_with(&root_canon) {
                    Some(canon)
                } else {
                    warn!("Path traversal detected: {:?}", candidate);
                    None
                }
            }
            Err(_) => None,
        }
    } else {
        // For non-existing paths (create case), canonicalize the parent
        let parent = candidate.parent()?;
        if !parent.exists() {
            return None;
        }
        let parent_canon = parent.canonicalize().ok()?;
        let root_canon = root.canonicalize().ok()?;
        if parent_canon.starts_with(&root_canon) {
            Some(parent_canon.join(candidate.file_name()?))
        } else {
            warn!("Path traversal detected: {:?}", candidate);
            None
        }
    }
}

/// Query metadata for a file or directory.
pub async fn stat(path: &Path) -> std::io::Result<FileInfo> {
    let meta = fs::metadata(path).await?;
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let is_dir = meta.is_dir();
    let size = meta.len();
    let modified = meta.modified().unwrap_or(UNIX_EPOCH);
    let accessed = meta.accessed().unwrap_or(UNIX_EPOCH);
    let created = meta.created().unwrap_or(UNIX_EPOCH);

    Ok(FileInfo {
        name,
        end_of_file: size,
        allocation_size: (size + 4095) & !4095, // round up to 4K block
        creation_time: system_time_to_filetime(created),
        last_access_time: system_time_to_filetime(accessed),
        last_write_time: system_time_to_filetime(modified),
        change_time: system_time_to_filetime(modified),
        file_attributes: if is_dir {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_ARCHIVE
        },
        is_directory: is_dir,
    })
}

/// Open or create a file based on SMB2 CreateDisposition.
///
/// Returns `(file_handle, was_created)`.
pub async fn open_file(
    path: &Path,
    disposition: u32,
    is_directory: bool,
) -> std::io::Result<(tokio::fs::File, bool)> {
    match disposition {
        create::FILE_OPEN => {
            // Open existing only
            let f = if is_directory || path.is_dir() {
                tokio::fs::File::open(path).await?
            } else {
                tokio::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .await?
            };
            Ok((f, false))
        }
        create::FILE_CREATE => {
            // Create new; fail if exists
            if is_directory {
                fs::create_dir(path).await?;
                let f = tokio::fs::File::open(path).await?;
                Ok((f, true))
            } else {
                let f = tokio::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .await?;
                Ok((f, true))
            }
        }
        create::FILE_OPEN_IF => {
            // Open if exists, else create
            if path.exists() {
                let f = tokio::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .await?;
                Ok((f, false))
            } else if is_directory {
                fs::create_dir(path).await?;
                let f = tokio::fs::File::open(path).await?;
                Ok((f, true))
            } else {
                let f = tokio::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(path)
                    .await?;
                Ok((f, true))
            }
        }
        create::FILE_SUPERSEDE | create::FILE_OVERWRITE_IF => {
            // Create or truncate
            if is_directory {
                if !path.exists() {
                    fs::create_dir(path).await?;
                }
                let f = tokio::fs::File::open(path).await?;
                Ok((f, true))
            } else {
                let f = tokio::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)
                    .await?;
                Ok((f, true))
            }
        }
        create::FILE_OVERWRITE => {
            // Overwrite existing; fail if doesn't exist
            let f = tokio::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .truncate(true)
                .open(path)
                .await?;
            Ok((f, false))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unknown create disposition",
        )),
    }
}

/// Read bytes from a file at a given offset.
pub async fn read_file(
    file: &tokio::fs::File,
    offset: u64,
    length: u32,
) -> std::io::Result<Vec<u8>> {
    let length = length.min(1_048_576) as usize; // Cap at 1MB
    let mut file = file.try_clone().await?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut buf = vec![0u8; length];
    let n = file.read(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

/// Write bytes to a file at a given offset.
pub async fn write_file(
    file: &tokio::fs::File,
    offset: u64,
    data: &[u8],
) -> std::io::Result<u32> {
    let mut file = file.try_clone().await?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    file.write_all(data).await?;
    Ok(data.len() as u32)
}

/// Flush a file's buffers to disk.
pub async fn flush_file(file: &tokio::fs::File) -> std::io::Result<()> {
    let file = file.try_clone().await?;
    file.sync_all().await
}

/// List entries in a directory, applying a simple glob pattern.
///
/// Always includes `.` and `..` entries at the beginning.
pub async fn list_directory(
    dir_path: &Path,
    pattern: &str,
) -> std::io::Result<Vec<FileInfo>> {
    let mut entries = Vec::new();

    // Add "." entry (current directory)
    if let Ok(dot_info) = stat(dir_path).await {
        entries.push(FileInfo {
            name: ".".to_string(),
            ..dot_info
        });
    }

    // Add ".." entry (parent directory)
    if let Some(parent) = dir_path.parent() {
        if let Ok(dotdot_info) = stat(parent).await {
            entries.push(FileInfo {
                name: "..".to_string(),
                ..dotdot_info
            });
        }
    }

    let mut read_dir = fs::read_dir(dir_path).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip hidden files starting with '.' unless pattern is "*"
        if name.starts_with('.') && pattern == "*" {
            // Include dotfiles in wildcard listing
        }

        if !glob_match(pattern, &name) {
            continue;
        }

        match stat(&entry.path()).await {
            Ok(info) => entries.push(info),
            Err(e) => {
                debug!("Skipping entry {:?}: {}", entry.path(), e);
            }
        }
    }

    Ok(entries)
}

/// Delete a file or empty directory.
pub async fn delete_path(path: &Path) -> std::io::Result<()> {
    let meta = fs::metadata(path).await?;
    if meta.is_dir() {
        fs::remove_dir(path).await
    } else {
        fs::remove_file(path).await
    }
}

/// Rename a file or directory.
pub async fn rename_path(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::rename(from, to).await
}

/// Simple glob matching supporting `*` and `*.*` patterns.
fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern == "*.*" {
        return name.contains('.');
    }

    // Handle prefix wildcard: *.ext
    if pattern.starts_with('*') && pattern.len() > 1 {
        return name.ends_with(&pattern[1..]);
    }
    // Handle suffix wildcard: prefix*
    if pattern.ends_with('*') {
        return name
            .to_ascii_lowercase()
            .starts_with(&pattern[..pattern.len() - 1].to_ascii_lowercase());
    }

    // Exact match (case-insensitive)
    name.eq_ignore_ascii_case(pattern)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*.*", "file.txt"));
        assert!(!glob_match("*.*", "noext"));
        assert!(glob_match("*.txt", "readme.txt"));
        assert!(!glob_match("*.txt", "readme.md"));
        assert!(glob_match("read*", "readme.txt"));
        assert!(glob_match("readme.txt", "readme.txt"));
        assert!(glob_match("README.TXT", "readme.txt"));
    }

    #[test]
    fn test_safe_resolve_ok() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("test.txt"), "hello").unwrap();
        let resolved = safe_resolve(root, "test.txt");
        assert!(resolved.is_some());
        assert!(resolved.unwrap().starts_with(root.canonicalize().unwrap()));
    }

    #[test]
    fn test_safe_resolve_traversal() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let resolved = safe_resolve(root, "../../etc/passwd");
        assert!(resolved.is_none());
    }

    #[test]
    fn test_safe_resolve_backslash() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/file.txt"), "data").unwrap();
        let resolved = safe_resolve(root, "sub\\file.txt");
        assert!(resolved.is_some());
    }

    #[test]
    fn test_safe_resolve_empty_is_root() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let resolved = safe_resolve(root, "");
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap(), root.canonicalize().unwrap());
    }

    #[tokio::test]
    async fn test_stat_file() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("hello.txt");
        std::fs::write(&file_path, "hello world").unwrap();
        let info = stat(&file_path).await.unwrap();
        assert_eq!(info.name, "hello.txt");
        assert_eq!(info.end_of_file, 11);
        assert!(!info.is_directory);
    }

    #[tokio::test]
    async fn test_stat_dir() {
        let tmp = TempDir::new().unwrap();
        let info = stat(tmp.path()).await.unwrap();
        assert!(info.is_directory);
    }

    #[tokio::test]
    async fn test_list_directory_includes_dot_entries() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("a.txt"), "a").unwrap();
        let entries = list_directory(tmp.path(), "*").await.unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"."));
        assert!(names.contains(&".."));
        assert!(names.contains(&"a.txt"));
    }

    #[tokio::test]
    async fn test_read_write_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("rw.txt");
        let (file, created) = open_file(&path, create::FILE_CREATE, false).await.unwrap();
        assert!(created);
        let written = write_file(&file, 0, b"hello world").await.unwrap();
        assert_eq!(written, 11);
        let data = read_file(&file, 0, 1024).await.unwrap();
        assert_eq!(data, b"hello world");
    }

    #[tokio::test]
    async fn test_delete_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("del.txt");
        std::fs::write(&path, "bye").unwrap();
        delete_path(&path).await.unwrap();
        assert!(!path.exists());
    }
}
