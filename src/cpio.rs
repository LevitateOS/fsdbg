//! CPIO archive reader
//!
//! Reads CPIO archives (newc format) without extraction.
//! Supports both gzip-compressed and uncompressed archives.

use crate::error::FsdbgError;
use flate2::read::GzDecoder;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// File type extracted from mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Unknown,
}

impl FileType {
    fn from_mode(mode: u32) -> Self {
        match mode & 0o170000 {
            0o100000 => FileType::Regular,
            0o040000 => FileType::Directory,
            0o120000 => FileType::Symlink,
            0o020000 => FileType::CharDevice,
            0o060000 => FileType::BlockDevice,
            0o010000 => FileType::Fifo,
            0o140000 => FileType::Socket,
            _ => FileType::Unknown,
        }
    }
}

/// Entry in a CPIO archive
#[derive(Debug, Clone)]
pub struct CpioEntry {
    pub path: String,
    pub size: u64,
    pub mode: u32,
    pub file_type: FileType,
    pub link_target: Option<String>,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub rdev_major: u32,
    pub rdev_minor: u32,
}

impl CpioEntry {
    /// Check if this is a directory
    pub fn is_dir(&self) -> bool {
        self.file_type == FileType::Directory
    }

    /// Check if this is a regular file
    pub fn is_file(&self) -> bool {
        self.file_type == FileType::Regular
    }

    /// Check if this is a symlink
    pub fn is_symlink(&self) -> bool {
        self.file_type == FileType::Symlink
    }

    /// Get permission bits (lower 12 bits of mode)
    pub fn permissions(&self) -> u32 {
        self.mode & 0o7777
    }

    /// Format mode as ls-style string (e.g., "drwxr-xr-x")
    pub fn mode_string(&self) -> String {
        let mut s = String::with_capacity(10);

        // File type
        s.push(match self.file_type {
            FileType::Directory => 'd',
            FileType::Symlink => 'l',
            FileType::CharDevice => 'c',
            FileType::BlockDevice => 'b',
            FileType::Fifo => 'p',
            FileType::Socket => 's',
            _ => '-',
        });

        // Owner permissions
        let perms = self.permissions();
        s.push(if perms & 0o400 != 0 { 'r' } else { '-' });
        s.push(if perms & 0o200 != 0 { 'w' } else { '-' });
        s.push(if perms & 0o4000 != 0 {
            if perms & 0o100 != 0 { 's' } else { 'S' }
        } else if perms & 0o100 != 0 {
            'x'
        } else {
            '-'
        });

        // Group permissions
        s.push(if perms & 0o040 != 0 { 'r' } else { '-' });
        s.push(if perms & 0o020 != 0 { 'w' } else { '-' });
        s.push(if perms & 0o2000 != 0 {
            if perms & 0o010 != 0 { 's' } else { 'S' }
        } else if perms & 0o010 != 0 {
            'x'
        } else {
            '-'
        });

        // Other permissions
        s.push(if perms & 0o004 != 0 { 'r' } else { '-' });
        s.push(if perms & 0o002 != 0 { 'w' } else { '-' });
        s.push(if perms & 0o1000 != 0 {
            if perms & 0o001 != 0 { 't' } else { 'T' }
        } else if perms & 0o001 != 0 {
            'x'
        } else {
            '-'
        });

        s
    }
}

/// CPIO archive reader
pub struct CpioReader {
    entries: Vec<CpioEntry>,
    entry_map: HashMap<String, usize>,
}

impl CpioReader {
    /// Open and parse a CPIO archive
    pub fn open(path: &Path) -> Result<Self, FsdbgError> {
        let file = File::open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                FsdbgError::file_not_found(path)
            } else {
                FsdbgError::from(e)
            }
        })?;

        let mut reader = BufReader::new(file);

        // Check for gzip magic
        let mut magic = [0u8; 2];
        reader.read_exact(&mut magic)?;

        // Rewind
        use std::io::Seek;
        reader.seek(std::io::SeekFrom::Start(0))?;

        if magic[0] == 0x1f && magic[1] == 0x8b {
            // Gzip compressed
            let decoder = GzDecoder::new(reader);
            Self::parse_cpio(decoder)
        } else {
            // Uncompressed
            Self::parse_cpio(reader)
        }
    }

    fn parse_cpio<R: Read>(mut reader: R) -> Result<Self, FsdbgError> {
        let mut entries = Vec::new();
        let mut entry_map = HashMap::new();

        loop {
            // Read header (110 bytes for newc format)
            let mut header = [0u8; 110];
            match reader.read_exact(&mut header) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(FsdbgError::from(e)),
            }

            // Verify magic
            let magic = std::str::from_utf8(&header[0..6])
                .map_err(|_| FsdbgError::invalid_format("Invalid CPIO header: not UTF-8"))?;

            if magic != "070701" && magic != "070702" {
                return Err(FsdbgError::invalid_format(format!(
                    "Invalid CPIO magic: expected 070701/070702, got {}",
                    magic
                )));
            }

            // Parse header fields (all hex strings)
            let parse_hex = |slice: &[u8]| -> Result<u32, FsdbgError> {
                let s = std::str::from_utf8(slice)
                    .map_err(|_| FsdbgError::invalid_format("Invalid hex field"))?;
                u32::from_str_radix(s, 16)
                    .map_err(|_| FsdbgError::invalid_format(format!("Invalid hex: {}", s)))
            };

            let mode = parse_hex(&header[14..22])?;
            let uid = parse_hex(&header[22..30])?;
            let gid = parse_hex(&header[30..38])?;
            let nlink = parse_hex(&header[38..46])?;
            let mtime = parse_hex(&header[46..54])?;
            let filesize = parse_hex(&header[54..62])? as u64;
            let dev_major = parse_hex(&header[62..70])?;
            let dev_minor = parse_hex(&header[70..78])?;
            let rdev_major = parse_hex(&header[78..86])?;
            let rdev_minor = parse_hex(&header[86..94])?;
            let namesize = parse_hex(&header[94..102])? as usize;

            // Read filename (padded to 4-byte boundary including header)
            let mut name_buf = vec![0u8; namesize];
            reader.read_exact(&mut name_buf)?;

            // Remove trailing null
            let name = String::from_utf8_lossy(&name_buf[..namesize.saturating_sub(1)]).to_string();

            // Skip padding after name (header + name aligned to 4 bytes)
            let header_plus_name = 110 + namesize;
            let padding = (4 - (header_plus_name % 4)) % 4;
            if padding > 0 {
                let mut skip = vec![0u8; padding];
                reader.read_exact(&mut skip)?;
            }

            // Check for trailer
            if name == "TRAILER!!!" {
                break;
            }

            // Read file content
            let mut content = vec![0u8; filesize as usize];
            reader.read_exact(&mut content)?;

            // Skip padding after content (aligned to 4 bytes)
            let content_padding = (4 - (filesize as usize % 4)) % 4;
            if content_padding > 0 {
                let mut skip = vec![0u8; content_padding];
                reader.read_exact(&mut skip)?;
            }

            // Determine file type and link target
            let file_type = FileType::from_mode(mode);
            let link_target = if file_type == FileType::Symlink {
                Some(String::from_utf8_lossy(&content).to_string())
            } else {
                None
            };

            let entry = CpioEntry {
                path: name.clone(),
                size: filesize,
                mode,
                file_type,
                link_target,
                uid,
                gid,
                nlink,
                mtime,
                dev_major,
                dev_minor,
                rdev_major,
                rdev_minor,
            };

            // Normalize the path for the entry_map (for lookups)
            let normalized_name = Self::normalize_path(&name);
            if !normalized_name.is_empty() {
                entry_map.insert(normalized_name, entries.len());
            }
            entries.push(entry);
        }

        Ok(Self { entries, entry_map })
    }

    /// Get all entries
    pub fn entries(&self) -> &[CpioEntry] {
        &self.entries
    }

    /// Check if a path exists
    pub fn exists(&self, path: &str) -> bool {
        let normalized = Self::normalize_path(path);
        self.entry_map.contains_key(&normalized)
    }

    /// Get an entry by path
    pub fn get(&self, path: &str) -> Option<&CpioEntry> {
        let normalized = Self::normalize_path(path);
        self.entry_map.get(&normalized).map(|&i| &self.entries[i])
    }

    /// List all files (not directories)
    pub fn files(&self) -> impl Iterator<Item = &CpioEntry> {
        self.entries.iter().filter(|e| e.is_file())
    }

    /// List all directories
    pub fn directories(&self) -> impl Iterator<Item = &CpioEntry> {
        self.entries.iter().filter(|e| e.is_dir())
    }

    /// List all symlinks
    pub fn symlinks(&self) -> impl Iterator<Item = &CpioEntry> {
        self.entries.iter().filter(|e| e.is_symlink())
    }

    /// Normalize a path (remove leading ./ or /)
    pub fn normalize_path(path: &str) -> String {
        let p = path.trim_start_matches("./").trim_start_matches('/');
        p.to_string()
    }

    /// Verify that a symlink target exists in the archive
    pub fn symlink_target_exists(&self, entry: &CpioEntry) -> bool {
        let Some(ref target) = entry.link_target else {
            return false;
        };

        // Resolve the target path relative to the symlink's directory
        let resolved = self.resolve_symlink_target(&entry.path, target);

        // Check if resolved path exists
        self.exists(&resolved)
    }

    /// Resolve a symlink target to an absolute path within the archive
    fn resolve_symlink_target(&self, link_path: &str, target: &str) -> String {
        if target.starts_with('/') {
            // Absolute symlink - strip leading /
            target.trim_start_matches('/').to_string()
        } else {
            // Relative symlink - resolve relative to link's directory
            let link_dir = Path::new(link_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            let mut components: Vec<&str> = if link_dir.is_empty() {
                Vec::new()
            } else {
                link_dir.split('/').collect()
            };

            for part in target.split('/') {
                match part {
                    "." | "" => {}
                    ".." => {
                        components.pop();
                    }
                    other => components.push(other),
                }
            }

            components.join("/")
        }
    }

    /// Get archive statistics
    pub fn stats(&self) -> CpioStats {
        let mut stats = CpioStats::default();
        for entry in &self.entries {
            match entry.file_type {
                FileType::Regular => {
                    stats.files += 1;
                    stats.total_size += entry.size;
                }
                FileType::Directory => stats.directories += 1,
                FileType::Symlink => stats.symlinks += 1,
                _ => stats.other += 1,
            }
        }
        stats
    }
}

/// Statistics about a CPIO archive
#[derive(Debug, Default)]
pub struct CpioStats {
    pub files: usize,
    pub directories: usize,
    pub symlinks: usize,
    pub other: usize,
    pub total_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use leviso_cheat_guard::cheat_reviewed;

    #[cheat_reviewed("Unit test for mode_string formatting - no cheat vectors (pure string formatting)")]
    #[test]
    fn test_mode_string() {
        let entry = CpioEntry {
            path: "test".to_string(),
            size: 0,
            mode: 0o100755,
            file_type: FileType::Regular,
            link_target: None,
            uid: 0,
            gid: 0,
            nlink: 1,
            mtime: 0,
            dev_major: 0,
            dev_minor: 0,
            rdev_major: 0,
            rdev_minor: 0,
        };
        assert_eq!(entry.mode_string(), "-rwxr-xr-x");
    }

    #[cheat_reviewed("Unit test for path normalization - no cheat vectors (pure string manipulation)")]
    #[test]
    fn test_normalize_path() {
        assert_eq!(CpioReader::normalize_path("./foo/bar"), "foo/bar");
        assert_eq!(CpioReader::normalize_path("/foo/bar"), "foo/bar");
        assert_eq!(CpioReader::normalize_path("foo/bar"), "foo/bar");
    }
}
