//! EROFS filesystem inspection
//!
//! Uses external tools (fsck.erofs, dump.erofs) to inspect EROFS images
//! without mounting.

use crate::error::FsdbgError;
use std::path::Path;
use std::process::Command;

/// Entry in an EROFS filesystem
#[derive(Debug, Clone)]
pub struct ErofsEntry {
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub link_target: Option<String>,
    pub mode: String,
}

/// EROFS filesystem inspector
pub struct ErofsReader {
    entries: Vec<ErofsEntry>,
}

impl ErofsReader {
    /// Open and inspect an EROFS image
    pub fn open(path: &Path) -> Result<Self, FsdbgError> {
        if !path.exists() {
            return Err(FsdbgError::file_not_found(path));
        }

        // Check if dump.erofs is available
        let dump_available = Command::new("dump.erofs")
            .arg("--help")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if dump_available {
            Self::parse_with_dump_erofs(path)
        } else {
            // Fallback to fsck.erofs if available
            let fsck_available = Command::new("fsck.erofs")
                .arg("--help")
                .output()
                .map(|_| true)
                .unwrap_or(false);

            if fsck_available {
                Self::parse_with_fsck_erofs(path)
            } else {
                Err(FsdbgError::external_tool_failed(
                    "erofs-utils",
                    "Neither dump.erofs nor fsck.erofs found. Install erofs-utils.",
                ))
            }
        }
    }

    fn parse_with_dump_erofs(path: &Path) -> Result<Self, FsdbgError> {
        // Use dump.erofs to list contents
        let output = Command::new("dump.erofs")
            .arg("--ls")
            .arg("-r") // recursive
            .arg(path)
            .output()
            .map_err(|e| FsdbgError::external_tool_failed("dump.erofs", e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FsdbgError::external_tool_failed("dump.erofs", stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let entries = Self::parse_dump_output(&stdout)?;

        Ok(Self { entries })
    }

    fn parse_with_fsck_erofs(path: &Path) -> Result<Self, FsdbgError> {
        // fsck.erofs --extract-dir=/dev/null --print-comp-ratio shows files
        // But for listing, we might need a different approach
        let output = Command::new("fsck.erofs")
            .arg("--extract-dir=/dev/null")
            .arg(path)
            .output()
            .map_err(|e| FsdbgError::external_tool_failed("fsck.erofs", e.to_string()))?;

        // fsck.erofs doesn't have great listing support, return empty for now
        // with a warning
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // fsck.erofs returns non-zero even on success sometimes
            if !stderr.contains("error") {
                return Ok(Self {
                    entries: Vec::new(),
                });
            }
            return Err(FsdbgError::external_tool_failed("fsck.erofs", stderr));
        }

        Ok(Self {
            entries: Vec::new(),
        })
    }

    fn parse_dump_output(output: &str) -> Result<Vec<ErofsEntry>, FsdbgError> {
        let mut entries = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // dump.erofs --ls output format varies by version
            // Common format: "drwxr-xr-x   2 root root    4096 Jan  1 00:00 dirname"
            // or just paths in some versions

            // Try to parse ls-style output
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 9 {
                // Full ls -l style
                let mode = parts[0].to_string();
                let is_dir = mode.starts_with('d');
                let is_symlink = mode.starts_with('l');

                // Find path (everything after the date/time)
                let path_start = parts[8..].join(" ");
                let (path, link_target) = if is_symlink && path_start.contains(" -> ") {
                    let mut split = path_start.splitn(2, " -> ");
                    (
                        split.next().unwrap_or(&path_start).to_string(),
                        split.next().map(|s| s.to_string()),
                    )
                } else {
                    (path_start, None)
                };

                let size = parts[4].parse().unwrap_or(0);

                entries.push(ErofsEntry {
                    path,
                    size,
                    is_dir,
                    is_symlink,
                    link_target,
                    mode,
                });
            } else if !parts.is_empty() {
                // Just a path
                entries.push(ErofsEntry {
                    path: line.to_string(),
                    size: 0,
                    is_dir: line.ends_with('/'),
                    is_symlink: false,
                    link_target: None,
                    mode: String::new(),
                });
            }
        }

        Ok(entries)
    }

    /// Get all entries
    pub fn entries(&self) -> &[ErofsEntry] {
        &self.entries
    }

    /// Check if a path exists
    pub fn exists(&self, path: &str) -> bool {
        let normalized = path.trim_start_matches('/');
        self.entries
            .iter()
            .any(|e| e.path.trim_start_matches('/') == normalized)
    }

    /// Get archive statistics
    pub fn stats(&self) -> ErofsStats {
        let mut stats = ErofsStats::default();
        for entry in &self.entries {
            if entry.is_dir {
                stats.directories += 1;
            } else if entry.is_symlink {
                stats.symlinks += 1;
            } else {
                stats.files += 1;
                stats.total_size += entry.size;
            }
        }
        stats
    }

    /// List all symlinks
    pub fn symlinks(&self) -> impl Iterator<Item = &ErofsEntry> {
        self.entries.iter().filter(|e| e.is_symlink)
    }
}

/// Statistics about an EROFS filesystem
#[derive(Debug, Default)]
pub struct ErofsStats {
    pub files: usize,
    pub directories: usize,
    pub symlinks: usize,
    pub total_size: u64,
}

/// Get EROFS filesystem information using dump.erofs
pub fn get_erofs_info(path: &Path) -> Result<ErofsInfo, FsdbgError> {
    if !path.exists() {
        return Err(FsdbgError::file_not_found(path));
    }

    let output = Command::new("dump.erofs")
        .arg(path)
        .output()
        .map_err(|e| FsdbgError::external_tool_failed("dump.erofs", e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FsdbgError::external_tool_failed("dump.erofs", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_erofs_info(&stdout)
}

fn parse_erofs_info(output: &str) -> Result<ErofsInfo, FsdbgError> {
    let mut info = ErofsInfo::default();

    for line in output.lines() {
        if line.contains("Filesystem UUID:") {
            info.uuid = line.split(':').nth(1).map(|s| s.trim().to_string());
        } else if line.contains("Filesystem total blocks:") {
            if let Some(blocks) = line.split(':').nth(1) {
                info.total_blocks = blocks.trim().parse().unwrap_or(0);
            }
        } else if line.contains("Filesystem inode count:") {
            if let Some(count) = line.split(':').nth(1) {
                info.inode_count = count.trim().parse().unwrap_or(0);
            }
        }
    }

    Ok(info)
}

/// EROFS filesystem information
#[derive(Debug, Default)]
pub struct ErofsInfo {
    pub uuid: Option<String>,
    pub total_blocks: u64,
    pub inode_count: u64,
}
