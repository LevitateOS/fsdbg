//! ISO 9660 image inspection
//!
//! Uses isoinfo from cdrtools/genisoimage to inspect ISO images
//! without mounting.

use crate::error::FsdbgError;
use std::path::Path;
use std::process::Command;

/// Entry in an ISO filesystem
#[derive(Debug, Clone)]
pub struct IsoEntry {
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub link_target: Option<String>,
}

/// ISO filesystem inspector
pub struct IsoReader {
    entries: Vec<IsoEntry>,
    volume_id: Option<String>,
}

impl IsoReader {
    /// Open and inspect an ISO image
    pub fn open(path: &Path) -> Result<Self, FsdbgError> {
        if !path.exists() {
            return Err(FsdbgError::file_not_found(path));
        }

        // Check if isoinfo is available
        let isoinfo_available = Command::new("isoinfo")
            .arg("-version")
            .output()
            .map(|_| true)
            .unwrap_or(false);

        if !isoinfo_available {
            return Err(FsdbgError::external_tool_failed(
                "isoinfo",
                "isoinfo not found. Install cdrtools or genisoimage.",
            ));
        }

        let entries = Self::list_entries(path)?;
        let volume_id = Self::get_volume_id(path).ok();

        Ok(Self { entries, volume_id })
    }

    fn list_entries(path: &Path) -> Result<Vec<IsoEntry>, FsdbgError> {
        // Use isoinfo with Rock Ridge extensions
        let output = Command::new("isoinfo")
            .arg("-l")
            .arg("-R") // Rock Ridge extensions (for symlinks, long names)
            .arg("-i")
            .arg(path)
            .output()
            .map_err(|e| FsdbgError::external_tool_failed("isoinfo", e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FsdbgError::external_tool_failed("isoinfo", stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_isoinfo_output(&stdout)
    }

    fn get_volume_id(path: &Path) -> Result<String, FsdbgError> {
        let output = Command::new("isoinfo")
            .arg("-d")
            .arg("-i")
            .arg(path)
            .output()
            .map_err(|e| FsdbgError::external_tool_failed("isoinfo", e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.starts_with("Volume id:") {
                return Ok(line
                    .strip_prefix("Volume id:")
                    .unwrap_or("")
                    .trim()
                    .to_string());
            }
        }

        Ok(String::new())
    }

    fn parse_isoinfo_output(output: &str) -> Result<Vec<IsoEntry>, FsdbgError> {
        let mut entries = Vec::new();
        let mut current_dir = String::new();

        for line in output.lines() {
            let line = line.trim();

            // Directory header: "Directory listing of /path/"
            if line.starts_with("Directory listing of ") {
                current_dir = line
                    .strip_prefix("Directory listing of ")
                    .unwrap_or("")
                    .to_string();
                continue;
            }

            // Skip empty lines and headers
            if line.is_empty() || line.starts_with("---") {
                continue;
            }

            // Parse ls-style output from isoinfo -l -R
            // Format: "drwxr-xr-x   1   0   0   2048 Jan 27 2026 [  37 02]  boot"
            //          mode      links uid gid size  month day year [extent]  name
            // The [extent] part is the ISO sector location, we need to skip it
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }

            let mode = parts[0];
            let is_dir = mode.starts_with('d');
            let is_symlink = mode.starts_with('l');

            let size: u64 = parts[4].parse().unwrap_or(0);

            // Find filename after the [extent] bracket
            // The bracket starts at parts[8] with '[' and we need to find where ']' ends
            let mut name_start_idx = 8;
            for (i, part) in parts[8..].iter().enumerate() {
                if part.ends_with(']') {
                    name_start_idx = 8 + i + 1;
                    break;
                }
            }

            if name_start_idx >= parts.len() {
                continue;
            }

            let name_parts = &parts[name_start_idx..];
            let name_str = name_parts.join(" ");

            // Handle symlinks (name -> target)
            let (name, link_target) = if is_symlink && name_str.contains(" -> ") {
                let mut split = name_str.splitn(2, " -> ");
                (
                    split.next().unwrap_or(&name_str).to_string(),
                    split.next().map(|s| s.to_string()),
                )
            } else {
                (name_str, None)
            };

            // Skip . and ..
            if name == "." || name == ".." {
                continue;
            }

            // Build full path
            let full_path = if current_dir == "/" {
                format!("/{}", name)
            } else {
                format!("{}{}", current_dir, name)
            };

            entries.push(IsoEntry {
                path: full_path,
                size,
                is_dir,
                is_symlink,
                link_target,
            });
        }

        Ok(entries)
    }

    /// Get all entries
    pub fn entries(&self) -> &[IsoEntry] {
        &self.entries
    }

    /// Get volume ID
    pub fn volume_id(&self) -> Option<&str> {
        self.volume_id.as_deref()
    }

    /// Check if a path exists
    pub fn exists(&self, path: &str) -> bool {
        let normalized = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{}", path)
        };
        self.entries.iter().any(|e| e.path == normalized)
    }

    /// Get archive statistics
    pub fn stats(&self) -> IsoStats {
        let mut stats = IsoStats::default();
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
    pub fn symlinks(&self) -> impl Iterator<Item = &IsoEntry> {
        self.entries.iter().filter(|e| e.is_symlink)
    }
}

/// Statistics about an ISO filesystem
#[derive(Debug, Default)]
pub struct IsoStats {
    pub files: usize,
    pub directories: usize,
    pub symlinks: usize,
    pub total_size: u64,
}

/// Get ISO image information
pub fn get_iso_info(path: &Path) -> Result<IsoInfo, FsdbgError> {
    if !path.exists() {
        return Err(FsdbgError::file_not_found(path));
    }

    let output = Command::new("isoinfo")
        .arg("-d")
        .arg("-i")
        .arg(path)
        .output()
        .map_err(|e| FsdbgError::external_tool_failed("isoinfo", e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FsdbgError::external_tool_failed("isoinfo", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_iso_info(&stdout)
}

fn parse_iso_info(output: &str) -> Result<IsoInfo, FsdbgError> {
    let mut info = IsoInfo::default();

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Volume id:") {
            info.volume_id = Some(
                line.strip_prefix("Volume id:")
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            );
        } else if line.starts_with("Volume size is:") {
            if let Some(size_str) = line.split(':').nth(1) {
                let size_str = size_str.trim().split_whitespace().next().unwrap_or("0");
                info.volume_size = size_str.parse().unwrap_or(0);
            }
        } else if line.starts_with("Logical block size is:") {
            if let Some(bs_str) = line.split(':').nth(1) {
                info.block_size = bs_str.trim().parse().unwrap_or(2048);
            }
        } else if line.starts_with("System id:") {
            info.system_id = Some(
                line.strip_prefix("System id:")
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            );
        } else if line.contains("Rock Ridge") && line.contains("YES") {
            info.rock_ridge = true;
        } else if line.contains("El Torito") {
            info.el_torito = true;
        }
    }

    Ok(info)
}

/// ISO image information
#[derive(Debug, Default)]
pub struct IsoInfo {
    pub volume_id: Option<String>,
    pub system_id: Option<String>,
    pub volume_size: u64,
    pub block_size: u32,
    pub rock_ridge: bool,
    pub el_torito: bool,
}
