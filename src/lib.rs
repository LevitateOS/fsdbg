//! fsdbg - Filesystem debugging tool for LevitateOS artifacts
//!
//! Provides inspection and verification of CPIO, EROFS, and ISO archives
//! without requiring extraction or root privileges.

pub mod checklist;
pub mod cpio;
pub mod erofs;
pub mod error;
pub mod iso;

pub use error::{ErrorCode, FsdbgError};

use std::path::Path;

/// Archive format detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    /// CPIO archive (gzip compressed)
    CpioGzip,
    /// CPIO archive (uncompressed)
    Cpio,
    /// EROFS filesystem image
    Erofs,
    /// ISO 9660 image
    Iso,
}

impl std::fmt::Display for ArchiveFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchiveFormat::CpioGzip => write!(f, "CPIO (gzip compressed)"),
            ArchiveFormat::Cpio => write!(f, "CPIO (uncompressed)"),
            ArchiveFormat::Erofs => write!(f, "EROFS"),
            ArchiveFormat::Iso => write!(f, "ISO 9660"),
        }
    }
}

/// Detect archive format from file
pub fn detect_format(path: &Path) -> Result<ArchiveFormat, FsdbgError> {
    use std::fs::File;
    use std::io::Read;

    if !path.exists() {
        return Err(FsdbgError::file_not_found(path));
    }

    let mut file = File::open(path)?;
    let mut magic = [0u8; 1024 + 4]; // Need up to offset 1024 for EROFS
    let bytes_read = file.read(&mut magic)?;

    // Check gzip magic (1f 8b)
    if bytes_read >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
        return Ok(ArchiveFormat::CpioGzip);
    }

    // Check CPIO newc magic "070701"
    if bytes_read >= 6 {
        let cpio_magic = std::str::from_utf8(&magic[0..6]).unwrap_or("");
        if cpio_magic == "070701" || cpio_magic == "070702" {
            return Ok(ArchiveFormat::Cpio);
        }
    }

    // Check ISO 9660 magic at offset 0x8001 ("CD001")
    // But first check simpler extension-based detection for .iso files
    if let Some(ext) = path.extension() {
        if ext == "iso" {
            // Read at offset 0x8001
            use std::io::Seek;
            file.seek(std::io::SeekFrom::Start(0x8001))?;
            let mut iso_magic = [0u8; 5];
            if file.read(&mut iso_magic)? == 5 && &iso_magic == b"CD001" {
                return Ok(ArchiveFormat::Iso);
            }
        }
    }

    // Check EROFS magic at offset 1024 (0xe2f5 in little-endian)
    if bytes_read >= 1024 + 4 {
        let erofs_magic = u32::from_le_bytes([magic[1024], magic[1025], magic[1026], magic[1027]]);
        if erofs_magic == 0xe0f5e1e2 {
            return Ok(ArchiveFormat::Erofs);
        }
    }

    // Fallback: check file extension
    if let Some(ext) = path.extension() {
        match ext.to_str() {
            Some("img") | Some("cpio") => return Ok(ArchiveFormat::Cpio),
            Some("erofs") => return Ok(ArchiveFormat::Erofs),
            Some("iso") => return Ok(ArchiveFormat::Iso),
            _ => {}
        }
    }

    Err(FsdbgError::invalid_format(format!(
        "Could not detect format for: {}",
        path.display()
    )))
}
