//! Error types for fsdbg

use std::fmt;
use std::path::PathBuf;

/// Error codes for structured error reporting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// E001: File not found
    FileNotFound = 1,
    /// E002: Invalid archive format
    InvalidFormat = 2,
    /// E003: Broken symlink
    SymlinkBroken = 3,
    /// E004: Missing required file
    MissingRequired = 4,
    /// E005: IO error
    IoError = 5,
    /// E006: External tool failed
    ExternalToolFailed = 6,
    /// E007: Parse error
    ParseError = 7,
    /// E008: Verification failed
    VerificationFailed = 8,
    /// E009: Unsupported format
    UnsupportedFormat = 9,
    /// E010: Invalid argument
    InvalidArgument = 10,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::FileNotFound => write!(f, "E001"),
            ErrorCode::InvalidFormat => write!(f, "E002"),
            ErrorCode::SymlinkBroken => write!(f, "E003"),
            ErrorCode::MissingRequired => write!(f, "E004"),
            ErrorCode::IoError => write!(f, "E005"),
            ErrorCode::ExternalToolFailed => write!(f, "E006"),
            ErrorCode::ParseError => write!(f, "E007"),
            ErrorCode::VerificationFailed => write!(f, "E008"),
            ErrorCode::UnsupportedFormat => write!(f, "E009"),
            ErrorCode::InvalidArgument => write!(f, "E010"),
        }
    }
}

/// Main error type for fsdbg
#[derive(Debug)]
pub struct FsdbgError {
    pub code: ErrorCode,
    pub message: String,
    pub path: Option<PathBuf>,
}

impl FsdbgError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            path: None,
        }
    }

    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn file_not_found(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self::new(ErrorCode::FileNotFound, format!("File not found: {}", path.display()))
            .with_path(path)
    }

    pub fn invalid_format(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidFormat, message)
    }

    pub fn symlink_broken(link: impl Into<String>, target: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::SymlinkBroken,
            format!("Broken symlink: {} -> {}", link.into(), target.into()),
        )
    }

    pub fn missing_required(item: impl Into<String>) -> Self {
        Self::new(ErrorCode::MissingRequired, format!("Missing required: {}", item.into()))
    }

    pub fn external_tool_failed(tool: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::ExternalToolFailed,
            format!("{} failed: {}", tool.into(), message.into()),
        )
    }

    pub fn unsupported_format(format: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnsupportedFormat, format!("Unsupported format: {}", format.into()))
    }
}

impl fmt::Display for FsdbgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)?;
        if let Some(ref path) = self.path {
            write!(f, " ({})", path.display())?;
        }
        Ok(())
    }
}

impl std::error::Error for FsdbgError {}

impl From<std::io::Error> for FsdbgError {
    fn from(err: std::io::Error) -> Self {
        Self::new(ErrorCode::IoError, err.to_string())
    }
}
