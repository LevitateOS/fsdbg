//! Verification checklists for filesystem artifacts
//!
//! Provides expected content definitions for different artifact types.

pub mod auth_audit;
pub mod install_initramfs;
pub mod iso;
pub mod live_initramfs;
pub mod qcow2;
pub mod rootfs;

use std::fmt;

/// A verification check result
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub item: String,
    pub passed: bool,
    pub message: Option<String>,
    pub category: CheckCategory,
}

impl CheckResult {
    pub fn pass(item: impl Into<String>, category: CheckCategory) -> Self {
        Self {
            item: item.into(),
            passed: true,
            message: None,
            category,
        }
    }

    pub fn fail(item: impl Into<String>, category: CheckCategory, message: impl Into<String>) -> Self {
        Self {
            item: item.into(),
            passed: false,
            message: Some(message.into()),
            category,
        }
    }
}

/// Category of check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckCategory {
    Binary,
    Unit,
    Symlink,
    EtcFile,
    UdevRule,
    Directory,
    Library,
    KernelModule,
    License,
    /// Items that MUST NOT be present (e.g., busybox in live rootfs)
    Forbidden,
    Other,
}

impl fmt::Display for CheckCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckCategory::Binary => write!(f, "Binaries"),
            CheckCategory::Unit => write!(f, "Systemd Units"),
            CheckCategory::Symlink => write!(f, "Symlinks"),
            CheckCategory::EtcFile => write!(f, "/etc Files"),
            CheckCategory::UdevRule => write!(f, "Udev Rules"),
            CheckCategory::Directory => write!(f, "Directories"),
            CheckCategory::Library => write!(f, "Libraries"),
            CheckCategory::KernelModule => write!(f, "Kernel Modules"),
            CheckCategory::License => write!(f, "Licenses"),
            CheckCategory::Forbidden => write!(f, "FORBIDDEN (must NOT exist)"),
            CheckCategory::Other => write!(f, "Other"),
        }
    }
}

/// Verification report
#[derive(Debug, Default)]
pub struct VerificationReport {
    pub results: Vec<CheckResult>,
    pub artifact_type: String,
}

impl VerificationReport {
    pub fn new(artifact_type: impl Into<String>) -> Self {
        Self {
            results: Vec::new(),
            artifact_type: artifact_type.into(),
        }
    }

    pub fn add(&mut self, result: CheckResult) {
        self.results.push(result);
    }

    pub fn passed(&self) -> usize {
        self.results.iter().filter(|r| r.passed).count()
    }

    pub fn failed(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }

    pub fn total(&self) -> usize {
        self.results.len()
    }

    pub fn is_success(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }

    /// Group results by category
    pub fn by_category(&self) -> Vec<(CheckCategory, Vec<&CheckResult>)> {
        use std::collections::BTreeMap;

        let mut groups: BTreeMap<u8, (CheckCategory, Vec<&CheckResult>)> = BTreeMap::new();

        for result in &self.results {
            let key = match result.category {
                CheckCategory::Binary => 0,
                CheckCategory::Unit => 1,
                CheckCategory::Symlink => 2,
                CheckCategory::EtcFile => 3,
                CheckCategory::UdevRule => 4,
                CheckCategory::Directory => 5,
                CheckCategory::Library => 6,
                CheckCategory::KernelModule => 7,
                CheckCategory::License => 8,
                CheckCategory::Forbidden => 9,
                CheckCategory::Other => 10,
            };
            groups
                .entry(key)
                .or_insert((result.category, Vec::new()))
                .1
                .push(result);
        }

        groups.into_values().collect()
    }
}

/// Checklist type for verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecklistType {
    /// Install initramfs (systemd-based, for actual installation)
    InstallInitramfs,
    /// Live initramfs (busybox-based, for live environment)
    LiveInitramfs,
    /// Full rootfs
    Rootfs,
    /// Live ISO image
    Iso,
    /// Authentication audit (PAM, sudo, login security)
    AuthAudit,
    /// Qcow2 VM image (mounted filesystem)
    Qcow2,
}

impl ChecklistType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "install-initramfs" | "install_initramfs" | "install" => {
                Some(ChecklistType::InstallInitramfs)
            }
            "live-initramfs" | "live_initramfs" | "live" => Some(ChecklistType::LiveInitramfs),
            "rootfs" | "root" => Some(ChecklistType::Rootfs),
            "iso" => Some(ChecklistType::Iso),
            "auth-audit" | "auth_audit" | "auth" => Some(ChecklistType::AuthAudit),
            "qcow2" | "qcow" | "vm" => Some(ChecklistType::Qcow2),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ChecklistType::InstallInitramfs => "Install Initramfs",
            ChecklistType::LiveInitramfs => "Live Initramfs",
            ChecklistType::Rootfs => "Rootfs",
            ChecklistType::Iso => "Live ISO",
            ChecklistType::AuthAudit => "Authentication Audit",
            ChecklistType::Qcow2 => "Qcow2 Image",
        }
    }
}

impl fmt::Display for ChecklistType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}
