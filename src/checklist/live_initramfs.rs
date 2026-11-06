//! Live initramfs checklist
//!
//! Expected contents for the busybox-based live environment initramfs.
//! This is a minimal initramfs that boots into a shell and mounts the EROFS rootfs.
//!
//! Directories come from recinit itself (`recinit::INITRAMFS_DIRS`).
//!
//! ## Boot Process
//!
//! 1. Kernel loads initramfs into memory
//! 2. /init script runs (busybox sh)
//! 3. Mounts devtmpfs, proc, sysfs
//! 4. Loads kernel modules for storage access
//! 5. Probes boot devices to find ISO
//! 6. Mounts ISO filesystem (isofs)
//! 7. Mounts EROFS rootfs from ISO
//! 8. Sets up overlay for writable layer
//! 9. switch_root to live system

use super::{CheckCategory, CheckResult, VerificationReport};
use crate::cpio::CpioReader;

use recinit::INITRAMFS_DIRS as DIRS;

// =============================================================================
// BUSYBOX - from recinit/src/busybox.rs
// =============================================================================

/// Path to busybox binary.
pub const BUSYBOX_BINARY: &str = "bin/busybox";


// =============================================================================
// INIT SCRIPT
// =============================================================================

/// The init script path and requirements.
pub const INIT_PATH: &str = "init";

/// permissions for init (must be executable).
pub const INIT_PERMS: u32 = 0o755;

// =============================================================================
// KERNEL MODULES - the live initramfs set recinit installs
// =============================================================================

// Re-export for consumers that expect these here
pub use recinit::LIVE_MODULES as MODULES;

// =============================================================================
// VERIFICATION
// =============================================================================

/// Verify a CPIO archive against the live initramfs checklist.
pub fn verify(reader: &CpioReader) -> VerificationReport {
    let mut report = VerificationReport::new("Live Initramfs");

    // =========================================================================
    // 1. Check directory structure
    // =========================================================================
    for dir in DIRS {
        if reader.exists(dir) {
            report.add(CheckResult::pass(*dir, CheckCategory::Directory));
        } else {
            report.add(CheckResult::fail(*dir, CheckCategory::Directory, "Missing"));
        }
    }

    // =========================================================================
    // 2. Check busybox binary
    // =========================================================================
    if let Some(busybox) = reader.get(BUSYBOX_BINARY) {
        if busybox.is_file() {
            let perms = busybox.permissions();
            if perms & 0o111 != 0 {
                report.add(CheckResult::pass(
                    format!("{} (executable)", BUSYBOX_BINARY),
                    CheckCategory::Binary,
                ));
            } else {
                report.add(CheckResult::fail(
                    BUSYBOX_BINARY,
                    CheckCategory::Binary,
                    format!("Not executable (mode {:04o})", perms),
                ));
            }
        } else {
            report.add(CheckResult::fail(
                BUSYBOX_BINARY,
                CheckCategory::Binary,
                "Exists but is not a regular file",
            ));
        }
    } else {
        report.add(CheckResult::fail(
            BUSYBOX_BINARY,
            CheckCategory::Binary,
            "Missing (CRITICAL: no shell commands available)",
        ));
    }

    // =========================================================================
    // 4. Check init script
    // =========================================================================
    if let Some(init) = reader.get(INIT_PATH) {
        if init.is_file() {
            let perms = init.permissions();
            if perms & 0o111 != 0 {
                report.add(CheckResult::pass(
                    format!("{} (executable, mode {:04o})", INIT_PATH, perms),
                    CheckCategory::Binary,
                ));
            } else {
                report.add(CheckResult::fail(
                    INIT_PATH,
                    CheckCategory::Binary,
                    format!(
                        "Not executable (mode {:04o}, need {:04o})",
                        perms, INIT_PERMS
                    ),
                ));
            }
        } else {
            report.add(CheckResult::fail(
                INIT_PATH,
                CheckCategory::Binary,
                "Must be the init script recinit writes (a regular file)",
            ));
        }
    } else {
        report.add(CheckResult::fail(
            INIT_PATH,
            CheckCategory::Binary,
            "Missing (CRITICAL: kernel will panic)",
        ));
    }

    // =========================================================================
    // 6. Check for modules.dep (needed by modprobe)
    // =========================================================================
    let has_modules_dep = reader
        .entries()
        .iter()
        .any(|e| e.path.contains("lib/modules/") && e.path.ends_with("modules.dep"));

    if has_modules_dep {
        report.add(CheckResult::pass("modules.dep", CheckCategory::EtcFile));
    } else {
        // Not critical for insmod (which loads directly), but needed for modprobe
        report.add(CheckResult::fail(
            "modules.dep",
            CheckCategory::EtcFile,
            "Missing (modprobe won't work, but insmod will)",
        ));
    }

    // =========================================================================
    // 7. Check that all symlinks resolve
    // =========================================================================
    for entry in reader.symlinks() {
        if !reader.symlink_target_exists(entry) {
            if let Some(ref target) = entry.link_target {
                report.add(CheckResult::fail(
                    format!("{} -> {}", entry.path, target),
                    CheckCategory::Symlink,
                    "Target does not exist in archive",
                ));
            }
        }
    }

    report
}
