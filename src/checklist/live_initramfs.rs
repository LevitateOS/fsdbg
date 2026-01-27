//! Live initramfs checklist
//!
//! Expected contents for the busybox-based live environment initramfs.
//! This is a minimal initramfs that boots into a shell and mounts the squashfs.

use super::{CheckCategory, CheckResult, VerificationReport};
use crate::cpio::CpioReader;

/// Required binaries for live boot
pub const REQUIRED_BINARIES: &[&str] = &["init", "bin/busybox"];

/// Required directories for live initramfs
pub const REQUIRED_DIRS: &[&str] = &["dev", "proc", "sys", "mnt", "newroot"];

/// Required busybox applets (must have symlinks)
pub const REQUIRED_APPLETS: &[&str] = &["sh", "mount", "mkdir", "cat", "echo", "switch_root"];

/// Verify a CPIO archive against the live initramfs checklist
pub fn verify(reader: &CpioReader) -> VerificationReport {
    let mut report = VerificationReport::new("Live Initramfs");

    // Check required binaries
    for binary in REQUIRED_BINARIES {
        if reader.exists(binary) {
            report.add(CheckResult::pass(*binary, CheckCategory::Binary));
        } else {
            report.add(CheckResult::fail(*binary, CheckCategory::Binary, "Missing"));
        }
    }

    // Check required directories
    for dir in REQUIRED_DIRS {
        if reader.exists(dir) {
            report.add(CheckResult::pass(*dir, CheckCategory::Directory));
        } else {
            report.add(CheckResult::fail(*dir, CheckCategory::Directory, "Missing"));
        }
    }

    // Check that init is executable
    if let Some(init) = reader.get("init") {
        if init.is_file() {
            let perms = init.permissions();
            if perms & 0o111 != 0 {
                report.add(CheckResult::pass("init is executable", CheckCategory::Other));
            } else {
                report.add(CheckResult::fail(
                    "init permissions",
                    CheckCategory::Other,
                    format!("init is not executable (mode {:o})", perms),
                ));
            }
        } else if init.is_symlink() {
            if let Some(ref target) = init.link_target {
                report.add(CheckResult::pass(
                    format!("init -> {}", target),
                    CheckCategory::Symlink,
                ));
            }
        }
    }

    // Check required busybox applets
    for applet in REQUIRED_APPLETS {
        let paths_to_check = [
            applet.to_string(),
            format!("bin/{}", applet),
            format!("sbin/{}", applet),
            format!("usr/bin/{}", applet),
            format!("usr/sbin/{}", applet),
        ];

        let found = paths_to_check.iter().any(|p| reader.exists(p));
        if found {
            report.add(CheckResult::pass(
                format!("applet: {}", applet),
                CheckCategory::Binary,
            ));
        } else {
            report.add(CheckResult::fail(
                format!("applet: {}", applet),
                CheckCategory::Binary,
                "Missing",
            ));
        }
    }

    report
}
