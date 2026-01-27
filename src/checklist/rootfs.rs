//! Rootfs checklist
//!
//! Expected contents for a complete LevitateOS rootfs.
//! This covers the full system after installation.

use super::{CheckCategory, CheckResult, VerificationReport};
use crate::cpio::CpioReader;

/// Core system binaries
pub const REQUIRED_BINARIES: &[&str] = &[
    // Init system
    "usr/lib/systemd/systemd",
    "usr/bin/systemctl",
    "usr/bin/journalctl",
    // Core utilities
    "usr/bin/bash",
    "usr/bin/sh",
    "usr/bin/cat",
    "usr/bin/ls",
    "usr/bin/cp",
    "usr/bin/mv",
    "usr/bin/rm",
    "usr/bin/mkdir",
    "usr/bin/chmod",
    "usr/bin/chown",
    // System tools
    "usr/bin/mount",
    "usr/bin/umount",
    "usr/sbin/blkid",
    "usr/sbin/fdisk",
    // Network (basic)
    "usr/bin/ip",
    "usr/bin/ping",
    // Package manager
    "usr/bin/recipe",
];

/// Essential systemd units
pub const REQUIRED_UNITS: &[&str] = &[
    "multi-user.target",
    "graphical.target",
    "getty@.service",
    "systemd-logind.service",
    "dbus.service",
    "network.target",
];

/// Required directories
pub const REQUIRED_DIRS: &[&str] = &[
    "bin",
    "boot",
    "dev",
    "etc",
    "home",
    "lib",
    "lib64",
    "mnt",
    "opt",
    "proc",
    "root",
    "run",
    "sbin",
    "srv",
    "sys",
    "tmp",
    "usr",
    "usr/bin",
    "usr/lib",
    "usr/lib64",
    "usr/sbin",
    "usr/share",
    "var",
    "var/log",
    "var/tmp",
];

/// Essential /etc files
pub const REQUIRED_ETC: &[&str] = &[
    "etc/passwd",
    "etc/group",
    "etc/shadow",
    "etc/fstab",
    "etc/hostname",
    "etc/hosts",
    "etc/os-release",
    "etc/nsswitch.conf",
    "etc/ld.so.conf",
];

/// Verify a CPIO archive against the rootfs checklist
pub fn verify(reader: &CpioReader) -> VerificationReport {
    let mut report = VerificationReport::new("Rootfs");

    // Check binaries
    for binary in REQUIRED_BINARIES {
        if reader.exists(binary) {
            report.add(CheckResult::pass(*binary, CheckCategory::Binary));
        } else {
            report.add(CheckResult::fail(*binary, CheckCategory::Binary, "Missing"));
        }
    }

    // Check units
    for unit in REQUIRED_UNITS {
        let unit_path = format!("usr/lib/systemd/system/{}", unit);
        if reader.exists(&unit_path) {
            report.add(CheckResult::pass(*unit, CheckCategory::Unit));
        } else {
            report.add(CheckResult::fail(*unit, CheckCategory::Unit, "Missing"));
        }
    }

    // Check directories
    for dir in REQUIRED_DIRS {
        if reader.exists(dir) {
            report.add(CheckResult::pass(*dir, CheckCategory::Directory));
        } else {
            report.add(CheckResult::fail(*dir, CheckCategory::Directory, "Missing"));
        }
    }

    // Check /etc files
    for etc_file in REQUIRED_ETC {
        if reader.exists(etc_file) {
            report.add(CheckResult::pass(*etc_file, CheckCategory::EtcFile));
        } else {
            report.add(CheckResult::fail(*etc_file, CheckCategory::EtcFile, "Missing"));
        }
    }

    report
}
