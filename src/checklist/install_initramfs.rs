//! Install initramfs checklist
//!
//! Expected contents for the systemd-based installation initramfs.
//! These are the files required for `initrd.target` to successfully boot
//! and switch_root to the installed system.

use super::{CheckCategory, CheckResult, VerificationReport};
use crate::cpio::CpioReader;

/// Essential systemd binaries
pub const REQUIRED_BINARIES: &[&str] = &[
    "usr/lib/systemd/systemd",
    "usr/lib/systemd/systemd-udevd",
    "usr/lib/systemd/systemd-journald",
    "usr/lib/systemd/systemd-modules-load",
    "usr/lib/systemd/systemd-sysctl",
    "usr/lib/systemd/systemd-fsck",
    "usr/lib/systemd/systemd-remount-fs",
    "usr/lib/systemd/systemd-sulogin-shell",
    "usr/lib/systemd/systemd-shutdown",
    "usr/lib/systemd/systemd-executor",
    "usr/lib/systemd/systemd-makefs",
    "usr/bin/systemctl",
    "usr/bin/systemd-tmpfiles",
    "usr/bin/udevadm",
    "usr/sbin/modprobe",
    "usr/sbin/insmod",
    "usr/bin/kmod",
    "usr/sbin/fsck",
    "usr/sbin/fsck.ext4",
    "usr/sbin/e2fsck",
    "usr/sbin/blkid",
    "usr/bin/mount",
    "usr/bin/umount",
    "usr/sbin/switch_root",
    "usr/bin/bash",
    "usr/bin/sh",
];

/// Essential systemd units
pub const REQUIRED_UNITS: &[&str] = &[
    // Targets
    "initrd.target",
    "initrd-root-fs.target",
    "initrd-root-device.target",
    "initrd-switch-root.target",
    "initrd-fs.target",
    "sysinit.target",
    "basic.target",
    "local-fs.target",
    "local-fs-pre.target",
    "slices.target",
    "sockets.target",
    "paths.target",
    "timers.target",
    "swap.target",
    "emergency.target",
    "rescue.target",
    // Services
    "systemd-journald.service",
    "systemd-udevd.service",
    "systemd-udev-trigger.service",
    "systemd-modules-load.service",
    "systemd-sysctl.service",
    "systemd-fsck@.service",
    "systemd-fsck-root.service",
    "systemd-remount-fs.service",
    "initrd-switch-root.service",
    "initrd-cleanup.service",
    "initrd-udevadm-cleanup-db.service",
    "initrd-parse-etc.service",
    // Sockets
    "systemd-journald.socket",
    "systemd-journald-dev-log.socket",
    "systemd-udevd-control.socket",
    "systemd-udevd-kernel.socket",
    // Note: -.slice and system.slice are built-in systemd units (compiled into systemd binary)
    // They don't exist as files on disk and don't need to be in the initramfs
];

/// Critical symlinks that must exist and resolve
pub const REQUIRED_SYMLINKS: &[(&str, &str)] = &[
    ("init", "/usr/lib/systemd/systemd"),
    ("bin", "usr/bin"),
    ("sbin", "usr/sbin"),
    ("lib", "usr/lib"),
    ("lib64", "usr/lib64"),
];

/// Required /etc files
pub const REQUIRED_ETC: &[&str] = &[
    "etc/initrd-release",
    "etc/passwd",
    "etc/group",
    "etc/shadow",
    "etc/nsswitch.conf",
];

/// Critical udev rules for device discovery
pub const REQUIRED_UDEV_RULES: &[&str] = &[
    "60-persistent-storage.rules",
    "80-drivers.rules",
];

/// Required directories
pub const REQUIRED_DIRS: &[&str] = &[
    "dev",
    "proc",
    "sys",
    "run",
    "tmp",
    "usr",
    "usr/bin",
    "usr/sbin",
    "usr/lib",
    "usr/lib/systemd",
    "usr/lib/systemd/system",
    "etc",
];

/// Verify a CPIO archive against the install initramfs checklist
pub fn verify(reader: &CpioReader) -> VerificationReport {
    let mut report = VerificationReport::new("Install Initramfs");

    // Check binaries
    for binary in REQUIRED_BINARIES {
        if reader.exists(binary) {
            report.add(CheckResult::pass(*binary, CheckCategory::Binary));
        } else {
            report.add(
                CheckResult::fail(*binary, CheckCategory::Binary, "Missing")
                    ,
            );
        }
    }

    // Check units
    for unit in REQUIRED_UNITS {
        let unit_path = format!("usr/lib/systemd/system/{}", unit);
        if reader.exists(&unit_path) {
            report.add(CheckResult::pass(*unit, CheckCategory::Unit));
        } else {
            report.add(
                CheckResult::fail(*unit, CheckCategory::Unit, "Missing")
                    ,
            );
        }
    }

    // Check symlinks
    for (link, target) in REQUIRED_SYMLINKS {
        if let Some(entry) = reader.get(*link) {
            if entry.is_symlink() {
                if let Some(ref actual_target) = entry.link_target {
                    if actual_target == *target {
                        report.add(CheckResult::pass(
                            format!("{} -> {}", link, target),
                            CheckCategory::Symlink,
                        ));
                    } else {
                        report.add(CheckResult::fail(
                            format!("{} -> {}", link, target),
                            CheckCategory::Symlink,
                            format!("Points to '{}' instead", actual_target),
                        ));
                    }
                } else {
                    report.add(CheckResult::fail(
                        format!("{} -> {}", link, target),
                        CheckCategory::Symlink,
                        "Symlink has no target",
                    ));
                }
            } else {
                report.add(CheckResult::fail(
                    *link,
                    CheckCategory::Symlink,
                    "Exists but is not a symlink",
                ));
            }
        } else {
            report.add(
                CheckResult::fail(*link, CheckCategory::Symlink, "Missing")
                    ,
            );
        }
    }

    // Check /etc files
    for etc_file in REQUIRED_ETC {
        if reader.exists(etc_file) {
            report.add(CheckResult::pass(*etc_file, CheckCategory::EtcFile));
        } else {
            report.add(
                CheckResult::fail(*etc_file, CheckCategory::EtcFile, "Missing")
                    ,
            );
        }
    }

    // Check udev rules
    for rule in REQUIRED_UDEV_RULES {
        let rule_path = format!("usr/lib/udev/rules.d/{}", rule);
        if reader.exists(&rule_path) {
            report.add(CheckResult::pass(*rule, CheckCategory::UdevRule));
        } else {
            report.add(
                CheckResult::fail(*rule, CheckCategory::UdevRule, "Missing (CRITICAL for /dev/disk/by-uuid)")
                    ,
            );
        }
    }

    // Check directories
    for dir in REQUIRED_DIRS {
        if reader.exists(dir) {
            report.add(CheckResult::pass(*dir, CheckCategory::Directory));
        } else {
            report.add(
                CheckResult::fail(*dir, CheckCategory::Directory, "Missing"),
            );
        }
    }

    // Check that all symlinks resolve (library symlinks, etc.)
    for entry in reader.symlinks() {
        // Skip the required symlinks we already checked
        if REQUIRED_SYMLINKS.iter().any(|(l, _)| *l == entry.path) {
            continue;
        }

        if !reader.symlink_target_exists(entry) {
            if let Some(ref target) = entry.link_target {
                report.add(CheckResult::fail(
                    format!("{} -> {}", entry.path, target),
                    CheckCategory::Library,
                    "Target does not exist in archive",
                ));
            }
        }
    }

    report
}
