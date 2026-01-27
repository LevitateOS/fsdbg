//! Install initramfs checklist
//!
//! Expected contents for the systemd-based installation initramfs.
//! Files for `initrd.target` to successfully boot
//! and switch_root to the installed system.
//!
//! SOURCE OF TRUTH:
//! - Kernel modules: `distro-spec/src/shared/modules.rs`
//! - Systemd files: `tools/recinit/src/systemd.rs`
//! - Install structure: `tools/recinit/src/install.rs`

use super::{CheckCategory, CheckResult, VerificationReport};
use crate::cpio::CpioReader;

// =============================================================================
// BINARIES - from recinit/src/systemd.rs SYSTEMD_FILES
// =============================================================================

/// Essential systemd binaries needed for initrd boot.
/// Must match SYSTEMD_FILES in recinit/src/systemd.rs
pub const BINARIES: &[&str] = &[
    // Systemd core
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
    // User commands
    "usr/bin/systemctl",
    "usr/bin/systemd-tmpfiles",
    "usr/bin/udevadm",
    // Module loading
    "usr/sbin/modprobe",
    "usr/sbin/insmod",
    "usr/bin/kmod",
    // Filesystem tools
    "usr/sbin/fsck",
    "usr/sbin/fsck.ext4",
    "usr/sbin/e2fsck",
    "usr/sbin/blkid",
    "usr/bin/mount",
    "usr/bin/umount",
    "usr/sbin/switch_root",
    // Shell
    "usr/bin/bash",
    "usr/bin/sh",
];

// =============================================================================
// SYSTEMD UNITS - from recinit/src/systemd.rs INITRD_UNITS
// =============================================================================

/// Essential initrd systemd units.
/// Must match INITRD_UNITS in recinit/src/systemd.rs
pub const UNITS: &[&str] = &[
    // === Targets ===
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
    // === Services ===
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
    // === Sockets ===
    "systemd-journald.socket",
    "systemd-journald-dev-log.socket",
    "systemd-udevd-control.socket",
    "systemd-udevd-kernel.socket",
    // === Slices ===
    // Note: -.slice and system.slice may be built-in to systemd binary.
    // They're listed in INITRD_UNITS but may not exist as files.
    // "-.slice",
    // "system.slice",
];

// =============================================================================
// SYMLINKS - from recinit/src/install.rs create_install_directory_structure
// =============================================================================

/// Critical symlinks that must exist and resolve.
/// These are the merged-usr symlinks plus init.
pub const SYMLINKS: &[(&str, &str)] = &[
    // Init must point to systemd
    ("init", "/usr/lib/systemd/systemd"),
    // Merged-usr symlinks
    ("bin", "usr/bin"),
    ("sbin", "usr/sbin"),
    ("lib", "usr/lib"),
    ("lib64", "usr/lib64"),
];

// =============================================================================
// /etc FILES - from recinit/src/install.rs build_install_initramfs
// =============================================================================

/// /etc files created by recinit.
pub const ETC_FILES: &[&str] = &[
    "etc/initrd-release",
    "etc/passwd",
    "etc/group",
    "etc/shadow",
    "etc/nsswitch.conf",
];

// =============================================================================
// UDEV RULES - critical rules for device discovery
// =============================================================================

/// Critical udev rules for /dev/disk/by-uuid symlinks.
/// Without these, root=UUID=xxx will not work.
pub const UDEV_RULES: &[&str] = &[
    "50-udev-default.rules",
    "60-block.rules",
    "60-persistent-storage.rules",
    "80-drivers.rules",
    "99-systemd.rules",
];

// =============================================================================
// UDEV HELPERS - from recinit/src/systemd.rs UDEV_HELPERS
// =============================================================================

/// Udev helper programs needed for device identification.
/// Must match UDEV_HELPERS in recinit/src/systemd.rs
pub const UDEV_HELPERS: &[&str] = &[
    "usr/lib/udev/ata_id",
    "usr/lib/udev/scsi_id",
    "usr/lib/udev/cdrom_id",
    "usr/lib/udev/mtd_probe",
    "usr/lib/udev/v4l_id",
];

// =============================================================================
// SYSTEMD GENERATORS - from recinit/src/systemd.rs copy_initrd_units
// =============================================================================

/// Essential systemd generators for parsing root= kernel parameter.
pub const GENERATORS: &[&str] = &[
    "usr/lib/systemd/system-generators/systemd-fstab-generator",
    "usr/lib/systemd/system-generators/systemd-gpt-auto-generator",
    "usr/lib/systemd/system-generators/systemd-debug-generator",
];

// =============================================================================
// TMPFILES.D - from recinit/src/systemd.rs copy_initrd_units
// =============================================================================

/// Essential tmpfiles.d configs for device node creation.
pub const TMPFILES: &[&str] = &[
    "usr/lib/tmpfiles.d/static-nodes-permissions.conf",
    "usr/lib/tmpfiles.d/systemd.conf",
    "usr/lib/tmpfiles.d/tmp.conf",
    "usr/lib/tmpfiles.d/var.conf",
];

// =============================================================================
// .WANTS SYMLINKS - from recinit/src/systemd.rs INITRD_WANTS_SYMLINKS
// =============================================================================

/// Service enablement symlinks in .wants directories.
/// Must match INITRD_WANTS_SYMLINKS in recinit/src/systemd.rs
pub const WANTS_SYMLINKS: &[&str] = &[
    // sysinit.target.wants
    "usr/lib/systemd/system/sysinit.target.wants/systemd-modules-load.service",
    "usr/lib/systemd/system/sysinit.target.wants/systemd-sysctl.service",
    "usr/lib/systemd/system/sysinit.target.wants/systemd-udevd.service",
    "usr/lib/systemd/system/sysinit.target.wants/systemd-udev-trigger.service",
    // sockets.target.wants
    "usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket",
    "usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket",
    "usr/lib/systemd/system/sockets.target.wants/systemd-udevd-control.socket",
    "usr/lib/systemd/system/sockets.target.wants/systemd-udevd-kernel.socket",
    // initrd.target.wants
    "usr/lib/systemd/system/initrd.target.wants/initrd-parse-etc.service",
    "usr/lib/systemd/system/initrd.target.wants/initrd-udevadm-cleanup-db.service",
    // initrd-switch-root.target.wants
    "usr/lib/systemd/system/initrd-switch-root.target.wants/initrd-cleanup.service",
];

// =============================================================================
// DIRECTORIES - from recinit/src/install.rs INSTALL_DIRS
// =============================================================================

/// directories for install initramfs.
/// Must match INSTALL_DIRS in recinit/src/install.rs
pub const DIRS: &[&str] = &[
    // Standard FHS (note: bin, sbin, lib, lib64 are symlinks to usr/*)
    "usr/bin",
    "usr/sbin",
    "usr/lib",
    "usr/lib64",
    "etc",
    "dev",
    "proc",
    "sys",
    "run",
    "tmp",
    "var",
    "var/run",
    // Systemd
    "usr/lib/systemd",
    "usr/lib/systemd/system",
    "usr/lib/systemd/system/initrd.target.wants",
    "usr/lib/systemd/system/sysinit.target.wants",
    "usr/lib/systemd/system-generators",
    "etc/systemd/system",
    // Modules
    "usr/lib/modules",
    // Firmware (if included)
    "usr/lib/firmware",
    // Udev
    "usr/lib/udev",
    "usr/lib/udev/rules.d",
];

// =============================================================================
// KERNEL MODULES - from distro-spec (SINGLE SOURCE OF TRUTH)
// =============================================================================

// Re-export for consumers that expect MODULES here
pub use distro_spec::shared::INSTALL_MODULES as MODULES;
pub use distro_spec::shared::INSTALL_MODULES_BUILTIN as TYPICALLY_BUILTIN;

// =============================================================================
// VERIFICATION
// =============================================================================

/// Verify a CPIO archive against the install initramfs checklist.
pub fn verify(reader: &CpioReader) -> VerificationReport {
    let mut report = VerificationReport::new("Install Initramfs");

    // Check binaries
    for binary in BINARIES {
        if reader.exists(binary) {
            report.add(CheckResult::pass(*binary, CheckCategory::Binary));
        } else {
            report.add(CheckResult::fail(
                *binary,
                CheckCategory::Binary,
                "Missing",
            ));
        }
    }

    // Check systemd units
    for unit in UNITS {
        let unit_path = format!("usr/lib/systemd/system/{}", unit);
        if reader.exists(&unit_path) {
            report.add(CheckResult::pass(*unit, CheckCategory::Unit));
        } else {
            report.add(CheckResult::fail(*unit, CheckCategory::Unit, "Missing"));
        }
    }

    // Check symlinks
    for (link, target) in SYMLINKS {
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
            report.add(CheckResult::fail(
                *link,
                CheckCategory::Symlink,
                "Missing",
            ));
        }
    }

    // Check /etc files
    for etc_file in ETC_FILES {
        if reader.exists(etc_file) {
            report.add(CheckResult::pass(*etc_file, CheckCategory::EtcFile));
        } else {
            report.add(CheckResult::fail(
                *etc_file,
                CheckCategory::EtcFile,
                "Missing",
            ));
        }
    }

    // Check udev rules
    for rule in UDEV_RULES {
        let rule_path = format!("usr/lib/udev/rules.d/{}", rule);
        if reader.exists(&rule_path) {
            report.add(CheckResult::pass(*rule, CheckCategory::UdevRule));
        } else {
            report.add(CheckResult::fail(
                *rule,
                CheckCategory::UdevRule,
                "Missing (CRITICAL for /dev/disk/by-uuid)",
            ));
        }
    }

    // Check udev helpers
    for helper in UDEV_HELPERS {
        if reader.exists(helper) {
            report.add(CheckResult::pass(*helper, CheckCategory::Binary));
        } else {
            report.add(CheckResult::fail(
                *helper,
                CheckCategory::Binary,
                "Missing (udev device identification)",
            ));
        }
    }

    // Check systemd generators
    for generator in GENERATORS {
        if reader.exists(generator) {
            report.add(CheckResult::pass(*generator, CheckCategory::Binary));
        } else {
            report.add(CheckResult::fail(
                *generator,
                CheckCategory::Binary,
                "Missing (for root= parsing)",
            ));
        }
    }

    // Check tmpfiles.d configs
    for tmpfile in TMPFILES {
        if reader.exists(tmpfile) {
            report.add(CheckResult::pass(*tmpfile, CheckCategory::EtcFile));
        } else {
            report.add(CheckResult::fail(
                *tmpfile,
                CheckCategory::EtcFile,
                "Missing (systemd-tmpfiles)",
            ));
        }
    }

    // Check .wants symlinks (service enablement)
    for wants in WANTS_SYMLINKS {
        if reader.exists(wants) {
            report.add(CheckResult::pass(*wants, CheckCategory::Symlink));
        } else {
            report.add(CheckResult::fail(
                *wants,
                CheckCategory::Symlink,
                "Missing (service not enabled)",
            ));
        }
    }

    // Check directories
    for dir in DIRS {
        if reader.exists(dir) {
            report.add(CheckResult::pass(*dir, CheckCategory::Directory));
        } else {
            report.add(CheckResult::fail(*dir, CheckCategory::Directory, "Missing"));
        }
    }

    // Check kernel modules (note: some may be built-in)
    // We look in lib/modules/<version>/kernel/... for .ko, .ko.xz, or .ko.gz files
    for module in MODULES {
        let found = reader.entries().iter().any(|e| {
            let path = &e.path;
            path.contains("lib/modules/")
                && (path.ends_with(&format!("{}.ko", module))
                    || path.ends_with(&format!("{}.ko.xz", module))
                    || path.ends_with(&format!("{}.ko.gz", module))
                    || path.contains(&format!("/{}/", module))
                    || path.contains(&format!("/{}.ko", module)))
        });

        if found {
            report.add(CheckResult::pass(
                format!("module: {}", module),
                CheckCategory::KernelModule,
            ));
        } else if TYPICALLY_BUILTIN.contains(module) {
            // Module is built-in to LevitateOS kernel - not a failure
            report.add(CheckResult::pass(
                format!("module: {} (built-in to kernel)", module),
                CheckCategory::KernelModule,
            ));
        } else {
            // Modules may be built-in to kernel, so this is a warning not failure
            report.add(CheckResult::fail(
                format!("module: {}", module),
                CheckCategory::KernelModule,
                "Not found (check kernel config if built-in)",
            ));
        }
    }

    // Check that all symlinks resolve (library symlinks, etc.)
    for entry in reader.symlinks() {
        // Skip the symlinks we already checked
        if SYMLINKS.iter().any(|(l, _)| *l == entry.path) {
            continue;
        }
        // Skip .wants symlinks we already checked
        if WANTS_SYMLINKS
            .iter()
            .any(|w| entry.path.ends_with(w.rsplit('/').next().unwrap_or("")))
        {
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
