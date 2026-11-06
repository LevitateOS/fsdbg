//! Install initramfs checklist.
//!
//! What recinit puts into the systemd-based install initramfs is declared in
//! `recinit::payload`; this checks a built archive against those same tables,
//! plus the udev rules device discovery depends on.

use super::{CheckCategory, CheckResult, VerificationReport};
use crate::cpio::CpioReader;

use recinit::payload::{
    ETC_FILES, EXECUTABLES as BINARIES, INIT, INITRD_RELEASE, TMPFILES, UNITS, UNIT_DIR,
    USR_LINKS as SYMLINKS, WANTS,
};

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

/// Directories the image must have: runtime mount points and the module tree.
fn dirs() -> impl Iterator<Item = &'static str> {
    recinit::MOUNT_DIRS.iter().copied().chain(["usr/lib/modules"])
}

/// `.wants` link paths.
fn wants_paths() -> Vec<String> {
    WANTS
        .iter()
        .map(|(target, unit)| format!("{UNIT_DIR}/{target}.wants/{unit}"))
        .collect()
}

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
            report.add(CheckResult::fail(*binary, CheckCategory::Binary, "Missing"));
        }
    }

    // Check systemd units
    for unit in UNITS {
        let unit_path = format!("{UNIT_DIR}/{unit}");
        if reader.exists(&unit_path) {
            report.add(CheckResult::pass(*unit, CheckCategory::Unit));
        } else {
            report.add(CheckResult::fail(*unit, CheckCategory::Unit, "Missing"));
        }
    }

    // Check init (can be symlink to systemd OR a wrapper script that exec's systemd)
    if let Some(entry) = reader.get("init") {
        if entry.is_symlink() {
            // Init is a symlink - must point to systemd
            if let Some(ref target) = entry.link_target {
                if *target == format!("/{INIT}") {
                    report.add(CheckResult::pass(
                        format!("init -> /{INIT}"),
                        CheckCategory::Symlink,
                    ));
                } else {
                    report.add(CheckResult::fail(
                        "init",
                        CheckCategory::Symlink,
                        format!("Symlink points to '{}' instead of systemd", target),
                    ));
                }
            } else {
                report.add(CheckResult::fail(
                    "init",
                    CheckCategory::Symlink,
                    "Symlink has no target",
                ));
            }
        } else if entry.is_file() {
            // Init is a file - must be a script that exec's systemd
            // (This is the dracut-style approach for setting up /run/udev before systemd)
            report.add(CheckResult::pass(
                "init (wrapper script)",
                CheckCategory::Binary,
            ));
        } else {
            report.add(CheckResult::fail(
                "init",
                CheckCategory::Binary,
                "Must be symlink or script file",
            ));
        }
    } else {
        report.add(CheckResult::fail("init", CheckCategory::Binary, "Missing"));
    }

    // Check symlinks (merged-usr symlinks)
    for (link, target) in SYMLINKS {
        if let Some(entry) = reader.get(link) {
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
            report.add(CheckResult::fail(*link, CheckCategory::Symlink, "Missing"));
        }
    }

    // Check /etc files
    for etc_file in ETC_FILES.iter().map(|(path, _)| path).chain([&INITRD_RELEASE]) {
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
    for wants in wants_paths() {
        if reader.exists(&wants) {
            report.add(CheckResult::pass(wants, CheckCategory::Symlink));
        } else {
            report.add(CheckResult::fail(
                wants,
                CheckCategory::Symlink,
                "Missing (service not enabled)",
            ));
        }
    }

    // Check directories
    for dir in dirs() {
        if reader.exists(dir) {
            report.add(CheckResult::pass(dir, CheckCategory::Directory));
        } else {
            report.add(CheckResult::fail(dir, CheckCategory::Directory, "Missing"));
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
        if wants_paths().iter().any(|w| entry.path == *w) {
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
