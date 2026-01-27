//! Live initramfs checklist
//!
//! Expected contents for the busybox-based live environment initramfs.
//! This is a minimal initramfs that boots into a shell and mounts the EROFS rootfs.
//!
//! SOURCE OF TRUTH:
//! - Kernel modules: `distro-spec/src/shared/modules.rs`
//! - Directories: `tools/recinit/src/tiny.rs`
//! - Busybox applets: `tools/recinit/src/busybox.rs`
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

// =============================================================================
// DIRECTORIES - from recinit/src/tiny.rs INITRAMFS_DIRS
// =============================================================================

/// directories for live initramfs.
/// Must match INITRAMFS_DIRS in recinit/src/tiny.rs
pub const DIRS: &[&str] = &[
    "bin",
    "dev",
    "proc",
    "sys",
    "tmp",
    "mnt",
    "lib/modules",
    "rootfs",
    "overlay",
    "newroot",
    "live-overlay",
];

// =============================================================================
// BUSYBOX - from recinit/src/busybox.rs
// =============================================================================

/// Path to busybox binary.
pub const BUSYBOX_BINARY: &str = "bin/busybox";

/// busybox applets (symlinks to busybox).
/// Must match BUSYBOX_COMMANDS in recinit/src/busybox.rs
///
/// These provide all the shell commands needed for the init script:
/// - Filesystem operations: mount, umount, mkdir, ln, rm, cp, mv
/// - Module loading: insmod, modprobe
/// - Text processing: cat, grep, sed, echo, head
/// - Loop devices: losetup, mount.loop
/// - Decompression: xz, gunzip (for compressed modules)
/// - Root switching: switch_root
pub const APPLETS: &[&str] = &[
    // Shell
    "sh",
    // Filesystem mounting
    "mount",
    "umount",
    // Directory/file operations
    "mkdir",
    "cat",
    "ls",
    "ln",
    "rm",
    "cp",
    "mv",
    "chmod",
    "chown",
    "mknod",
    "find",
    // Text processing
    "echo",
    "grep",
    "sed",
    "head",
    // Control flow
    "test",
    "[",
    "sleep",
    // Module loading
    "insmod",
    "modprobe",
    // Loop device handling
    "losetup",
    "mount.loop",
    // Decompression (for .ko.xz modules)
    "xz",
    "gunzip",
    // Root switching (critical!)
    "switch_root",
];

// =============================================================================
// INIT SCRIPT
// =============================================================================

/// The init script path and requirements.
pub const INIT_PATH: &str = "init";

/// Expected init script shebang.
pub const INIT_SHEBANG: &str = "#!/bin/sh";

/// permissions for init (must be executable).
pub const INIT_PERMS: u32 = 0o755;

// =============================================================================
// KERNEL MODULES - from distro-spec (SINGLE SOURCE OF TRUTH)
// =============================================================================

// Re-export for consumers that expect these here
pub use distro_spec::shared::LIVE_MODULES as MODULES;
pub use distro_spec::shared::LIVE_MODULES_BUILTIN as TYPICALLY_BUILTIN;

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
    // 3. Check busybox applet symlinks
    // =========================================================================
    for applet in APPLETS {
        let applet_path = format!("bin/{}", applet);

        if let Some(entry) = reader.get(&applet_path) {
            if entry.is_symlink() {
                if let Some(ref target) = entry.link_target {
                    if target == "busybox" {
                        report.add(CheckResult::pass(
                            format!("applet: {} -> busybox", applet),
                            CheckCategory::Symlink,
                        ));
                    } else {
                        report.add(CheckResult::fail(
                            format!("applet: {}", applet),
                            CheckCategory::Symlink,
                            format!("Points to '{}' instead of 'busybox'", target),
                        ));
                    }
                } else {
                    report.add(CheckResult::fail(
                        format!("applet: {}", applet),
                        CheckCategory::Symlink,
                        "Symlink has no target",
                    ));
                }
            } else if entry.is_file() {
                // Acceptable: could be a standalone binary
                report.add(CheckResult::pass(
                    format!("applet: {} (standalone)", applet),
                    CheckCategory::Binary,
                ));
            } else {
                report.add(CheckResult::fail(
                    format!("applet: {}", applet),
                    CheckCategory::Symlink,
                    "Exists but is neither symlink nor file",
                ));
            }
        } else {
            report.add(CheckResult::fail(
                format!("applet: {}", applet),
                CheckCategory::Symlink,
                "Missing",
            ));
        }
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
        } else if init.is_symlink() {
            if let Some(ref target) = init.link_target {
                report.add(CheckResult::pass(
                    format!("{} -> {}", INIT_PATH, target),
                    CheckCategory::Symlink,
                ));
            }
        } else {
            report.add(CheckResult::fail(
                INIT_PATH,
                CheckCategory::Binary,
                "Exists but is not a file or symlink",
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
    // 5. Check kernel modules
    // =========================================================================
    for module in MODULES {
        // Search for module in lib/modules/<version>/kernel/...
        let found = reader.entries().iter().any(|e| {
            let path = &e.path;
            path.contains("lib/modules/")
                && (path.ends_with(&format!("{}.ko", module))
                    || path.ends_with(&format!("{}.ko.xz", module))
                    || path.ends_with(&format!("{}.ko.gz", module))
                    || path.ends_with(&format!("{}.ko.zst", module)))
        });

        if found {
            report.add(CheckResult::pass(
                format!("module: {}", module),
                CheckCategory::KernelModule,
            ));
        } else if TYPICALLY_BUILTIN.contains(module) {
            // Don't fail for typically built-in modules
            report.add(CheckResult::pass(
                format!("module: {} (built-in to kernel)", module),
                CheckCategory::KernelModule,
            ));
        } else {
            report.add(CheckResult::fail(
                format!("module: {}", module),
                CheckCategory::KernelModule,
                "Not found (check kernel config if built-in)",
            ));
        }
    }

    // =========================================================================
    // 6. Check for modules.dep (needed by modprobe)
    // =========================================================================
    let has_modules_dep = reader.entries().iter().any(|e| {
        e.path.contains("lib/modules/") && e.path.ends_with("modules.dep")
    });

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
        // Skip applet symlinks we already checked
        if entry.path.starts_with("bin/") && APPLETS.iter().any(|a| entry.path == format!("bin/{}", a)) {
            continue;
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dirs_match_recinit() {
        // Verify we have all the directories from INITRAMFS_DIRS
        assert!(DIRS.contains(&"bin"));
        assert!(DIRS.contains(&"dev"));
        assert!(DIRS.contains(&"proc"));
        assert!(DIRS.contains(&"sys"));
        assert!(DIRS.contains(&"tmp"));
        assert!(DIRS.contains(&"mnt"));
        assert!(DIRS.contains(&"lib/modules"));
        assert!(DIRS.contains(&"rootfs"));
        assert!(DIRS.contains(&"overlay"));
        assert!(DIRS.contains(&"newroot"));
        assert!(DIRS.contains(&"live-overlay"));
    }

    #[test]
    fn test_applets_match_recinit() {
        // Verify critical applets are present
        assert!(APPLETS.contains(&"sh"));
        assert!(APPLETS.contains(&"mount"));
        assert!(APPLETS.contains(&"switch_root"));
        assert!(APPLETS.contains(&"insmod"));
        assert!(APPLETS.contains(&"modprobe"));
        assert!(APPLETS.contains(&"losetup"));
    }

    #[test]
    fn test_modules_for_live_boot() {
        // Verify essential modules for ISO boot
        assert!(MODULES.contains(&"virtio"));
        assert!(MODULES.contains(&"sr_mod"));
        assert!(MODULES.contains(&"isofs"));
        assert!(MODULES.contains(&"loop"));
        assert!(MODULES.contains(&"overlay"));
    }
}
