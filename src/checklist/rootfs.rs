//! Rootfs checklist
//!
//! Expected contents for a complete LevitateOS rootfs (EROFS image).
//! This covers the full system after installation - a daily driver desktop OS.
//!
//! ## Single Source of Truth
//!
//! All lists are imported from `distro-spec/src/shared/components.rs`.
//! To add new requirements, edit that file - both leviso and fsdbg will pick up the change.
//!
//! ## Philosophy
//!
//! LevitateOS is a daily driver Linux distribution competing with Arch Linux.
//! It is NOT minimal - if something is missing that a desktop user needs, that's a BUG.

use super::{CheckCategory, CheckResult, VerificationReport};
use crate::cpio::CpioReader;
use std::collections::HashSet;

// Import from SINGLE SOURCE OF TRUTH
use distro_spec::shared::{
    FHS_DIRS, FHS_SYMLINKS,
    BIN_UTILS, AUTH_BIN, SSH_BIN, NM_BIN,
    SBIN_UTILS, AUTH_SBIN, SHADOW_SBIN, NM_SBIN, WPA_SBIN, SSH_SBIN,
    BLUETOOTH_SBIN, PIPEWIRE_SBIN, POLKIT_SBIN, UDISKS_SBIN, UPOWER_SBIN,
    SYSTEMD_BINARIES,
    ESSENTIAL_UNITS, NM_UNITS, WPA_UNITS,
    BLUETOOTH_UNITS, PIPEWIRE_UNITS, POLKIT_UNITS, UDISKS_UNITS, UPOWER_UNITS,
    UDEV_HELPERS,
    PAM_MODULES, PAM_CONFIGS, SECURITY_FILES,
    ETC_FILES,
    CRITICAL_LIBS,
};

// Re-export for backwards compatibility with any external consumers
pub use distro_spec::shared::{
    FHS_DIRS as DIRS,
    FHS_SYMLINKS as SYMLINKS,
    CRITICAL_LIBS as LIBS,
    SYSTEM_USERS as USERS,
    SYSTEM_GROUPS as GROUPS,
};

// =============================================================================
// COMBINED LISTS (for verification)
// =============================================================================

/// Systemd binaries that should exist in /usr/lib/systemd/.
/// Note: "systemd" itself is added during verification.
pub const SYSTEMD_BINS: &[&str] = SYSTEMD_BINARIES;

// =============================================================================
// VERIFICATION
// =============================================================================

/// Verify a CPIO/EROFS archive against the rootfs checklist.
pub fn verify(reader: &CpioReader) -> VerificationReport {
    let mut report = VerificationReport::new("Rootfs");

    // =========================================================================
    // 1. Check directory structure
    // =========================================================================
    for dir in FHS_DIRS {
        if reader.exists(dir) {
            report.add(CheckResult::pass(*dir, CheckCategory::Directory));
        } else {
            report.add(CheckResult::fail(*dir, CheckCategory::Directory, "Missing"));
        }
    }

    // =========================================================================
    // 2. Check merged-usr symlinks
    // =========================================================================
    for (link, target) in FHS_SYMLINKS {
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
                }
            } else {
                report.add(CheckResult::fail(
                    *link,
                    CheckCategory::Symlink,
                    "Exists but is not a symlink (merged-usr broken)",
                ));
            }
        } else {
            report.add(CheckResult::fail(
                *link,
                CheckCategory::Symlink,
                "Missing (merged-usr broken)",
            ));
        }
    }

    // =========================================================================
    // 3. Check /usr/bin binaries
    // =========================================================================
    // Combine all bin lists
    let all_bins: Vec<&str> = BIN_UTILS.iter()
        .chain(AUTH_BIN.iter())
        .chain(SSH_BIN.iter())
        .chain(NM_BIN.iter())
        .copied()
        .collect();

    // Also need bash which is handled separately in leviso
    let mut bins_to_check = all_bins;
    if !bins_to_check.contains(&"bash") {
        bins_to_check.push("bash");
    }
    // openssl is needed for password hashing
    if !bins_to_check.contains(&"openssl") {
        bins_to_check.push("openssl");
    }

    for bin in &bins_to_check {
        let bin_path = format!("usr/bin/{}", bin);
        if reader.exists(&bin_path) {
            report.add(CheckResult::pass(bin_path, CheckCategory::Binary));
        } else {
            report.add(CheckResult::fail(
                bin_path,
                CheckCategory::Binary,
                "Missing",
            ));
        }
    }

    // =========================================================================
    // 4. Check /usr/sbin binaries
    // =========================================================================
    let all_sbins: Vec<&str> = SBIN_UTILS.iter()
        .chain(AUTH_SBIN.iter())
        .chain(SHADOW_SBIN.iter())
        .chain(NM_SBIN.iter())
        .chain(WPA_SBIN.iter())
        .chain(SSH_SBIN.iter())
        .chain(BLUETOOTH_SBIN.iter())
        .chain(PIPEWIRE_SBIN.iter())
        .chain(POLKIT_SBIN.iter())
        .chain(UDISKS_SBIN.iter())
        .chain(UPOWER_SBIN.iter())
        .copied()
        .collect();

    for sbin in &all_sbins {
        let sbin_path = format!("usr/sbin/{}", sbin);
        if reader.exists(&sbin_path) {
            report.add(CheckResult::pass(sbin_path, CheckCategory::Binary));
        } else {
            report.add(CheckResult::fail(
                sbin_path,
                CheckCategory::Binary,
                "Missing",
            ));
        }
    }

    // =========================================================================
    // 5. Check systemd binaries
    // =========================================================================
    // systemd itself plus all helpers
    let systemd_bins_to_check: Vec<&str> = std::iter::once("systemd")
        .chain(SYSTEMD_BINARIES.iter().copied())
        // Filter out networkd/resolved - LevitateOS uses NetworkManager
        .filter(|b| *b != "systemd-networkd" && *b != "systemd-resolved")
        .collect();

    for systemd_bin in &systemd_bins_to_check {
        let systemd_path = format!("usr/lib/systemd/{}", systemd_bin);
        if reader.exists(&systemd_path) {
            report.add(CheckResult::pass(systemd_path, CheckCategory::Binary));
        } else {
            report.add(CheckResult::fail(
                systemd_path,
                CheckCategory::Binary,
                "Missing",
            ));
        }
    }

    // =========================================================================
    // 6. Check systemd units
    // =========================================================================
    // Combine all unit lists, filtering out NetworkManager-specific ones that may vary
    let all_units: Vec<&str> = ESSENTIAL_UNITS.iter()
        .chain(NM_UNITS.iter())
        .chain(WPA_UNITS.iter())
        .chain(BLUETOOTH_UNITS.iter())
        .chain(POLKIT_UNITS.iter())
        .chain(UDISKS_UNITS.iter())
        .chain(UPOWER_UNITS.iter())
        .copied()
        // Filter out systemd-networkd/resolved units - LevitateOS uses NetworkManager
        .filter(|u| !u.contains("networkd") && !u.contains("resolved"))
        // Filter out system.slice - auto-generated at runtime
        .filter(|u| *u != "system.slice")
        .collect();

    // PipeWire units are in user/ directory, not system/
    let pipewire_user_units: Vec<&str> = PIPEWIRE_UNITS.iter().copied().collect();

    for unit in &all_units {
        let unit_path = format!("usr/lib/systemd/system/{}", unit);
        if reader.exists(&unit_path) {
            report.add(CheckResult::pass(*unit, CheckCategory::Unit));
        } else {
            report.add(CheckResult::fail(*unit, CheckCategory::Unit, "Missing"));
        }
    }

    // Check PipeWire user units (in user/ directory)
    for unit in &pipewire_user_units {
        let unit_path = format!("usr/lib/systemd/user/{}", unit);
        if reader.exists(&unit_path) {
            report.add(CheckResult::pass(format!("user/{}", unit), CheckCategory::Unit));
        } else {
            report.add(CheckResult::fail(
                format!("user/{}", unit),
                CheckCategory::Unit,
                "Missing (PipeWire audio broken)",
            ));
        }
    }

    // =========================================================================
    // 7. Check /etc files
    // =========================================================================
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

    // =========================================================================
    // 8. Check PAM configuration
    // =========================================================================
    for pam_file in PAM_CONFIGS {
        if reader.exists(pam_file) {
            report.add(CheckResult::pass(*pam_file, CheckCategory::EtcFile));
        } else {
            report.add(CheckResult::fail(
                *pam_file,
                CheckCategory::EtcFile,
                "Missing (authentication will fail)",
            ));
        }
    }

    // =========================================================================
    // 8.5. Check security configuration files
    // =========================================================================
    for sec_file in SECURITY_FILES {
        if reader.exists(sec_file) {
            report.add(CheckResult::pass(*sec_file, CheckCategory::EtcFile));
        } else {
            report.add(CheckResult::fail(
                *sec_file,
                CheckCategory::EtcFile,
                "Missing (security policy incomplete)",
            ));
        }
    }

    // =========================================================================
    // 9. Check PAM modules
    // =========================================================================
    for pam_module in PAM_MODULES {
        let module_path = format!("usr/lib64/security/{}", pam_module);
        if reader.exists(&module_path) {
            report.add(CheckResult::pass(module_path, CheckCategory::Library));
        } else {
            report.add(CheckResult::fail(
                module_path,
                CheckCategory::Library,
                "Missing (PAM authentication broken)",
            ));
        }
    }

    // =========================================================================
    // 10. Check udev helpers
    // =========================================================================
    for helper in UDEV_HELPERS {
        let helper_path = format!("usr/lib/udev/{}", helper);
        if reader.exists(&helper_path) {
            report.add(CheckResult::pass(helper_path, CheckCategory::Binary));
        } else {
            report.add(CheckResult::fail(
                helper_path,
                CheckCategory::Binary,
                "Missing (device identification broken)",
            ));
        }
    }

    // =========================================================================
    // 11. Check critical libraries
    // =========================================================================
    for lib in CRITICAL_LIBS {
        if reader.exists(lib) {
            report.add(CheckResult::pass(*lib, CheckCategory::Library));
        } else {
            report.add(CheckResult::fail(
                *lib,
                CheckCategory::Library,
                "Missing (system will not boot)",
            ));
        }
    }

    // =========================================================================
    // 12. Check init symlink
    // =========================================================================
    let init_path = "usr/sbin/init";
    if let Some(entry) = reader.get(init_path) {
        if entry.is_symlink() {
            if let Some(ref target) = entry.link_target {
                if target.contains("systemd") {
                    report.add(CheckResult::pass(
                        format!("{} -> {}", init_path, target),
                        CheckCategory::Symlink,
                    ));
                } else {
                    report.add(CheckResult::fail(
                        init_path,
                        CheckCategory::Symlink,
                        format!("Points to '{}' instead of systemd", target),
                    ));
                }
            }
        } else {
            report.add(CheckResult::fail(
                init_path,
                CheckCategory::Symlink,
                "Exists but is not a symlink",
            ));
        }
    } else {
        report.add(CheckResult::fail(
            init_path,
            CheckCategory::Symlink,
            "Missing (kernel can't find init)",
        ));
    }

    // =========================================================================
    // 13. Check that all symlinks resolve
    // =========================================================================
    for entry in reader.symlinks() {
        // Skip symlinks we already checked
        if FHS_SYMLINKS.iter().any(|(l, _)| entry.path == *l) {
            continue;
        }
        if entry.path == init_path {
            continue;
        }

        if !reader.symlink_target_exists(entry) {
            if let Some(ref target) = entry.link_target {
                // Only report broken symlinks in critical paths
                if entry.path.starts_with("usr/bin/")
                    || entry.path.starts_with("usr/sbin/")
                    || entry.path.starts_with("usr/lib64/")
                    || entry.path.starts_with("etc/")
                {
                    report.add(CheckResult::fail(
                        format!("{} -> {}", entry.path, target),
                        CheckCategory::Symlink,
                        "Target does not exist",
                    ));
                }
            }
        }
    }

    // =========================================================================
    // 14. Check for kernel modules directory
    // =========================================================================
    let has_modules = reader.entries().iter().any(|e| {
        e.path.starts_with("usr/lib/modules/") && e.path.contains("/kernel/")
    });
    if has_modules {
        report.add(CheckResult::pass(
            "usr/lib/modules/*/kernel/",
            CheckCategory::KernelModule,
        ));
    } else {
        report.add(CheckResult::fail(
            "usr/lib/modules/*/kernel/",
            CheckCategory::KernelModule,
            "No kernel modules found",
        ));
    }

    // =========================================================================
    // 15. Check for udev rules
    // =========================================================================
    let has_udev_rules = reader.entries().iter().any(|e| {
        e.path.starts_with("usr/lib/udev/rules.d/") && e.path.ends_with(".rules")
    });
    if has_udev_rules {
        report.add(CheckResult::pass(
            "usr/lib/udev/rules.d/*.rules",
            CheckCategory::UdevRule,
        ));
    } else {
        report.add(CheckResult::fail(
            "usr/lib/udev/rules.d/*.rules",
            CheckCategory::UdevRule,
            "No udev rules found (device detection broken)",
        ));
    }

    // =========================================================================
    // 16. Check for terminfo (required for tmux, ncurses apps)
    // =========================================================================
    let has_terminfo = reader.entries().iter().any(|e| {
        e.path.starts_with("usr/share/terminfo/")
    });
    if has_terminfo {
        report.add(CheckResult::pass(
            "usr/share/terminfo/",
            CheckCategory::Other,
        ));
    } else {
        report.add(CheckResult::fail(
            "usr/share/terminfo/",
            CheckCategory::Other,
            "No terminfo database (terminal apps broken)",
        ));
    }

    // =========================================================================
    // 17. Check for locale data
    // =========================================================================
    let has_locale = reader.entries().iter().any(|e| {
        e.path.starts_with("usr/lib/locale/") || e.path.starts_with("usr/share/locale/")
    });
    if has_locale {
        report.add(CheckResult::pass("locale data", CheckCategory::Other));
    } else {
        report.add(CheckResult::fail(
            "locale data",
            CheckCategory::Other,
            "No locale data found",
        ));
    }

    // =========================================================================
    // 18. Check for timezone data
    // =========================================================================
    let has_zoneinfo = reader.entries().iter().any(|e| {
        e.path.starts_with("usr/share/zoneinfo/")
    });
    if has_zoneinfo {
        report.add(CheckResult::pass(
            "usr/share/zoneinfo/",
            CheckCategory::Other,
        ));
    } else {
        report.add(CheckResult::fail(
            "usr/share/zoneinfo/",
            CheckCategory::Other,
            "No timezone data (timedatectl broken)",
        ));
    }

    // =========================================================================
    // 19. Check for license files (legal compliance)
    // =========================================================================
    // LevitateOS copies binaries from Rocky Linux and must include their licenses.
    // These are the critical packages that MUST have license directories.
    verify_licenses(reader, &mut report);

    report
}

/// Critical packages that must have license directories.
///
/// These are packages that LevitateOS always redistributes.
/// Missing licenses = legal compliance failure.
const CRITICAL_LICENSE_PACKAGES: &[&str] = &[
    // Core system
    "glibc",
    "bash",
    "coreutils",
    "systemd",
    "util-linux",
    // Authentication
    "pam",
    "shadow-utils",
    // Networking
    "NetworkManager",
    "iproute",
    "openssh-clients",
    // Filesystem tools
    "e2fsprogs",
    "btrfs-progs",
    "dosfstools",
    // Compression
    "gzip",
    "xz",
    "tar",
    // Editors
    "vim-minimal",
    // Kernel/firmware
    "kernel",
    "linux-firmware",
    // Data files
    "tzdata",
    "kbd",
];

/// Verify license directories are present.
fn verify_licenses(reader: &CpioReader, report: &mut VerificationReport) {
    // First check: do we have any licenses at all?
    let has_licenses = reader.entries().iter().any(|e| {
        e.path.starts_with("usr/share/licenses/")
    });

    if !has_licenses {
        report.add(CheckResult::fail(
            "usr/share/licenses/",
            CheckCategory::License,
            "No license directory found (legal compliance failure)",
        ));
        return;
    }

    // Collect all license directories present
    let license_dirs: HashSet<String> = reader
        .entries()
        .iter()
        .filter(|e| e.path.starts_with("usr/share/licenses/"))
        .filter_map(|e| {
            // Extract package name from path like "usr/share/licenses/bash/COPYING"
            let rest = e.path.strip_prefix("usr/share/licenses/")?;
            let pkg = rest.split('/').next()?;
            if pkg.is_empty() {
                None
            } else {
                Some(pkg.to_string())
            }
        })
        .collect();

    // Check critical packages
    for pkg in CRITICAL_LICENSE_PACKAGES {
        let license_path = format!("usr/share/licenses/{}/", pkg);
        if license_dirs.contains(*pkg) {
            report.add(CheckResult::pass(license_path, CheckCategory::License));
        } else {
            report.add(CheckResult::fail(
                license_path,
                CheckCategory::License,
                "Missing license (legal compliance)",
            ));
        }
    }

    // Report total license count as informational
    let total_licenses = license_dirs.len();
    if total_licenses > 0 {
        report.add(CheckResult::pass(
            format!("{} package licenses found", total_licenses),
            CheckCategory::License,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_essential_dirs_covered() {
        // Verify ESSENTIAL_DIRS from distro-spec are in our list
        let essential = ["bin", "etc", "lib", "sbin", "usr", "var"];
        for dir in essential {
            assert!(
                FHS_DIRS.contains(&dir) ||
                FHS_SYMLINKS.iter().any(|(l, _)| *l == dir),
                "Missing essential dir: {}",
                dir
            );
        }
    }

    #[test]
    fn test_critical_binaries_present() {
        // Verify critical binaries are in the lists
        assert!(BIN_UTILS.contains(&"ls"));
        assert!(BIN_UTILS.contains(&"systemctl"));
        assert!(BIN_UTILS.contains(&"vim"));
        assert!(BIN_UTILS.contains(&"rsync"));
        assert!(BIN_UTILS.contains(&"man"));
        assert!(SBIN_UTILS.contains(&"passwd"));
        assert!(AUTH_SBIN.contains(&"unix_chkpwd"));
        assert!(SBIN_UTILS.contains(&"btrfs"));
        assert!(SBIN_UTILS.contains(&"mdadm"));
        assert!(SBIN_UTILS.contains(&"testdisk"));
    }

    #[test]
    fn test_systemd_bins_present() {
        assert!(SYSTEMD_BINARIES.contains(&"systemd-journald"));
        assert!(SYSTEMD_BINARIES.contains(&"systemd-udevd"));
    }

    #[test]
    fn test_critical_units_present() {
        assert!(ESSENTIAL_UNITS.contains(&"multi-user.target"));
        assert!(ESSENTIAL_UNITS.contains(&"getty@.service"));
        assert!(ESSENTIAL_UNITS.contains(&"systemd-journald.service"));
    }

    #[test]
    fn test_pam_critical_modules() {
        assert!(PAM_MODULES.contains(&"pam_unix.so"));
        assert!(PAM_MODULES.contains(&"pam_deny.so"));
    }

    #[test]
    fn test_fhs_dirs_have_usr() {
        assert!(FHS_DIRS.contains(&"usr/bin"));
        assert!(FHS_DIRS.contains(&"usr/sbin"));
        assert!(FHS_DIRS.contains(&"etc"));
    }

    #[test]
    fn test_critical_license_packages_defined() {
        // Verify critical license packages are reasonable
        assert!(CRITICAL_LICENSE_PACKAGES.contains(&"glibc"));
        assert!(CRITICAL_LICENSE_PACKAGES.contains(&"bash"));
        assert!(CRITICAL_LICENSE_PACKAGES.contains(&"systemd"));
        assert!(CRITICAL_LICENSE_PACKAGES.contains(&"coreutils"));
        assert!(CRITICAL_LICENSE_PACKAGES.contains(&"kernel"));
        assert!(CRITICAL_LICENSE_PACKAGES.contains(&"linux-firmware"));
    }
}
