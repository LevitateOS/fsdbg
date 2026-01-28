//! Qcow2 image checklist
//!
//! Static verification for LevitateOS qcow2 VM images.
//!
//! This checklist verifies that a qcow2 image contains all required files
//! and configurations for a bootable, properly configured system.
//!
//! Unlike archive-based checklists, this works on a mounted filesystem path.

use super::{CheckCategory, CheckResult, VerificationReport};
use std::fs;
use std::path::Path;

// =============================================================================
// BOOT - Critical bootloader and kernel components
// =============================================================================

/// systemd-boot EFI binary
const BOOT_EFI: &str = "boot/EFI/systemd/systemd-bootx64.efi";

/// Boot loader configuration
const LOADER_CONF: &str = "boot/loader/loader.conf";

/// Boot loader entries directory
const LOADER_ENTRIES_DIR: &str = "boot/loader/entries";

// =============================================================================
// FILESYSTEM - Critical filesystem configuration
// =============================================================================

/// Fstab file
const FSTAB: &str = "etc/fstab";

// =============================================================================
// SYSTEM CONFIG - Required system files
// =============================================================================

/// Hostname file
const HOSTNAME: &str = "etc/hostname";

/// Machine ID file (should be empty for first-boot regeneration)
const MACHINE_ID: &str = "etc/machine-id";

/// Shadow file (root should have empty password, not locked)
const SHADOW: &str = "etc/shadow";

/// Passwd file
const PASSWD: &str = "etc/passwd";

/// Group file
const GROUP: &str = "etc/group";

/// OS release file
const OS_RELEASE: &str = "etc/os-release";

/// Locale configuration
const LOCALE_CONF: &str = "etc/locale.conf";

// =============================================================================
// SERVICE ENABLEMENT - Required systemd service symlinks
// =============================================================================

/// Enabled services that must have symlinks in multi-user.target.wants
const REQUIRED_ENABLED_SERVICES: &[&str] = &[
    "NetworkManager.service",
    "sshd.service",
    "chronyd.service",
];

/// multi-user.target.wants directory
const MULTI_USER_WANTS: &str = "etc/systemd/system/multi-user.target.wants";

// =============================================================================
// SECURITY - Files that should NOT exist
// =============================================================================

/// SSH host keys that should NOT exist (regenerated on first boot)
const SSH_HOST_KEYS: &[&str] = &[
    "etc/ssh/ssh_host_rsa_key",
    "etc/ssh/ssh_host_ecdsa_key",
    "etc/ssh/ssh_host_ed25519_key",
];

// =============================================================================
// VERIFICATION
// =============================================================================

/// Verify a mounted qcow2 filesystem against the checklist.
///
/// # Arguments
///
/// * `mount_point` - Path where the qcow2 partitions are mounted
pub fn verify(mount_point: &Path) -> VerificationReport {
    let mut report = VerificationReport::new("Qcow2 Image");

    check_boot(&mut report, mount_point);
    check_kernel_initramfs(&mut report, mount_point);
    check_filesystem(&mut report, mount_point);
    check_system_config(&mut report, mount_point);
    check_user_database(&mut report, mount_point);
    check_enabled_services(&mut report, mount_point);
    check_security(&mut report, mount_point);

    report
}

/// Check boot loader installation
fn check_boot(report: &mut VerificationReport, root: &Path) {
    // systemd-boot EFI binary
    let efi_path = root.join(BOOT_EFI);
    if efi_path.exists() {
        report.add(CheckResult::pass(BOOT_EFI, CheckCategory::Binary));
    } else {
        report.add(CheckResult::fail(
            BOOT_EFI,
            CheckCategory::Binary,
            "Missing (system won't boot)",
        ));
    }

    // loader.conf
    let loader_conf = root.join(LOADER_CONF);
    if loader_conf.exists() {
        // Verify it has content
        match fs::read_to_string(&loader_conf) {
            Ok(content) if !content.trim().is_empty() => {
                report.add(CheckResult::pass(LOADER_CONF, CheckCategory::EtcFile));
            }
            Ok(_) => {
                report.add(CheckResult::fail(
                    LOADER_CONF,
                    CheckCategory::EtcFile,
                    "Empty configuration",
                ));
            }
            Err(e) => {
                report.add(CheckResult::fail(
                    LOADER_CONF,
                    CheckCategory::EtcFile,
                    format!("Cannot read: {}", e),
                ));
            }
        }
    } else {
        report.add(CheckResult::fail(
            LOADER_CONF,
            CheckCategory::EtcFile,
            "Missing",
        ));
    }

    // Boot entries
    let entries_dir = root.join(LOADER_ENTRIES_DIR);
    if entries_dir.is_dir() {
        match fs::read_dir(&entries_dir) {
            Ok(entries) => {
                let conf_files: Vec<_> = entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        e.path()
                            .extension()
                            .is_some_and(|ext| ext == "conf")
                    })
                    .collect();

                if conf_files.is_empty() {
                    report.add(CheckResult::fail(
                        LOADER_ENTRIES_DIR,
                        CheckCategory::Directory,
                        "No .conf boot entries found",
                    ));
                } else {
                    report.add(CheckResult::pass(
                        format!("{} ({} entries)", LOADER_ENTRIES_DIR, conf_files.len()),
                        CheckCategory::Directory,
                    ));

                    // Validate each boot entry has required fields and references exist
                    for entry in conf_files {
                        let name = entry.file_name().to_string_lossy().to_string();
                        match fs::read_to_string(entry.path()) {
                            Ok(content) => {
                                let has_title = content.lines().any(|l| l.starts_with("title"));
                                let has_linux = content.lines().any(|l| l.starts_with("linux"));
                                let has_initrd = content.lines().any(|l| l.starts_with("initrd"));
                                let has_options = content.lines().any(|l| l.starts_with("options"));

                                if has_title && has_linux && has_initrd {
                                    // Verify the referenced kernel and initramfs exist
                                    let mut valid = true;
                                    let mut problems = Vec::new();

                                    // Check linux path exists
                                    if let Some(linux_line) = content.lines().find(|l| l.starts_with("linux")) {
                                        let path = linux_line.trim_start_matches("linux").trim();
                                        // Path is relative to /boot, like /vmlinuz-*
                                        let full_path = root.join("boot").join(path.trim_start_matches('/'));
                                        if !full_path.exists() {
                                            valid = false;
                                            problems.push(format!("kernel '{}' not found", path));
                                        }
                                    }

                                    // Check initrd path exists
                                    if let Some(initrd_line) = content.lines().find(|l| l.starts_with("initrd")) {
                                        let path = initrd_line.trim_start_matches("initrd").trim();
                                        let full_path = root.join("boot").join(path.trim_start_matches('/'));
                                        if !full_path.exists() {
                                            valid = false;
                                            problems.push(format!("initramfs '{}' not found", path));
                                        }
                                    }

                                    // Check options has root= (warning only)
                                    if has_options {
                                        if let Some(options_line) = content.lines().find(|l| l.starts_with("options")) {
                                            if !options_line.contains("root=") {
                                                problems.push("options missing root= parameter".to_string());
                                            }
                                        }
                                    } else {
                                        problems.push("no options line".to_string());
                                    }

                                    if valid && problems.is_empty() {
                                        report.add(CheckResult::pass(
                                            format!("boot entry: {}", name),
                                            CheckCategory::EtcFile,
                                        ));
                                    } else if valid {
                                        // Valid but with warnings
                                        report.add(CheckResult::pass(
                                            format!("boot entry: {} ({})", name, problems.join(", ")),
                                            CheckCategory::EtcFile,
                                        ));
                                    } else {
                                        report.add(CheckResult::fail(
                                            format!("boot entry: {}", name),
                                            CheckCategory::EtcFile,
                                            problems.join(", "),
                                        ));
                                    }
                                } else {
                                    let missing: Vec<_> = [
                                        (!has_title).then_some("title"),
                                        (!has_linux).then_some("linux"),
                                        (!has_initrd).then_some("initrd"),
                                    ]
                                    .into_iter()
                                    .flatten()
                                    .collect();
                                    report.add(CheckResult::fail(
                                        format!("boot entry: {}", name),
                                        CheckCategory::EtcFile,
                                        format!("Missing fields: {}", missing.join(", ")),
                                    ));
                                }
                            }
                            Err(e) => {
                                report.add(CheckResult::fail(
                                    format!("boot entry: {}", name),
                                    CheckCategory::EtcFile,
                                    format_permission_error("Cannot read", &e),
                                ));
                            }
                        }
                    }
                }
            }
            Err(e) => {
                report.add(CheckResult::fail(
                    LOADER_ENTRIES_DIR,
                    CheckCategory::Directory,
                    format!("Cannot read: {}", e),
                ));
            }
        }
    } else {
        report.add(CheckResult::fail(
            LOADER_ENTRIES_DIR,
            CheckCategory::Directory,
            "Missing",
        ));
    }
}

/// Check kernel and initramfs exist
///
/// Accepts both canonical names (vmlinuz, initramfs.img) and versioned names
/// (vmlinuz-*, initramfs-*.img) for compatibility with different builds.
fn check_kernel_initramfs(report: &mut VerificationReport, root: &Path) {
    let boot = root.join("boot");

    // Look for vmlinuz (canonical) or vmlinuz-* (versioned)
    let vmlinuz_found = fs::read_dir(&boot)
        .ok()
        .and_then(|entries| {
            entries
                .filter_map(|e| e.ok())
                .find(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    // Accept "vmlinuz" (canonical) or "vmlinuz-*" (versioned)
                    name == "vmlinuz" || name.starts_with("vmlinuz-")
                })
                .map(|e| e.file_name().to_string_lossy().to_string())
        });

    match vmlinuz_found {
        Some(name) => {
            report.add(CheckResult::pass(
                format!("boot/{}", name),
                CheckCategory::Binary,
            ));
        }
        None => {
            report.add(CheckResult::fail(
                "boot/vmlinuz",
                CheckCategory::Binary,
                "No kernel found",
            ));
        }
    }

    // Look for initramfs.img (canonical) or initramfs-*.img (versioned)
    let initramfs_found = fs::read_dir(&boot)
        .ok()
        .and_then(|entries| {
            entries
                .filter_map(|e| e.ok())
                .find(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    // Accept "initramfs.img" (canonical) or "initramfs-*.img" (versioned)
                    name == "initramfs.img"
                        || (name.starts_with("initramfs-") && name.ends_with(".img"))
                })
                .map(|e| e.file_name().to_string_lossy().to_string())
        });

    match initramfs_found {
        Some(name) => {
            report.add(CheckResult::pass(
                format!("boot/{}", name),
                CheckCategory::Binary,
            ));
        }
        None => {
            report.add(CheckResult::fail(
                "boot/initramfs.img",
                CheckCategory::Binary,
                "No initramfs found",
            ));
        }
    }
}

/// Check filesystem configuration
fn check_filesystem(report: &mut VerificationReport, root: &Path) {
    let fstab_path = root.join(FSTAB);
    if fstab_path.exists() {
        match fs::read_to_string(&fstab_path) {
            Ok(content) => {
                // Count non-empty, non-comment lines
                let entries: Vec<_> = content
                    .lines()
                    .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                    .collect();

                if entries.is_empty() {
                    report.add(CheckResult::fail(
                        FSTAB,
                        CheckCategory::EtcFile,
                        "No mount entries",
                    ));
                } else {
                    // Check for root and boot mounts
                    let has_root = entries.iter().any(|l| {
                        let parts: Vec<_> = l.split_whitespace().collect();
                        parts.len() >= 2 && parts[1] == "/"
                    });
                    let has_boot = entries.iter().any(|l| {
                        let parts: Vec<_> = l.split_whitespace().collect();
                        parts.len() >= 2 && parts[1] == "/boot"
                    });

                    if has_root && has_boot {
                        report.add(CheckResult::pass(
                            format!("{} ({} entries, has / and /boot)", FSTAB, entries.len()),
                            CheckCategory::EtcFile,
                        ));
                    } else {
                        let missing: Vec<_> = [
                            (!has_root).then_some("/"),
                            (!has_boot).then_some("/boot"),
                        ]
                        .into_iter()
                        .flatten()
                        .collect();
                        report.add(CheckResult::fail(
                            FSTAB,
                            CheckCategory::EtcFile,
                            format!("Missing mounts: {}", missing.join(", ")),
                        ));
                    }
                }
            }
            Err(e) => {
                report.add(CheckResult::fail(
                    FSTAB,
                    CheckCategory::EtcFile,
                    format!("Cannot read: {}", e),
                ));
            }
        }
    } else {
        report.add(CheckResult::fail(
            FSTAB,
            CheckCategory::EtcFile,
            "Missing",
        ));
    }
}

/// Check system configuration files
fn check_system_config(report: &mut VerificationReport, root: &Path) {
    // Hostname
    let hostname_path = root.join(HOSTNAME);
    if hostname_path.exists() {
        match fs::read_to_string(&hostname_path) {
            Ok(content) if !content.trim().is_empty() => {
                report.add(CheckResult::pass(
                    format!("{} ({})", HOSTNAME, content.trim()),
                    CheckCategory::EtcFile,
                ));
            }
            Ok(_) => {
                report.add(CheckResult::fail(
                    HOSTNAME,
                    CheckCategory::EtcFile,
                    "Empty",
                ));
            }
            Err(e) => {
                report.add(CheckResult::fail(
                    HOSTNAME,
                    CheckCategory::EtcFile,
                    format_permission_error("Cannot read", &e),
                ));
            }
        }
    } else {
        report.add(CheckResult::fail(
            HOSTNAME,
            CheckCategory::EtcFile,
            "Missing",
        ));
    }

    // Machine ID - should be empty for first-boot regeneration
    let machine_id_path = root.join(MACHINE_ID);
    if machine_id_path.exists() {
        match fs::read_to_string(&machine_id_path) {
            Ok(content) if content.trim().is_empty() => {
                report.add(CheckResult::pass(
                    format!("{} (empty for first-boot regeneration)", MACHINE_ID),
                    CheckCategory::EtcFile,
                ));
            }
            Ok(content) if content.trim() == "uninitialized" => {
                report.add(CheckResult::pass(
                    format!("{} (uninitialized for first-boot regeneration)", MACHINE_ID),
                    CheckCategory::EtcFile,
                ));
            }
            Ok(content) => {
                // Non-empty machine ID is a warning - image may have been booted
                report.add(CheckResult::fail(
                    MACHINE_ID,
                    CheckCategory::EtcFile,
                    format!(
                        "Contains value '{}' - should be empty for unique ID generation",
                        content.trim()
                    ),
                ));
            }
            Err(e) => {
                report.add(CheckResult::fail(
                    MACHINE_ID,
                    CheckCategory::EtcFile,
                    format_permission_error("Cannot read", &e),
                ));
            }
        }
    } else {
        // Missing is OK - systemd will create it on first boot
        report.add(CheckResult::pass(
            format!("{} (missing, will be created on first boot)", MACHINE_ID),
            CheckCategory::EtcFile,
        ));
    }

    // Shadow file - check root password is empty (not locked)
    check_shadow_file(report, root);

    // OS release
    let os_release_path = root.join(OS_RELEASE);
    if os_release_path.exists() {
        match fs::read_to_string(&os_release_path) {
            Ok(content) => {
                let has_name = content.lines().any(|l| l.starts_with("NAME="));
                let has_id = content.lines().any(|l| l.starts_with("ID="));
                if has_name && has_id {
                    // Extract NAME for display
                    let name = content
                        .lines()
                        .find(|l| l.starts_with("NAME="))
                        .and_then(|l| l.strip_prefix("NAME="))
                        .map(|s| s.trim_matches('"'))
                        .unwrap_or("unknown");
                    report.add(CheckResult::pass(
                        format!("{} ({})", OS_RELEASE, name),
                        CheckCategory::EtcFile,
                    ));
                } else {
                    report.add(CheckResult::fail(
                        OS_RELEASE,
                        CheckCategory::EtcFile,
                        "Missing NAME or ID fields",
                    ));
                }
            }
            Err(e) => {
                report.add(CheckResult::fail(
                    OS_RELEASE,
                    CheckCategory::EtcFile,
                    format_permission_error("Cannot read", &e),
                ));
            }
        }
    } else {
        report.add(CheckResult::fail(
            OS_RELEASE,
            CheckCategory::EtcFile,
            "Missing",
        ));
    }

    // Locale - optional but good to have
    let locale_path = root.join(LOCALE_CONF);
    if locale_path.exists() {
        match fs::read_to_string(&locale_path) {
            Ok(content) if content.contains("LANG=") => {
                let lang = content
                    .lines()
                    .find(|l| l.starts_with("LANG="))
                    .and_then(|l| l.strip_prefix("LANG="))
                    .unwrap_or("unknown");
                report.add(CheckResult::pass(
                    format!("{} ({})", LOCALE_CONF, lang),
                    CheckCategory::EtcFile,
                ));
            }
            Ok(_) => {
                report.add(CheckResult::pass(
                    format!("{} (exists, no LANG set)", LOCALE_CONF),
                    CheckCategory::EtcFile,
                ));
            }
            Err(e) => {
                report.add(CheckResult::fail(
                    LOCALE_CONF,
                    CheckCategory::EtcFile,
                    format_permission_error("Cannot read", &e),
                ));
            }
        }
    } else {
        // Missing locale.conf is OK - system will use defaults
        report.add(CheckResult::pass(
            format!("{} (missing, will use defaults)", LOCALE_CONF),
            CheckCategory::EtcFile,
        ));
    }
}

/// Check shadow file separately (handles permission errors gracefully)
fn check_shadow_file(report: &mut VerificationReport, root: &Path) {
    let shadow_path = root.join(SHADOW);
    if shadow_path.exists() {
        match fs::read_to_string(&shadow_path) {
            Ok(content) => {
                // Find root line
                let root_line = content.lines().find(|l| l.starts_with("root:"));
                match root_line {
                    Some(line) => {
                        let parts: Vec<_> = line.split(':').collect();
                        if parts.len() >= 2 {
                            let password_field = parts[1];
                            if password_field.is_empty() {
                                report.add(CheckResult::pass(
                                    format!("{} (root has empty password)", SHADOW),
                                    CheckCategory::EtcFile,
                                ));
                            } else if password_field == "!" || password_field == "*" {
                                report.add(CheckResult::fail(
                                    SHADOW,
                                    CheckCategory::EtcFile,
                                    "Root account is locked (should have empty password for initial login)",
                                ));
                            } else {
                                // Has a password hash
                                report.add(CheckResult::fail(
                                    SHADOW,
                                    CheckCategory::EtcFile,
                                    "Root has a password set (should be empty for initial configuration)",
                                ));
                            }
                        } else {
                            report.add(CheckResult::fail(
                                SHADOW,
                                CheckCategory::EtcFile,
                                "Malformed root entry",
                            ));
                        }
                    }
                    None => {
                        report.add(CheckResult::fail(
                            SHADOW,
                            CheckCategory::EtcFile,
                            "No root entry found",
                        ));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // Permission denied is expected without root
                report.add(CheckResult::fail(
                    SHADOW,
                    CheckCategory::EtcFile,
                    "Permission denied (run with sudo to check root password)",
                ));
            }
            Err(e) => {
                report.add(CheckResult::fail(
                    SHADOW,
                    CheckCategory::EtcFile,
                    format!("Cannot read: {}", e),
                ));
            }
        }
    } else {
        report.add(CheckResult::fail(
            SHADOW,
            CheckCategory::EtcFile,
            "Missing",
        ));
    }
}

/// Format error message, noting if it's a permission error
fn format_permission_error(prefix: &str, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        format!("{}: permission denied (run with sudo)", prefix)
    } else {
        format!("{}: {}", prefix, e)
    }
}

/// Check user database files (passwd, group)
fn check_user_database(report: &mut VerificationReport, root: &Path) {
    // Passwd file
    let passwd_path = root.join(PASSWD);
    if passwd_path.exists() {
        match fs::read_to_string(&passwd_path) {
            Ok(content) => {
                let has_root = content.lines().any(|l| l.starts_with("root:"));
                let has_nobody = content.lines().any(|l| l.starts_with("nobody:"));
                let entry_count = content.lines().filter(|l| !l.trim().is_empty()).count();

                if has_root {
                    report.add(CheckResult::pass(
                        format!("{} ({} entries, has root{})",
                            PASSWD,
                            entry_count,
                            if has_nobody { " and nobody" } else { "" }
                        ),
                        CheckCategory::EtcFile,
                    ));
                } else {
                    report.add(CheckResult::fail(
                        PASSWD,
                        CheckCategory::EtcFile,
                        "No root entry found",
                    ));
                }
            }
            Err(e) => {
                report.add(CheckResult::fail(
                    PASSWD,
                    CheckCategory::EtcFile,
                    format_permission_error("Cannot read", &e),
                ));
            }
        }
    } else {
        report.add(CheckResult::fail(
            PASSWD,
            CheckCategory::EtcFile,
            "Missing",
        ));
    }

    // Group file
    let group_path = root.join(GROUP);
    if group_path.exists() {
        match fs::read_to_string(&group_path) {
            Ok(content) => {
                let has_root = content.lines().any(|l| l.starts_with("root:"));
                let has_wheel = content.lines().any(|l| l.starts_with("wheel:"));
                let entry_count = content.lines().filter(|l| !l.trim().is_empty()).count();

                if has_root {
                    report.add(CheckResult::pass(
                        format!("{} ({} entries, has root{})",
                            GROUP,
                            entry_count,
                            if has_wheel { " and wheel" } else { "" }
                        ),
                        CheckCategory::EtcFile,
                    ));
                } else {
                    report.add(CheckResult::fail(
                        GROUP,
                        CheckCategory::EtcFile,
                        "No root group found",
                    ));
                }
            }
            Err(e) => {
                report.add(CheckResult::fail(
                    GROUP,
                    CheckCategory::EtcFile,
                    format_permission_error("Cannot read", &e),
                ));
            }
        }
    } else {
        report.add(CheckResult::fail(
            GROUP,
            CheckCategory::EtcFile,
            "Missing",
        ));
    }
}

/// Check that required services are enabled
fn check_enabled_services(report: &mut VerificationReport, root: &Path) {
    let wants_dir = root.join(MULTI_USER_WANTS);

    if !wants_dir.is_dir() {
        // Check if directory exists at all
        report.add(CheckResult::fail(
            MULTI_USER_WANTS,
            CheckCategory::Directory,
            "Directory missing",
        ));
        return;
    }

    for service in REQUIRED_ENABLED_SERVICES {
        let symlink = wants_dir.join(service);
        if symlink.exists() || symlink.is_symlink() {
            report.add(CheckResult::pass(
                format!("enabled: {}", service),
                CheckCategory::Symlink,
            ));
        } else {
            report.add(CheckResult::fail(
                format!("enabled: {}", service),
                CheckCategory::Symlink,
                "Service not enabled",
            ));
        }
    }
}

/// Check security requirements
fn check_security(report: &mut VerificationReport, root: &Path) {
    // SSH host keys should NOT exist (regenerated on first boot)
    for key in SSH_HOST_KEYS {
        let key_path = root.join(key);
        if key_path.exists() {
            report.add(CheckResult::fail(
                *key,
                CheckCategory::Other,
                "Should not exist (unique keys should be generated on first boot)",
            ));
        } else {
            report.add(CheckResult::pass(
                format!("{} (absent, will regenerate)", key),
                CheckCategory::Other,
            ));
        }
    }
}
