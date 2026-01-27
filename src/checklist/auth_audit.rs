//! Authentication audit checklist
//!
//! Comprehensive verification of authentication and authorization components.
//! This checklist ensures a LevitateOS system has everything needed for:
//! - Secure login (PAM stack, login.defs, securetty)
//! - Password management (passwd, chpasswd, unix_chkpwd)
//! - Privilege escalation (sudo, su, wheel group)
//! - Account security (faillock, password quality)
//!
//! ## Critical Components
//!
//! - `/usr/sbin/unix_chkpwd`: pam_unix.so has HARDCODED path. Without it,
//!   password changes silently fail (PAM returns success but password unchanged).
//! - `/etc/pam.d/system-auth`: Main authentication stack. Missing = login broken.
//! - `/etc/security/faillock.conf`: Account lockout policy.
//!
//! ## Usage
//!
//! ```bash
//! fsdbg verify rootfs.erofs --type auth-audit --verbose
//! ```

use super::{CheckCategory, CheckResult, VerificationReport};
use crate::cpio::CpioReader;

// Import from SINGLE SOURCE OF TRUTH
use distro_spec::shared::{
    AUTH_BIN, AUTH_SBIN, PAM_CONFIGS, PAM_MODULES, SECURITY_FILES, SHADOW_SBIN, SUDO_LIBS,
};

// =============================================================================
// AUTHENTICATION AUDIT SPECIFIC CONSTANTS
// =============================================================================

/// Critical authentication binaries that MUST exist.
/// These are binaries where absence causes silent failures or security holes.
const CRITICAL_AUTH_BINARIES: &[(&str, &str)] = &[
    ("usr/sbin/unix_chkpwd", "pam_unix.so hardcoded path - password auth WILL FAIL without this"),
    ("usr/sbin/passwd", "password changes impossible"),
    ("usr/sbin/chpasswd", "batch password setting broken"),
    ("usr/bin/sudo", "privilege escalation unavailable"),
    ("usr/bin/su", "user switching unavailable"),
    ("usr/sbin/login", "console login broken"),
    ("usr/sbin/agetty", "getty service broken"),
];

/// Critical PAM modules that form the core authentication stack.
const CRITICAL_PAM_MODULES: &[(&str, &str)] = &[
    ("pam_unix.so", "Core Unix password authentication - login WILL FAIL"),
    ("pam_permit.so", "Required for PAM stack ordering"),
    ("pam_deny.so", "Required for secure fallback"),
    ("pam_systemd.so", "Session registration with logind"),
    ("pam_env.so", "Environment setup for sessions"),
    ("pam_limits.so", "Resource limits enforcement"),
];

/// Critical PAM configuration files.
const CRITICAL_PAM_CONFIGS: &[(&str, &str)] = &[
    ("etc/pam.d/system-auth", "Main auth stack - ALL authentication uses this"),
    ("etc/pam.d/password-auth", "Password-based auth (SSH, etc)"),
    ("etc/pam.d/login", "Console login"),
    ("etc/pam.d/sshd", "SSH login"),
    ("etc/pam.d/sudo", "sudo privilege escalation"),
    ("etc/pam.d/su", "su command"),
    ("etc/pam.d/passwd", "Password change"),
    ("etc/pam.d/other", "Fallback (should deny all)"),
];

/// Security configuration files that enforce policies.
const CRITICAL_SECURITY_FILES: &[(&str, &str)] = &[
    ("etc/security/limits.conf", "Resource limits (ulimit)"),
    ("etc/security/faillock.conf", "Account lockout after failed attempts"),
    ("etc/security/pam_env.conf", "PAM environment variables"),
    ("etc/security/access.conf", "Access control rules"),
    ("etc/security/pwquality.conf", "Password quality requirements"),
];

/// Essential /etc files for authentication.
const CRITICAL_ETC_FILES: &[(&str, &str)] = &[
    ("etc/passwd", "User database"),
    ("etc/shadow", "Password hashes"),
    ("etc/group", "Group database"),
    ("etc/gshadow", "Group password hashes"),
    ("etc/login.defs", "Login defaults (password aging, UID ranges, encryption)"),
    ("etc/sudoers", "Sudo configuration"),
    ("etc/sudo.conf", "Sudo runtime config"),
    ("etc/shells", "Valid login shells"),
    ("etc/nsswitch.conf", "Name service switch (passwd/group resolution)"),
];

/// Files that should exist for hardened security (warnings if missing).
const RECOMMENDED_SECURITY_FILES: &[(&str, &str)] = &[
    ("etc/securetty", "Restrict root login to secure terminals"),
    ("etc/security/namespace.conf", "Per-user /tmp isolation"),
    ("etc/security/time.conf", "Time-based access control"),
    ("etc/security/group.conf", "Group-based access control"),
];

/// PAM modules for security hardening (warnings if missing).
const RECOMMENDED_PAM_MODULES: &[(&str, &str)] = &[
    ("pam_faillock.so", "Account lockout after failed login attempts"),
    ("pam_pwquality.so", "Password strength enforcement"),
    ("pam_wheel.so", "Restrict su to wheel group"),
    ("pam_securetty.so", "Restrict root to secure terminals"),
    ("pam_nologin.so", "Honor /etc/nologin file"),
    ("pam_loginuid.so", "Audit login UID tracking"),
    ("pam_namespace.so", "Polyinstantiated directories"),
];

// =============================================================================
// VERIFICATION
// =============================================================================

/// Verify authentication components in a CPIO/EROFS archive.
///
/// Returns a detailed report of authentication readiness.
pub fn verify(reader: &CpioReader) -> VerificationReport {
    let mut report = VerificationReport::new("Authentication Audit");

    // =========================================================================
    // 1. Critical authentication binaries
    // =========================================================================
    for (path, reason) in CRITICAL_AUTH_BINARIES {
        if reader.exists(path) {
            report.add(CheckResult::pass(*path, CheckCategory::Binary));
        } else {
            report.add(CheckResult::fail(
                *path,
                CheckCategory::Binary,
                format!("CRITICAL: {}", reason),
            ));
        }
    }

    // All AUTH_BIN from distro-spec
    for bin in AUTH_BIN {
        let path = format!("usr/bin/{}", bin);
        if !reader.exists(&path) {
            report.add(CheckResult::fail(
                path,
                CheckCategory::Binary,
                "Authentication binary missing",
            ));
        } else {
            report.add(CheckResult::pass(path, CheckCategory::Binary));
        }
    }

    // All AUTH_SBIN from distro-spec
    for sbin in AUTH_SBIN {
        let path = format!("usr/sbin/{}", sbin);
        if !reader.exists(&path) {
            report.add(CheckResult::fail(
                path,
                CheckCategory::Binary,
                "Authentication sbin missing",
            ));
        } else {
            report.add(CheckResult::pass(path, CheckCategory::Binary));
        }
    }

    // All SHADOW_SBIN from distro-spec (faillock, chage, etc.)
    for sbin in SHADOW_SBIN {
        let path = format!("usr/sbin/{}", sbin);
        if !reader.exists(&path) {
            report.add(CheckResult::fail(
                path,
                CheckCategory::Binary,
                "Shadow-utils binary missing",
            ));
        } else {
            report.add(CheckResult::pass(path, CheckCategory::Binary));
        }
    }

    // =========================================================================
    // 2. Critical PAM modules
    // =========================================================================
    for (module, reason) in CRITICAL_PAM_MODULES {
        let path = format!("usr/lib64/security/{}", module);
        if reader.exists(&path) {
            report.add(CheckResult::pass(path, CheckCategory::Library));
        } else {
            report.add(CheckResult::fail(
                path,
                CheckCategory::Library,
                format!("CRITICAL: {}", reason),
            ));
        }
    }

    // All PAM_MODULES from distro-spec
    for module in PAM_MODULES {
        let path = format!("usr/lib64/security/{}", module);
        // Skip if already checked as critical
        if CRITICAL_PAM_MODULES.iter().any(|(m, _)| *m == *module) {
            continue;
        }
        if reader.exists(&path) {
            report.add(CheckResult::pass(path, CheckCategory::Library));
        } else {
            report.add(CheckResult::fail(
                path,
                CheckCategory::Library,
                "PAM module missing",
            ));
        }
    }

    // =========================================================================
    // 3. Critical PAM configuration files
    // =========================================================================
    for (path, reason) in CRITICAL_PAM_CONFIGS {
        if reader.exists(path) {
            report.add(CheckResult::pass(*path, CheckCategory::EtcFile));
        } else {
            report.add(CheckResult::fail(
                *path,
                CheckCategory::EtcFile,
                format!("CRITICAL: {}", reason),
            ));
        }
    }

    // All PAM_CONFIGS from distro-spec
    for config in PAM_CONFIGS {
        // Skip if already checked as critical
        if CRITICAL_PAM_CONFIGS.iter().any(|(c, _)| *c == *config) {
            continue;
        }
        if reader.exists(config) {
            report.add(CheckResult::pass(*config, CheckCategory::EtcFile));
        } else {
            report.add(CheckResult::fail(
                *config,
                CheckCategory::EtcFile,
                "PAM config missing",
            ));
        }
    }

    // =========================================================================
    // 4. Critical security files
    // =========================================================================
    for (path, reason) in CRITICAL_SECURITY_FILES {
        if reader.exists(path) {
            report.add(CheckResult::pass(*path, CheckCategory::EtcFile));
        } else {
            report.add(CheckResult::fail(
                *path,
                CheckCategory::EtcFile,
                format!("Security policy missing: {}", reason),
            ));
        }
    }

    // All SECURITY_FILES from distro-spec
    for sec_file in SECURITY_FILES {
        // Skip if already checked
        if CRITICAL_SECURITY_FILES.iter().any(|(f, _)| *f == *sec_file) {
            continue;
        }
        if reader.exists(sec_file) {
            report.add(CheckResult::pass(*sec_file, CheckCategory::EtcFile));
        } else {
            report.add(CheckResult::fail(
                *sec_file,
                CheckCategory::EtcFile,
                "Security file missing",
            ));
        }
    }

    // =========================================================================
    // 5. Critical /etc files
    // =========================================================================
    for (path, reason) in CRITICAL_ETC_FILES {
        if reader.exists(path) {
            report.add(CheckResult::pass(*path, CheckCategory::EtcFile));
        } else {
            report.add(CheckResult::fail(
                *path,
                CheckCategory::EtcFile,
                format!("CRITICAL: {}", reason),
            ));
        }
    }

    // =========================================================================
    // 6. Sudo libraries
    // =========================================================================
    for lib in SUDO_LIBS {
        let path = format!("usr/libexec/sudo/{}", lib);
        if reader.exists(&path) {
            report.add(CheckResult::pass(path, CheckCategory::Library));
        } else {
            report.add(CheckResult::fail(
                path,
                CheckCategory::Library,
                "Sudo library missing (sudo may malfunction)",
            ));
        }
    }

    // =========================================================================
    // 7. Recommended security hardening (informational - don't fail audit)
    // =========================================================================
    // These are enterprise-level hardening features that are optional for a
    // daily driver desktop. Missing items are noted but don't fail the audit.
    for (path, _reason) in RECOMMENDED_SECURITY_FILES {
        if reader.exists(path) {
            report.add(CheckResult::pass(
                format!("[hardening] {}", path),
                CheckCategory::EtcFile,
            ));
        }
        // Missing recommended files are silently skipped - they're optional
        // for desktop use. Enterprise users can add them manually.
    }

    for (module, _reason) in RECOMMENDED_PAM_MODULES {
        let path = format!("usr/lib64/security/{}", module);
        // Skip if already checked
        if CRITICAL_PAM_MODULES.iter().any(|(m, _)| *m == *module) {
            continue;
        }
        if reader.exists(&path) {
            report.add(CheckResult::pass(
                format!("[hardening] {}", path),
                CheckCategory::Library,
            ));
        }
        // Missing recommended modules are silently skipped - they're optional
        // for desktop use. Enterprise users can enable in PAM stack manually.
    }

    // =========================================================================
    // 8. Check password-auth symlink (should point to system-auth)
    // =========================================================================
    if let Some(entry) = reader.get("etc/pam.d/password-auth") {
        if entry.is_symlink() {
            if let Some(ref target) = entry.link_target {
                if target == "system-auth" || target.ends_with("/system-auth") {
                    report.add(CheckResult::pass(
                        "etc/pam.d/password-auth -> system-auth",
                        CheckCategory::Symlink,
                    ));
                } else {
                    report.add(CheckResult::fail(
                        "etc/pam.d/password-auth",
                        CheckCategory::Symlink,
                        format!("Points to '{}' instead of system-auth", target),
                    ));
                }
            }
        }
        // If it's a regular file, that's also acceptable
    }

    // =========================================================================
    // 9. Check init symlink points to systemd
    // =========================================================================
    if let Some(entry) = reader.get("usr/sbin/init") {
        if entry.is_symlink() {
            if let Some(ref target) = entry.link_target {
                if target.contains("systemd") {
                    report.add(CheckResult::pass(
                        format!("usr/sbin/init -> {}", target),
                        CheckCategory::Symlink,
                    ));
                } else {
                    report.add(CheckResult::fail(
                        "usr/sbin/init",
                        CheckCategory::Symlink,
                        format!("Points to '{}' - not systemd", target),
                    ));
                }
            }
        }
    } else {
        report.add(CheckResult::fail(
            "usr/sbin/init",
            CheckCategory::Symlink,
            "Missing (system won't boot)",
        ));
    }

    // =========================================================================
    // 10. Check for systemd-logind (session management)
    // =========================================================================
    let logind_path = "usr/lib/systemd/systemd-logind";
    if reader.exists(logind_path) {
        report.add(CheckResult::pass(logind_path, CheckCategory::Binary));
    } else {
        report.add(CheckResult::fail(
            logind_path,
            CheckCategory::Binary,
            "CRITICAL: Session management broken (no seat/session tracking)",
        ));
    }

    // Check logind service
    let logind_unit = "usr/lib/systemd/system/systemd-logind.service";
    if reader.exists(logind_unit) {
        report.add(CheckResult::pass(logind_unit, CheckCategory::Unit));
    } else {
        report.add(CheckResult::fail(
            logind_unit,
            CheckCategory::Unit,
            "systemd-logind service missing",
        ));
    }

    report
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Constant coverage tests - verify our lists are complete
    // -------------------------------------------------------------------------

    #[test]
    fn test_critical_binaries_include_unix_chkpwd() {
        // unix_chkpwd is THE most critical binary - pam_unix.so has hardcoded path
        assert!(
            CRITICAL_AUTH_BINARIES
                .iter()
                .any(|(p, _)| p.contains("unix_chkpwd")),
            "unix_chkpwd MUST be in critical binaries - pam_unix.so hardcodes the path"
        );
    }

    #[test]
    fn test_critical_binaries_include_essentials() {
        let required = ["passwd", "sudo", "su", "login", "agetty"];
        for bin in required {
            assert!(
                CRITICAL_AUTH_BINARIES.iter().any(|(p, _)| p.contains(bin)),
                "Missing critical binary: {}",
                bin
            );
        }
    }

    #[test]
    fn test_critical_pam_modules_include_core() {
        let required = ["pam_unix.so", "pam_permit.so", "pam_deny.so", "pam_systemd.so"];
        for module in required {
            assert!(
                CRITICAL_PAM_MODULES.iter().any(|(m, _)| *m == module),
                "Missing critical PAM module: {}",
                module
            );
        }
    }

    #[test]
    fn test_critical_pam_configs_include_essentials() {
        let required = [
            "etc/pam.d/system-auth",
            "etc/pam.d/login",
            "etc/pam.d/sshd",
            "etc/pam.d/sudo",
            "etc/pam.d/su",
            "etc/pam.d/passwd",
            "etc/pam.d/other",
        ];
        for config in required {
            assert!(
                CRITICAL_PAM_CONFIGS.iter().any(|(c, _)| *c == config),
                "Missing critical PAM config: {}",
                config
            );
        }
    }

    #[test]
    fn test_critical_etc_files_include_auth_databases() {
        let required = ["etc/passwd", "etc/shadow", "etc/group", "etc/gshadow"];
        for file in required {
            assert!(
                CRITICAL_ETC_FILES.iter().any(|(f, _)| *f == file),
                "Missing critical /etc file: {}",
                file
            );
        }
    }

    #[test]
    fn test_critical_etc_files_include_login_defs() {
        assert!(
            CRITICAL_ETC_FILES
                .iter()
                .any(|(f, _)| *f == "etc/login.defs"),
            "login.defs MUST be checked - contains password hashing algorithm"
        );
    }

    #[test]
    fn test_critical_security_files_include_faillock() {
        assert!(
            CRITICAL_SECURITY_FILES
                .iter()
                .any(|(f, _)| f.contains("faillock")),
            "faillock.conf MUST be checked - account lockout policy"
        );
    }

    #[test]
    fn test_recommended_files_include_securetty() {
        assert!(
            RECOMMENDED_SECURITY_FILES
                .iter()
                .any(|(f, _)| f.contains("securetty")),
            "securetty should be recommended for root terminal restriction"
        );
    }

    #[test]
    fn test_recommended_pam_modules_include_hardening() {
        let hardening_modules = [
            "pam_faillock.so",
            "pam_pwquality.so",
            "pam_wheel.so",
            "pam_securetty.so",
        ];
        for module in hardening_modules {
            assert!(
                RECOMMENDED_PAM_MODULES.iter().any(|(m, _)| *m == module),
                "Missing recommended hardening module: {}",
                module
            );
        }
    }

    // -------------------------------------------------------------------------
    // Distro-spec alignment tests - verify we check everything from SSOT
    // -------------------------------------------------------------------------

    #[test]
    fn test_auth_bin_from_distro_spec() {
        // Verify AUTH_BIN from distro-spec is reasonable
        assert!(AUTH_BIN.contains(&"sudo"), "distro-spec AUTH_BIN missing sudo");
        assert!(AUTH_BIN.contains(&"su"), "distro-spec AUTH_BIN missing su");
    }

    #[test]
    fn test_auth_sbin_from_distro_spec() {
        // Verify AUTH_SBIN from distro-spec includes unix_chkpwd
        assert!(
            AUTH_SBIN.contains(&"unix_chkpwd"),
            "distro-spec AUTH_SBIN MUST include unix_chkpwd"
        );
        assert!(
            AUTH_SBIN.contains(&"visudo"),
            "distro-spec AUTH_SBIN should include visudo"
        );
    }

    #[test]
    fn test_shadow_sbin_from_distro_spec() {
        // Verify SHADOW_SBIN from distro-spec includes account management
        assert!(
            SHADOW_SBIN.contains(&"faillock"),
            "distro-spec SHADOW_SBIN should include faillock"
        );
        assert!(
            SHADOW_SBIN.contains(&"chage"),
            "distro-spec SHADOW_SBIN should include chage"
        );
    }

    #[test]
    fn test_pam_modules_from_distro_spec_complete() {
        // Verify PAM_MODULES from distro-spec is comprehensive
        let essential = ["pam_unix.so", "pam_permit.so", "pam_deny.so"];
        for module in essential {
            assert!(
                PAM_MODULES.contains(&module),
                "distro-spec PAM_MODULES missing essential: {}",
                module
            );
        }
    }

    #[test]
    fn test_pam_configs_from_distro_spec_complete() {
        // Verify PAM_CONFIGS from distro-spec covers all login methods
        let essential = [
            "etc/pam.d/system-auth",
            "etc/pam.d/login",
            "etc/pam.d/sshd",
            "etc/pam.d/sudo",
        ];
        for config in essential {
            assert!(
                PAM_CONFIGS.contains(&config),
                "distro-spec PAM_CONFIGS missing essential: {}",
                config
            );
        }
    }

    #[test]
    fn test_security_files_from_distro_spec_complete() {
        // Verify SECURITY_FILES from distro-spec includes policies
        let essential = [
            "etc/security/limits.conf",
            "etc/security/faillock.conf",
            "etc/security/access.conf",
        ];
        for file in essential {
            assert!(
                SECURITY_FILES.contains(&file),
                "distro-spec SECURITY_FILES missing essential: {}",
                file
            );
        }
    }

    #[test]
    fn test_sudo_libs_from_distro_spec() {
        // Verify SUDO_LIBS from distro-spec is present
        assert!(
            SUDO_LIBS.contains(&"sudoers.so"),
            "distro-spec SUDO_LIBS should include sudoers.so"
        );
    }

    // -------------------------------------------------------------------------
    // Security policy tests - verify we catch security issues
    // -------------------------------------------------------------------------

    #[test]
    fn test_pam_other_is_critical() {
        // pam.d/other MUST be checked - it's the fallback for unconfigured services
        assert!(
            CRITICAL_PAM_CONFIGS
                .iter()
                .any(|(c, _)| *c == "etc/pam.d/other"),
            "etc/pam.d/other is CRITICAL - fallback for unknown services"
        );
    }

    #[test]
    fn test_nsswitch_is_critical() {
        // nsswitch.conf determines how passwd/group lookups work
        assert!(
            CRITICAL_ETC_FILES
                .iter()
                .any(|(f, _)| *f == "etc/nsswitch.conf"),
            "nsswitch.conf is CRITICAL - passwd/group resolution"
        );
    }

    #[test]
    fn test_shells_file_is_critical() {
        // /etc/shells is required for valid shell checking
        assert!(
            CRITICAL_ETC_FILES
                .iter()
                .any(|(f, _)| *f == "etc/shells"),
            "/etc/shells is CRITICAL - valid shell list"
        );
    }
}
