//! Authentication component definitions.
//!
//! Binaries, PAM modules and configuration files the authentication
//! subsystem needs in the rootfs.

/// Authentication binaries for /usr/bin.
///
/// Implements privilege escalation and user management.
pub const AUTH_BIN: &[&str] = &["su", "sudo", "sudoedit", "sudoreplay"];

/// Authentication binaries for /usr/sbin.
///
/// **unix_chkpwd is CRITICAL**: pam_unix.so has a hardcoded path to /usr/sbin/unix_chkpwd.
/// Without it, chpasswd/passwd silently fail (PAM returns success but password unchanged).
/// This is the most common cause of silent authentication failures.
pub const AUTH_SBIN: &[&str] = &["visudo", "unix_chkpwd"];

/// Additional shadow-utils binaries for /usr/sbin.
///
/// These provide password expiry, account lockout, and batch user management.
pub const SHADOW_SBIN: &[&str] = &[
    "faillock",  // Account lockout management (pam_faillock)
    "chage",     // Password expiry management
    "newusers",  // Batch user creation
    "chgpasswd", // Batch group password changes
    "pwck",      // Verify passwd file integrity
    "grpck",     // Verify group file integrity
    "vipw",      // Safe passwd/shadow/group editing
    "vigr",      // Safe group editing
    "pwconv",    // Convert to shadow format
    "pwunconv",  // Unconvert from shadow format
    "grpconv",   // Convert to shadow group format
    "grpunconv", // Unconvert from shadow group format
];

/// SSH binaries in /usr/sbin.
///
/// Implements remote login capability for the system.
pub const SSH_SBIN: &[&str] = &["sshd"];

/// SSH binaries in /usr/bin.
///
/// Client-side SSH utilities for users.
pub const SSH_BIN: &[&str] = &["ssh", "scp", "sftp", "ssh-keygen", "ssh-add", "ssh-agent"];

/// PAM modules in /usr/lib64/security/.
///
/// Only includes modules actually used by LevitateOS PAM configurations.
/// Verified against all /etc/pam.d/*.so references.
pub const PAM_MODULES: &[&str] = &[
    // === CORE AUTH ===
    "pam_unix.so", // Traditional Unix password auth (CRITICAL)
    "pam_deny.so", // Always deny (fallback for 'other' policy)
    // === PASSWORD QUALITY ===
    "pam_pwquality.so", // Password strength checking (password stack)
    // === ACCOUNT ACCESS ===
    "pam_access.so",  // /etc/security/access.conf (login services)
    "pam_nologin.so", // Deny login when /etc/nologin exists (login)
    "pam_rootok.so",  // Skip auth for root (su, runuser)
    // === FAILURE/DELAY ===
    "pam_faildelay.so", // Delay after auth failure (system-auth)
    // === RESOURCE LIMITS ===
    "pam_limits.so", // /etc/security/limits.conf (ulimit)
    "pam_umask.so",  // Set default umask (session)
    // === SESSION SETUP ===
    "pam_env.so",       // Set environment from pam_env.conf (auth)
    "pam_systemd.so",   // Register session with systemd-logind (session)
    "pam_keyinit.so",   // Initialize kernel keyring (session)
    "pam_loginuid.so",  // Set loginuid for auditing (login, su, su-l)
    "pam_namespace.so", // Polyinstantiated /tmp per-user (login, su-l)
    // === CONDITIONAL ===
    "pam_succeed_if.so", // Conditional success (system-auth cron bypass)
    // === INFO/LOGGING ===
    "pam_lastlog.so", // Record/display last login (postlogin)
    "pam_motd.so",    // Display message of the day (postlogin)
    // === X11 ===
    "pam_xauth.so", // Forward X11 credentials on su (su-l)
];

/// Essential PAM configuration files in /etc/pam.d/.
///
/// These files define the authentication policy for all services.
/// Each file contains stacks of PAM modules that are called in sequence.
///
/// Note: Not all PAM-using services need their own config file.
/// User/group management commands (useradd, groupadd, chage, etc.) fall back
/// to the "other" policy and don't have custom configs.
pub const PAM_CONFIGS: &[&str] = &[
    // === CORE AUTH STACKS ===
    "etc/pam.d/system-auth",   // Main auth stack (password, session, account)
    "etc/pam.d/password-auth", // Password-based auth (remote services)
    // === LOGIN SERVICES ===
    "etc/pam.d/login",  // Console login (agetty)
    "etc/pam.d/sshd",   // SSH login
    "etc/pam.d/remote", // Remote login services
    // === PRIVILEGE ESCALATION ===
    "etc/pam.d/sudo",      // sudo command
    "etc/pam.d/su",        // su command
    "etc/pam.d/su-l",      // su - (login shell)
    "etc/pam.d/runuser",   // runuser (root-only su)
    "etc/pam.d/runuser-l", // runuser - (login shell)
    // === PASSWORD MANAGEMENT ===
    "etc/pam.d/passwd",   // passwd command
    "etc/pam.d/chpasswd", // chpasswd command (batch password setting)
    "etc/pam.d/chfn",     // chfn command (change full name)
    "etc/pam.d/chsh",     // chsh command (change shell)
    // === SYSTEM SERVICES ===
    "etc/pam.d/crond",        // cron daemon
    "etc/pam.d/systemd-user", // systemd user sessions
    // === FALLBACK ===
    "etc/pam.d/other", // Fallback for unconfigured services (should deny)
    // === POSTLOGIN ===
    "etc/pam.d/postlogin", // Post-login session setup (included by login services)
];

/// Security configuration files in /etc/security/.
///
/// These files configure PAM policies, resource limits, and access control.
/// Only includes files actually created by create_security_config().
pub const SECURITY_FILES: &[&str] = &[
    "etc/security/limits.conf",    // Resource limits (ulimit)
    "etc/security/pam_env.conf",   // PAM environment variables
    "etc/security/access.conf",    // Access control by user/group/host
    "etc/security/namespace.conf", // Namespace/polyinstantiation
    "etc/security/pwquality.conf", // Password quality requirements
];

/// Libraries required for sudo.
///
/// The sudo binary depends on several shared libraries from sudo-libs.
pub const SUDO_LIBS: &[&str] = &[
    "libsudo_util.so.0.0.0",
    "libsudo_util.so.0",
    "libsudo_util.so",
    "sudoers.so",
    "group_file.so",
    "system_group.so",
];
