//! /etc files and critical library definitions.

/// Essential /etc files for a bootable system.
pub const ETC_FILES: &[&str] = &[
    // === USER DATABASE ===
    "etc/passwd",
    "etc/group",
    "etc/shadow",
    "etc/gshadow",
    // === NETWORK ===
    "etc/hostname",
    "etc/hosts",
    "etc/resolv.conf",
    "etc/nsswitch.conf",
    // === SYSTEM IDENTITY ===
    "etc/os-release",
    "etc/machine-id",
    // === FILESYSTEM ===
    "etc/fstab",
    // === LIBRARIES ===
    "etc/ld.so.conf",
    // === SHELLS ===
    "etc/shells",
    // === LOGIN/AUTH ===
    "etc/login.defs",
    // === SUDO ===
    "etc/sudoers",
    "etc/sudo.conf",
    // === SSH SERVER ===
    "etc/ssh/sshd_config",
    "etc/ssh/ssh_host_rsa_key",
    "etc/ssh/ssh_host_rsa_key.pub",
    "etc/ssh/ssh_host_ecdsa_key",
    "etc/ssh/ssh_host_ecdsa_key.pub",
    "etc/ssh/ssh_host_ed25519_key",
    "etc/ssh/ssh_host_ed25519_key.pub",
    // === SSH CLIENT ===
    "etc/ssh/ssh_config",
    // === TIMEZONE ===
    "etc/localtime",
    // === TIME SYNC ===
    "etc/chrony.conf",
    // === LOCALE ===
    "etc/locale.conf",
    "etc/vconsole.conf",
];

/// Critical libraries that must exist for system to boot.
///
/// NOTE: In glibc 2.34+, libpthread/libdl/librt are merged into libc.so.6,
/// but the .so.0 files must still exist as compatibility stubs for binaries
/// compiled against older glibc. Without these, apps fail with:
///   "error while loading shared libraries: libpthread.so.0: cannot open..."
pub const CRITICAL_LIBS: &[&str] = &[
    // Core glibc
    "usr/lib64/libc.so.6",
    "usr/lib64/ld-linux-x86-64.so.2",
    // glibc 2.34+ compatibility stubs (REQUIRED for older binaries)
    // These are symlinks to libc.so.6 but must exist
    "usr/lib64/libpthread.so.0",
    "usr/lib64/libdl.so.2",
    "usr/lib64/librt.so.1",
    "usr/lib64/libm.so.6",
    // PAM and auth
    "usr/lib64/libpam.so.0",
    "usr/lib64/libcrypt.so.2",
    // systemd and security
    "usr/lib64/libsystemd.so.0",
    "usr/lib64/libnss_files.so.2",
    "usr/lib64/libselinux.so.1",
];
