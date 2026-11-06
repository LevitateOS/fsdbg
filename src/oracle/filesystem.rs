//! Filesystem hierarchy definitions.

/// FHS directory structure for a complete rootfs.
///
/// These directories are created during rootfs build and verified by fsdbg.
pub const FHS_DIRS: &[&str] = &[
    // /usr hierarchy (merged)
    "usr/bin",
    "usr/sbin",
    "usr/lib",
    "usr/lib64",
    "usr/share",
    "usr/share/man",
    "usr/share/doc",
    "usr/share/licenses",
    "usr/share/zoneinfo",
    "usr/local/bin",
    "usr/local/sbin",
    "usr/local/lib",
    "usr/local/share",
    // /etc configuration
    "etc",
    "etc/systemd/system",
    "etc/pam.d",
    "etc/security",
    "etc/profile.d",
    // XDG Base Directory spec
    "etc/xdg",
    "etc/xdg/autostart",
    // User skeleton with XDG structure
    "etc/skel",
    "etc/skel/.config",
    "etc/skel/.local",
    "etc/skel/.local/share",
    "etc/skel/.local/state",
    "etc/skel/.cache",
    // Volatile directories
    "proc",
    "sys",
    "dev",
    "dev/pts",
    "dev/shm",
    "run",
    "run/lock",
    "tmp",
    // Persistent data
    "var",
    "var/log",
    "var/log/journal",
    "var/tmp",
    "var/cache",
    "var/lib",
    "var/spool",
    // Mount points
    "mnt",
    "media",
    // User directories
    "root",
    "home",
    // Optional
    "opt",
    "srv",
    // Boot (for installed kernels)
    "boot",
    // Systemd
    "usr/lib/systemd/system",
    "usr/lib/systemd/system-generators",
    "usr/lib64/systemd",
    // Modules
    "usr/lib/modules",
    // PAM
    "usr/lib64/security",
    // D-Bus
    "usr/share/dbus-1/system.d",
    "usr/share/dbus-1/system-services",
    // Locale
    "usr/lib/locale",
];

/// Merged-usr symlinks that must exist.
pub const FHS_SYMLINKS: &[(&str, &str)] = &[
    ("bin", "usr/bin"),
    ("sbin", "usr/sbin"),
    ("lib", "usr/lib"),
    ("lib64", "usr/lib64"),
];

/// /var symlinks to /run (systemd convention).
pub const VAR_SYMLINKS: &[(&str, &str)] = &[("var/run", "/run"), ("var/lock", "/run/lock")];
