//! Systemd binary and udev helper definitions.

/// Systemd helper binaries in /usr/lib/systemd/.
/// Note: systemd-tmpfiles is in /usr/bin/, not here - see BIN_UTILS.
pub const SYSTEMD_BINARIES: &[&str] = &[
    "systemd-executor",
    "systemd-shutdown",
    "systemd-sulogin-shell",
    "systemd-cgroups-agent",
    "systemd-journald",
    "systemd-modules-load",
    "systemd-sysctl",
    // systemd-tmpfiles is in /usr/bin/, not /usr/lib/systemd/ - see BIN_UTILS
    "systemd-timedated",
    "systemd-hostnamed",
    "systemd-localed",
    "systemd-logind",
    "systemd-networkd",
    "systemd-resolved",
    "systemd-udevd",
    "systemd-fsck",
    "systemd-remount-fs",
    "systemd-makefs", // For creating/formatting filesystems during boot
    "systemd-vconsole-setup",
    "systemd-random-seed",
];

/// Udev helper binaries in /usr/lib/udev/.
pub const UDEV_HELPERS: &[&str] = &[
    "ata_id",
    "scsi_id",
    "cdrom_id",
    "v4l_id",
    "dmi_memory_id",
    "mtd_probe",
];
