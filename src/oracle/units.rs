//! Systemd unit definitions.

/// Essential systemd unit files.
///
/// These units are required for a bootable system.
pub const ESSENTIAL_UNITS: &[&str] = &[
    // Targets
    "basic.target",
    "sysinit.target",
    "multi-user.target",
    "default.target",
    "getty.target",
    "local-fs.target",
    "local-fs-pre.target",
    "remote-fs.target",
    "remote-fs-pre.target",
    "network.target",
    "network-pre.target",
    "network-online.target",
    "paths.target",
    "slices.target",
    "sockets.target",
    "timers.target",
    "swap.target",
    "shutdown.target",
    "rescue.target",
    "emergency.target",
    "reboot.target",
    "poweroff.target",
    "halt.target",
    "suspend.target",
    "sleep.target",
    "umount.target",
    "final.target",
    "graphical.target",
    // Initrd targets (required for install initramfs boot)
    "initrd.target",
    "initrd-root-fs.target",
    "initrd-root-device.target",
    "initrd-switch-root.target",
    "initrd-fs.target",
    // Services - core
    "systemd-journald.service",
    "systemd-journald@.service",
    "systemd-udevd.service",
    "systemd-udev-trigger.service",
    "systemd-modules-load.service",
    "systemd-sysctl.service",
    "systemd-tmpfiles-setup.service",
    "systemd-tmpfiles-setup-dev.service",
    "systemd-tmpfiles-clean.service",
    "systemd-random-seed.service",
    "systemd-vconsole-setup.service",
    // Services - disk
    "systemd-fsck-root.service",
    "systemd-fsck@.service",
    "systemd-remount-fs.service",
    // Note: systemd-fstab-generator is in system-generators/, not a unit file
    // Services - initrd (required for install initramfs boot)
    "initrd-switch-root.service",
    "initrd-cleanup.service",
    "initrd-udevadm-cleanup-db.service",
    "initrd-parse-etc.service",
    // Services - auth
    "systemd-logind.service",
    // Services - getty
    "getty@.service",
    "serial-getty@.service",
    "console-getty.service",
    "container-getty@.service",
    // Services - shutdown (CRITICAL: required for halt/poweroff/reboot)
    "systemd-halt.service",
    "systemd-poweroff.service",
    "systemd-reboot.service",
    "systemd-soft-reboot.service",
    // Services - time/network
    "systemd-timedated.service",
    "systemd-hostnamed.service",
    "systemd-localed.service",
    "systemd-networkd.service",
    "systemd-resolved.service",
    "systemd-networkd-wait-online.service",
    // Services - misc
    "dbus.service",
    "dbus-broker.service",
    "chronyd.service",
    // Services - SSH
    "sshd.service",
    "sshd@.service",
    "sshd.socket",
    "sshd-keygen.target",
    "sshd-keygen@.service",
    // Sockets
    "systemd-journald.socket",
    "systemd-journald-dev-log.socket",
    "systemd-journald-audit.socket",
    "systemd-udevd-control.socket",
    "systemd-udevd-kernel.socket",
    "dbus.socket",
    // Paths
    "systemd-ask-password-console.path",
    "systemd-ask-password-wall.path",
    // Slices (note: -.slice, system.slice, machine.slice are built-in to systemd)
    "user.slice",
];

/// NetworkManager units.
pub const NM_UNITS: &[&str] = &[
    "NetworkManager.service",
    "NetworkManager-dispatcher.service",
];

/// wpa_supplicant units.
pub const WPA_UNITS: &[&str] = &["wpa_supplicant.service"];

/// Bluetooth units (bluez).
pub const BLUETOOTH_UNITS: &[&str] = &["bluetooth.service", "bluetooth.target"];

/// PipeWire units (user service - runs per-user, not system-wide).
/// Note: PipeWire runs as a user service, so these are in user/ not system/.
pub const PIPEWIRE_UNITS: &[&str] = &[
    "pipewire.service",
    "pipewire.socket",
    "pipewire-pulse.service",
    "pipewire-pulse.socket",
    "wireplumber.service",
];

/// Polkit units.
pub const POLKIT_UNITS: &[&str] = &["polkit.service"];

/// UDisks2 units.
pub const UDISKS_UNITS: &[&str] = &["udisks2.service"];

/// UPower units.
pub const UPOWER_UNITS: &[&str] = &["upower.service"];

/// SSH units (for Service definition).
pub const SSH_UNITS: &[&str] = &[
    "sshd.service",
    "sshd.socket",
    "sshd@.service",
    "sshd-keygen.target",
    "sshd-keygen@.service",
    "ssh-host-keys-migration.service",
];

/// D-Bus activation symlinks.
pub const DBUS_ACTIVATION_SYMLINKS: &[&str] = &[
    "dbus-org.freedesktop.timedate1.service",
    "dbus-org.freedesktop.hostname1.service",
    "dbus-org.freedesktop.locale1.service",
    "dbus-org.freedesktop.login1.service",
    "dbus-org.freedesktop.network1.service",
    "dbus-org.freedesktop.resolve1.service",
];

/// Returns ALL systemd units that must be present in the rootfs.
///
/// Composed from the constituent unit lists rather than manually maintained.
/// Duplicates (e.g., SSH units in both ESSENTIAL_UNITS and SSH_UNITS) are removed.
///
/// Used by fsdbg to verify the rootfs contains all required systemd units.
pub fn all_systemd_units() -> Vec<&'static str> {
    let mut seen = std::collections::HashSet::new();
    let mut units = Vec::new();

    let sources: &[&[&str]] = &[
        ESSENTIAL_UNITS,
        NM_UNITS,
        WPA_UNITS,
        BLUETOOTH_UNITS,
        PIPEWIRE_UNITS,
        POLKIT_UNITS,
        UDISKS_UNITS,
        UPOWER_UNITS,
        SSH_UNITS,
        DBUS_ACTIVATION_SYMLINKS,
    ];

    for source in sources {
        for unit in *source {
            if seen.insert(*unit) {
                units.push(*unit);
            }
        }
    }

    units
}
