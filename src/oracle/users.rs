//! System user, group, and installation tool definitions.

/// System users that must exist in /etc/passwd.
pub const SYSTEM_USERS: &[&str] = &[
    "root", "dbus", "sshd", "chrony", "polkitd",
    "pipewire", // For PipeWire system mode (optional)
];

/// System groups that must exist in /etc/group.
pub const SYSTEM_GROUPS: &[&str] = &[
    "root",
    "wheel",
    "dbus",
    "sshd",
    "chrony",
    "polkitd",
    "pipewire",
    "bluetooth", // Users in this group can use bluetooth
    "audio",     // Users in this group can use audio
    "video",     // Users in this group can use video devices
];

/// LevitateOS-specific installation tools (ALL).
///
/// These are REQUIRED for installing LevitateOS from the live ISO.
/// They are automatically rebuilt during ISO creation to ensure latest versions.
///
/// - recstrap: Rootfs extractor (like pacstrap)
/// - recfstab: Fstab generator (like genfstab)
/// - recchroot: Chroot helper (like arch-chroot)
/// - recipe: Package manager (like pacman)
/// - levitate-docs: Interactive documentation TUI
pub const LEVITATE_TOOLS: &[&str] = &[
    "recstrap",
    "recfstab",
    "recchroot",
    "recipe",
    "levitate-docs",
];

