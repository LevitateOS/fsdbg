//! Binary definitions for /usr/bin and /usr/sbin.

/// Binaries for /usr/bin.
///
/// These are the core utilities expected in a daily-driver Linux distribution.
/// Comparable to Arch Linux base + base-devel.
pub const BIN_UTILS: &[&str] = &[
    // === COREUTILS ===
    "ls",
    "cat",
    "cp",
    "mv",
    "rm",
    "mkdir",
    "rmdir",
    "touch",
    "chmod",
    "chown",
    "chgrp",
    "ln",
    "readlink",
    "realpath",
    "stat",
    "file",
    "mknod",
    "mkfifo",
    "timeout",
    "sleep",
    "true",
    "false",
    "test",
    "[",
    // Text processing
    "echo",
    "head",
    "tail",
    "wc",
    "sort",
    "cut",
    "tr",
    "tee",
    "sed",
    "awk",
    "gawk",
    "printf",
    "uniq",
    "seq",
    // Search
    "grep",
    "find",
    "xargs",
    // System info
    "pwd",
    "uname",
    "date",
    "env",
    "id",
    "hostname",
    "printenv",
    "whoami",
    "groups",
    "dmesg",
    "lsusb",
    // Process control
    "kill",
    "nice",
    "nohup",
    "setsid",
    // Compression
    "gzip",
    "gunzip",
    "xz",
    "unxz",
    "tar",
    "bzip2",
    "bunzip2",
    "cpio",
    // Shell utilities
    "expr",
    "yes",
    "mktemp",
    // Disk info
    "df",
    "du",
    "sync",
    "mount",
    "umount",
    "lsblk",
    "findmnt",
    "flock",
    // Path utilities
    "dirname",
    "basename",
    // Other
    "which",
    // === DIFFUTILS ===
    "diff",
    "cmp",
    // === PROCPS-NG ===
    "ps",
    "pgrep",
    "pkill",
    "top",
    "free",
    "uptime",
    "w",
    "vmstat",
    "watch",
    // === SYSTEMD ===
    "systemctl",
    "journalctl",
    "timedatectl",
    "hostnamectl",
    "localectl",
    "loginctl",
    "bootctl",
    "systemd-tmpfiles", // Note: this is in /usr/bin/, not /usr/lib/systemd/
    // === EDITORS ===
    "vi",
    "vim",
    "nano",
    // === NETWORK ===
    "ping",
    "curl",
    "wget",
    // === TERMINAL ===
    "clear",
    "stty",
    "tty",
    // === KEYBOARD ===
    "loadkeys",
    // === LOCALE ===
    "localedef",
    // === UDEV ===
    "udevadm",
    // === MISC ===
    "less",
    "more",
    // === UTIL-LINUX ===
    "getopt",
    // === GLIBC UTILITIES ===
    "getent",
    "ldd",
    // === CHECKSUMS ===
    "base64",
    "md5sum",
    "sha256sum",
    "sha512sum",
    // === TERMINAL MULTIPLEXER ===
    "tmux",
    "screen",
    // === NETWORK DIAGNOSTICS ===
    "dig",
    "nslookup",
    "tracepath",
    // iwctl (iwd) is not in the base repos; WiFi uses NetworkManager-wifi
    // === BINARY INSPECTION ===
    "strings",
    "hexdump",
    // === FILE SYNC ===
    "rsync",
    // === DOCUMENTATION ===
    "man",
    "mandb",
    "apropos",
    "whatis",
    // === FILE MANAGERS ===
    "mc",
    "mcedit",
    "mcview",
    // === PIPE UTILITIES ===
    "pv",
    // === TEXT BROWSER ===
    "lynx",
    // === NETWORK TOOLS ===
    "nmap",
    // === AUDIO ===
    "alsamixer",
    "amixer",
    "aplay",
    "arecord",
    "speaker-test",
    // === GPG/CRYPTO ===
    "gpg",
    "gpg2",
    "gpgconf",
    "gpg-agent",
    // === NTFS (bin tools) ===
    "ntfsfix",
    "ntfscat",
    "ntfscluster",
    "ntfscmp",
    "ntfsfallocate",
    "ntfsinfo",
    "ntfsls",
    "ntfsmove",
    "ntfsrecover",
    "ntfssecaudit",
    "ntfstruncate",
    "ntfsusermap",
    "ntfswipe",
    // === VERSION CONTROL ===
    "git",
    // === SCRIPTING LANGUAGES ===
    "python3", // the base packages provide no 'python' symlink
    "perl",
    // === PROCESS MONITORING ===
    "htop",
    // === ARCHIVE TOOLS ===
    "zip",
    "unzip",
    "7za", // Note: p7zip only provides 7za wrapper script, not 7z/7zr
    // === DIRECTORY TOOLS ===
    "tree",
    // === BLUETOOTH ===
    "bluetoothctl",
    // === PIPEWIRE AUDIO ===
    "pw-cli",
    "pw-dump",
    "pw-cat",
    "pw-play",
    "pw-record",
    "pw-top",
    "pw-metadata",
    "pw-mon",
    "pw-link",
    "wpctl", // WirePlumber control
    // === PULSEAUDIO COMPAT (pipewire-pulse) ===
    "pactl",
    "paplay",
    "parecord", // Note: pacmd not provided by pipewire-pulseaudio
    // === POLKIT ===
    "pkexec",
    "pkaction",
    "pkcheck",
    // === UDISKS2 ===
    "udisksctl",
    // === POWER MANAGEMENT ===
    "upower",
];

// Authentication and SSH binaries are listed in `super::auth`.

/// NetworkManager binaries for /usr/bin.
pub const NM_BIN: &[&str] = &["nmcli", "nm-online", "nmtui"];

/// Binaries for /usr/sbin.
///
/// System administration utilities requiring elevated privileges.
pub const SBIN_UTILS: &[&str] = &[
    // === UTIL-LINUX ===
    "fsck",
    "blkid",
    "losetup",
    "mkswap",
    "swapon",
    "swapoff",
    "fdisk",
    "sfdisk",
    "wipefs",
    "blockdev",
    "pivot_root",
    "chroot",
    "switch_root",
    "parted",
    // === E2FSPROGS ===
    "fsck.ext4",
    "fsck.ext2",
    "fsck.ext3",
    "e2fsck",
    "mke2fs",
    "mkfs.ext4",
    "mkfs.ext2",
    "mkfs.ext3",
    "tune2fs",
    "resize2fs",
    // === DOSFSTOOLS ===
    "mkfs.fat",
    "mkfs.vfat",
    "fsck.fat",
    "fsck.vfat",
    // === BTRFS ===
    "btrfs",
    "btrfsck",
    "mkfs.btrfs",
    "btrfs-convert",
    "btrfs-find-root",
    "btrfs-image",
    "btrfs-map-logical",
    "btrfs-select-super",
    // === NTFS (sbin tools) ===
    "mkfs.ntfs",
    "ntfsresize",
    "ntfsclone",
    "ntfscp",
    "ntfslabel",
    // === KMOD ===
    "insmod",
    "rmmod",
    "modprobe",
    "lsmod",
    "depmod",
    "modinfo",
    // === SHADOW-UTILS ===
    "useradd",
    "userdel",
    "usermod",
    "groupadd",
    "groupdel",
    "groupmod",
    "chpasswd",
    "passwd",
    // === IPROUTE ===
    "ip",
    "ss",
    "bridge",
    // === PROCPS-NG ===
    "sysctl",
    // === SYSTEM CONTROL ===
    "reboot",
    "shutdown",
    "poweroff",
    "halt",
    "efibootmgr",
    // === OTHER ===
    "ldconfig",
    "hwclock",
    "lspci",
    "ifconfig",
    "route",
    "agetty",
    "login",
    "sulogin",
    "nologin",
    "chronyd",
    // === CRYPTSETUP (LUKS) ===
    "cryptsetup",
    // === LVM ===
    "lvm",
    // === RAID ===
    "mdadm",
    "mdmon",
    // === HARDWARE DETECTION ===
    "dmidecode",
    "ethtool",
    // === XFS ===
    "mkfs.xfs",
    "xfs_repair",
    "xfs_admin",
    "xfs_copy",
    "xfs_db",
    "xfs_freeze",
    "xfs_growfs",
    "xfs_info",
    "xfs_io",
    "xfs_logprint",
    "xfs_mdrestore",
    "xfs_metadump",
    "xfs_ncheck",
    "xfs_quota",
    "xfs_rtcp",
    "xfs_spaceman",
    // === DISK HEALTH ===
    "smartctl",
    "hdparm",
    "nvme",
    // === RECOVERY TOOLS ===
    "ddrescue",
    "testdisk",
    "photorec",
];

// Authentication and shadow-utils binaries have been moved to the auth subsystem.
// Listed in `super::auth`.

/// NetworkManager binaries for /usr/sbin.
pub const NM_SBIN: &[&str] = &["NetworkManager"];

/// wpa_supplicant binaries for /usr/sbin.
pub const WPA_SBIN: &[&str] = &["wpa_supplicant", "wpa_cli", "wpa_passphrase"];

// SSH server binaries have been moved to the auth subsystem.
// Listed in `super::auth`.

/// Bluetooth binaries for /usr/sbin (from bluez).
/// Note: bluetoothd is in /usr/libexec/bluetooth/, not /usr/sbin - handled via CopyTree
pub const BLUETOOTH_SBIN: &[&str] = &[];

/// PipeWire binaries for /usr/sbin.
pub const PIPEWIRE_SBIN: &[&str] = &["pipewire", "pipewire-pulse", "wireplumber"];

/// Polkit binaries for /usr/sbin.
/// Note: polkitd is in /usr/lib/polkit-1/, not /usr/sbin - handled via config_trees
pub const POLKIT_SBIN: &[&str] = &[];

/// UDisks2 binaries for /usr/sbin.
/// Note: udisksd is in /usr/libexec/udisks2/, not /usr/sbin - handled via config_trees
pub const UDISKS_SBIN: &[&str] = &[];

/// UPower binaries for /usr/sbin.
/// Note: upowerd is in /usr/libexec/, not /usr/sbin - handled via config_trees
pub const UPOWER_SBIN: &[&str] = &[];
