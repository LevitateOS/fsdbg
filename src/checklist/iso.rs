//! ISO 9660 image checklist for LevitateOS live ISO.
//!
//! Verifies that the ISO contains ALL boot infrastructure,
//! UKIs, rootfs, and installation support files.
//!
//! SOURCE OF TRUTH: `distro-spec/src/shared/iso.rs`, `distro-spec/src/levitate/paths.rs`,
//!                  `distro-spec/src/shared/uki.rs`, `leviso/src/artifact/iso.rs`
//!
//! This checklist must stay in sync with what reciso/leviso actually builds.
//!
//! ## ISO Structure
//!
//! ```text
//! ISO Root:
//! ├── boot/
//! │   ├── vmlinuz                    # Linux kernel
//! │   ├── initramfs.img              # Live initramfs (tiny, mounts EROFS)
//! │   ├── initramfs-installed.img    # Installed initramfs (full, for disk boot)
//! │   └── uki/                       # Pre-built UKIs for installed systems
//! │       ├── levitateos.efi         # Normal boot UKI
//! │       └── levitateos-recovery.efi# Recovery mode UKI
//! ├── live/
//! │   ├── filesystem.erofs           # EROFS rootfs (~350MB)
//! │   └── overlay/                   # Live-specific configs (autologin, etc.)
//! ├── EFI/
//! │   ├── BOOT/
//! │   │   └── BOOTX64.EFI            # systemd-boot
//! │   └── Linux/
//! │       ├── levitateos-live.efi    # Live boot UKI
//! │       ├── levitateos-emergency.efi # Emergency UKI
//! │       └── levitateos-debug.efi   # Debug UKI
//! ├── loader/
//! │   └── loader.conf                # systemd-boot config
//! └── efiboot.img                    # FAT16 EFI boot image
//! ```
//!
//! ## Boot Flow
//!
//! 1. UEFI firmware loads `/EFI/BOOT/BOOTX64.EFI` (systemd-boot)
//! 2. systemd-boot auto-discovers UKIs in `/EFI/Linux/`
//! 3. User selects boot option (or default after timeout)
//! 4. UKI contains kernel + initramfs + cmdline
//! 5. Kernel extracts initramfs to rootfs
//! 6. init_tiny mounts ISO by LABEL=LEVITATEOS
//! 7. Mounts `/live/filesystem.erofs` as lower layer
//! 8. Mounts `/live/overlay` as middle layer
//! 9. Mounts tmpfs as upper layer (for writes)
//! 10. switch_root to overlay

use super::{CheckCategory, CheckResult, VerificationReport};
use crate::iso::IsoReader;

// Import constants from distro-spec
use distro_spec::levitate::{
    // ISO identity
    ISO_LABEL,
    // Paths
    INITRAMFS_INSTALLED_ISO_PATH,
    UKI_INSTALLED_ISO_DIR,
    UKI_INSTALLED_ISO_PATH,
    UKI_INSTALLED_RECOVERY_ISO_PATH,
};
use distro_spec::shared::{
    // ISO structure
    EFI_BOOTLOADER,
    EFIBOOT_FILENAME,
    INITRAMFS_LIVE_ISO_PATH,
    ISO_BOOT_DIR,
    ISO_EFI_DIR,
    ISO_LIVE_DIR,
    KERNEL_ISO_PATH,
    LIVE_OVERLAY_ISO_PATH,
    ROOTFS_ISO_PATH,
    // UKI filenames
    UKI_DEBUG_FILENAME,
    UKI_EFI_DIR,
    UKI_EMERGENCY_FILENAME,
    UKI_LIVE_FILENAME,
    // Loader
    LOADER_ENTRIES_DIR,
    LOADER_CONF_FILENAME,
};

// =============================================================================
// DIRECTORIES
// =============================================================================

/// Directories that exist in the ISO.
pub const DIRS: &[&str] = &[
    // Boot directory (kernel, initramfs)
    ISO_BOOT_DIR,           // "boot"
    // Live directory (EROFS rootfs, overlay)
    ISO_LIVE_DIR,           // "live"
    // EFI boot structure
    "EFI",
    ISO_EFI_DIR,            // "EFI/BOOT"
    UKI_EFI_DIR,            // "EFI/Linux"
    // systemd-boot loader config
    LOADER_ENTRIES_DIR,     // "loader"
    // Installed UKIs directory
    UKI_INSTALLED_ISO_DIR,  // "boot/uki"
];

// =============================================================================
// BOOT FILES
// =============================================================================

/// Boot files (kernel, initramfs).
pub const BOOT_FILES: &[&str] = &[
    // Linux kernel
    KERNEL_ISO_PATH,                // "boot/vmlinuz"
    // Live initramfs (tiny - mounts EROFS from ISO)
    INITRAMFS_LIVE_ISO_PATH,        // "boot/initramfs-live.img"
    // Installed initramfs (full - for installed systems)
    INITRAMFS_INSTALLED_ISO_PATH,   // "boot/initramfs-installed.img"
];

// =============================================================================
// ROOTFS FILES
// =============================================================================

/// Rootfs and overlay files.
pub const ROOTFS_FILES: &[&str] = &[
    // EROFS rootfs (~350MB complete system)
    ROOTFS_ISO_PATH,                // "live/filesystem.erofs"
];

/// Overlay directory (live-specific configs).
/// This is a directory, not a file.
pub const OVERLAY_DIR: &str = LIVE_OVERLAY_ISO_PATH; // "live/overlay"

// =============================================================================
// LIVE UKIS (for booting from ISO)
// =============================================================================

/// Live UKIs for booting from the ISO.
/// These are in /EFI/Linux/ and auto-discovered by systemd-boot.
pub const LIVE_UKIS: &[&str] = &[
    // Normal live boot
    UKI_LIVE_FILENAME,              // "levitateos-live.efi"
    // Emergency shell (emergency target)
    UKI_EMERGENCY_FILENAME,         // "levitateos-emergency.efi"
    // Debug mode (verbose output)
    UKI_DEBUG_FILENAME,             // "levitateos-debug.efi"
];

// =============================================================================
// INSTALLED UKIS (pre-built for installation)
// =============================================================================

/// Installed UKIs - pre-built during ISO creation.
/// Users copy these to /boot/EFI/Linux/ during installation.
pub const INSTALLED_UKIS: &[&str] = &[
    // Normal boot for installed system
    UKI_INSTALLED_ISO_PATH,         // "boot/uki/levitateos.efi"
    // Recovery mode for installed system
    UKI_INSTALLED_RECOVERY_ISO_PATH, // "boot/uki/levitateos-recovery.efi"
];

// =============================================================================
// LOADER CONFIG
// =============================================================================

/// systemd-boot loader configuration file.
pub const LOADER_CONF: &str = LOADER_CONF_FILENAME; // "loader.conf"

// =============================================================================
// VOLUME LABEL
// =============================================================================

/// Expected ISO volume label.
/// Used for boot device detection (root=LABEL=X in kernel params).
pub const VOLUME_ID: &str = ISO_LABEL; // "LEVITATEOS"

// =============================================================================
// VERIFICATION
// =============================================================================

/// Verify an ISO image against the live ISO checklist.
pub fn verify(reader: &IsoReader) -> VerificationReport {
    let mut report = VerificationReport::new("Live ISO");

    // =========================================================================
    // 1. Check directories
    // =========================================================================
    for dir in DIRS {
        let path = format!("/{}", dir);
        if reader.exists(&path) {
            report.add(CheckResult::pass(&path, CheckCategory::Directory));
        } else {
            report.add(CheckResult::fail(
                &path,
                CheckCategory::Directory,
                "Missing",
            ));
        }
    }

    // =========================================================================
    // 2. Check boot files (kernel, initramfs)
    // =========================================================================
    for file in BOOT_FILES {
        let path = format!("/{}", file);
        if reader.exists(&path) {
            report.add(CheckResult::pass(&path, CheckCategory::Binary));
        } else {
            report.add(CheckResult::fail(
                &path,
                CheckCategory::Binary,
                "Missing (CRITICAL: system won't boot)",
            ));
        }
    }

    // =========================================================================
    // 3. Check rootfs files
    // =========================================================================
    for file in ROOTFS_FILES {
        let path = format!("/{}", file);
        if reader.exists(&path) {
            report.add(CheckResult::pass(&path, CheckCategory::Other));
        } else {
            report.add(CheckResult::fail(
                &path,
                CheckCategory::Other,
                "Missing (CRITICAL: no system to boot into)",
            ));
        }
    }

    // Check overlay directory
    let overlay_path = format!("/{}", OVERLAY_DIR);
    if reader.exists(&overlay_path) {
        report.add(CheckResult::pass(&overlay_path, CheckCategory::Directory));
    } else {
        report.add(CheckResult::fail(
            &overlay_path,
            CheckCategory::Directory,
            "Missing (live system won't have autologin/serial console)",
        ));
    }

    // =========================================================================
    // 4. Check EFI boot files
    // =========================================================================
    // systemd-boot in EFI/BOOT/
    let bootloader_path = format!("/{}/{}", ISO_EFI_DIR, EFI_BOOTLOADER);
    if reader.exists(&bootloader_path) {
        report.add(CheckResult::pass(&bootloader_path, CheckCategory::Binary));
    } else {
        report.add(CheckResult::fail(
            &bootloader_path,
            CheckCategory::Binary,
            "Missing (CRITICAL: UEFI won't find bootloader)",
        ));
    }

    // efiboot.img at root
    let efiboot_path = format!("/{}", EFIBOOT_FILENAME);
    if reader.exists(&efiboot_path) {
        report.add(CheckResult::pass(&efiboot_path, CheckCategory::Other));
    } else {
        report.add(CheckResult::fail(
            &efiboot_path,
            CheckCategory::Other,
            "Missing (CRITICAL: EFI boot partition image)",
        ));
    }

    // =========================================================================
    // 5. Check live UKIs in EFI/Linux/
    // =========================================================================
    for uki in LIVE_UKIS {
        let path = format!("/{}/{}", UKI_EFI_DIR, uki);
        if reader.exists(&path) {
            report.add(CheckResult::pass(&path, CheckCategory::Binary));
        } else {
            report.add(CheckResult::fail(
                &path,
                CheckCategory::Binary,
                "Missing (boot menu entry won't appear)",
            ));
        }
    }

    // =========================================================================
    // 6. Check installed UKIs in boot/uki/
    // =========================================================================
    for uki in INSTALLED_UKIS {
        let path = format!("/{}", uki);
        if reader.exists(&path) {
            report.add(CheckResult::pass(&path, CheckCategory::Binary));
        } else {
            report.add(CheckResult::fail(
                &path,
                CheckCategory::Binary,
                "Missing (users can't easily install bootloader)",
            ));
        }
    }

    // =========================================================================
    // 7. Check loader.conf
    // =========================================================================
    let loader_path = format!("/{}/{}", LOADER_ENTRIES_DIR, LOADER_CONF);
    if reader.exists(&loader_path) {
        report.add(CheckResult::pass(&loader_path, CheckCategory::EtcFile));
    } else {
        report.add(CheckResult::fail(
            &loader_path,
            CheckCategory::EtcFile,
            "Missing (systemd-boot config)",
        ));
    }

    // =========================================================================
    // 8. Check volume label
    // =========================================================================
    if let Some(vol_id) = reader.volume_id() {
        if vol_id == VOLUME_ID {
            report.add(CheckResult::pass(
                format!("Volume ID: {}", vol_id),
                CheckCategory::Other,
            ));
        } else {
            report.add(CheckResult::fail(
                format!("Volume ID: {}", vol_id),
                CheckCategory::Other,
                format!("Expected {} (init won't find boot device)", VOLUME_ID),
            ));
        }
    } else {
        report.add(CheckResult::fail(
            "Volume ID",
            CheckCategory::Other,
            format!("No volume ID set (must be {})", VOLUME_ID),
        ));
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dirs_match_distro_spec() {
        // Verify critical directories are present
        assert!(DIRS.contains(&"boot"));
        assert!(DIRS.contains(&"live"));
        assert!(DIRS.contains(&"EFI"));
        assert!(DIRS.contains(&"EFI/BOOT"));
        assert!(DIRS.contains(&"EFI/Linux"));
        assert!(DIRS.contains(&"loader"));
        assert!(DIRS.contains(&"boot/uki"));
    }

    #[test]
    fn test_boot_files_present() {
        // Verify kernel and initramfs paths using actual constants
        // Don't hardcode paths - use the constants from BOOT_FILES
        assert!(!BOOT_FILES.is_empty(), "BOOT_FILES must not be empty");
        assert!(
            BOOT_FILES.iter().any(|p| p.contains("vmlinuz")),
            "BOOT_FILES must contain kernel"
        );
        assert!(
            BOOT_FILES.iter().any(|p| p.contains("initramfs")),
            "BOOT_FILES must contain initramfs"
        );
    }

    #[test]
    fn test_live_ukis_present() {
        // Verify live UKI filenames
        assert!(LIVE_UKIS.contains(&"levitateos-live.efi"));
        assert!(LIVE_UKIS.contains(&"levitateos-emergency.efi"));
        assert!(LIVE_UKIS.contains(&"levitateos-debug.efi"));
    }

    #[test]
    fn test_installed_ukis_present() {
        // Verify installed UKI paths
        assert!(INSTALLED_UKIS.contains(&"boot/uki/levitateos.efi"));
        assert!(INSTALLED_UKIS.contains(&"boot/uki/levitateos-recovery.efi"));
    }

    #[test]
    fn test_volume_label() {
        assert_eq!(VOLUME_ID, "LEVITATEOS");
    }
}
