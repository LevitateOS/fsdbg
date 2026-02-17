//! ISO 9660 image checklist for Stage 00 live ISOs.
//!
//! Verifies shared cross-distro boot infrastructure:
//! kernel/initramfs/rootfs/overlay + EFI boot essentials + live UKIs.
//!
//! ## ISO Structure
//!
//! ```text
//! ISO Root:
//! ├── boot/
//! │   ├── vmlinuz                    # Linux kernel
//! │   ├── initramfs.img              # Live initramfs (tiny, mounts EROFS)
//! │   └── initramfs.img              # Live initramfs (tiny, mounts EROFS)
//! ├── live/
//! │   ├── filesystem.erofs           # EROFS rootfs (minimal in Stage 00)
//! │   └── overlayfs.erofs            # Live overlay payload image (EROFS)
//! ├── EFI/
//! │   ├── BOOT/
//! │   │   └── BOOTX64.EFI            # systemd-boot
//! │   └── Linux/
//! │       ├── <distro>-live.efi      # Live boot UKI
//! │       ├── <distro>-emergency.efi # Emergency UKI
//! │       └── <distro>-debug.efi     # Debug UKI
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
//! 6. init_tiny mounts ISO by LABEL=<distro label>
//! 7. Mounts `/live/filesystem.erofs` as lower layer
//! 8. Mounts `live/overlayfs.erofs` as middle lowerdir payload
//! 9. Mounts tmpfs as upper layer (for writes)
//! 10. switch_root to overlay

use super::{CheckCategory, CheckResult, VerificationReport};
use crate::iso::IsoReader;

// Import constants from distro-spec
use distro_spec::shared::{
    EFIBOOT_FILENAME,
    // ISO structure
    EFI_BOOTLOADER,
    INITRAMFS_LIVE_ISO_PATH,
    ISO_BOOT_DIR,
    ISO_EFI_DIR,
    ISO_LIVE_DIR,
    KERNEL_ISO_PATH,
    LIVE_OVERLAYFS_ISO_PATH,
    LIVE_OVERLAY_ISO_PATH,
    LOADER_CONF_FILENAME,
    LOADER_ENTRIES_DIR,
    ROOTFS_ISO_PATH,
    UKI_EFI_DIR,
};

// =============================================================================
// DIRECTORIES
// =============================================================================

/// Directories that exist in the ISO.
pub const DIRS: &[&str] = &[
    // Boot directory (kernel, initramfs)
    ISO_BOOT_DIR, // "boot"
    // Live directory (EROFS rootfs, overlay)
    ISO_LIVE_DIR, // "live"
    // EFI boot structure
    "EFI",
    ISO_EFI_DIR, // "EFI/BOOT"
    UKI_EFI_DIR, // "EFI/Linux"
    // systemd-boot loader config
    LOADER_ENTRIES_DIR, // "loader"
];

// =============================================================================
// BOOT FILES
// =============================================================================

/// Boot files (kernel, initramfs).
pub const BOOT_FILES: &[&str] = &[
    // Linux kernel
    KERNEL_ISO_PATH, // "boot/vmlinuz"
    // Live initramfs (tiny - mounts EROFS from ISO)
    INITRAMFS_LIVE_ISO_PATH, // "boot/initramfs-live.img"
];

// =============================================================================
// ROOTFS FILES
// =============================================================================

/// Rootfs and overlay payload image files.
pub const ROOTFS_FILES: &[&str] = &[
    // EROFS rootfs (~350MB complete system)
    ROOTFS_ISO_PATH, // "live/filesystem.erofs"
    // Live overlay payload image (read-only EROFS)
    LIVE_OVERLAYFS_ISO_PATH, // "live/overlayfs.erofs"
];

/// Compatibility alias retained in distro-spec. Checklist uses image path.
#[allow(dead_code)]
pub const OVERLAY_COMPAT_ALIAS: &str = LIVE_OVERLAY_ISO_PATH;

/// Required number of live UKIs under `/EFI/Linux`.
pub const LIVE_UKI_MIN_COUNT: usize = 3;

// =============================================================================
// LOADER CONFIG
// =============================================================================

/// systemd-boot loader configuration file.
pub const LOADER_CONF: &str = LOADER_CONF_FILENAME; // "loader.conf"

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
    let uki_prefix = format!("/{}/", UKI_EFI_DIR);
    let live_uki_count = reader
        .entries()
        .iter()
        .filter(|entry| {
            !entry.is_dir && entry.path.starts_with(&uki_prefix) && entry.path.ends_with(".efi")
        })
        .count();
    if live_uki_count >= LIVE_UKI_MIN_COUNT {
        report.add(CheckResult::pass(
            format!("{}*.efi (count={})", uki_prefix, live_uki_count),
            CheckCategory::Binary,
        ));
    } else {
        report.add(CheckResult::fail(
            format!("{}*.efi (count={})", uki_prefix, live_uki_count),
            CheckCategory::Binary,
            format!(
                "Expected at least {} live UKIs in EFI/Linux",
                LIVE_UKI_MIN_COUNT
            ),
        ));
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
    // 7. Check volume label presence
    // =========================================================================
    if let Some(vol_id) = reader.volume_id() {
        if !vol_id.trim().is_empty() {
            report.add(CheckResult::pass(
                format!("Volume ID: {}", vol_id),
                CheckCategory::Other,
            ));
        } else {
            report.add(CheckResult::fail(
                format!("Volume ID: {}", vol_id),
                CheckCategory::Other,
                "Empty volume ID (init may fail to find boot device)",
            ));
        }
    } else {
        report.add(CheckResult::fail(
            "Volume ID",
            CheckCategory::Other,
            "No volume ID set",
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
    fn test_live_uki_min_count() {
        assert_eq!(LIVE_UKI_MIN_COUNT, 3);
    }
}
