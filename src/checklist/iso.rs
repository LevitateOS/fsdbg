//! ISO 9660 image checklist for LevitateOS live ISO.
//!
//! Verifies that the ISO contains all required boot infrastructure,
//! UKIs, and root filesystem components.
//!
//! Uses constants from `distro-spec` to ensure consistency with the build system.

use super::{CheckCategory, CheckResult, VerificationReport};
use crate::iso::IsoReader;
use distro_spec::shared::{
    EFI_BOOTLOADER, INITRAMFS_LIVE_ISO_PATH, ISO_BOOT_DIR, ISO_EFI_DIR, ISO_LIVE_DIR,
    KERNEL_ISO_PATH, ROOTFS_ISO_PATH,
};
use distro_spec::levitate::ISO_LABEL;

/// Required files that must exist in the ISO.
/// Built from distro-spec constants with leading slashes for ISO paths.
pub fn required_paths() -> Vec<String> {
    vec![
        format!("/{}", KERNEL_ISO_PATH),
        format!("/{}", INITRAMFS_LIVE_ISO_PATH),
        format!("/{}/{}", ISO_EFI_DIR, EFI_BOOTLOADER),
        format!("/{}", ROOTFS_ISO_PATH),
    ]
}

/// Required directories.
/// Built from distro-spec constants with leading slashes for ISO paths.
pub fn required_dirs() -> Vec<String> {
    vec![
        format!("/{}", ISO_BOOT_DIR),
        "/EFI".to_string(),
        format!("/{}", ISO_EFI_DIR),
        format!("/{}", ISO_LIVE_DIR),
    ]
}

/// Expected volume label from distro-spec.
pub const EXPECTED_VOLUME_ID: &str = ISO_LABEL;

/// Verify an ISO image against the live ISO checklist.
pub fn verify(reader: &IsoReader) -> VerificationReport {
    let mut report = VerificationReport::new("Live ISO");

    // Check required directories
    for dir in required_dirs() {
        if reader.exists(&dir) {
            report.add(CheckResult::pass(&dir, CheckCategory::Directory));
        } else {
            report.add(CheckResult::fail(
                &dir,
                CheckCategory::Directory,
                "Missing directory",
            ));
        }
    }

    // Check required files
    for path in required_paths() {
        if reader.exists(&path) {
            report.add(CheckResult::pass(&path, CheckCategory::Other));
        } else {
            report.add(CheckResult::fail(&path, CheckCategory::Other, "Missing file"));
        }
    }

    // Check volume label
    if let Some(vol_id) = reader.volume_id() {
        if vol_id == EXPECTED_VOLUME_ID {
            report.add(CheckResult::pass(
                format!("Volume ID: {}", vol_id),
                CheckCategory::Other,
            ));
        } else {
            report.add(CheckResult::fail(
                format!("Volume ID: {}", vol_id),
                CheckCategory::Other,
                format!("Expected {}", EXPECTED_VOLUME_ID),
            ));
        }
    } else {
        report.add(CheckResult::fail(
            "Volume ID",
            CheckCategory::Other,
            "No volume ID set",
        ));
    }

    // Check for at least one UKI in EFI/Linux/
    let has_uki = reader
        .entries()
        .iter()
        .any(|e| e.path.starts_with("/EFI/Linux/") && e.path.ends_with(".efi"));

    if has_uki {
        report.add(CheckResult::pass(
            "UKI in /EFI/Linux/",
            CheckCategory::Other,
        ));
    } else {
        report.add(CheckResult::fail(
            "UKI in /EFI/Linux/",
            CheckCategory::Other,
            "No .efi files found in /EFI/Linux/",
        ));
    }

    report
}
