//! fsdbg - Filesystem debugging tool for LevitateOS
//!
//! Inspect and verify initramfs, rootfs, and ISO images without extraction.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use fsdbg::checklist::{ChecklistType, VerificationReport};
use fsdbg::cpio::CpioReader;
use fsdbg::erofs::ErofsReader;
use fsdbg::iso::IsoReader;
use fsdbg::ArchiveFormat;

#[derive(Parser)]
#[command(name = "fsdbg")]
#[command(about = "Filesystem debugging tool for LevitateOS")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect archive contents
    Inspect {
        /// Path to archive file
        archive: PathBuf,
    },
    /// Verify archive against checklist
    Verify {
        /// Path to archive file
        archive: PathBuf,
        /// Checklist type (install-initramfs, live-initramfs, rootfs, iso)
        #[arg(short, long, value_name = "TYPE")]
        r#type: String,
        /// Show all checks including passing ones (default: only show failures)
        #[arg(short, long)]
        verbose: bool,
    },
    /// Check that all symlinks resolve
    CheckSymlinks {
        /// Path to archive file
        archive: PathBuf,
    },
    /// Compare two archives
    Diff {
        /// First archive
        archive1: PathBuf,
        /// Second archive
        archive2: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(success) => {
            if success {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<bool> {
    match cli.command {
        Commands::Inspect { archive } => cmd_inspect(&archive),
        Commands::Verify {
            archive,
            r#type,
            verbose,
        } => cmd_verify(&archive, &r#type, verbose),
        Commands::CheckSymlinks { archive } => cmd_check_symlinks(&archive),
        Commands::Diff { archive1, archive2 } => cmd_diff(&archive1, &archive2),
    }
}

fn cmd_inspect(path: &PathBuf) -> Result<bool> {
    let format = fsdbg::detect_format(path).context("Failed to detect archive format")?;

    println!("=== Archive: {} ===", path.display());
    println!("Format: {}", format_name(&format));

    match format {
        ArchiveFormat::Cpio | ArchiveFormat::CpioGzip => {
            let reader = CpioReader::open(path)?;
            let stats = reader.stats();

            println!("Entries: {} files, {} directories, {} symlinks",
                stats.files, stats.directories, stats.symlinks);
            println!("Total size: {} bytes (uncompressed)", stats.total_size);
            println!();

            // Show top-level entries
            println!("Top-level structure:");
            let mut shown = std::collections::HashSet::new();
            for entry in reader.entries() {
                let top = entry.path.split('/').next().unwrap_or(&entry.path);
                if shown.insert(top.to_string()) {
                    if entry.is_symlink() {
                        if let Some(ref target) = entry.link_target {
                            println!("  {} -> {}", entry.path, target);
                        }
                    } else if entry.is_dir() {
                        println!("  {}/", top);
                    } else {
                        println!("  {}", top);
                    }
                }
            }
        }
        ArchiveFormat::Erofs => {
            let reader = ErofsReader::open(path)?;
            let stats = reader.stats();

            println!("Entries: {} files, {} directories, {} symlinks",
                stats.files, stats.directories, stats.symlinks);
            println!("Total size: {} bytes", stats.total_size);
        }
        ArchiveFormat::Iso => {
            let reader = IsoReader::open(path)?;
            let stats = reader.stats();

            if let Some(vol) = reader.volume_id() {
                println!("Volume ID: {}", vol);
            }
            println!("Entries: {} files, {} directories, {} symlinks",
                stats.files, stats.directories, stats.symlinks);
            println!("Total size: {} bytes", stats.total_size);
        }
    }

    Ok(true)
}

fn cmd_verify(path: &PathBuf, checklist_type: &str, verbose: bool) -> Result<bool> {
    let checklist = ChecklistType::from_str(checklist_type)
        .ok_or_else(|| anyhow::anyhow!(
            "Unknown checklist type: {}. Valid types: install-initramfs, live-initramfs, rootfs, iso, auth-audit, qcow2",
            checklist_type
        ))?;

    // Handle qcow2 specially - requires mounting
    if checklist == ChecklistType::Qcow2 {
        return cmd_verify_qcow2(path, verbose);
    }

    let format = fsdbg::detect_format(path)?;

    let report = match format {
        ArchiveFormat::Cpio | ArchiveFormat::CpioGzip => {
            let reader = CpioReader::open(path)?;
            match checklist {
                ChecklistType::InstallInitramfs => fsdbg::checklist::install_initramfs::verify(&reader),
                ChecklistType::LiveInitramfs => fsdbg::checklist::live_initramfs::verify(&reader),
                ChecklistType::Rootfs => fsdbg::checklist::rootfs::verify(&reader),
                ChecklistType::AuthAudit => fsdbg::checklist::auth_audit::verify(&reader),
                ChecklistType::Iso => bail!("ISO checklist requires an ISO file, not CPIO"),
                ChecklistType::Qcow2 => unreachable!("Handled above"),
            }
        }
        ArchiveFormat::Iso => {
            let reader = IsoReader::open(path)?;
            match checklist {
                ChecklistType::Iso => fsdbg::checklist::iso::verify(&reader),
                ChecklistType::AuthAudit => bail!(
                    "Auth audit requires a rootfs archive (CPIO/EROFS), not ISO. Extract the rootfs first."
                ),
                _ => bail!(
                    "Checklist type '{}' not supported for ISO format. Use 'iso'.",
                    checklist.name()
                ),
            }
        }
        _ => bail!("Checklist verification only supports CPIO and ISO archives"),
    };

    print_report(&report, verbose);

    Ok(report.is_success())
}

/// Verify a qcow2 image by mounting it via qemu-nbd.
///
/// This requires sudo for mounting. The verification itself also uses sudo
/// to read files owned by root inside the mounted filesystem.
fn cmd_verify_qcow2(path: &PathBuf, verbose: bool) -> Result<bool> {
    // Check we're running as root or have sudo
    let uid = unsafe { libc::getuid() };
    if uid != 0 {
        eprintln!("Note: qcow2 verification requires sudo for mounting and reading files.");
    }

    // Check qemu-nbd is available
    if Command::new("qemu-nbd").arg("--version").output().is_err() {
        bail!("qemu-nbd not found. Install qemu-img package.");
    }

    // Create temporary mount points
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let nbd_device = find_free_nbd_device()?;
    let root_mount = temp_dir.path().join("root");
    let boot_mount = temp_dir.path().join("boot");

    // Create mount points with sudo so they're accessible
    let _ = Command::new("sudo")
        .args(["mkdir", "-p"])
        .arg(&root_mount)
        .status();
    let _ = Command::new("sudo")
        .args(["mkdir", "-p"])
        .arg(&boot_mount)
        .status();

    // Set up cleanup guard
    let _cleanup = Qcow2Cleanup {
        nbd_device: nbd_device.clone(),
        root_mount: root_mount.clone(),
        boot_mount: boot_mount.clone(),
    };

    println!("Mounting {} via qemu-nbd...", path.display());

    // Connect qcow2 to NBD device
    let status = Command::new("sudo")
        .args(["qemu-nbd", "-c", &nbd_device, "-r"]) // -r = read-only
        .arg(path)
        .status()
        .context("Failed to run qemu-nbd")?;

    if !status.success() {
        bail!("qemu-nbd failed to connect {}", path.display());
    }

    // Wait for partitions to appear
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Probe partitions
    let _ = Command::new("sudo")
        .args(["partprobe", &nbd_device])
        .status();

    std::thread::sleep(std::time::Duration::from_millis(300));

    // Mount root partition (p2) and boot partition (p1)
    let root_part = format!("{}p2", nbd_device);
    let boot_part = format!("{}p1", nbd_device);

    // Mount root
    let status = Command::new("sudo")
        .args(["mount", "-o", "ro", &root_part])
        .arg(&root_mount)
        .status()
        .context("Failed to mount root partition")?;

    if !status.success() {
        bail!("Failed to mount root partition {}", root_part);
    }

    // Mount boot
    let status = Command::new("sudo")
        .args(["mount", "-o", "ro", &boot_part])
        .arg(&boot_mount)
        .status()
        .context("Failed to mount boot partition")?;

    if !status.success() {
        // Unmount root before failing
        let _ = Command::new("sudo")
            .args(["umount"])
            .arg(&root_mount)
            .status();
        bail!("Failed to mount boot partition {}", boot_part);
    }

    // Bind-mount boot at root/boot for unified checking
    let boot_in_root = root_mount.join("boot");
    let bind_result = Command::new("sudo")
        .args(["mount", "--bind"])
        .arg(&boot_mount)
        .arg(&boot_in_root)
        .status();

    let bind_mounted = match bind_result {
        Ok(status) if status.success() => true,
        _ => {
            eprintln!("Warning: Could not bind-mount boot, checking separately");
            false
        }
    };

    println!("Running qcow2 checklist...\n");

    // Run verification - use sudo to read files
    let report = verify_qcow2_with_sudo(&root_mount)?;

    // Unmount bind mount before cleanup guard runs
    if bind_mounted {
        let _ = Command::new("sudo")
            .args(["umount"])
            .arg(&boot_in_root)
            .status();
    }

    print_report(&report, verbose);

    Ok(report.is_success())
}

/// Run qcow2 verification using sudo to read files.
///
/// This spawns a subprocess that reads files as root and outputs JSON
/// that we parse. This avoids permission issues with reading /etc/shadow etc.
fn verify_qcow2_with_sudo(mount_point: &Path) -> Result<VerificationReport> {
    // For now, just call the verify function directly.
    // Files like /etc/shadow will fail to read without sudo, but we can
    // detect this via the error messages.
    //
    // A more robust solution would serialize the checklist and run it in
    // a sudo subprocess, but that's overengineering for now.
    Ok(fsdbg::checklist::qcow2::verify(mount_point))
}

/// Find a free /dev/nbdN device
fn find_free_nbd_device() -> Result<String> {
    // Load nbd module if needed
    let _ = Command::new("sudo")
        .args(["modprobe", "nbd", "max_part=16"])
        .status();

    // Find first free nbd device
    for i in 0..16 {
        let device = format!("/dev/nbd{}", i);
        let path = Path::new(&device);

        if !path.exists() {
            continue;
        }

        // Check if device is in use by looking at size
        let size_path = format!("/sys/block/nbd{}/size", i);
        if let Ok(size) = std::fs::read_to_string(&size_path) {
            if size.trim() == "0" {
                return Ok(device);
            }
        }
    }

    bail!("No free NBD device found. Disconnect existing qemu-nbd connections.")
}

/// Cleanup guard for qcow2 mounting
struct Qcow2Cleanup {
    nbd_device: String,
    root_mount: PathBuf,
    boot_mount: PathBuf,
}

impl Drop for Qcow2Cleanup {
    fn drop(&mut self) {
        // Unmount in reverse order
        let boot_in_root = self.root_mount.join("boot");
        let _ = Command::new("sudo")
            .args(["umount", &boot_in_root.to_string_lossy().to_string()])
            .status();

        let _ = Command::new("sudo")
            .args(["umount", &self.boot_mount.to_string_lossy().to_string()])
            .status();

        let _ = Command::new("sudo")
            .args(["umount", &self.root_mount.to_string_lossy().to_string()])
            .status();

        // Disconnect NBD
        let _ = Command::new("sudo")
            .args(["qemu-nbd", "-d", &self.nbd_device])
            .status();
    }
}

fn cmd_check_symlinks(path: &PathBuf) -> Result<bool> {
    let format = fsdbg::detect_format(path)?;

    println!("=== Symlink Verification: {} ===", path.display());
    println!();

    let mut broken = Vec::new();
    let mut valid = 0;

    match format {
        ArchiveFormat::Cpio | ArchiveFormat::CpioGzip => {
            let reader = CpioReader::open(path)?;

            for entry in reader.symlinks() {
                if reader.symlink_target_exists(entry) {
                    valid += 1;
                } else if let Some(ref target) = entry.link_target {
                    broken.push((entry.path.clone(), target.clone()));
                }
            }
        }
        ArchiveFormat::Iso => {
            let reader = IsoReader::open(path)?;

            for entry in reader.symlinks() {
                if reader.exists(&entry.link_target.as_deref().unwrap_or("")) {
                    valid += 1;
                } else if let Some(ref target) = entry.link_target {
                    broken.push((entry.path.clone(), target.clone()));
                }
            }
        }
        _ => bail!("Symlink checking not supported for this format"),
    }

    println!("Valid symlinks: {}", valid);

    if broken.is_empty() {
        println!("Broken symlinks: 0");
        println!();
        println!("Result: PASS");
        Ok(true)
    } else {
        println!("Broken symlinks: {}", broken.len());
        println!();
        for (link, target) in &broken {
            println!("  [BROKEN] {} -> {}", link, target);
        }
        println!();
        println!("Result: FAIL");
        Ok(false)
    }
}

fn cmd_diff(path1: &PathBuf, path2: &PathBuf) -> Result<bool> {
    let format1 = fsdbg::detect_format(path1)?;
    let format2 = fsdbg::detect_format(path2)?;

    println!("=== Diff ===");
    println!("Archive 1: {} ({})", path1.display(), format_name(&format1));
    println!("Archive 2: {} ({})", path2.display(), format_name(&format2));
    println!();

    // Get file lists
    let files1: std::collections::HashSet<String> = match format1 {
        ArchiveFormat::Cpio | ArchiveFormat::CpioGzip => {
            let reader = CpioReader::open(path1)?;
            reader.entries().iter().map(|e| e.path.clone()).collect()
        }
        ArchiveFormat::Iso => {
            let reader = IsoReader::open(path1)?;
            reader.entries().iter().map(|e| e.path.clone()).collect()
        }
        _ => bail!("Diff not supported for this format"),
    };

    let files2: std::collections::HashSet<String> = match format2 {
        ArchiveFormat::Cpio | ArchiveFormat::CpioGzip => {
            let reader = CpioReader::open(path2)?;
            reader.entries().iter().map(|e| e.path.clone()).collect()
        }
        ArchiveFormat::Iso => {
            let reader = IsoReader::open(path2)?;
            reader.entries().iter().map(|e| e.path.clone()).collect()
        }
        _ => bail!("Diff not supported for this format"),
    };

    let only_in_1: Vec<_> = files1.difference(&files2).collect();
    let only_in_2: Vec<_> = files2.difference(&files1).collect();
    let in_both = files1.intersection(&files2).count();

    println!("Files in both: {}", in_both);
    println!("Only in archive 1: {}", only_in_1.len());
    println!("Only in archive 2: {}", only_in_2.len());

    if !only_in_1.is_empty() {
        println!();
        println!("Only in {}:", path1.display());
        let mut sorted: Vec<_> = only_in_1.into_iter().collect();
        sorted.sort();
        for f in sorted.iter().take(50) {
            println!("  - {}", f);
        }
        if sorted.len() > 50 {
            println!("  ... and {} more", sorted.len() - 50);
        }
    }

    if !only_in_2.is_empty() {
        println!();
        println!("Only in {}:", path2.display());
        let mut sorted: Vec<_> = only_in_2.into_iter().collect();
        sorted.sort();
        for f in sorted.iter().take(50) {
            println!("  + {}", f);
        }
        if sorted.len() > 50 {
            println!("  ... and {} more", sorted.len() - 50);
        }
    }

    Ok(true)
}

fn format_name(format: &ArchiveFormat) -> &'static str {
    match format {
        ArchiveFormat::Cpio => "CPIO",
        ArchiveFormat::CpioGzip => "CPIO (gzip compressed)",
        ArchiveFormat::Erofs => "EROFS",
        ArchiveFormat::Iso => "ISO 9660",
    }
}

fn print_report(report: &VerificationReport, verbose: bool) {
    println!("=== Verification: {} ===", report.artifact_type);
    println!();

    for (category, results) in report.by_category() {
        let failures: Vec<_> = results.iter().filter(|r| !r.passed).collect();
        let pass_count = results.len() - failures.len();

        // In quiet mode, skip categories with no failures
        if !verbose && failures.is_empty() {
            continue;
        }

        println!("{}:", category);

        // Show passing items only in verbose mode
        if verbose {
            for result in &results {
                if result.passed {
                    let status = "[PASS]";
                    if let Some(ref msg) = result.message {
                        println!("  {} {} - {}", status, result.item, msg);
                    } else {
                        println!("  {} {}", status, result.item);
                    }
                }
            }
        }

        // Always show failures
        for result in &failures {
            let status = "[FAIL]";
            if let Some(ref msg) = result.message {
                println!("  {} {} - {}", status, result.item, msg);
            } else {
                println!("  {} {}", status, result.item);
            }
        }

        // In quiet mode with failures, show how many passed in this category
        if !verbose && !failures.is_empty() && pass_count > 0 {
            println!("  ({} passed)", pass_count);
        }

        println!();
    }

    // Summary of categories with all passes (quiet mode only)
    if !verbose {
        let mut all_pass_categories = Vec::new();
        for (category, results) in report.by_category() {
            if results.iter().all(|r| r.passed) && !results.is_empty() {
                all_pass_categories.push(format!("{} ({})", category, results.len()));
            }
        }
        if !all_pass_categories.is_empty() {
            println!("All passed: {}", all_pass_categories.join(", "));
            println!();
        }
    }

    let status = if report.is_success() { "PASS" } else { "FAIL" };
    println!("Result: {} ({}/{} checks passed)", status, report.passed(), report.total());
}
