//! fsdbg - Filesystem debugging tool for LevitateOS
//!
//! Inspect and verify initramfs, rootfs, and ISO images without extraction.

use std::path::PathBuf;
use std::process::ExitCode;

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
        /// Show only failures
        #[arg(long)]
        failures_only: bool,
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
            failures_only,
        } => cmd_verify(&archive, &r#type, failures_only),
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

fn cmd_verify(path: &PathBuf, checklist_type: &str, failures_only: bool) -> Result<bool> {
    let checklist = ChecklistType::from_str(checklist_type)
        .ok_or_else(|| anyhow::anyhow!(
            "Unknown checklist type: {}. Valid types: install-initramfs, live-initramfs, rootfs, iso",
            checklist_type
        ))?;

    let format = fsdbg::detect_format(path)?;

    let report = match format {
        ArchiveFormat::Cpio | ArchiveFormat::CpioGzip => {
            let reader = CpioReader::open(path)?;
            match checklist {
                ChecklistType::InstallInitramfs => fsdbg::checklist::install_initramfs::verify(&reader),
                ChecklistType::LiveInitramfs => fsdbg::checklist::live_initramfs::verify(&reader),
                ChecklistType::Rootfs => fsdbg::checklist::rootfs::verify(&reader),
                ChecklistType::Iso => bail!("ISO checklist requires an ISO file, not CPIO"),
            }
        }
        ArchiveFormat::Iso => {
            let reader = IsoReader::open(path)?;
            match checklist {
                ChecklistType::Iso => fsdbg::checklist::iso::verify(&reader),
                _ => bail!(
                    "Checklist type '{}' not supported for ISO format. Use 'iso'.",
                    checklist.name()
                ),
            }
        }
        _ => bail!("Checklist verification only supports CPIO and ISO archives"),
    };

    print_report(&report, failures_only);

    Ok(report.is_success())
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

fn print_report(report: &VerificationReport, failures_only: bool) {
    println!("=== Verification: {} ===", report.artifact_type);
    println!();

    for (category, results) in report.by_category() {
        let has_content = if failures_only {
            results.iter().any(|r| !r.passed)
        } else {
            !results.is_empty()
        };

        if !has_content {
            continue;
        }

        println!("{}:", category);
        for result in results {
            if failures_only && result.passed {
                continue;
            }

            let status = if result.passed { "[PASS]" } else { "[FAIL]" };

            if let Some(ref msg) = result.message {
                println!("  {} {} - {}", status, result.item, msg);
            } else {
                println!("  {} {}", status, result.item);
            }
        }
        println!();
    }

    let status = if report.is_success() { "PASS" } else { "FAIL" };
    println!("Result: {} ({}/{} checks passed)", status, report.passed(), report.total());
}
