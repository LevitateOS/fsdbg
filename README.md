# fsdbg

Debug and verify filesystem archives (CPIO, EROFS, ISO) without extraction or mounting.

Inspect initramfs contents, verify required components, check symlinks, and compare archives - all without needing root privileges or temporary directories.

## Status

**Beta.** Works for CPIO (gzip), EROFS, and ISO 9660 archives.

## Usage

```bash
# Inspect an archive
fsdbg inspect initramfs.img

# Verify against a checklist
fsdbg verify initramfs.img --type install-initramfs

# Check all symlinks resolve
fsdbg check-symlinks initramfs.img

# Compare two archives
fsdbg diff old-initramfs.img new-initramfs.img
```

## Commands

### inspect

List archive contents and show structure.

```bash
fsdbg inspect initramfs.img
fsdbg inspect initramfs.img --verbose           # Show all entries
fsdbg inspect initramfs.img --filter "*.so*"    # Filter by pattern
```

### verify

Verify archive contains required components.

```bash
fsdbg verify initramfs.img --type install-initramfs
fsdbg verify initramfs.img --type live-initramfs
fsdbg verify initramfs.img --type rootfs
fsdbg verify initramfs.img --type install-initramfs --verbose  # Show all checks
```

### check-symlinks

Verify all symlinks in the archive resolve to existing targets.

```bash
fsdbg check-symlinks initramfs.img
fsdbg check-symlinks initramfs.img --verbose    # Show valid symlinks too
```

### diff

Compare two archives and show differences.

```bash
fsdbg diff old.img new.img
fsdbg diff old.img new.img --only-diff    # Hide common files
```

## Library Usage

```rust
use fsdbg::cpio::CpioReader;
use fsdbg::checklist::{ChecklistType, install_initramfs};

// Read a CPIO archive
let reader = CpioReader::open("initramfs.img")?;

// Check if a file exists
if reader.exists("usr/lib/systemd/systemd") {
    println!("systemd found!");
}

// Verify against checklist
let report = install_initramfs::verify(&reader);
if report.has_critical_failures() {
    eprintln!("Missing critical components!");
}

// Iterate entries
for entry in reader.entries() {
    println!("{} {}", entry.mode_string(), entry.path);
}
```

## Supported Formats

| Format | Detection | Method |
|--------|-----------|--------|
| CPIO (gzip) | Magic `1f 8b` | Native Rust |
| CPIO (uncompressed) | Magic `070701` | Native Rust |
| EROFS | Magic at offset 1024 | `dump.erofs` / `fsck.erofs` |
| ISO 9660 | Magic `CD001` at 0x8001 | `isoinfo` |

## What It Does

- Reads CPIO archives directly (no extraction needed)
- Lists contents with ls-style output
- Verifies symlinks resolve within the archive
- Checks for required binaries, units, configs
- Compares archives to find differences

## What It Does NOT Do

- Extract files (use `cpio` or `bsdtar`)
- Modify archives
- Mount filesystems
- Require root privileges

## Checklists

Built-in verification checklists:

- **install-initramfs**: systemd-based initramfs for installed systems
- **live-initramfs**: busybox-based initramfs for live boot
- **rootfs**: Full system rootfs

## Requirements

For CPIO archives: No external tools required.

For EROFS: `erofs-utils` (`dump.erofs` or `fsck.erofs`)
```bash
sudo dnf install erofs-utils
```

For ISO: `cdrtools` or `genisoimage` (`isoinfo`)
```bash
sudo dnf install cdrtools
```

## Building

```bash
cargo build --release
```

## License

MIT OR Apache-2.0
