# CLAUDE.md - fsdbg

## What is fsdbg?

Filesystem debugging tool for inspecting and verifying archives (CPIO, EROFS, ISO) without extraction or mounting.

Designed for debugging initramfs and rootfs images - quickly check contents, verify required components, find broken symlinks.

## What Belongs Here

- Archive reading (CPIO, EROFS, ISO)
- Content verification checklists
- Symlink validation
- Archive comparison

## What Does NOT Belong Here

| Don't put here | Put it in |
|----------------|-----------|
| Initramfs building | `recinit/` |
| ISO building | `reciso/` |
| LevitateOS-specific paths | `distro-spec/` |
| Archive extraction | Use `bsdtar` or `cpio` |

## Commands

```bash
cargo build --release
cargo test
```

## Usage

```bash
# Inspect archive
fsdbg inspect initramfs.img

# Verify contents
fsdbg verify initramfs.img --type install-initramfs

# Check symlinks
fsdbg check-symlinks initramfs.img

# Compare archives
fsdbg diff old.img new.img
```

## Library Usage

```rust
use fsdbg::cpio::CpioReader;
use fsdbg::checklist::install_initramfs;

let reader = CpioReader::open("initramfs.img")?;
let report = install_initramfs::verify(&reader);

if report.has_critical_failures() {
    bail!("Initramfs missing critical components");
}
```

## Architecture

```
src/
├── main.rs           # CLI entry point
├── lib.rs            # Library exports, format detection
├── error.rs          # Error types (E001-E010)
├── cpio.rs           # CPIO reader (native Rust)
├── erofs.rs          # EROFS inspection (via dump.erofs)
├── iso.rs            # ISO inspection (via isoinfo)
└── checklist/
    ├── mod.rs                  # Checklist trait
    ├── install_initramfs.rs    # systemd initramfs requirements
    ├── live_initramfs.rs       # busybox initramfs requirements
    └── rootfs.rs               # Full rootfs requirements
```

## Adding New Checklists

1. Create `src/checklist/your_checklist.rs`
2. Define `REQUIRED_*` constants
3. Implement `verify(reader: &CpioReader) -> VerificationReport`
4. Add to `ChecklistType` enum in `mod.rs`
5. Add to CLI in `main.rs`
