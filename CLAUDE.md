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
    ├── auth_audit.rs           # **Authentication subsystem verification**
    ├── iso.rs                  # ISO structure verification
    └── rootfs.rs               # Full rootfs requirements
```

### Authentication Audit Checklist (auth_audit.rs)

Comprehensive verification of authentication and authorization components:

**Critical Checks** (failures = system cannot boot):
- `/usr/sbin/unix_chkpwd` - pam_unix.so hardcoded dependency
- `/usr/sbin/passwd`, `/usr/sbin/chpasswd` - password management
- `/usr/bin/sudo`, `/usr/bin/su` - privilege escalation
- PAM modules (18 total) - authentication stack
- PAM configs (18 total) - login services (sshd, login, sudo, etc.)
- Security files (5 total) - policy enforcement

**Optional Hardening** (informational warnings):
- `/etc/securetty` - restrict root to secure terminals
- Per-user `/tmp` isolation
- Hardening modules (faillock, pwquality, securetty)

**Why separate checklist**:
- Authentication is critical for boot and first login
- Single source of truth: imports from `distro_spec::shared::auth`
- 19 tests verify all components from distro-spec match actual needs
- Prevents regressions in auth subsystem

## Adding New Checklists

1. Create `src/checklist/your_checklist.rs`
2. Define `REQUIRED_*` constants
3. Implement `verify(reader: &CpioReader) -> VerificationReport`
4. Add to `ChecklistType` enum in `mod.rs`
5. Add to CLI in `main.rs`
