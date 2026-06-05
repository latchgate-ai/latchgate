//! Host-mediated filesystem I/O for the `builtin:fs` provider.
//!
//! Every filesystem operation from a WASM provider module traverses this
//! module's validation pipeline before any syscall touches the filesystem.
//!
//! SECURITY: this module contains the only `unsafe` code in the providers
//! crate. All unsafe is confined to thin wrappers around POSIX syscalls,
//! each with a SAFETY comment explaining the invariant.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use latchgate_core::crypto::sha256_raw;
use latchgate_core::fs_path::{evaluate_path_detailed, DetailedPathDecision, GlobPattern};
use latchgate_core::FsOperation;

/// `O_PATH` is Linux-only. On macOS we fall back to `O_RDONLY` which opens
/// a real fd instead of a path-only handle — functionally equivalent for
/// our use (directory traversal and fstat), just slightly less restrictive.
#[cfg(target_os = "linux")]
const O_PATH: libc::c_int = libc::O_PATH;
#[cfg(not(target_os = "linux"))]
const O_PATH: libc::c_int = libc::O_RDONLY;

// Types

/// Configuration for a single fs action execution. Constructed by the kernel
/// from the manifest's `FsConfig` and the operator-configured root.
///
/// Held in `Arc` so it can be moved into `spawn_blocking` closures cheaply.
pub struct FsHostConfig {
    /// Open directory fd for the configured root. All operations are
    /// performed relative to this fd — the provider never supplies an
    /// absolute root.
    pub root_fd: Arc<OwnedFd>,

    /// Canonical path of the root directory, resolved at open time.
    pub root_canonical: PathBuf,

    /// Operations this action's grant permits (read, create, overwrite, delete).
    /// Checked before any syscall — a WASM module that calls a host import
    /// not listed here receives `FsError::OperationNotAllowed`.
    pub allowed_operations: Vec<FsOperation>,

    /// Compiled allowed path patterns from the manifest (plus learned paths).
    pub allowed_paths: Vec<GlobPattern>,

    /// Compiled denied path patterns from the manifest (immutable).
    pub denied_paths: Vec<GlobPattern>,

    /// Maximum file size in bytes (applied to decoded content).
    pub max_file_bytes: u64,
}

impl FsHostConfig {
    /// Verify that `op` is listed in the grant's `allowed_operations`.
    ///
    /// SECURITY: called before any path validation or syscall. This is the
    /// operation-level gate — without it, a WASM module loaded for `fs_read`
    /// could invoke the `write()` or `delete()` host imports.
    fn require_operation(&self, op: FsOperation) -> Result<(), FsHostError> {
        if self.allowed_operations.contains(&op) {
            Ok(())
        } else {
            tracing::warn!(
                requested = %op,
                allowed = ?self.allowed_operations,
                "fs operation blocked: not in allowed_operations"
            );
            Err(FsHostError::OperationNotAllowed(op))
        }
    }
}

/// Write mode, mirroring the WIT `fs-write-mode` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsWriteMode {
    Create,
    Overwrite,
}

/// Result of a successful read operation.
#[derive(Debug)]
pub struct FsReadResult {
    pub content: Vec<u8>,
    pub hash: [u8; 32],
    pub size: u64,
}

/// Result of a successful write operation.
#[derive(Debug)]
pub struct FsWriteResult {
    pub before_hash: Option<[u8; 32]>,
    pub after_hash: [u8; 32],
    pub bytes_before: u64,
    pub bytes_written: u64,
}

/// Result of a successful delete operation.
#[derive(Debug)]
pub struct FsDeleteResult {
    pub before_hash: Option<[u8; 32]>,
    pub bytes_before: u64,
}

/// Typed errors from the host fs pipeline. Each variant maps to a WIT
/// `fs-error` discriminant. No panics — every failure path is typed.
#[derive(Debug, thiserror::Error)]
pub enum FsHostError {
    #[error("operation `{0}` not in allowed_operations")]
    OperationNotAllowed(FsOperation),
    #[error("path not covered by allowed_paths")]
    PathNotAllowed,
    #[error("path matched denied_paths: {path} (pattern: {pattern})")]
    PathDenied { path: String, pattern: String },
    #[error("file not found: {0}")]
    PathNotFound(String),
    #[error("invalid path: {0}")]
    PathInvalid(String),
    #[error("file already exists")]
    AlreadyExists,
    #[error("content exceeds max_file_bytes ({limit} bytes)")]
    TooLarge { limit: u64 },
    #[error("symlink escape detected: {0}")]
    SymlinkEscape(String),
    #[error("path traversal: `..` segment")]
    Traversal,
    #[error("special file rejected (not a regular file): {0}")]
    SpecialFile(String),
    #[error("expected_before_hash mismatch (conflict)")]
    Conflict,
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),
    #[error("fs config not available")]
    NotConfigured,
}

// Root fd — opened once at config/manifest load time

/// Open a directory as a root fd for subsequent fs operations.
///
/// Canonicalizes the path, verifies it is a directory, and opens it with
/// `O_PATH | O_DIRECTORY | O_CLOEXEC`. Rejects non-existent paths and
/// non-directories.
pub fn open_root_fd(path: &Path) -> Result<(OwnedFd, PathBuf), FsHostError> {
    let canonical = path
        .canonicalize()
        .map_err(|e| FsHostError::PathNotFound(format!("{}: {e}", path.display())))?;

    let c_path = path_to_cstring(&canonical)?;

    // SAFETY: opening a directory with O_PATH|O_DIRECTORY|O_CLOEXEC (Linux)
    // or O_RDONLY|O_DIRECTORY|O_CLOEXEC (macOS) is a standard POSIX
    // operation. The CString is valid for the duration of the call.
    // On success we get a valid fd that OwnedFd will close.
    let raw_fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw_fd == -1 {
        return Err(FsHostError::IoError(io::Error::last_os_error()));
    }

    // SAFETY: raw_fd is a valid open fd returned by libc::open above.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    Ok((fd, canonical))
}

// Step 1-2: Path string validation

/// Reject paths that are structurally invalid before any filesystem access.
fn validate_path_string(path: &str) -> Result<(), FsHostError> {
    if path.is_empty() {
        return Err(FsHostError::PathInvalid("empty path".into()));
    }

    // Reject absolute paths.
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(FsHostError::PathInvalid("absolute path".into()));
    }

    // Reject Windows-style drive prefixes (C:, \\?\, etc.).
    if path.len() >= 2 && path.as_bytes()[1] == b':' && path.as_bytes()[0].is_ascii_alphabetic() {
        return Err(FsHostError::PathInvalid("drive prefix".into()));
    }
    if path.starts_with(r"\\") {
        return Err(FsHostError::PathInvalid("UNC prefix".into()));
    }

    // Reject null bytes and control characters.
    for (i, byte) in path.bytes().enumerate() {
        if byte == 0 {
            return Err(FsHostError::PathInvalid(format!("null byte at offset {i}")));
        }
        if byte <= 0x1F || byte == 0x7F {
            return Err(FsHostError::PathInvalid(format!(
                "control character 0x{byte:02x} at offset {i}"
            )));
        }
    }

    // Reject `..` segments (step 2).
    for component in path.split('/') {
        if component == ".." {
            return Err(FsHostError::Traversal);
        }
    }

    Ok(())
}

// Step 3 & 7: Deny/allow evaluation

fn check_deny_allow(
    path: &Path,
    allowed: &[GlobPattern],
    denied: &[GlobPattern],
) -> Result<(), FsHostError> {
    match evaluate_path_detailed(path, allowed, denied) {
        DetailedPathDecision::Allowed { .. } => Ok(()),
        DetailedPathDecision::Denied { pattern } => Err(FsHostError::PathDenied {
            path: path.display().to_string(),
            pattern,
        }),
        DetailedPathDecision::NotMatched => Err(FsHostError::PathNotAllowed),
    }
}

// Steps 4-6: Secure root-relative open

/// Open a path securely beneath `root_fd`.
///
/// Prefers `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
/// RESOLVE_NO_MAGICLINKS` on Linux 5.6+. Falls back to component-by-
/// component `openat` with `O_NOFOLLOW` on older kernels and macOS.
///
/// After opening, verifies the fd's canonical path (via `/proc/self/fd/`)
/// is under the root. Returns the opened fd and the canonical relative path.
fn secure_open(
    root_fd: BorrowedFd<'_>,
    root_canonical: &Path,
    relative: &str,
    flags: i32,
    mode: u32,
) -> Result<(OwnedFd, PathBuf), FsHostError> {
    let fd = open_beneath(root_fd, relative, flags, mode)?;

    // Step 6: post-open verification.
    let fd_canonical = canonical_from_fd(fd.as_fd())?;
    let canonical_relative = verify_under_root(&fd_canonical, root_canonical)?;

    Ok((fd, canonical_relative))
}

/// Open the *parent directory* of `relative` securely, returning the parent
/// fd and the basename. Used for create and delete which operate on a
/// parent + child.
fn secure_open_parent(
    root_fd: BorrowedFd<'_>,
    root_canonical: &Path,
    relative: &str,
) -> Result<(OwnedFd, String, PathBuf), FsHostError> {
    let rel_path = Path::new(relative);
    let parent = rel_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_string_lossy().into_owned());
    let basename = rel_path
        .file_name()
        .ok_or_else(|| FsHostError::PathInvalid("no filename component".into()))?
        .to_string_lossy()
        .into_owned();

    let parent_fd = if let Some(ref parent_str) = parent {
        let (fd, _) = secure_open(
            root_fd,
            root_canonical,
            parent_str,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        fd
    } else {
        // Parent is the root itself.
        // SAFETY: dup-ing a valid borrowed fd.
        let raw = unsafe { libc::dup(root_fd.as_raw_fd()) };
        if raw == -1 {
            return Err(FsHostError::IoError(io::Error::last_os_error()));
        }
        // SAFETY: raw is a valid fd returned by dup.
        unsafe { OwnedFd::from_raw_fd(raw) }
    };

    // Verify parent is a directory.
    let pstat = fstat_fd(parent_fd.as_fd())?;
    if (pstat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(FsHostError::PathInvalid("parent is not a directory".into()));
    }

    // Derive canonical relative from the parent's canonical + basename.
    let parent_canonical = canonical_from_fd(parent_fd.as_fd())?;
    let _ = verify_under_root(&parent_canonical, root_canonical)?;
    let canonical_relative = parent_canonical
        .strip_prefix(root_canonical)
        .unwrap_or(&parent_canonical)
        .join(&basename);

    Ok((parent_fd, basename, canonical_relative))
}

// openat2 / component-walk dispatch

#[cfg(target_os = "linux")]
mod openat2_linux {
    use super::*;
    use std::os::unix::io::RawFd;
    use std::sync::atomic::{AtomicU8, Ordering};

    /// 0 = untested, 1 = available, 2 = unavailable.
    static OPENAT2_AVAILABLE: AtomicU8 = AtomicU8::new(0);

    const RESOLVE_BENEATH: u64 = 0x08;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    pub(super) fn try_openat2(
        dirfd: RawFd,
        path: &CString,
        flags: i32,
        mode: u32,
    ) -> Result<Option<OwnedFd>, io::Error> {
        let status = OPENAT2_AVAILABLE.load(Ordering::Relaxed);
        if status == 2 {
            return Ok(None); // known unavailable
        }

        let how = OpenHow {
            flags: flags as u64,
            mode: mode as u64,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };

        // SAFETY: SYS_openat2 is a Linux syscall. dirfd is a valid fd,
        // path is a valid C string, how is a valid stack-allocated struct.
        // On success, returns a new fd. On error, returns -1.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                path.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };

        if ret >= 0 {
            OPENAT2_AVAILABLE.store(1, Ordering::Relaxed);
            // SAFETY: ret is a valid fd returned by the kernel.
            Ok(Some(unsafe { OwnedFd::from_raw_fd(ret as RawFd) }))
        } else {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOSYS) {
                OPENAT2_AVAILABLE.store(2, Ordering::Relaxed);
                Ok(None) // fall back to component walk
            } else {
                Err(err)
            }
        }
    }
}

/// Open a file beneath `root_fd` using the best available mechanism.
fn open_beneath(
    root_fd: BorrowedFd<'_>,
    relative: &str,
    flags: i32,
    mode: u32,
) -> Result<OwnedFd, FsHostError> {
    let full_flags = flags | libc::O_CLOEXEC | libc::O_NOFOLLOW;

    // Try openat2 on Linux (preferred — single atomic check).
    #[cfg(target_os = "linux")]
    {
        let c_path =
            CString::new(relative).map_err(|_| FsHostError::PathInvalid("null in path".into()))?;
        match openat2_linux::try_openat2(root_fd.as_raw_fd(), &c_path, full_flags, mode) {
            Ok(Some(fd)) => return Ok(fd),
            Ok(None) => { /* ENOSYS — fall through to component walk */ }
            Err(e) => return Err(map_open_error(e, relative)),
        }
    }

    // Fallback: component-by-component walk with O_NOFOLLOW.
    component_walk_open(root_fd, relative, full_flags, mode)
}

/// Walk each path component with `openat` + `O_NOFOLLOW`, verifying each
/// intermediate is a directory. The final component is opened with the
/// caller's flags.
fn component_walk_open(
    root_fd: BorrowedFd<'_>,
    relative: &str,
    final_flags: i32,
    final_mode: u32,
) -> Result<OwnedFd, FsHostError> {
    let components: Vec<&str> = relative.split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return Err(FsHostError::PathInvalid("empty path after split".into()));
    }

    // SAFETY: dup is a standard POSIX call on a valid borrowed fd.
    let raw = unsafe { libc::dup(root_fd.as_raw_fd()) };
    if raw == -1 {
        return Err(FsHostError::IoError(io::Error::last_os_error()));
    }
    // SAFETY: raw is a valid fd returned by dup.
    let mut current_fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // Walk intermediate directories.
    for &component in &components[..components.len() - 1] {
        let c_name = CString::new(component)
            .map_err(|_| FsHostError::PathInvalid("null in component".into()))?;

        // SAFETY: openat on a valid dirfd with a valid C string.
        let fd = unsafe {
            libc::openat(
                current_fd.as_raw_fd(),
                c_name.as_ptr(),
                O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd == -1 {
            let e = io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(libc::ELOOP) {
                FsHostError::SymlinkEscape(component.into())
            } else {
                map_open_error(e, component)
            });
        }
        // SAFETY: fd is a valid new fd from openat.
        current_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // Verify it is actually a directory (not a symlink to one, since
        // O_NOFOLLOW would have failed on symlinks, but defense-in-depth).
        let stat = fstat_fd(current_fd.as_fd())?;
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            return Err(FsHostError::SpecialFile(format!(
                "intermediate `{component}` is not a directory"
            )));
        }
    }

    // Open final component with caller's flags.
    let final_component = components
        .last()
        .ok_or_else(|| FsHostError::PathInvalid("empty path components".into()))?;
    let final_name = CString::new(*final_component)
        .map_err(|_| FsHostError::PathInvalid("null in final component".into()))?;

    // SAFETY: openat on a valid dirfd with a valid C string and caller-
    // supplied flags. O_CLOEXEC and O_NOFOLLOW are already in final_flags.
    let fd = unsafe {
        libc::openat(
            current_fd.as_raw_fd(),
            final_name.as_ptr(),
            final_flags,
            final_mode,
        )
    };
    if fd == -1 {
        let e = io::Error::last_os_error();
        return Err(map_open_error(e, final_component));
    }

    // SAFETY: fd is a valid new fd from openat.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// Step 6: Post-open fd verification

/// Read the kernel's canonical path for an open fd.
#[cfg(target_os = "linux")]
fn canonical_from_fd(fd: BorrowedFd<'_>) -> Result<PathBuf, FsHostError> {
    let link = format!("/proc/self/fd/{}", fd.as_raw_fd());
    std::fs::read_link(&link).map_err(|e| {
        FsHostError::IoError(io::Error::new(e.kind(), format!("readlink {link}: {e}")))
    })
}

#[cfg(target_os = "macos")]
fn canonical_from_fd(fd: BorrowedFd<'_>) -> Result<PathBuf, FsHostError> {
    use std::ffi::OsStr;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH is a macOS fcntl that writes the path into buf.
    let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if ret == -1 {
        return Err(FsHostError::IoError(io::Error::last_os_error()));
    }
    let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(PathBuf::from(OsStr::from_bytes(&buf[..nul_pos])))
}

/// Verify that the fd's canonical path is under the root, and return the
/// relative portion.
fn verify_under_root(fd_canonical: &Path, root_canonical: &Path) -> Result<PathBuf, FsHostError> {
    fd_canonical
        .strip_prefix(root_canonical)
        .map(|rel| rel.to_path_buf())
        .map_err(|_| {
            FsHostError::SymlinkEscape(format!(
                "fd path {} escapes root {}",
                fd_canonical.display(),
                root_canonical.display()
            ))
        })
}

// Full pipeline: validate => precheck => open => postcheck => I/O

/// Validate and precheck a path, returning early on any failure.
fn validate_and_precheck(
    path: &str,
    allowed: &[GlobPattern],
    denied: &[GlobPattern],
) -> Result<(), FsHostError> {
    validate_path_string(path)?;
    check_deny_allow(Path::new(path), allowed, denied)
}

/// Full read operation (sync, called inside `spawn_blocking`).
fn read_sync(config: &FsHostConfig, path: &str) -> Result<FsReadResult, FsHostError> {
    // Step 0: operation-level gate.
    config.require_operation(FsOperation::Read)?;

    // Steps 1-3: validate + precheck.
    validate_and_precheck(path, &config.allowed_paths, &config.denied_paths)?;

    // Steps 4-6: secure open.
    let (fd, canonical_rel) = secure_open(
        config.root_fd.as_fd(),
        &config.root_canonical,
        path,
        libc::O_RDONLY,
        0,
    )?;

    // Reject non-regular files.
    let stat = fstat_fd(fd.as_fd())?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(FsHostError::SpecialFile(path.into()));
    }

    // Size check.
    let size = stat.st_size as u64;
    if size > config.max_file_bytes {
        return Err(FsHostError::TooLarge {
            limit: config.max_file_bytes,
        });
    }

    // Step 7: canonical postcheck.
    check_deny_allow(&canonical_rel, &config.allowed_paths, &config.denied_paths)?;

    // Step 8: read content from the validated fd.
    let content = read_fd_full(fd.as_fd(), size as usize)?;
    let hash = sha256(&content);

    Ok(FsReadResult {
        size: content.len() as u64,
        content,
        hash,
    })
}

/// Full write operation (sync).
fn write_sync(
    config: &FsHostConfig,
    path: &str,
    content: &[u8],
    mode: FsWriteMode,
    expected_before_hash: Option<&[u8]>,
) -> Result<FsWriteResult, FsHostError> {
    // Step 0: operation-level gate.
    let required_op = match mode {
        FsWriteMode::Create => FsOperation::Create,
        FsWriteMode::Overwrite => FsOperation::Overwrite,
    };
    config.require_operation(required_op)?;

    // Size check on decoded content.
    if content.len() as u64 > config.max_file_bytes {
        return Err(FsHostError::TooLarge {
            limit: config.max_file_bytes,
        });
    }

    // Steps 1-3: validate + precheck.
    validate_and_precheck(path, &config.allowed_paths, &config.denied_paths)?;

    let after_hash = sha256(content);

    match mode {
        FsWriteMode::Create => write_create_sync(config, path, content, after_hash),
        FsWriteMode::Overwrite => {
            write_overwrite_sync(config, path, content, after_hash, expected_before_hash)
        }
    }
}

fn write_create_sync(
    config: &FsHostConfig,
    path: &str,
    content: &[u8],
    after_hash: [u8; 32],
) -> Result<FsWriteResult, FsHostError> {
    // Open parent securely, then create child with O_CREAT | O_EXCL.
    let (parent_fd, basename, canonical_rel) =
        secure_open_parent(config.root_fd.as_fd(), &config.root_canonical, path)?;

    // Step 7: canonical postcheck on the target path.
    check_deny_allow(&canonical_rel, &config.allowed_paths, &config.denied_paths)?;

    let c_name = CString::new(basename.as_str())
        .map_err(|_| FsHostError::PathInvalid("null in basename".into()))?;

    // SAFETY: openat with O_CREAT|O_EXCL|O_WRONLY on a valid parent dirfd.
    // Mode 0o666 is masked by the process umask.
    let raw_fd = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o666u32,
        )
    };
    if raw_fd == -1 {
        let e = io::Error::last_os_error();
        return Err(if e.raw_os_error() == Some(libc::EEXIST) {
            FsHostError::AlreadyExists
        } else {
            FsHostError::IoError(e)
        });
    }
    // SAFETY: raw_fd is valid from the openat above.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    write_all_fd(fd.as_fd(), content)?;
    fsync_fd(fd.as_fd())?;

    Ok(FsWriteResult {
        before_hash: None,
        after_hash,
        bytes_before: 0,
        bytes_written: content.len() as u64,
    })
}

fn write_overwrite_sync(
    config: &FsHostConfig,
    path: &str,
    content: &[u8],
    after_hash: [u8; 32],
    expected_before_hash: Option<&[u8]>,
) -> Result<FsWriteResult, FsHostError> {
    // Steps 4-6: secure open for reading + writing.
    let (fd, canonical_rel) = secure_open(
        config.root_fd.as_fd(),
        &config.root_canonical,
        path,
        libc::O_RDWR,
        0,
    )?;

    // Reject non-regular files.
    let stat = fstat_fd(fd.as_fd())?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(FsHostError::SpecialFile(path.into()));
    }

    let bytes_before = stat.st_size as u64;

    // Size check on existing file (for reading before_hash).
    if bytes_before > config.max_file_bytes {
        return Err(FsHostError::TooLarge {
            limit: config.max_file_bytes,
        });
    }

    // Step 7: canonical postcheck.
    check_deny_allow(&canonical_rel, &config.allowed_paths, &config.denied_paths)?;

    // Read existing content for before_hash.
    let existing = read_fd_full(fd.as_fd(), bytes_before as usize)?;
    let before_hash = sha256(&existing);

    // Optimistic concurrency check.
    if let Some(expected) = expected_before_hash {
        if expected.len() != 32 || expected != before_hash.as_slice() {
            return Err(FsHostError::Conflict);
        }
    }

    // Truncate and write new content on the same fd.
    // SAFETY: ftruncate on a valid writable fd.
    if unsafe { libc::ftruncate(fd.as_raw_fd(), 0) } == -1 {
        return Err(FsHostError::IoError(io::Error::last_os_error()));
    }
    // SAFETY: lseek on a valid fd.
    if unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } == -1 {
        return Err(FsHostError::IoError(io::Error::last_os_error()));
    }

    write_all_fd(fd.as_fd(), content)?;
    fsync_fd(fd.as_fd())?;

    Ok(FsWriteResult {
        before_hash: Some(before_hash),
        after_hash,
        bytes_before,
        bytes_written: content.len() as u64,
    })
}

/// Full delete operation (sync).
fn delete_sync(config: &FsHostConfig, path: &str) -> Result<FsDeleteResult, FsHostError> {
    // Step 0: operation-level gate.
    config.require_operation(FsOperation::Delete)?;

    // Steps 1-3: validate + precheck.
    validate_and_precheck(path, &config.allowed_paths, &config.denied_paths)?;

    // Open parent securely and resolve the target.
    let (parent_fd, basename, canonical_rel) =
        secure_open_parent(config.root_fd.as_fd(), &config.root_canonical, path)?;

    // Step 7: canonical postcheck.
    check_deny_allow(&canonical_rel, &config.allowed_paths, &config.denied_paths)?;

    // Verify target exists and is a regular file. Open with O_PATH first
    // to check type without triggering content reads.
    let c_name = CString::new(basename.as_str())
        .map_err(|_| FsHostError::PathInvalid("null in basename".into()))?;

    // SAFETY: openat with O_PATH | O_NOFOLLOW on a valid parent dirfd.
    let target_raw = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            c_name.as_ptr(),
            O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if target_raw == -1 {
        let e = io::Error::last_os_error();
        return Err(if e.raw_os_error() == Some(libc::ENOENT) {
            FsHostError::PathNotFound(path.into())
        } else {
            FsHostError::IoError(e)
        });
    }
    // SAFETY: target_raw is valid from openat above.
    let target_fd = unsafe { OwnedFd::from_raw_fd(target_raw) };
    let stat = fstat_fd(target_fd.as_fd())?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(FsHostError::SpecialFile(path.into()));
    }
    let bytes_before = stat.st_size as u64;

    // Best-effort before_hash: open for reading to hash content.
    let before_hash = if bytes_before <= config.max_file_bytes {
        // Re-open for reading (O_PATH fds cannot be read).
        let read_raw = unsafe {
            libc::openat(
                parent_fd.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if read_raw != -1 {
            // SAFETY: read_raw is valid.
            let read_fd = unsafe { OwnedFd::from_raw_fd(read_raw) };
            read_fd_full(read_fd.as_fd(), bytes_before as usize)
                .ok()
                .map(|data| sha256(&data))
        } else {
            None
        }
    } else {
        None
    };

    // Unlink via the verified parent fd.
    // SAFETY: unlinkat on a valid parent dirfd with a valid C string.
    if unsafe { libc::unlinkat(parent_fd.as_raw_fd(), c_name.as_ptr(), 0) } == -1 {
        return Err(FsHostError::IoError(io::Error::last_os_error()));
    }

    Ok(FsDeleteResult {
        before_hash,
        bytes_before,
    })
}

// Async entry points (called from Host trait impl)

pub async fn fs_read(config: Arc<FsHostConfig>, path: String) -> Result<FsReadResult, FsHostError> {
    tokio::task::spawn_blocking(move || read_sync(&config, &path))
        .await
        .map_err(|e| FsHostError::IoError(io::Error::other(e)))?
}

pub async fn fs_write(
    config: Arc<FsHostConfig>,
    path: String,
    content: Vec<u8>,
    mode: FsWriteMode,
    expected_before_hash: Option<Vec<u8>>,
) -> Result<FsWriteResult, FsHostError> {
    tokio::task::spawn_blocking(move || {
        write_sync(
            &config,
            &path,
            &content,
            mode,
            expected_before_hash.as_deref(),
        )
    })
    .await
    .map_err(|e| FsHostError::IoError(io::Error::other(e)))?
}

pub async fn fs_delete(
    config: Arc<FsHostConfig>,
    path: String,
) -> Result<FsDeleteResult, FsHostError> {
    tokio::task::spawn_blocking(move || delete_sync(&config, &path))
        .await
        .map_err(|e| FsHostError::IoError(io::Error::other(e)))?
}

// Helpers

fn sha256(data: &[u8]) -> [u8; 32] {
    sha256_raw(data)
}

fn fstat_fd(fd: BorrowedFd<'_>) -> Result<libc::stat, FsHostError> {
    // SAFETY: fstat on a valid fd writes into a zeroed stat struct.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) };
    if ret == -1 {
        Err(FsHostError::IoError(io::Error::last_os_error()))
    } else {
        Ok(stat)
    }
}

/// Read all bytes from an fd (assumed positioned at start for regular files
/// opened by this module).
fn read_fd_full(fd: BorrowedFd<'_>, size_hint: usize) -> Result<Vec<u8>, FsHostError> {
    use std::io::Read;
    // SAFETY: we construct a File from a borrowed fd. The fd remains owned
    // by the caller; we must not close it. ManuallyDrop prevents File::drop
    // from closing the fd.
    let file = unsafe { std::fs::File::from_raw_fd(fd.as_raw_fd()) };
    let mut file = std::mem::ManuallyDrop::new(file);
    let mut buf = Vec::with_capacity(size_hint);
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Write all bytes to an fd.
fn write_all_fd(fd: BorrowedFd<'_>, data: &[u8]) -> Result<(), FsHostError> {
    use std::io::Write;
    // SAFETY: we construct a File from a borrowed fd. The fd remains owned
    // by the caller; we must not close it. ManuallyDrop prevents File::drop
    // from closing the fd.
    let file = unsafe { std::fs::File::from_raw_fd(fd.as_raw_fd()) };
    let mut file = std::mem::ManuallyDrop::new(file);
    file.write_all(data)?;
    Ok(())
}

/// fsync a file fd.
fn fsync_fd(fd: BorrowedFd<'_>) -> Result<(), FsHostError> {
    // SAFETY: fsync on a valid fd.
    if unsafe { libc::fsync(fd.as_raw_fd()) } == -1 {
        Err(FsHostError::IoError(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn path_to_cstring(path: &Path) -> Result<CString, FsHostError> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| FsHostError::PathInvalid("null byte in path".into()))
}

/// Map an `io::Error` from `open`/`openat` to the appropriate `FsHostError`.
fn map_open_error(e: io::Error, context: &str) -> FsHostError {
    match e.raw_os_error() {
        Some(libc::ENOENT) => FsHostError::PathNotFound(context.into()),
        Some(libc::EEXIST) => FsHostError::AlreadyExists,
        Some(libc::ELOOP) => FsHostError::SymlinkEscape(context.into()),
        Some(libc::EXDEV) => {
            // openat2 RESOLVE_BENEATH returns EXDEV on escape attempts.
            FsHostError::SymlinkEscape(context.into())
        }
        _ => FsHostError::IoError(e),
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // -- validate_path_string -----------------------------------------------

    #[test]
    fn rejects_empty_path() {
        assert!(matches!(
            validate_path_string(""),
            Err(FsHostError::PathInvalid(_))
        ));
    }

    #[test]
    fn rejects_absolute_path() {
        assert!(matches!(
            validate_path_string("/etc/passwd"),
            Err(FsHostError::PathInvalid(_))
        ));
    }

    #[test]
    fn rejects_null_byte() {
        assert!(matches!(
            validate_path_string("src/\0main.rs"),
            Err(FsHostError::PathInvalid(_))
        ));
    }

    #[test]
    fn rejects_control_char() {
        assert!(matches!(
            validate_path_string("src/\x01main.rs"),
            Err(FsHostError::PathInvalid(_))
        ));
        assert!(matches!(
            validate_path_string("src/\x7fmain.rs"),
            Err(FsHostError::PathInvalid(_))
        ));
    }

    #[test]
    fn rejects_dot_dot_traversal() {
        assert!(matches!(
            validate_path_string("src/../etc/passwd"),
            Err(FsHostError::Traversal)
        ));
        assert!(matches!(
            validate_path_string(".."),
            Err(FsHostError::Traversal)
        ));
    }

    #[test]
    fn rejects_windows_drive_prefix() {
        assert!(matches!(
            validate_path_string("C:\\Windows\\System32"),
            Err(FsHostError::PathInvalid(_))
        ));
    }

    #[test]
    fn rejects_unc_prefix() {
        assert!(matches!(
            validate_path_string("\\\\server\\share"),
            Err(FsHostError::PathInvalid(_))
        ));
    }

    #[test]
    fn accepts_valid_relative_path() {
        assert!(validate_path_string("src/main.rs").is_ok());
        assert!(validate_path_string("docs/guide.md").is_ok());
        assert!(validate_path_string("file.txt").is_ok());
        assert!(validate_path_string("a/b/c/d/e.rs").is_ok());
    }

    #[test]
    fn accepts_single_dot_component() {
        // "." is not ".." — it's valid (though unusual).
        assert!(validate_path_string("./src/main.rs").is_ok());
    }

    // -- Integration: open_root_fd + read -----------------------------------

    #[test]
    fn open_root_fd_rejects_nonexistent() {
        let result = open_root_fd(Path::new("/nonexistent_latchgate_test_dir"));
        assert!(result.is_err());
    }

    #[test]
    fn open_root_fd_rejects_regular_file() {
        // O_DIRECTORY must reject non-directories on all platforms, including
        // macOS where O_PATH is unavailable and we fall back to O_RDONLY.
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("not_a_dir.txt");
        std::fs::write(&file_path, b"data").unwrap();
        let result = open_root_fd(&file_path);
        assert!(result.is_err(), "open_root_fd must reject a regular file");
    }

    #[test]
    fn open_root_fd_succeeds_on_valid_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (fd, canonical) = open_root_fd(dir.path()).unwrap();
        // fd must be usable as a base for openat — verify with fstat.
        let stat = fstat_fd(fd.as_fd()).unwrap();
        assert_eq!(
            stat.st_mode & libc::S_IFMT,
            libc::S_IFDIR,
            "root fd must refer to a directory"
        );
        assert!(canonical.is_absolute());
    }

    #[test]
    fn read_sync_full_pipeline() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Create a test file.
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();

        let (root_fd, root_canonical) = open_root_fd(root).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Read],
            allowed_paths: vec![GlobPattern::new("src/**").unwrap()],
            denied_paths: vec![GlobPattern::new("**/.env").unwrap()],
            max_file_bytes: 1024 * 1024,
        };

        let result = read_sync(&config, "src/main.rs").unwrap();
        assert_eq!(result.content, b"fn main() {}");
        assert_eq!(result.size, 12);
        assert_eq!(result.hash, sha256(b"fn main() {}"));
    }

    #[test]
    fn read_sync_rejects_denied_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), b"SECRET=x").unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Read],
            allowed_paths: vec![GlobPattern::new("**").unwrap()],
            denied_paths: vec![GlobPattern::new("**/.env").unwrap()],
            max_file_bytes: 1024 * 1024,
        };

        let result = read_sync(&config, ".env");
        assert!(matches!(result, Err(FsHostError::PathDenied { .. })));
    }

    #[test]
    fn read_sync_rejects_unallowed_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("other.txt"), b"data").unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Read],
            allowed_paths: vec![GlobPattern::new("src/**").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let result = read_sync(&config, "other.txt");
        assert!(matches!(result, Err(FsHostError::PathNotAllowed)));
    }

    #[test]
    fn read_sync_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big.txt"), vec![0u8; 2048]).unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Read],
            allowed_paths: vec![GlobPattern::new("*").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024,
        };

        let result = read_sync(&config, "big.txt");
        assert!(matches!(result, Err(FsHostError::TooLarge { .. })));
    }

    // -- Write create -------------------------------------------------------

    #[test]
    fn write_create_sync_success() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Create],
            allowed_paths: vec![GlobPattern::new("src/**").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let content = b"hello world";
        let result = write_sync(&config, "src/new.rs", content, FsWriteMode::Create, None).unwrap();
        assert!(result.before_hash.is_none());
        assert_eq!(result.after_hash, sha256(content));
        assert_eq!(result.bytes_before, 0);
        assert_eq!(result.bytes_written, 11);

        // Verify file was actually written.
        let on_disk = std::fs::read(dir.path().join("src/new.rs")).unwrap();
        assert_eq!(on_disk, content);
    }

    #[test]
    fn write_create_sync_already_exists() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("exists.txt"), b"old").unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Create],
            allowed_paths: vec![GlobPattern::new("*").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let result = write_sync(&config, "exists.txt", b"new", FsWriteMode::Create, None);
        assert!(matches!(result, Err(FsHostError::AlreadyExists)));
    }

    // -- Write overwrite ----------------------------------------------------

    #[test]
    fn write_overwrite_sync_success() {
        let dir = tempfile::tempdir().unwrap();
        let old_content = b"old content";
        std::fs::write(dir.path().join("file.txt"), old_content).unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Overwrite],
            allowed_paths: vec![GlobPattern::new("*").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let new_content = b"new content here";
        let result = write_sync(
            &config,
            "file.txt",
            new_content,
            FsWriteMode::Overwrite,
            None,
        )
        .unwrap();

        assert_eq!(result.before_hash.unwrap(), sha256(old_content));
        assert_eq!(result.after_hash, sha256(new_content));
        assert_eq!(result.bytes_before, old_content.len() as u64);
        assert_eq!(result.bytes_written, new_content.len() as u64);
    }

    #[test]
    fn write_overwrite_sync_conflict() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"current").unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Overwrite],
            allowed_paths: vec![GlobPattern::new("*").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let wrong_hash = [0xFFu8; 32];
        let result = write_sync(
            &config,
            "file.txt",
            b"new",
            FsWriteMode::Overwrite,
            Some(&wrong_hash),
        );
        assert!(matches!(result, Err(FsHostError::Conflict)));

        // File must be unchanged.
        assert_eq!(
            std::fs::read(dir.path().join("file.txt")).unwrap(),
            b"current"
        );
    }

    #[test]
    fn write_overwrite_sync_expected_hash_match() {
        let dir = tempfile::tempdir().unwrap();
        let old = b"original";
        std::fs::write(dir.path().join("file.txt"), old).unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Overwrite],
            allowed_paths: vec![GlobPattern::new("*").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let correct_hash = sha256(old);
        let result = write_sync(
            &config,
            "file.txt",
            b"updated",
            FsWriteMode::Overwrite,
            Some(&correct_hash),
        );
        assert!(result.is_ok());
        assert_eq!(
            std::fs::read(dir.path().join("file.txt")).unwrap(),
            b"updated"
        );
    }

    // -- Delete -------------------------------------------------------------

    #[test]
    fn delete_sync_success() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        let content = b"to be deleted";
        std::fs::write(dir.path().join("src/old.rs"), content).unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Delete],
            allowed_paths: vec![GlobPattern::new("src/**").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let result = delete_sync(&config, "src/old.rs").unwrap();
        assert_eq!(result.before_hash.unwrap(), sha256(content));
        assert_eq!(result.bytes_before, content.len() as u64);
        assert!(!dir.path().join("src/old.rs").exists());
    }

    #[test]
    fn delete_sync_not_found() {
        let dir = tempfile::tempdir().unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Delete],
            allowed_paths: vec![GlobPattern::new("*").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let result = delete_sync(&config, "nonexistent.txt");
        assert!(matches!(result, Err(FsHostError::PathNotFound(_))));
    }

    // -- Symlink escape -----------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn read_rejects_symlink_leaf() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("target.txt"), b"secret").unwrap();
        std::os::unix::fs::symlink("target.txt", dir.path().join("link.txt")).unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Read],
            allowed_paths: vec![GlobPattern::new("*").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let result = read_sync(&config, "link.txt");
        // O_NOFOLLOW should cause ELOOP => SymlinkEscape.
        assert!(
            matches!(
                &result,
                Err(FsHostError::SymlinkEscape(_)) | Err(FsHostError::IoError(_))
            ),
            "expected symlink rejection, got: {result:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_rejects_symlink_intermediate() {
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("real");
        std::fs::create_dir_all(&real_dir).unwrap();
        std::fs::write(real_dir.join("file.txt"), b"data").unwrap();
        std::os::unix::fs::symlink("real", dir.path().join("link")).unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Read],
            allowed_paths: vec![GlobPattern::new("**").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let result = read_sync(&config, "link/file.txt");
        assert!(result.is_err(), "symlink intermediate should be rejected");
    }

    // -- Operation enforcement -----------------------------------------------

    #[test]
    fn read_blocked_when_not_in_allowed_operations() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"data").unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            // Grant only permits write — read must be rejected.
            allowed_operations: vec![FsOperation::Create],
            allowed_paths: vec![GlobPattern::new("*").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let result = read_sync(&config, "file.txt");
        assert!(
            matches!(
                result,
                Err(FsHostError::OperationNotAllowed(FsOperation::Read))
            ),
            "read must be rejected when Read is not in allowed_operations, got: {result:?}"
        );
    }

    #[test]
    fn write_create_blocked_when_not_in_allowed_operations() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            // Grant only permits read — create must be rejected.
            allowed_operations: vec![FsOperation::Read],
            allowed_paths: vec![GlobPattern::new("src/**").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let result = write_sync(&config, "src/new.rs", b"hello", FsWriteMode::Create, None);
        assert!(
            matches!(
                result,
                Err(FsHostError::OperationNotAllowed(FsOperation::Create))
            ),
            "create must be rejected when Create is not in allowed_operations, got: {result:?}"
        );

        // File must not exist.
        assert!(!dir.path().join("src/new.rs").exists());
    }

    #[test]
    fn write_overwrite_blocked_when_not_in_allowed_operations() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"original").unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            // Grant permits create but NOT overwrite.
            allowed_operations: vec![FsOperation::Create],
            allowed_paths: vec![GlobPattern::new("*").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let result = write_sync(
            &config,
            "file.txt",
            b"replaced",
            FsWriteMode::Overwrite,
            None,
        );
        assert!(
            matches!(result, Err(FsHostError::OperationNotAllowed(FsOperation::Overwrite))),
            "overwrite must be rejected when Overwrite is not in allowed_operations, got: {result:?}"
        );

        // File must be unchanged.
        assert_eq!(
            std::fs::read(dir.path().join("file.txt")).unwrap(),
            b"original"
        );
    }

    #[test]
    fn delete_blocked_when_not_in_allowed_operations() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("keep.txt"), b"important").unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            // Grant only permits read — delete must be rejected.
            allowed_operations: vec![FsOperation::Read],
            allowed_paths: vec![GlobPattern::new("*").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        let result = delete_sync(&config, "keep.txt");
        assert!(
            matches!(
                result,
                Err(FsHostError::OperationNotAllowed(FsOperation::Delete))
            ),
            "delete must be rejected when Delete is not in allowed_operations, got: {result:?}"
        );

        // File must still exist.
        assert!(dir.path().join("keep.txt").exists());
    }

    #[test]
    fn empty_allowed_operations_blocks_everything() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"data").unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![],
            allowed_paths: vec![GlobPattern::new("*").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        assert!(matches!(
            read_sync(&config, "file.txt"),
            Err(FsHostError::OperationNotAllowed(FsOperation::Read))
        ));
        assert!(matches!(
            write_sync(&config, "file.txt", b"x", FsWriteMode::Create, None),
            Err(FsHostError::OperationNotAllowed(FsOperation::Create))
        ));
        assert!(matches!(
            write_sync(&config, "file.txt", b"x", FsWriteMode::Overwrite, None),
            Err(FsHostError::OperationNotAllowed(FsOperation::Overwrite))
        ));
        assert!(matches!(
            delete_sync(&config, "file.txt"),
            Err(FsHostError::OperationNotAllowed(FsOperation::Delete))
        ));
    }

    #[test]
    fn operation_check_precedes_path_check() {
        // Even if the path would be allowed, a missing operation must
        // reject before any filesystem access occurs.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("allowed.txt"), b"ok").unwrap();

        let (root_fd, root_canonical) = open_root_fd(dir.path()).unwrap();
        let config = FsHostConfig {
            root_fd: Arc::new(root_fd),
            root_canonical,
            allowed_operations: vec![FsOperation::Read],
            allowed_paths: vec![GlobPattern::new("*").unwrap()],
            denied_paths: vec![],
            max_file_bytes: 1024 * 1024,
        };

        // Path is valid and allowed, but Delete is not in operations.
        let result = delete_sync(&config, "allowed.txt");
        assert!(
            matches!(result, Err(FsHostError::OperationNotAllowed(_))),
            "operation check must fire before path validation, got: {result:?}"
        );

        // File must still exist — no filesystem side-effect occurred.
        assert!(dir.path().join("allowed.txt").exists());
    }
}
