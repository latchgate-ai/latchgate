//! Landlock filesystem and network restriction for defense-in-depth.
//!
//! Applies a Landlock ruleset inside the sandbox after `pivot_root` and
//! before `seccomp::apply`. This is an **independent** kernel enforcement
//! layer — if a namespace escape CVE grants the agent unexpected access,
//! Landlock independently enforces the same filesystem boundaries.
//!
//! The seccomp filter (applied after Landlock) blocks the agent from
//! invoking Landlock syscalls, preventing it from modifying its own
//! restrictions.
//!
//! # ABI versioning
//!
//! The Landlock ABI is versioned by the kernel:
//!
//! | ABI | Kernel | Additions                            |
//! |-----|--------|--------------------------------------|
//! | v1  | 5.13   | Filesystem access control            |
//! | v2  | 5.19   | `REFER` (cross-directory rename)      |
//! | v3  | 6.2    | `TRUNCATE`                           |
//! | v4  | 6.7    | TCP bind/connect port filtering       |
//! | v5  | 6.10   | `IOCTL_DEV` (device ioctls)          |
//!
//! The handled access mask is built from only the rights supported by
//! the running kernel. Per-path allowed access is intersected with the
//! handled mask before each `add_rule` call.
//!
//! # TCP filtering (ABI v4+)
//!
//! On kernels ≥ 6.7, Landlock can restrict TCP `connect` and `bind`
//! operations by port number. By handling both `CONNECT_TCP` and
//! `BIND_TCP` without adding any port rules, **all TCP is denied**.
//!
//! This is the correct policy: the agent communicates exclusively through
//! the Unix domain socket proxy. No legitimate TCP connections are needed.
//!
//! # Graceful degradation
//!
//! On kernels < 5.13 (no Landlock), [`apply`] logs a warning and returns
//! `Ok(())` — namespace + seccomp remain the enforcement layers. If
//! Landlock IS available but setup fails, the error propagates (fail-closed).

use std::ffi::CString;

use crate::{SandboxError, SandboxLaunchParams};

// Syscall numbers (generic range — identical on x86_64 and aarch64)

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

// Kernel UAPI constants (include/uapi/linux/landlock.h)

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_RULE_NET_PORT: u32 = 2;

// Filesystem access rights — ABI v1 (kernel 5.13+).
const ACCESS_FS_EXECUTE: u64 = 1 << 0;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_READ_DIR: u64 = 1 << 3;
const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
// ABI v2 (kernel 5.19+).
const ACCESS_FS_REFER: u64 = 1 << 13;
// ABI v3 (kernel 6.2+).
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;
// ABI v5 (kernel 6.10+).
const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

// Network access rights — ABI v4 (kernel 6.7+).
const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

// Composite access sets

/// Read-only: list directories and read files.
const ACCESS_RO: u64 = ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR;

/// Read + execute (runtime dirs, ro_mounts).
const ACCESS_RO_EXEC: u64 = ACCESS_RO | ACCESS_FS_EXECUTE;

/// Full write access base (before ABI-version additions).
const ACCESS_RW_BASE: u64 = ACCESS_RO_EXEC
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_SYM;

// Kernel structures

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    // handled_access_net added in ABI v4. Passing zeros in the extra bytes
    // is accepted by all ABI versions (the kernel checks that unknown
    // trailing bytes are zero before accepting the struct).
    handled_access_net: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Landlock net port attribute (ABI v4, kernel 6.7+).
///
/// Used with `LANDLOCK_RULE_NET_PORT` to allow TCP connect or bind on a
/// specific port. Both fields are u64 for alignment with the kernel ABI.
#[repr(C)]
struct NetPortAttr {
    allowed_access: u64,
    port: u64,
}

// Syscall wrappers

/// Detect the Landlock ABI version supported by the running kernel.
///
/// Returns `None` if Landlock is not available (kernel < 5.13, or blocked
/// by a security module).
fn detect_abi_version() -> Option<i32> {
    // SAFETY: NULL attr + size 0 + VERSION flag is the documented way to
    // query the ABI version. No memory access, no side effects.
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<u8>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret < 0 {
        None
    } else {
        Some(ret as i32)
    }
}

/// Build the `handled_access_fs` bitmask for the given ABI version.
///
/// Only includes access rights the kernel understands. Including an
/// unknown right would cause `create_ruleset` to fail with `EINVAL`.
fn build_handled_fs(abi: i32) -> u64 {
    let mut handled = ACCESS_FS_EXECUTE
        | ACCESS_FS_WRITE_FILE
        | ACCESS_FS_READ_FILE
        | ACCESS_FS_READ_DIR
        | ACCESS_FS_REMOVE_DIR
        | ACCESS_FS_REMOVE_FILE
        | ACCESS_FS_MAKE_CHAR
        | ACCESS_FS_MAKE_DIR
        | ACCESS_FS_MAKE_REG
        | ACCESS_FS_MAKE_SOCK
        | ACCESS_FS_MAKE_FIFO
        | ACCESS_FS_MAKE_BLOCK
        | ACCESS_FS_MAKE_SYM;

    if abi >= 2 {
        handled |= ACCESS_FS_REFER;
    }
    if abi >= 3 {
        handled |= ACCESS_FS_TRUNCATE;
    }
    if abi >= 5 {
        handled |= ACCESS_FS_IOCTL_DEV;
    }
    handled
}

/// Build the `handled_access_net` bitmask for the given ABI version.
///
/// On ABI v4+ (kernel 6.7+), handles both TCP connect and bind. Without
/// any corresponding port rules, ALL TCP operations are denied.
///
/// On ABI < 4, returns 0 (no network handling — TCP is unrestricted by
/// Landlock, but CLONE_NEWNET blocks it).
fn build_handled_net(abi: i32) -> u64 {
    if abi >= 4 {
        ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP
    } else {
        0
    }
}

/// Create a Landlock ruleset restricting the given filesystem and network
/// access types.
///
/// Returns the ruleset file descriptor (must be closed by the caller).
fn create_ruleset(handled_fs: u64, handled_net: u64) -> Result<i32, SandboxError> {
    let attr = RulesetAttr {
        handled_access_fs: handled_fs,
        handled_access_net: handled_net,
    };
    // SAFETY: attr is a valid, initialized struct. The size matches the
    // struct layout. Flags = 0 (not VERSION query). The kernel validates
    // the struct contents and returns a file descriptor or an error.
    let fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if fd < 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "landlock_create_ruleset: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(fd as i32)
}

/// Add a path-beneath rule to the ruleset.
///
/// Opens `path` with `O_PATH | O_CLOEXEC` to get a handle for the rule,
/// then adds it. Silently skips paths that don't exist (returns `Ok`).
fn add_path_rule(ruleset_fd: i32, path: &str, allowed_access: u64) -> Result<(), SandboxError> {
    if allowed_access == 0 {
        return Ok(());
    }

    let c_path = CString::new(path).map_err(|_| {
        SandboxError::NamespaceSetup(format!("landlock path contains null byte: {path}"))
    })?;

    // SAFETY: c_path is a valid NUL-terminated string. O_PATH returns a
    // handle without opening the file for I/O. O_CLOEXEC prevents fd leak
    // across exec.
    let parent_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if parent_fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            // Path doesn't exist in the sandbox — skip.
            return Ok(());
        }
        return Err(SandboxError::NamespaceSetup(format!(
            "landlock: open({path}, O_PATH): {err}"
        )));
    }

    let attr = PathBeneathAttr {
        allowed_access,
        parent_fd,
    };

    // SAFETY: ruleset_fd is a valid Landlock ruleset fd from
    // create_ruleset. attr is a valid packed struct with a valid fd.
    // LANDLOCK_RULE_PATH_BENEATH is the documented rule type.
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const PathBeneathAttr,
            0u32,
        )
    };

    // SAFETY: parent_fd is a valid open fd from our open() above.
    unsafe { libc::close(parent_fd) };

    if ret < 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "landlock_add_rule({path}): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Add a TCP port rule to the ruleset (ABI v4+).
///
/// Allows the specified `allowed_access` (CONNECT_TCP, BIND_TCP, or both)
/// on the given port. Only meaningful when `handled_access_net` includes
/// the corresponding bits; otherwise the kernel ignores the rule.
fn add_net_port_rule(ruleset_fd: i32, port: u16, allowed_access: u64) -> Result<(), SandboxError> {
    if allowed_access == 0 {
        return Ok(());
    }

    let attr = NetPortAttr {
        allowed_access,
        port: port as u64,
    };

    // SAFETY: ruleset_fd is a valid Landlock ruleset fd from
    // create_ruleset. attr is a valid struct with a port number.
    // LANDLOCK_RULE_NET_PORT is the documented rule type for ABI v4+.
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_NET_PORT,
            &attr as *const NetPortAttr,
            0u32,
        )
    };

    if ret < 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "landlock_add_rule(net_port:{port}): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Apply the ruleset to the calling process (irreversible).
fn restrict_self(ruleset_fd: i32) -> Result<(), SandboxError> {
    // SAFETY: ruleset_fd is a valid Landlock ruleset fd with rules added.
    // restrict_self is irreversible — the process and all future children
    // are permanently bound by the ruleset. Flags = 0 (no extensions).
    let ret = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };
    if ret < 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "landlock_restrict_self: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

// Public API

/// Return the Landlock ABI version (0 if not available).
///
/// Used to populate [`SandboxInitConfig::landlock_abi`] so the bwrap
/// shim knows whether to apply Landlock.
pub(crate) fn detect_abi() -> i32 {
    detect_abi_version().unwrap_or(0)
}

/// Apply Landlock filesystem and network restrictions inside the sandbox.
///
/// Called in the grandchild (raw namespace path) or the bwrap shim after
/// namespace creation and before `seccomp::apply`. All sandbox paths
/// must already be mounted.
///
/// `forwarder_port` is the loopback TCP port of the in-sandbox forwarder.
/// On kernels ≥ 6.7 (ABI v4), a `CONNECT_TCP` rule is added for this
/// port so the agent can reach the proxy through the forwarder. All other
/// TCP is denied.
///
/// On kernels without Landlock (< 5.13), logs a warning and returns
/// `Ok(())` — namespace + seccomp remain the enforcement layers.
pub(crate) fn apply(params: &SandboxLaunchParams, forwarder_port: u16) -> Result<(), SandboxError> {
    let abi = match detect_abi_version() {
        Some(v) => v,
        None => {
            tracing::warn!(
                "Landlock not available (kernel < 5.13) — \
                 skipping defense-in-depth filesystem restrictions"
            );
            return Ok(());
        }
    };

    let handled_fs = build_handled_fs(abi);
    let handled_net = build_handled_net(abi);

    if handled_net > 0 {
        tracing::debug!(
            abi_version = abi,
            "applying Landlock filesystem + TCP restrictions"
        );
    } else {
        tracing::debug!(
            abi_version = abi,
            "applying Landlock filesystem restrictions (TCP filtering requires ABI v4 / kernel 6.7+)"
        );
    }

    let ruleset_fd = create_ruleset(handled_fs, handled_net)?;

    // Filesystem and network rules.
    let result = add_all_rules(
        ruleset_fd,
        params,
        abi,
        handled_fs,
        "/workspace",
        forwarder_port,
    );
    if let Err(e) = result {
        // SAFETY: ruleset_fd is a valid fd from create_ruleset.
        unsafe { libc::close(ruleset_fd) };
        return Err(e);
    }

    let result = restrict_self(ruleset_fd);
    // SAFETY: ruleset_fd is a valid fd from create_ruleset. Must be
    // closed regardless of whether restrict_self succeeded.
    unsafe { libc::close(ruleset_fd) };
    result
}

/// Add rules for every allowed path (and the forwarder port) in the sandbox.
fn add_all_rules(
    ruleset_fd: i32,
    params: &SandboxLaunchParams,
    abi: i32,
    handled_fs: u64,
    workspace_path: &str,
    forwarder_port: u16,
) -> Result<(), SandboxError> {
    // Build access sets bounded by the kernel's handled mask.
    let mut access_rw = ACCESS_RW_BASE;
    if abi >= 2 {
        access_rw |= ACCESS_FS_REFER;
    }
    if abi >= 3 {
        access_rw |= ACCESS_FS_TRUNCATE;
    }
    let access_rw = access_rw & handled_fs;
    let access_ro = ACCESS_RO & handled_fs;
    let access_ro_exec = ACCESS_RO_EXEC & handled_fs;

    // /tmp: writable but NOT executable — defense-in-depth against
    // write-then-exec patterns (the agent should only execute binaries
    // from read-only system paths).
    let access_tmp = (access_rw & !ACCESS_FS_EXECUTE) & handled_fs;

    // Devices: read + write + ioctl (if supported).
    let mut access_dev = ACCESS_FS_READ_FILE | ACCESS_FS_WRITE_FILE;
    if abi >= 5 {
        access_dev |= ACCESS_FS_IOCTL_DEV;
    }
    let access_dev = access_dev & handled_fs;

    // ── Scaffold root: directory listing only ──
    add_path_rule(ruleset_fd, "/", ACCESS_FS_READ_DIR & handled_fs)?;

    // ── Workspace: full read-write + execute ──
    add_path_rule(ruleset_fd, workspace_path, access_rw)?;

    // ── System runtime dirs: read + execute ──
    add_path_rule(ruleset_fd, "/usr", access_ro_exec)?;
    add_path_rule(ruleset_fd, "/bin", access_ro_exec)?;
    add_path_rule(ruleset_fd, "/sbin", access_ro_exec)?;
    add_path_rule(ruleset_fd, "/lib", access_ro_exec)?;
    add_path_rule(ruleset_fd, "/lib64", access_ro_exec)?;

    // ── /tmp: writable, not executable ──
    add_path_rule(ruleset_fd, "/tmp", access_tmp)?;

    // ── Read-only paths ──
    add_path_rule(ruleset_fd, "/etc", access_ro)?;
    add_path_rule(ruleset_fd, "/proc", access_ro)?;
    add_path_rule(ruleset_fd, "/run/latchgate", access_ro)?;

    // ── Device nodes ──
    add_path_rule(ruleset_fd, "/dev/null", access_dev)?;
    add_path_rule(ruleset_fd, "/dev/urandom", access_dev)?;
    add_path_rule(ruleset_fd, "/dev/zero", access_dev)?;

    // ── Read-only mounts: read + execute ──
    for mount in &params.ro_mounts {
        add_path_rule(ruleset_fd, &mount.to_string_lossy(), access_ro_exec)?;
    }

    // ── Network: allow TCP connect to the loopback forwarder only ──
    //
    // On ABI v4+ (kernel 6.7+), handled_access_net includes CONNECT_TCP
    // and BIND_TCP. By adding a single CONNECT_TCP rule for the forwarder
    // port, the agent can reach the proxy. All other TCP connect and all
    // TCP bind remain denied. On ABI < 4 this is a no-op (handled_net
    // is 0, so the kernel ignores network rules entirely).
    if abi >= 4 {
        add_net_port_rule(ruleset_fd, forwarder_port, ACCESS_NET_CONNECT_TCP)?;
    }

    Ok(())
}
