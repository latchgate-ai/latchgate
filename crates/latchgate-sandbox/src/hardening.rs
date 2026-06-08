//! Post-namespace hardening: capabilities, resource limits, exec.
//!
//! These functions are called by the bwrap sandbox-init shim after
//! namespace creation to restrict the agent process before `exec`.

use std::ffi::CString;
use std::path::Path;

use crate::{SandboxError, SandboxLaunchParams};

// Capability drop

/// Drop all capabilities from the bounding and ambient sets.
///
/// Called inside the bwrap sandbox-init shim after loopback bring-up
/// and before applying rlimits, Landlock, and seccomp. The agent must
/// not inherit any capabilities across `exec`.
///
/// - Ambient set: cleared with `PR_CAP_AMBIENT_CLEAR_ALL`. `EINVAL` on
///   kernels < 4.3 is harmless (ambient caps cannot be populated there).
/// - Bounding set: each cap 0..127 is dropped with `PR_CAPBSET_DROP`.
///   `EINVAL` terminates the loop (cap number past `CAP_LAST_CAP`).
///
/// # EPERM in user namespaces
///
/// On restricted kernels (WSL2, hardened Ubuntu, some container runtimes)
/// `PR_CAPBSET_DROP` and `PR_CAP_AMBIENT_CLEAR_ALL` return `EPERM` even
/// inside the user namespace bwrap creates. The capabilities in question
/// are **synthetic and namespace-scoped** — they grant zero host
/// privilege. The primary containment layers (user-namespace boundary,
/// seccomp, Landlock) are applied *after* this function and remain fully
/// effective regardless. Aborting here would deny the sandbox entirely
/// on these platforms for no security gain.
///
/// Policy: `EPERM` → warn and continue. Any other unexpected error →
/// fail closed.
pub(crate) fn drop_capabilities() -> Result<(), SandboxError> {
    // Clear the ambient capability set in one shot.
    //
    // SAFETY: PR_CAP_AMBIENT with PR_CAP_AMBIENT_CLEAR_ALL removes all
    // ambient capabilities. Returns EINVAL on older kernels (< 4.3) where
    // ambient caps don't exist — harmless, as they can't be set either.
    let ret = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            6, /* PR_CAP_AMBIENT_CLEAR_ALL */
            0,
            0,
            0,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // Kernel < 4.3: ambient caps unsupported, can't be populated.
            Some(libc::EINVAL) => {}
            // Restricted user namespace — caps are synthetic and
            // namespace-scoped. Seccomp is the primary enforcement.
            Some(libc::EPERM) => {
                tracing::warn!(
                    "prctl(PR_CAP_AMBIENT_CLEAR_ALL): EPERM — \
                     cannot clear ambient caps in this user namespace \
                     (defense-in-depth reduced; seccomp + Landlock still enforced)"
                );
            }
            _ => {
                return Err(SandboxError::NamespaceSetup(format!(
                    "prctl(PR_CAP_AMBIENT_CLEAR_ALL): {err}"
                )));
            }
        }
    }

    // Drop every capability from the bounding set.
    //
    // Cap values are 0..CAP_LAST_CAP. Current CAP_LAST_CAP is ~41; we
    // loop to 128 to cover future kernel additions without a code change.
    // EINVAL terminates the loop (the cap number doesn't exist).
    for cap in 0..128 {
        // SAFETY: PR_CAPBSET_DROP with an invalid cap number returns EINVAL,
        // which we use as the termination signal.
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                // Past CAP_LAST_CAP — bounding set fully walked.
                Some(libc::EINVAL) => break,
                // Restricted user namespace — same reasoning as ambient
                // clear above. All subsequent caps will also EPERM, so
                // stop the loop.
                Some(libc::EPERM) => {
                    tracing::warn!(
                        "prctl(PR_CAPBSET_DROP, {cap}): EPERM — \
                         cannot drop bounding set in this user namespace \
                         (defense-in-depth reduced; seccomp + Landlock still enforced)"
                    );
                    break;
                }
                _ => {
                    return Err(SandboxError::NamespaceSetup(format!(
                        "prctl(PR_CAPBSET_DROP, {cap}): {err}"
                    )));
                }
            }
        }
    }

    Ok(())
}

// Resource limits

/// Maximum processes (including threads) the agent can create.
const RLIMIT_NPROC_MAX: libc::rlim_t = 512;

/// Maximum virtual address space in bytes (8 GiB).
const RLIMIT_AS_MAX: libc::rlim_t = 8 * 1024 * 1024 * 1024;

/// Maximum size of a single file in bytes (1 GiB).
const RLIMIT_FSIZE_MAX: libc::rlim_t = 1024 * 1024 * 1024;

/// Maximum number of open file descriptors (4096).
const RLIMIT_NOFILE_MAX: libc::rlim_t = 4096;

/// Maximum core dump size (0 = disabled).
///
/// SECURITY: core dumps can contain decrypted secrets, session tokens,
/// and other sensitive data from process memory.
const RLIMIT_CORE_MAX: libc::rlim_t = 0;

/// Maximum data segment (heap) size in bytes (4 GiB).
const RLIMIT_DATA_MAX: libc::rlim_t = 4 * 1024 * 1024 * 1024;

/// Maximum stack size in bytes (8 MiB).
const RLIMIT_STACK_MAX: libc::rlim_t = 8 * 1024 * 1024;

/// Maximum cumulative CPU seconds for the agent process tree (600 = 10 min).
const RLIMIT_CPU_MAX: libc::rlim_t = 600;

/// Maximum locked (non-swappable) memory in bytes (64 KiB).
const RLIMIT_MEMLOCK_MAX: libc::rlim_t = 64 * 1024;

/// Maximum number of pending signals (256).
const RLIMIT_SIGPENDING_MAX: libc::rlim_t = 256;

/// Maximum bytes of POSIX message queue memory (0 = disabled).
const RLIMIT_MSGQUEUE_MAX: libc::rlim_t = 0;

// `__rlimit_resource_t` is glibc-specific; musl uses plain `c_int`.
#[cfg(target_env = "gnu")]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))]
type RlimitResource = libc::c_int;

fn set_rlimit(resource: RlimitResource, max: libc::rlim_t, name: &str) -> Result<(), SandboxError> {
    let rlim = libc::rlimit {
        rlim_cur: max,
        rlim_max: max,
    };
    // SAFETY: setrlimit with a valid RLIMIT_* constant and a correctly
    // initialized rlimit struct. Only restricts the calling process further.
    let ret = unsafe { libc::setrlimit(resource, &rlim) };
    if ret != 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "setrlimit({name}): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Apply resource limits to the calling process.
///
/// Called by the sandbox-init shim before Landlock and seccomp. These
/// limits bound the agent's resource consumption as a defense-in-depth
/// layer independent of namespace isolation.
pub(crate) fn apply_rlimits() -> Result<(), SandboxError> {
    set_rlimit(libc::RLIMIT_NPROC, RLIMIT_NPROC_MAX, "RLIMIT_NPROC")?;
    set_rlimit(libc::RLIMIT_AS, RLIMIT_AS_MAX, "RLIMIT_AS")?;
    set_rlimit(libc::RLIMIT_DATA, RLIMIT_DATA_MAX, "RLIMIT_DATA")?;
    set_rlimit(libc::RLIMIT_STACK, RLIMIT_STACK_MAX, "RLIMIT_STACK")?;
    set_rlimit(libc::RLIMIT_FSIZE, RLIMIT_FSIZE_MAX, "RLIMIT_FSIZE")?;
    set_rlimit(libc::RLIMIT_NOFILE, RLIMIT_NOFILE_MAX, "RLIMIT_NOFILE")?;
    set_rlimit(libc::RLIMIT_CORE, RLIMIT_CORE_MAX, "RLIMIT_CORE")?;
    set_rlimit(libc::RLIMIT_CPU, RLIMIT_CPU_MAX, "RLIMIT_CPU")?;
    set_rlimit(libc::RLIMIT_MEMLOCK, RLIMIT_MEMLOCK_MAX, "RLIMIT_MEMLOCK")?;
    set_rlimit(
        libc::RLIMIT_SIGPENDING,
        RLIMIT_SIGPENDING_MAX,
        "RLIMIT_SIGPENDING",
    )?;
    set_rlimit(
        libc::RLIMIT_MSGQUEUE,
        RLIMIT_MSGQUEUE_MAX,
        "RLIMIT_MSGQUEUE",
    )?;
    Ok(())
}

// PATH and exec

/// PATH directories for the sandbox.
const SANDBOX_PATH: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

/// Build the PATH string for the sandbox, including `bin`/`sbin` from
/// any read-only mounts.
pub(crate) fn build_sandbox_path(ro_mounts: &[std::path::PathBuf]) -> String {
    let mut path = SANDBOX_PATH.join(":");
    for mount in ro_mounts {
        for subdir in &["bin", "sbin"] {
            let candidate = mount.join(subdir);
            if candidate.is_dir() {
                path.push(':');
                path.push_str(&candidate.to_string_lossy());
            }
        }
    }
    path
}

fn resolve_in_path(cmd: &str, ro_mounts: &[std::path::PathBuf]) -> Result<CString, SandboxError> {
    let resolved = if cmd.starts_with('/') {
        let p = Path::new(cmd);
        if p.exists() {
            cmd.to_string()
        } else {
            return Err(SandboxError::Spawn(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("command not found: {cmd}"),
            )));
        }
    } else {
        let from_standard = SANDBOX_PATH
            .iter()
            .map(|dir| format!("{dir}/{cmd}"))
            .find(|candidate| Path::new(candidate).exists());

        if let Some(found) = from_standard {
            found
        } else {
            ro_mounts
                .iter()
                .flat_map(|mount| {
                    ["bin", "sbin"].iter().filter_map(move |sub| {
                        let candidate = mount.join(sub).join(cmd);
                        candidate
                            .exists()
                            .then(|| candidate.to_string_lossy().into_owned())
                    })
                })
                .next()
                .ok_or_else(|| {
                    SandboxError::Spawn(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("command not found in sandbox PATH: {cmd}"),
                    ))
                })?
        }
    };

    CString::new(resolved.into_bytes())
        .map_err(|_| SandboxError::NamespaceSetup("resolved path contains null byte".to_string()))
}

/// Resolve and exec the command from `params`.
///
/// Does not return on success — `execv` replaces the process image.
/// On failure, returns a [`SandboxError`].
///
/// # Preconditions
///
/// - Caller must have already applied all hardening (rlimits, Landlock,
///   seccomp). `execv` inherits the process's security state.
pub(crate) fn exec_command(params: &SandboxLaunchParams) -> Result<(), SandboxError> {
    let program = resolve_in_path(&params.command[0], &params.ro_mounts)?;

    let c_args: Vec<CString> = params
        .command
        .iter()
        .map(|a| {
            CString::new(a.as_bytes())
                .map_err(|_| SandboxError::NamespaceSetup("arg contains null byte".to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let c_argv: Vec<*const libc::c_char> = c_args
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // SAFETY: program is a valid CString containing an absolute path.
    // argv is a null-terminated array of valid CString pointers. c_args
    // is alive for the duration. execv replaces the process on success.
    unsafe { libc::execv(program.as_ptr(), c_argv.as_ptr()) };

    Err(SandboxError::Spawn(std::io::Error::last_os_error()))
}
