//! Platform support detection for agent sandboxing.
//!
//! Compile-time gating via `cfg(target_os)` plus runtime checks for
//! kernel feature availability. Fail-closed: if any check fails, the
//! sandbox refuses to start and returns an actionable error message.

use crate::SandboxError;

// Sandbox tier

/// Sandbox launch tier — reported by `doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxTier {
    /// Real root — parent-assisted netns. Works on every kernel.
    RootAssisted,
    /// Non-root — rootless bwrap with `--unshare-net` + `CAP_NET_ADMIN`.
    /// Works on permissive kernels only; hardened kernels (Ubuntu 24.04,
    /// RHEL 9, WSL2) block the loopback ioctl under synthetic caps.
    RootlessBwrap,
    /// Cannot sandbox — bubblewrap not available.
    Unavailable,
}

impl std::fmt::Display for SandboxTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootAssisted => f.write_str("root — parent-assisted network namespace (robust)"),
            Self::RootlessBwrap => {
                f.write_str("non-root — rootless bubblewrap (permissive kernels only)")
            }
            Self::Unavailable => f.write_str("unavailable — bubblewrap not found"),
        }
    }
}

/// Detect the sandbox launch tier based on effective uid and bwrap
/// availability.
#[cfg(target_os = "linux")]
pub fn detect_tier() -> SandboxTier {
    // SAFETY: geteuid() is a read-only syscall with no side effects.
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root && is_bwrap_available() {
        SandboxTier::RootAssisted
    } else if is_bwrap_available() {
        SandboxTier::RootlessBwrap
    } else {
        SandboxTier::Unavailable
    }
}

#[cfg(not(target_os = "linux"))]
pub fn detect_tier() -> SandboxTier {
    SandboxTier::Unavailable
}

// Sandbox readiness check

/// Verify the current platform can run the agent sandbox.
///
/// On Linux, checks that bubblewrap is available (the sole launch path).
/// On all other platforms, returns [`SandboxError::UnsupportedPlatform`].
pub fn check() -> Result<(), SandboxError> {
    check_inner()
}

#[cfg(target_os = "linux")]
fn check_inner() -> Result<(), SandboxError> {
    if is_bwrap_available() {
        Ok(())
    } else {
        Err(SandboxError::UserNamespacesDisabled {
            reason: "bubblewrap (bwrap) not found on PATH — required for sandbox".into(),
        })
    }
}

#[cfg(not(target_os = "linux"))]
fn check_inner() -> Result<(), SandboxError> {
    Err(SandboxError::UnsupportedPlatform(platform_message()))
}

#[cfg(not(target_os = "linux"))]
fn platform_message() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    format!(
        "detected {os}/{arch} — Linux namespace primitives are not available.\n\
         Options:\n\
         • Run inside a Linux VM (e.g. Lima, UTM, or WSL2)\n\
         • Use Docker with a Linux image\n\
         • Deploy to a Linux server"
    )
}

// Bubblewrap availability

/// Returns `true` if bubblewrap (`bwrap`) is available and functional.
///
/// Two-step probe:
/// 1. `which bwrap` — binary exists on PATH.
/// 2. `bwrap --unshare-user --ro-bind / / -- /bin/true` — actually works
///    (some systems have bwrap but restrict it via AppArmor/SELinux).
///
/// The result is cached per process via [`OnceLock`].
pub fn is_bwrap_available() -> bool {
    use std::sync::OnceLock;
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(probe_bwrap)
}

fn probe_bwrap() -> bool {
    // Step 1: binary on PATH.
    if !run_with_timeout("which", &["bwrap"], 5) {
        tracing::debug!("bwrap: not found on PATH");
        return false;
    }

    // Step 2: functional test — actually create a namespace.
    // Includes --clearenv to reject bwrap < 0.5 which lacks it.
    if !run_with_timeout(
        "bwrap",
        &[
            "--unshare-user",
            "--clearenv",
            "--ro-bind",
            "/",
            "/",
            "--",
            "/bin/true",
        ],
        10,
    ) {
        tracing::debug!(
            "bwrap: probe failed (binary found but namespace creation denied or timed out)"
        );
        return false;
    }

    tracing::debug!("bwrap: available and functional");
    true
}

/// Run a command with a hard timeout. Returns `true` only on exit code 0.
///
/// Uses `spawn` + `try_wait` poll instead of `status()` to prevent the
/// caller from blocking indefinitely when namespace operations hang
/// (common under AppArmor, restrictive seccomp, or nested containers).
fn run_with_timeout(program: &str, args: &[&str], timeout_secs: u64) -> bool {
    let mut child = match std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    tracing::debug!(
                        program,
                        timeout_secs,
                        "probe timed out — namespace operation likely blocked"
                    );
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => return false,
        }
    }
}

// Landlock availability (exposed for doctor probing)

/// Returns `true` if the running kernel supports Landlock (ABI ≥ 1).
///
/// Used by `latchgate doctor` to determine whether Landlock
/// defense-in-depth is available inside the sandbox.
#[cfg(target_os = "linux")]
pub fn is_landlock_available() -> bool {
    // SAFETY: NULL attr + size 0 + VERSION flag queries the ABI version
    // without side effects. Returns the version number on success.
    let ret = unsafe {
        libc::syscall(
            444i64, // SYS_landlock_create_ruleset
            std::ptr::null::<u8>(),
            0usize,
            1u32, // LANDLOCK_CREATE_RULESET_VERSION
        )
    };
    ret >= 1
}

#[cfg(not(target_os = "linux"))]
pub fn is_landlock_available() -> bool {
    false
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn platform_check_consistent_with_bwrap() {
        let result = check();
        if is_bwrap_available() {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn platform_check_fails_on_non_linux() {
        let err = check().unwrap_err();
        match err {
            SandboxError::UnsupportedPlatform(msg) => {
                assert!(msg.contains("Linux"));
            }
            other => panic!("expected UnsupportedPlatform, got: {other}"),
        }
    }

    #[test]
    fn bwrap_probe_is_deterministic() {
        let first = is_bwrap_available();
        let second = is_bwrap_available();
        assert_eq!(first, second);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn detect_tier_is_consistent() {
        let tier = detect_tier();
        // SAFETY: geteuid() is a read-only syscall.
        let is_root = unsafe { libc::geteuid() } == 0;
        if is_root && is_bwrap_available() {
            assert_eq!(tier, SandboxTier::RootAssisted);
        } else if is_bwrap_available() {
            assert_eq!(tier, SandboxTier::RootlessBwrap);
        } else {
            assert_eq!(tier, SandboxTier::Unavailable);
        }
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn detect_tier_unavailable_on_non_linux() {
        assert_eq!(detect_tier(), SandboxTier::Unavailable);
    }
}
