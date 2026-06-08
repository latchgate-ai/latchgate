//! Parent-assisted network namespace helper.
//!
//! On hardened kernels (Ubuntu 24.04, RHEL 9, WSL2), unprivileged
//! `CAP_NET_ADMIN` is insufficient to bring loopback up inside a
//! `CLONE_NEWNET` namespace. When the launcher is real root (euid 0),
//! this module forks a minimal helper that creates the network namespace
//! and configures loopback with real capabilities — an operation every
//! kernel permits for real root. bubblewrap then joins the pre-configured
//! namespace via `nsenter`, requiring no network capabilities itself.
//!
//! # Lifecycle
//!
//! ```text
//! Parent (latchgate, euid 0)
//!   ├─ fork() ──► Helper child
//!   │               │ prctl(PR_SET_PDEATHSIG, SIGKILL)
//!   │               │ unshare(CLONE_NEWNET)
//!   │               │ bring_up_loopback()    ← real CAP_NET_ADMIN
//!   │  ◄── pipe ──  │ write(0x42)            ← readiness signal
//!   │               │ pause()                ← holds netns alive
//!   │
//!   ├─ nsenter --net=/proc/<helper>/ns/net -- bwrap ...
//!   │    └─ agent (zero added caps, lo already up)
//!   │
//!   └─ drop(NetnsHelper)
//!        │ kill(helper, SIGKILL)
//!        │ waitpid(helper)                   ← netns destroyed
//! ```
//!
//! The helper is an anonymous namespace holder: no named netns, no
//! `/run/netns` state, no cleanup-on-crash concerns. `PR_SET_PDEATHSIG`
//! guarantees teardown even if the parent panics or is killed.

use std::io;

use crate::SandboxError;

// Readiness pipe timeout

/// Maximum time (ms) to wait for the helper to signal readiness.
///
/// The helper's work (unshare + one ioctl) takes microseconds. A timeout
/// this generous means something is fundamentally broken.
const READINESS_TIMEOUT_MS: libc::c_int = 10_000;

// NetnsHelper handle

/// Handle to a running netns helper process.
///
/// Owns the helper's lifetime: [`Drop`] sends `SIGKILL` and reaps the
/// child, destroying the network namespace. The namespace persists
/// exactly as long as this handle lives.
pub(crate) struct NetnsHelper {
    pid: libc::pid_t,
}

impl NetnsHelper {
    /// Procfs path to the helper's network namespace fd.
    ///
    /// Passed to `nsenter --net=<path>` so bwrap joins this namespace
    /// instead of creating its own.
    pub(crate) fn netns_path(&self) -> String {
        format!("/proc/{}/ns/net", self.pid)
    }
}

impl Drop for NetnsHelper {
    fn drop(&mut self) {
        // SAFETY: self.pid is a valid child PID from our fork(). SIGKILL
        // terminates unconditionally; waitpid prevents zombies.
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
            libc::waitpid(self.pid, std::ptr::null_mut(), 0);
        }
    }
}

// nsenter validation

/// Verify `nsenter` (from `util-linux`) is available on PATH.
fn validate_nsenter() -> Result<(), SandboxError> {
    let found = std::process::Command::new("which")
        .arg("nsenter")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if found {
        Ok(())
    } else {
        Err(SandboxError::NamespaceSetup(
            "nsenter not found on PATH — install util-linux \
             (required for sandbox network namespace setup)"
                .into(),
        ))
    }
}

// Helper spawn

/// Spawn the netns helper process.
///
/// Forks a minimal child that creates an isolated network namespace with
/// loopback up, then blocks. Returns a [`NetnsHelper`] whose [`Drop`]
/// tears everything down.
///
/// # Preconditions
///
/// - Caller must be real root (`geteuid() == 0`).
/// - `nsenter` must be on PATH (validated here).
pub(crate) fn spawn_helper() -> Result<NetnsHelper, SandboxError> {
    validate_nsenter()?;

    // Readiness pipe: child writes one byte after lo is up; parent
    // blocks until it arrives. O_CLOEXEC prevents leaking into bwrap.
    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe2 with valid pointer and O_CLOEXEC flag.
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "netns helper: pipe2: {}",
            io::Error::last_os_error()
        )));
    }
    let pipe_r = pipe_fds[0];
    let pipe_w = pipe_fds[1];

    // SAFETY: fork() with a running tokio runtime. The child performs
    // only async-signal-safe operations (prctl, unshare, socket, ioctl,
    // write, close, pause, _exit) and never returns to the caller or
    // touches the runtime.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let err = io::Error::last_os_error();
        // SAFETY: both fds are valid from pipe2 above.
        unsafe {
            libc::close(pipe_r);
            libc::close(pipe_w);
        }
        return Err(SandboxError::NamespaceSetup(format!(
            "netns helper: fork: {err}"
        )));
    }

    if pid == 0 {
        // Child — never returns.
        helper_child(pipe_r, pipe_w);
    }

    // Parent: close write end, wait for readiness from child.
    // SAFETY: pipe_w is a valid fd; parent doesn't write to it.
    unsafe { libc::close(pipe_w) };

    wait_for_readiness(pid, pipe_r)
}

// Helper child (runs in forked process, never returns)

/// Helper child entry point. Calls `_exit()` on all paths — never returns.
fn helper_child(pipe_r: i32, pipe_w: i32) -> ! {
    // SAFETY: pipe_r is valid; child doesn't read from it.
    unsafe { libc::close(pipe_r) };

    // Death-bind: auto-teardown if the parent dies before we do.
    // SAFETY: prctl(PR_SET_PDEATHSIG) only restricts this process.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        // SAFETY: _exit is async-signal-safe.
        unsafe { libc::_exit(1) };
    }

    // Race guard: if the parent died between fork() and prctl(), our
    // parent pid is now 1 (init). Bail — init will reap us.
    // SAFETY: getppid() is a read-only syscall.
    if unsafe { libc::getppid() } == 1 {
        // SAFETY: _exit is async-signal-safe; terminates only this child.
        unsafe { libc::_exit(1) };
    }

    // Create a new, isolated network namespace. lo exists but is DOWN.
    // SAFETY: unshare(CLONE_NEWNET) creates a new netns for this process.
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        // SAFETY: _exit is async-signal-safe; terminates only this child.
        unsafe { libc::_exit(1) };
    }

    // Bring loopback up. We hold real CAP_NET_ADMIN (inherited from
    // the real-root parent), so this succeeds on every kernel.
    if crate::loopback_forward::bring_up_loopback().is_err() {
        // SAFETY: _exit is async-signal-safe; terminates only this child.
        unsafe { libc::_exit(1) };
    }

    // Signal readiness: netns is configured, lo is up.
    let byte: [u8; 1] = [0x42];
    // SAFETY: pipe_w is valid; buffer is 1 byte.
    let n = unsafe { libc::write(pipe_w, byte.as_ptr() as *const libc::c_void, 1) };
    // SAFETY: close write end after signaling.
    unsafe { libc::close(pipe_w) };
    if n != 1 {
        // SAFETY: _exit is async-signal-safe; terminates only this child.
        unsafe { libc::_exit(1) };
    }

    // Hold the namespace alive until killed. pause() blocks until a
    // signal; the loop handles spurious wakeups.
    loop {
        // SAFETY: pause() is async-signal-safe, no side effects.
        unsafe { libc::pause() };
    }
}

// Parent readiness wait

/// Wait for the helper to signal readiness, with a timeout.
///
/// On success returns a `NetnsHelper` owning the child. On any failure
/// kills and reaps the child (no zombie, no leaked namespace).
fn wait_for_readiness(pid: libc::pid_t, pipe_r: i32) -> Result<NetnsHelper, SandboxError> {
    let mut pfd = libc::pollfd {
        fd: pipe_r,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pfd is a valid pollfd; nfds=1; timeout in ms.
    let ret = unsafe { libc::poll(&mut pfd, 1, READINESS_TIMEOUT_MS) };

    if ret <= 0 {
        let msg = if ret == 0 {
            format!(
                "netns helper: timed out waiting for readiness ({}s)",
                READINESS_TIMEOUT_MS / 1000
            )
        } else {
            format!("netns helper: poll: {}", io::Error::last_os_error())
        };
        // SAFETY: pid is a valid child; pipe_r is valid.
        unsafe {
            libc::close(pipe_r);
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        return Err(SandboxError::NamespaceSetup(msg));
    }

    // Read the readiness byte.
    let mut buf = [0u8; 1];
    // SAFETY: pipe_r is a valid, readable fd; buffer is 1 byte.
    let n = unsafe { libc::read(pipe_r, buf.as_mut_ptr() as *mut libc::c_void, 1) };
    // SAFETY: close read end — no longer needed.
    unsafe { libc::close(pipe_r) };

    if n != 1 {
        // Child died or closed the pipe before writing the byte.
        // SAFETY: pid is a valid child PID.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        return Err(SandboxError::NamespaceSetup(
            "netns helper: child exited before signaling readiness \
             (loopback bring-up may have failed)"
                .into(),
        ));
    }

    // Belt-and-suspenders: verify the namespace fd is accessible.
    let netns_path = format!("/proc/{pid}/ns/net");
    if !std::path::Path::new(&netns_path).exists() {
        // SAFETY: pid is a valid child PID.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        return Err(SandboxError::NamespaceSetup(format!(
            "netns helper: {netns_path} not accessible after readiness signal"
        )));
    }

    tracing::debug!(
        pid,
        netns = %netns_path,
        "netns helper ready — loopback up in isolated namespace"
    );

    Ok(NetnsHelper { pid })
}
