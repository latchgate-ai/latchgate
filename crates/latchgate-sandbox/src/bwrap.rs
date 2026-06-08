//! Bubblewrap (`bwrap`) sandbox integration.
//!
//! Uses bubblewrap to create user/PID/network/mount/UTS/IPC/cgroup
//! namespaces. This is the sole launch path for the agent sandbox.
//!
//! When running as root, the parent spawns a helper that pre-configures
//! a network namespace with loopback up (parent-assisted path); bwrap
//! joins it via `nsenter`. When non-root on a permissive kernel, bwrap
//! creates its own network namespace and the shim brings up loopback
//! with `CAP_NET_ADMIN`.
//!
//! # Architecture
//!
//! ```text
//! Parent (latchgate)
//!   ├─ proxy::start()                → tokio task (UDS listener)
//!   ├─ create_sealed_memfd(config)   → sealed fd 3
//!   └─ exec bwrap --unshare-* ... -- /sandbox-bin/latchgate sandbox-init --config-fd 3
//!        └─ sandbox-init shim:
//!             read config from fd 3, close fd
//!             apply_rlimits()
//!             landlock::apply()
//!             seccomp::apply()
//!             exec(agent-command)
//! ```
//!
//! # Config delivery
//!
//! The parent writes a [`SandboxInitConfig`] to a sealed memfd. Sealing
//! with `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL`
//! prevents any modification after creation — a compromised agent cannot
//! tamper with the config. The shim reads, deserializes, and closes the
//! fd before exec'ing the agent.

use std::ffi::CString;
use std::os::fd::RawFd;
use std::path::Path;
use std::process::Command;

use crate::{SandboxError, SandboxLaunchParams};

// Launch mode

/// Parameters controlling bwrap command construction that differ between
/// the root-assisted and rootless launch paths.
pub(crate) struct BwrapMode {
    /// If `Some`, bwrap is launched under `nsenter --net=<path>` to join
    /// the parent-configured network namespace. `--unshare-net` and
    /// `--cap-add CAP_NET_ADMIN` are omitted.
    ///
    /// If `None`, bwrap creates its own network namespace (rootless path)
    /// and the shim brings up loopback with `CAP_NET_ADMIN`.
    pub netns_path: Option<String>,

    /// uid for the agent process inside the sandbox. Must not be 0.
    pub sandbox_uid: u32,

    /// gid for the agent process inside the sandbox. Must not be 0.
    pub sandbox_gid: u32,
}

// Sandbox uid/gid resolution

/// Resolve the uid/gid for the sandboxed agent process.
///
/// Precedence (first non-zero match wins):
/// 1. `SUDO_UID` / `SUDO_GID` — the real user behind `sudo`
/// 2. Explicitly configured `sandbox_uid` / `sandbox_gid`
/// 3. Owner uid/gid of the workspace directory
/// 4. `nobody` / `nogroup` (65534)
///
/// Never returns uid 0. Under `sudo` the real user's identity is
/// preserved so `/workspace` writes have correct ownership.
pub(crate) fn resolve_sandbox_uid_gid(
    workspace: &Path,
    configured_uid: Option<u32>,
    configured_gid: Option<u32>,
) -> (u32, u32) {
    resolve_uid_gid_inner(
        std::env::var("SUDO_UID").ok(),
        std::env::var("SUDO_GID").ok(),
        configured_uid,
        configured_gid,
        workspace,
    )
}

/// Testable inner: accepts env-var values and config values as parameters
/// to avoid `set_var` in tests (not thread-safe since Rust 1.66).
fn resolve_uid_gid_inner(
    sudo_uid: Option<String>,
    sudo_gid: Option<String>,
    configured_uid: Option<u32>,
    configured_gid: Option<u32>,
    workspace: &Path,
) -> (u32, u32) {
    // 1. SUDO_UID / SUDO_GID
    if let Some(uid) = sudo_uid.as_deref().and_then(|s| s.parse::<u32>().ok()) {
        if uid != 0 {
            let gid = sudo_gid
                .as_deref()
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|&g| g != 0)
                .unwrap_or(uid);
            return (uid, gid);
        }
    }

    // 2. Explicitly configured uid/gid (validated non-zero at config load)
    if let Some(uid) = configured_uid.filter(|&u| u != 0) {
        let gid = configured_gid.filter(|&g| g != 0).unwrap_or(uid);
        return (uid, gid);
    }

    // 3. Workspace directory owner
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = workspace.metadata() {
            let uid = meta.uid();
            let gid = meta.gid();
            if uid != 0 {
                return (uid, gid);
            }
        }
    }

    // 4. nobody / nogroup
    (65534, 65534)
}

// Config struct

/// Configuration for the sandbox-init shim.
///
/// Serialized to JSON, written to a sealed memfd, read by the shim
/// inside the bwrap sandbox. All fields are resolved values —
/// no lookups or env reads needed inside the sandbox.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub(crate) struct SandboxInitConfig {
    /// Workspace path inside the sandbox (always "/workspace").
    pub workspace: String,

    /// Read-only mount paths (for Landlock rules).
    pub ro_mounts: Vec<String>,

    /// Command + args to exec after hardening.
    pub command: Vec<String>,

    /// Landlock ABI version detected on host (before bwrap).
    /// The shim skips Landlock if 0 (kernel < 5.13).
    pub landlock_abi: i32,

    /// Reverse-proxy credential route names. The shim builds
    /// `<ROUTE>_BASE_URL` env vars pointing at the loopback proxy once the
    /// forwarder port is known.
    pub credential_routes: Vec<String>,

    /// Reverse-proxy session token (hex), if credential routing is active.
    /// Set as `LATCHGATE_PROXY_TOKEN` by the shim.
    pub proxy_token: Option<String>,
}

// Sealed memfd

/// Create a sealed memfd containing the serialized config.
///
/// The memfd is created with `MFD_ALLOW_SEALING`, written, then sealed
/// with all four seals. `FD_CLOEXEC` is cleared so bwrap inherits the fd.
///
/// Returns the raw fd number (caller must close after bwrap exits).
pub(crate) fn create_sealed_memfd(config: &SandboxInitConfig) -> Result<RawFd, SandboxError> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

    let json = serde_json::to_vec(config)
        .map_err(|e| SandboxError::NamespaceSetup(format!("serialize SandboxInitConfig: {e}")))?;

    let name = CString::new("latchgate-sandbox-config")
        .map_err(|_| SandboxError::NamespaceSetup("memfd name contains null byte".into()))?;

    // SAFETY: memfd_create with valid name and sealing flag. Creates an
    // anonymous file descriptor backed by RAM — no filesystem side effects.
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "memfd_create: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: fd is valid from memfd_create above. OwnedFd/File takes
    // ownership; if any subsequent step fails, drop closes the fd.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };

    file.write_all(&json)
        .map_err(|e| SandboxError::NamespaceSetup(format!("memfd write: {e}")))?;

    // Seal — no further writes, truncation, or extension.
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
    // SAFETY: fd is a valid memfd created with MFD_ALLOW_SEALING.
    let ret = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) };
    if ret < 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "memfd F_ADD_SEALS: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Clear CLOEXEC so bwrap inherits the fd across exec.
    // SAFETY: fd is a valid memfd; F_GETFD reads the fd flags without side effects.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "fcntl F_GETFD: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: F_SETFD with a valid flags bitmask.
    let ret = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if ret < 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "fcntl clear CLOEXEC: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Release ownership — caller manages the fd lifetime.
    Ok(file.into_raw_fd())
}

/// Maximum config size (64 KiB). The sealed memfd cannot grow, but
/// defense-in-depth caps reads in case of fd injection with a large file.
const MAX_CONFIG_SIZE: u64 = 64 * 1024;

/// Read and deserialize the config from a sealed memfd.
///
/// Seeks to the start (the parent's write cursor may be at EOF),
/// reads up to [`MAX_CONFIG_SIZE`] bytes, and drops the file (closing the fd).
fn read_config_from_fd(fd: RawFd) -> Result<SandboxInitConfig, SandboxError> {
    use std::io::{Read, Seek};
    use std::os::fd::FromRawFd;

    // SAFETY: fd is a valid file descriptor passed by the parent via bwrap.
    // File takes ownership — fd is closed when this function returns.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };

    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|e| SandboxError::NamespaceSetup(format!("memfd seek: {e}")))?;

    let mut buf = Vec::new();
    file.take(MAX_CONFIG_SIZE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| SandboxError::NamespaceSetup(format!("memfd read: {e}")))?;
    // `file` (via `take`) dropped here → fd closed.

    if buf.len() as u64 > MAX_CONFIG_SIZE {
        return Err(SandboxError::NamespaceSetup(format!(
            "config exceeds {MAX_CONFIG_SIZE} byte limit ({} bytes read)",
            buf.len()
        )));
    }

    serde_json::from_slice(&buf)
        .map_err(|e| SandboxError::NamespaceSetup(format!("config deserialization: {e}")))
}

// Bwrap command construction

/// `/etc` entries agents need — not the full host `/etc`.
const ETC_ALLOWLIST: &[&str] = &[
    "/etc/alternatives",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
];

/// System runtime dirs that may or may not exist (split-usr vs merged-usr).
const SYSTEM_RO_BIND_TRY: &[&str] = &["/bin", "/lib", "/lib64", "/sbin"];

/// Build the bwrap command line.
///
/// The returned `Command` is ready to spawn. In root-assisted mode, it
/// is wrapped with `nsenter` to join the pre-configured network namespace.
/// Environment is set via `--clearenv` + `--setenv`; the shim command is
/// the final `--` arg.
pub(crate) fn build_bwrap_command(
    params: &SandboxLaunchParams,
    proxy_socket: &Path,
    config_fd: RawFd,
    latchgate_bin: &Path,
    env_args: &[(String, String)],
    mode: &BwrapMode,
) -> Command {
    let root_assisted = mode.netns_path.is_some();

    // Root-assisted: wrap bwrap under nsenter to join the parent-configured
    // network namespace. Rootless: run bwrap directly.
    let mut cmd = if let Some(ref netns) = mode.netns_path {
        let mut c = Command::new("nsenter");
        c.arg(format!("--net={netns}"));
        c.args(["--", "bwrap"]);
        c
    } else {
        Command::new("bwrap")
    };

    // ── Namespace isolation ──
    //
    // Network namespace: root-assisted mode joins the pre-configured netns
    // (no --unshare-net); rootless mode creates its own.
    cmd.args([
        "--unshare-user",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-ipc",
        "--unshare-cgroup",
    ]);
    if !root_assisted {
        cmd.arg("--unshare-net");
    }
    cmd.args(["--hostname", "sandbox"]);

    // ── Capabilities ──
    //
    // Root-assisted: lo is already up — zero added capabilities.
    // Rootless: shim needs CAP_NET_ADMIN transiently for loopback bring-up
    // (dropped via PR_CAPBSET_DROP + PR_CAP_AMBIENT_CLEAR_ALL before exec).
    if !root_assisted {
        cmd.args(["--cap-add", "CAP_NET_ADMIN"]);
    }

    // ── uid/gid mapping ──
    //
    // The agent runs as an unprivileged uid inside the sandbox — never 0.
    // Under sudo this preserves the real user's identity so /workspace
    // writes have correct ownership.
    cmd.args(["--uid", &mode.sandbox_uid.to_string()]);
    cmd.args(["--gid", &mode.sandbox_gid.to_string()]);

    // ── Process lifecycle ──
    cmd.arg("--die-with-parent");
    cmd.arg("--new-session");

    // ── Filesystem: workspace (read-write) ──
    let ws_str = params.workspace.to_string_lossy();
    cmd.args(["--bind", &ws_str, "/workspace"]);

    // ── Filesystem: system runtime (read-only) ──
    cmd.args(["--ro-bind", "/usr", "/usr"]);
    for path in SYSTEM_RO_BIND_TRY {
        cmd.args(["--ro-bind-try", path, path]);
    }

    // ── Filesystem: /etc (selective, read-only) ──
    for entry in ETC_ALLOWLIST {
        cmd.args(["--ro-bind-try", entry, entry]);
    }

    // ── Filesystem: /tmp, /proc, /dev ──
    cmd.args(["--tmpfs", "/tmp"]);
    cmd.args(["--proc", "/proc"]);
    cmd.args(["--dev", "/dev"]);

    // ── Filesystem: additional read-only mounts ──
    for mount in &params.ro_mounts {
        let mount_str = mount.to_string_lossy();
        cmd.args(["--ro-bind", &mount_str, &mount_str]);
    }

    // ── Gate + proxy sockets ──
    // Use --bind (not --ro-bind): connecting to a Unix-domain socket
    // requires MAY_WRITE at the VFS layer. A read-only mount causes
    // connect() to fail with EROFS.
    let gate_str = params.gate_socket.to_string_lossy();
    cmd.args(["--bind", &gate_str, "/run/latchgate/gate.sock"]);
    let proxy_str = proxy_socket.to_string_lossy();
    cmd.args(["--bind", &proxy_str, "/run/latchgate/proxy.sock"]);

    // ── Latchgate binary (for the shim) ──
    //
    // Mounted at /sandbox-bin — a dedicated path outside the read-only
    // /usr bind-mount. Mounting into /usr/bin would fail with EROFS
    // because /usr is already mounted read-only above.
    let bin_str = latchgate_bin.to_string_lossy();
    cmd.args(["--ro-bind", &bin_str, "/sandbox-bin/latchgate"]);

    // ── Environment ──
    cmd.arg("--clearenv");
    for (key, value) in env_args {
        cmd.args(["--setenv", key, value]);
    }

    // ── Shim command (must be after --) ──
    cmd.args(["--", "/sandbox-bin/latchgate", "sandbox-init"]);
    cmd.args(["--config-fd", &config_fd.to_string()]);

    cmd
}

/// Compute environment variables passed to bwrap via `--setenv`.
///
/// Proxy-dependent variables (`HTTPS_PROXY` and friends, `LATCHGATE_PROXY_TOKEN`,
/// `<ROUTE>_BASE_URL`) are intentionally *not* set here: the loopback
/// forwarder port is only known inside the shim, after the network
/// namespace exists. The shim sets those itself before exec'ing the agent.
/// User passthrough vars are applied first; sandbox-critical vars override.
pub(crate) fn build_env_args(
    params: &SandboxLaunchParams,
    env_snapshot: &[(String, String)],
) -> Vec<(String, String)> {
    let mut env = Vec::with_capacity(env_snapshot.len() + 4);

    // User passthrough first — sandbox-critical vars override below.
    env.extend_from_slice(env_snapshot);

    // Sandbox-critical (override any passthrough).
    env.push(("HOME".into(), "/workspace".into()));
    env.push((
        "LATCHGATE_URL".into(),
        "unix:///run/latchgate/gate.sock".into(),
    ));
    env.push((
        "PATH".into(),
        crate::hardening::build_sandbox_path(&params.ro_mounts),
    ));

    env
}

// Shim entry point

/// Verify that a memfd has the expected seals before trusting its contents.
///
/// Defends against fd injection: if the parent process is compromised or
/// the fd was swapped, the seals won't match and we refuse to proceed.
fn verify_seals(fd: RawFd) -> Result<(), SandboxError> {
    // SAFETY: fd is a valid file descriptor; F_GET_SEALS is read-only.
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "memfd F_GET_SEALS: {}",
            std::io::Error::last_os_error()
        )));
    }
    let expected = libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
    if seals & expected != expected {
        return Err(SandboxError::NamespaceSetup(format!(
            "memfd seal verification failed: expected 0x{expected:x}, got 0x{seals:x} — \
             refusing to trust config (possible fd injection)"
        )));
    }
    Ok(())
}

/// Entry point for `latchgate sandbox-init --config-fd <N>`.
///
/// Runs inside the bwrap sandbox. Verifies memfd seals, reads config,
/// applies post-namespace hardening (rlimits, Landlock, seccomp), then
/// execs the agent command.
///
/// This function does not return on success — `exec` replaces the process.
/// On failure, returns a [`SandboxError`] for the CLI to report.
///
/// # Preconditions
///
/// - Must be called from a single-threaded process (bwrap sandbox).
/// - `config_fd` must be a valid sealed memfd inherited from the parent.
pub fn run_sandbox_init(config_fd: RawFd) -> Result<(), SandboxError> {
    // Verify seals BEFORE reading — reject unsealed or tampered fds.
    verify_seals(config_fd)?;

    let config = read_config_from_fd(config_fd)?;
    // fd is now closed (File dropped in read_config_from_fd).

    // chdir to workspace.
    // SAFETY: "/workspace" is a valid NUL-terminated C literal.
    if unsafe { libc::chdir(c"/workspace".as_ptr()) } != 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "chdir(/workspace): {}",
            std::io::Error::last_os_error()
        )));
    }

    // Build a SandboxLaunchParams for the hardening functions.
    // Only workspace, ro_mounts, and command are used by the shim.
    let params = SandboxLaunchParams {
        workspace: std::path::PathBuf::from(&config.workspace),
        ro_mounts: config
            .ro_mounts
            .iter()
            .map(std::path::PathBuf::from)
            .collect(),
        command: config.command.clone(),
        allow_hosts: Vec::new(),
        pass_env: Vec::new(),
        gate_socket: std::path::PathBuf::from("/run/latchgate/gate.sock"),
        credentials: std::collections::HashMap::new(),
        sandbox_uid: None,
        sandbox_gid: None,
    };

    // Bring up loopback and start the TCP→Unix forwarder while we still
    // hold CAP_NET_ADMIN (bwrap granted it via --cap-add). spawn() forks a
    // dedicated forwarder process and returns the bound loopback port.
    let proxy_port =
        crate::loopback_forward::spawn(std::path::Path::new("/run/latchgate/proxy.sock"))?;

    // Set proxy-dependent environment now that the port is known. These are
    // inherited across the upcoming execve into the agent.
    let proxy_url = format!("http://127.0.0.1:{proxy_port}");
    // SAFETY: the shim is single-threaded here — no concurrent getenv.
    unsafe {
        std::env::set_var("HTTPS_PROXY", &proxy_url);
        std::env::set_var("https_proxy", &proxy_url);
        std::env::set_var("HTTP_PROXY", &proxy_url);
        std::env::set_var("http_proxy", &proxy_url);
        if let Some(token) = &config.proxy_token {
            std::env::set_var("LATCHGATE_PROXY_TOKEN", token);
        }
        for route in &config.credential_routes {
            let var = format!("{}_BASE_URL", route.to_uppercase());
            std::env::set_var(var, format!("{proxy_url}/{route}"));
        }
    }

    // Drop CAP_NET_ADMIN (and any residual capabilities) now that loopback
    // is up — the agent must not inherit it. Done before the hardening
    // sequence so the agent runs fully unprivileged.
    crate::hardening::drop_capabilities()?;

    // PR_SET_NO_NEW_PRIVS — required before Landlock and seccomp.
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS) only restricts the process further.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "prctl(PR_SET_NO_NEW_PRIVS): {}",
            std::io::Error::last_os_error()
        )));
    }

    // Apply hardening in order: rlimits → Landlock → seccomp → exec.

    crate::hardening::apply_rlimits()?;

    if config.landlock_abi > 0 {
        crate::landlock::apply(&params, proxy_port)?;
    }

    crate::seccomp::apply()?;

    // exec does not return on success.
    crate::hardening::exec_command(&params)
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> SandboxLaunchParams {
        SandboxLaunchParams {
            workspace: std::path::PathBuf::from("/home/user/project"),
            allow_hosts: vec![],
            ro_mounts: vec![],
            pass_env: vec![],
            gate_socket: std::path::PathBuf::from("/tmp/gate.sock"),
            command: vec!["agent".into()],
            credentials: std::collections::HashMap::new(),
            sandbox_uid: None,
            sandbox_gid: None,
        }
    }

    /// Default mode for existing tests — rootless (no parent-assisted netns).
    fn test_mode() -> BwrapMode {
        BwrapMode {
            netns_path: None,
            sandbox_uid: 1000,
            sandbox_gid: 1000,
        }
    }

    // -- Config serialization -----------------------------------------------

    #[test]
    fn config_round_trip() {
        let config = SandboxInitConfig {
            workspace: "/workspace".to_string(),
            ro_mounts: vec!["/opt/tools".to_string(), "/opt/data".to_string()],
            command: vec![
                "/usr/bin/agent".to_string(),
                "--flag".to_string(),
                "value with spaces".to_string(),
            ],
            landlock_abi: 4,
            credential_routes: Vec::new(),
            proxy_token: None,
        };

        let json = serde_json::to_vec(&config).unwrap();
        let deserialized: SandboxInitConfig = serde_json::from_slice(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn config_round_trip_no_landlock() {
        let config = SandboxInitConfig {
            workspace: "/workspace".to_string(),
            ro_mounts: vec![],
            command: vec!["/bin/sh".to_string()],
            landlock_abi: 0,
            credential_routes: Vec::new(),
            proxy_token: None,
        };

        let json = serde_json::to_vec(&config).unwrap();
        let deserialized: SandboxInitConfig = serde_json::from_slice(&json).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn config_deserialization_rejects_malformed_json() {
        use std::io::Write;
        use std::os::fd::{FromRawFd, IntoRawFd};

        let name = CString::new("test-malformed").unwrap();
        // SAFETY: memfd_create with valid name.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        assert!(fd >= 0);

        // SAFETY: valid fd.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(b"not json at all {{{{").unwrap();
        let raw = file.into_raw_fd();

        let result = read_config_from_fd(raw);
        assert!(result.is_err(), "malformed JSON must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("deserialization"),
            "error must mention deserialization: {msg}"
        );
    }

    #[test]
    fn config_deserialization_rejects_missing_fields() {
        use std::io::Write;
        use std::os::fd::{FromRawFd, IntoRawFd};

        let name = CString::new("test-missing-fields").unwrap();
        // SAFETY: memfd_create with valid name.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        assert!(fd >= 0);

        // Valid JSON but missing required `command` field.
        // SAFETY: valid fd.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(br#"{"workspace":"/workspace","ro_mounts":[],"landlock_abi":1}"#)
            .unwrap();
        let raw = file.into_raw_fd();

        let result = read_config_from_fd(raw);
        assert!(result.is_err(), "missing fields must be rejected");
    }

    #[test]
    fn config_size_limit_enforced() {
        use std::io::Write;
        use std::os::fd::{FromRawFd, IntoRawFd};

        let name = CString::new("test-oversized").unwrap();
        // SAFETY: memfd_create with valid name.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
        assert!(fd >= 0);

        // Write > MAX_CONFIG_SIZE bytes.
        // SAFETY: valid fd.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let oversized = vec![b'A'; (MAX_CONFIG_SIZE as usize) + 1];
        file.write_all(&oversized).unwrap();
        let raw = file.into_raw_fd();

        let result = read_config_from_fd(raw);
        assert!(result.is_err(), "oversized config must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("limit"), "error must mention limit: {msg}");
    }

    // -- Memfd sealing ------------------------------------------------------

    #[test]
    fn memfd_sealed_config_round_trip() {
        let config = SandboxInitConfig {
            workspace: "/workspace".to_string(),
            ro_mounts: vec!["/opt/tools".to_string()],
            command: vec!["/usr/bin/agent".to_string(), "--verbose".to_string()],
            landlock_abi: 3,
            credential_routes: Vec::new(),
            proxy_token: None,
        };

        let fd = create_sealed_memfd(&config).unwrap();
        verify_seals(fd).expect("seals must be valid on freshly created memfd");

        let recovered = read_config_from_fd(fd).unwrap();
        assert_eq!(config, recovered);
    }

    #[test]
    fn memfd_write_after_seal_rejected() {
        let config = SandboxInitConfig {
            workspace: "/workspace".to_string(),
            ro_mounts: vec![],
            command: vec!["/bin/sh".to_string()],
            landlock_abi: 0,
            credential_routes: Vec::new(),
            proxy_token: None,
        };

        let fd = create_sealed_memfd(&config).unwrap();

        let buf = b"tampered";
        // SAFETY: fd is a valid sealed memfd; write is expected to fail.
        let ret = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        assert_eq!(ret, -1, "write to sealed memfd must fail");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM),
            "sealed memfd write must return EPERM"
        );

        // SAFETY: fd still valid (write failed).
        unsafe { libc::close(fd) };
    }

    #[test]
    fn verify_seals_rejects_unsealed_fd() {
        use std::io::Write;
        use std::os::fd::{FromRawFd, IntoRawFd};

        let name = CString::new("test-unsealed").unwrap();
        // SAFETY: memfd_create with valid name and MFD_ALLOW_SEALING.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
        assert!(fd >= 0);

        // SAFETY: fd is valid.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(b"test").unwrap();
        let raw = file.into_raw_fd();

        let result = verify_seals(raw);
        assert!(result.is_err(), "unsealed memfd must be rejected");

        // SAFETY: raw is valid.
        unsafe { libc::close(raw) };
    }

    #[test]
    fn verify_seals_rejects_partial_seals() {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

        let name = CString::new("test-partial-seal").unwrap();
        // SAFETY: memfd_create with valid name and MFD_ALLOW_SEALING.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
        assert!(fd >= 0);

        // SAFETY: fd is valid.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        file.write_all(b"test").unwrap();

        // Apply only WRITE seal — missing SHRINK, GROW, SEAL.
        // SAFETY: fd is a valid memfd with MFD_ALLOW_SEALING.
        let ret = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, libc::F_SEAL_WRITE) };
        assert!(ret >= 0, "partial seal must succeed");
        let raw = file.into_raw_fd();

        let result = verify_seals(raw);
        assert!(result.is_err(), "partial seals must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("seal verification failed"),
            "error must describe seal mismatch: {msg}"
        );

        // SAFETY: raw is valid.
        unsafe { libc::close(raw) };
    }

    #[test]
    fn owned_fd_closes_on_drop() {
        use std::os::fd::{FromRawFd, OwnedFd};

        let config = SandboxInitConfig {
            workspace: "/workspace".to_string(),
            ro_mounts: vec![],
            command: vec!["/bin/sh".to_string()],
            landlock_abi: 0,
            credential_routes: Vec::new(),
            proxy_token: None,
        };

        let fd = create_sealed_memfd(&config).unwrap();

        // Verify fd is open.
        // SAFETY: F_GETFD on a valid fd is a read-only query with no side effects.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "fd must be open");

        // Wrap in OwnedFd and drop.
        // SAFETY: fd is valid.
        drop(unsafe { OwnedFd::from_raw_fd(fd) });

        // Verify fd is closed — F_GETFD returns -1 with EBADF.
        // SAFETY: probing a closed fd is safe; kernel returns EBADF.
        let ret = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_eq!(ret, -1, "fd must be closed after OwnedFd drop");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF),
            "closed fd must return EBADF"
        );
    }

    // -- Bwrap command construction -----------------------------------------

    #[test]
    fn bwrap_command_contains_all_namespace_flags() {
        let params = test_params();
        let env = vec![("HOME".into(), "/workspace".into())];
        let cmd = build_bwrap_command(
            &params,
            Path::new("/tmp/proxy.sock"),
            3,
            Path::new("/usr/bin/latchgate"),
            &env,
            &test_mode(),
        );

        let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy()).collect();
        let joined = args.join(" ");

        for flag in [
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-uts",
            "--unshare-ipc",
            "--unshare-cgroup",
        ] {
            assert!(args.iter().any(|a| a == flag), "{flag} missing");
        }

        assert!(joined.contains("--die-with-parent"));
        assert!(joined.contains("--new-session"));
        assert!(joined.contains("--clearenv"));
        assert!(joined.contains("--hostname sandbox"));
        assert!(
            joined.contains("--cap-add CAP_NET_ADMIN"),
            "shim needs CAP_NET_ADMIN to bring up loopback"
        );
    }

    #[test]
    fn bwrap_command_mounts_workspace_rw() {
        let params = test_params();
        let cmd = build_bwrap_command(
            &params,
            Path::new("/tmp/proxy.sock"),
            3,
            Path::new("/usr/bin/latchgate"),
            &[],
            &test_mode(),
        );

        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let has_rw_bind = args
            .windows(3)
            .any(|w| w[0] == "--bind" && w[1] == "/home/user/project" && w[2] == "/workspace");
        assert!(has_rw_bind, "workspace must be --bind (rw) to /workspace");
    }

    #[test]
    fn bwrap_command_mounts_sockets() {
        let params = test_params();
        let cmd = build_bwrap_command(
            &params,
            Path::new("/tmp/proxy.sock"),
            3,
            Path::new("/usr/bin/latchgate"),
            &[],
            &test_mode(),
        );

        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let joined = args.join(" ");
        assert!(joined.contains("/run/latchgate/gate.sock"));
        assert!(joined.contains("/run/latchgate/proxy.sock"));
    }

    #[test]
    fn bwrap_command_includes_ro_mounts() {
        let mut params = test_params();
        params.ro_mounts = vec![
            std::path::PathBuf::from("/opt/tools"),
            std::path::PathBuf::from("/opt/data"),
        ];

        let cmd = build_bwrap_command(
            &params,
            Path::new("/tmp/proxy.sock"),
            3,
            Path::new("/usr/bin/latchgate"),
            &[],
            &test_mode(),
        );

        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let joined = args.join(" ");
        assert!(joined.contains("--ro-bind /opt/tools /opt/tools"));
        assert!(joined.contains("--ro-bind /opt/data /opt/data"));
    }

    #[test]
    fn bwrap_command_ends_with_shim() {
        let params = test_params();
        let cmd = build_bwrap_command(
            &params,
            Path::new("/tmp/proxy.sock"),
            3,
            Path::new("/usr/bin/latchgate"),
            &[],
            &test_mode(),
        );

        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let len = args.len();
        assert!(len >= 5);
        assert_eq!(args[len - 5], "--");
        assert_eq!(args[len - 4], "/sandbox-bin/latchgate");
        assert_eq!(args[len - 3], "sandbox-init");
        assert_eq!(args[len - 2], "--config-fd");
        assert_eq!(args[len - 1], "3");
    }

    #[test]
    fn bwrap_binary_mount_is_outside_usr() {
        // /usr is mounted read-only. A bind-mount INTO /usr would fail
        // with EROFS. The shim binary must land at a non-overlapping path.
        let params = test_params();
        let cmd = build_bwrap_command(
            &params,
            Path::new("/tmp/proxy.sock"),
            3,
            Path::new("/usr/bin/latchgate"),
            &[],
            &test_mode(),
        );

        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        // Find the ro-bind triple for the latchgate binary.
        let bind_target = args
            .windows(3)
            .find(|w| w[0] == "--ro-bind" && w[1] == "/usr/bin/latchgate")
            .map(|w| w[2].clone());

        assert_eq!(
            bind_target.as_deref(),
            Some("/sandbox-bin/latchgate"),
            "shim binary must mount outside /usr"
        );
    }

    #[test]
    fn bwrap_command_handles_paths_with_spaces() {
        let mut params = test_params();
        params.workspace = std::path::PathBuf::from("/home/user/my project");
        params.gate_socket = std::path::PathBuf::from("/tmp/my gate/gate.sock");

        let cmd = build_bwrap_command(
            &params,
            Path::new("/tmp/my proxy/proxy.sock"),
            5,
            Path::new("/usr/bin/latchgate"),
            &[],
            &test_mode(),
        );

        // Paths with spaces must appear as discrete args, not shell-split.
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.iter().any(|a| a == "/home/user/my project"),
            "workspace path with space must be a single arg"
        );
        assert!(
            args.iter().any(|a| a == "/tmp/my proxy/proxy.sock"),
            "proxy path with space must be a single arg"
        );
    }

    // -- Environment computation --------------------------------------------

    #[test]
    fn env_args_critical_vars_always_last() {
        let params = test_params();

        // Adversarial passthrough: every sandbox-critical var set to attacker values.
        let snapshot = vec![
            ("HOME".into(), "/home/attacker".into()),
            ("LATCHGATE_URL".into(), "http://evil.com".into()),
            ("PATH".into(), "/tmp/evil".into()),
        ];
        let env = build_env_args(&params, &snapshot);

        // For each critical var, the LAST occurrence must be the sandbox value.
        // bwrap processes --setenv sequentially; last write wins.
        let last = |key: &str| env.iter().rfind(|(k, _)| k == key).map(|(_, v)| v.as_str());

        assert_eq!(last("HOME"), Some("/workspace"));
        assert_eq!(
            last("LATCHGATE_URL"),
            Some("unix:///run/latchgate/gate.sock")
        );
        assert!(
            last("PATH").unwrap().starts_with("/usr/local/sbin"),
            "PATH must be the sandbox PATH, not attacker's"
        );
    }

    #[test]
    fn env_args_omit_proxy_vars() {
        // Proxy env is materialized by the shim once the loopback forwarder
        // port is known — build_env_args must NOT set it (the port is
        // unknown at this stage). Crucially, an attacker-supplied HTTPS_PROXY
        // in the snapshot must not survive as a usable value: the shim
        // overwrites it post-fork. Here we assert build_env_args adds none.
        let params = test_params();
        let env = build_env_args(&params, &[]);

        for key in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            assert!(
                !env.iter().any(|(k, _)| k == key),
                "{key} must not be set by build_env_args (shim sets it)"
            );
        }
        assert!(
            !env.iter().any(|(k, _)| k == "LATCHGATE_PROXY_TOKEN"),
            "proxy token must not be set by build_env_args (shim sets it)"
        );
    }

    #[test]
    fn env_args_no_api_key_leak() {
        let params = test_params();
        let snapshot = vec![
            ("ANTHROPIC_API_KEY".into(), "sk-secret".into()),
            ("OPENAI_API_KEY".into(), "sk-secret2".into()),
        ];
        let env = build_env_args(&params, &snapshot);

        // build_env_args must not inject secrets beyond what was in the snapshot.
        let has_key = env.iter().any(|(k, v)| {
            !snapshot.iter().any(|(sk, sv)| sk == k && sv == v) && v.contains("sk-secret")
        });
        assert!(
            !has_key,
            "API key must not leak through build_env_args itself"
        );
    }

    // -- Root-assisted vs rootless mode ----------------------------------------

    #[test]
    fn root_mode_wraps_with_nsenter_and_omits_net_cap() {
        let params = test_params();
        let mode = BwrapMode {
            netns_path: Some("/proc/42/ns/net".to_string()),
            sandbox_uid: 1000,
            sandbox_gid: 1000,
        };
        let cmd = build_bwrap_command(
            &params,
            Path::new("/tmp/proxy.sock"),
            3,
            Path::new("/usr/bin/latchgate"),
            &[],
            &mode,
        );

        assert_eq!(
            cmd.get_program().to_string_lossy(),
            "nsenter",
            "root mode must use nsenter"
        );

        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        assert!(
            args.iter().any(|a| a == "--net=/proc/42/ns/net"),
            "must pass netns path to nsenter"
        );
        assert!(
            args.iter().any(|a| a == "bwrap"),
            "bwrap must appear as arg to nsenter"
        );
        assert!(
            !args.iter().any(|a| a == "--unshare-net"),
            "root mode must not have --unshare-net"
        );
        assert!(
            !args.iter().any(|a| a == "CAP_NET_ADMIN"),
            "root mode must not add CAP_NET_ADMIN"
        );
    }

    #[test]
    fn rootless_mode_uses_bwrap_directly_with_net_cap() {
        let params = test_params();
        let mode = BwrapMode {
            netns_path: None,
            sandbox_uid: 1000,
            sandbox_gid: 1000,
        };
        let cmd = build_bwrap_command(
            &params,
            Path::new("/tmp/proxy.sock"),
            3,
            Path::new("/usr/bin/latchgate"),
            &[],
            &mode,
        );

        assert_eq!(
            cmd.get_program().to_string_lossy(),
            "bwrap",
            "rootless mode must invoke bwrap directly"
        );

        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let joined = args.join(" ");

        assert!(args.iter().any(|a| a == "--unshare-net"));
        assert!(joined.contains("--cap-add CAP_NET_ADMIN"));
    }

    #[test]
    fn both_modes_always_set_uid_gid() {
        for netns in [None, Some("/proc/1/ns/net".to_string())] {
            let mode = BwrapMode {
                netns_path: netns.clone(),
                sandbox_uid: 1234,
                sandbox_gid: 5678,
            };
            let cmd = build_bwrap_command(
                &test_params(),
                Path::new("/tmp/proxy.sock"),
                3,
                Path::new("/usr/bin/latchgate"),
                &[],
                &mode,
            );

            let args: Vec<_> = cmd
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let joined = args.join(" ");

            assert!(
                joined.contains("--uid 1234"),
                "must set --uid in mode {netns:?}"
            );
            assert!(
                joined.contains("--gid 5678"),
                "must set --gid in mode {netns:?}"
            );
        }
    }

    // -- uid/gid resolution ----------------------------------------------------

    #[test]
    fn uid_sudo_uid_takes_precedence() {
        let (uid, gid) = resolve_uid_gid_inner(
            Some("1000".into()),
            Some("1000".into()),
            None,
            None,
            Path::new("/tmp"),
        );
        assert_eq!((uid, gid), (1000, 1000));
    }

    #[test]
    fn uid_sudo_uid_zero_falls_through() {
        let (uid, _) = resolve_uid_gid_inner(
            Some("0".into()),
            Some("0".into()),
            None,
            None,
            Path::new("/nonexistent"),
        );
        assert_ne!(uid, 0, "uid must never be 0");
    }

    #[test]
    fn uid_sudo_gid_absent_defaults_to_uid() {
        let (uid, gid) =
            resolve_uid_gid_inner(Some("1000".into()), None, None, None, Path::new("/tmp"));
        assert_eq!(uid, 1000);
        assert_eq!(gid, 1000);
    }

    #[test]
    fn uid_sudo_gid_zero_defaults_to_uid() {
        let (uid, gid) = resolve_uid_gid_inner(
            Some("1000".into()),
            Some("0".into()),
            None,
            None,
            Path::new("/tmp"),
        );
        assert_eq!(uid, 1000);
        assert_eq!(gid, 1000, "gid 0 must fall back to uid");
    }

    #[test]
    fn uid_no_sudo_uses_workspace_owner() {
        let dir = tempfile::tempdir().unwrap();
        let (uid, _) = resolve_uid_gid_inner(None, None, None, None, dir.path());
        // SAFETY: getuid() is a read-only syscall with no side effects.
        let expected = unsafe { libc::getuid() } as u32;
        if expected != 0 {
            assert_eq!(uid, expected, "must use workspace owner");
        }
    }

    #[test]
    fn uid_nonexistent_workspace_falls_to_nobody() {
        let (uid, gid) = resolve_uid_gid_inner(
            None,
            None,
            None,
            None,
            Path::new("/nonexistent/path/does/not/exist"),
        );
        assert_eq!((uid, gid), (65534, 65534));
    }

    #[test]
    fn uid_root_owned_workspace_falls_to_nobody() {
        // / is root-owned on every system
        let (uid, _) = resolve_uid_gid_inner(None, None, None, None, Path::new("/"));
        assert_ne!(uid, 0, "uid must never be 0");
        assert_eq!(uid, 65534);
    }

    #[test]
    fn uid_invalid_sudo_uid_falls_through() {
        let (uid, _) = resolve_uid_gid_inner(
            Some("notanumber".into()),
            None,
            None,
            None,
            Path::new("/nonexistent"),
        );
        assert_eq!(uid, 65534, "invalid SUDO_UID must fall through to nobody");
    }

    // --- Configured uid/gid tier ---

    #[test]
    fn uid_configured_takes_precedence_over_workspace() {
        // configured uid/gid should win over workspace owner
        let dir = tempfile::tempdir().unwrap();
        let (uid, gid) = resolve_uid_gid_inner(None, None, Some(2000), Some(2001), dir.path());
        assert_eq!(uid, 2000);
        assert_eq!(gid, 2001);
    }

    #[test]
    fn uid_configured_gid_defaults_to_uid() {
        let (uid, gid) =
            resolve_uid_gid_inner(None, None, Some(3000), None, Path::new("/nonexistent"));
        assert_eq!(uid, 3000);
        assert_eq!(
            gid, 3000,
            "configured gid absent must default to configured uid"
        );
    }

    #[test]
    fn uid_sudo_beats_configured() {
        // SUDO_UID has highest precedence
        let (uid, gid) = resolve_uid_gid_inner(
            Some("1000".into()),
            Some("1000".into()),
            Some(2000),
            Some(2000),
            Path::new("/tmp"),
        );
        assert_eq!((uid, gid), (1000, 1000), "SUDO_UID must beat configured");
    }

    #[test]
    fn uid_configured_zero_falls_through() {
        // configured uid 0 must be rejected (defense-in-depth)
        let dir = tempfile::tempdir().unwrap();
        let (uid, _) = resolve_uid_gid_inner(None, None, Some(0), None, dir.path());
        assert_ne!(uid, 0, "configured uid 0 must fall through");
    }

    #[test]
    fn uid_configured_gid_zero_defaults_to_uid() {
        let (uid, gid) =
            resolve_uid_gid_inner(None, None, Some(4000), Some(0), Path::new("/nonexistent"));
        assert_eq!(uid, 4000);
        assert_eq!(gid, 4000, "configured gid 0 must default to configured uid");
    }
}
