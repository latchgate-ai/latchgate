//! Integration tests for sandbox launch and proxy enforcement.
//!
//! Each sandbox test forks real Linux namespaces with `/bin/sh` inside.
//! Requires Linux with unprivileged user namespaces — gracefully skipped
//! on hosts without support.
//!
//! All sandbox launches are bounded by [`LAUNCH_TIMEOUT`]. If a sandboxed
//! process hangs (e.g. `mount` blocks in a restricted namespace), the test
//! fails with a clear timeout error instead of blocking the test runner.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use crate::{AgentSandboxConfig, SandboxError, SandboxLaunchParams};

/// Maximum wall-clock time for a single sandbox launch. Sandbox operations
/// normally complete in <1 s; 15 s is generous enough for slow CI hosts
/// while still detecting genuine hangs before the test runner's 60 s warning.
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(15);

/// Overall budget for the concurrent launch stress test.
///
/// Namespace creation (`clone(CLONE_NEWUSER)`) is kernel-serialized, bwrap
/// mount setup is I/O-bound, and each sandbox starts a proxy listener.
/// Under CI load, concurrent sandboxes contend for these resources.
/// The budget covers the whole batch — a genuine deadlock is caught, but
/// transient CI slowness on individual sandboxes is tolerated.
const CONCURRENT_BATCH_TIMEOUT: Duration = Duration::from_secs(90);

/// Tokio runtime wrapper that guarantees `shutdown_timeout` on drop —
/// including during panic unwind.
///
/// Without this, `Runtime::drop` blocks indefinitely when a
/// `spawn_blocking` task is stuck in a blocking syscall (e.g. `waitpid`).
/// `tokio::time::timeout` fires (completing the future), but the runtime
/// destructor waits for the orphaned thread. This wrapper replaces the
/// default destructor with `shutdown_timeout(5s)`, which abandons stuck
/// threads after the deadline.
struct ScopedRuntime(Option<tokio::runtime::Runtime>);

impl ScopedRuntime {
    fn new() -> Self {
        Self(Some(tokio::runtime::Runtime::new().unwrap()))
    }

    fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        self.0.as_ref().unwrap().block_on(f)
    }
}

impl Drop for ScopedRuntime {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_timeout(Duration::from_secs(5));
        }
    }
}

// Harness

/// Returns `true` when the sandbox tests should be skipped.
///
/// All sandbox launches use bubblewrap. The probe runs **once per
/// process** and the result is cached. Goes beyond
/// [`crate::platform::is_bwrap_available`] (which tests `--unshare-user`
/// only) by exercising the full namespace flag set. This catches hosts
/// that allow user-namespace creation but block PID, network, or IPC
/// namespaces (nested containers, AppArmor, restrictive seccomp).
fn should_skip() -> bool {
    static CAN_SANDBOX: OnceLock<bool> = OnceLock::new();
    !*CAN_SANDBOX.get_or_init(|| {
        if !crate::platform::is_bwrap_available() {
            eprintln!("SKIP sandbox tests: bwrap not available");
            return false;
        }
        probe_bwrap_full()
    })
}

/// Launch `/bin/sh -c <script>` in a sandbox with a fresh workspace.
fn sandbox_sh(script: &str) -> Result<i32, SandboxError> {
    let workspace = tempfile::tempdir().unwrap();
    sandbox_sh_with(script, &workspace)
}

/// Launch a sandbox and return the exit code, workspace path, and the
/// `TempDir` that owns the workspace. The caller must keep the `TempDir`
/// alive while reading output files from the workspace.
fn sandbox_sh_with_workspace(
    script: &str,
) -> Result<(i32, PathBuf, tempfile::TempDir), SandboxError> {
    let workspace = tempfile::tempdir().unwrap();
    let ws_path = workspace.path().to_path_buf();
    let code = sandbox_sh_with(script, &workspace)?;
    Ok((code, ws_path, workspace))
}

fn sandbox_sh_with(script: &str, workspace: &tempfile::TempDir) -> Result<i32, SandboxError> {
    let gate_dir = tempfile::tempdir().unwrap();
    let gate_sock = gate_dir.path().join("gate.sock");
    std::fs::write(&gate_sock, "").unwrap();

    let config = AgentSandboxConfig {
        workspace: Some(workspace.path().to_path_buf()),
        gate_socket: gate_sock,
        allow_hosts: vec!["api.anthropic.com".into()],
        pass_env: vec![],
        ro_mounts: vec![],
        credentials: std::collections::HashMap::new(),
        sandbox_uid: None,
        sandbox_gid: None,
    };

    let params =
        SandboxLaunchParams::resolve(&config, vec!["/bin/sh".into(), "-c".into(), script.into()])?;

    let rt = ScopedRuntime::new();
    let result = rt.block_on(async {
        tokio::time::timeout(LAUNCH_TIMEOUT, crate::launch(params))
            .await
            .map_err(|_| {
                SandboxError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "sandbox launch timed out after {}s",
                        LAUNCH_TIMEOUT.as_secs()
                    ),
                ))
            })?
            .map(|r| r.exit_code)
    });

    result
}

// Mount visibility

#[test]
fn only_expected_paths_at_root() {
    if should_skip() {
        return;
    }
    let (code, ws, _dir) = sandbox_sh_with_workspace("ls -1 / > /workspace/.out").unwrap();
    assert_eq!(code, 0);

    let output = std::fs::read_to_string(ws.join(".out")).unwrap();
    let entries: Vec<&str> = output.lines().collect();

    for expected in &["workspace", "usr", "dev", "tmp", "etc", "run", "proc"] {
        assert!(entries.contains(expected), "missing /{expected}");
    }

    for forbidden in &["home", "root", "sys", "boot", "media", "srv", "var"] {
        assert!(
            !entries.contains(forbidden),
            "/{forbidden} should not exist in sandbox"
        );
    }
}

#[test]
fn host_sensitive_files_absent() {
    if should_skip() {
        return;
    }
    let code = sandbox_sh(
        "! test -e /etc/shadow && ! test -e /etc/ssh && ! test -d /home && ! test -d /root",
    )
    .unwrap();
    assert_eq!(code, 0, "sensitive host paths must not exist in sandbox");
}

// Filesystem permissions

#[test]
fn workspace_is_writable() {
    if should_skip() {
        return;
    }
    let code = sandbox_sh("echo ok > /workspace/test_write && cat /workspace/test_write").unwrap();
    assert_eq!(code, 0);
}

#[test]
fn workspace_rejects_device_creation() {
    if should_skip() {
        return;
    }
    // MS_NODEV on workspace prevents device node interpretation.
    // mknod is also blocked by seccomp and user namespace, but the mount
    // flag is an independent enforcement layer.
    let code = sandbox_sh("mknod /workspace/test_dev c 1 3 2>/dev/null").unwrap();
    assert_ne!(code, 0, "device creation in workspace must fail");
}

#[test]
fn runtime_is_readonly() {
    if should_skip() {
        return;
    }
    let code = sandbox_sh("touch /usr/test_write 2>/dev/null").unwrap();
    assert_ne!(code, 0, "/usr must be read-only");
}

#[test]
fn tmp_is_writable() {
    if should_skip() {
        return;
    }
    let code = sandbox_sh("echo ok > /tmp/test_write").unwrap();
    assert_eq!(code, 0);
}

// Synthetic /etc

#[test]
fn hostname_is_sandbox() {
    if should_skip() {
        return;
    }
    // UTS namespace must isolate the hostname. bwrap sets it via
    // --hostname; verify via the hostname(1) command.
    let (code, ws, _dir) = sandbox_sh_with_workspace("hostname > /workspace/.out 2>&1").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    assert_eq!(content.trim(), "sandbox");
}

#[test]
fn no_dns_resolver_configured() {
    if should_skip() {
        return;
    }
    // The sandbox must not have a functional DNS resolver — the proxy
    // resolves DNS on the host side. Verify /etc/resolv.conf is absent
    // or contains no nameserver directives.
    let (code, ws, _dir) = sandbox_sh_with_workspace(
        "grep -c '^nameserver' /etc/resolv.conf 2>/dev/null > /workspace/.out; true",
    )
    .unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    let nameservers: u64 = content.trim().parse().unwrap_or(0);
    assert_eq!(
        nameservers, 0,
        "no nameserver directives should exist in sandbox"
    );
}

#[test]
fn etc_group_exists() {
    if should_skip() {
        return;
    }
    let (code, ws, _dir) = sandbox_sh_with_workspace("cat /etc/group > /workspace/.out").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    assert!(
        content.contains("root:x:0:"),
        "/etc/group must contain root group"
    );
}

// Device nodes

#[test]
fn dev_null_is_functional() {
    if should_skip() {
        return;
    }
    let code = sandbox_sh("echo discard > /dev/null").unwrap();
    assert_eq!(code, 0);
}

#[test]
fn dev_null_reads_empty() {
    if should_skip() {
        return;
    }
    let (code, ws, _dir) =
        sandbox_sh_with_workspace("wc -c < /dev/null > /workspace/.out").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    assert_eq!(content.trim(), "0");
}

#[test]
fn dev_urandom_produces_bytes() {
    if should_skip() {
        return;
    }
    let (code, ws, _dir) =
        sandbox_sh_with_workspace("head -c 16 /dev/urandom | wc -c > /workspace/.out").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    assert_eq!(content.trim(), "16");
}

#[test]
fn dev_urandom_accepts_writes() {
    if should_skip() {
        return;
    }
    // Linux's urandom driver accepts writes (feeds entropy pool).
    // This is by design and harmless — no security value in blocking it.
    let code = sandbox_sh("echo entropy > /dev/urandom").unwrap();
    assert_eq!(code, 0);
}

#[test]
fn dev_zero_is_writable() {
    if should_skip() {
        return;
    }
    let code = sandbox_sh("echo test > /dev/zero").unwrap();
    assert_eq!(code, 0, "/dev/zero must accept writes");
}

// Environment

#[test]
fn environment_is_clean() {
    if should_skip() {
        return;
    }
    let (code, ws, _dir) = sandbox_sh_with_workspace("env > /workspace/.out").unwrap();
    assert_eq!(code, 0);

    let output = std::fs::read_to_string(ws.join(".out")).unwrap();
    let env: std::collections::HashMap<&str, &str> =
        output.lines().filter_map(|l| l.split_once('=')).collect();

    assert_eq!(env.get("HOME"), Some(&"/workspace"));
    assert!(env.contains_key("PATH"));
    assert!(env.contains_key("LATCHGATE_URL"));
    assert!(env.contains_key("HTTPS_PROXY"));
    assert!(env.contains_key("HTTP_PROXY"));

    for leaked in &["USER", "SHELL", "LOGNAME"] {
        assert!(
            !env.contains_key(leaked),
            "{leaked} should not be in sandbox env"
        );
    }
}

#[test]
fn pass_env_is_forwarded() {
    if should_skip() {
        return;
    }
    std::env::set_var("LATCHGATE_TEST_MARKER", "sandbox_test_value");

    let workspace = tempfile::tempdir().unwrap();
    let gate_dir = tempfile::tempdir().unwrap();
    let gate_sock = gate_dir.path().join("gate.sock");
    std::fs::write(&gate_sock, "").unwrap();

    let config = AgentSandboxConfig {
        workspace: Some(workspace.path().to_path_buf()),
        gate_socket: gate_sock,
        allow_hosts: vec![],
        pass_env: vec!["LATCHGATE_TEST_MARKER".into()],
        ro_mounts: vec![],
        credentials: std::collections::HashMap::new(),
        sandbox_uid: None,
        sandbox_gid: None,
    };
    let params = SandboxLaunchParams::resolve(
        &config,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "echo $LATCHGATE_TEST_MARKER > /workspace/.out".into(),
        ],
    )
    .unwrap();

    let rt = ScopedRuntime::new();
    let result =
        rt.block_on(async { tokio::time::timeout(LAUNCH_TIMEOUT, crate::launch(params)).await });
    let code = result.expect("sandbox launch timed out").unwrap().exit_code;

    assert_eq!(code, 0);
    let val = std::fs::read_to_string(workspace.path().join(".out")).unwrap();
    assert_eq!(val.trim(), "sandbox_test_value");
}

// Exit code propagation

#[test]
fn exit_code_zero() {
    if should_skip() {
        return;
    }
    assert_eq!(sandbox_sh("true").unwrap(), 0);
}

#[test]
fn exit_code_nonzero() {
    if should_skip() {
        return;
    }
    assert_eq!(sandbox_sh("exit 42").unwrap(), 42);
}

#[test]
fn exit_code_from_failed_command() {
    if should_skip() {
        return;
    }
    let code = sandbox_sh("cat /nonexistent/file").unwrap();
    assert_ne!(code, 0);
}

// Gate socket

#[test]
fn gate_socket_is_mounted() {
    if should_skip() {
        return;
    }
    let code = sandbox_sh("test -e /run/latchgate/gate.sock").unwrap();
    assert_eq!(code, 0, "gate socket should be visible in sandbox");
}

// Privilege escalation

#[test]
fn cannot_mount() {
    if should_skip() {
        return;
    }
    let code = sandbox_sh("mount -t tmpfs none /tmp/test 2>/dev/null").unwrap();
    assert_ne!(code, 0, "mount must be denied in sandbox");
}

#[test]
fn cannot_write_to_gate_socket() {
    if should_skip() {
        return;
    }
    let code = sandbox_sh("echo x > /run/latchgate/gate.sock 2>/dev/null").unwrap();
    assert_ne!(code, 0, "gate socket must be read-only");
}

/// Gate socket must be validated before bwrap launch. A missing socket
/// (gate not running) must produce a clear error, not a cryptic bwrap
/// "Can't find source path" failure.
#[test]
fn missing_gate_socket_returns_clear_error() {
    let workspace = tempfile::tempdir().unwrap();
    let config = AgentSandboxConfig {
        workspace: Some(workspace.path().to_path_buf()),
        gate_socket: std::path::PathBuf::from("/nonexistent/path/gate.sock"),
        allow_hosts: vec![],
        pass_env: vec![],
        ro_mounts: vec![],
        credentials: std::collections::HashMap::new(),
        sandbox_uid: None,
        sandbox_gid: None,
    };
    let result =
        SandboxLaunchParams::resolve(&config, vec!["/bin/sh".into(), "-c".into(), "true".into()]);
    let err = result.expect_err("missing gate socket must fail resolve()");
    let msg = err.to_string();
    assert!(
        msg.contains("gate") && msg.contains("not found"),
        "error must mention gate socket: {msg}"
    );
}

/// Gate socket pointing at an existing non-socket file must resolve
/// successfully — canonicalization cares about existence, not file type.
/// bwrap handles the bind mount; the sandbox-init shim treats it as
/// opaque.
#[test]
fn existing_gate_socket_path_resolves() {
    let workspace = tempfile::tempdir().unwrap();
    let gate_dir = tempfile::tempdir().unwrap();
    let gate_sock = gate_dir.path().join("gate.sock");
    std::fs::write(&gate_sock, "").unwrap();

    let config = AgentSandboxConfig {
        workspace: Some(workspace.path().to_path_buf()),
        gate_socket: gate_sock,
        allow_hosts: vec![],
        pass_env: vec![],
        ro_mounts: vec![],
        credentials: std::collections::HashMap::new(),
        sandbox_uid: None,
        sandbox_gid: None,
    };
    let result =
        SandboxLaunchParams::resolve(&config, vec!["/bin/sh".into(), "-c".into(), "true".into()]);
    assert!(
        result.is_ok(),
        "existing gate socket must resolve: {:?}",
        result.err()
    );
}

#[test]
fn cannot_create_namespaces() {
    if should_skip() {
        return;
    }
    // unshare is blocked by seccomp (EPERM). clone with namespace flags
    // is also blocked. clone3 returns ENOSYS (glibc falls back to clone).
    let code = sandbox_sh("unshare -U true 2>/dev/null").unwrap();
    assert_ne!(code, 0, "namespace creation must be denied in sandbox");
}

// Resource limits

#[test]
fn rlimit_fsize_rejects_oversized_write() {
    if should_skip() {
        return;
    }
    // Seek past the 1 GiB RLIMIT_FSIZE and attempt a 1-byte write.
    // The kernel delivers SIGXFSZ or returns EFBIG, causing dd to fail.
    // Fast: only 1 byte of actual I/O, the rest is a sparse hole.
    let code = sandbox_sh(
        "dd if=/dev/zero of=/workspace/bigfile bs=1 count=1 seek=1073741825 2>/dev/null",
    )
    .unwrap();
    assert_ne!(code, 0, "writing past 1 GiB must fail under RLIMIT_FSIZE");
}

#[test]
fn rlimit_fsize_allows_normal_write() {
    if should_skip() {
        return;
    }
    // A write well within the 1 GiB limit must succeed.
    let code =
        sandbox_sh("dd if=/dev/zero of=/workspace/smallfile bs=1K count=1 2>/dev/null").unwrap();
    assert_eq!(code, 0, "small writes must succeed under RLIMIT_FSIZE");
}

// UTS namespace isolation

#[test]
fn uts_namespace_isolates_hostname() {
    if should_skip() {
        return;
    }
    // `hostname` inside the sandbox must return the synthetic "sandbox"
    // hostname from /etc/hostname (set by setup_mount_tree), NOT the host
    // hostname. This verifies CLONE_NEWUTS is in effect.
    //
    // The `timeout 5` wrapper prevents indefinite hang: hostname(1) on some
    // distros queries NSS modules that block when /etc/resolv.conf is empty
    // and the network namespace has no loopback. Five seconds is generous
    // for a syscall that normally returns instantly.
    let (code, ws, _dir) =
        sandbox_sh_with_workspace("timeout 5 hostname > /workspace/.out 2>&1").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    assert_eq!(
        content.trim(),
        "sandbox",
        "hostname must reflect the isolated UTS namespace, not the host"
    );
}

// IPC namespace isolation

#[test]
fn ipc_syscalls_blocked_by_seccomp() {
    if should_skip() {
        return;
    }
    // ipcmk creates a SysV shared memory segment. It must fail: the IPC
    // namespace is isolated AND the seccomp filter blocks shmget.
    let code = sandbox_sh("ipcmk -M 4096 2>/dev/null").unwrap();
    assert_ne!(
        code, 0,
        "SysV IPC operations must be denied (CLONE_NEWIPC + seccomp)"
    );
}

// File descriptor limit

#[test]
fn rlimit_nofile_enforced() {
    if should_skip() {
        return;
    }
    // Read the soft fd limit from inside the sandbox. It must match the
    // enforced RLIMIT_NOFILE_MAX (4096).
    let (code, ws, _dir) = sandbox_sh_with_workspace("ulimit -n > /workspace/.out").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    let limit: u64 = content.trim().parse().expect("ulimit -n must be numeric");
    assert_eq!(limit, 4096, "RLIMIT_NOFILE must be 4096 inside sandbox");
}

// Core dump disabled

#[test]
fn rlimit_core_is_zero() {
    if should_skip() {
        return;
    }
    // Read the core dump size limit. Must be 0 — no core dumps allowed
    // inside the sandbox (prevents secret leakage through crash dumps).
    let (code, ws, _dir) = sandbox_sh_with_workspace("ulimit -c > /workspace/.out").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    let limit: u64 = content.trim().parse().expect("ulimit -c must be numeric");
    assert_eq!(
        limit, 0,
        "RLIMIT_CORE must be 0 (no core dumps) inside sandbox"
    );
}

#[test]
fn rlimit_cpu_enforced() {
    if should_skip() {
        return;
    }
    // Read the CPU time limit. Must be 600 seconds (10 min) —
    // bounds cumulative CPU consumption across the agent process tree.
    let (code, ws, _dir) = sandbox_sh_with_workspace("ulimit -t > /workspace/.out").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    let limit: u64 = content.trim().parse().expect("ulimit -t must be numeric");
    assert_eq!(limit, 600, "RLIMIT_CPU must be 600 seconds inside sandbox");
}

#[test]
fn rlimit_data_enforced() {
    if should_skip() {
        return;
    }
    // Read the data segment limit. Must be 4 GiB (4194304 kB).
    // Defense-in-depth: bounds brk()-backed allocations independently of
    // RLIMIT_AS.
    let (code, ws, _dir) = sandbox_sh_with_workspace("ulimit -d > /workspace/.out").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    let limit_kb: u64 = content.trim().parse().expect("ulimit -d must be numeric");
    assert_eq!(
        limit_kb,
        4 * 1024 * 1024,
        "RLIMIT_DATA must be 4 GiB (4194304 kB) inside sandbox"
    );
}

#[test]
fn rlimit_stack_enforced() {
    if should_skip() {
        return;
    }
    // Read the stack size limit. Must be 8 MiB (8192 kB).
    let (code, ws, _dir) = sandbox_sh_with_workspace("ulimit -s > /workspace/.out").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    let limit_kb: u64 = content.trim().parse().expect("ulimit -s must be numeric");
    assert_eq!(
        limit_kb, 8192,
        "RLIMIT_STACK must be 8 MiB (8192 kB) inside sandbox"
    );
}

#[test]
fn rlimit_memlock_enforced() {
    if should_skip() {
        return;
    }
    // Read the locked memory limit. Must be 64 KiB.
    // `ulimit -l` reports in KiB on Linux.
    let (code, ws, _dir) = sandbox_sh_with_workspace("ulimit -l > /workspace/.out").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    let limit_kb: u64 = content.trim().parse().expect("ulimit -l must be numeric");
    assert_eq!(limit_kb, 64, "RLIMIT_MEMLOCK must be 64 KiB inside sandbox");
}

#[test]
fn rlimit_sigpending_enforced() {
    if should_skip() {
        return;
    }
    // `ulimit -i` is a bash extension; the sandbox shell is dash.
    // Use python3's `resource` module to call getrlimit(2) directly.
    let (code, ws, _dir) = sandbox_sh_with_workspace(
        "python3 -c 'import resource; print(resource.getrlimit(resource.RLIMIT_SIGPENDING)[0])' \
         > /workspace/.out 2>&1",
    )
    .unwrap();
    assert_eq!(code, 0, "python3 getrlimit must succeed");
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    let limit: u64 = content
        .trim()
        .parse()
        .expect("RLIMIT_SIGPENDING must be numeric");
    assert_eq!(limit, 256, "RLIMIT_SIGPENDING must be 256 inside sandbox");
}

#[test]
fn rlimit_msgqueue_is_zero() {
    if should_skip() {
        return;
    }
    // `ulimit -q` is a bash extension; use python3's `resource` module.
    let (code, ws, _dir) = sandbox_sh_with_workspace(
        "python3 -c 'import resource; print(resource.getrlimit(resource.RLIMIT_MSGQUEUE)[0])' \
         > /workspace/.out 2>&1",
    )
    .unwrap();
    assert_eq!(code, 0, "python3 getrlimit must succeed");
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    let limit: u64 = content
        .trim()
        .parse()
        .expect("RLIMIT_MSGQUEUE must be numeric");
    assert_eq!(
        limit, 0,
        "RLIMIT_MSGQUEUE must be 0 (no POSIX mqueues) inside sandbox"
    );
}

// Stress: concurrent launches

#[test]
fn concurrent_launches() {
    if should_skip() {
        return;
    }
    let rt = ScopedRuntime::new();
    rt.block_on(async {
        let result = tokio::time::timeout(CONCURRENT_BATCH_TIMEOUT, async {
            let mut handles = Vec::new();
            for i in 0..5 {
                handles.push(tokio::spawn(async move {
                    let workspace = tempfile::tempdir().unwrap();
                    let gate_dir = tempfile::tempdir().unwrap();
                    let gate_sock = gate_dir.path().join("gate.sock");
                    std::fs::write(&gate_sock, "").unwrap();

                    let config = AgentSandboxConfig {
                        workspace: Some(workspace.path().to_path_buf()),
                        gate_socket: gate_sock,
                        allow_hosts: vec![],
                        pass_env: vec![],
                        ro_mounts: vec![],
                        credentials: std::collections::HashMap::new(),
                        sandbox_uid: None,
                        sandbox_gid: None,
                    };
                    let params = SandboxLaunchParams::resolve(
                        &config,
                        vec![
                            "/bin/sh".into(),
                            "-c".into(),
                            format!("echo {i} > /workspace/.id"),
                        ],
                    )
                    .unwrap();

                    let launch_result = crate::launch(params).await.unwrap();
                    assert_eq!(launch_result.exit_code, 0, "sandbox {i} failed");

                    let id = std::fs::read_to_string(workspace.path().join(".id")).unwrap();
                    assert_eq!(id.trim(), &i.to_string(), "sandbox {i} wrong output");
                }));
            }

            let mut failures = Vec::new();
            for (i, h) in handles.into_iter().enumerate() {
                if let Err(e) = h.await {
                    failures.push(format!("sandbox {i}: {e}"));
                }
            }
            failures
        })
        .await;

        match result {
            Err(_) => panic!(
                "concurrent launch batch timed out after {}s — \
                 possible deadlock in namespace setup",
                CONCURRENT_BATCH_TIMEOUT.as_secs()
            ),
            Ok(failures) if !failures.is_empty() => {
                panic!("concurrent launch failures:\n  {}", failures.join("\n  "));
            }
            Ok(_) => {} // all 5 passed
        }
    });
}

// /proc mount

#[test]
fn proc_self_exe_readable() {
    if should_skip() {
        return;
    }
    let (code, ws, _dir) =
        sandbox_sh_with_workspace("readlink /proc/self/exe > /workspace/.out").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    assert!(
        !content.trim().is_empty(),
        "/proc/self/exe must be readable inside sandbox"
    );
}

#[test]
fn proc_only_shows_sandbox_pids() {
    if should_skip() {
        return;
    }
    // Count numeric entries in /proc — each represents a visible PID.
    // In the isolated PID namespace, only the shell and its children
    // should be visible (typically 2–4 PIDs).
    let (code, ws, _dir) =
        sandbox_sh_with_workspace("ls -1 /proc | grep -cE '^[0-9]+$' > /workspace/.out").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    let count: usize = content.trim().parse().expect("pid count must be numeric");
    assert!(
        count > 0 && count < 10,
        "expected only sandbox PIDs in /proc, found {count}"
    );
}

#[test]
fn proc_mounted_with_restrictions() {
    if should_skip() {
        return;
    }
    let (code, ws, _dir) =
        sandbox_sh_with_workspace("grep ' /proc ' /proc/mounts > /workspace/.out").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    assert!(content.contains("nosuid"), "/proc must have nosuid");
    assert!(content.contains("nodev"), "/proc must have nodev");
    assert!(content.contains("noexec"), "/proc must have noexec");
}

#[test]
fn proc_self_status_readable() {
    if should_skip() {
        return;
    }
    // Python multiprocessing and many runtimes read /proc/self/status.
    let (code, ws, _dir) =
        sandbox_sh_with_workspace("head -1 /proc/self/status > /workspace/.out").unwrap();
    assert_eq!(code, 0);
    let content = std::fs::read_to_string(ws.join(".out")).unwrap();
    assert!(
        content.starts_with("Name:"),
        "/proc/self/status must be readable, got: {content}"
    );
}

// Read-only mount PATH discovery

#[test]
fn ro_mount_bin_added_to_path() {
    if should_skip() {
        return;
    }
    let workspace = tempfile::tempdir().unwrap();
    let gate_dir = tempfile::tempdir().unwrap();
    let gate_sock = gate_dir.path().join("gate.sock");
    std::fs::write(&gate_sock, "").unwrap();

    // Create an ro_mount with a bin/ directory containing a script.
    // IMPORTANT: must be outside /tmp — the sandbox mounts a private
    // tmpfs on /tmp which would hide any ro_mount beneath it.
    let tool_dir = tempfile::Builder::new()
        .prefix("latchgate-test-tools-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let bin_dir = tool_dir.path().join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let script_path = bin_dir.join("latchgate-test-tool");
    std::fs::write(&script_path, "#!/bin/sh\necho tool-output\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();

    let config = AgentSandboxConfig {
        workspace: Some(workspace.path().to_path_buf()),
        gate_socket: gate_sock,
        allow_hosts: vec![],
        pass_env: vec![],
        ro_mounts: vec![tool_dir.path().canonicalize().unwrap()],
        credentials: std::collections::HashMap::new(),
        sandbox_uid: None,
        sandbox_gid: None,
    };

    // The script is found by the shell via PATH (not by resolve_in_path).
    let params = SandboxLaunchParams::resolve(
        &config,
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "latchgate-test-tool > /workspace/.out".into(),
        ],
    )
    .unwrap();

    let ws_path = workspace.path().to_path_buf();
    let rt = ScopedRuntime::new();
    let result = rt.block_on(async {
        tokio::time::timeout(LAUNCH_TIMEOUT, crate::launch(params))
            .await
            .expect("sandbox timed out")
            .map(|r| r.exit_code)
    });
    let code = result.unwrap();

    assert_eq!(code, 0, "tool in ro_mount bin/ must be executable via PATH");
    let output = std::fs::read_to_string(ws_path.join(".out")).unwrap();
    assert_eq!(output.trim(), "tool-output");
}

#[test]
fn ro_mount_command_resolved_directly() {
    if should_skip() {
        return;
    }
    let workspace = tempfile::tempdir().unwrap();
    let gate_dir = tempfile::tempdir().unwrap();
    let gate_sock = gate_dir.path().join("gate.sock");
    std::fs::write(&gate_sock, "").unwrap();

    // Create a tool that is used as the OUTER command (resolve_in_path).
    // IMPORTANT: must be outside /tmp — the sandbox mounts a private
    // tmpfs on /tmp which would hide any ro_mount beneath it.
    let tool_dir = tempfile::Builder::new()
        .prefix("latchgate-test-tools-")
        .tempdir_in("/var/tmp")
        .unwrap();
    let bin_dir = tool_dir.path().join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let script_path = bin_dir.join("latchgate-outer-tool");
    std::fs::write(&script_path, "#!/bin/sh\necho resolved > /workspace/.out\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();

    let canonical_tool_dir = tool_dir.path().canonicalize().unwrap();
    let config = AgentSandboxConfig {
        workspace: Some(workspace.path().to_path_buf()),
        gate_socket: gate_sock,
        allow_hosts: vec![],
        pass_env: vec![],
        ro_mounts: vec![canonical_tool_dir],
        credentials: std::collections::HashMap::new(),
        sandbox_uid: None,
        sandbox_gid: None,
    };

    // "latchgate-outer-tool" as the top-level command — resolve_in_path
    // must find it in the ro_mount's bin/ directory.
    let params =
        SandboxLaunchParams::resolve(&config, vec!["latchgate-outer-tool".into()]).unwrap();

    let ws_path = workspace.path().to_path_buf();
    let rt = ScopedRuntime::new();
    let result = rt.block_on(async {
        tokio::time::timeout(LAUNCH_TIMEOUT, crate::launch(params))
            .await
            .expect("sandbox timed out")
            .map(|r| r.exit_code)
    });
    let code = result.unwrap();

    assert_eq!(code, 0, "outer command in ro_mount bin/ must resolve");
    let output = std::fs::read_to_string(ws_path.join(".out")).unwrap();
    assert_eq!(output.trim(), "resolved");
}

// Landlock defense-in-depth

/// Returns `true` if the running kernel supports Landlock (ABI ≥ 1).
fn is_landlock_supported() -> bool {
    // SAFETY: NULL attr + size 0 + VERSION flag queries the ABI version
    // without side effects. Returns the version number on success, -1 on
    // failure (kernel < 5.13 or blocked by security module).
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

#[test]
fn landlock_restricts_etc_writes() {
    if should_skip() {
        return;
    }
    if !is_landlock_supported() {
        eprintln!("SKIP landlock test: kernel < 5.13");
        return;
    }
    // /etc sits on the scaffold tmpfs — writable by mount-tree alone.
    // Landlock restricts it to read-only. This verifies the defense-in-depth
    // layer closes a gap that the mount namespace leaves open.
    let code = sandbox_sh("touch /etc/landlock_probe 2>/dev/null").unwrap();
    assert_ne!(
        code, 0,
        "Landlock must deny writes to /etc (defense-in-depth over mount-tree)"
    );
}

#[test]
fn landlock_restricts_scaffold_root_writes() {
    if should_skip() {
        return;
    }
    if !is_landlock_supported() {
        eprintln!("SKIP landlock test: kernel < 5.13");
        return;
    }
    // Creating files directly on / (the scaffold tmpfs) should be denied
    // by Landlock — only explicitly allowed paths are writable.
    let code = sandbox_sh("touch /landlock_root_probe 2>/dev/null").unwrap();
    assert_ne!(code, 0, "Landlock must deny writes to scaffold root");
}

#[test]
fn landlock_allows_workspace_writes() {
    if should_skip() {
        return;
    }
    if !is_landlock_supported() {
        eprintln!("SKIP landlock test: kernel < 5.13");
        return;
    }
    // /workspace must remain writable under Landlock.
    let code = sandbox_sh("echo ok > /workspace/landlock_write_test").unwrap();
    assert_eq!(code, 0, "/workspace must be writable with Landlock active");
}

#[test]
fn landlock_allows_tmp_writes() {
    if should_skip() {
        return;
    }
    if !is_landlock_supported() {
        eprintln!("SKIP landlock test: kernel < 5.13");
        return;
    }
    let code = sandbox_sh("echo ok > /tmp/landlock_tmp_test").unwrap();
    assert_eq!(code, 0, "/tmp must be writable with Landlock active");
}

#[test]
fn landlock_denies_tmp_execute() {
    if should_skip() {
        return;
    }
    if !is_landlock_supported() {
        eprintln!("SKIP landlock test: kernel < 5.13");
        return;
    }
    // /tmp is writable but Landlock denies EXECUTE — defense-in-depth
    // against write-then-exec patterns.
    let code = sandbox_sh(
        "cp /bin/true /tmp/exec_probe && chmod +x /tmp/exec_probe && /tmp/exec_probe 2>/dev/null",
    )
    .unwrap();
    assert_ne!(code, 0, "Landlock must deny execution from /tmp");
}

#[test]
fn landlock_allows_usr_execute() {
    if should_skip() {
        return;
    }
    if !is_landlock_supported() {
        eprintln!("SKIP landlock test: kernel < 5.13");
        return;
    }
    // System binaries under /usr must remain executable.
    let code = sandbox_sh("/usr/bin/true").unwrap();
    assert_eq!(code, 0, "/usr/bin/true must execute with Landlock active");
}

// Bubblewrap integration tests
//
// These tests exercise bwrap's namespace isolation directly (without the
// sandbox-init shim) to verify the isolation properties bwrap creates.
// Skip gracefully when bwrap is not installed.

/// Returns `true` when bwrap integration tests should be skipped.
///
/// Delegates to [`should_skip`] — all sandbox tests now require bwrap.
fn should_skip_bwrap() -> bool {
    should_skip()
}

/// Probe bwrap with the full set of namespace flags used by [`bwrap_sh`].
fn probe_bwrap_full() -> bool {
    let mut child = match std::process::Command::new("bwrap")
        .args(["--unshare-user", "--unshare-pid", "--unshare-net"])
        .args(["--unshare-uts", "--unshare-ipc", "--unshare-cgroup"])
        .args(["--die-with-parent", "--new-session"])
        .args(["--ro-bind", "/usr", "/usr"])
        .args(["--ro-bind-try", "/bin", "/bin"])
        .args(["--ro-bind-try", "/lib", "/lib"])
        .args(["--ro-bind-try", "/lib64", "/lib64"])
        .args(["--symlink", "/usr/lib", "/lib"])
        .args(["--tmpfs", "/tmp"])
        .args(["--proc", "/proc"])
        .args(["--dev", "/dev"])
        .args(["--clearenv"])
        .args(["--", "/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIP bwrap tests: full probe spawn failed: {e}");
            return false;
        }
    };

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return true,
            Ok(Some(status)) => {
                eprintln!(
                    "SKIP bwrap tests: full namespace probe exited with {:?}",
                    status.code()
                );
                return false;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    eprintln!(
                        "SKIP bwrap tests: full namespace probe timed out \
                         (PID/NET/IPC namespaces likely blocked)"
                    );
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("SKIP bwrap tests: full probe try_wait failed: {e}");
                return false;
            }
        }
    }
}

/// Run a script inside bwrap with full namespace isolation.
///
/// Uses bwrap directly (no shim), capturing stdout. Returns `(exit_code, stdout)`.
///
/// The child is polled via `try_wait` with `LAUNCH_TIMEOUT`. If bwrap
/// hangs (namespace setup blocked by AppArmor, kernel policy, or a stuck
/// mount), the child is killed and the test panics with a clear message
/// instead of blocking the test runner.
fn bwrap_sh(script: &str, workspace: &std::path::Path) -> (i32, String) {
    let ws = workspace.to_string_lossy();
    let mut child = std::process::Command::new("bwrap")
        .args(["--unshare-user", "--unshare-pid", "--unshare-net"])
        .args(["--unshare-uts", "--unshare-ipc", "--unshare-cgroup"])
        .args(["--die-with-parent", "--new-session"])
        .args(["--bind", &ws, "/workspace"])
        .args(["--ro-bind", "/usr", "/usr"])
        .args(["--ro-bind-try", "/bin", "/bin"])
        .args(["--ro-bind-try", "/lib", "/lib"])
        .args(["--ro-bind-try", "/lib64", "/lib64"])
        .args(["--ro-bind-try", "/sbin", "/sbin"])
        .args(["--tmpfs", "/tmp"])
        .args(["--proc", "/proc"])
        .args(["--dev", "/dev"])
        .args(["--clearenv"])
        .args(["--setenv", "HOME", "/workspace"])
        .args([
            "--setenv",
            "PATH",
            "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        ])
        .args(["--hostname", "sandbox"])
        .args(["--", "/bin/sh", "-c", script])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to spawn bwrap");

    // Read stdout on a separate thread so full pipe buffers can't
    // deadlock the child while we poll for exit.
    let stdout_pipe = child.stdout.take().expect("stdout was piped");
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = String::new();
        let _ = std::io::BufReader::new(stdout_pipe).read_to_string(&mut buf);
        buf
    });

    let deadline = std::time::Instant::now() + LAUNCH_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("try_wait failed") {
            Some(s) => break s,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "bwrap timed out after {}s — the sandboxed process did not exit",
                    LAUNCH_TIMEOUT.as_secs(),
                );
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };

    let stdout = reader.join().unwrap_or_default();
    let code = status.code().unwrap_or(1);
    (code, stdout)
}

#[test]
fn bwrap_host_sensitive_paths_absent() {
    if should_skip_bwrap() {
        eprintln!("SKIP bwrap tests: bwrap not available");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let (code, _) = bwrap_sh(
        "! test -e /etc/shadow && ! test -e /etc/ssh && ! test -d /home && ! test -d /root",
        ws.path(),
    );
    assert_eq!(
        code, 0,
        "sensitive host paths must not exist inside bwrap sandbox"
    );
}

#[test]
fn bwrap_workspace_is_writable() {
    if should_skip_bwrap() {
        eprintln!("SKIP bwrap tests: bwrap not available");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let (code, _) = bwrap_sh("echo bwrap-write-test > /workspace/.probe", ws.path());
    assert_eq!(code, 0, "workspace write must succeed inside bwrap");

    let content = std::fs::read_to_string(ws.path().join(".probe")).unwrap();
    assert_eq!(content.trim(), "bwrap-write-test");
}

#[test]
fn bwrap_network_is_isolated() {
    if should_skip_bwrap() {
        eprintln!("SKIP bwrap tests: bwrap not available");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    // Attempt a network operation — must fail with CLONE_NEWNET isolation.
    // wget/curl may not be available, so use a low-level approach: try to
    // list any network interfaces beyond loopback.
    let (code, stdout) = bwrap_sh("cat /proc/net/tcp 2>/dev/null | wc -l", ws.path());
    assert_eq!(code, 0);
    // In an empty network namespace, /proc/net/tcp has only the header (1 line)
    // or is empty (0 lines). No established connections possible.
    let lines: usize = stdout.trim().parse().unwrap_or(0);
    assert!(
        lines <= 1,
        "expected no TCP connections in network namespace, found {lines} lines in /proc/net/tcp"
    );
}

#[test]
fn bwrap_pid_namespace_isolated() {
    if should_skip_bwrap() {
        eprintln!("SKIP bwrap tests: bwrap not available");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    // Count numeric entries in /proc — only sandbox PIDs should be visible.
    let (code, stdout) = bwrap_sh("ls -1 /proc | grep -cE '^[0-9]+$'", ws.path());
    assert_eq!(code, 0);
    let count: usize = stdout.trim().parse().expect("pid count must be numeric");
    assert!(
        count > 0 && count < 10,
        "expected only sandbox PIDs in /proc, found {count}"
    );
}

#[test]
fn bwrap_environment_is_clean() {
    if should_skip_bwrap() {
        eprintln!("SKIP bwrap tests: bwrap not available");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let (code, stdout) = bwrap_sh("env", ws.path());
    assert_eq!(code, 0);

    let env: std::collections::HashMap<&str, &str> =
        stdout.lines().filter_map(|l| l.split_once('=')).collect();

    assert_eq!(
        env.get("HOME"),
        Some(&"/workspace"),
        "--clearenv HOME override"
    );
    assert!(env.contains_key("PATH"), "--clearenv PATH override");

    for leaked in &["USER", "SHELL", "LOGNAME", "DISPLAY", "SSH_AUTH_SOCK"] {
        assert!(
            !env.contains_key(leaked),
            "{leaked} must not leak through --clearenv"
        );
    }
}

#[test]
fn bwrap_hostname_is_sandbox() {
    if should_skip_bwrap() {
        eprintln!("SKIP bwrap tests: bwrap not available");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let (code, stdout) = bwrap_sh("hostname", ws.path());
    assert_eq!(code, 0);
    assert_eq!(
        stdout.trim(),
        "sandbox",
        "UTS namespace must isolate hostname"
    );
}

#[test]
fn bwrap_tmp_is_writable() {
    if should_skip_bwrap() {
        eprintln!("SKIP bwrap tests: bwrap not available");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let (code, _) = bwrap_sh("echo test > /tmp/bwrap_probe", ws.path());
    assert_eq!(code, 0, "/tmp must be writable inside bwrap (tmpfs)");
}

#[test]
fn bwrap_dev_null_functional() {
    if should_skip_bwrap() {
        eprintln!("SKIP bwrap tests: bwrap not available");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let (code, _) = bwrap_sh("echo discard > /dev/null", ws.path());
    assert_eq!(code, 0, "/dev/null must work inside bwrap");
}

#[test]
fn bwrap_usr_is_readonly() {
    if should_skip_bwrap() {
        eprintln!("SKIP bwrap tests: bwrap not available");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let (code, _) = bwrap_sh("touch /usr/bwrap_probe 2>/dev/null", ws.path());
    assert_ne!(code, 0, "/usr must be read-only inside bwrap");
}

#[test]
fn bwrap_exit_code_propagated() {
    if should_skip_bwrap() {
        eprintln!("SKIP bwrap tests: bwrap not available");
        return;
    }
    let ws = tempfile::tempdir().unwrap();
    let (code, _) = bwrap_sh("exit 42", ws.path());
    assert_eq!(code, 42, "bwrap must propagate child exit code");
}

// (strategy_detection_is_deterministic removed — detect_strategy is gone;
//  platform::detect_tier consistency is tested in platform.rs)
