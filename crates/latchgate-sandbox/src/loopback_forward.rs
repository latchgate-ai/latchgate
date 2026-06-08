//! In-sandbox loopback bridge: TCP → Unix-domain egress proxy.
//!
//! The egress proxy listens on a Unix-domain socket bind-mounted into the
//! sandbox at `/run/latchgate/proxy.sock`. Many agent runtimes (Node.js,
//! Go, Python `requests`) cannot use a `http+unix://` proxy URL — their
//! `HTTPS_PROXY` handling only understands `http://host:port`. This module
//! provides the missing transport: a loopback TCP listener inside the
//! sandbox network namespace that relays every accepted connection,
//! byte-for-byte, to the Unix socket.
//!
//! ```text
//!   agent ──HTTPS_PROXY=http://127.0.0.1:PORT──► forwarder ──► /run/latchgate/proxy.sock ──► host proxy
//! ```
//!
//! # Security
//!
//! The bridge introduces no new egress path. The forwarder is a pure byte
//! relay: it performs no parsing, no policy, and no host resolution. Every
//! request still terminates at the same Unix-socket proxy, which remains
//! the sole enforcement point for the host allowlist, credential
//! injection, DNS-rebinding defense, and TLS-only outbound.
//!
//! - The listener binds `127.0.0.1` inside `CLONE_NEWNET`. Loopback in an
//!   otherwise-empty network namespace can only reach itself; there is no
//!   route to the host network, to other namespaces, or to any external
//!   address.
//! - The forwarder runs as a dedicated child process (see [`spawn`]). It
//!   must outlive the `execve` that replaces the agent's process image, so
//!   a thread would not survive; a separate process does. It is reaped by
//!   the sandbox PID-namespace init when the agent tree exits.
//! - Bringing `lo` up requires `CAP_NET_ADMIN` in the namespace, so
//!   [`bring_up_loopback`] must be called *before* the capability set is
//!   dropped. The forwarder itself needs no capabilities and is spawned
//!   after the drop.
//!
//! # Process model
//!
//! [`spawn`] forks. The child binds a fresh loopback TCP listener, sends
//! the kernel-assigned port to the parent over a pipe, then enters a
//! blocking accept loop. Each accepted connection is relayed in a pair of
//! threads using `std::io::copy` — one thread per direction. The parent
//! blocks on the pipe read and returns the port to the caller.
//!
//! The forwarder deliberately avoids async runtimes (tokio/epoll). On
//! WSL2's kernel, an epoll instance created after `fork()` inside
//! `CLONE_NEWNET` silently fails to deliver readiness events — `epoll_ctl`
//! succeeds but `epoll_wait` never wakes. Blocking I/O with threads is
//! the only portable relay strategy across mainline Linux, WSL2, and
//! other variants.
//!
//! # Why the listener is created after fork
//!
//! The TCP listener is bound in the child process, not before `fork()`.
//! This ensures the socket's file description is created in the same
//! process that will use it, avoiding any cross-fork fd inheritance
//! interactions with the kernel's network namespace tracking.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::SandboxError;

/// Loopback address the forwarder binds inside the sandbox netns.
pub(crate) const LOOPBACK_HOST: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// Maximum concurrent relayed connections.
///
/// Mirrors the egress proxy's own `MAX_CONNECTIONS` ceiling: the proxy
/// rejects beyond that bound anyway, so a matching cap bounds the
/// forwarder's memory without changing observable behavior.
const MAX_RELAYS: usize = 64;

/// Size of the port handshake payload (network-byte-order `u16`).
const PORT_MSG_LEN: usize = std::mem::size_of::<u16>();

/// Maximum time (ms) to wait for the child to report its port.
///
/// The child's work (bind + write 2 bytes) takes microseconds. A timeout
/// this generous means something is fundamentally broken. Matches the
/// netns helper's `READINESS_TIMEOUT_MS`.
const PORT_HANDSHAKE_TIMEOUT_MS: libc::c_int = 10_000;

// Kernel ABI for the loopback bring-up ioctl
//
// `struct ifreq` and the `SIOCxIFFLAGS` request numbers are part of the
// stable Linux uapi (uapi/linux/if.h, uapi/linux/sockios.h) but are not
// reliably exposed by the `libc` crate across the versions this workspace
// supports. They are defined locally here — matching the crate's existing
// convention for kernel ABI that libc omits (see `namespace.rs`'s local
// `CLONE_NEWCGROUP`/`CLONE_NEWTIME` and the new-mount-API syscall numbers
// in `seccomp.rs`).

/// Platform-correct type for `ioctl(2)` request codes.
///
/// glibc defines the request parameter as `unsigned long` (`c_ulong`);
/// musl defines it as `int` (`c_int`). Using `c_ulong` unconditionally
/// causes a type mismatch on musl targets (the static-musl release build).
/// Both values below (0x8913, 0x8914) fit in either type.
#[cfg(target_env = "musl")]
type IoctlRequest = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = libc::c_ulong;

/// `SIOCGIFFLAGS` — get interface flags. Stable across all architectures.
const SIOCGIFFLAGS: IoctlRequest = 0x8913;

/// `SIOCSIFFLAGS` — set interface flags. Stable across all architectures.
const SIOCSIFFLAGS: IoctlRequest = 0x8914;

/// `IFF_UP` — interface is administratively up (uapi/linux/if.h).
const IFF_UP: libc::c_short = 0x1;

/// Interface name size, including the trailing NUL (uapi/linux/if.h).
const IFNAMSIZ: usize = 16;

/// Size of the kernel `struct ifreq` in bytes.
///
/// The struct is `ifr_name[IFNAMSIZ]` followed by the `ifr_ifru` union.
/// The union is 24 bytes on LP64 (x86-64, aarch64) and 16 on ILP32,
/// giving totals of 40 and 32 respectively — verified against glibc's
/// `sizeof(struct ifreq)`. We allocate the full size so `SIOCGIFFLAGS`
/// cannot write past our buffer; a compile-time assertion guards it.
const IFREQ_SIZE: usize = IFNAMSIZ + IFRU_UNION_SIZE;

/// Size of the `ifr_ifru` union, selected by pointer width (the property
/// that drives the union's largest member, `void *ifru_data`).
#[cfg(target_pointer_width = "64")]
const IFRU_UNION_SIZE: usize = 24;
#[cfg(target_pointer_width = "32")]
const IFRU_UNION_SIZE: usize = 16;

/// Byte offset of `ifr_flags` within `struct ifreq` (immediately after the
/// name array). The flags member is a `c_short`.
const IFR_FLAGS_OFFSET: usize = IFNAMSIZ;

/// ABI-faithful `struct ifreq`, sized to exactly match the kernel's.
///
/// Represented as an opaque, correctly-sized, `c_ulong`-aligned byte buffer
/// rather than named fields. This guarantees the size matches the kernel
/// ABI on every target (so `SIOCGIFFLAGS` cannot write out of bounds) and
/// sidesteps the fragile union layout entirely. The two fields we touch —
/// the name and the flags `short` — are written/read at their fixed,
/// ABI-stable offsets via helper methods.
#[repr(C, align(8))]
struct IfReq {
    bytes: [u8; IFREQ_SIZE],
}

// Compile-time guarantee that our struct is exactly the kernel ABI size.
// 40 bytes on LP64, 32 on ILP32. If a future target breaks this, the build
// fails here rather than corrupting the stack at runtime.
const _: () = assert!(std::mem::size_of::<IfReq>() == IFREQ_SIZE);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<IfReq>() == 40);
#[cfg(target_pointer_width = "32")]
const _: () = assert!(std::mem::size_of::<IfReq>() == 32);

impl IfReq {
    /// A fully zeroed `ifreq`.
    fn zeroed() -> Self {
        IfReq {
            bytes: [0u8; IFREQ_SIZE],
        }
    }

    /// Write the interface name into `ifr_name`, NUL-padded. Names longer
    /// than `IFNAMSIZ - 1` are rejected (the caller only ever passes "lo").
    fn set_name(&mut self, name: &str) -> Result<(), SandboxError> {
        let raw = name.as_bytes();
        if raw.len() >= IFNAMSIZ {
            return Err(SandboxError::NamespaceSetup(format!(
                "loopback: interface name too long: {name:?}"
            )));
        }
        self.bytes[..raw.len()].copy_from_slice(raw);
        // Remaining bytes are already zero (NUL padding).
        Ok(())
    }

    /// Read `ifr_flags` (native-endian `c_short` at the union offset).
    fn flags(&self) -> libc::c_short {
        const N: usize = std::mem::size_of::<libc::c_short>();
        let mut buf = [0u8; N];
        buf.copy_from_slice(&self.bytes[IFR_FLAGS_OFFSET..IFR_FLAGS_OFFSET + N]);
        libc::c_short::from_ne_bytes(buf)
    }

    /// Write `ifr_flags`.
    fn set_flags(&mut self, flags: libc::c_short) {
        const N: usize = std::mem::size_of::<libc::c_short>();
        let buf = flags.to_ne_bytes();
        self.bytes[IFR_FLAGS_OFFSET..IFR_FLAGS_OFFSET + N].copy_from_slice(&buf);
    }

    /// Pointer for ioctl. The kernel reads/writes up to `IFREQ_SIZE` bytes.
    fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        std::ptr::addr_of_mut!(self.bytes) as *mut libc::c_void
    }
}

/// Bring the loopback interface (`lo`) up inside the current network
/// namespace.
///
/// A fresh `CLONE_NEWNET` namespace contains `lo` in the `DOWN` state with
/// no addresses configured. Binding `127.0.0.1` fails until the interface
/// is administratively up. This sets `IFF_UP` via `SIOCSIFFLAGS`, which
/// auto-configures the `127.0.0.0/8` loopback route in the kernel.
///
/// # Capability requirement
///
/// `SIOCSIFFLAGS` requires `CAP_NET_ADMIN` in the network namespace. Call
/// this before dropping the bounding/effective capability set.
pub(crate) fn bring_up_loopback() -> Result<(), SandboxError> {
    // AF_INET datagram socket used purely as an ioctl handle; never sends.
    // SAFETY: socket(2) with valid domain/type/protocol returns an fd or -1.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "loopback: socket(AF_INET): {}",
            io::Error::last_os_error()
        )));
    }
    // Guarantee the handle is closed on every return path.
    let _guard = FdGuard(fd);

    let mut ifr = IfReq::zeroed();
    ifr.set_name("lo")?;

    // Read current flags (SIOCGIFFLAGS) so we set IFF_UP without clobbering
    // any other flag the kernel already established.
    // SAFETY: fd is a valid socket; the buffer is exactly the kernel ifreq
    // size, so ioctl cannot read or write out of bounds.
    if unsafe { libc::ioctl(fd, SIOCGIFFLAGS, ifr.as_mut_ptr()) } < 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "loopback: ioctl(SIOCGIFFLAGS): {}",
            io::Error::last_os_error()
        )));
    }

    // Idempotent: when lo is already up (parent-assisted netns path), skip
    // the privileged SIOCSIFFLAGS write entirely. This avoids requiring
    // CAP_NET_ADMIN in the shim when the parent has already configured the
    // namespace — the only privileged operation in the non-root path.
    if ifr.flags() & IFF_UP != 0 {
        return Ok(());
    }

    // Set IFF_UP. The kernel sets IFF_RUNNING for loopback automatically
    // once it is up, so we only need to request IFF_UP. All other flags
    // read above are preserved.
    ifr.set_flags(ifr.flags() | IFF_UP);

    // SAFETY: fd is a valid socket; the buffer is exactly the kernel ifreq
    // size. ioctl reads the flags from it.
    if unsafe { libc::ioctl(fd, SIOCSIFFLAGS, ifr.as_mut_ptr()) } < 0 {
        let err = io::Error::last_os_error();
        let hint = if err.raw_os_error() == Some(libc::EPERM) {
            "\n\nhint: this kernel does not permit unprivileged loopback \
             configuration inside a network namespace.\n\
             Re-run with: sudo latchgate sandbox ..."
        } else {
            ""
        };
        return Err(SandboxError::NamespaceSetup(format!(
            "loopback: ioctl(SIOCSIFFLAGS): {err}{hint}"
        )));
    }

    Ok(())
}

/// RAII closer for a raw fd used only within a single function scope.
struct FdGuard(libc::c_int);

impl Drop for FdGuard {
    fn drop(&mut self) {
        // SAFETY: self.0 is an fd we own and have not handed off.
        unsafe { libc::close(self.0) };
    }
}

/// Bind a loopback TCP listener on an ephemeral port and return both the
/// std listener and the kernel-assigned port.
///
/// Binding to port 0 lets the kernel pick a free port; reading it back via
/// `local_addr` avoids any bind race a fixed port would introduce.
fn bind_ephemeral() -> io::Result<(std::net::TcpListener, u16)> {
    let listener = std::net::TcpListener::bind(SocketAddrV4::new(LOOPBACK_HOST, 0))?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

// Port handshake helpers

/// Encode a port number for the child→parent pipe handshake.
///
/// Big-endian encoding for a fixed, unambiguous wire format. Two bytes
/// is the exact size of a `u16`; a partial write is always detectable.
fn encode_port(port: u16) -> [u8; PORT_MSG_LEN] {
    port.to_be_bytes()
}

/// Decode a port number received from the child→parent pipe handshake.
fn decode_port(buf: [u8; PORT_MSG_LEN]) -> u16 {
    u16::from_be_bytes(buf)
}

/// Read the child's port from the handshake pipe.
///
/// Waits up to [`PORT_HANDSHAKE_TIMEOUT_MS`] for the pipe to become
/// readable, then reads exactly [`PORT_MSG_LEN`] bytes. Handles EINTR
/// on both `poll` and `read`. Closes `pipe_r` on every path.
fn read_port_from_pipe(pipe_r: libc::c_int) -> Result<u16, SandboxError> {
    let _guard = FdGuard(pipe_r);

    // Wait for data (or EOF) with a hard timeout. The child's work —
    // bind + write 2 bytes — takes microseconds; a timeout here means the
    // child is stuck or dead.
    let mut pfd = libc::pollfd {
        fd: pipe_r,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: pfd is a valid pollfd; nfds=1; timeout in ms.
        let ret = unsafe { libc::poll(&mut pfd, 1, PORT_HANDSHAKE_TIMEOUT_MS) };
        if ret > 0 {
            break; // Readable (or hangup — read will return 0/EOF).
        }
        if ret == 0 {
            return Err(SandboxError::ProxySetup(format!(
                "loopback: forwarder child did not report port within {}s \
                 (child may be stuck in bind or runtime construction)",
                PORT_HANDSHAKE_TIMEOUT_MS / 1000
            )));
        }
        // ret < 0: check for EINTR (signal interrupted poll).
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(SandboxError::ProxySetup(format!(
                "loopback: poll on port handshake pipe: {err}"
            )));
        }
        // EINTR — retry poll with the full timeout. The child's work is
        // sub-millisecond; spending an extra cycle here is harmless.
    }

    let mut buf = [0u8; PORT_MSG_LEN];
    let mut total = 0usize;

    // Loop for short reads and EINTR. Pipe reads of ≤ PIPE_BUF are atomic
    // on Linux, but defensive coding costs nothing.
    while total < PORT_MSG_LEN {
        // SAFETY: pipe_r is a valid fd from pipe2; buf is PORT_MSG_LEN
        // bytes; we pass the remaining capacity.
        let n = unsafe {
            libc::read(
                pipe_r,
                buf[total..].as_mut_ptr().cast::<libc::c_void>(),
                PORT_MSG_LEN - total,
            )
        };
        if n > 0 {
            total += n as usize;
            continue;
        }
        if n == 0 {
            // EOF: child closed the write end before sending the full port.
            return Err(SandboxError::ProxySetup(
                "loopback: forwarder child exited before reporting port \
                 (check logs for bind or runtime errors)"
                    .into(),
            ));
        }
        // n < 0: error.
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(SandboxError::ProxySetup(format!(
            "loopback: read on port handshake pipe: {err}"
        )));
    }

    let port = decode_port(buf);
    if port == 0 {
        return Err(SandboxError::ProxySetup(
            "loopback: forwarder child reported port 0 (bind failure)".into(),
        ));
    }

    Ok(port)
}

/// Write the bound port to the handshake pipe. Returns `true` on success.
///
/// Called from the forwarder child immediately after `bind_ephemeral`.
/// Handles EINTR. Closes `pipe_w` on every path.
fn write_port_to_pipe(pipe_w: libc::c_int, port: u16) -> bool {
    let buf = encode_port(port);
    let ok = loop {
        // SAFETY: pipe_w is a valid fd from pipe2; buf is PORT_MSG_LEN bytes.
        let n = unsafe { libc::write(pipe_w, buf.as_ptr().cast::<libc::c_void>(), PORT_MSG_LEN) };
        if n == PORT_MSG_LEN as isize {
            break true;
        }
        if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break false;
    };
    // SAFETY: pipe_w is a valid fd; closing the write end signals the
    // parent that no more data will be sent.
    unsafe { libc::close(pipe_w) };
    ok
}

// Spawn

/// Bring up loopback, fork a forwarder child, and return the listener port.
///
/// On success the returned port is live: the parent may immediately set
/// `HTTPS_PROXY=http://127.0.0.1:<port>` and exec the agent. The forwarder
/// child never returns from this function — it serves until the sandbox
/// PID namespace is torn down.
///
/// The child creates its own TCP listener after the fork and sends the
/// kernel-assigned port to the parent over a pipe. It then enters a
/// blocking accept loop — no async runtime, no epoll — relaying each
/// connection in a pair of threads via `std::io::copy`. This is the only
/// portable relay strategy across mainline Linux and WSL2.
///
/// # Preconditions
///
/// - The caller is inside the sandbox network namespace (`CLONE_NEWNET`).
/// - `CAP_NET_ADMIN` is still held (loopback bring-up happens here).
/// - The caller is single-threaded (this forks; only the calling thread
///   survives in the child, which is exactly what we want before building
///   a fresh runtime).
///
/// `proxy_socket` is the in-sandbox path of the Unix-domain egress proxy
/// (`/run/latchgate/proxy.sock`).
pub(crate) fn spawn(proxy_socket: &Path) -> Result<u16, SandboxError> {
    bring_up_loopback()?;

    // Pipe for child→parent port handshake. O_CLOEXEC prevents leaking
    // into the agent process when the parent execs.
    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe2 with valid pointer and O_CLOEXEC flag.
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(SandboxError::ProxySetup(format!(
            "loopback: pipe2: {}",
            io::Error::last_os_error()
        )));
    }
    let pipe_r = pipe_fds[0];
    let pipe_w = pipe_fds[1];

    let proxy_socket = proxy_socket.to_path_buf();

    // SAFETY: fork() in a single-threaded process. The child inherits the
    // pipe write end and the proxy socket path; it shares no mutable state
    // with the parent beyond copy-on-write memory.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let err = io::Error::last_os_error();
        // SAFETY: both fds are valid from pipe2 above.
        unsafe {
            libc::close(pipe_r);
            libc::close(pipe_w);
        }
        return Err(SandboxError::Spawn(err));
    }

    if pid > 0 {
        // Parent: close write end, read port from child.
        // SAFETY: pipe_w is a valid fd; parent doesn't write.
        unsafe { libc::close(pipe_w) };
        return read_port_from_pipe(pipe_r);
    }

    // === Forwarder child ===
    //
    // Close the read end — only the parent reads from it.
    // SAFETY: pipe_r is a valid fd; child doesn't read.
    unsafe { libc::close(pipe_r) };

    // Bind AFTER fork: the socket's file description is created in the
    // same process that will use it, avoiding cross-fork fd inheritance
    // interactions with the kernel's network namespace tracking.
    let (listener, port) = match bind_ephemeral() {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!("loopback forwarder: bind 127.0.0.1:0: {e}");
            // SAFETY: close the write end so the parent sees EOF and
            // reports a clear error rather than blocking forever.
            unsafe { libc::close(pipe_w) };
            // SAFETY: _exit is async-signal-safe; terminates this child.
            unsafe { libc::_exit(1) }
        }
    };

    // Send the port to the parent. On failure the parent will see a short
    // read / EOF and report the error.
    if !write_port_to_pipe(pipe_w, port) {
        tracing::error!("loopback forwarder: failed to send port to parent");
        // SAFETY: _exit is async-signal-safe; terminates this child.
        unsafe { libc::_exit(1) }
    }

    // Serve forever with blocking I/O. run_forwarder never returns; on a
    // fatal error we exit non-zero so the failure is observable to the
    // PID-namespace init rather than silently lingering.
    let code = run_forwarder(listener, proxy_socket);
    // SAFETY: _exit is async-signal-safe and terminates this child only.
    unsafe { libc::_exit(code) }
}

// Forwarder (blocking I/O, no async runtime)

/// Entry point for the forwarder child. Returns a process exit code.
///
/// Uses a blocking accept loop with per-connection thread pairs for
/// bidirectional relay. No epoll, no async runtime — this is the only
/// portable approach after `fork()` inside `CLONE_NEWNET` on WSL2.
fn run_forwarder(listener: std::net::TcpListener, proxy_socket: PathBuf) -> i32 {
    let active = Arc::new(AtomicUsize::new(0));

    loop {
        let (tcp, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) => {
                // Transient accept errors (EMFILE under load, etc.) must
                // not kill the bridge — log and continue.
                tracing::warn!("loopback forwarder: accept error: {e}");
                continue;
            }
        };

        // Bound concurrency. If the ceiling is reached, drop the new
        // connection: the proxy would reject it anyway, and back-
        // pressure on the agent is preferable to unbounded growth.
        if active.load(Ordering::Relaxed) >= MAX_RELAYS {
            tracing::warn!("loopback forwarder: max relays reached, dropping");
            drop(tcp);
            continue;
        }

        let proxy_socket = proxy_socket.clone();
        let active = active.clone();
        active.fetch_add(1, Ordering::Relaxed);

        std::thread::spawn(move || {
            // Decrement active count when relay finishes, regardless of
            // success or failure.
            struct RelayGuard(Arc<AtomicUsize>);
            impl Drop for RelayGuard {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::Relaxed);
                }
            }
            let _guard = RelayGuard(active);

            if let Err(e) = relay(tcp, &proxy_socket) {
                tracing::debug!("loopback forwarder: relay ended: {e}");
            }
        });
    }
}

/// Relay one accepted TCP connection to the Unix-domain proxy, copying in
/// both directions until either side closes.
///
/// Spawns one thread for TCP→Unix; the calling thread handles Unix→TCP.
/// Each direction uses blocking `std::io::copy`. When one direction
/// reaches EOF or errors, the write half of the opposite socket is shut
/// down so the peer's `read` returns 0, unblocking the other thread.
fn relay(tcp: std::net::TcpStream, proxy_socket: &Path) -> io::Result<()> {
    // Disable Nagle: proxy traffic is request/response and latency-
    // sensitive (TLS handshakes, small CONNECT requests).
    let _ = tcp.set_nodelay(true);

    let unix = UnixStream::connect(proxy_socket)?;

    // Clone handles for the second thread. Each clone shares the
    // underlying fd; concurrent read on one + write on the other is safe.
    let tcp_c = tcp.try_clone()?;
    let unix_c = unix.try_clone()?;

    // TCP → Unix: read from the agent, write to the proxy.
    let fwd = std::thread::spawn(move || -> io::Result<u64> {
        let result = io::copy(&mut &tcp_c, &mut &unix_c);
        // Always signal the proxy we're done, whether the copy succeeded
        // or failed — this unblocks the reverse direction on the main
        // thread.
        let _ = unix_c.shutdown(std::net::Shutdown::Write);
        result
    });

    // Unix → TCP: read from the proxy, write to the agent.
    let rev_result = io::copy(&mut &unix, &mut &tcp);
    // Always signal the agent we're done.
    let _ = tcp.shutdown(std::net::Shutdown::Write);

    // Collect the forward direction's result.
    let fwd_result = match fwd.join() {
        Ok(r) => r,
        Err(_) => Err(io::Error::other("tcp-to-unix relay thread panicked")),
    };

    // Surface the first error from either direction.
    fwd_result?;
    rev_result?;
    Ok(())
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// The forwarder must relay bytes in both directions, faithfully and
    /// without modification, between a loopback TCP client and a Unix-socket
    /// server standing in for the egress proxy. This is the core contract:
    /// a transparent byte bridge.
    #[test]
    fn relay_is_byte_transparent_bidirectional() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("proxy.sock");

        // Stand-in "proxy": echo server on the Unix socket that upper-cases
        // a fixed-length request so we can assert both directions moved.
        let unix_listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = unix_listener.accept().unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).unwrap();
            for b in &mut buf {
                b.make_ascii_uppercase();
            }
            s.write_all(&buf).unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
        });

        // Bind a TCP listener and run a single relay against one accepted
        // connection (bypassing fork — we test the relay logic directly).
        let (tcp_listener, port) = bind_ephemeral().unwrap();

        let sock_for_relay = sock_path.clone();
        let relay_thread = std::thread::spawn(move || {
            let (tcp, _) = tcp_listener.accept().unwrap();
            relay(tcp, &sock_for_relay).unwrap();
        });

        let mut client = std::net::TcpStream::connect((LOOPBACK_HOST, port)).unwrap();
        client.write_all(b"hello").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let mut resp = [0u8; 5];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"HELLO");

        relay_thread.join().unwrap();
        server.join().unwrap();
    }

    /// A large payload (multiple relay buffers) must arrive intact, proving
    /// the copy loop handles partial reads/writes and buffer boundaries.
    #[test]
    fn relay_handles_payloads_larger_than_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("proxy.sock");
        // Payload spanning several internal copy buffers (>64 KiB) to
        // exercise partial reads/writes and buffer boundaries.
        let payload: Vec<u8> = (0..(64 * 1024 * 4 + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        let expected = payload.clone();
        let expected_len = expected.len();

        let unix_listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = unix_listener.accept().unwrap();
            // Drain everything the client sends, echo it back verbatim.
            let mut got = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = s.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&chunk[..n]);
                if got.len() == expected_len {
                    break;
                }
            }
            s.write_all(&got).unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
            got
        });

        let (tcp_listener, port) = bind_ephemeral().unwrap();
        let sock_for_relay = sock_path.clone();
        let relay_thread = std::thread::spawn(move || {
            let (tcp, _) = tcp_listener.accept().unwrap();
            relay(tcp, &sock_for_relay).unwrap();
        });

        let mut client = std::net::TcpStream::connect((LOOPBACK_HOST, port)).unwrap();
        client.write_all(&payload).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let mut back = Vec::new();
        client.read_to_end(&mut back).unwrap();
        assert_eq!(back, expected, "echoed payload must match byte-for-byte");

        let server_got = server.join().unwrap();
        assert_eq!(server_got, expected, "server must receive payload intact");
        relay_thread.join().unwrap();
    }

    /// Connecting to a non-existent proxy socket must surface an error from
    /// the relay rather than hanging or panicking — the forwarder reports
    /// and drops the connection.
    #[test]
    fn relay_errors_when_proxy_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");

        let (tcp_listener, port) = bind_ephemeral().unwrap();
        let relay_thread = std::thread::spawn(move || {
            let (tcp, _) = tcp_listener.accept().unwrap();
            relay(tcp, &missing)
        });

        let _client = std::net::TcpStream::connect((LOOPBACK_HOST, port)).unwrap();

        let result = relay_thread.join().unwrap();
        assert!(result.is_err(), "relay must error on missing proxy socket");
    }

    /// `bind_ephemeral` must yield a usable loopback port that round-trips
    /// through `local_addr`. Pure userspace; no namespace required.
    #[test]
    fn bind_ephemeral_returns_live_loopback_port() {
        let (listener, port) = bind_ephemeral().unwrap();
        assert_ne!(port, 0, "kernel must assign a non-zero port");
        let local = listener.local_addr().unwrap();
        assert!(local.ip().is_loopback());
        assert_eq!(local.port(), port);

        // A synchronous client can connect to the bound listener.
        let accept = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut b = [0u8; 3];
            s.read_exact(&mut b).unwrap();
            s.write_all(&b).unwrap();
        });
        let mut c = std::net::TcpStream::connect((LOOPBACK_HOST, port)).unwrap();
        c.write_all(b"abc").unwrap();
        let mut back = [0u8; 3];
        c.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"abc");
        accept.join().unwrap();
    }

    // -- Port handshake encoding -----------------------------------------------

    /// Port encoding must round-trip every value faithfully. Boundary
    /// values exercise the big-endian byte swap.
    #[test]
    fn port_encoding_round_trips_boundary_values() {
        for port in [1u16, 80, 443, 1023, 1024, 8080, 49152, u16::MAX] {
            let encoded = encode_port(port);
            let decoded = decode_port(encoded);
            assert_eq!(decoded, port, "round-trip failed for port {port}");
        }
    }

    /// The wire format is big-endian: high byte first. This is a
    /// byte-level contract between the forwarder child and the parent.
    #[test]
    fn port_encoding_is_big_endian() {
        let encoded = encode_port(0x1234);
        assert_eq!(encoded, [0x12, 0x34]);
    }

    // -- Port handshake over pipe -----------------------------------------------

    /// A pipe write→read round-trip must faithfully deliver the port.
    /// Exercises the actual syscall path used in production.
    #[test]
    fn port_pipe_round_trip() {
        let mut fds = [0i32; 2];
        // SAFETY: pipe2 with valid pointer and flags.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let (pipe_r, pipe_w) = (fds[0], fds[1]);

        let port: u16 = 38_721;
        assert!(write_port_to_pipe(pipe_w, port));
        // pipe_w is closed by write_port_to_pipe.

        let got = read_port_from_pipe(pipe_r).unwrap();
        // pipe_r is closed by read_port_from_pipe.
        assert_eq!(got, port);
    }

    /// If the write end closes before sending data (child died during
    /// bind), `read_port_from_pipe` must return a clear error.
    #[test]
    fn port_pipe_eof_yields_error() {
        let mut fds = [0i32; 2];
        // SAFETY: pipe2 with valid pointer and flags.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let (pipe_r, pipe_w) = (fds[0], fds[1]);

        // Simulate child death: close write end without writing.
        // SAFETY: pipe_w is a valid fd.
        unsafe { libc::close(pipe_w) };

        let result = read_port_from_pipe(pipe_r);
        assert!(result.is_err(), "EOF on pipe must surface as error");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("exited before reporting port"),
            "error must be actionable: {msg}"
        );
    }

    /// Port 0 is never valid (the kernel assigns ephemeral ports ≥ 1024).
    /// If the child somehow writes port 0, reject it.
    #[test]
    fn port_pipe_rejects_zero() {
        let mut fds = [0i32; 2];
        // SAFETY: pipe2 with valid pointer and flags.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let (pipe_r, pipe_w) = (fds[0], fds[1]);

        assert!(write_port_to_pipe(pipe_w, 0));
        let result = read_port_from_pipe(pipe_r);
        assert!(result.is_err(), "port 0 must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("port 0"), "error must mention port 0: {msg}");
    }

    // -- IfReq structural tests ------------------------------------------------

    #[test]
    fn ifreq_flags_round_trip() {
        let mut ifr = IfReq::zeroed();
        assert_eq!(ifr.flags(), 0, "zeroed ifreq must have flags = 0");

        ifr.set_flags(IFF_UP);
        assert_eq!(ifr.flags(), IFF_UP);

        // Simulate kernel returning IFF_UP | IFF_RUNNING (0x41).
        ifr.set_flags(IFF_UP | 0x40);
        assert_ne!(
            ifr.flags() & IFF_UP,
            0,
            "IFF_UP must survive compound flags"
        );
    }

    #[test]
    fn ifreq_name_lo() {
        let mut ifr = IfReq::zeroed();
        ifr.set_name("lo").unwrap();
        assert_eq!(&ifr.bytes[..2], b"lo");
        assert_eq!(ifr.bytes[2], 0, "name must be NUL-terminated");
    }

    #[test]
    fn ifreq_name_too_long_is_rejected() {
        let mut ifr = IfReq::zeroed();
        let long = "a".repeat(IFNAMSIZ);
        assert!(
            ifr.set_name(&long).is_err(),
            "name >= IFNAMSIZ must be rejected"
        );
    }

    // -- Loopback idempotence --------------------------------------------------

    /// On any Linux host, `lo` is already UP. The idempotent path must
    /// detect IFF_UP and return Ok without issuing SIOCSIFFLAGS — which
    /// would require CAP_NET_ADMIN and fail for unprivileged CI runners.
    ///
    /// This test is the direct proof that the idempotent guard works: on
    /// a non-root CI host, the old (non-idempotent) code would fail with
    /// EPERM at SIOCSIFFLAGS; the fixed code succeeds.
    #[test]
    fn bring_up_loopback_idempotent_when_already_up() {
        // If this environment has no loopback at all (exotic container),
        // the SIOCGIFFLAGS read itself will fail — skip gracefully.
        match bring_up_loopback() {
            Ok(()) => {} // expected: lo was up, idempotent return
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("SIOCGIFFLAGS") {
                    eprintln!("SKIP: no loopback interface in this environment");
                    return;
                }
                panic!("bring_up_loopback failed unexpectedly: {e}");
            }
        }
    }
}
