//! Seccomp-BPF syscall filter for sandboxed agents.
//!
//! Defense-in-depth: the namespace already restricts most operations, but
//! seccomp adds an independent enforcement layer. A kernel namespace escape
//! CVE that grants the agent capabilities it shouldn't have still hits the
//! seccomp wall.
//!
//! Policy: **blocklist** with argument filtering for `clone`. The agent may
//! use any syscall except the ones listed below. Blocked syscalls return
//! `EPERM` (not `KILL_PROCESS`) so the agent gets a clean error.
//!
//! # Namespace creation defense
//!
//! Three independent layers prevent the agent from creating nested
//! namespaces (a common sandbox escape vector):
//!
//! 1. `unshare` — unconditionally blocked (EPERM).
//! 2. `clone` — argument filter blocks calls with any namespace creation
//!    flag (all 8 types, including `CLONE_NEWTIME`). Normal `fork`/`clone`
//!    (thread creation) is allowed.
//! 3. `clone3` — returns ENOSYS. glibc falls back to `clone` (which hits
//!    the argument filter). `clone3` takes a pointer to `clone_args`, so
//!    BPF cannot inspect its flags — ENOSYS is the only safe option.
//!
//! # io_uring defense
//!
//! On kernels < 5.12, `io_uring` submissions with `IORING_SETUP_SQPOLL`
//! bypass seccomp entirely. All three io_uring syscalls are blocked to
//! close this vector. On ≥ 5.12 this is defense-in-depth.
//!
//! # Fileless execution defense
//!
//! `memfd_create` is blocked to prevent anonymous-fd ELF execution via
//! `execveat`/`fexecve`, which would bypass filesystem integrity controls.
//!
//! # Fail-closed
//!
//! If seccomp-bpf installation fails for any reason, the sandbox refuses
//! to start. There is no degraded mode.
//!
//! Applied in the grandchild after `drop_privileges()` and before `exec()`.
//! `PR_SET_NO_NEW_PRIVS` (inherited from the intermediate child) is a
//! prerequisite for unprivileged seccomp.
//!
//! Uses `seccomp(2)` with `SECCOMP_FILTER_FLAG_TSYNC` rather than
//! `prctl(PR_SET_SECCOMP)`. TSYNC synchronizes the filter across all
//! threads of the calling process. In the single-threaded grandchild this
//! is a no-op, but it closes a future-proofing gap: if any code between
//! the double-fork and seccomp installation ever spawns a thread, TSYNC
//! either filters it or fails the call — preventing a silently unfiltered
//! thread. A thread-count assertion provides a clear diagnostic before the
//! syscall.

use crate::SandboxError;

// Syscall numbers not yet available in all libc crate versions

// New mount API (Linux 5.2+). These syscall numbers are identical on
// x86_64 and aarch64 — both architectures assigned them from the shared
// generic range (include/uapi/asm-generic/unistd.h).
//
// Defined locally rather than relying on a specific libc crate version
// to guarantee compilation across all supported dependency versions.
const SYS_OPEN_TREE: libc::c_long = 428;
const SYS_MOVE_MOUNT: libc::c_long = 429;
const SYS_FSOPEN: libc::c_long = 430;
const SYS_FSCONFIG: libc::c_long = 431;
const SYS_FSMOUNT: libc::c_long = 432;
const SYS_FSPICK: libc::c_long = 433;

// mount_setattr (Linux 5.12+). Same generic range.
const SYS_MOUNT_SETATTR: libc::c_long = 442;

// io_uring (Linux 5.1+). Generic range — identical on x86_64 and aarch64.
// On kernels < 5.12, io_uring submissions with IORING_SETUP_SQPOLL bypass
// seccomp entirely. Blocking the setup syscall prevents this.
const SYS_IO_URING_SETUP: libc::c_long = 425;
const SYS_IO_URING_ENTER: libc::c_long = 426;
const SYS_IO_URING_REGISTER: libc::c_long = 427;

// pidfd (Linux 5.3+ / 5.6+). Generic range.
// pidfd_getfd can duplicate a file descriptor from another process.
const SYS_PIDFD_OPEN: libc::c_long = 434;
const SYS_PIDFD_GETFD: libc::c_long = 438;

// process_madvise (Linux 5.10+). Generic range.
// Allows a process to influence another process's memory advice flags.
// Defense-in-depth alongside PID namespace isolation.
const SYS_PROCESS_MADVISE: libc::c_long = 440;

// landlock (Linux 5.13+). Generic range.
// Agents should not install their own filesystem access rules — the
// sandbox controls all filesystem visibility. Allowing landlock would
// let an agent restrict its own access in ways that interfere with
// sandbox-mediated operations (e.g. blocking access to the gate socket
// after it has been bind-mounted).
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

// Memory protection keys (Linux 4.9+). x86_64: 329-331; aarch64: N/A
// (not implemented on ARM). Blocking on both architectures is harmless
// (ENOSYS on aarch64, EPERM on x86_64). No legitimate agent use case.
#[cfg(target_arch = "x86_64")]
const SYS_PKEY_MPROTECT: libc::c_long = 329;
#[cfg(target_arch = "x86_64")]
const SYS_PKEY_ALLOC: libc::c_long = 330;
#[cfg(target_arch = "x86_64")]
const SYS_PKEY_FREE: libc::c_long = 331;

// Blocked syscalls (unconditional)

/// Syscalls unconditionally blocked inside the sandbox.
///
/// **Filesystem namespace manipulation** — the mount tree is frozen after
/// `pivot_root`. The agent must not modify it. Covers both the classic
/// mount API (`mount`, `umount2`, `pivot_root`) and the newer mount API
/// (`open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`,
/// `mount_setattr`). The newer API provides an independent path to mount
/// manipulation and must be blocked separately from capabilities.
///
/// **Namespace creation / entry** — `unshare` and `setns` blocked here;
/// `clone`/`clone3` handled separately with argument filtering (see
/// `build_filter`). `setns` blocks entering existing namespaces by fd.
///
/// **Process introspection** — prevent debugging, memory access, or kernel
/// object comparison across processes (defense-in-depth over PID namespace).
///
/// **Kernel modification** — loading modules, kexec, reboot.
///
/// **System state** — swap, accounting, clock, hostname.
///
/// **Kernel facilities** — BPF, perf, userfaultfd reduce attack surface.
/// `io_uring` blocked because kernel < 5.12 allows seccomp bypass via
/// `IORING_SETUP_SQPOLL`. `pidfd_open`/`pidfd_getfd` blocked to prevent
/// cross-process fd duplication if PID namespace isolation weakens.
/// `memfd_create` blocked to prevent fileless ELF execution.
///
/// **Keyring** — prevent kernel keyring manipulation.
///
/// **SysV IPC** — shared memory, message queues, and semaphores blocked
/// as defense-in-depth alongside `CLONE_NEWIPC`. Even with an isolated
/// IPC namespace, a kernel bug that leaks namespace isolation would still
/// hit this wall. Agents have no legitimate use for SysV IPC (POSIX
/// threads, pipes, and Unix sockets are available and preferred).
///
/// **POSIX message queues** — `mq_open`, `mq_unlink`, `mq_timedsend`,
/// `mq_timedreceive`, `mq_notify`, and `mq_getsetattr` use dedicated
/// `mq_*` syscalls that are independent of the SysV `msg*` path above.
/// Belt-and-suspenders alongside `RLIMIT_MSGQUEUE = 0`.
const BLOCKED: &[libc::c_long] = &[
    // Filesystem namespace manipulation — classic mount API
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    // Filesystem namespace manipulation — new mount API (Linux 5.2+)
    SYS_OPEN_TREE,
    SYS_MOVE_MOUNT,
    SYS_FSOPEN,
    SYS_FSCONFIG,
    SYS_FSMOUNT,
    SYS_FSPICK,
    SYS_MOUNT_SETATTR,
    // Namespace creation (unconditional block)
    libc::SYS_unshare,
    // Namespace entry by fd
    libc::SYS_setns,
    // Process introspection / manipulation
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_kcmp,
    // Kernel modification
    libc::SYS_kexec_load,
    // kexec_file_load(2) — libc exports this for x86_64 but not for aarch64
    // musl (as of libc 0.2.186). Use the raw syscall number on architectures
    // where the binding is missing. The number is stable Linux ABI (assigned
    // in 5.13 for aarch64). Omitting it would leave kexec unblocked — a
    // sandbox escape vector.
    #[cfg(target_arch = "x86_64")]
    libc::SYS_kexec_file_load,
    #[cfg(target_arch = "aarch64")]
    294, // __NR_kexec_file_load
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    // System state
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_acct,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
    // Kernel facilities
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    // NOTE: kernel ≥ 5.11 added UFFD_FEATURE_UNPRIVILEGED which allows
    // userfaultfd creation via ioctl on /dev/userfaultfd. The sandbox mount
    // tree exposes only /dev/{null,urandom,zero} — /dev/userfaultfd is
    // absent — so the ioctl vector is closed. If the mount tree is ever
    // broadened to expose /dev more liberally, revisit this.
    // io_uring — on kernels < 5.12 with IORING_SETUP_SQPOLL, submitted
    // syscalls bypass seccomp entirely. Blocking setup prevents this.
    // On ≥ 5.12 this is defense-in-depth (seccomp applies to io_uring
    // submissions), but agents have no legitimate use for io_uring.
    SYS_IO_URING_SETUP,
    SYS_IO_URING_ENTER,
    SYS_IO_URING_REGISTER,
    // pidfd — pidfd_getfd duplicates an fd from another process. PID
    // namespace isolation limits the blast radius, but blocking these
    // prevents fd-theft if the PID boundary is ever weakened.
    SYS_PIDFD_OPEN,
    SYS_PIDFD_GETFD,
    // Fileless execution — memfd_create creates an anonymous fd that can
    // hold an ELF binary for execution via execveat/fexecve, bypassing
    // any filesystem integrity controls. No legitimate agent use case.
    libc::SYS_memfd_create,
    // SysV IPC — defense-in-depth alongside CLONE_NEWIPC namespace.
    // Blocked: shared memory, message queues, semaphores.
    libc::SYS_shmget,
    libc::SYS_shmat,
    libc::SYS_shmctl,
    libc::SYS_shmdt,
    libc::SYS_msgget,
    libc::SYS_msgsnd,
    libc::SYS_msgrcv,
    libc::SYS_msgctl,
    libc::SYS_semget,
    libc::SYS_semop,
    libc::SYS_semctl,
    libc::SYS_semtimedop,
    // POSIX message queues — defense-in-depth alongside RLIMIT_MSGQUEUE = 0.
    // POSIX mq uses dedicated mq_* syscalls (not the SysV msg* path above),
    // providing an independent IPC channel that must be blocked separately.
    libc::SYS_mq_open,
    libc::SYS_mq_unlink,
    libc::SYS_mq_timedsend,
    libc::SYS_mq_timedreceive,
    libc::SYS_mq_notify,
    libc::SYS_mq_getsetattr,
    // Keyring
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_keyctl,
    // Cross-process memory advice — defense-in-depth alongside PID ns.
    SYS_PROCESS_MADVISE,
    // Landlock — sandbox controls filesystem visibility; agents must not
    // install their own rules that could interfere with gate socket access.
    SYS_LANDLOCK_CREATE_RULESET,
    SYS_LANDLOCK_ADD_RULE,
    SYS_LANDLOCK_RESTRICT_SELF,
];

// Namespace creation flags (from linux/sched.h)

/// Bitmask of all clone flags that create new namespaces.
///
/// If any of these bits are set in `clone`'s flags argument, the call is
/// attempting to create a new namespace — blocked with EPERM.
///
/// Covers all 8 namespace types including `CLONE_NEWTIME` (Linux 5.6+).
const NAMESPACE_FLAGS_MASK: u32 = 0x0000_0080  // CLONE_NEWTIME
    | 0x0002_0000  // CLONE_NEWNS
    | 0x0200_0000  // CLONE_NEWCGROUP
    | 0x0400_0000  // CLONE_NEWUTS
    | 0x0800_0000  // CLONE_NEWIPC
    | 0x1000_0000  // CLONE_NEWUSER
    | 0x2000_0000  // CLONE_NEWPID
    | 0x4000_0000; // CLONE_NEWNET

// BPF program construction

// BPF instruction encoding (from linux/filter.h).
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
#[cfg(target_arch = "x86_64")]
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// x32 ABI marker (x86_64 only). The x32 ABI shares AUDIT_ARCH_X86_64 but
// sets bit 30 (`__X32_SYSCALL_BIT`) in the syscall number. A syscall issued
// with this bit set has a number that does not equal any entry in the
// blocklist (which holds bare numbers), so without an explicit guard an x32
// caller bypasses every number-matched block. There is no legitimate x32
// use inside the sandbox, so such calls are killed.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// seccomp return actions (from linux/seccomp.h).
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

// seccomp(2) syscall constants (from linux/seccomp.h).
// Used with libc::SYS_seccomp instead of the older prctl interface.
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;

// SECCOMP_FILTER_FLAG_TSYNC: synchronize the filter across all threads of
// the calling process. If any thread cannot be synchronized (e.g. it has a
// more restrictive filter from a different ancestor), the call fails. This
// turns "silent unfiltered thread" into a hard startup failure.
const SECCOMP_FILTER_FLAG_TSYNC: libc::c_ulong = 1;

// seccomp_data field offsets (from linux/seccomp.h).
const OFFSET_NR: u32 = 0; // offsetof(seccomp_data, nr)
const OFFSET_ARCH: u32 = 4; // offsetof(seccomp_data, arch)
const OFFSET_ARGS_0_LO: u32 = 16; // offsetof(seccomp_data, args[0]), low 32 bits (LE)

// Architecture audit constants.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

/// Single BPF instruction.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// BPF program descriptor for seccomp.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Build the BPF filter program.
///
/// ```text
/// [0]  LD    arch
/// [1]  JEQ   AUDIT_ARCH_NATIVE => [3]       else [2]
/// [2]  RET   KILL_PROCESS                   ← wrong architecture
/// [3]  LD    syscall number
///
///      ── x32 ABI guard (x86_64 only) ──
/// [x]  JGE   X32_SYSCALL_BIT => KILL_PROCESS  ← x32 bypasses blocklist
///
///      ── clone3: force glibc fallback ──
/// [4]  JEQ   SYS_clone3 => [5]              else [6]
/// [5]  RET   ERRNO(ENOSYS)                  ← glibc retries with clone
///
///      ── clone: block namespace flags ──
/// [6]  JEQ   SYS_clone => [7]               else [12]
/// [7]  LD    args[0] (clone flags)
/// [8]  AND   NAMESPACE_FLAGS_MASK
/// [9]  JEQ   0 => [11]                      else [10]
/// [10] RET   ERRNO(EPERM)                   ← namespace creation denied
/// [11] RET   ALLOW                          ← normal fork/thread allowed
///
///      ── unconditional blocklist ──
/// [12] LD    syscall number                 ← reload (clobbered by [7])
/// [13] JEQ   blocked[0] => [14]             else [15]
/// [14] RET   ERRNO(EPERM)
///      ...
/// [N]  RET   ALLOW                          ← default
/// ```
fn build_filter() -> Vec<SockFilter> {
    // 13 fixed instructions + 2 per blocked syscall + arch-specific + 1 default ALLOW.
    // x86_64 additionally emits a 2-instruction x32 ABI guard.
    #[cfg(target_arch = "x86_64")]
    let arch_blocked_count = 3; // pkey_mprotect, pkey_alloc, pkey_free
    #[cfg(not(target_arch = "x86_64"))]
    let arch_blocked_count = 0;

    #[cfg(target_arch = "x86_64")]
    let x32_guard_count = 2;
    #[cfg(not(target_arch = "x86_64"))]
    let x32_guard_count = 0;

    let mut f =
        Vec::with_capacity(13 + x32_guard_count + (BLOCKED.len() + arch_blocked_count) * 2 + 1);

    let deny_eperm = SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xFFFF);
    let deny_enosys = SECCOMP_RET_ERRNO | (libc::ENOSYS as u32 & 0xFFFF);

    // ── Architecture validation ──

    // [0] Load architecture.
    f.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH));
    // [1] If native arch: skip to [3]. Otherwise: fall to [2].
    f.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_NATIVE, 1, 0));
    // [2] Wrong architecture — kill.
    f.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // ── Load syscall number ──

    // [3] Load syscall number into accumulator.
    f.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));

    // ── x32 ABI guard (x86_64 only) ──
    //
    // The x32 ABI shares AUDIT_ARCH_X86_64 but sets __X32_SYSCALL_BIT in the
    // syscall number. Such a number matches no bare entry in the blocklist,
    // so an x32 caller would slip past every number-matched block (including
    // the namespace-flag clone filter). No legitimate sandboxed agent uses
    // x32; kill any syscall carrying the bit. KILL (not EPERM) matches the
    // wrong-architecture handling above — there is no clean error to return
    // for an ABI the sandbox does not support.
    #[cfg(target_arch = "x86_64")]
    {
        // If nr >= X32_SYSCALL_BIT: fall through to KILL. Otherwise skip it.
        f.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1));
        f.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    }

    // ── clone3 => ENOSYS (glibc falls back to clone) ──
    //
    // clone3 takes a pointer to struct clone_args, so BPF cannot inspect
    // its flags field. Returning ENOSYS makes glibc fall back to the
    // older clone syscall, where we CAN inspect the flags argument.

    // [4] If SYS_clone3: fall to [5]. Otherwise: skip to [6].
    f.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_clone3 as u32,
        0,
        1,
    ));
    // [5] clone3 => ENOSYS.
    f.push(stmt(BPF_RET | BPF_K, deny_enosys));

    // ── clone with namespace flags => EPERM ──
    //
    // The first argument to clone is `unsigned long flags`. If any
    // namespace creation bit is set (all 8 types), deny. Otherwise
    // allow (normal fork/thread creation).

    // [6] If SYS_clone: fall to [7]. Otherwise: skip 5 to [12].
    f.push(jump(
        BPF_JMP | BPF_JEQ | BPF_K,
        libc::SYS_clone as u32,
        0,
        5,
    ));
    // [7] Load clone flags (args[0], low 32 bits on little-endian).
    f.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARGS_0_LO));
    // [8] Mask with namespace flags.
    f.push(stmt(BPF_ALU | BPF_AND | BPF_K, NAMESPACE_FLAGS_MASK));
    // [9] If result is 0 (no namespace flags): skip to [11] ALLOW.
    //     If non-zero (has namespace flags): fall to [10] DENY.
    f.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0));
    // [10] Namespace creation attempted — deny.
    f.push(stmt(BPF_RET | BPF_K, deny_eperm));
    // [11] Normal fork/thread — allow.
    f.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    // ── Unconditional blocklist ──

    // [12] Reload syscall number (accumulator was clobbered by [7]).
    f.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));

    // [13..] Each blocked syscall: match => deny, no match => skip 1.
    for &nr in BLOCKED {
        f.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1));
        f.push(stmt(BPF_RET | BPF_K, deny_eperm));
    }

    // ── Architecture-specific blocklist ──
    //
    // Memory protection keys (pkey) are x86_64-only. The syscall numbers
    // are architecture-specific (329-331 on x86_64), so we emit them
    // conditionally to avoid blocking unrelated syscalls on aarch64.
    #[cfg(target_arch = "x86_64")]
    for &nr in &[SYS_PKEY_MPROTECT, SYS_PKEY_ALLOC, SYS_PKEY_FREE] {
        f.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1));
        f.push(stmt(BPF_RET | BPF_K, deny_eperm));
    }

    // Default: allow.
    f.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    f
}

// Public API

/// Install the seccomp-BPF filter on the calling process.
///
/// Must be called after `PR_SET_NO_NEW_PRIVS` (prerequisite for
/// unprivileged seccomp) and before `exec()`. The filter is inherited
/// by the exec'd process and all its children.
///
/// Uses `seccomp(2)` with `SECCOMP_FILTER_FLAG_TSYNC` instead of the
/// older `prctl(PR_SET_SECCOMP)` interface. TSYNC synchronizes the filter
/// across all threads of the calling process. In the single-threaded
/// grandchild this is a no-op, but if the invariant is violated (a thread
/// exists that shouldn't), TSYNC either applies the filter to it or fails
/// the call — turning a silent "thread runs unfiltered" into a hard startup
/// failure. Defense-in-depth against future code adding threaded work
/// between the double-fork and seccomp installation.
///
/// A thread-count assertion before the syscall provides a clear diagnostic
/// when the invariant is violated, rather than relying on TSYNC's error
/// (which reports ESRCH for threads that can't be synchronized, an
/// opaque signal).
///
/// **Fail-closed:** returns `Err` if the filter cannot be installed.
/// The sandbox must not start the agent without a seccomp filter.
pub(crate) fn apply() -> Result<(), SandboxError> {
    // Defense-in-depth: verify the single-threaded invariant that the
    // seccomp filter relies on. The grandchild is single-threaded after
    // the double-fork — no tokio runtime, no TLS threads, no background
    // workers. If anything between fork() and here spawned a thread,
    // catch it before the filter is installed.
    assert_single_threaded()?;

    let filter = build_filter();
    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    // SAFETY: seccomp(2) with SECCOMP_SET_MODE_FILTER installs a BPF
    // filter. The SockFprog points to a valid, correctly-sized filter
    // array that outlives this call. PR_SET_NO_NEW_PRIVS is already set
    // (checked by the kernel — fails with EACCES if not).
    // SECCOMP_FILTER_FLAG_TSYNC synchronizes the filter across all threads;
    // in the single-threaded grandchild this is a no-op.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &prog as *const SockFprog,
        )
    };

    if ret != 0 {
        return Err(SandboxError::NamespaceSetup(format!(
            "seccomp(SECCOMP_SET_MODE_FILTER, TSYNC) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    tracing::debug!(
        blocked_syscalls = BLOCKED.len(),
        "seccomp filter installed with TSYNC (clone3 => ENOSYS, clone ns-flags => EPERM)"
    );
    Ok(())
}

/// Verify the calling process has exactly one thread.
///
/// Reads `/proc/self/task/` — each entry is a thread. The grandchild must
/// be single-threaded at seccomp installation time; any additional thread
/// would either run unfiltered (without TSYNC) or cause TSYNC to fail with
/// an unhelpful ESRCH. This assertion provides a clear diagnostic.
fn assert_single_threaded() -> Result<(), SandboxError> {
    let count = match std::fs::read_dir("/proc/self/task") {
        Ok(entries) => entries.count(),
        Err(e) => {
            // /proc not mounted inside the sandbox mount tree is unexpected
            // but possible. Log and proceed — TSYNC itself will catch any
            // threading issue.
            tracing::warn!("cannot read /proc/self/task: {e} — skipping thread-count assertion");
            return Ok(());
        }
    };
    if count != 1 {
        return Err(SandboxError::NamespaceSetup(format!(
            "seccomp: expected 1 thread before filter installation, found {count} — \
             the grandchild must be single-threaded after the double-fork"
        )));
    }
    Ok(())
}
