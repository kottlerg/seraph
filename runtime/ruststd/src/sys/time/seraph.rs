// seraph-overlay: std::sys::time::seraph
//
// `Instant` reads the kernel's microsecond-granularity elapsed counter via
// `SYS_SYSTEM_INFO(SystemInfoType::ElapsedUs)` (see `abi/syscall/src/lib.rs`).
// `SystemTime::now()` discovers the `timed` service via the per-process
// `service_registry_cap` (installed by `_start` from `ProcessInfo` into
// `registry_client::REGISTRY_CAP`), calls `timed_labels::GET_WALL_TIME`,
// and returns the reply as a Duration since the Unix epoch. The discovered
// cap is cached for the rest of the process lifetime in a process-global
// atomic; subsequent calls skip the lookup. On registry-miss (no `timed`
// registered) or any IPC failure, `now()` returns `UNIX_EPOCH` — the
// documented degraded-mode behaviour matching
// `timed_errors::WALL_CLOCK_UNAVAILABLE`.

use crate::time::Duration;
use core::sync::atomic::{AtomicU32, Ordering};

use ipc::{IpcMessage, timed_errors, timed_labels};
use syscall_abi::SystemInfoType;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Instant(Duration);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct SystemTime(Duration);

pub const UNIX_EPOCH: SystemTime = SystemTime(Duration::from_secs(0));

/// Cached SEND cap on `timed`'s service endpoint. Zero means "not yet
/// resolved or resolution failed"; any non-zero value is a valid slot in
/// this process's CSpace for the rest of its lifetime.
static TIMED_CAP: AtomicU32 = AtomicU32::new(0);

/// Resolution state machine for `TIMED_CAP`:
/// `0` = untried, `1` = resolving (some thread is doing the registry
/// lookup), `2` = resolved (success or terminal failure; readers should
/// load `TIMED_CAP` and accept it as final).
static TIMED_RESOLVED: AtomicU32 = AtomicU32::new(0);

/// Resolve `timed` exactly once per process, even under concurrent
/// `SystemTime::now()` calls. Returns zero on failure.
///
/// Liveness: the gate is designed to survive a resolver that panics
/// or is killed mid-lookup — a single hung `SystemTime::now()` must
/// not propagate to the whole process. Waiting threads bound their
/// spin to `SPIN_BUDGET` `pause` iterations, then perform the lookup
/// themselves. The straggler tries to install its result via a second
/// compare-exchange; on collision (resolver finished first) it deletes
/// its now-redundant cap and returns the resolver's. This bounds
/// CSpace consumption to one slot per stuck-resolver event.
fn timed_cap_once(ipc_buf: *mut u64) -> u32
{
    const SPIN_BUDGET: u32 = 1 << 20;
    let c = TIMED_CAP.load(Ordering::Acquire);
    if c != 0
    {
        return c;
    }
    let mut spins: u32 = 0;
    loop
    {
        match TIMED_RESOLVED.compare_exchange(
            0,
            1,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        {
            Ok(_) =>
            {
                // We claimed the resolution duty.
                // SAFETY: ipc_buf is the registered IPC buffer page.
                let resolved = unsafe { registry_client::lookup(b"timed", ipc_buf) }.unwrap_or(0);
                if resolved != 0
                {
                    TIMED_CAP.store(resolved, Ordering::Release);
                }
                TIMED_RESOLVED.store(2, Ordering::Release);
                return resolved;
            }
            Err(2) => return TIMED_CAP.load(Ordering::Acquire),
            // 1 means another thread is resolving. Spin briefly, then
            // give up on the wait and do our own lookup so a panicked
            // or cancelled resolver cannot wedge us forever.
            Err(_) =>
            {
                spins += 1;
                if spins > SPIN_BUDGET
                {
                    // SAFETY: ipc_buf is the registered IPC buffer page.
                    let fallback = unsafe { registry_client::lookup(b"timed", ipc_buf) }
                        .unwrap_or(0);
                    if fallback == 0
                    {
                        return 0;
                    }
                    // Try to install our result. If the resolver finished
                    // first and stored its own cap, delete ours and use
                    // theirs — keeps the per-process CSpace bounded.
                    match TIMED_CAP.compare_exchange(
                        0,
                        fallback,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    {
                        Ok(_) => return fallback,
                        Err(installed) =>
                        {
                            let _ = syscall::cap_delete(fallback);
                            return installed;
                        }
                    }
                }
                core::hint::spin_loop();
            }
        }
    }
}

impl Instant {
    pub fn now() -> Instant {
        // SystemInfoType::ElapsedUs returns microseconds since kernel timer
        // init, or 0 if the timer is not yet live. Treat the pre-timer
        // interval as a zero-point rather than panicking — any derived
        // Duration is still monotonic and consistent across calls.
        let us = syscall::system_info(SystemInfoType::ElapsedUs as u64).unwrap_or(0);
        Instant(Duration::from_micros(us))
    }

    pub fn checked_sub_instant(&self, other: &Instant) -> Option<Duration> {
        self.0.checked_sub(other.0)
    }

    pub fn checked_add_duration(&self, other: &Duration) -> Option<Instant> {
        Some(Instant(self.0.checked_add(*other)?))
    }

    pub fn checked_sub_duration(&self, other: &Duration) -> Option<Instant> {
        Some(Instant(self.0.checked_sub(*other)?))
    }
}

impl SystemTime {
    pub const MAX: SystemTime = SystemTime(Duration::MAX);
    pub const MIN: SystemTime = SystemTime(Duration::ZERO);

    pub fn now() -> SystemTime {
        let ipc_buf = crate::os::seraph::current_ipc_buf();
        if ipc_buf.is_null() {
            return UNIX_EPOCH;
        }

        let cap = timed_cap_once(ipc_buf);
        if cap == 0 {
            return UNIX_EPOCH;
        }

        let request = IpcMessage::new(timed_labels::GET_WALL_TIME);
        // SAFETY: ipc_buf is the registered IPC buffer page for this thread.
        let Ok(reply) = (unsafe { ipc::ipc_call(cap, &request, ipc_buf) }) else {
            return UNIX_EPOCH;
        };
        if reply.label != timed_errors::SUCCESS {
            return UNIX_EPOCH;
        }
        SystemTime(Duration::from_micros(reply.word(0)))
    }

    pub fn sub_time(&self, other: &SystemTime) -> Result<Duration, Duration> {
        self.0.checked_sub(other.0).ok_or_else(|| other.0 - self.0)
    }

    pub fn checked_add_duration(&self, other: &Duration) -> Option<SystemTime> {
        Some(SystemTime(self.0.checked_add(*other)?))
    }

    pub fn checked_sub_duration(&self, other: &Duration) -> Option<SystemTime> {
        Some(SystemTime(self.0.checked_sub(*other)?))
    }
}
