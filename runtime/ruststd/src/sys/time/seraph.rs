// seraph-overlay: std::sys::time::seraph
//
// `Instant` reads the kernel's microsecond-granularity elapsed counter via
// `SYS_SYSTEM_INFO(SystemInfoType::ElapsedUs)` (see `abi/syscall/src/lib.rs`).
// `SystemTime::now()` discovers the `timed` service via the per-process
// `service_registry_cap` installed by procmgr at spawn, calls
// `timed_labels::GET_WALL_TIME`, and returns the reply as a Duration since
// the Unix epoch. The discovered cap is cached for the rest of the process
// lifetime in a process-global atomic; subsequent calls skip the lookup.
// On registry-miss (no `timed` registered) or any IPC failure, `now()`
// returns `UNIX_EPOCH` — the documented degraded-mode behaviour matching
// `timed_errors::WALL_CLOCK_UNAVAILABLE`.

use crate::time::Duration;
use core::sync::atomic::{AtomicU32, Ordering};

use ipc::{IpcMessage, svcmgr_labels, timed_errors, timed_labels};
use syscall_abi::SystemInfoType;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Instant(Duration);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct SystemTime(Duration);

pub const UNIX_EPOCH: SystemTime = SystemTime(Duration::from_secs(0));

/// Cached SEND cap on `timed`'s service endpoint. Zero means "not yet
/// resolved"; any non-zero value is a valid slot in this process's CSpace
/// for the rest of its lifetime.
static TIMED_CAP: AtomicU32 = AtomicU32::new(0);
/// Set once the first `now()` call has attempted resolution, regardless
/// of success. Prevents repeated registry hits when `timed` is absent.
static TIMED_RESOLVED: AtomicU32 = AtomicU32::new(0);

/// Maximum service-registry name length (must match svcmgr's `NAME_MAX`).
const REGISTRY_NAME_MAX: usize = 64;

/// Pack `name` little-endian-by-byte into u64 words; returns word count.
fn pack_name(name: &[u8], out: &mut [u64; REGISTRY_NAME_MAX / 8]) -> usize {
    for (i, &b) in name.iter().enumerate() {
        out[i / 8] |= u64::from(b) << ((i % 8) * 8);
    }
    name.len().div_ceil(8)
}

/// Resolve `timed` via the per-process svcmgr cap. Returns zero on any
/// failure (no registry cap, lookup miss, IPC error).
fn lookup_timed(ipc_buf: *mut u64) -> u32 {
    let registry_cap = crate::os::seraph::startup_info().service_registry_cap;
    let name: &[u8] = b"timed";
    if registry_cap == 0 || name.is_empty() || name.len() > REGISTRY_NAME_MAX {
        return 0;
    }

    let mut words = [0u64; REGISTRY_NAME_MAX / 8];
    let word_count = pack_name(name, &mut words);

    let mut builder =
        IpcMessage::builder(svcmgr_labels::QUERY_ENDPOINT | ((name.len() as u64) << 16));
    for (i, &w) in words.iter().take(word_count).enumerate() {
        builder = builder.word(i, w);
    }
    let request = builder.build();

    // SAFETY: ipc_buf is the registered IPC buffer page for this thread.
    let Ok(reply) = (unsafe { ipc::ipc_call(registry_cap, &request, ipc_buf) }) else {
        return 0;
    };
    if reply.label != ipc::svcmgr_errors::SUCCESS {
        return 0;
    }
    reply.caps().first().copied().filter(|&c| c != 0).unwrap_or(0)
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

        let cap = match TIMED_CAP.load(Ordering::Acquire) {
            0 if TIMED_RESOLVED.load(Ordering::Acquire) == 0 => {
                let resolved = lookup_timed(ipc_buf);
                if resolved != 0 {
                    TIMED_CAP.store(resolved, Ordering::Release);
                }
                TIMED_RESOLVED.store(1, Ordering::Release);
                resolved
            }
            c => c,
        };
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
