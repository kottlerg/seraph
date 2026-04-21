// seraph-overlay: std::sys::time::seraph
//
// `Instant` reads the kernel's microsecond-granularity elapsed counter via
// `SYS_SYSTEM_INFO(SystemInfoType::ElapsedUs)` (see
// `abi/syscall/src/lib.rs:349`). `SystemTime` has no kernel backing — we
// do not yet have a wall-clock syscall — so it preserves the upstream
// `unsupported` behaviour: the struct exists, but `now()` panics. Callers
// that need wall-clock time get a clear failure rather than a silent zero.

use crate::time::Duration;

use syscall_abi::SystemInfoType;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Instant(Duration);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct SystemTime(Duration);

pub const UNIX_EPOCH: SystemTime = SystemTime(Duration::from_secs(0));

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
        panic!("SystemTime not implemented on seraph — no wall-clock syscall")
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
