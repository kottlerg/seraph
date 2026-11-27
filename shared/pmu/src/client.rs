// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/pmu/src/client.rs

//! The user API: describe and program the calling CPU's counters through a
//! `PmuControl` capability, grant a thread their reads, and read them
//! directly (`RDPMC` on x86-64, `csrr hpmcounterN` on riscv64).
//!
//! A value is the calling CPU's, valid while the reader stays pinned there,
//! and counts all work on that CPU in the configuration's mode. A measuring
//! thread pins itself to one CPU and yields once, so that it runs there, then
//! calls [`Pmu::configure`] and [`Counters::bind`] on itself
//! (docs/capability-model.md § `PmuControl`).

use core::marker::PhantomData;

use syscall_abi::{PMU_CONFIGURE_MAX, SyscallError};

use crate::{EventList, Info, PmuEvent, PmuMode, entry};

/// A `PmuControl` capability carrying `RIGHTS_PMU_CONFIGURE`.
#[derive(Clone, Copy, Debug)]
pub struct Pmu
{
    cap: u64,
}

impl Pmu
{
    /// The PMU authority `cap` names.
    #[must_use]
    pub const fn new(cap: u64) -> Pmu
    {
        Pmu { cap }
    }

    /// The calling CPU's counters.
    ///
    /// # Errors
    /// The `SYS_PMU_INFO` error code (`syscall::pmu_info`); `NotSupported`
    /// where the CPU has no PMU.
    pub fn info(&self) -> Result<Info, i64>
    {
        syscall::pmu_info(self.cap).map(Info::unpack)
    }

    /// Program the calling CPU's user counters with `events`, counting in
    /// `mode`, replacing the CPU's previous configuration. The caller's
    /// affinity names the CPU it runs on.
    ///
    /// # Errors
    /// `InvalidArgument` for more than [`PMU_CONFIGURE_MAX`] events or an
    /// event named twice, before any syscall; otherwise the `SYS_PMU_INFO` or
    /// `SYS_PMU_CONFIGURE` error code (`syscall::pmu_configure`).
    pub fn configure(&self, events: &[PmuEvent], mode: PmuMode) -> Result<Counters, i64>
    {
        let list = EventList::new(events).map_err(|_| SyscallError::InvalidArgument as i64)?;
        let info = self.info()?;
        let word = syscall::pmu_configure(self.cap, list.encode(), list.len() as u64, mode.raw())?;
        let mut handles = [0; PMU_CONFIGURE_MAX];
        for (i, h) in handles.iter_mut().enumerate().take(list.len())
        {
            *h = entry(word, i);
        }
        Ok(Counters {
            pmu: *self,
            handles,
            len: list.len(),
            width: info.width,
            _pinned: PhantomData,
        })
    }

    /// Release the calling CPU's user counters.
    ///
    /// # Errors
    /// The `SYS_PMU_CONFIGURE` error code.
    pub fn release(&self) -> Result<(), i64>
    {
        syscall::pmu_configure(self.cap, 0, 0, 0).map(|_| ())
    }

    /// Grant the thread `thread_cap` names the direct reads of its CPU's
    /// counters.
    ///
    /// # Errors
    /// The `SYS_PMU_BIND` error code (`syscall::pmu_bind`).
    pub fn bind(&self, thread_cap: u64) -> Result<(), i64>
    {
        syscall::pmu_bind(self.cap, thread_cap)
    }

    /// Revoke the direct counter reads of the thread `thread_cap` names.
    ///
    /// # Errors
    /// The `SYS_PMU_BIND` error code (`syscall::pmu_unbind`).
    pub fn unbind(&self, thread_cap: u64) -> Result<(), i64>
    {
        syscall::pmu_unbind(self.cap, thread_cap)
    }
}

/// The counters of one configuration, on the CPU that made it: one read
/// handle per event, in the order of the events.
///
/// Neither `Send` nor `Sync`: a value is read on the CPU it counts on.
#[derive(Debug)]
pub struct Counters
{
    pmu: Pmu,
    handles: [u8; PMU_CONFIGURE_MAX],
    len: usize,
    width: u8,
    _pinned: PhantomData<*const ()>,
}

impl Counters
{
    /// Grant the thread `thread_cap` names, normally the caller's own, the
    /// direct reads of these counters.
    ///
    /// # Errors
    /// The `SYS_PMU_BIND` error code.
    pub fn bind(&self, thread_cap: u64) -> Result<(), i64>
    {
        self.pmu.bind(thread_cap)
    }

    /// The number of counters.
    #[must_use]
    pub const fn len(&self) -> usize
    {
        self.len
    }

    /// Whether the configuration has no counter.
    #[must_use]
    pub const fn is_empty(&self) -> bool
    {
        self.len == 0
    }

    /// The counters' width in bits.
    #[must_use]
    pub const fn width(&self) -> u8
    {
        self.width
    }

    /// The read handles, in the order of the events.
    #[must_use]
    pub fn handles(&self) -> &[u8]
    {
        self.handles.get(..self.len).unwrap_or(&[])
    }

    /// Read the counters into `out`, in the order of the events, as many as
    /// both hold. The calling thread must be bound: an unbound read raises
    /// the CPU's fault (`#GP` on x86-64, an illegal instruction on riscv64).
    pub fn read(&self, out: &mut [u64])
    {
        for (value, &handle) in out.iter_mut().zip(self.handles())
        {
            *value = read_counter(handle);
        }
    }

    /// The count of a counter between two of its readings, `start` and
    /// `end`, across at most one wrap.
    #[must_use]
    pub const fn delta(&self, start: u64, end: u64) -> u64
    {
        crate::delta(start, end, self.width)
    }
}

/// Read the counter of read handle `handle` with `RDPMC`.
#[cfg(target_arch = "x86_64")]
#[inline]
#[must_use]
pub fn read_counter(handle: u8) -> u64
{
    let lo: u32;
    let hi: u32;
    // SAFETY: RDPMC reads the counter ECX names into EDX:EAX and touches no
    // memory; at CPL 3 it raises #GP unless the kernel granted the calling
    // thread reads, which the kernel delivers as the thread's fault. The
    // block omits `nomem` so the compiler keeps memory accesses on their
    // side of the read.
    unsafe {
        core::arch::asm!(
            "rdpmc",
            in("ecx") u32::from(handle),
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Read the counter of read handle `handle`, the CSR offset from `cycle`
/// (3 to 31 for `hpmcounter3` to `hpmcounter31`), with `csrr`; 0 for a
/// handle no counter CSR has.
#[cfg(target_arch = "riscv64")]
#[inline]
#[must_use]
pub fn read_counter(handle: u8) -> u64
{
    macro_rules! csrr {
        ($($n:literal),*) => {
            match handle
            {
                $($n => {
                    let v: u64;
                    // SAFETY: csrr of a counter CSR reads it into a register
                    // and touches no memory; in U-mode it raises an
                    // illegal-instruction exception unless the kernel granted
                    // the calling thread the counter, which the kernel
                    // delivers as the thread's fault. The block omits
                    // `nomem` so the compiler keeps memory accesses on their
                    // side of the read.
                    unsafe {
                        core::arch::asm!(
                            concat!("csrr {}, hpmcounter", $n),
                            out(reg) v,
                            options(nostack),
                        );
                    }
                    v
                })*
                _ => 0,
            }
        };
    }
    csrr!(
        3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 31
    )
}
