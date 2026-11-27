// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/pmu.rs

//! A CPU's performance counters: describe them at bring-up, program the user
//! counters' event selects, and grant ring 3 `RDPMC` through `CR4.PCE`
//! (core/kernel/docs/perfmon.md).
//!
//! Intel's architectural performance monitoring (CPUID 0AH) and AMD's core
//! counter extension, family 17h and later, are supported; the per-vendor
//! decode and encodings are `pmu::intel` and `pmu::amd`, host-tested there.
//! A configuration takes the user counters from counter 0 up, one per event,
//! so a read handle is the counter's `RDPMC` index.

use pmu::intel::{self, CoreType, Layout, Model};
use pmu::{EventList, Info, PmuEvent, PmuMode, amd};
use syscall::{PMU_CONFIGURE_MAX, PMU_EVENT_COUNT, SyscallError};

use super::cpu::{cpuid, cpuid_subleaf};
#[cfg(not(test))]
use super::cpu::{read_cr4, read_msr, write_cr4, write_msr};
use super::vulnerability::Vendor;

/// `CR4.PCE` (bit 8): lets `RDPMC` execute at CPL > 0.
#[cfg(not(test))]
const CR4_PCE: u64 = 1 << 8;

/// The counter family a CPU has.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind
{
    /// No counters the kernel drives.
    None,
    /// Intel architectural performance monitoring, `version` 1 or later.
    Intel
    {
        version: u8
    },
    /// AMD core counters; `global_ctl` where `PerfCntrGlobalCtl` gates them.
    Amd
    {
        global_ctl: bool
    },
}

/// One CPU's counter state, in its `PerCpuData`; read and written only by
/// that CPU, with interrupts disabled.
pub struct ArchPmu
{
    /// The counter family.
    kind: Kind,
    /// The user counters: `0..user`.
    user: u8,
    /// The counters the current configuration holds: `0..configured`.
    configured: u8,
    /// Each event's encoding on an Intel CPU, by event id.
    intel: [Option<intel::Encoding>; PMU_EVENT_COUNT as usize],
}

impl ArchPmu
{
    /// No counters.
    pub const fn new() -> Self
    {
        Self {
            kind: Kind::None,
            user: 0,
            configured: 0,
            intel: [None; PMU_EVENT_COUNT as usize],
        }
    }

    /// Whether a configuration holds counters on this CPU.
    #[cfg(not(test))]
    pub const fn configured(&self) -> bool
    {
        self.configured != 0
    }
}

/// Describe this CPU's counters into `state` and leave every user counter
/// stopped at zero and enabled in the global control. `Info::NONE` for
/// another vendor, or a CPU whose CPUID reports no counter a configuration
/// can take (QEMU's TCG among them).
///
/// # Safety
/// Ring 0 on the CPU being initialised, with interrupts disabled.
pub unsafe fn init(state: &mut ArchPmu) -> Info
{
    let (max, ebx, ecx, edx) = cpuid(0);
    let model = Model::decode(cpuid(1).0);
    let info = match Vendor::from_string_registers(ebx, edx, ecx)
    {
        Vendor::Intel if max >= intel::LEAF_PERFMON => init_intel(state, max, model),
        Vendor::Amd => init_amd(state, model),
        Vendor::Intel | Vendor::Other => Info::NONE,
    };
    if info.present()
    {
        // SAFETY: ring 0 with interrupts disabled (contract); the kind and
        // the user counters were just read from CPUID.
        unsafe { reset(state, state.user) };
        // SAFETY: as above.
        unsafe { enable_global(state) };
    }
    info
}

/// [`init`] on an Intel CPU whose maximum basic leaf is `max`.
fn init_intel(state: &mut ArchPmu, max: u32, model: Model) -> Info
{
    let (eax, ebx, _, edx) = cpuid(intel::LEAF_PERFMON);
    let Some(perfmon) = intel::Perfmon::decode(eax, ebx, edx)
    else
    {
        return Info::NONE;
    };
    let Some(layout) = Layout::of(&perfmon)
    else
    {
        return Info::NONE;
    };
    let core = if max >= intel::LEAF_HYBRID
    {
        CoreType::decode(cpuid_subleaf(intel::LEAF_HYBRID, 0).0)
    }
    else
    {
        CoreType::Other
    };
    for (slot, event) in state.intel.iter_mut().zip(PmuEvent::ALL)
    {
        *slot = intel::encoding(&perfmon, model, core, event);
    }
    state.kind = Kind::Intel {
        version: perfmon.version,
    };
    state.user = layout.user;
    Info {
        counters: layout.user,
        width: perfmon.width,
        events: intel::events(&perfmon, model, core),
    }
}

/// [`init`] on an AMD CPU of `model`.
fn init_amd(state: &mut ArchPmu, model: Model) -> Info
{
    let max_ext = cpuid(0x8000_0000).0;
    if max_ext < amd::LEAF_EXT_FEATURES
    {
        return Info::NONE;
    }
    let ext_ecx = cpuid(amd::LEAF_EXT_FEATURES).2;
    let v2 = (max_ext >= amd::LEAF_PERFMON_V2).then(|| {
        let (eax, ebx, _, _) = cpuid(amd::LEAF_PERFMON_V2);
        (eax, ebx)
    });
    let Some(perfmon) = amd::Perfmon::decode(model.family, ext_ecx, v2)
    else
    {
        return Info::NONE;
    };
    state.kind = Kind::Amd {
        global_ctl: perfmon.global_ctl,
    };
    state.user = perfmon.user();
    Info {
        counters: perfmon.user(),
        width: amd::WIDTH,
        events: amd::events(),
    }
}

/// The select and count MSRs of counter `i` of `kind`.
const fn counter_msrs(kind: Kind, i: u8) -> Option<(u32, u32)>
{
    let i = i as u32;
    match kind
    {
        Kind::Intel { .. } => Some((
            intel::MSR_PERFEVTSEL0.wrapping_add(i),
            intel::MSR_PMC0.wrapping_add(i),
        )),
        Kind::Amd { .. } =>
        {
            let select = amd::MSR_PERF_CTL0.wrapping_add(i.wrapping_mul(2));
            Some((select, select.wrapping_add(1)))
        }
        Kind::None => None,
    }
}

/// Stop counters `0..n` and set their counts to zero.
///
/// # Safety
/// Ring 0 on this CPU; `state.kind` is this CPU's and `n` at most its user
/// counters.
#[cfg(not(test))]
unsafe fn reset(state: &ArchPmu, n: u8)
{
    for i in 0..n
    {
        if let Some((select, count)) = counter_msrs(state.kind, i)
        {
            // SAFETY: the MSRs of a counter CPUID reports (contract); a zero
            // select stops it, and a zero count is valid on both vendors.
            unsafe { write_msr(select, 0) };
            // SAFETY: as above.
            unsafe { write_msr(count, 0) };
        }
    }
}

/// Test stub.
#[cfg(test)]
unsafe fn reset(_state: &ArchPmu, _n: u8) {}

/// Enable the user counters in the global control, where one gates them,
/// leaving every other counter's enable as it is.
///
/// # Safety
/// Ring 0 on this CPU; `state` is this CPU's.
#[cfg(not(test))]
unsafe fn enable_global(state: &ArchPmu)
{
    let msr = match state.kind
    {
        Kind::Intel { version } if version >= 2 => intel::MSR_PERF_GLOBAL_CTRL,
        Kind::Amd { global_ctl: true } => amd::MSR_GLOBAL_CTL,
        Kind::Intel { .. } | Kind::Amd { .. } | Kind::None => return,
    };
    // At most eight user counters on Intel and six on AMD, so the shift is
    // in range.
    let user = (1u64 << state.user).wrapping_sub(1);
    // SAFETY: the global control CPUID reports (version 2 or PerfMonV2).
    let global = unsafe { read_msr(msr) };
    // SAFETY: as above; the write sets only the enables of counters that exist.
    unsafe { write_msr(msr, global | user) };
}

/// Test stub.
#[cfg(test)]
unsafe fn enable_global(_state: &ArchPmu) {}

/// Write `value` to the event select MSR `msr`.
///
/// # Safety
/// Ring 0 on this CPU; `msr` is the select of a user counter CPUID reports,
/// and `value` an event select of `pmu::intel` or `pmu::amd`.
#[cfg(not(test))]
unsafe fn write_select(msr: u32, value: u64)
{
    // SAFETY: the caller's contract.
    unsafe { write_msr(msr, value) };
}

/// Test stub.
#[cfg(test)]
unsafe fn write_select(_msr: u32, _value: u64) {}

/// The event select that counts `event` in `mode` on a CPU of `state`, or
/// `None` where it does not count the event.
fn select(state: &ArchPmu, event: PmuEvent, mode: PmuMode) -> Option<u64>
{
    match state.kind
    {
        Kind::Intel { .. } => state
            .intel
            .get(usize::from(event.id()))
            .copied()
            .flatten()
            .map(|enc| intel::event_select(enc, mode)),
        Kind::Amd { .. } => amd::encoding(event).map(|enc| amd::event_select(enc, mode)),
        Kind::None => None,
    }
}

/// Program the user counters with `events` counting in `mode`, replacing the
/// configuration `state` holds, or release them for an empty list; the read
/// handles go to `handles`, in the order of the events. A released counter is
/// stopped at zero.
///
/// # Errors
/// `NotSupported` for more events than `info` has counters or an event the
/// CPU does not count; nothing is changed then.
///
/// # Safety
/// Ring 0 on this CPU with interrupts disabled; `state` and `info` are this
/// CPU's.
pub unsafe fn configure(
    state: &mut ArchPmu,
    info: Info,
    events: &EventList,
    mode: PmuMode,
    handles: &mut [u8],
) -> Result<(), SyscallError>
{
    let mut selects = [0u64; PMU_CONFIGURE_MAX];
    if events.len() > usize::from(info.counters)
    {
        return Err(SyscallError::NotSupported);
    }
    for (slot, event) in selects.iter_mut().zip(events.as_slice())
    {
        *slot = select(state, *event, mode).ok_or(SyscallError::NotSupported)?;
    }
    // SAFETY: ring 0 on this CPU (contract); the configured counters are user
    // counters.
    unsafe { reset(state, state.configured) };
    state.configured = 0;
    for ((i, sel), handle) in (0u8..)
        .zip(selects.iter().take(events.len()))
        .zip(handles.iter_mut())
    {
        if let Some((select_msr, _)) = counter_msrs(state.kind, i)
        {
            // SAFETY: counter i is a user counter (fewer events than user
            // counters, checked above), stopped at zero by the reset; the
            // select sets only the event, the unit mask, USR, OS and EN.
            unsafe { write_select(select_msr, *sel) };
        }
        *handle = i;
        state.configured = i.wrapping_add(1);
    }
    Ok(())
}

/// Set this CPU's `CR4.PCE` for a reader, else clear it.
///
/// # Safety
/// Ring 0 on this CPU with interrupts disabled.
#[cfg(not(test))]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "reader is data: the pmu_reader flag of the thread the grant is written for"
)]
pub unsafe fn apply_grant(_state: &ArchPmu, reader: bool)
{
    let cr4 = read_cr4();
    let want = if reader
    {
        cr4 | CR4_PCE
    }
    else
    {
        cr4 & !CR4_PCE
    };
    if want != cr4
    {
        // SAFETY: ring 0 (contract); PCE gates only ring 3's RDPMC.
        unsafe { write_cr4(want) };
    }
}

/// Test stub.
///
/// # Safety
/// No preconditions; `unsafe` only for signature parity with the non-test
/// item.
#[cfg(test)]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "reader is data: the pmu_reader flag of the thread the grant is written for"
)]
pub unsafe fn apply_grant(_state: &ArchPmu, _reader: bool) {}
