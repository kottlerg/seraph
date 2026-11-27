// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/pmu.rs

//! A hart's performance counters through the SBI PMU extension: describe them
//! at bring-up, configure the user counters, and grant U-mode their reads
//! through `scounteren` (core/kernel/docs/perfmon.md).
//!
//! The firmware owns the counters' selectors (`mhpmevent`), so a counter is
//! claimed with `sbi_pmu_counter_config_matching` and released with
//! `sbi_pmu_counter_stop` and its reset flag. The user counters are the
//! programmable hardware counters but the highest (`pmu::riscv::Layout`); a
//! read handle is the counter's CSR offset from `cycle`.

#[cfg(not(test))]
use pmu::riscv::{
    CFG_CLEAR_VALUE, Counter, CounterInfo, EXT_PMU, FID_COUNTER_CONFIG_MATCHING,
    FID_COUNTER_GET_INFO, FID_COUNTER_STOP, FID_NUM_COUNTERS, Layout, STOP_RESET, config_flags,
    event_index,
};
#[cfg(not(test))]
use pmu::{EventList, Info, PmuEvent, PmuMode};
#[cfg(not(test))]
use syscall::SyscallError;

#[cfg(not(test))]
use super::sbi::{sbi_call, sbi_call5};

/// SBI Base extension ID.
#[cfg(not(test))]
const SBI_EXT_BASE: u64 = 0x10;
/// `sbi_probe_extension` function ID.
#[cfg(not(test))]
const SBI_PROBE_EXTENSION: u64 = 3;

/// The most SBI counter indices a hart's description takes: a counter mask
/// is one `u64`.
#[cfg(not(test))]
const MAX_INDICES: usize = 64;

/// One hart's counter state, in its `PerCpuData`; read and written only by
/// that hart, with interrupts disabled.
pub struct ArchPmu
{
    /// The SBI indices of the user counters.
    user: u64,
    /// The SBI indices the current configuration holds.
    configured: u64,
    /// The `scounteren` bits of the configured counters.
    grant: u64,
}

impl ArchPmu
{
    /// No counters.
    pub const fn new() -> Self
    {
        Self {
            user: 0,
            configured: 0,
            grant: 0,
        }
    }
}

/// The SBI description of counter `index`, or `None` where the firmware
/// gives none.
#[cfg(not(test))]
fn counter_info(index: u64) -> Option<CounterInfo>
{
    let ret = sbi_call(EXT_PMU, FID_COUNTER_GET_INFO, index, 0, 0);
    (ret.error == 0).then(|| CounterInfo::decode(ret.value))
}

/// Claim a counter among `mask` for SBI event `event` with `flags`: its SBI
/// index, or `None` where no counter of `mask` counts it.
#[cfg(not(test))]
fn config_matching(mask: u64, flags: u64, event: u64) -> Option<u64>
{
    let ret = sbi_call5(
        EXT_PMU,
        FID_COUNTER_CONFIG_MATCHING,
        [0, mask, flags, event, 0],
    );
    (ret.error == 0 && ret.value < MAX_INDICES as u64).then_some(ret.value)
}

/// Stop and release every counter of `mask` (SBI indices).
#[cfg(not(test))]
fn release(mask: u64)
{
    let mut rest = mask;
    while rest != 0
    {
        let index = u64::from(rest.trailing_zeros());
        rest &= rest.wrapping_sub(1);
        // A counter the firmware already released answers an error, which
        // leaves nothing to undo.
        let _ = sbi_call(EXT_PMU, FID_COUNTER_STOP, index, 1, STOP_RESET);
    }
}

/// Describe this hart's counters into `state`: the user counters, their
/// width and the events they count, probed one by one. `Info::NONE` where the
/// firmware has no PMU extension or leaves no user counter.
///
/// # Safety
/// S-mode on the hart being initialised, with interrupts disabled.
#[cfg(not(test))]
pub unsafe fn init(state: &mut ArchPmu) -> Info
{
    let probe = sbi_call(SBI_EXT_BASE, SBI_PROBE_EXTENSION, EXT_PMU, 0, 0);
    if probe.error != 0 || probe.value == 0
    {
        return Info::NONE;
    }
    let num = sbi_call(EXT_PMU, FID_NUM_COUNTERS, 0, 0, 0);
    if num.error != 0
    {
        return Info::NONE;
    }
    let count = usize::try_from(num.value).map_or(MAX_INDICES, |n| n.min(MAX_INDICES));
    let mut counters = [Counter {
        index: 0,
        info: CounterInfo::decode(1 << 63),
    }; MAX_INDICES];
    for (index, slot) in (0u8..).zip(counters.iter_mut().take(count))
    {
        if let Some(info) = counter_info(u64::from(index))
        {
            *slot = Counter { index, info };
        }
    }
    let layout = Layout::of(counters.iter().take(count).copied());
    if layout.user == 0
    {
        return Info::NONE;
    }
    let mut events = 0;
    for event in PmuEvent::ALL
    {
        if let Some(index) = config_matching(layout.user, CFG_CLEAR_VALUE, event_index(event))
        {
            release(1 << index);
            events |= event.bit();
        }
    }
    state.user = layout.user;
    Info {
        counters: layout.counters(),
        width: layout.width,
        events,
    }
}

/// Program the user counters with `events` counting in `mode`, replacing the
/// configuration `state` holds, or release them for an empty list; the read
/// handles go to `handles`, in the order of the events.
///
/// # Errors
/// `NotSupported` for more events than `info` has counters, an event
/// `info` does not count, or an event no free counter takes; the previous
/// configuration is then released only in the last case.
///
/// # Safety
/// S-mode on this hart with interrupts disabled; `state` and `info` are this
/// hart's.
#[cfg(not(test))]
pub unsafe fn configure(
    state: &mut ArchPmu,
    info: Info,
    events: &EventList,
    mode: PmuMode,
    handles: &mut [u8],
) -> Result<(), SyscallError>
{
    if events.len() > usize::from(info.counters) || events.mask() & !info.events != 0
    {
        return Err(SyscallError::NotSupported);
    }
    release(state.configured);
    state.configured = 0;
    state.grant = 0;
    let flags = config_flags(mode);
    for (event, handle) in events.as_slice().iter().zip(handles.iter_mut())
    {
        let free = state.user & !state.configured;
        let claimed = config_matching(free, flags, event_index(*event)).and_then(|index| {
            state.configured |= 1 << index;
            counter_info(index)
                .and_then(|c| c.programmable())
                .and_then(|offset| u8::try_from(offset).ok())
        });
        let Some(offset) = claimed
        else
        {
            release(state.configured);
            state.configured = 0;
            state.grant = 0;
            return Err(SyscallError::NotSupported);
        };
        state.grant |= 1 << offset;
        *handle = offset;
    }
    Ok(())
}

/// Write this hart's `scounteren`: `cycle` alone
/// (`interrupts::USER_COUNTERS`), with the configured counters for a reader.
///
/// # Safety
/// S-mode on this hart with interrupts disabled; `state` is this hart's.
#[cfg(not(test))]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "reader is data: the pmu_reader flag of the thread the grant is written for"
)]
pub unsafe fn apply_grant(state: &ArchPmu, reader: bool)
{
    let grant = if reader
    {
        super::interrupts::USER_COUNTERS | state.grant
    }
    else
    {
        super::interrupts::USER_COUNTERS
    };
    // SAFETY: csrw scounteren is a privileged S-mode instruction on a per-hart
    // register that gates U-mode counter reads only; the caller is in S-mode.
    unsafe {
        core::arch::asm!(
            "csrw scounteren, {grant}",
            grant = in(reg) grant,
            options(nostack, nomem),
        );
    }
}
