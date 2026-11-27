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
    Counter, CounterInfo, EXT_PMU, FID_COUNTER_CONFIG_MATCHING, FID_COUNTER_GET_INFO,
    FID_COUNTER_START, FID_COUNTER_STOP, FID_NUM_COUNTERS, Layout, START_SET_INIT_VALUE,
    STOP_RESET, claimed_index, config_flags, event_index, fixed_counter,
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

    /// Whether a configuration holds counters on this hart.
    #[cfg(not(test))]
    pub const fn configured(&self) -> bool
    {
        self.configured != 0
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

/// Claim a counter among `mask` for `event` with `flags`, which neither
/// clear nor start it (`config_flags`): its SBI index, or `None` where no
/// counter of `mask` counts it. The fixed `cycle` or `instret` counter the
/// firmware answers with on a hart with Smcntrpmf (`claimed_index`) is no
/// claim: its value is untouched, and the filter the request wrote into its
/// `mcyclecfg` or `minstretcfg` is written back at once (`reset_fixed`).
#[cfg(not(test))]
fn config_matching(mask: u64, flags: u64, event: PmuEvent) -> Option<u64>
{
    let ret = sbi_call5(
        EXT_PMU,
        FID_COUNTER_CONFIG_MATCHING,
        [0, mask, flags, event_index(event), 0],
    );
    if ret.error != 0
    {
        return None;
    }
    let claimed = claimed_index(mask, ret.value);
    if claimed.is_none() && fixed_counter(event) == Some(ret.value)
    {
        reset_fixed(event);
    }
    claimed
}

/// Write the filter of `event`'s fixed counter (`pmu::riscv::fixed_counter`)
/// to the one a request with no inhibit flag gives it, counting every mode
/// but M-mode. Offered that counter alone, the firmware answers with it only
/// on a hart with Smcntrpmf, where it writes the counter's `mcyclecfg` or
/// `minstretcfg` and leaves its value; elsewhere it refuses and nothing
/// changes.
#[cfg(not(test))]
fn reset_fixed(event: PmuEvent)
{
    if let Some(index) = fixed_counter(event)
    {
        let _ = sbi_call5(
            EXT_PMU,
            FID_COUNTER_CONFIG_MATCHING,
            [0, 1 << index, 0, event_index(event), 0],
        );
    }
}

/// Start the claimed counter `index` at zero; whether the firmware did.
#[cfg(not(test))]
fn start(index: u64) -> bool
{
    let ret = sbi_call5(
        EXT_PMU,
        FID_COUNTER_START,
        [index, 1, START_SET_INIT_VALUE, 0, 0],
    );
    ret.error == 0
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
/// width and the events they count, probed one by one. `Info::NONE` where a
/// hart lacks Sscofpmf (`boot_protocol::HART_CAP_SSCOFPMF`), without which
/// the firmware cannot filter a counter by privilege mode and a user reader's
/// counts would include the kernel's execution, or where the firmware has no
/// PMU extension or leaves no user counter. On a hart with Smcntrpmf it sets
/// the filter of `cycle` and `instret` first (`reset_fixed`), the one a
/// refused claim's write is undone to.
///
/// # Safety
/// S-mode on the hart being initialised, with interrupts disabled.
#[cfg(not(test))]
pub unsafe fn init(state: &mut ArchPmu) -> Info
{
    if crate::platform::kernel_mmio().hart_caps & boot_protocol::HART_CAP_SSCOFPMF == 0
    {
        return Info::NONE;
    }
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
    reset_fixed(PmuEvent::Cycles);
    reset_fixed(PmuEvent::Instructions);
    let mut events = 0;
    for event in PmuEvent::ALL
    {
        if let Some(index) = config_matching(layout.user, 0, event)
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
        let claimed = config_matching(free, flags, *event).and_then(|index| {
            state.configured |= 1 << index;
            if !start(index)
            {
                return None;
            }
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
