// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/pmu/src/riscv.rs

//! The RISC-V SBI Performance Monitoring Unit extension (SBI specification,
//! chapter "Performance Monitoring Unit Extension"): its function ids and
//! flags, the decode of a counter's description, the portable events' SBI
//! event indices, and which counters a configuration takes.
//!
//! A configuration takes the programmable hardware counters
//! (`hpmcounter3` to `hpmcounter31`) but the highest, which is the
//! kernel's. It never takes `cycle`, `time` or `instret`: `cycle` is the
//! counter every thread reads, and a configuration's inhibit bits and value
//! reset would change it under them.

use crate::{PmuEvent, PmuMode};

/// The PMU extension's id (`"PMU"`).
pub const EXT_PMU: u64 = 0x0050_4D55;

/// `sbi_pmu_num_counters`.
pub const FID_NUM_COUNTERS: u64 = 0;
/// `sbi_pmu_counter_get_info`.
pub const FID_COUNTER_GET_INFO: u64 = 1;
/// `sbi_pmu_counter_config_matching`.
pub const FID_COUNTER_CONFIG_MATCHING: u64 = 2;
/// `sbi_pmu_counter_start`.
pub const FID_COUNTER_START: u64 = 3;
/// `sbi_pmu_counter_stop`.
pub const FID_COUNTER_STOP: u64 = 4;

/// Config flag: clear the counter's value.
pub const CFG_CLEAR_VALUE: u64 = 1 << 1;
/// Config flag: start the counter.
pub const CFG_AUTO_START: u64 = 1 << 2;
/// Config flag: do not count in VU-mode.
pub const CFG_SET_VUINH: u64 = 1 << 3;
/// Config flag: do not count in VS-mode.
pub const CFG_SET_VSINH: u64 = 1 << 4;
/// Config flag: do not count in U-mode.
pub const CFG_SET_UINH: u64 = 1 << 5;
/// Config flag: do not count in S-mode.
pub const CFG_SET_SINH: u64 = 1 << 6;
/// Config flag: do not count in M-mode.
pub const CFG_SET_MINH: u64 = 1 << 7;
/// Stop flag: stop the counter and release it.
pub const STOP_RESET: u64 = 1 << 0;

/// The CSR number of `cycle`; counter CSR `n` is `CSR_CYCLE + n`.
pub const CSR_CYCLE: u16 = 0xC00;
/// The first programmable hardware counter's CSR offset (`hpmcounter3`).
pub const FIRST_PROGRAMMABLE: u16 = 3;
/// The last counter CSR offset (`hpmcounter31`).
pub const LAST_PROGRAMMABLE: u16 = 31;

/// A counter as `sbi_pmu_counter_get_info` describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CounterInfo
{
    /// Its CSR number, for a hardware counter.
    pub csr: u16,
    /// Its width in bits, for a hardware counter.
    pub width: u8,
    /// Whether it is a firmware counter, which no CSR reads.
    pub firmware: bool,
}

impl CounterInfo
{
    /// Decode `sbi_pmu_counter_get_info`'s value: the CSR in bits 11:0, the
    /// width less one in bits 17:12, the firmware flag in bit 63.
    #[must_use]
    pub const fn decode(value: u64) -> CounterInfo
    {
        CounterInfo {
            csr: (value & 0xFFF) as u16,
            width: (((value >> 12) & 0x3F) as u8).wrapping_add(1),
            firmware: value >> 63 != 0,
        }
    }

    /// The counter's CSR offset from `cycle` when it is a programmable
    /// hardware counter, which a configuration or the kernel may take.
    #[must_use]
    pub const fn programmable(&self) -> Option<u16>
    {
        if self.firmware || self.csr < CSR_CYCLE + FIRST_PROGRAMMABLE
        {
            return None;
        }
        let offset = self.csr.wrapping_sub(CSR_CYCLE);
        if offset > LAST_PROGRAMMABLE
        {
            None
        }
        else
        {
            Some(offset)
        }
    }
}

/// How a hart's counters divide between configurations and the kernel, in
/// SBI counter indices below 64.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Layout
{
    /// The counters a configuration takes, one bit per SBI index.
    pub user: u64,
    /// The kernel's counter's SBI index.
    pub reserved: Option<u8>,
    /// The narrowest user counter's width in bits.
    pub width: u8,
}

/// The counter of SBI index `index` with description `info`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counter
{
    /// Its SBI index.
    pub index: u8,
    /// Its description.
    pub info: CounterInfo,
}

impl Layout
{
    /// The layout of `counters`: the programmable hardware counter of the
    /// highest CSR is the kernel's, and the others a configuration's.
    /// Indices of 64 and above are left out, as are firmware counters and
    /// `cycle`, `time` and `instret`.
    #[must_use]
    pub fn of(counters: impl Iterator<Item = Counter> + Clone) -> Layout
    {
        let programmable = counters.filter(|c| c.index < 64 && c.info.programmable().is_some());
        let reserved = programmable.clone().max_by_key(|c| c.info.csr);
        let mut layout = Layout {
            user: 0,
            reserved: reserved.map(|c| c.index),
            width: 0,
        };
        for c in programmable
        {
            if Some(c.index) == layout.reserved
            {
                continue;
            }
            layout.user |= 1 << c.index;
            layout.width = if layout.width == 0
            {
                c.info.width
            }
            else
            {
                layout.width.min(c.info.width)
            };
        }
        layout
    }

    /// The number of counters a configuration takes.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a u64 has at most 64 bits set"
    )]
    pub const fn counters(&self) -> u8
    {
        self.user.count_ones() as u8
    }
}

/// The SBI event index of `event` (`event_idx`): a generic hardware event
/// (type 0), or a hardware cache event (type 1: cache id in bits 15:3, the
/// read operation, the access or miss result).
#[must_use]
pub const fn event_index(event: PmuEvent) -> u64
{
    match event
    {
        // SBI_PMU_HW_CPU_CYCLES.
        PmuEvent::Cycles => 0x1,
        // SBI_PMU_HW_INSTRUCTIONS.
        PmuEvent::Instructions => 0x2,
        // SBI_PMU_HW_BRANCH_INSTRUCTIONS.
        PmuEvent::BranchInstructions => 0x5,
        // SBI_PMU_HW_BRANCH_MISSES.
        PmuEvent::BranchMisses => 0x6,
        // LL cache (2), read, access / miss.
        PmuEvent::LlcReferences => cache_event(2, 0),
        PmuEvent::LlcMisses => cache_event(2, 1),
        // DTLB (3) and ITLB (4), read, miss.
        PmuEvent::DtlbMisses => cache_event(3, 1),
        PmuEvent::ItlbMisses => cache_event(4, 1),
    }
}

/// A hardware cache event's index: type 1, `cache` id, the read operation
/// (0), `result` (0 access, 1 miss).
const fn cache_event(cache: u64, result: u64) -> u64
{
    (1 << 16) | (cache << 3) | result
}

/// `sbi_pmu_counter_config_matching`'s flags for a configuration counting in
/// `mode`: clear the value, start the counter, and inhibit every mode the
/// configuration does not count (M-mode and the virtualised modes always).
#[must_use]
pub const fn config_flags(mode: PmuMode) -> u64
{
    let mut flags = CFG_CLEAR_VALUE | CFG_AUTO_START | CFG_SET_MINH | CFG_SET_VUINH | CFG_SET_VSINH;
    if !mode.counts_user()
    {
        flags |= CFG_SET_UINH;
    }
    if !mode.counts_kernel()
    {
        flags |= CFG_SET_SINH;
    }
    flags
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn hw(index: u8, offset: u16, width: u8) -> Counter
    {
        Counter {
            index,
            info: CounterInfo {
                csr: CSR_CYCLE + offset,
                width,
                firmware: false,
            },
        }
    }

    // Defect guarded: a field read from the wrong bits of the info value, or
    // a firmware counter taken for a CSR.
    #[test]
    fn counter_info_decodes_each_field()
    {
        let info = CounterInfo::decode(0xC03 | (63 << 12));
        assert_eq!(
            info,
            CounterInfo {
                csr: 0xC03,
                width: 64,
                firmware: false
            }
        );
        assert_eq!(info.programmable(), Some(3));
        let fw = CounterInfo::decode((1 << 63) | 0xC05);
        assert!(fw.firmware);
        assert_eq!(fw.programmable(), None);
        for fixed in [0xC00, 0xC01, 0xC02]
        {
            assert_eq!(CounterInfo::decode(fixed | (63 << 12)).programmable(), None);
        }
        assert_eq!(CounterInfo::decode(0xC20).programmable(), None);
    }

    // Defect guarded: a configuration given cycle, time, instret or the
    // kernel's counter, or the kernel's chosen from a firmware counter.
    #[test]
    fn the_kernel_keeps_the_highest_programmable_counter()
    {
        let fw = Counter {
            index: 20,
            info: CounterInfo {
                csr: 0,
                width: 64,
                firmware: true,
            },
        };
        let counters = [
            hw(0, 0, 64),
            hw(1, 1, 64),
            hw(2, 2, 64),
            hw(3, 3, 48),
            hw(4, 4, 40),
            hw(5, 18, 48),
            fw,
        ];
        let layout = Layout::of(counters.iter().copied());
        assert_eq!(layout.reserved, Some(5));
        assert_eq!(layout.user, (1 << 3) | (1 << 4));
        assert_eq!(layout.width, 40);
        assert_eq!(layout.counters(), 2);
        assert_eq!(
            Layout::of([hw(0, 0, 64)].iter().copied()),
            Layout::default()
        );
        let lone = Layout::of([hw(3, 3, 64)].iter().copied());
        assert_eq!((lone.user, lone.reserved), (0, Some(3)));
    }

    // Defect guarded: an event mapped to another SBI event, or a cache
    // event's fields in the wrong bits.
    #[test]
    fn event_indices_follow_the_sbi_encoding()
    {
        assert_eq!(event_index(PmuEvent::Cycles), 0x1);
        assert_eq!(event_index(PmuEvent::Instructions), 0x2);
        assert_eq!(event_index(PmuEvent::LlcReferences), 0x10010);
        assert_eq!(event_index(PmuEvent::LlcMisses), 0x10011);
        assert_eq!(event_index(PmuEvent::DtlbMisses), 0x10019);
        assert_eq!(event_index(PmuEvent::ItlbMisses), 0x10021);
    }

    // Defect guarded: a configuration counting a mode it was not asked to,
    // or M-mode.
    #[test]
    fn config_flags_inhibit_the_modes_not_counted()
    {
        let base = CFG_CLEAR_VALUE | CFG_AUTO_START | CFG_SET_MINH | CFG_SET_VUINH | CFG_SET_VSINH;
        assert_eq!(config_flags(PmuMode::User), base | CFG_SET_SINH);
        assert_eq!(config_flags(PmuMode::Kernel), base | CFG_SET_UINH);
        assert_eq!(config_flags(PmuMode::All), base);
    }
}
