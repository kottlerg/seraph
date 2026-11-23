// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/src/cmp.rs

//! The compare operands `SanitizerCoverage` reports
//! (`-sanitizer-coverage-trace-compares`): instrumented code calls a hook with
//! both operands of each integer comparison and the value and cases of each
//! `switch`. The engine empties a fixed table before each execution, so it
//! holds that execution's pairs; a queued input keeps its own, which the
//! mutator reads to write one operand where the input holds the other
//! (input-to-state replacement), and the run learns the constants the target
//! compares against (its dictionary).

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// The table's size as a power of two.
const SLOT_BITS: u32 = 9;

/// The number of operand pairs the table holds.
const SLOTS: usize = 1 << SLOT_BITS;

/// The flag of a slot's `width` byte whose left operand is a compile-time
/// constant.
const CONSTANT: u8 = 0x80;

/// The most cases of one `switch` the table records.
const MAX_SWITCH_CASES: usize = 32;

/// The operands of one recorded comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operands
{
    /// The operands' width in bytes: 1, 2, 4 or 8.
    pub width: u8,
    /// The first operand; the constant when `constant` is set.
    pub left: u64,
    /// The second operand.
    pub right: u64,
    /// Whether `left` is a constant of the code compared against.
    pub constant: bool,
}

/// One slot of the table. A `width` of 0 marks it empty.
struct Slot
{
    width: AtomicU8,
    left: AtomicU64,
    right: AtomicU64,
}

impl Slot
{
    const fn new() -> Self
    {
        Self {
            width: AtomicU8::new(0),
            left: AtomicU64::new(0),
            right: AtomicU64::new(0),
        }
    }
}

/// The recorded pairs, each in the slot its hash selects, so a pair the target
/// compares at every execution keeps one slot. Only the thread that executes
/// the target writes it; relaxed atomics keep the hooks free of locks.
static TABLE: [Slot; SLOTS] = [const { Slot::new() }; SLOTS];

/// Record a comparison of `left` and `right`, `width` bytes wide; an equal
/// pair teaches nothing and is skipped.
fn record(width: u8, left: u64, right: u64)
{
    if left == right
    {
        return;
    }
    let hash =
        (left ^ right.rotate_left(29) ^ u64::from(width)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let index = usize::try_from(hash.wrapping_shr(u64::BITS.wrapping_sub(SLOT_BITS))).unwrap_or(0);
    if let Some(slot) = TABLE.get(index)
    {
        slot.left.store(left, Ordering::Relaxed);
        slot.right.store(right, Ordering::Relaxed);
        slot.width.store(width, Ordering::Relaxed);
    }
}

/// The pair in `slot`, or `None` for an empty slot.
fn read(slot: &Slot) -> Option<Operands>
{
    let width = slot.width.load(Ordering::Relaxed);
    (width != 0).then(|| Operands {
        width: width & !CONSTANT,
        left: slot.left.load(Ordering::Relaxed),
        right: slot.right.load(Ordering::Relaxed),
        constant: width & CONSTANT != 0,
    })
}

/// Empty the table, so that after one execution it holds that execution's
/// pairs alone.
pub fn clear()
{
    for slot in &TABLE
    {
        slot.width.store(0, Ordering::Relaxed);
    }
}

/// Every recorded pair, in table order.
#[must_use]
pub fn recorded() -> Vec<Operands>
{
    TABLE.iter().filter_map(read).collect()
}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_cmp1(left: u8, right: u8)
{
    record(1, left.into(), right.into());
}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_cmp2(left: u16, right: u16)
{
    record(2, left.into(), right.into());
}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_cmp4(left: u32, right: u32)
{
    record(4, left.into(), right.into());
}

#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_cmp8(left: u64, right: u64)
{
    record(8, left, right);
}

/// A comparison whose first operand is a compile-time constant.
#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_const_cmp1(constant: u8, value: u8)
{
    record(1 | CONSTANT, constant.into(), value.into());
}

/// A comparison whose first operand is a compile-time constant.
#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_const_cmp2(constant: u16, value: u16)
{
    record(2 | CONSTANT, constant.into(), value.into());
}

/// A comparison whose first operand is a compile-time constant.
#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_const_cmp4(constant: u32, value: u32)
{
    record(4 | CONSTANT, constant.into(), value.into());
}

/// A comparison whose first operand is a compile-time constant.
#[unsafe(no_mangle)]
pub extern "C" fn __sanitizer_cov_trace_const_cmp8(constant: u64, value: u64)
{
    record(8 | CONSTANT, constant, value);
}

/// A `switch` on `value`: each case is recorded as a constant compared with
/// it, up to [`MAX_SWITCH_CASES`].
///
/// # Safety
///
/// `cases` points to the case table the compiler emits for the `switch`: the
/// number of cases `n`, the bit width of `value`, then the `n` case values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_switch(value: u64, cases: *const u64)
{
    // SAFETY: the table's first word is its number of cases, by the contract.
    let count = unsafe { cases.read() };
    // SAFETY: the table's second word is the bit width of `value`.
    let bits = unsafe { cases.wrapping_add(1).read() };
    let width = u8::try_from(bits.checked_div(8).unwrap_or(0)).unwrap_or(0);
    let Ok(count) = usize::try_from(count)
    else
    {
        return;
    };
    // SAFETY: the `count` case values follow the table's two leading words.
    let values = unsafe { std::slice::from_raw_parts(cases.wrapping_add(2), count) };
    for &case in values.iter().take(MAX_SWITCH_CASES)
    {
        record(width | CONSTANT, case, value);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a hook that loses an operand, its width, or which side is
    // the constant, so the mutator writes the wrong bytes or learns the
    // input's value as a constant; or a switch table read past its cases.
    #[test]
    fn each_hook_records_its_operands_width_and_constant_side()
    {
        __sanitizer_cov_trace_cmp4(0x1234_5678, 0x0BAD_CAFE);
        __sanitizer_cov_trace_const_cmp8(0x5452_4150_2049_4645, 7);
        __sanitizer_cov_trace_cmp2(9, 9);
        let cases = [2u64, 16, 0x0101, 0x0202, 0x0303];
        // SAFETY: `cases` is a table of the compiler's form with two cases.
        unsafe { __sanitizer_cov_trace_switch(0x4242, cases.as_ptr()) };
        let recorded = recorded();
        let expected = [
            Operands {
                width: 4,
                left: 0x1234_5678,
                right: 0x0BAD_CAFE,
                constant: false,
            },
            Operands {
                width: 8,
                left: 0x5452_4150_2049_4645,
                right: 7,
                constant: true,
            },
            Operands {
                width: 2,
                left: 0x0101,
                right: 0x4242,
                constant: true,
            },
            Operands {
                width: 2,
                left: 0x0202,
                right: 0x4242,
                constant: true,
            },
        ];
        for operands in expected
        {
            assert!(
                recorded.contains(&operands),
                "{operands:?} not in {recorded:?}"
            );
        }
        assert!(
            !recorded.iter().any(|o| o.left == 9 && o.right == 9),
            "{recorded:?}"
        );
        assert!(!recorded.iter().any(|o| o.left == 0x0303), "{recorded:?}");
        clear();
        assert_eq!(super::recorded(), []);
    }
}
