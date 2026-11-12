// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/hw.rs

//! Tier 1 tests for hardware access syscalls.
//!
//! Covers: `SYS_MMIO_MAP`, `SYS_MMIO_SPLIT`, `SYS_IRQ_REGISTER`,
//! `SYS_IRQ_ACK`, `SYS_IRQ_SPLIT`, `SYS_IRQ_MSG_ALLOC` and the message
//! selectors of `SYS_CAP_INFO`. The per-architecture `SYS_IOPORT_BIND`,
//! `SYS_IOPORT_SPLIT`, and `SYS_SBI_CALL` tests live behind `crate::arch`.
//!
//! Tests that require specific hardware capability types (`Mmio`, Interrupt,
//! `IoPort`) scan the initial capability set for a matching cap. If none is
//! found in the current boot configuration, the test is skipped and reports Ok.
//! Skips are logged to serial so they are visible in the test run output.

use syscall::{
    aspace_query, cap_create_notification, irq_ack, irq_msg_alloc, irq_register, irq_split,
    mem_unmap, mmio_split,
};
use syscall_abi::{CAP_INFO_IRQ_MSG_ADDRESS, CAP_INFO_IRQ_MSG_DATA, SyscallError};

use crate::{TestContext, TestResult};

/// Test virtual address for MMIO mapping: 5.25 GiB, in ktest's low scratch
/// band (ktest is `no_std` and has no byte heap or reservation arena), below
/// every `process_layout` window (ktest's PIE image loads in `IMAGE_WINDOW`).
const MMIO_TEST_VA: u64 = 0x1_5000_0000;

/// Upper bound for a slot scan over the test's own `CSpace`: its backed
/// capacity, which the kernel clamps below its structural slot ceiling (under
/// 2^32), so the narrowing cannot fail; the address-space cap's index if the
/// query fails, which still covers every boot-minted cap.
pub fn scan_bound(ctx: &TestContext) -> u32
{
    syscall::cap_info(ctx.cspace_cap, syscall_abi::CAP_INFO_CSPACE_CAPACITY)
        .ok()
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(syscall_abi::cap_handle_index(ctx.aspace_cap))
}

// ── SYS_MMIO_MAP ──────────────────────────────────────────────────────────────

/// `mmio_map` maps a hardware MMIO region into the address space.
///
/// Maps only a single carved page, not the whole aperture:
/// `sys_mmio_map` draws intermediate PT pages from the *target* AS's own pool,
/// and the first `Mmio` in the boot config can span hundreds of MiB
/// (hundreds of PT pages) — mapping it whole would drain `ctx.aspace_cap`'s
/// pool, which the `mem_map` integration and bench tests share. One page
/// suffices to exercise the map + `aspace_query` path. The region is split so
/// its large remainder stays a valid `Mmio` for [`mmio_split_carves`].
/// Skipped if no `Mmio` of at least two pages exists in this boot config.
pub fn mmio_map(ctx: &TestContext) -> TestResult
{
    // Probe each slot with a one-page split. `InvalidCapability` ⇒ wrong tag;
    // `InvalidArgument` ⇒ an `Mmio` smaller than two pages. Both leave
    // the cap intact, so the scan is non-destructive until a split succeeds.
    // The scan bound is the cspace's backed capacity (queried at runtime)
    // so the test stays robust against cap mint order.
    let bound = scan_bound(ctx);
    for slot in 1..=u64::from(bound)
    {
        let Ok((lo, _hi)) = mmio_split(slot, 0x1000)
        else
        {
            continue;
        };
        // `lo` covers one page; map and verify it. The remainder child (`_hi`)
        // stays in the CSpace as a valid `Mmio` for the split test that
        // runs next.
        let result = (|| -> TestResult {
            // SAFETY: `MMIO_TEST_VA` is a scratch VA (crate docs § Scratch VAs), so the
            // span holds no Rust object or IPC page of ktest.
            // The test only queries the mapping (`aspace_query`), never accesses it,
            // and unmaps it before MMIO_TEST_VA's next use (`mmio_map` § Safety).
            unsafe { syscall::mmio_map(ctx.aspace_cap, lo, MMIO_TEST_VA, 0) }
                .map_err(|_| "mmio_map of carved page failed")?;
            let phys = aspace_query(ctx.aspace_cap, MMIO_TEST_VA)
                .map_err(|_| "aspace_query after mmio_map failed")?;
            if phys == 0 || phys & 0xFFF != 0
            {
                return Err("aspace_query returned invalid phys after mmio_map");
            }
            Ok(())
        })();
        // SAFETY: `MMIO_TEST_VA` is a scratch VA (crate docs § Scratch VAs), so the
        // span holds no Rust object or IPC page of ktest.
        let _ = unsafe { mem_unmap(ctx.aspace_cap, MMIO_TEST_VA, 1) };
        syscall::cap_delete(lo).ok();
        return result;
    }

    crate::log("ktest: hw::mmio_map SKIP (no Mmio >= 2 pages in initial cap set)");
    Ok(())
}

// ── SYS_IRQ_REGISTER / SYS_IRQ_ACK ───────────────────────────────────────────

/// `irq_register` binds a notification to an interrupt; `irq_ack` re-enables delivery.
///
/// Scans for the first Interrupt capability that binds, through a derived copy
/// of each slot, so the binding goes with the copy's delete (a binding holds
/// its notification until its Interrupt capability goes). Creates a
/// notification for delivery. After registration, ACKs to re-enable the
/// interrupt line. If no Interrupt cap binds, the test is skipped.
pub fn irq_register_ack(ctx: &TestContext) -> TestResult
{
    let irq_sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_create_notification for IRQ test failed")?;

    // The scan bound is the cspace's backed capacity (queried at runtime)
    // so the test stays robust against cap mint order.
    let bound = scan_bound(ctx);
    for slot in 1..=u64::from(bound)
    {
        // An empty slot refuses the derive; any other error (a slot of
        // another type, most often) leaves the copy unbound; keep scanning.
        let Ok(copy) = syscall::cap_derive(slot, syscall::RIGHTS_ALL)
        else
        {
            continue;
        };
        if irq_register(copy, irq_sig, 0).is_ok()
        {
            let acked = irq_ack(copy).map_err(|_| "irq_ack failed");
            syscall::cap_delete(copy).map_err(|_| "cap_delete of the bound copy failed")?;
            syscall::cap_delete(irq_sig).map_err(|_| "cap_delete irq_sig after irq test failed")?;
            return acked;
        }
        syscall::cap_delete(copy).ok();
    }

    crate::log("ktest: hw::irq_register_ack SKIP (no Interrupt caps in initial cap set)");
    syscall::cap_delete(irq_sig).ok();
    Ok(())
}

// ── SYS_MMIO_SPLIT ────────────────────────────────────────────────────────────

/// `mmio_split` on the first `Mmio` ≥ 8 KiB returns two valid children
/// with disjoint base/size. Skipped if no suitable cap exists.
pub fn mmio_split_carves(ctx: &TestContext) -> TestResult
{
    let bound = scan_bound(ctx);

    for slot in 1..=u64::from(bound)
    {
        // Probe: split at PAGE_SIZE. InvalidCapability ⇒ wrong tag.
        // InvalidArgument ⇒ Mmio exists but too small.
        match mmio_split(slot, 0x1000)
        {
            Err(e) if e == SyscallError::InvalidCapability as i64 =>
            {}
            Err(e) if e == SyscallError::InvalidArgument as i64 =>
            {}
            Err(_) => return Err("hw::mmio_split_carves: unexpected error from mmio_split"),
            Ok((slot1, slot2)) =>
            {
                if slot1 == 0 || slot2 == 0 || slot1 == slot2
                {
                    return Err("hw::mmio_split_carves: split returned bad slot ids");
                }
                syscall::cap_delete(slot1).ok();
                syscall::cap_delete(slot2).ok();
                return Ok(());
            }
        }
    }

    crate::log("ktest: hw::mmio_split_carves SKIP (no Mmio caps in initial cap set)");
    Ok(())
}

/// `mmio_split` on a Memory cap (wrong tag) must return `InvalidCapability`.
pub fn mmio_split_wrong_tag_err(ctx: &TestContext) -> TestResult
{
    let err = mmio_split(ctx.memory_base, 0x1000);
    if err != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("hw::mmio_split_wrong_tag_err: did not return InvalidCapability");
    }
    Ok(())
}

/// An Interrupt cap naming an id no discovered interrupt controller
/// implements is refused by `irq_register` with `InvalidArgument`, and
/// deleting it leaves the kernel's routing table alone.
///
/// The root Interrupt cap spans more ids than the controllers implement on
/// both architectures: on riscv64 the APLIC's 1024-id space against the sources
/// its `riscv,num-sources` reports, on x86-64 32768 GSIs against the pins the I/O APICs
/// report, which size the kernel's routing table. Each id of
/// `crate::arch::UNROUTABLE_IRQ_IDS` is isolated as a single-id cap split off a
/// derived copy of the first cap whose range contains it, so the original range
/// stays whole for later tests (the IRQ stress cell carves a device line from
/// the root).
pub fn irq_register_unroutable_id_err(ctx: &TestContext) -> TestResult
{
    let irq_sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "hw::irq_register_unroutable_id_err: cap_create_notification failed")?;
    let result = crate::arch::UNROUTABLE_IRQ_IDS
        .iter()
        .try_for_each(|&id| refuse_unroutable_id(ctx, id, irq_sig));
    syscall::cap_delete(irq_sig).ok();
    result
}

/// An Interrupt cap naming a line a fixed-size routing table once refused, but
/// that the discovered controller implements, is accepted by `irq_register`,
/// acknowledged, and deleted. Each id of `crate::arch::ROUTABLE_HIGH_IRQ_IDS`
/// (x86-64: a GSI above the old 23-vector gate range; riscv64: the APLIC's
/// last reported source) is isolated as for `irq_register_unroutable_id_err`.
pub fn irq_register_high_id(ctx: &TestContext) -> TestResult
{
    let irq_sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "hw::irq_register_high_id: cap_create_notification failed")?;
    let result = crate::arch::ROUTABLE_HIGH_IRQ_IDS
        .iter()
        .try_for_each(|&id| route_high_id(ctx, id, irq_sig));
    syscall::cap_delete(irq_sig).ok();
    result
}

/// Isolate `id`, register `irq_sig` on it, acknowledge it, and delete the cap,
/// which clears the route.
fn route_high_id(ctx: &TestContext, id: u32, irq_sig: u64) -> TestResult
{
    let single =
        isolate_irq_id(ctx, id).ok_or("hw::irq_register_high_id: cannot isolate the id")?;
    let registered = irq_register(single, irq_sig, 0);
    let acked = registered.and_then(|()| irq_ack(single));
    let deleted = syscall::cap_delete(single);
    registered.map_err(|_| "hw::irq_register_high_id: routable id refused")?;
    acked.map_err(|_| "hw::irq_register_high_id: irq_ack failed")?;
    deleted.map_err(|_| "hw::irq_register_high_id: cap_delete of the id failed")
}

/// Isolate `id` and check `irq_register` refuses it with `InvalidArgument`
/// and that deleting its cap succeeds.
fn refuse_unroutable_id(ctx: &TestContext, id: u32, irq_sig: u64) -> TestResult
{
    let single = isolate_irq_id(ctx, id)
        .ok_or("hw::irq_register_unroutable_id_err: cannot isolate the id")?;
    let err = irq_register(single, irq_sig, 0);
    // Deleting the cap must not touch the routing table for an id it cannot
    // index (the kernel panicked here before the teardown guard).
    let deleted = syscall::cap_delete(single);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("hw::irq_register_unroutable_id_err: unroutable id not refused");
    }
    deleted.map_err(|_| "hw::irq_register_unroutable_id_err: cap_delete of the id failed")
}

/// A single-id Interrupt cap for `id`, split off a derived copy of the first
/// cap in the test's `CSpace` whose range contains it; `None` when no cap does
/// or the split that cuts the id off from the ids above it is refused.
pub fn isolate_irq_id(ctx: &TestContext, id: u32) -> Option<u64>
{
    let bound = scan_bound(ctx);
    for slot in 1..=u64::from(bound)
    {
        // A slot that cannot be derived is empty; keep scanning.
        let Ok(copy) = syscall::cap_derive(slot, syscall::RIGHTS_ALL)
        else
        {
            continue;
        };
        // Wrong-tag and out-of-range responses leave the copy intact.
        let Ok((below, from_id)) = irq_split(copy, id)
        else
        {
            syscall::cap_delete(copy).ok();
            continue;
        };
        syscall::cap_delete(below).ok();
        return match irq_split(from_id, id + 1)
        {
            Ok((single, above)) =>
            {
                syscall::cap_delete(above).ok();
                Some(single)
            }
            // `id + 1` is not strictly inside `from_id`, whose range starts at
            // `id`: the range ends at `id`, and `from_id` is the id alone.
            Err(e) if e == SyscallError::InvalidArgument as i64 => Some(from_id),
            // Any other refusal leaves a multi-id cap, which `irq_register`
            // would refuse for its width, not its id; fail instead.
            Err(_) =>
            {
                syscall::cap_delete(from_id).ok();
                None
            }
        };
    }
    None
}

// ── SYS_IRQ_MSG_ALLOC ─────────────────────────────────────────────────────────

/// Slots of one CPU's delivery space no architecture exceeds: an x86-64 CPU has
/// 217 device vectors, a riscv64 hart's IMSIC file at most 2047 identities.
/// `irq_msg_exhaustion_and_reuse` stops looking for the end past this many
/// mints per CPU.
const MSG_SLOTS_PER_CPU_MAX: u64 = 2048;

/// Pages `irq_msg_exhaustion_and_reuse` adds to the test's `CSpace` at a time
/// when a mint finds it full.
const MSG_AUGMENT_PAGES: u64 = 32;

/// Most mints `irq_msg_exhaustion_and_reuse` makes, and most pages it adds to
/// the test's `CSpace` for them: a slot (`CSPACE_SLOTS_PER_PAGE` a page) and an
/// arena body (`CSPACE_BODIES_PER_PAGE` a page) per minted cap, and one
/// augment's worth besides.
fn msg_exhaustion_bounds() -> Result<(u64, u64), &'static str>
{
    let cpus = syscall::system_info(syscall_abi::SystemInfoType::CpuCount as u64)
        .map_err(|_| "hw::irq_msg_exhaustion_and_reuse: system_info(CpuCount) failed")?;
    let mints = cpus * MSG_SLOTS_PER_CPU_MAX;
    let pages = mints.div_ceil(syscall_abi::CSPACE_SLOTS_PER_PAGE)
        + mints.div_ceil(syscall_abi::CSPACE_BODIES_PER_PAGE)
        + MSG_AUGMENT_PAGES;
    Ok((mints, pages))
}

/// A derived copy of the first cap in the test's `CSpace` that mints a
/// message-signaled target, carrying every right of it, and nothing minted.
/// The root Interrupt cap carries `RIGHTS_IRQ_MINT`, so one is always found.
pub fn msg_authority(ctx: &TestContext) -> Result<u64, &'static str>
{
    let bound = scan_bound(ctx);
    for slot in 1..=u64::from(bound)
    {
        // A slot without the right, of another type, or empty refuses and is
        // left intact; a mint through it proves the right.
        let Ok(minted) = irq_msg_alloc(slot)
        else
        {
            continue;
        };
        syscall::cap_delete(minted).map_err(|_| "msg_authority: cap_delete of the probe failed")?;
        return syscall::cap_derive(slot, syscall::RIGHTS_ALL)
            .map_err(|_| "msg_authority: cap_derive of the authority failed");
    }
    Err("msg_authority: no Interrupt cap carrying RIGHTS_IRQ_MINT in the initial cap set")
}

/// The message address and data `SYS_CAP_INFO` gives `cap`.
pub fn msg_of(cap: u64) -> Result<(u64, u64), i64>
{
    Ok((
        syscall::cap_info(cap, CAP_INFO_IRQ_MSG_ADDRESS)?,
        syscall::cap_info(cap, CAP_INFO_IRQ_MSG_DATA)?,
    ))
}

/// `irq_msg_alloc` through a cap carrying `RIGHTS_IRQ_MINT` returns an
/// Interrupt cap carrying `RIGHTS_IRQ_NOTIFY` alone, whose message address and
/// data are the architecture's (a local APIC message and a device vector on
/// x86-64, an IMSIC file and an identity on riscv64).
pub fn irq_msg_alloc_mints(ctx: &TestContext) -> TestResult
{
    let authority = msg_authority(ctx)?;
    let result = (|| -> TestResult {
        let minted =
            irq_msg_alloc(authority).map_err(|_| "hw::irq_msg_alloc_mints: mint failed")?;
        let checked = (|| -> TestResult {
            let packed = syscall::cap_info(minted, syscall_abi::CAP_INFO_TAG_RIGHTS)
                .map_err(|_| "hw::irq_msg_alloc_mints: CAP_INFO_TAG_RIGHTS failed")?;
            if packed & 0xFFFF_FFFF != syscall::RIGHTS_IRQ_NOTIFY
            {
                return Err("hw::irq_msg_alloc_mints: minted cap's rights are not NOTIFY alone");
            }
            let (address, data) =
                msg_of(minted).map_err(|_| "hw::irq_msg_alloc_mints: message selectors refused")?;
            if !crate::arch::msi_message_plausible(address, data)
            {
                return Err("hw::irq_msg_alloc_mints: message address or data out of range");
            }
            Ok(())
        })();
        syscall::cap_delete(minted).map_err(|_| "hw::irq_msg_alloc_mints: cap_delete failed")?;
        checked
    })();
    syscall::cap_delete(authority).ok();
    result
}

/// `irq_msg_alloc` refuses a cap without `RIGHTS_IRQ_MINT` (an attenuated copy
/// of the authority, and a minted cap) with `InsufficientRights`, and a cap of
/// another type with `InvalidCapability`.
pub fn irq_msg_alloc_refusals(ctx: &TestContext) -> TestResult
{
    let authority = msg_authority(ctx)?;
    let result = (|| -> TestResult {
        let notify_only = syscall::cap_derive(authority, syscall::RIGHTS_IRQ_NOTIFY)
            .map_err(|_| "hw::irq_msg_alloc_refusals: cap_derive failed")?;
        let attenuated = irq_msg_alloc(notify_only);
        syscall::cap_delete(notify_only).ok();
        if attenuated != Err(SyscallError::InsufficientRights as i64)
        {
            return Err("hw::irq_msg_alloc_refusals: a cap without MINT minted");
        }
        let minted =
            irq_msg_alloc(authority).map_err(|_| "hw::irq_msg_alloc_refusals: mint failed")?;
        let from_minted = irq_msg_alloc(minted);
        syscall::cap_delete(minted).ok();
        if from_minted != Err(SyscallError::InsufficientRights as i64)
        {
            return Err("hw::irq_msg_alloc_refusals: a minted cap minted");
        }
        if irq_msg_alloc(ctx.memory_base) != Err(SyscallError::InvalidCapability as i64)
        {
            return Err("hw::irq_msg_alloc_refusals: a Memory cap was not InvalidCapability");
        }
        Ok(())
    })();
    syscall::cap_delete(authority).ok();
    result
}

/// The message selectors of `cap_info` refuse, with `InvalidArgument`, an
/// Interrupt range cap, a single wired line's cap, and a cap of another type.
pub fn irq_msg_info_wired_err(ctx: &TestContext) -> TestResult
{
    let authority = msg_authority(ctx)?;
    let range = msg_of(authority);
    syscall::cap_delete(authority).ok();
    if range.map(|_| ()) != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("hw::irq_msg_info_wired_err: a range cap answered the message selectors");
    }
    let id = crate::arch::ROUTABLE_HIGH_IRQ_IDS[0];
    let line =
        isolate_irq_id(ctx, id).ok_or("hw::irq_msg_info_wired_err: cannot isolate a line")?;
    let wired = msg_of(line);
    syscall::cap_delete(line).ok();
    if wired.map(|_| ()) != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("hw::irq_msg_info_wired_err: a wired line answered the message selectors");
    }
    if syscall::cap_info(ctx.memory_base, CAP_INFO_IRQ_MSG_ADDRESS)
        != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("hw::irq_msg_info_wired_err: a Memory cap answered the message selectors");
    }
    Ok(())
}

/// A message-signaled cap binds once, in mode 0: a nonzero mode is refused
/// with `InvalidArgument`, a copy (which names the same message) cannot bind
/// a second time (`QuotaExceeded`), `irq_ack` succeeds, and a copy outliving
/// the minted cap keeps the target and its message.
pub fn irq_msg_register(ctx: &TestContext) -> TestResult
{
    let authority = msg_authority(ctx)?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "hw::irq_msg_register: cap_create_notification failed")?;
    let result = (|| -> TestResult {
        let minted = irq_msg_alloc(authority).map_err(|_| "hw::irq_msg_register: mint failed")?;
        let copy = syscall::cap_derive(minted, syscall::RIGHTS_ALL);
        let checked = copy
            .map_err(|_| "hw::irq_msg_register: cap_derive of the minted cap failed")
            .and_then(|copy| {
                let message = msg_of(minted).map_err(|_| "hw::irq_msg_register: no message")?;
                if msg_of(copy) != Ok(message)
                {
                    return Err("hw::irq_msg_register: a copy names another message");
                }
                if irq_register(minted, sig, syscall::IRQ_MODE_LEVEL)
                    != Err(SyscallError::InvalidArgument as i64)
                {
                    return Err("hw::irq_msg_register: a level mode was not refused");
                }
                irq_register(minted, sig, 0).map_err(|_| "hw::irq_msg_register: mode 0 refused")?;
                irq_ack(minted).map_err(|_| "hw::irq_msg_register: irq_ack failed")?;
                if irq_register(copy, sig, 0) != Err(SyscallError::QuotaExceeded as i64)
                {
                    return Err("hw::irq_msg_register: a second binding was not refused");
                }
                // The copy keeps the target once the minted cap goes.
                syscall::cap_delete(minted)
                    .map_err(|_| "hw::irq_msg_register: cap_delete of the minted cap failed")?;
                if msg_of(copy) != Ok(message)
                {
                    return Err("hw::irq_msg_register: the copy lost its message");
                }
                irq_register(copy, sig, 0)
                    .map_err(|_| "hw::irq_msg_register: the copy cannot bind once alone")?;
                Ok(())
            });
        if let Ok(copy) = copy
        {
            syscall::cap_delete(copy).ok();
        }
        syscall::cap_delete(minted).ok();
        checked
    })();
    syscall::cap_delete(sig).ok();
    syscall::cap_delete(authority).ok();
    result
}

/// A bound Interrupt binding holds a reference on its Notification: once the
/// Notification's capabilities are deleted the binding keeps it, and its
/// funding Memory cap is not sole, until the Interrupt cap is deleted, which
/// frees the Notification and returns its bytes. A second cap to the
/// Notification counts the binding as a holder (`CAP_INFO_SOLE_REFERENCE`).
pub fn irq_binding_holds_its_notification(ctx: &TestContext) -> TestResult
{
    let memory = crate::frame_pool::alloc()
        .ok_or("hw::irq_binding_holds_its_notification: frame pool exhausted")?;
    let authority = msg_authority(ctx);
    let result = authority.and_then(|authority| {
        let probed = binding_reference_probe(authority, memory);
        syscall::cap_delete(authority).ok();
        probed
    });
    // A failed step can leave the Notification live; the frame then stays out
    // of the pool rather than break `free`'s precondition.
    if syscall::cap_info(memory, syscall_abi::CAP_INFO_SOLE_REFERENCE) == Ok(1)
    {
        // SAFETY: the kernel reports no other reference to the frame's
        // object, so the Notification retyped from it is gone, and the test
        // never mapped the frame.
        unsafe { crate::frame_pool::free(memory) };
    }
    result
}

/// The steps of [`irq_binding_holds_its_notification`]: a Notification
/// retyped from `memory`, bound to a target minted through `authority`, kept by
/// the binding alone, then freed with it.
fn binding_reference_probe(authority: u64, memory: u64) -> TestResult
{
    let sole = |cap| {
        syscall::cap_info(cap, syscall_abi::CAP_INFO_SOLE_REFERENCE)
            .map_err(|_| "hw::irq_binding_holds_its_notification: SOLE_REFERENCE failed")
    };
    let sig = cap_create_notification(memory)
        .map_err(|_| "hw::irq_binding_holds_its_notification: cap_create_notification failed")?;
    let Ok(minted) = irq_msg_alloc(authority)
    else
    {
        syscall::cap_delete(sig).ok();
        return Err("hw::irq_binding_holds_its_notification: mint failed");
    };
    let checked = (|| -> TestResult {
        irq_register(minted, sig, 0)
            .map_err(|_| "hw::irq_binding_holds_its_notification: bind failed")?;
        let other = syscall::cap_derive(sig, syscall::RIGHTS_ALL)
            .map_err(|_| "hw::irq_binding_holds_its_notification: cap_derive failed")?;
        syscall::cap_delete(sig)
            .map_err(|_| "hw::irq_binding_holds_its_notification: first cap's delete failed")?;
        let shared = sole(other);
        syscall::cap_delete(other)
            .map_err(|_| "hw::irq_binding_holds_its_notification: last cap's delete failed")?;
        if shared? != 0
        {
            return Err("hw::irq_binding_holds_its_notification: the binding is not a holder");
        }
        if sole(memory)? != 0
        {
            return Err("hw::irq_binding_holds_its_notification: freed with a binding naming it");
        }
        syscall::cap_delete(minted)
            .map_err(|_| "hw::irq_binding_holds_its_notification: Interrupt cap delete failed")?;
        if sole(memory)? != 1
        {
            return Err("hw::irq_binding_holds_its_notification: not freed with its binding");
        }
        Ok(())
    })();
    // A handle an earlier step deleted names an empty slot, since nothing is
    // created after that delete, and its delete here changes nothing.
    syscall::cap_delete(minted).ok();
    syscall::cap_delete(sig).ok();
    checked
}

/// Minting until `QuotaExceeded` exhausts the message targets, and what ran
/// out is the CPUs' slots, not the kernel's table: a wired line cannot then be
/// routed either (`QuotaExceeded`), since no CPU has a slot left for it.
/// Deleting a minted cap frees its target for the next mint, and revoking the
/// authority deletes every cap minted through it and frees their targets. The
/// test's own `CSpace` is augmented from its Memory cap whenever a mint finds it
/// full (`OutOfMemory`), so the targets, not the `CSpace`, run out first.
pub fn irq_msg_exhaustion_and_reuse(ctx: &TestContext) -> TestResult
{
    let (mint_limit, donation_limit) = msg_exhaustion_bounds()?;
    let authority = msg_authority(ctx)?;
    // The line and the notification are made before the mints fill the
    // `CSpace`.
    let line = isolate_irq_id(ctx, crate::arch::ROUTABLE_HIGH_IRQ_IDS[0]);
    let sig = cap_create_notification(ctx.memory_base);
    let result = (|| -> TestResult {
        let line = line.ok_or("hw::irq_msg_exhaustion_and_reuse: cannot isolate a line")?;
        let sig =
            sig.map_err(|_| "hw::irq_msg_exhaustion_and_reuse: cap_create_notification failed")?;
        let mut last = 0;
        let mut minted = 0;
        let mut donated = 0;
        loop
        {
            if minted == mint_limit
            {
                return Err("hw::irq_msg_exhaustion_and_reuse: targets never ran out");
            }
            match irq_msg_alloc(authority)
            {
                Ok(cap) =>
                {
                    last = cap;
                    minted += 1;
                }
                Err(e) if e == SyscallError::QuotaExceeded as i64 => break,
                Err(e) if e == SyscallError::OutOfMemory as i64 && donated < donation_limit =>
                {
                    syscall::cap_create_cspace(ctx.memory_base, ctx.cspace_cap, MSG_AUGMENT_PAGES)
                        .map_err(|_| "hw::irq_msg_exhaustion_and_reuse: CSpace augment failed")?;
                    donated += MSG_AUGMENT_PAGES;
                }
                Err(_) => return Err("hw::irq_msg_exhaustion_and_reuse: unexpected mint error"),
            }
        }
        if minted == 0
        {
            return Err("hw::irq_msg_exhaustion_and_reuse: no target could be minted");
        }
        crate::log_u64(
            "ktest: hw::irq_msg_exhaustion_and_reuse targets minted=",
            minted,
        );
        if irq_register(line, sig, 0) != Err(SyscallError::QuotaExceeded as i64)
        {
            return Err("hw::irq_msg_exhaustion_and_reuse: mints stopped while a slot was free");
        }
        syscall::cap_delete(last)
            .map_err(|_| "hw::irq_msg_exhaustion_and_reuse: cap_delete failed")?;
        let probe = irq_msg_alloc(authority)
            .map_err(|_| "hw::irq_msg_exhaustion_and_reuse: a freed target was not reused")?;
        if irq_msg_alloc(authority) != Err(SyscallError::QuotaExceeded as i64)
        {
            return Err("hw::irq_msg_exhaustion_and_reuse: minted past exhaustion");
        }
        syscall::cap_revoke(authority)
            .map_err(|_| "hw::irq_msg_exhaustion_and_reuse: cap_revoke failed")?;
        if syscall::cap_info(probe, CAP_INFO_IRQ_MSG_DATA)
            != Err(SyscallError::InvalidCapability as i64)
        {
            return Err("hw::irq_msg_exhaustion_and_reuse: a minted cap survived the revoke");
        }
        let again = irq_msg_alloc(authority)
            .map_err(|_| "hw::irq_msg_exhaustion_and_reuse: the revoke freed no target")?;
        syscall::cap_delete(again).ok();
        Ok(())
    })();
    if let Some(line) = line
    {
        syscall::cap_delete(line).ok();
    }
    if let Ok(sig) = sig
    {
        syscall::cap_delete(sig).ok();
    }
    syscall::cap_revoke(authority).ok();
    syscall::cap_delete(authority).ok();
    result
}

/// Words of [`MSG_SEEN`]: one bit per message key ([`msg_key`]), 256 pages of
/// [`MSG_SLOTS_PER_CPU_MAX`] slots.
const MSG_SEEN_WORDS: usize = 8192;
const _: () = assert!(MSG_SEEN_WORDS as u64 * 64 == 256 * MSG_SLOTS_PER_CPU_MAX);

/// The messages [`mint_every_slot`] has seen live, one bit per [`msg_key`]. A
/// static, since ktest has no heap; only that function, which ktest's
/// sequential unit tier runs on one thread, touches it.
static MSG_SEEN: [core::sync::atomic::AtomicU64; MSG_SEEN_WORDS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MSG_SEEN_WORDS];

/// The bit of message (`address`, `data`) in [`MSG_SEEN`]: the low 8 bits of
/// the address's page (the local APIC id on x86-64, the IMSIC file's page on
/// riscv64) above the data's 11 bits. Equal messages always share a key, so a
/// repeat is always found; two messages whose pages differ only above those 8
/// bits would also share one and fail the test, never pass it. `None` for data
/// past 11 bits.
fn msg_key(address: u64, data: u64) -> Option<usize>
{
    if data >= MSG_SLOTS_PER_CPU_MAX
    {
        return None;
    }
    let page = (address >> 12) & 0xFF;
    usize::try_from(page * MSG_SLOTS_PER_CPU_MAX + data).ok()
}

/// Mint through `authority` until the targets run out (`QuotaExceeded`),
/// binding each to `sig` when one is given, and fail when a live target's
/// message repeats another's. The test's `CSpace` is augmented from its Memory
/// cap whenever a mint finds its pool spent (`OutOfMemory`), and the next mint
/// must then succeed. Returns how many targets were minted; every one stays
/// live, a child of `authority`.
fn mint_every_slot(ctx: &TestContext, authority: u64, sig: Option<u64>)
-> Result<u64, &'static str>
{
    let (mint_limit, donation_limit) = msg_exhaustion_bounds()?;
    for word in &MSG_SEEN
    {
        word.store(0, core::sync::atomic::Ordering::Relaxed);
    }
    let mut minted = 0;
    let mut donated = 0;
    let mut refills = 0;
    let mut refilled = false;
    loop
    {
        if minted == mint_limit
        {
            return Err("hw::irq_msg_every_slot_one_notification: targets never ran out");
        }
        match irq_msg_alloc(authority)
        {
            Ok(cap) =>
            {
                minted += 1;
                refilled = false;
                let (address, data) = msg_of(cap)
                    .map_err(|_| "hw::irq_msg_every_slot_one_notification: no message")?;
                if !crate::arch::msi_message_plausible(address, data)
                {
                    return Err("hw::irq_msg_every_slot_one_notification: message out of range");
                }
                let key = msg_key(address, data)
                    .ok_or("hw::irq_msg_every_slot_one_notification: data past 11 bits")?;
                let bit = 1u64 << (key % 64);
                if MSG_SEEN[key / 64].fetch_or(bit, core::sync::atomic::Ordering::Relaxed) & bit
                    != 0
                {
                    return Err(
                        "hw::irq_msg_every_slot_one_notification: two targets share a message",
                    );
                }
                if let Some(sig) = sig
                {
                    irq_register(cap, sig, 0)
                        .map_err(|_| "hw::irq_msg_every_slot_one_notification: bind failed")?;
                }
            }
            Err(e) if e == SyscallError::QuotaExceeded as i64 => break,
            Err(e) if e == SyscallError::OutOfMemory as i64 && refilled =>
            {
                return Err(
                    "hw::irq_msg_every_slot_one_notification: a refill did not cure OutOfMemory",
                );
            }
            Err(e) if e == SyscallError::OutOfMemory as i64 && donated < donation_limit =>
            {
                syscall::cap_create_cspace(ctx.memory_base, ctx.cspace_cap, MSG_AUGMENT_PAGES)
                    .map_err(
                        |_| "hw::irq_msg_every_slot_one_notification: CSpace augment failed",
                    )?;
                donated += MSG_AUGMENT_PAGES;
                refills += 1;
                refilled = true;
            }
            Err(_) => return Err("hw::irq_msg_every_slot_one_notification: unexpected mint error"),
        }
    }
    if minted == 0
    {
        return Err("hw::irq_msg_every_slot_one_notification: no target could be minted");
    }
    crate::log_u64(
        "ktest: hw::irq_msg_every_slot_one_notification targets minted=",
        minted,
    );
    crate::log_u64(
        "ktest: hw::irq_msg_every_slot_one_notification OutOfMemory refills=",
        refills,
    );
    Ok(minted)
}

/// Every free slot of every CPU minted and bound to one Notification: no two
/// live targets share a message, the bindings keep the Notification once its
/// only capability is deleted, and deleting each target's capability (a revoke
/// of the authority they were minted through) unbinds them, frees the
/// Notification and frees every slot, so a second round mints as many targets,
/// again each with a message of its own.
pub fn irq_msg_every_slot_one_notification(ctx: &TestContext) -> TestResult
{
    let memory = crate::frame_pool::alloc()
        .ok_or("hw::irq_msg_every_slot_one_notification: frame pool exhausted")?;
    let authority = msg_authority(ctx);
    let result = authority.and_then(|authority| {
        let probed = every_slot_probe(ctx, authority, memory);
        syscall::cap_revoke(authority).ok();
        syscall::cap_delete(authority).ok();
        probed
    });
    // A failed step can leave the Notification live; the frame then stays out
    // of the pool rather than break `free`'s precondition.
    if syscall::cap_info(memory, syscall_abi::CAP_INFO_SOLE_REFERENCE) == Ok(1)
    {
        // SAFETY: the kernel reports no other reference to the frame's
        // object, so the Notification retyped from it is gone, and the test
        // never mapped the frame.
        unsafe { crate::frame_pool::free(memory) };
    }
    result
}

/// The steps of [`irq_msg_every_slot_one_notification`], with the Notification
/// retyped from `memory` and the targets minted through `authority`.
fn every_slot_probe(ctx: &TestContext, authority: u64, memory: u64) -> TestResult
{
    let sole = |cap| {
        syscall::cap_info(cap, syscall_abi::CAP_INFO_SOLE_REFERENCE)
            .map_err(|_| "hw::irq_msg_every_slot_one_notification: SOLE_REFERENCE failed")
    };
    let sig = cap_create_notification(memory)
        .map_err(|_| "hw::irq_msg_every_slot_one_notification: cap_create_notification failed")?;
    let first = mint_every_slot(ctx, authority, Some(sig));
    // The bindings now hold the Notification alone.
    syscall::cap_delete(sig)
        .map_err(|_| "hw::irq_msg_every_slot_one_notification: notification delete failed")?;
    let first = first?;
    if sole(memory)? != 0
    {
        return Err("hw::irq_msg_every_slot_one_notification: freed with bindings naming it");
    }
    syscall::cap_revoke(authority)
        .map_err(|_| "hw::irq_msg_every_slot_one_notification: cap_revoke failed")?;
    if sole(memory)? != 1
    {
        return Err("hw::irq_msg_every_slot_one_notification: not freed with its last binding");
    }
    let second = mint_every_slot(ctx, authority, None)?;
    if second != first
    {
        return Err("hw::irq_msg_every_slot_one_notification: a re-mint found another slot count");
    }
    Ok(())
}

// ── SYS_IRQ_SPLIT ─────────────────────────────────────────────────────────────

/// `irq_split` at IRQ id 1 on a derived copy of the first Interrupt-range cap
/// whose range strictly contains it (start 0, `count > 1`) returns two
/// disjoint children. The copy, not the original, is consumed, so the
/// original range stays whole for later tests. Skipped if no such cap exists.
pub fn irq_split_carves(ctx: &TestContext) -> TestResult
{
    let bound = scan_bound(ctx);

    for slot in 1..=u64::from(bound)
    {
        // A slot that cannot be derived is empty; keep scanning.
        let Ok(copy) = syscall::cap_derive(slot, syscall::RIGHTS_ALL)
        else
        {
            continue;
        };
        // Probe: split at IRQ id 1 (`split_at` is absolute), which only a cap
        // starting at IRQ 0 with count > 1 accepts. Wrong-tag and out-of-range
        // responses both leave the copy intact.
        match irq_split(copy, 1)
        {
            Err(_) =>
            {
                // Wrong tag or non-splittable; keep scanning.
                syscall::cap_delete(copy).ok();
            }
            Ok((slot1, slot2)) =>
            {
                if slot1 == 0 || slot2 == 0 || slot1 == slot2
                {
                    return Err("hw::irq_split_carves: split returned bad slot ids");
                }
                syscall::cap_delete(slot1).ok();
                syscall::cap_delete(slot2).ok();
                return Ok(());
            }
        }
    }

    crate::log("ktest: hw::irq_split_carves SKIP (no Interrupt range caps with count>1)");
    Ok(())
}

/// `irq_split` on a Memory cap (wrong tag) must return `InvalidCapability`.
pub fn irq_split_wrong_tag_err(ctx: &TestContext) -> TestResult
{
    let err = irq_split(ctx.memory_base, 0);
    if err != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("hw::irq_split_wrong_tag_err: did not return InvalidCapability");
    }
    Ok(())
}
