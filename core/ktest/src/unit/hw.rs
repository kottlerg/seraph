// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/hw.rs

//! Tier 1 tests for hardware access syscalls.
//!
//! Covers: `SYS_MMIO_MAP`, `SYS_MMIO_SPLIT`, `SYS_MMIO_MERGE`, `SYS_IRQ_REGISTER`,
//! `SYS_IRQ_ACK`, `SYS_IRQ_SPLIT`, `SYS_IRQ_MSG_ALLOC`, `SYS_IRQ_ROUTE`,
//! `SYS_IRQ_REMAP`, and the message and remapping selectors of
//! `SYS_CAP_INFO`. The per-architecture `SYS_IOPORT_BIND`,
//! `SYS_IOPORT_SPLIT`, and `SYS_SBI_CALL` tests live behind `crate::arch`.
//!
//! Tests that require specific hardware capability types (`Mmio`, Interrupt,
//! `IoPort`) look up a matching boot cap among the `InitInfo` descriptors
//! ([`boot_caps`]). If none is found in the current boot configuration, the
//! test is skipped and reports Ok.
//! Skips are logged to serial so they are visible in the test run output.

use init_protocol::{CapDescriptor, CapType, InitInfo};
use syscall::{
    aspace_query, cap_create_notification, irq_ack, irq_msg_alloc, irq_register, irq_remap,
    irq_route, irq_split, mem_unmap, mmio_merge, mmio_split,
};
use syscall_abi::{CAP_INFO_IRQ_MSG_ADDRESS, CAP_INFO_IRQ_MSG_DATA, SyscallError};

use crate::{TestContext, TestResult};

/// Test virtual address for MMIO mapping: 5.25 GiB, in ktest's low scratch
/// band (ktest is `no_std` and has no byte heap or reservation arena), below
/// every `process_layout` window (ktest's PIE image loads in `IMAGE_WINDOW`).
const MMIO_TEST_VA: u64 = 0x1_5000_0000;

/// The boot capabilities of `cap_type` that `InitInfo` describes, each
/// descriptor's `slot` the cap's handle. A boot cap's slot is never recycled
/// while the cap lives, so the handle stays valid; a test that splits one works
/// on a derived copy, which leaves the boot cap whole.
pub fn boot_caps(
    ctx: &TestContext,
    cap_type: CapType,
) -> impl Iterator<Item = &'static CapDescriptor>
{
    // SAFETY: the kernel maps the read-only InitInfo page at init_info_va for
    // ktest's lifetime.
    let info: &'static InitInfo = unsafe { &*(ctx.init_info_va as *const InitInfo) };
    crate::init_info::descriptors(info)
        .iter()
        .filter(move |d| d.cap_type == cap_type)
}

// ── SYS_MMIO_MAP ──────────────────────────────────────────────────────────────

/// `mmio_map` maps a hardware MMIO region into the address space.
///
/// Maps only a single page, split off a derived copy of the first boot `Mmio`
/// cap of at least two pages, not the whole aperture: `sys_mmio_map` draws
/// intermediate PT pages from the *target* AS's own pool, and an aperture can
/// span hundreds of MiB (hundreds of PT pages), which would drain
/// `ctx.aspace_cap`'s pool, which the `mem_map` integration and bench tests
/// share. One page suffices to exercise the map + `aspace_query` path. The
/// split consumes the copy, so the boot cap stays whole. Skipped if no `Mmio` of
/// at least two pages exists in this boot config.
pub fn mmio_map(ctx: &TestContext) -> TestResult
{
    for boot in boot_caps(ctx, CapType::Mmio).filter(|d| d.aux1 >= 0x2000)
    {
        let Some((lo, hi)) = split_copy(boot.slot)
        else
        {
            continue;
        };
        syscall::cap_delete(hi).ok();
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

/// Split a derived copy of the `Mmio` cap `boot` one page in; the two halves,
/// or `None` when the derive or the split is refused (a boot cap an earlier test
/// consumed, or one under two pages), the copy then deleted.
fn split_copy(boot: u64) -> Option<(u64, u64)>
{
    let copy = syscall::cap_derive(boot, syscall::RIGHTS_ALL).ok()?;
    let halves = mmio_split(copy, 0x1000).ok();
    if halves.is_none()
    {
        syscall::cap_delete(copy).ok();
    }
    halves
}

/// `mmio_map` at VA 0, and at the page below `USER_VA_FLOOR`, fails with
/// `InvalidAddress`.
///
/// Maps through a derived copy of the `Mmio` capability for the probe
/// register page (`crate::arch::MMIO_PROBE_PHYS`). The copy has its own
/// object, so the boot capability and its mappings (the riscv64 serial
/// console's) are untouched, and the copy's delete withdraws anything the call
/// mapped. Skipped if the boot config has no probe `Mmio`.
pub fn mmio_map_below_floor_err(ctx: &TestContext) -> TestResult
{
    const REFUSED: Result<(), i64> = Err(SyscallError::InvalidAddress as i64);
    // SAFETY: the kernel maps the read-only InitInfo page at init_info_va for
    // ktest's lifetime.
    let info = unsafe { &*(ctx.init_info_va as *const init_protocol::InitInfo) };
    let Some(boot_cap) = crate::init_info::descriptors(info)
        .iter()
        .find(|d| {
            d.cap_type == init_protocol::CapType::Mmio && d.aux0 == crate::arch::MMIO_PROBE_PHYS
        })
        .map(|d| d.slot)
    else
    {
        crate::log("ktest: hw::mmio_map_below_floor_err SKIP (no probe Mmio cap)");
        return Ok(());
    };
    let copy = syscall::cap_derive(boot_cap, syscall::RIGHTS_ALL)
        .map_err(|_| "hw::mmio_map_below_floor_err: cap_derive failed")?;

    // SAFETY: the span starts below `USER_VA_FLOOR`, which the kernel refuses
    // (the test's premise), so the call maps nothing.
    let at_zero = unsafe { syscall::mmio_map(ctx.aspace_cap, copy, 0, 0) };
    let below = syscall_abi::USER_VA_FLOOR - syscall_abi::PAGE_SIZE;
    // SAFETY: as above.
    let below_floor = unsafe { syscall::mmio_map(ctx.aspace_cap, copy, below, 0) };
    syscall::cap_delete(copy).ok();

    if at_zero != REFUSED
    {
        return Err(
            "hw::mmio_map_below_floor_err: mmio_map at VA 0 did not fail with InvalidAddress",
        );
    }
    if below_floor != REFUSED
    {
        return Err(
            "hw::mmio_map_below_floor_err: mmio_map below the floor did not fail with InvalidAddress",
        );
    }
    Ok(())
}

// ── SYS_IRQ_ROUTE ────────────────────────────────────────────────────────────

/// `irq_route` routes a line through a single-line cap carrying
/// `RIGHTS_IRQ_MINT`, which then holds the route: `irq_register` refuses the
/// line before it (`InvalidState`) and in another mode after it; a second
/// route through the same cap, or through another holder in the same mode,
/// succeeds, and one in another mode is refused; the route outlives the last
/// binding while a holder remains, and is released once neither a holder nor
/// a binding remains, after which the line routes in another mode. A range
/// cap and a cap without `RIGHTS_IRQ_MINT` are refused.
pub fn irq_route_holds_the_line(ctx: &TestContext) -> TestResult
{
    let id = *crate::arch::ROUTABLE_HIGH_IRQ_IDS
        .first()
        .ok_or("hw::irq_route_holds_the_line: no routable id")?;
    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "hw::irq_route_holds_the_line: cap_create_notification failed")?;
    let single = isolate_irq_id(ctx, id);
    let result = single
        .ok_or("hw::irq_route_holds_the_line: cannot isolate the id")
        .and_then(|single| route_holds(ctx, id, single, sig));
    if let Some(single) = single
    {
        syscall::cap_delete(single).ok();
    }
    syscall::cap_delete(sig).ok();
    result?;
    // Neither a holder nor a binding remains: the line is released.
    let fresh = isolate_irq_id(ctx, id).ok_or("hw::irq_route_holds_the_line: re-isolate failed")?;
    let rerouted = irq_route(fresh, syscall_abi::IRQ_MODE_LEVEL);
    syscall::cap_delete(fresh).ok();
    rerouted.map_err(|_| "hw::irq_route_holds_the_line: the line was not released")?;
    let range = msg_authority(ctx)?;
    let ranged = irq_route(range, 0);
    syscall::cap_delete(range).ok();
    if ranged != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("hw::irq_route_holds_the_line: a range cap was routed");
    }
    Ok(())
}

/// The checks of [`irq_route_holds_the_line`] on `single`, the cap of line
/// `id`, with notification `sig`, up to the release; leaves `single`
/// holding the route, and deletes every other cap it makes.
fn route_holds(ctx: &TestContext, id: u32, single: u64, sig: u64) -> TestResult
{
    if irq_register(single, sig, 0) != Err(SyscallError::InvalidState as i64)
    {
        return Err("hw::irq_route_holds_the_line: an unrouted line was bound");
    }
    let notify_only = syscall::cap_derive(single, syscall::RIGHTS_IRQ_NOTIFY)
        .map_err(|_| "hw::irq_route_holds_the_line: cap_derive failed")?;
    let refused = irq_route(notify_only, 0);
    syscall::cap_delete(notify_only).ok();
    if refused != Err(SyscallError::InsufficientRights as i64)
    {
        return Err("hw::irq_route_holds_the_line: routed without RIGHTS_IRQ_MINT");
    }
    if irq_route(single, syscall_abi::IRQ_MODE_MASK + 1)
        != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("hw::irq_route_holds_the_line: a mode outside IRQ_MODE_MASK was taken");
    }
    irq_route(single, 0).map_err(|_| "hw::irq_route_holds_the_line: route refused")?;
    irq_route(single, 0).map_err(|_| "hw::irq_route_holds_the_line: repeat route refused")?;
    if irq_route(single, syscall_abi::IRQ_MODE_LEVEL) != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("hw::irq_route_holds_the_line: a route in another mode was taken");
    }
    let holder = syscall::cap_derive(single, syscall::RIGHTS_ALL)
        .map_err(|_| "hw::irq_route_holds_the_line: cap_derive failed")?;
    let checked = holder_checks(single, holder, sig);
    syscall::cap_delete(holder).ok();
    checked?;
    // `single` still holds the route: the line stays routed in mode 0.
    let fresh = isolate_irq_id(ctx, id).ok_or("hw::irq_route_holds_the_line: re-isolate failed")?;
    let held = irq_route(fresh, syscall_abi::IRQ_MODE_LEVEL);
    syscall::cap_delete(fresh).ok();
    if held != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("hw::irq_route_holds_the_line: the route went with a holder left");
    }
    Ok(())
}

/// The checks of [`irq_route_holds_the_line`] with `holder`, a second
/// derivation of the routed `single`: it becomes a holder; a binding in
/// another mode is refused and one in the route's is taken; and once that
/// binding's cap is gone the holders keep the route, so a new binding is
/// taken. Deletes every cap it makes.
fn holder_checks(single: u64, holder: u64, sig: u64) -> TestResult
{
    irq_route(holder, 0).map_err(|_| "hw::irq_route_holds_the_line: a second holder refused")?;
    let bound = syscall::cap_derive(single, syscall::RIGHTS_IRQ_NOTIFY)
        .map_err(|_| "hw::irq_route_holds_the_line: cap_derive failed")?;
    let other_mode = irq_register(bound, sig, syscall_abi::IRQ_MODE_LEVEL);
    let registered = irq_register(bound, sig, 0).and_then(|()| irq_ack(bound));
    syscall::cap_delete(bound).ok();
    if other_mode != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("hw::irq_route_holds_the_line: bound in another mode than the route's");
    }
    registered.map_err(|_| "hw::irq_route_holds_the_line: bind on the routed line refused")?;
    let rebound = syscall::cap_derive(single, syscall::RIGHTS_IRQ_NOTIFY)
        .map_err(|_| "hw::irq_route_holds_the_line: cap_derive failed")?;
    let kept = irq_register(rebound, sig, 0);
    syscall::cap_delete(rebound).ok();
    kept.map_err(|_| "hw::irq_route_holds_the_line: the route went with the last binding")?;
    Ok(())
}

// ── SYS_IRQ_REMAP ────────────────────────────────────────────────────────────

/// `irq_remap` and the remapping selectors of `SYS_CAP_INFO`: on riscv64,
/// which has no interrupt remapping the kernel programs, each is
/// `NotSupported`. On x86-64, the switch is refused without
/// `RIGHTS_IRQ_MINT`, for an unknown setting, and while a line is routed
/// (`InvalidState`); a routed line has no remapping entry with remapping off
/// (`InvalidState`); and the handle count covers at least one CPU's device
/// vectors. Remapping is never turned on: with no IOMMU remapping ktest's
/// interrupts, the remappable formats would deliver none.
pub fn irq_remap_refusals(ctx: &TestContext) -> TestResult
{
    let authority = msg_authority(ctx)?;
    let line = crate::arch::ROUTABLE_HIGH_IRQ_IDS
        .first()
        .and_then(|&id| isolate_irq_id(ctx, id));
    let result = line
        .ok_or("hw::irq_remap_refusals: cannot isolate a line")
        .and_then(|line| remap_refusals(authority, line));
    if let Some(line) = line
    {
        syscall::cap_delete(line).ok();
    }
    syscall::cap_delete(authority).ok();
    result
}

/// The checks of [`irq_remap_refusals`] through `authority` and the line cap
/// `line`, which it routes.
fn remap_refusals(authority: u64, line: u64) -> TestResult
{
    let handles = syscall::cap_info(authority, syscall_abi::CAP_INFO_IRQ_REMAP_HANDLES);
    if cfg!(target_arch = "riscv64")
    {
        let not_supported = SyscallError::NotSupported as i64;
        if irq_remap(authority, syscall_abi::IRQ_REMAP_ON) != Err(not_supported)
            || handles != Err(not_supported)
        {
            return Err("hw::irq_remap_refusals: riscv64 took interrupt remapping");
        }
        irq_route(line, 0).map_err(|_| "hw::irq_remap_refusals: route refused")?;
        if syscall::cap_info(line, syscall_abi::CAP_INFO_IRQ_REMAP_ENTRY) != Err(not_supported)
        {
            return Err("hw::irq_remap_refusals: riscv64 reported a remapping entry");
        }
        return Ok(());
    }
    let handles = handles.map_err(|_| "hw::irq_remap_refusals: no handle count")?;
    // One CPU's device vectors, 33 to 249.
    if handles < 217
    {
        return Err("hw::irq_remap_refusals: handle count below one CPU's device vectors");
    }
    if irq_remap(authority, syscall_abi::IRQ_REMAP_ON_EXTENDED + 1)
        != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("hw::irq_remap_refusals: an unknown setting was taken");
    }
    let notify_only = syscall::cap_derive(authority, syscall::RIGHTS_IRQ_NOTIFY)
        .map_err(|_| "hw::irq_remap_refusals: cap_derive failed")?;
    let refused = irq_remap(notify_only, syscall_abi::IRQ_REMAP_ON);
    syscall::cap_delete(notify_only).ok();
    if refused != Err(SyscallError::InsufficientRights as i64)
    {
        return Err("hw::irq_remap_refusals: switched without RIGHTS_IRQ_MINT");
    }
    irq_route(line, 0).map_err(|_| "hw::irq_remap_refusals: route refused")?;
    if irq_remap(authority, syscall_abi::IRQ_REMAP_ON) != Err(SyscallError::InvalidState as i64)
    {
        return Err("hw::irq_remap_refusals: switched while a line is routed");
    }
    if syscall::cap_info(line, syscall_abi::CAP_INFO_IRQ_REMAP_ENTRY)
        != Err(SyscallError::InvalidState as i64)
    {
        return Err("hw::irq_remap_refusals: a remapping entry with remapping off");
    }
    Ok(())
}

// ── SYS_MMIO_SPLIT ────────────────────────────────────────────────────────────

/// `mmio_split` on a derived copy of the first boot `Mmio` cap of at least two
/// pages returns two valid, distinct children. Skipped if no suitable cap
/// exists.
pub fn mmio_split_carves(ctx: &TestContext) -> TestResult
{
    let Some((lo, hi)) = boot_caps(ctx, CapType::Mmio)
        .filter(|d| d.aux1 >= 0x2000)
        .find_map(|d| split_copy(d.slot))
    else
    {
        crate::log("ktest: hw::mmio_split_carves SKIP (no Mmio >= 2 pages in initial cap set)");
        return Ok(());
    };
    syscall::cap_delete(lo).ok();
    syscall::cap_delete(hi).ok();
    if lo == 0 || hi == 0 || lo == hi
    {
        return Err("hw::mmio_split_carves: split returned bad slot ids");
    }
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

// ── SYS_MMIO_MERGE ────────────────────────────────────────────────────────────

/// One page, the granule of `SYS_MMIO_SPLIT` and `SYS_MMIO_MERGE`.
const PAGE: u64 = 0x1000;

/// Four sibling `Mmio` caps over adjacent ranges, `a`, `b` and `c` one page
/// each from the base and `d` the rest, split from a derived copy of `boot`,
/// a boot `Mmio` cap, so the boot cap stays whole and every piece is a child
/// of it.
#[derive(Clone, Copy)]
struct Pieces
{
    boot: u64,
    a: u64,
    b: u64,
    c: u64,
    d: u64,
}

impl Pieces
{
    /// Split a copy of the first boot `Mmio` cap of at least four pages;
    /// `None` when the boot configuration has none.
    fn split(ctx: &TestContext) -> Option<Self>
    {
        // SAFETY: the kernel maps the read-only InitInfo page at init_info_va for
        // ktest's lifetime.
        let info = unsafe { &*(ctx.init_info_va as *const init_protocol::InitInfo) };
        crate::init_info::descriptors(info)
            .iter()
            .filter(|d| d.cap_type == init_protocol::CapType::Mmio && d.aux1 >= 4 * PAGE)
            .find_map(|d| Self::split_copy(d.slot))
    }

    /// Split a copy of `boot` page by page into the pieces; `None`, with
    /// every cap made deleted, when a step fails.
    fn split_copy(boot: u64) -> Option<Self>
    {
        let copy = syscall::cap_derive(boot, syscall::RIGHTS_ALL).ok()?;
        let mut made = [0u64; 3];
        let mut rest = copy;
        for piece in &mut made
        {
            let Ok((page, upper)) = mmio_split(rest, PAGE)
            else
            {
                delete_all(&made);
                syscall::cap_delete(rest).ok();
                return None;
            };
            *piece = page;
            rest = upper;
        }
        let [a, b, c] = made;
        Some(Self {
            boot,
            a,
            b,
            c,
            d: rest,
        })
    }

    fn all(self) -> [u64; 4]
    {
        [self.a, self.b, self.c, self.d]
    }
}

/// Delete every cap of `caps`; a handle a merge consumed, or a 0, no longer
/// resolves, and its delete fails harmlessly.
fn delete_all(caps: &[u64])
{
    for &cap in caps
    {
        syscall::cap_delete(cap).ok();
    }
}

/// `mmio_merge` joins two adjacent sibling caps: both handles stop
/// resolving, a mapping made through either is withdrawn, the joined cap maps
/// both pages contiguously from the lower base, and it merges again with the
/// next sibling (a chain).
pub fn mmio_merge_joins(ctx: &TestContext) -> TestResult
{
    let Some(p) = Pieces::split(ctx)
    else
    {
        crate::log("ktest: hw::mmio_merge_joins SKIP (no Mmio >= 4 pages in initial cap set)");
        return Ok(());
    };
    let mut joined = [0u64; 2];
    let result = merge_joins(ctx, p, &mut joined);
    // SAFETY: `MMIO_TEST_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    let _ = unsafe { mem_unmap(ctx.aspace_cap, MMIO_TEST_VA, 3) };
    delete_all(&p.all());
    delete_all(&joined);
    result
}

/// The checks of [`mmio_merge_joins`], recording each joined cap in `joined`
/// for the caller's cleanup.
fn merge_joins(ctx: &TestContext, p: Pieces, joined: &mut [u64; 2]) -> TestResult
{
    // SAFETY: `MMIO_TEST_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest. The test only queries
    // the mappings, never accesses them, and the caller unmaps the span before
    // the VA's next use (`mmio_map` § Safety).
    unsafe { syscall::mmio_map(ctx.aspace_cap, p.a, MMIO_TEST_VA, 0) }
        .map_err(|_| "hw::mmio_merge_joins: mmio_map of the lower piece failed")?;
    let base = aspace_query(ctx.aspace_cap, MMIO_TEST_VA)
        .map_err(|_| "hw::mmio_merge_joins: aspace_query of the lower piece failed")?;

    let ab = mmio_merge(p.a, p.b).map_err(|_| "hw::mmio_merge_joins: mmio_merge(a, b) failed")?;
    joined[0] = ab;
    if aspace_query(ctx.aspace_cap, MMIO_TEST_VA).is_ok()
    {
        return Err("hw::mmio_merge_joins: the lower piece's mapping survived the merge");
    }
    let gone = Err(SyscallError::InvalidCapability as i64);
    if syscall::cap_info(p.a, syscall_abi::CAP_INFO_TAG_RIGHTS).map(|_| ()) != gone
        || syscall::cap_info(p.b, syscall_abi::CAP_INFO_TAG_RIGHTS).map(|_| ()) != gone
    {
        return Err("hw::mmio_merge_joins: a merged cap still resolves");
    }

    // SAFETY: as for the first map; the lower piece's mapping is gone.
    unsafe { syscall::mmio_map(ctx.aspace_cap, ab, MMIO_TEST_VA, 0) }
        .map_err(|_| "hw::mmio_merge_joins: mmio_map of the joined cap failed")?;
    if aspace_query(ctx.aspace_cap, MMIO_TEST_VA + PAGE) != Ok(base.wrapping_add(PAGE))
    {
        return Err(
            "hw::mmio_merge_joins: the joined cap does not map the upper page after the base",
        );
    }

    let abc = mmio_merge(ab, p.c).map_err(|_| "hw::mmio_merge_joins: mmio_merge(ab, c) failed")?;
    joined[0] = abc;
    if aspace_query(ctx.aspace_cap, MMIO_TEST_VA).is_ok()
    {
        return Err("hw::mmio_merge_joins: the joined cap's mapping survived the second merge");
    }
    // SAFETY: as for the first map; nothing is mapped in the span.
    unsafe { syscall::mmio_map(ctx.aspace_cap, abc, MMIO_TEST_VA, 0) }
        .map_err(|_| "hw::mmio_merge_joins: mmio_map of the chain failed")?;
    if aspace_query(ctx.aspace_cap, MMIO_TEST_VA + 2 * PAGE) != Ok(base.wrapping_add(2 * PAGE))
    {
        return Err("hw::mmio_merge_joins: the chain does not map its third page after the base");
    }
    // The chain joins the rest of the copy, its one remaining neighbour.
    let all =
        mmio_merge(abc, p.d).map_err(|_| "hw::mmio_merge_joins: mmio_merge(abc, d) failed")?;
    joined[0] = all;
    Ok(())
}

/// `mmio_merge` refuses, changing neither cap: ranges with a gap between
/// them, ranges in the wrong order, the same cap twice, a non-`Mmio` cap,
/// caps whose rights differ, caps that are not derivation siblings, and a
/// cap with a derivation child, which merges once the child is gone.
pub fn mmio_merge_refusals(ctx: &TestContext) -> TestResult
{
    let Some(p) = Pieces::split(ctx)
    else
    {
        crate::log("ktest: hw::mmio_merge_refusals SKIP (no Mmio >= 4 pages in initial cap set)");
        return Ok(());
    };
    let mut made = [0u64; 4];
    let result = merge_refusals(ctx, p, &mut made);
    delete_all(&made);
    delete_all(&p.all());
    result
}

/// The checks of [`mmio_merge_refusals`], recording each cap it makes in
/// `made` for the caller's cleanup.
fn merge_refusals(ctx: &TestContext, p: Pieces, made: &mut [u64; 4]) -> TestResult
{
    let invalid = Err(SyscallError::InvalidArgument as i64);
    if mmio_merge(p.a, p.c) != invalid
    {
        return Err("hw::mmio_merge_refusals: caps with a gap between them merged");
    }
    if mmio_merge(p.b, p.a) != invalid
    {
        return Err("hw::mmio_merge_refusals: caps in the wrong order merged");
    }
    if mmio_merge(p.a, p.a) != invalid
    {
        return Err("hw::mmio_merge_refusals: a cap merged with itself");
    }
    if mmio_merge(ctx.memory_base, p.a) != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("hw::mmio_merge_refusals: a Memory cap was not refused as a capability");
    }

    // A Map-only sibling copy of the boot cap, split: its upper piece starts
    // where `a` ends, under the same parent, with fewer rights.
    let narrow = syscall::cap_derive(p.boot, syscall_abi::RIGHTS_MMIO_MAP)
        .map_err(|_| "hw::mmio_merge_refusals: cap_derive of a Map-only copy failed")?;
    made[0] = narrow;
    let (narrow_lo, narrow_hi) = mmio_split(narrow, PAGE)
        .map_err(|_| "hw::mmio_merge_refusals: mmio_split of the Map-only copy failed")?;
    made[0] = narrow_lo;
    made[1] = narrow_hi;
    if mmio_merge(p.a, narrow_hi) != invalid
    {
        return Err("hw::mmio_merge_refusals: caps with different rights merged");
    }

    // `child` covers `a`'s range and ends where `b` starts, but its parent
    // is `a`, not the boot cap.
    let child = syscall::cap_derive(p.a, syscall::RIGHTS_ALL)
        .map_err(|_| "hw::mmio_merge_refusals: cap_derive of a child failed")?;
    made[2] = child;
    if mmio_merge(child, p.b) != invalid
    {
        return Err("hw::mmio_merge_refusals: caps that are not siblings merged");
    }
    if mmio_merge(p.a, p.b) != Err(SyscallError::InvalidState as i64)
    {
        return Err("hw::mmio_merge_refusals: a cap with a derivation child merged");
    }
    syscall::cap_delete(child)
        .map_err(|_| "hw::mmio_merge_refusals: cap_delete of the child failed")?;
    made[3] = mmio_merge(p.a, p.b)
        .map_err(|_| "hw::mmio_merge_refusals: the refused caps did not merge once childless")?;
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

/// Isolate `id`, route it, register `irq_sig` on it, acknowledge it, and
/// delete the cap, which releases the route.
fn route_high_id(ctx: &TestContext, id: u32, irq_sig: u64) -> TestResult
{
    let single =
        isolate_irq_id(ctx, id).ok_or("hw::irq_register_high_id: cannot isolate the id")?;
    let registered = irq_route(single, 0).and_then(|()| irq_register(single, irq_sig, 0));
    let acked = registered.and_then(|()| irq_ack(single));
    let deleted = syscall::cap_delete(single);
    registered.map_err(|_| "hw::irq_register_high_id: routable id refused")?;
    acked.map_err(|_| "hw::irq_register_high_id: irq_ack failed")?;
    deleted.map_err(|_| "hw::irq_register_high_id: cap_delete of the id failed")
}

/// Isolate `id` and check `irq_route` and `irq_register` refuse it with
/// `InvalidArgument` and that deleting its cap succeeds.
fn refuse_unroutable_id(ctx: &TestContext, id: u32, irq_sig: u64) -> TestResult
{
    let single = isolate_irq_id(ctx, id)
        .ok_or("hw::irq_register_unroutable_id_err: cannot isolate the id")?;
    let routed = irq_route(single, 0);
    let err = irq_register(single, irq_sig, 0);
    // Deleting the cap must not touch the routing table for an id it cannot
    // index (the kernel panicked here before the teardown guard).
    let deleted = syscall::cap_delete(single);
    if err != Err(SyscallError::InvalidArgument as i64)
        || routed != Err(SyscallError::InvalidArgument as i64)
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
    for boot in boot_caps(ctx, CapType::Interrupt)
    {
        // A boot cap an earlier test consumed refuses the derive; keep
        // looking.
        let Ok(copy) = syscall::cap_derive(boot.slot, syscall::RIGHTS_ALL)
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
        let Some(next) = id.checked_add(1)
        else
        {
            syscall::cap_delete(from_id).ok();
            return None;
        };
        return match irq_split(from_id, next)
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
    let mints = cpus
        .checked_mul(MSG_SLOTS_PER_CPU_MAX)
        .ok_or("hw::irq_msg_exhaustion_and_reuse: mint bound out of range")?;
    let pages = mints
        .div_ceil(syscall_abi::CSPACE_SLOTS_PER_PAGE)
        .checked_add(mints.div_ceil(syscall_abi::CSPACE_BODIES_PER_PAGE))
        .and_then(|pages| pages.checked_add(MSG_AUGMENT_PAGES))
        .ok_or("hw::irq_msg_exhaustion_and_reuse: page bound out of range")?;
    Ok((mints, pages))
}

/// A derived copy of the first cap in the test's `CSpace` that mints a
/// message-signaled target, carrying every right of it, and nothing minted.
/// The root Interrupt cap carries `RIGHTS_IRQ_MINT`, so one is always found.
pub fn msg_authority(ctx: &TestContext) -> Result<u64, &'static str>
{
    for boot in boot_caps(ctx, CapType::Interrupt)
    {
        // A cap without the right refuses and is left intact; a mint through
        // it proves the right.
        let Ok(minted) = irq_msg_alloc(boot.slot)
        else
        {
            continue;
        };
        syscall::cap_delete(minted).map_err(|_| "msg_authority: cap_delete of the probe failed")?;
        return syscall::cap_derive(boot.slot, syscall::RIGHTS_ALL)
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
    let id = crate::arch::ROUTABLE_HIGH_IRQ_IDS
        .first()
        .copied()
        .ok_or("hw::irq_msg_info_wired_err: no routable high IRQ id")?;
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
    // The line is carved before the mints fill the `CSpace`.
    let line = crate::arch::ROUTABLE_HIGH_IRQ_IDS
        .first()
        .and_then(|&id| isolate_irq_id(ctx, id));
    let result = (|| -> TestResult {
        let line = line.ok_or("hw::irq_msg_exhaustion_and_reuse: cannot isolate a line")?;
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
                    minted = minted.saturating_add(1);
                }
                Err(e) if e == SyscallError::QuotaExceeded as i64 => break,
                Err(e) if e == SyscallError::OutOfMemory as i64 && donated < donation_limit =>
                {
                    syscall::cap_create_cspace(ctx.memory_base, ctx.cspace_cap, MSG_AUGMENT_PAGES)
                        .map_err(|_| "hw::irq_msg_exhaustion_and_reuse: CSpace augment failed")?;
                    donated = donated.saturating_add(MSG_AUGMENT_PAGES);
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
        if irq_route(line, 0) != Err(SyscallError::QuotaExceeded as i64)
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
    syscall::cap_revoke(authority).ok();
    syscall::cap_delete(authority).ok();
    result
}

/// Target pages [`mint_every_slot`] tells apart: one per CPU (a local APIC on
/// x86-64, an IMSIC interrupt file on riscv64), so at most `MAX_CPUS`.
const MSG_PAGES_MAX: usize = boot_protocol::MAX_CPUS;

/// Slots of [`MSG_PAGE_TABLE`], twice the pages it holds, so a probe for a page
/// never meets a full table.
const MSG_PAGE_SLOTS: usize = 2 * MSG_PAGES_MAX;

/// Data values one page's row of [`MSG_SEEN`] tells apart:
/// [`MSG_SLOTS_PER_CPU_MAX`], as an index.
const MSG_DATA_VALUES: usize = 2048;
const _: () = assert!(MSG_DATA_VALUES as u64 == MSG_SLOTS_PER_CPU_MAX);

/// Words of one page's row of [`MSG_SEEN`]: one bit per data value below
/// [`MSG_DATA_VALUES`].
const MSG_ROW_WORDS: usize = MSG_DATA_VALUES / 64;

/// The target pages [`mint_every_slot`] has seen, an open-addressed table of
/// page numbers plus one (0 marks a free slot), probed linearly from the
/// page number modulo its length.
static MSG_PAGE_TABLE: [core::sync::atomic::AtomicU64; MSG_PAGE_SLOTS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MSG_PAGE_SLOTS];

/// The row of [`MSG_SEEN`] each page of [`MSG_PAGE_TABLE`] took, at the same
/// index: rows are taken in the order the pages are first seen.
static MSG_PAGE_ROW: [core::sync::atomic::AtomicU32; MSG_PAGE_SLOTS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; MSG_PAGE_SLOTS];

/// The messages [`mint_every_slot`] has seen live, one bit per [`msg_key`]: a
/// row of [`MSG_ROW_WORDS`] words per target page. Statics, since ktest has no
/// heap; only that function, which ktest's sequential unit tier runs on one
/// thread, touches them.
static MSG_SEEN: [core::sync::atomic::AtomicU64; MSG_PAGES_MAX * MSG_ROW_WORDS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; MSG_PAGES_MAX * MSG_ROW_WORDS];

/// Forget every message and page [`mint_every_slot`] has seen.
fn msg_seen_reset()
{
    for word in MSG_PAGE_TABLE.iter().chain(&MSG_SEEN)
    {
        word.store(0, core::sync::atomic::Ordering::Relaxed);
    }
}

/// The row of [`MSG_SEEN`] for target page `page`, taking the next free row
/// (`rows` counts the rows taken) the first time the page is seen. Fails when
/// more pages are seen than there are CPUs to own them.
fn msg_page_row(page: u64, rows: &mut usize) -> Result<usize, &'static str>
{
    const MANY: &str = "hw::irq_msg_every_slot_one_notification: more target pages than CPUs";
    let tag = page.checked_add(1).ok_or(MANY)?;
    // The remainder is below MSG_PAGE_SLOTS, which fits a usize.
    let slot = page.checked_rem(MSG_PAGE_SLOTS as u64).ok_or(MANY)?;
    let mut index = usize::try_from(slot).map_err(|_| MANY)?;
    for _ in 0..MSG_PAGE_SLOTS
    {
        let (Some(slot), Some(row)) = (MSG_PAGE_TABLE.get(index), MSG_PAGE_ROW.get(index))
        else
        {
            return Err(MANY);
        };
        match slot.load(core::sync::atomic::Ordering::Relaxed)
        {
            0 =>
            {
                if *rows >= MSG_PAGES_MAX
                {
                    return Err(MANY);
                }
                let taken = *rows;
                slot.store(tag, core::sync::atomic::Ordering::Relaxed);
                row.store(
                    u32::try_from(taken).map_err(|_| MANY)?,
                    core::sync::atomic::Ordering::Relaxed,
                );
                *rows = taken.saturating_add(1);
                return Ok(taken);
            }
            seen if seen == tag =>
            {
                return usize::try_from(row.load(core::sync::atomic::Ordering::Relaxed))
                    .map_err(|_| MANY);
            }
            _ => index = index.saturating_add(1) % MSG_PAGE_SLOTS,
        }
    }
    Err(MANY)
}

/// The bit of message (`address`, `data`) in [`MSG_SEEN`]: the data's bit in
/// the row of the address's whole page (the local APIC on x86-64, the IMSIC
/// file on riscv64). Two messages share a key exactly when both their pages
/// and their data are equal, at any CPU count. Fails for data past 11 bits.
fn msg_key(address: u64, data: u64, rows: &mut usize) -> Result<usize, &'static str>
{
    if data >= MSG_SLOTS_PER_CPU_MAX
    {
        return Err("hw::irq_msg_every_slot_one_notification: data past 11 bits");
    }
    let row = msg_page_row(address >> 12, rows)?;
    let data = usize::try_from(data)
        .map_err(|_| "hw::irq_msg_every_slot_one_notification: data past 11 bits")?;
    row.checked_mul(MSG_DATA_VALUES)
        .and_then(|base| base.checked_add(data))
        .ok_or("hw::irq_msg_every_slot_one_notification: message key out of range")
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
    msg_seen_reset();
    let mut rows = 0;
    let mut minted = 0;
    let mut donated = 0;
    let mut refills = 0u64;
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
                minted = minted.saturating_add(1);
                refilled = false;
                let (address, data) = msg_of(cap)
                    .map_err(|_| "hw::irq_msg_every_slot_one_notification: no message")?;
                if !crate::arch::msi_message_plausible(address, data)
                {
                    return Err("hw::irq_msg_every_slot_one_notification: message out of range");
                }
                let key = msg_key(address, data, &mut rows)?;
                let bit = 1u64 << (key % 64);
                let word = MSG_SEEN
                    .get(key / 64)
                    .ok_or("hw::irq_msg_every_slot_one_notification: message key out of range")?;
                if word.fetch_or(bit, core::sync::atomic::Ordering::Relaxed) & bit != 0
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
                donated = donated.saturating_add(MSG_AUGMENT_PAGES);
                refills = refills.saturating_add(1);
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
    for boot in boot_caps(ctx, CapType::Interrupt)
    {
        // A boot cap an earlier test consumed refuses the derive; keep
        // looking.
        let Ok(copy) = syscall::cap_derive(boot.slot, syscall::RIGHTS_ALL)
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

/// A raw `SYS_IRQ_SPLIT` whose split-point register has a bit set above bit 31
/// returns `InvalidArgument` and leaves the cap unsplit, even when its low 32
/// bits lie inside the range: `0x1_0000_0001` would otherwise split a range
/// starting at IRQ id 0 at id 1. Run on a derived copy of the first
/// Interrupt-range cap that the plain split at id 1 then carves, so the refusal
/// is the register's, not the range's. Skipped if no such cap exists.
pub fn irq_split_wide_arg_err(ctx: &TestContext) -> TestResult
{
    const WIDE_SPLIT_AT: u64 = (1 << 32) | 1;
    for boot in boot_caps(ctx, CapType::Interrupt)
    {
        // A boot cap an earlier test consumed refuses the derive; keep
        // looking.
        let Ok(copy) = syscall::cap_derive(boot.slot, syscall::RIGHTS_ALL)
        else
        {
            continue;
        };
        // SAFETY: raw_syscall3's four conditions hold. SYS_IRQ_SPLIT takes no
        // pointer and uses no IPC buffer; it changes no mapping and no thread
        // beyond the registers the call clobbers in this thread; and in
        // ktest's CSpace it changes only the slot `copy` names and the fresh
        // slots it fills with the two children.
        let ret =
            unsafe { syscall::raw_syscall3(syscall_abi::SYS_IRQ_SPLIT, copy, WIDE_SPLIT_AT, 0) };
        if ret >= 0
        {
            // The split consumed `copy`; its children are in fresh slots this
            // call cannot name without the secondary return register.
            return Err("hw::irq_split_wide_arg_err: split accepted a split point above u32::MAX");
        }
        if ret != SyscallError::InvalidArgument as i64
        {
            // Wrong tag; keep scanning.
            syscall::cap_delete(copy).ok();
            continue;
        }
        // The refused split left the copy whole: the plain split at id 1
        // carves it when its range starts at 0 with more than one id.
        match irq_split(copy, 1)
        {
            Ok((below, above)) =>
            {
                syscall::cap_delete(below).ok();
                syscall::cap_delete(above).ok();
                return Ok(());
            }
            Err(_) =>
            {
                syscall::cap_delete(copy).ok();
            }
        }
    }

    crate::log("ktest: hw::irq_split_wide_arg_err SKIP (no Interrupt range caps with count>1)");
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
