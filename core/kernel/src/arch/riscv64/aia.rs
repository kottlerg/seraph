// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/aia.rs

//! RISC-V Advanced Interrupt Architecture: the supervisor-level APLIC domain in
//! MSI delivery mode, and each hart's supervisor-level IMSIC interrupt file.
//!
//! The kernel requires AIA (Ssaia, an APLIC and an IMSIC) and has no other
//! external-interrupt path: [`init_bsp`] halts the boot without them.
//!
//! # Delivery
//! The M-mode firmware delegates every wired source to the supervisor-level APLIC
//! domain the bootloader reports (`KernelMmio::aplic`) and programs that domain's
//! MSI address configuration, which only the machine-level domain can write. The
//! kernel runs the domain in MSI delivery mode: a routed source's `target`
//! register names a hart (its hart index, which is its hart id, as the boot
//! checked against `ImsicLayout::s_file_address`) and an interrupt identity
//! (EID) in that hart's supervisor-level IMSIC file. An asserted, enabled source
//! is forwarded as a write to that file, which raises the hart's supervisor
//! external interrupt (`sip.SEIP`); the trap claims the identity through the
//! `stopei` CSR ([`claim`]), whose entry in the hart's EID row
//! `irq::dispatch_device_irq` delivers.
//!
//! # Identities
//! Each hart's file has its own identity space, `1..=ids` (`KernelMmio::imsic`).
//! [`init_eid_storage`] allocates one EID row per CPU, a per-CPU slab sized from
//! the boot CPU count: entry `e` of CPU `c`'s row is identity `e`'s
//! `irq::SlotEntry` on that CPU, which names the source that takes the identity,
//! or is free. A source is a routed APLIC source or a message-signaled target,
//! which the entry anchors (its id is computed from the CPU and the identity,
//! `irq::message_id`). A source's route ([`route`]) or a target's mint
//! ([`alloc_message`]) takes the lowest free identity of its target CPU's row,
//! and its release ([`unroute`], [`free_message`]) frees it. A message-signaled
//! target is raised by a device's
//! write of its identity to its hart's file ([`message_address`]), with no APLIC
//! source between. Every identity of every file is enabled at
//! its hart's init ([`init_hart`]) and never disabled: an IMSIC enable bit is
//! reachable only through its own hart's CSRs, so masking is the APLIC's
//! (`setienum`/`clrienum`, MMIO any hart can write), and no route change needs a
//! cross-hart CSR write.
//!
//! An identity a release frees can still be pending in its file, from a
//! forward that preceded the release. Its claim finds the entry free and drops
//! it, or, once a later route has taken the identity, delivers once to that
//! source's receivers, which read their device's state as every driver does on
//! a delivery.
//!
//! # Level-sensitive sources
//! In MSI delivery mode the APLIC clears a source's pending bit when it forwards
//! it, and does not set it again while a level-sensitive source stays asserted
//! (AIA specification § 4.9.2). [`unmask`] therefore writes a level source's
//! number to `setipnum_le` after enabling it, which pends the source again only
//! if it is still asserted; a line held asserted across its receivers'
//! acknowledgements is delivered again, as on the x86-64 I/O APIC.
//!
//! # Locking
//! Every APLIC access is a single register write, with no read-modify-write, so
//! none takes a lock. The per-source routes ([`SOURCE_ROUTES`]) and the EID rows
//! are written only by [`route`], [`unroute`], [`alloc_message`] and
//! [`free_message`], which `irq` serialises under its routing lock; [`unmask`]
//! runs under it too, and a delivery reads the entry [`claim`] returns from its
//! own hart's row lock-free, inside that hart's delivery gate
//! (`irq::DeliveryGate`).

use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use super::aia_encoding::{
    APLIC_MAX_HART_INDEX, APLIC_MAX_SOURCES, APLIC_MIN_WINDOW, IMSIC_MAX_IDS, SourceRoute,
    aplic_mode_is_level, aplic_msi_target, aplic_source_mode, aplic_sources_for, imsic_ids_valid,
    imsic_reg_words, lowest_free_eid,
};
use crate::irq::{Slot, SlotEntry};
use crate::mm::paging::phys_to_virt;

// ── APLIC registers ───────────────────────────────────────────────────────────

/// Domain configuration register.
const APLIC_DOMAINCFG: u64 = 0x0000;

/// `domaincfg` Interrupt Enable bit.
const DOMAINCFG_IE: u32 = 1 << 8;

/// `domaincfg` Delivery Mode bit: 1 selects MSI delivery.
const DOMAINCFG_DM: u32 = 1 << 2;

/// Writing a source number here sets its enable bit.
const APLIC_SETIENUM: u64 = 0x1EDC;

/// Writing a source number here clears its enable bit.
const APLIC_CLRIENUM: u64 = 0x1FDC;

/// Writing a source number here (little-endian) sets its pending bit, for a
/// level-sensitive source only while it is asserted.
const APLIC_SETIPNUM_LE: u64 = 0x2000;

/// Offset of source `source`'s `sourcecfg` register (sources from 1).
const fn sourcecfg_offset(source: u32) -> u64
{
    source as u64 * 4
}

/// Offset of source `source`'s `target` register (sources from 1).
const fn target_offset(source: u32) -> u64
{
    // A u32 source times 4 is below 2^34, so the sum does not wrap.
    0x3000u64.wrapping_add(source as u64 * 4)
}

// ── IMSIC indirect registers (through `siselect` / `sireg`) ──────────────────

/// `eidelivery`: 1 enables the file's delivery of interrupts to the hart.
const ISEL_EIDELIVERY: u64 = 0x70;

/// `eithreshold`: 0 admits every enabled identity.
const ISEL_EITHRESHOLD: u64 = 0x72;

/// First pending-bit register; on RV64 the `k`-th 64-bit one is `0x80 + 2k`.
const ISEL_EIP0: u64 = 0x80;

/// First enable-bit register; on RV64 the `k`-th 64-bit one is `0xC0 + 2k`.
const ISEL_EIE0: u64 = 0xC0;

// ── State ─────────────────────────────────────────────────────────────────────

/// Physical base of the APLIC domain's register window; set by [`init_bsp`].
static APLIC_BASE: AtomicU64 = AtomicU64::new(0);

/// Number of sources the APLIC domain implements (`1..=APLIC_SOURCES`); set by
/// [`init_bsp`].
static APLIC_SOURCES: AtomicU32 = AtomicU32::new(0);

/// Interrupt identities each IMSIC file implements (`1..=ids`); set by
/// [`init_eid_storage`].
static IMSIC_IDS: AtomicU32 = AtomicU32::new(0);

/// Base of the EID-row slab: `IMSIC_IDS + 1` entries per CPU (module doc
/// § Identities); set by [`init_eid_storage`].
static EID_ROWS: AtomicPtr<SlotEntry> = AtomicPtr::new(core::ptr::null_mut());

/// The route of each source (`SourceRoute::pack`), 0 while unrouted. Indexed by
/// source number over the specification's source space. Written only by
/// [`route`] and [`unroute`] under `irq`'s routing lock.
static SOURCE_ROUTES: [AtomicU64; APLIC_MAX_SOURCES as usize + 1] =
    [const { AtomicU64::new(0) }; APLIC_MAX_SOURCES as usize + 1];

/// The EID-row slab: one [`SlotEntry`] per identity (identity 0 included) per
/// CPU, the per-CPU element count set at boot from the IMSIC's identity count.
const EID_ROW_SLAB: crate::sched::PerCpuSlab =
    crate::sched::PerCpuSlab::of::<SlotEntry>("IMSIC_EID_ROWS");
const _: () = assert!(
    EID_ROW_SLAB
        .with_elems_per_cpu(IMSIC_MAX_IDS as usize + 1)
        .sized_at_every_width(),
    "IMSIC_EID_ROWS slab overflows"
);

// ── Initialisation ────────────────────────────────────────────────────────────

/// Allocate the per-CPU EID rows for `cpu_count` CPUs, each sized from the
/// IMSIC's identity count. Halts the boot when the bootloader reported no IMSIC
/// or an identity count outside the AIA specification's range. Called from
/// `init_ap_percpu_storage` (Phase 4, after `kernel_mmio` is captured), before
/// any interrupt is routed.
pub fn init_eid_storage(cpu_count: usize, allocator: &mut crate::mm::BuddyAllocator)
{
    let imsic = crate::platform::kernel_mmio().imsic;
    if imsic.base == 0 || !imsic_ids_valid(imsic.ids)
    {
        crate::fatal(
            "riscv64: no supervisor-level IMSIC reported, or its identity count is \
             outside 63..=2047; AIA (APLIC and IMSIC) is required. Check the firmware \
             tables (ACPI MADT / DTB) or the QEMU machine (aia=aplic-imsic).",
        );
    }
    let row_len = imsic.ids as usize + 1;
    let base = crate::sched::alloc_per_cpu_slab::<SlotEntry>(
        EID_ROW_SLAB.with_elems_per_cpu(row_len),
        cpu_count,
        allocator,
    );
    IMSIC_IDS.store(imsic.ids, Ordering::Relaxed);
    EID_ROWS.store(base, Ordering::Release);
}

/// CPU `cpu`'s EID row, or `None` when `cpu` is past the boot CPU count or the
/// rows are not yet allocated.
fn eid_row(cpu: usize) -> Option<&'static [SlotEntry]>
{
    let cpu_count = crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize;
    let base = EID_ROWS.load(Ordering::Acquire);
    if cpu >= cpu_count || base.is_null()
    {
        return None;
    }
    let row_len = IMSIC_IDS.load(Ordering::Relaxed) as usize + 1;
    let start = cpu.checked_mul(row_len)?;
    // SAFETY: the slab holds `row_len` zero-initialised entries (an atomic, for
    // which zero is a valid value and a free slot) for each of the boot CPUs,
    // and `cpu` is below their count; the slab is never freed.
    Some(unsafe { core::slice::from_raw_parts(base.add(start), row_len) })
}

/// Halt the boot unless the hart with hart id `hart` can be an APLIC MSI target:
/// its id fits the `target` register's hart index, and its supervisor-level
/// file lies where the reported IMSIC layout places it.
fn require_hart_target(hart: u32)
{
    let imsic = crate::platform::kernel_mmio().imsic;
    if hart > APLIC_MAX_HART_INDEX || imsic.s_file_address(u64::from(hart)).is_none()
    {
        crate::fatal(
            "riscv64: a hart id is past the APLIC target's hart index or outside the \
             IMSIC layout",
        );
    }
}

/// Bring up the APLIC domain and the boot hart's IMSIC file: check that every
/// hart implements Ssaia and that the bootloader reported a supervisor-level
/// APLIC domain, put the domain in MSI delivery mode with every source inactive
/// and disabled, then initialise the file of the boot hart, hart id `bsp_hart`.
/// Halts the boot when AIA is missing or the domain refuses MSI delivery.
///
/// # Safety
/// Once, on the BSP in supervisor mode with the direct map active and
/// interrupts disabled, after [`init_eid_storage`].
pub unsafe fn init_bsp(bsp_hart: u32)
{
    let km = crate::platform::kernel_mmio();
    if km.hart_caps & boot_protocol::HART_CAP_SSAIA == 0
    {
        crate::fatal(
            "riscv64: Ssaia not advertised for every hart; AIA is required. Check the \
             firmware tables (ACPI RHCT / DTB) or the QEMU -cpu selection (ssaia=on).",
        );
    }
    let Some(sources) = aplic_sources_for(km.aplic.sources)
    else
    {
        crate::fatal(
            "riscv64: no supervisor-level APLIC domain reported; AIA is required. Check \
             the firmware tables (ACPI MADT / DTB) or the QEMU machine (aia=aplic-imsic).",
        );
    };
    if km.aplic.base == 0 || km.aplic.size < APLIC_MIN_WINDOW
    {
        crate::fatal("riscv64: the APLIC domain's register window is missing or too small");
    }
    APLIC_BASE.store(km.aplic.base, Ordering::Relaxed);
    APLIC_SOURCES.store(sources, Ordering::Relaxed);
    crate::kprintln!(
        "aia: APLIC {} sources (MSI delivery), IMSIC {} identities per hart",
        sources,
        IMSIC_IDS.load(Ordering::Relaxed)
    );

    // SAFETY: the domain's window was checked above to hold every register
    // written here; the direct map covers it (below the RAM ceiling).
    unsafe {
        aplic_write(APLIC_DOMAINCFG, DOMAINCFG_DM);
        for source in 1..=sources
        {
            aplic_write(APLIC_CLRIENUM, source);
            aplic_write(sourcecfg_offset(source), 0);
        }
        aplic_write(APLIC_DOMAINCFG, DOMAINCFG_IE | DOMAINCFG_DM);
    }
    if aplic_read(APLIC_DOMAINCFG) & DOMAINCFG_DM == 0
    {
        crate::fatal("riscv64: the APLIC domain does not support MSI delivery mode");
    }
    // SAFETY: caller contract (BSP, S-mode, interrupts disabled).
    unsafe { init_hart(bsp_hart) };
}

/// Initialise the executing hart's supervisor-level IMSIC file: delivery off,
/// threshold 0, every identity's pending bit cleared and enable bit set
/// (module doc § Identities), then delivery on. `hart` is the executing hart's
/// hart id, checked here to be a valid APLIC MSI target (the boot halts
/// otherwise).
///
/// # Safety
/// On the hart `hart` names, in supervisor mode with interrupts disabled (the
/// `siselect`/`sireg` pairs must not be split by a trap), after
/// [`init_eid_storage`].
pub unsafe fn init_hart(hart: u32)
{
    require_hart_target(hart);
    let words = imsic_reg_words(IMSIC_IDS.load(Ordering::Relaxed)) as usize;
    // The k-th 64-bit pending and enable registers, every second select on RV64.
    let selects = (ISEL_EIP0..)
        .step_by(2)
        .zip((ISEL_EIE0..).step_by(2))
        .take(words);
    // SAFETY: caller contract; each select names a register Ssaia defines for
    // a file of this identity count.
    unsafe {
        imsic_write(ISEL_EIDELIVERY, 0);
        imsic_write(ISEL_EITHRESHOLD, 0);
        for (eip, eie) in selects
        {
            imsic_write(eip, 0);
            imsic_write(eie, u64::MAX);
        }
        imsic_write(ISEL_EIDELIVERY, 1);
    }
}

// ── Routing ───────────────────────────────────────────────────────────────────

/// Number of sources the APLIC domain implements (sources `1..=source_count()`).
pub fn source_count() -> u32
{
    APLIC_SOURCES.load(Ordering::Relaxed)
}

/// Whether `source` is a source the domain implements.
fn implemented(source: u32) -> bool
{
    source != 0 && source <= source_count()
}

/// The route word of `source` in [`SOURCE_ROUTES`], or `None` when the domain does
/// not implement `source`.
fn route_word(source: u32) -> Option<&'static AtomicU64>
{
    if !implemented(source)
    {
        return None;
    }
    SOURCE_ROUTES.get(source as usize)
}

/// The CPU and identity a new source takes: the next CPU in turn with a free
/// identity (`irq::next_target_cpu`) and that CPU's lowest free identity, whose
/// row entry is then set to `slot`. `None` when no CPU has a free identity.
fn take_identity(slot: Slot) -> Option<crate::irq::Target>
{
    let has_free = |cpu: usize| eid_row(cpu).and_then(lowest_free_eid).is_some();
    let cpu = crate::irq::next_target_cpu(has_free)?;
    let row = eid_row(cpu)?;
    let eid = lowest_free_eid(row)?;
    row.get(eid as usize)?.store(slot);
    // A CPU index is below MAX_CPUS, which u32 holds.
    #[allow(clippy::cast_possible_truncation)]
    let cpu = cpu as u32;
    Some(crate::irq::Target { cpu, slot: eid })
}

/// The row entry of identity `target`, or `None` when its CPU is past the boot
/// CPUs or the identity is 0 or past the file's identities.
pub fn slot_entry(target: crate::irq::Target) -> Option<&'static SlotEntry>
{
    if target.slot == 0
    {
        return None;
    }
    eid_row(target.cpu as usize)?.get(target.slot as usize)
}

/// Free identity `target`: its row entry becomes free.
fn release_identity(target: crate::irq::Target)
{
    if let Some(entry) = slot_entry(target)
    {
        entry.store(Slot::Free);
    }
}

/// Route `source`, leaving it disabled: pick its target CPU (the next in turn
/// with a free identity, `irq::next_target_cpu`), take that CPU's lowest free
/// identity, and program the source's mode from the `SYS_IRQ_REGISTER` word
/// `mode` and its target. Unmasking ([`unmask`]) enables it. Returns the CPU and
/// identity.
///
/// # Errors
/// `NoSuchLine` for a source the domain does not implement; `Exhausted` when
/// no CPU has a free identity.
///
/// Called under `irq`'s routing lock, after [`init_bsp`], for a source that is
/// not routed.
pub fn route(source: u32, mode: u32) -> Result<crate::irq::Target, crate::irq::RouteError>
{
    let Some(word) = route_word(source)
    else
    {
        return Err(crate::irq::RouteError::NoSuchLine);
    };
    let taken = take_identity(Slot::Line(source)).ok_or(crate::irq::RouteError::Exhausted)?;
    // SAFETY: `take_identity` returns a CPU with a row, so below CPU_COUNT; the
    // hart id slab is read-only after boot.
    let hart = unsafe { crate::percpu::apic_id_for(taken.cpu as usize) };
    // Every hart was checked a valid target at its init.
    let Some(target) = aplic_msi_target(hart, taken.slot)
    else
    {
        release_identity(taken);
        return Err(crate::irq::RouteError::Exhausted);
    };
    let source_mode = aplic_source_mode(mode);
    let route = SourceRoute {
        cpu: taken.cpu,
        eid: taken.slot,
        level: aplic_mode_is_level(source_mode),
    };
    word.store(route.pack(), Ordering::Relaxed);
    // SAFETY: an implemented source's registers lie in the window init_bsp
    // checked.
    unsafe {
        aplic_write(APLIC_CLRIENUM, source);
        aplic_write(sourcecfg_offset(source), source_mode);
        aplic_write(target_offset(source), target);
    }
    Ok(taken)
}

/// Release `source`'s route: disable it, make it inactive, and free its
/// identity, whose row entry is cleared with a `SeqCst` store
/// (`irq::SlotEntry`), so `irq` can then wait out a delivery on that CPU that
/// read the source from it (module doc § Identities on a forward still
/// pending). An unrouted source is only disabled.
///
/// Called under `irq`'s routing lock.
pub fn unroute(source: u32)
{
    let Some(route_word) = route_word(source)
    else
    {
        return;
    };
    // SAFETY: an implemented source's registers lie in the window init_bsp
    // checked.
    unsafe {
        aplic_write(APLIC_CLRIENUM, source);
        aplic_write(sourcecfg_offset(source), 0);
    }
    let word = route_word.swap(0, Ordering::Relaxed);
    if let Some(route) = SourceRoute::unpack(word)
    {
        release_identity(crate::irq::Target {
            cpu: route.cpu,
            slot: route.eid,
        });
    }
}

/// Take an identity for a new message-signaled target: the next CPU in turn
/// with a free one, and its lowest free identity (module doc § Identities),
/// whose row entry is left `irq::Slot::Unbound`. The identity is enabled in its
/// file from the hart's init, so the target is deliverable once a device writes
/// the message [`message_address`] gives.
///
/// # Errors
/// `Exhausted` when no CPU has a free identity.
///
/// Called under `irq`'s routing lock.
pub fn alloc_message() -> Result<crate::irq::Target, crate::irq::RouteError>
{
    let target = take_identity(Slot::Unbound).ok_or(crate::irq::RouteError::Exhausted)?;
    // The row entry is visible before this hart's later device writes, as a
    // route's is before its APLIC programming.
    mmio::dma_to_mmio_barrier();
    Ok(target)
}

/// Free the identity of the message-signaled target on `target`, whose row
/// entry no binding holds (module doc § Identities on a write still pending).
///
/// Called under `irq`'s routing lock.
pub fn free_message(target: crate::irq::Target)
{
    release_identity(target);
}

/// The physical address a device writes `target`'s identity to: the
/// `seteipnum_le` register at the start of its hart's supervisor-level IMSIC file
/// (`ImsicLayout::s_file_address`). `None` when the CPU index is past the boot
/// CPUs or the layout places no file for its hart.
#[must_use]
pub fn message_address(target: crate::irq::Target) -> Option<u64>
{
    let cpu = target.cpu as usize;
    if cpu >= crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize
    {
        return None;
    }
    // SAFETY: `cpu` is below CPU_COUNT; the hart id slab is read-only after boot.
    let hart = unsafe { crate::percpu::apic_id_for(cpu) };
    crate::platform::kernel_mmio()
        .imsic
        .s_file_address(u64::from(hart))
}

/// Disable `source` at the APLIC (`clrienum`); a source the domain does not
/// implement is ignored. The write is ordered after this hart's earlier memory
/// writes, so a delivery's marking of its bindings owing precedes its mask at
/// the APLIC (`irq::unmask_settled`), and before its later memory writes, so
/// the mask precedes the delivery's signals and its exit from its CPU's
/// delivery gate: an acknowledgement made after a receiver saw a signal, or
/// after `irq::register` waited out the delivery, cannot have its `setienum`
/// reach the APLIC ahead of this `clrienum`.
pub fn mask(source: u32)
{
    if implemented(source)
    {
        // SAFETY: an implemented source; the register lies in the checked window.
        // The fence has no operands and changes no register or memory; it is
        // left without `nomem` so the compiler keeps later stores after it.
        unsafe {
            aplic_write(APLIC_CLRIENUM, source);
            // `fence o,w`: the APLIC write above is performed before this
            // hart's later memory writes.
            core::arch::asm!("fence o,w", options(nostack, preserves_flags));
        }
    }
}

/// Enable routed `source` at the APLIC (`setienum`), then, for a
/// level-sensitive source, pend it again if it is still asserted (module doc
/// § Level-sensitive sources). An unrouted source is left disabled. The writes
/// are ordered before this hart's later memory reads, so the caller's read of
/// the line's owing mask after the unmask (`irq::unmask_settled`) follows the
/// enable at the APLIC.
///
/// Called under `irq`'s routing lock.
pub fn unmask(source: u32)
{
    let Some(route) =
        route_word(source).and_then(|word| SourceRoute::unpack(word.load(Ordering::Relaxed)))
    else
    {
        return;
    };
    // SAFETY: an implemented source; the registers lie in the checked window.
    // The fence has no operands and changes no register or memory; it is
    // left without `nomem` so the compiler keeps later loads after it.
    unsafe {
        aplic_write(APLIC_SETIENUM, source);
        if route.level
        {
            aplic_write(APLIC_SETIPNUM_LE, source);
        }
        // `fence o,r`: the APLIC writes above are performed before this hart's
        // later memory reads.
        core::arch::asm!("fence o,r", options(nostack, preserves_flags));
    }
}

/// Claim the executing hart's highest-priority pending identity (`stopei`) and
/// return its entry in the hart's row, which `irq::dispatch_device_irq` reads
/// inside the hart's delivery gate; `None` when nothing was pending. A free
/// entry is returned too (module doc § Identities).
///
/// Called from the supervisor external-interrupt trap.
pub fn claim() -> Option<&'static SlotEntry>
{
    let eid = imsic_claim();
    slot_entry(crate::irq::Target {
        cpu: super::cpu::current_cpu(),
        slot: eid,
    })
}

// ── Register access ───────────────────────────────────────────────────────────

/// Read the APLIC register at `offset`.
fn aplic_read(offset: u64) -> u32
{
    let vaddr = phys_to_virt(APLIC_BASE.load(Ordering::Relaxed).wrapping_add(offset));
    // SAFETY: the APLIC window lies in the direct map and `offset` is a
    // register inside it (every caller passes a constant register offset);
    // a volatile read is not elided or reordered by the compiler.
    unsafe { core::ptr::read_volatile(vaddr as *const u32) }
}

/// Write `val` to the APLIC register at `offset`, ordered after this hart's
/// earlier memory writes (a route's EID-row entry is visible before the source
/// can be forwarded, and a delivery's owing marking before its mask) and before
/// its later MMIO stores.
///
/// # Safety
/// The direct map must be active, [`init_bsp`] must have recorded the window,
/// and `offset` must name a register inside it.
unsafe fn aplic_write(offset: u64, val: u32)
{
    let vaddr = phys_to_virt(APLIC_BASE.load(Ordering::Relaxed).wrapping_add(offset));
    mmio::dma_to_mmio_barrier();
    // SAFETY: caller contract; a volatile write is not elided or reordered by
    // the compiler.
    unsafe { core::ptr::write_volatile(vaddr as *mut u32, val) };
    mmio::mmio_to_mmio_barrier();
}

/// Write `value` to the executing hart's IMSIC indirect register `select`.
///
/// # Safety
/// Supervisor mode on a hart with Ssaia, with interrupts disabled so no trap
/// changes `siselect` between the two writes; `select` names a register the
/// file implements.
unsafe fn imsic_write(select: u64, value: u64)
{
    // SAFETY: caller contract. `csrw siselect` (CSR 0x150) selects the
    // register and `csrw sireg` (CSR 0x151) writes it; both are per-hart
    // S-mode CSRs, touch no memory, and clobber nothing but the CSRs.
    unsafe {
        core::arch::asm!(
            "csrw 0x150, {select}",
            "csrw 0x151, {value}",
            select = in(reg) select,
            value = in(reg) value,
            options(nostack, nomem, preserves_flags),
        );
    }
}

/// Claim the executing hart's top pending identity through `stopei` and
/// return it, 0 when none is pending.
fn imsic_claim() -> u32
{
    let top: u64;
    // SAFETY: `csrrw rd, stopei, zero` (CSR 0x15C) reads the top pending
    // identity of this hart's supervisor file and clears its pending bit; a
    // per-hart S-mode CSR that touches no memory and clobbers only `rd`. The
    // kernel runs in S-mode on harts init_bsp checked for Ssaia.
    unsafe {
        core::arch::asm!(
            "csrrw {0}, 0x15C, zero",
            out(reg) top,
            options(nostack, nomem, preserves_flags),
        );
    }
    // stopei bits 26:16 hold the identity (11 bits).
    #[allow(clippy::cast_possible_truncation)]
    let eid = ((top >> 16) & 0x7FF) as u32;
    eid
}
