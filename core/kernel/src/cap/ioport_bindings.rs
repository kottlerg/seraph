// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/cap/ioport_bindings.rs

//! Per-thread I/O-port binding table: the x86-64 I/O permission bitmap a
//! thread runs with, and the record of every `SYS_IOPORT_BIND` behind it.
//!
//! `SYS_IOPORT_BIND` records each binding against the `IoPort` object it was
//! made through. When that object is freed — its capability deleted, consumed
//! by a split, or revoked through an ancestor — [`withdraw_everywhere`] drops
//! the object's records from every thread and rebuilds each bitmap from the
//! bindings that remain, so a port another live binding still grants stays
//! permitted. The rebuilt bitmap reaches a CPU that is running the thread
//! through the lazy IOPB reload of `arch::current::gdt`
//! (`invalidate_all_iopbs`). See
//! core/kernel/docs/capability-internals.md § `IoPort` Bindings.
//!
//! The table is one page, and the bitmap it heads is held in further pages
//! (`ThreadIopb`, `IOPB_PARTS` page-sized parts), all taken from the pool of
//! the `CSpace` the first bind resolves through ([`TABLE_PAGES`], arena
//! leases of `cap::object::CSpaceKernelObject`). The bitmap sits at offset 0,
//! so the TCB's `iopb` pointer is the bitmap the context switch loads. On
//! RISC-V the bitmap has no part and no thread ever binds.

use crate::arch::current::{IOPB_PART_BYTES, IOPB_PARTS, ThreadIopb};

/// One recorded binding: the `IoPort` object it was made through (its address,
/// compared but never dereferenced) and the ports it grants.
#[derive(Clone, Copy)]
#[repr(C)]
struct IoPortBinding
{
    object: usize,
    base: u32,
    count: u32,
}

/// Most bindings one thread records: as many as the table's page holds after
/// its header (254 on x86-64). A bind past it returns `QuotaExceeded`; binding
/// the same `IoPort` object again reuses its record. Each binding is made
/// through a distinct `IoPort` object, and the page is funded by the binding
/// caller's `CSpace`.
pub const MAX_IOPORT_BINDINGS: usize =
    (crate::mm::PAGE_SIZE - core::mem::size_of::<ThreadIopb>() - 2 * core::mem::size_of::<usize>())
        / core::mem::size_of::<IoPortBinding>();

/// The port-binding table of one thread: one page.
#[repr(C)]
pub struct IoPortBindings
{
    /// I/O permission bitmap: bit N is port N, 0 permits, 1 denies. Always the
    /// union of the recorded bindings.
    pub bitmap: ThreadIopb,
    /// The `CSpaceKernelObject` whose pool funded this page and the bitmap's
    /// parts, as an address.
    funder: usize,
    count: usize,
    records: [IoPortBinding; MAX_IOPORT_BINDINGS],
}

const _: () = assert!(core::mem::size_of::<IoPortBindings>() <= crate::mm::PAGE_SIZE);

/// Pages one table takes from its funder: the table's own and the bitmap's
/// parts.
pub const TABLE_PAGES: usize = 1 + IOPB_PARTS;

/// A bind the table cannot record.
#[derive(Debug, PartialEq, Eq)]
pub struct TableFull;

impl IoPortBindings
{
    /// Initialise a table in place: every port denied, no bindings, the
    /// bitmap held in `parts`, all funded by `funder`.
    ///
    /// # Safety
    /// `table` points at a writable page and each of `parts` at a writable
    /// [`IOPB_PART_BYTES`] block, page-aligned, that nothing else references
    /// and that stay live, owned by the table, until it is freed.
    pub unsafe fn init_in_place(
        table: *mut Self,
        parts: [*mut [u8; IOPB_PART_BYTES]; IOPB_PARTS],
        funder: usize,
    )
    {
        for &part in &parts
        {
            // SAFETY: caller contract.
            unsafe { (*part).fill(0xFF) };
        }
        // SAFETY: caller contract; the fields are plain data.
        unsafe {
            core::ptr::addr_of_mut!((*table).bitmap).write(ThreadIopb { parts });
            core::ptr::addr_of_mut!((*table).funder).write(funder);
            core::ptr::addr_of_mut!((*table).count).write(0);
        }
    }

    /// The address of the `CSpaceKernelObject` that funded the table.
    pub fn funder(&self) -> usize
    {
        self.funder
    }

    /// Permit `count` ports from `base` in every part of the bitmap.
    // cast_possible_truncation: a part's first port is below 65536.
    #[allow(clippy::cast_possible_truncation)]
    fn permit(&mut self, base: u32, count: u32)
    {
        for (i, &part) in self.bitmap.parts.iter().enumerate()
        {
            // SAFETY: each part is a live block the table owns
            // (init_in_place's contract), and `&mut self` excludes every
            // other use of it.
            let part = unsafe { &mut *part };
            let first_port = (i * IOPB_PART_BYTES * 8) as u32;
            crate::arch::current::gdt::permit_port_range(part, first_port, base, count);
        }
    }

    /// Record a binding of `count` ports from `base` through `object` and
    /// permit them. A binding already recorded for `object` is not recorded
    /// twice.
    ///
    /// # Errors
    /// [`TableFull`] when [`MAX_IOPORT_BINDINGS`] bindings are already recorded.
    pub fn bind(&mut self, object: usize, base: u32, count: u32) -> Result<(), TableFull>
    {
        if self.records[..self.count]
            .iter()
            .any(|r| r.object == object)
        {
            return Ok(());
        }
        if self.count == MAX_IOPORT_BINDINGS
        {
            return Err(TableFull);
        }
        self.records[self.count] = IoPortBinding {
            object,
            base,
            count,
        };
        self.count += 1;
        self.permit(base, count);
        Ok(())
    }

    /// Drop every binding made through `object` and rebuild the bitmap from
    /// those that remain. Returns whether any binding was dropped.
    pub fn withdraw(&mut self, object: usize) -> bool
    {
        let before = self.count;
        let mut kept = 0;
        for i in 0..before
        {
            if self.records[i].object != object
            {
                self.records[kept] = self.records[i];
                kept += 1;
            }
        }
        self.count = kept;
        if kept == before
        {
            return false;
        }
        for &part in &self.bitmap.parts
        {
            // SAFETY: as in `permit`.
            unsafe { (*part).fill(0xFF) };
        }
        for i in 0..kept
        {
            let r = self.records[i];
            self.permit(r.base, r.count);
        }
        true
    }
}

/// Withdraw every binding made through the `IoPort` object at address
/// `object` from every live thread, then make every CPU reload its I/O
/// permission bitmap before its next port access.
///
/// Called from the `IoPort` arm of `dealloc_object` before the object's bytes
/// are freed. A bind through the object holds a syscall pin on it, so no bind
/// can record it once this runs.
///
/// # Safety
/// No lock is held (the walk takes the thread registry lock and each thread's
/// `sched_lock`).
#[cfg(not(test))]
pub unsafe fn withdraw_everywhere(object: usize)
{
    if !crate::arch::current::HAS_IO_PORTS
    {
        return;
    }
    let mut changed = false;
    // SAFETY: the closure registers nothing and waits on no other CPU; it
    // takes only each thread's sched_lock, ordered after the registry lock.
    unsafe {
        crate::sched::thread_registry::for_each(|tcb| {
            let saved = (*tcb).sched_lock.lock_raw();
            // `iopb` and the table's bytes are owned by this lock; the Thread
            // arm of dealloc_object nulls the pointer under it before freeing.
            // cast_ptr_alignment: a non-null `iopb` heads a page-aligned
            // IoPortBindings page (sys_ioport_bind).
            #[allow(clippy::cast_ptr_alignment)]
            let table = (*tcb).iopb.cast::<IoPortBindings>();
            if !table.is_null() && (*table).withdraw(object)
            {
                changed = true;
            }
            (*tcb).sched_lock.unlock_raw(saved);
        });
    }
    if changed
    {
        crate::arch::current::gdt::invalidate_all_iopbs();
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A table with its parts, kept alive by the returned backing.
    struct Table
    {
        table: Box<IoPortBindings>,
        _parts: Vec<Box<[u8; IOPB_PART_BYTES]>>,
    }

    fn table() -> Table
    {
        let mut parts_box: Vec<Box<[u8; IOPB_PART_BYTES]>> = (0..IOPB_PARTS)
            .map(|_| Box::new([0u8; IOPB_PART_BYTES]))
            .collect();
        let mut parts = [core::ptr::null_mut(); IOPB_PARTS];
        for (p, b) in parts.iter_mut().zip(parts_box.iter_mut())
        {
            *p = core::ptr::from_mut(&mut **b);
        }
        let layout = std::alloc::Layout::new::<IoPortBindings>();
        // SAFETY: a fresh allocation of the table's layout and fresh parts,
        // initialised in place before use; the parts outlive the table.
        let table = unsafe {
            let p = std::alloc::alloc(layout).cast::<IoPortBindings>();
            assert!(!p.is_null());
            IoPortBindings::init_in_place(p, parts, 0x5000);
            Box::from_raw(p)
        };
        Table {
            table,
            _parts: parts_box,
        }
    }

    fn permitted(t: &IoPortBindings, port: u32) -> bool
    {
        let bits = (IOPB_PART_BYTES * 8) as u32;
        let part = t.bitmap.parts[(port / bits) as usize];
        let rel = port % bits;
        // SAFETY: the part is live for the table's life.
        unsafe { (*part)[(rel / 8) as usize] & (1 << (rel % 8)) == 0 }
    }

    #[test]
    fn withdrawing_one_binding_keeps_ports_another_binding_grants()
    {
        let mut t = table();
        let t = &mut *t.table;
        t.bind(0xA000, 0x60, 8).unwrap();
        t.bind(0xB000, 0x64, 8).unwrap();
        assert!(t.withdraw(0xA000));
        assert!(
            !permitted(t, 0x60),
            "a port only the withdrawn binding granted is denied"
        );
        assert!(
            permitted(t, 0x64),
            "an overlapping port the other binding grants survives"
        );
        assert!(permitted(t, 0x6B));
        assert!(!t.withdraw(0xA000), "a second withdrawal finds nothing");
    }

    // The defect caught: a binding that straddles two parts permits ports in
    // only one of them, or a rebuild that resets only the first part.
    #[test]
    fn a_binding_across_the_parts_is_permitted_and_withdrawn_in_both()
    {
        let mut t = table();
        let t = &mut *t.table;
        let edge = (IOPB_PART_BYTES * 8) as u32;
        t.bind(0xA000, edge - 4, 8).unwrap();
        assert!(permitted(t, edge - 4) && permitted(t, edge + 3));
        assert!(!permitted(t, edge - 5) && !permitted(t, edge + 4));
        t.bind(0xB000, 0xFFF0, 16).unwrap();
        assert!(t.withdraw(0xA000));
        assert!(!permitted(t, edge - 1) && !permitted(t, edge));
        assert!(
            permitted(t, 0xFFFF),
            "the other binding survives the rebuild"
        );
    }

    #[test]
    fn a_full_table_refuses_a_new_object_but_not_a_rebind()
    {
        let mut t = table();
        let t = &mut *t.table;
        for i in 0..MAX_IOPORT_BINDINGS
        {
            t.bind(0x1000 + i, 0x100 + i as u32, 1).unwrap();
        }
        assert_eq!(t.bind(0x9000, 0x200, 1), Err(TableFull));
        assert_eq!(t.bind(0x1000, 0x100, 1), Ok(()));
        assert_eq!(t.funder(), 0x5000);
    }
}
