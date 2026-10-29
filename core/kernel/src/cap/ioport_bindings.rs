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
//! The table lives in one SEED scratch allocation per bound thread
//! ([`TABLE_BYTES`]), its bitmap at offset 0 so the TCB's `iopb` pointer is
//! the bitmap the context switch loads. On RISC-V the bitmap is empty
//! (`IOPB_SIZE == 0`) and no thread ever binds.

use crate::arch::current::IOPB_SIZE;

/// Most bindings one thread records. A bind past it returns `QuotaExceeded`;
/// binding the same `IoPort` object again reuses its record.
pub const MAX_IOPORT_BINDINGS: usize = 16;

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

/// The port-binding table of one thread.
#[repr(C)]
pub struct IoPortBindings
{
    /// I/O permission bitmap: bit N is port N, 0 permits, 1 denies. Always the
    /// union of the recorded bindings.
    pub bitmap: [u8; IOPB_SIZE],
    records: [IoPortBinding; MAX_IOPORT_BINDINGS],
    count: usize,
}

/// Bytes of the SEED scratch allocation backing one table.
pub const TABLE_BYTES: u64 = core::mem::size_of::<IoPortBindings>() as u64;

/// A bind the table cannot record.
#[derive(Debug, PartialEq, Eq)]
pub struct TableFull;

impl IoPortBindings
{
    /// Initialise a table in place: every port denied, no bindings.
    ///
    /// # Safety
    /// `table` points at [`TABLE_BYTES`] writable bytes, suitably aligned, that
    /// nothing else references.
    pub unsafe fn init_in_place(table: *mut Self)
    {
        // SAFETY: caller contract; the fields are plain data.
        unsafe {
            core::ptr::addr_of_mut!((*table).bitmap).write_bytes(0xFF, 1);
            core::ptr::addr_of_mut!((*table).count).write(0);
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
        crate::arch::current::gdt::permit_port_range(&mut self.bitmap, base, count);
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
        self.bitmap.fill(0xFF);
        for r in &self.records[..kept]
        {
            crate::arch::current::gdt::permit_port_range(&mut self.bitmap, r.base, r.count);
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
            // IoPortBindings block (sys_ioport_bind).
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

    fn table() -> Box<IoPortBindings>
    {
        let layout = std::alloc::Layout::new::<IoPortBindings>();
        // SAFETY: a fresh allocation of the table's layout, initialised in
        // place before use.
        unsafe {
            let p = std::alloc::alloc(layout).cast::<IoPortBindings>();
            assert!(!p.is_null());
            IoPortBindings::init_in_place(p);
            Box::from_raw(p)
        }
    }

    fn permitted(t: &IoPortBindings, port: u32) -> bool
    {
        t.bitmap[(port / 8) as usize] & (1 << (port % 8)) == 0
    }

    #[test]
    fn withdrawing_one_binding_keeps_ports_another_binding_grants()
    {
        let mut t = table();
        t.bind(0xA000, 0x60, 8).unwrap();
        t.bind(0xB000, 0x64, 8).unwrap();
        assert!(t.withdraw(0xA000));
        assert!(
            !permitted(&t, 0x60),
            "a port only the withdrawn binding granted is denied"
        );
        assert!(
            permitted(&t, 0x64),
            "an overlapping port the other binding grants survives"
        );
        assert!(permitted(&t, 0x6B));
        assert!(!t.withdraw(0xA000), "a second withdrawal finds nothing");
    }

    #[test]
    fn a_full_table_refuses_a_new_object_but_not_a_rebind()
    {
        let mut t = table();
        for i in 0..MAX_IOPORT_BINDINGS
        {
            t.bind(0x1000 + i, 0x100 + i as u32, 1).unwrap();
        }
        assert_eq!(t.bind(0x9000, 0x200, 1), Err(TableFull));
        assert_eq!(t.bind(0x1000, 0x100, 1), Ok(()));
    }
}
