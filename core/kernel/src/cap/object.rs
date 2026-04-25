// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/cap/object.rs

//! Kernel object types backing capability objects.
//!
//! Each struct has a [`KernelObjectHeader`] as its first field at offset 0
//! (`#[repr(C)]`), so a `*mut ConcreteObject` can safely be cast to
//! `*mut KernelObjectHeader` and back.
//!
//! ## Allocation pattern
//!
//! ```text
//! Box::new(FrameObject { ... })
//!   → Box::into_raw()            // *mut FrameObject
//!   → cast to *mut KernelObjectHeader  // safe: header at offset 0
//!   → NonNull::new_unchecked()
//! ```
//!
//! Deallocation: read `header.obj_type` from the raw pointer,
//! then reconstruct the original `Box<ConcreteObject>` and drop it.
//!
//! ## Sizes (verified by tests below)
//!
//! | Type                | Size |
//! |---------------------|------|
//! | KernelObjectHeader  |  8 B |
//! | FrameObject         | 24 B |
//! | MmioRegionObject    | 32 B |
//! | InterruptObject     | 16 B |
//! | IoPortRangeObject   | 12 B |
//! | SchedControlObject  |  8 B |
//! | ThreadObject        | 16 B |
//! | AddressSpaceObject  | 16 B |
//! | CSpaceKernelObject  | 16 B |
//! | EndpointObject      | 16 B |
//! | SignalObject        | 16 B |
//! | EventQueueObject    | 16 B |
//! | WaitSetObject       | 16 B |

use core::sync::atomic::{AtomicU32, Ordering};

// ── ObjectType ────────────────────────────────────────────────────────────────

/// Discriminant for the concrete type behind a `*mut KernelObjectHeader`.
///
/// Used during deallocation to reconstruct the original `Box<ConcreteObject>`.
/// Values must not be renumbered after assignment.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectType
{
    Frame = 0,
    MmioRegion = 1,
    Interrupt = 2,
    IoPortRange = 3,
    SchedControl = 4,
    Thread = 5,
    AddressSpace = 6,
    CSpaceObj = 7,
    Endpoint = 8,
    Signal = 9,
    EventQueue = 10,
    WaitSet = 11,
    SbiControl = 12,
}

// ── KernelObjectHeader ────────────────────────────────────────────────────────

/// Common header at offset 0 of every kernel object.
///
/// The `ref_count` tracks how many capability slots reference this object.
/// When `dec_ref` returns 0, the object has no remaining references and can
/// be freed (future phases will handle deallocation via `obj_type`).
///
/// `#[repr(C)]` with size 8 B, alignment 4. All concrete object structs place
/// this as their first field so pointer casts are safe.
#[repr(C)]
pub struct KernelObjectHeader
{
    /// Reference count; starts at 1 when created.
    pub ref_count: AtomicU32,
    /// Concrete type, for use during deallocation.
    pub obj_type: ObjectType,
    // Padding to reach 8 bytes; field is intentionally public for repr(C)
    // interop but unused by name — allow the underscore prefix convention.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad: [u8; 3],
}

impl KernelObjectHeader
{
    /// Construct a new header with `ref_count = 1`.
    pub fn new(obj_type: ObjectType) -> Self
    {
        Self {
            ref_count: AtomicU32::new(1),
            obj_type,
            _pad: [0; 3],
        }
    }

    /// Increment the reference count. Call when a new capability slot is
    /// derived pointing to this object.
    pub fn inc_ref(&self)
    {
        self.ref_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the reference count and return the new value.
    ///
    /// Returns 0 when the object has no remaining capability references; the
    /// caller is responsible for freeing the object at that point.
    pub fn dec_ref(&self) -> u32
    {
        self.ref_count.fetch_sub(1, Ordering::Release) - 1
    }
}

// ── Concrete object types ─────────────────────────────────────────────────────

/// Kernel object for a contiguous physical memory range (Frame capability).
#[repr(C)]
pub struct FrameObject
{
    pub header: KernelObjectHeader,
    /// Physical base address of the region.
    pub base: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// `true` if this Frame is responsible for returning `[base, base + size)`
    /// to the buddy allocator on final destruction. Buddy-backed frames set
    /// this at creation (Phase 7 `drain_for_usercaps`, `frame_split` children).
    /// Caps over non-buddy-managed physical memory (MMIO regions, firmware
    /// tables, boot modules, boot-loaded ELF segments) leave it `false`.
    ///
    /// `frame_split` atomically transfers ownership by clearing this flag on
    /// the original and setting it on both children before the original is
    /// dec-ref'd — so only the children's destruction ever reaches the buddy.
    pub owns_memory: core::sync::atomic::AtomicBool,
}

/// Kernel object for a memory-mapped I/O region (`MmioRegion` capability).
#[repr(C)]
pub struct MmioRegionObject
{
    pub header: KernelObjectHeader,
    /// Physical base address of the MMIO region.
    pub base: u64,
    /// Size of the MMIO region in bytes.
    pub size: u64,
    /// Flags from the platform resource entry (bit 0: write-combine).
    pub flags: u32,
    // Explicit padding to preserve repr(C) layout.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad: u32,
}

/// Kernel object for a hardware interrupt range (Interrupt capability).
///
/// A cap with `count == 1` is a single-IRQ cap usable with
/// `sys_irq_register` / `sys_irq_ack`. Wider caps are delegatable
/// range authorities: narrow them with `sys_irq_split` before use.
#[repr(C)]
pub struct InterruptObject
{
    pub header: KernelObjectHeader,
    /// First IRQ line in the range (GSI on x86-64, PLIC source on RISC-V).
    pub start: u32,
    /// Number of consecutive IRQ lines covered by the cap.
    pub count: u32,
}

/// Kernel object for an x86-64 I/O port range (`IoPortRange` capability).
#[repr(C)]
pub struct IoPortRangeObject
{
    pub header: KernelObjectHeader,
    /// First port number in the range.
    pub base: u16,
    /// Number of consecutive ports.
    pub size: u16,
    // Explicit padding to preserve repr(C) layout.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad: u32,
}

/// Kernel object for scheduling control authority (`SchedControl` capability).
///
/// There is exactly one `SchedControl` object, created at boot.
#[repr(C)]
pub struct SchedControlObject
{
    pub header: KernelObjectHeader,
}

/// Kernel object for SBI forwarding authority (`SbiControl` capability).
///
/// RISC-V only. There is exactly one `SbiControl` object, created at boot.
/// Grants the holder authority to forward SBI calls through the kernel to
/// M-mode firmware.
#[repr(C)]
pub struct SbiControlObject
{
    pub header: KernelObjectHeader,
}

/// Kernel object for a thread control block (Thread capability).
#[repr(C)]
pub struct ThreadObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the TCB (heap-allocated).
    pub tcb: *mut crate::sched::thread::ThreadControlBlock,
}

// SAFETY: ThreadObject is accessed only under the scheduler lock.
unsafe impl Send for ThreadObject {}
// SAFETY: ThreadObject is accessed only under the scheduler lock.
unsafe impl Sync for ThreadObject {}

/// Kernel object for a user-mode address space (`AddressSpace` capability).
#[repr(C)]
pub struct AddressSpaceObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the `AddressSpace` (heap-allocated).
    pub address_space: *mut crate::mm::address_space::AddressSpace,
}

// SAFETY: AddressSpaceObject is accessed only with proper locks.
unsafe impl Send for AddressSpaceObject {}
// SAFETY: AddressSpaceObject is accessed only with proper locks.
unsafe impl Sync for AddressSpaceObject {}

/// Kernel object for a capability space (`CSpace` capability).
#[repr(C)]
pub struct CSpaceKernelObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the `CSpace` (heap-allocated).
    pub cspace: *mut crate::cap::cspace::CSpace,
}

// SAFETY: CSpaceKernelObject is accessed only with proper locks.
unsafe impl Send for CSpaceKernelObject {}
// SAFETY: CSpaceKernelObject is accessed only with proper locks.
unsafe impl Sync for CSpaceKernelObject {}

/// Kernel object for an IPC endpoint (Endpoint capability).
#[repr(C)]
pub struct EndpointObject
{
    pub header: KernelObjectHeader,
    /// Mutable endpoint state (heap-allocated).
    pub state: *mut crate::ipc::endpoint::EndpointState,
}

// SAFETY: EndpointObject is accessed only under the scheduler lock.
unsafe impl Send for EndpointObject {}
// SAFETY: EndpointObject is accessed only under the scheduler lock.
unsafe impl Sync for EndpointObject {}

/// Kernel object for a signal (Signal capability).
#[repr(C)]
pub struct SignalObject
{
    pub header: KernelObjectHeader,
    /// Mutable signal state (heap-allocated).
    pub state: *mut crate::ipc::signal::SignalState,
}

// SAFETY: SignalObject is accessed only under the scheduler lock.
unsafe impl Send for SignalObject {}
// SAFETY: SignalObject is accessed only under the scheduler lock.
unsafe impl Sync for SignalObject {}

/// Kernel object for an event queue (`EventQueue` capability).
///
/// The ring buffer body is a separate heap allocation stored in `EventQueueState`.
#[repr(C)]
pub struct EventQueueObject
{
    pub header: KernelObjectHeader,
    /// Mutable event queue state (heap-allocated).
    pub state: *mut crate::ipc::event_queue::EventQueueState,
}

// SAFETY: EventQueueObject is accessed only under the scheduler lock.
unsafe impl Send for EventQueueObject {}
// SAFETY: EventQueueObject is accessed only under the scheduler lock.
unsafe impl Sync for EventQueueObject {}

/// Kernel object for a wait set (`WaitSet` capability).
///
/// `WaitSetState` is a ~500-byte heap allocation; this object wrapper is 16 B.
#[repr(C)]
pub struct WaitSetObject
{
    pub header: KernelObjectHeader,
    /// Mutable wait set state (heap-allocated).
    pub state: *mut crate::ipc::wait_set::WaitSetState,
}

// SAFETY: WaitSetObject is accessed only under the scheduler lock.
unsafe impl Send for WaitSetObject {}
// SAFETY: WaitSetObject is accessed only under the scheduler lock.
unsafe impl Sync for WaitSetObject {}

// ── Object deallocation ───────────────────────────────────────────────────────

/// Free a kernel object whose reference count has just reached zero.
///
/// Dispatches on `obj_type` to reconstruct the original `Box<ConcreteObject>`
/// and drop it, freeing any sub-resources first.
///
/// # Safety
///
/// - `ptr` must be a valid, non-null pointer originally produced by
///   `Box::into_raw` (cast to `*mut KernelObjectHeader`).
/// - The object's reference count must be 0; no other capability slot may
///   reference it.
/// - Must NOT be called with `DERIVATION_LOCK` held, since freeing complex
///   objects (Thread, `AddressSpace`) may acquire the frame-allocator lock.
///
/// # Modification guide
///
/// Add a new arm when a new `ObjectType` variant is added. Each arm must:
/// 1. Cast `ptr` to the concrete object type.
/// 2. Free any sub-resources (nested allocations, physical frames).
/// 3. `Box::from_raw(ptr as *mut ConcreteType)` to drop the box.
///
/// For objects with blocked threads (Endpoint, Signal), drain wait queues and
/// re-enqueue threads so they are not permanently lost.
// cast_ptr_alignment: every concrete object type is allocated as Box<ConcreteType>,
// which guarantees alignment to align_of::<ConcreteType>(). The NonNull<KernelObjectHeader>
// points to the first field (header at offset 0), so the pointer retains the concrete
// type's alignment even when stored as KernelObjectHeader*.
// too_many_lines: structural dispatch over all object types; splitting further
// would obscure the type hierarchy without reducing complexity.
#[allow(clippy::cast_ptr_alignment, clippy::too_many_lines)]
#[cfg(not(test))]
pub unsafe fn dealloc_object(ptr: core::ptr::NonNull<KernelObjectHeader>)
{
    use alloc::boxed::Box;

    // SAFETY: ptr is NonNull<KernelObjectHeader>, validated at call site.
    let header = unsafe { ptr.as_ref() };
    match header.obj_type
    {
        // ── Simple objects (no sub-resources) ─────────────────────────────
        ObjectType::Frame =>
        {
            // Return buddy-backed physical memory before freeing the Rust
            // object. `owns_memory` is false for MMIO / firmware / boot
            // module / init-segment caps (the physical memory is not part
            // of the buddy pool at all) and for split originals (ownership
            // was atomically transferred to the children).
            // SAFETY: ptr points to a live FrameObject; single-owner access
            // since refcount reached zero at the call site.
            let (base, size, owned) = unsafe {
                let obj = &*ptr.as_ptr().cast::<FrameObject>();
                (
                    obj.base,
                    obj.size,
                    obj.owns_memory.load(core::sync::atomic::Ordering::Acquire),
                )
            };
            if owned
            {
                // SAFETY: buddy free-range frees the pages we originally
                // allocated from the buddy. Pages are not mapped anywhere
                // once we are here: CSpace teardown on the owning process
                // has already cleared every mapping that referenced them.
                unsafe {
                    crate::mm::with_frame_allocator(|alloc| alloc.free_range(base, size));
                }
            }
            // SAFETY: ptr originally from Box<FrameObject>::into_raw; header at offset 0.
            unsafe { drop(Box::from_raw(ptr.as_ptr().cast::<FrameObject>())) };
        }
        ObjectType::MmioRegion =>
        {
            // SAFETY: ptr originally from Box<MmioRegionObject>::into_raw; header at offset 0.
            unsafe { drop(Box::from_raw(ptr.as_ptr().cast::<MmioRegionObject>())) };
        }
        ObjectType::Interrupt =>
        {
            // SAFETY: ptr originally from Box<InterruptObject>::into_raw; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<InterruptObject>()) };
            let start = obj.start;
            let count = obj.count;

            // Only single-IRQ caps ever register a signal with the routing
            // table and program the controller (sys_irq_register asserts
            // `count == 1`). Range caps are delegation authorities; they
            // have no routing-table footprint to clean up.
            if count == 1
            {
                // SAFETY: single-CPU; disable interrupts to serialise with
                //         dispatch_device_irq (interrupt context).
                unsafe {
                    let saved = crate::arch::current::cpu::save_and_disable_interrupts();
                    crate::irq::unregister(start);
                    crate::arch::current::cpu::restore_interrupts(saved);
                }
                crate::arch::current::interrupts::mask(start);
            }

            // SAFETY: ptr originally from Box<InterruptObject>::into_raw.
            unsafe { drop(Box::from_raw(ptr.as_ptr().cast::<InterruptObject>())) };
        }
        ObjectType::IoPortRange =>
        {
            // SAFETY: ptr originally from Box<IoPortRangeObject>::into_raw; header at offset 0.
            unsafe { drop(Box::from_raw(ptr.as_ptr().cast::<IoPortRangeObject>())) };
        }
        ObjectType::SchedControl =>
        {
            // SAFETY: ptr originally from Box<SchedControlObject>::into_raw; header at offset 0.
            unsafe { drop(Box::from_raw(ptr.as_ptr().cast::<SchedControlObject>())) };
        }
        ObjectType::SbiControl =>
        {
            // SAFETY: ptr originally from Box<SbiControlObject>::into_raw; header at offset 0.
            unsafe { drop(Box::from_raw(ptr.as_ptr().cast::<SbiControlObject>())) };
        }

        // ── Thread ────────────────────────────────────────────────────────
        ObjectType::Thread =>
        {
            // SAFETY: ptr originally from Box<ThreadObject>::into_raw; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<ThreadObject>()) };
            let tcb = obj.tcb;

            if !tcb.is_null()
            {
                // 2^2 = 4 pages; must match KERNEL_STACK_PAGES (sys_cap_create_thread).
                const STACK_ORDER: usize = 2;

                // Remove the TCB from the scheduler's run queue before freeing.
                // Without this, the scheduler could dequeue a freed TCB pointer
                // after this cap_delete completes — a use-after-free that
                // corrupts the slab and/or causes a hang when the scheduler
                // tries to context-switch to garbage state.
                //
                // Must use preferred_cpu (where the thread was last scheduled),
                // NOT select_target_cpu (which load-balances and may return a
                // completely different CPU). The TCB is only in the scheduler
                // of the CPU where it was last enqueued.
                //
                // If the thread is still sched.current on its CPU (actively
                // running or mid-context-switch), we must wait for the context
                // switch to complete before freeing, otherwise the scheduler
                // holds stale pointers into freed memory.
                // SAFETY: tcb validated non-null; sched lock protects queue access.
                // Lock ALL schedulers, set Exited, remove from all queues.
                //
                // preferred_cpu can be stale: between reading it and acquiring
                // the lock, enqueue_and_wake on another CPU may have moved the
                // thread. Locking all schedulers eliminates this race entirely.
                // With only 2 CPUs the overhead is trivial.
                // needless_range_loop: explicit indexing is clearer for scheduler_for(cpu)
                // and saved_flags[cpu] parallel access.
                #[allow(clippy::needless_range_loop)]
                // SAFETY: tcb validated non-null; all scheduler locks are acquired in
                // ascending order to prevent deadlock; lock_raw paired with unlock_raw.
                unsafe {
                    use crate::sched::thread::ThreadState;
                    let prio = (*tcb).priority;
                    let cpu_count = crate::sched::CPU_COUNT
                        .load(core::sync::atomic::Ordering::Relaxed)
                        as usize;

                    // Acquire all scheduler locks in ascending CPU order to
                    // prevent ABBA deadlock.
                    let mut saved_flags: [u64; crate::sched::MAX_CPUS] =
                        [0; crate::sched::MAX_CPUS];
                    for cpu in 0..cpu_count
                    {
                        saved_flags[cpu] = crate::sched::scheduler_for(cpu).lock.lock_raw();
                    }

                    // Mark Exited under all locks — no schedule() on any CPU
                    // can see this thread as Ready/Running after this point.
                    (*tcb).state = ThreadState::Exited;

                    // Remove from whichever queue it's actually in.
                    for cpu in 0..cpu_count
                    {
                        crate::sched::scheduler_for(cpu).remove_from_queue(tcb, prio);
                    }

                    // Check if the thread is actively running (sched.current)
                    // on any CPU.
                    let mut running_on: Option<usize> = None;
                    for cpu in 0..cpu_count
                    {
                        if crate::sched::scheduler_for(cpu).current == tcb
                        {
                            running_on = Some(cpu);
                            break;
                        }
                    }

                    // Release all locks.
                    for cpu in (0..cpu_count).rev()
                    {
                        crate::sched::scheduler_for(cpu)
                            .lock
                            .unlock_raw(saved_flags[cpu]);
                    }

                    // If the thread is mid-context-switch on another CPU, spin
                    // until it finishes.
                    if let Some(run_cpu) = running_on
                    {
                        let sched = crate::sched::scheduler_for(run_cpu);
                        while {
                            let s = sched.lock.lock_raw();
                            let still_current = sched.current == tcb;
                            sched.lock.unlock_raw(s);
                            still_current
                        }
                        {
                            core::hint::spin_loop();
                        }
                    }
                }

                // Unlink this thread from any IPC object it's blocked on.
                // Without this, a signal/endpoint/event_queue retains a
                // dangling waiter pointer to the freed TCB. A subsequent
                // signal_send would return that pointer, and the caller
                // would enqueue_and_wake a freed TCB — use-after-free.
                // SAFETY: tcb is valid (not yet freed); blocked_on_object
                // and ipc_state are always valid on an initialized TCB.
                unsafe {
                    use crate::sched::thread::IpcThreadState;
                    let blocked_obj = (*tcb).blocked_on_object;
                    if !blocked_obj.is_null()
                    {
                        match (*tcb).ipc_state
                        {
                            IpcThreadState::BlockedOnSignal =>
                            {
                                let sig = blocked_obj.cast::<crate::ipc::signal::SignalState>();
                                // SAFETY: sig is valid; lock serialises with signal_send.
                                let saved = (*sig).lock.lock_raw();
                                if (*sig).waiter == tcb
                                {
                                    (*sig).waiter = core::ptr::null_mut();
                                }
                                (*sig).lock.unlock_raw(saved);
                            }
                            IpcThreadState::BlockedOnSend =>
                            {
                                let ep =
                                    &mut *blocked_obj.cast::<crate::ipc::endpoint::EndpointState>();
                                // SAFETY: ep is valid; lock serialises with endpoint ops.
                                let saved = ep.lock.lock_raw();
                                crate::ipc::endpoint::unlink_from_wait_queue(
                                    tcb,
                                    &mut ep.send_head,
                                    &mut ep.send_tail,
                                );
                                ep.lock.unlock_raw(saved);
                            }
                            IpcThreadState::BlockedOnRecv =>
                            {
                                let ep =
                                    &mut *blocked_obj.cast::<crate::ipc::endpoint::EndpointState>();
                                // SAFETY: ep is valid; lock serialises with endpoint ops.
                                let saved = ep.lock.lock_raw();
                                crate::ipc::endpoint::unlink_from_wait_queue(
                                    tcb,
                                    &mut ep.recv_head,
                                    &mut ep.recv_tail,
                                );
                                ep.lock.unlock_raw(saved);
                            }
                            IpcThreadState::BlockedOnEventQueue =>
                            {
                                let eq =
                                    blocked_obj.cast::<crate::ipc::event_queue::EventQueueState>();
                                // SAFETY: eq is valid; lock serialises with event_queue ops.
                                let saved = (*eq).lock.lock_raw();
                                if (*eq).waiter == tcb
                                {
                                    (*eq).waiter = core::ptr::null_mut();
                                }
                                (*eq).lock.unlock_raw(saved);
                            }
                            IpcThreadState::BlockedOnWaitSet =>
                            {
                                let ws = blocked_obj.cast::<crate::ipc::wait_set::WaitSetState>();
                                // WaitSetState has a single waiter field.
                                if (*ws).waiter == tcb
                                {
                                    (*ws).waiter = core::ptr::null_mut();
                                }
                            }
                            _ =>
                            {} // None, BlockedOnReply: no cleanup needed
                        }
                        (*tcb).blocked_on_object = core::ptr::null_mut();
                    }
                }

                // Free the kernel stack back to the buddy allocator.
                // SAFETY: tcb validated non-null; kernel_stack_top set at creation.
                let kstack_top = unsafe { (*tcb).kernel_stack_top };
                let kstack_virt =
                    kstack_top - (crate::sched::KERNEL_STACK_PAGES * crate::mm::PAGE_SIZE) as u64;
                let kstack_phys = crate::mm::paging::virt_to_phys(kstack_virt);
                // SAFETY: kstack_phys from buddy allocator; order matches allocation.
                unsafe {
                    crate::mm::with_frame_allocator(|alloc| {
                        alloc.free(kstack_phys, STACK_ORDER);
                    });
                }

                // Poison the TCB so any use-after-free reads garbage
                // instead of plausible values.
                // SAFETY: tcb is valid; we are about to free it.
                unsafe {
                    (*tcb).magic = 0;
                    (*tcb).priority = 0xFF;
                }

                // Drop the TCB allocation.
                // SAFETY: tcb originally from Box::into_raw at thread creation.
                unsafe { drop(Box::from_raw(tcb)) };
            }

            // SAFETY: ptr originally from Box<ThreadObject>::into_raw.
            unsafe { drop(Box::from_raw(ptr.as_ptr().cast::<ThreadObject>())) };
        }

        // ── AddressSpace ──────────────────────────────────────────────────
        ObjectType::AddressSpace =>
        {
            // SAFETY: ptr originally from Box<AddressSpaceObject>::into_raw; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<AddressSpaceObject>()) };
            let as_ptr = obj.address_space;

            if !as_ptr.is_null()
            {
                // No CPU should still have this address space loaded in
                // satp/CR3 when we free its root page table. The scheduler
                // loads the kernel root on user→idle transitions, so
                // active_cpus reaching zero guarantees all CPUs have
                // switched away.
                debug_assert!(
                    // SAFETY: as_ptr validated non-null; active_cpu_mask is an Acquire load.
                    unsafe { (*as_ptr).active_cpu_mask() } == 0,
                    "dealloc AddressSpace: freeing root while active_cpus != 0"
                );

                // SAFETY: as_ptr validated non-null; root_phys/root_virt
                // allocated at creation; active_cpu_mask == 0 asserted above.
                let (root_phys, root_virt) = unsafe { ((*as_ptr).root_phys, (*as_ptr).root_virt) };

                // Walk the user half of the page table and return every
                // intermediate frame (PDPT/PD/PT on x86-64; L2/L1/L0 on
                // Sv48) to the buddy. Leaf pages are Frame-cap-backed and
                // are freed separately when the owning CSpace is torn down.
                //
                // SAFETY: root_virt is the direct-map VA of the root frame,
                // still mapped until we free it below; caller-arranged
                // CSpace teardown has released every mapping that referenced
                // leaf frames.
                unsafe {
                    crate::mm::with_frame_allocator(|alloc| {
                        crate::arch::current::paging::free_user_page_tables(root_virt, alloc);
                    });
                }

                // Free the root page-table frame itself (order 0).
                // SAFETY: root_phys was allocated order-0 from the buddy at
                // `AddressSpace::new_user` time.
                unsafe {
                    crate::mm::with_frame_allocator(|alloc| alloc.free(root_phys, 0));
                }

                // SAFETY: as_ptr originally from Box::into_raw.
                unsafe { drop(Box::from_raw(as_ptr)) };
            }

            // SAFETY: ptr originally from Box<AddressSpaceObject>::into_raw.
            unsafe { drop(Box::from_raw(ptr.as_ptr().cast::<AddressSpaceObject>())) };
        }

        // ── CSpaceObj ─────────────────────────────────────────────────────
        ObjectType::CSpaceObj =>
        {
            // SAFETY: ptr originally from Box<CSpaceKernelObject>::into_raw; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<CSpaceKernelObject>()) };
            let cs_ptr = obj.cspace;

            if !cs_ptr.is_null()
            {
                // SAFETY: cs_ptr validated non-null; allocated at creation.
                let id = unsafe { (*cs_ptr).id() };
                // Unregister before freeing so no window exists where the
                // registry contains a dangling pointer.
                crate::cap::unregister_cspace(id);

                // Dec-ref all objects referenced by non-null slots.
                // Without this, destroying a CSpace with live caps inside
                // (e.g., cap_copy'd caps in a child CSpace) leaks the
                // underlying kernel objects permanently.
                //
                // TODO: unlink derivation tree pointers in other CSpaces
                // that reference slots in this dying CSpace. Currently
                // those SlotId references become stale, which is harmless
                // unless cap_revoke traverses them.
                // SAFETY: cs_ptr validated non-null; for_each_object handles iteration.
                unsafe {
                    (*cs_ptr).for_each_object(|obj_ptr| {
                        let hdr = obj_ptr.as_ref();
                        let rc = hdr.dec_ref();
                        if rc == 0
                        {
                            dealloc_object(obj_ptr);
                        }
                    });
                }

                // SAFETY: cs_ptr originally from Box::into_raw.
                unsafe { drop(Box::from_raw(cs_ptr)) };
            }

            // SAFETY: ptr originally from Box<CSpaceKernelObject>::into_raw.
            unsafe { drop(Box::from_raw(ptr.as_ptr().cast::<CSpaceKernelObject>())) };
        }

        // ── Endpoint ──────────────────────────────────────────────────────
        ObjectType::Endpoint =>
        {
            // SAFETY: ptr originally from Box<EndpointObject>::into_raw; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<EndpointObject>()) };
            let state = obj.state;

            if !state.is_null()
            {
                // Unregister from wait set before freeing state.
                // SAFETY: state validated non-null; EndpointState allocated at creation.
                unsafe {
                    let ep = &mut *state;
                    if !ep.wait_set.is_null()
                    {
                        // cast_ptr_alignment: ep.wait_set stores a type-erased *mut WaitSetState;
                        // the original Box<WaitSetState> allocation guarantees the alignment.
                        #[allow(clippy::cast_ptr_alignment)]
                        let ws = ep.wait_set.cast::<crate::ipc::wait_set::WaitSetState>();
                        let _ = crate::ipc::wait_set::waitset_remove(ws, state.cast::<u8>());
                        ep.wait_set = core::ptr::null_mut();
                        ep.wait_set_member_idx = 0;
                    }
                }

                // Drain blocked senders and receivers with a zero return value.
                // They will wake up and resume from sys_ipc_call / sys_ipc_recv,
                // reading a zero-length message (effectively an ObjectGone hint).
                // TODO: set TrapFrame return to SyscallError::ObjectGone when
                // a proper per-thread wakeup error path is added.
                // SAFETY: state validated non-null; wake queue traversal under sched lock.
                unsafe {
                    let ep = &mut *state;
                    // Wake senders.
                    let mut tcb = ep.send_head;
                    while !tcb.is_null()
                    {
                        let next = (*tcb).ipc_wait_next;
                        (*tcb).ipc_wait_next = None;
                        (*tcb).ipc_state = crate::sched::thread::IpcThreadState::None;
                        (*tcb).state = crate::sched::thread::ThreadState::Ready;
                        let prio = (*tcb).priority;
                        let target_cpu = crate::sched::select_target_cpu(tcb);
                        crate::sched::enqueue_and_wake(tcb, target_cpu, prio);
                        tcb = next.unwrap_or(core::ptr::null_mut());
                    }
                    ep.send_head = core::ptr::null_mut();
                    ep.send_tail = core::ptr::null_mut();
                    // Wake receivers.
                    let mut tcb = ep.recv_head;
                    while !tcb.is_null()
                    {
                        let next = (*tcb).ipc_wait_next;
                        (*tcb).ipc_wait_next = None;
                        (*tcb).ipc_state = crate::sched::thread::IpcThreadState::None;
                        (*tcb).state = crate::sched::thread::ThreadState::Ready;
                        let prio = (*tcb).priority;
                        let target_cpu = crate::sched::select_target_cpu(tcb);
                        crate::sched::enqueue_and_wake(tcb, target_cpu, prio);
                        tcb = next.unwrap_or(core::ptr::null_mut());
                    }
                    ep.recv_head = core::ptr::null_mut();
                    ep.recv_tail = core::ptr::null_mut();
                }

                // SAFETY: state originally from Box::into_raw at endpoint creation.
                unsafe { drop(Box::from_raw(state)) };
            }

            // SAFETY: ptr originally from Box<EndpointObject>::into_raw.
            unsafe { drop(Box::from_raw(ptr.as_ptr().cast::<EndpointObject>())) };
        }

        // ── Signal ────────────────────────────────────────────────────────
        ObjectType::Signal =>
        {
            // SAFETY: ptr originally from Box<SignalObject>::into_raw; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<SignalObject>()) };
            let state = obj.state;

            if !state.is_null()
            {
                // Clear any IRQ routing table entries that point to this
                // SignalState. Without this, a hardware interrupt firing after
                // the signal is freed would call signal_send on a dead slot,
                // corrupting the slab-32 free list via fetch_or on offset 0.
                // SAFETY: interrupts disabled to serialize with IRQ delivery.
                unsafe {
                    let saved = crate::arch::current::cpu::save_and_disable_interrupts();
                    crate::irq::unregister_signal(state);
                    crate::arch::current::cpu::restore_interrupts(saved);
                }

                // Unregister from wait set BEFORE freeing state. If the signal
                // is registered with a wait set, the wait set's member array
                // still holds a source_ptr to this SignalState. Failing to
                // remove it causes wait_set_drop to write to freed memory.
                // SAFETY: state validated non-null; SignalState allocated at creation.
                unsafe {
                    let sig = &mut *state;
                    if !sig.wait_set.is_null()
                    {
                        // cast_ptr_alignment: sig.wait_set stores a type-erased *mut WaitSetState.
                        #[allow(clippy::cast_ptr_alignment)]
                        let ws = sig.wait_set.cast::<crate::ipc::wait_set::WaitSetState>();
                        let _ = crate::ipc::wait_set::waitset_remove(ws, state.cast::<u8>());
                        sig.wait_set = core::ptr::null_mut();
                        sig.wait_set_member_idx = 0;
                    }
                }

                // Wake a blocked waiter with wakeup_value = 0.
                // TODO: return SyscallError::ObjectGone when a proper wakeup
                // error path is available in sys_signal_wait.
                // SAFETY: state validated non-null; waiter TCB still valid.
                unsafe {
                    let sig = &mut *state;
                    let waiter = sig.waiter;
                    if !waiter.is_null()
                    {
                        sig.waiter = core::ptr::null_mut();
                        (*waiter).wakeup_value = 0;
                        (*waiter).ipc_state = crate::sched::thread::IpcThreadState::None;
                        (*waiter).state = crate::sched::thread::ThreadState::Ready;
                        let prio = (*waiter).priority;
                        let target_cpu = crate::sched::select_target_cpu(waiter);
                        crate::sched::enqueue_and_wake(waiter, target_cpu, prio);
                    }
                }

                // SAFETY: state originally from Box::into_raw at signal creation.
                unsafe { drop(Box::from_raw(state)) };
            }

            // SAFETY: ptr originally from Box<SignalObject>::into_raw.
            unsafe { drop(Box::from_raw(ptr.as_ptr().cast::<SignalObject>())) };
        }

        // ── EventQueue ────────────────────────────────────────────────────
        ObjectType::EventQueue =>
        {
            // SAFETY: ptr originally from Box<EventQueueObject>::into_raw; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<EventQueueObject>()) };
            let state = obj.state;

            if !state.is_null()
            {
                // Unregister from wait set before freeing state.
                // SAFETY: state validated non-null; EventQueueState allocated at creation.
                unsafe {
                    let eq = &mut *state;
                    if !eq.wait_set.is_null()
                    {
                        // cast_ptr_alignment: eq.wait_set stores a type-erased *mut WaitSetState.
                        #[allow(clippy::cast_ptr_alignment)]
                        let ws = eq.wait_set.cast::<crate::ipc::wait_set::WaitSetState>();
                        let _ = crate::ipc::wait_set::waitset_remove(ws, state.cast::<u8>());
                        eq.wait_set = core::ptr::null_mut();
                        eq.wait_set_member_idx = 0;
                    }
                }

                // SAFETY: state was allocated in sys_cap_create_event_queue.
                // Wake any blocked waiter (wakeup_value = 0 signals object gone).
                unsafe { crate::ipc::event_queue::event_queue_drop(state) };
            }

            // SAFETY: ptr originally from Box<EventQueueObject>::into_raw.
            unsafe { drop(Box::from_raw(ptr.as_ptr().cast::<EventQueueObject>())) };
        }

        // ── WaitSet ───────────────────────────────────────────────────────
        ObjectType::WaitSet =>
        {
            // SAFETY: ptr originally from Box<WaitSetObject>::into_raw; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<WaitSetObject>()) };
            let state = obj.state;

            if !state.is_null()
            {
                // SAFETY: state was allocated in sys_cap_create_wait_set.
                // Wakes any blocked waiter and clears all source back-pointers.
                unsafe { crate::ipc::wait_set::wait_set_drop(state) };
            }

            // SAFETY: ptr originally from Box<WaitSetObject>::into_raw.
            unsafe { drop(Box::from_raw(ptr.as_ptr().cast::<WaitSetObject>())) };
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use core::mem::{offset_of, size_of};

    // Verify header is at offset 0 in each concrete type — required for safe
    // pointer casts from *mut ConcreteObject to *mut KernelObjectHeader.
    #[test]
    fn frame_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(FrameObject, header), 0);
    }

    #[test]
    fn mmio_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(MmioRegionObject, header), 0);
    }

    #[test]
    fn interrupt_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(InterruptObject, header), 0);
    }

    #[test]
    fn ioport_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(IoPortRangeObject, header), 0);
    }

    #[test]
    fn sched_control_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(SchedControlObject, header), 0);
    }

    #[test]
    fn struct_sizes()
    {
        assert_eq!(size_of::<KernelObjectHeader>(), 8);
        // FrameObject: 8 header + 8 base + 8 size + 1 owns_memory + 7 tail
        // padding (struct aligned to 8 via u64 fields) = 32 bytes.
        assert_eq!(size_of::<FrameObject>(), 32);
        assert_eq!(size_of::<MmioRegionObject>(), 32);
        assert_eq!(size_of::<InterruptObject>(), 16);
        assert_eq!(size_of::<IoPortRangeObject>(), 16); // 8 header + 4 ports + 4 pad
        assert_eq!(size_of::<SchedControlObject>(), 8);
    }

    #[test]
    fn header_ref_count_lifecycle()
    {
        let h = KernelObjectHeader::new(ObjectType::Frame);
        assert_eq!(h.ref_count.load(core::sync::atomic::Ordering::Relaxed), 1);
        h.inc_ref();
        assert_eq!(h.ref_count.load(core::sync::atomic::Ordering::Relaxed), 2);
        let after_dec = h.dec_ref();
        assert_eq!(after_dec, 1);
        let after_dec2 = h.dec_ref();
        assert_eq!(after_dec2, 0);
    }
}
