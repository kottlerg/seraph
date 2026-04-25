// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/mm/address_space.rs

//! User-mode address space management (Phase 9).
//!
//! An [`AddressSpace`] owns one root page table (PML4 on x86-64, Sv48 root
//! on RISC-V). Intermediate page table frames are allocated from the buddy
//! allocator on demand.
//!
//! Init stack constants (`INIT_STACK_TOP`, `INIT_STACK_PAGES`) are defined in
//! the `init-protocol` ABI crate and re-exported here for kernel use.
//!
//! ## Kernel mapping inheritance
//! `new_user` copies kernel PML4 entries [256..512] from the currently active
//! page table root into the new user PML4, so kernel memory is reachable from
//! user address spaces without per-process kernel mapping maintenance.
//!
//! On RISC-V the equivalent root entries are VPN[3] entries 256–511.
//!
//! ## Concurrency
//!
//! Page table modifications (`map_page`, `unmap_page`, `protect_page`) are
//! serialized per address space by `pt_lock`. The lock ordering is:
//!
//!   `pt_lock` → `FRAME_ALLOC_LOCK` → `SHOOTDOWN_LOCK`
//!
//! `pt_lock` does NOT disable interrupts; shootdown needs interrupts enabled.
//! Preemption is disabled via `preempt_disable()` while the lock is held.

// cast_possible_truncation: u64→usize page count arithmetic; bounded by address space size.
#![allow(clippy::cast_possible_truncation)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use boot_protocol::{InitSegment, SegmentFlags};

use crate::mm::paging::phys_to_virt;
use crate::mm::{BuddyAllocator, PAGE_SIZE};

// Init stack constants are defined in the init protocol ABI crate.
pub use init_protocol::{INIT_STACK_PAGES, INIT_STACK_TOP};

// ── AddressSpace ──────────────────────────────────────────────────────────────

/// A user-mode virtual address space.
///
/// Owns the physical frame of the root page table. All intermediate frames
/// allocated during mapping are tracked only implicitly through the page table
/// structure (full tracking + freeing is deferred to a future phase).
pub struct AddressSpace
{
    /// Physical address of the root page table frame (PML4 / Sv48 root).
    pub root_phys: u64,
    /// Virtual address of the root frame (via the direct physical map).
    pub root_virt: u64,
    /// Bitmask of CPUs currently running threads in this address space.
    ///
    /// Bit N set = CPU N has this AS active, TLB may contain cached entries.
    /// Updated on every context switch by the scheduler; queried by TLB
    /// shootdown to determine which CPUs need IPIs.
    active_cpus: AtomicU64,
    /// Lock serializing page table modifications (map/unmap/protect).
    ///
    /// Simple CAS spin lock — does NOT disable interrupts (shootdown needs
    /// IF=1 to deliver IPIs). Preemption is prevented by caller's
    /// `preempt_disable()`.
    pt_lock: AtomicBool,
}

// SAFETY: All mutable state is protected by pt_lock (page tables) or atomic
// operations (active_cpus). Safe to share across threads and CPUs.
unsafe impl Send for AddressSpace {}
// SAFETY: pt_lock serializes page table modifications; active_cpus is atomic.
unsafe impl Sync for AddressSpace {}

impl AddressSpace
{
    /// Acquire the page table modification lock.
    ///
    /// On the contended path, enables interrupts while spinning so that
    /// incoming TLB shootdown IPIs from the lock holder can be serviced.
    /// Caller must have called `preempt_disable()` first.
    #[cfg(not(test))]
    #[inline]
    fn pt_lock(&self)
    {
        // Fast path: uncontended.
        if self
            .pt_lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }

        // Contended path: enable interrupts while spinning so the lock
        // holder's shootdown IPI can be delivered to this CPU. Without
        // this, the holder spins forever on pending_cpus waiting for us
        // to ack, while we spin forever on pt_lock waiting for the holder.
        // Preemption is disabled by the caller, so timer_tick() will not
        // call schedule().
        //
        // SAFETY: save_and_disable_interrupts is valid at ring 0 / S-mode.
        let saved = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
        // SAFETY: IDT / trap vector is installed; enabling interrupts is safe
        // at ring 0 / S-mode. Preemption is disabled by the caller.
        unsafe { crate::arch::current::interrupts::enable() };

        loop
        {
            while self.pt_lock.load(Ordering::Relaxed)
            {
                core::hint::spin_loop();
            }
            if self
                .pt_lock
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }

        // SAFETY: restoring previously saved interrupt state.
        unsafe { crate::arch::current::cpu::restore_interrupts(saved) };
    }

    /// Release the page table modification lock.
    #[cfg(not(test))]
    #[inline]
    fn pt_unlock(&self)
    {
        self.pt_lock.store(false, Ordering::Release);
    }

    /// Allocate a new, empty user address space.
    ///
    /// 1. Allocates one frame from `allocator` for the root page table.
    /// 2. Zeros the frame.
    /// 3. Copies kernel-half entries (indices 256–511) from the current
    ///    hardware page table root so the kernel is reachable from this space.
    ///
    /// # Panics
    /// Calls `crate::fatal` if the buddy allocator is exhausted.
    ///
    /// # Safety
    /// Must be called after Phase 3 (page tables active) and Phase 4 (heap active).
    /// The current CPU's page table root must be the kernel's PML4/Sv48 root.
    #[cfg(not(test))]
    pub unsafe fn new_user(allocator: &mut BuddyAllocator) -> Self
    {
        // Allocate one 4 KiB frame (order 0) for the root page table.
        let root_phys = allocator
            .alloc(0)
            .unwrap_or_else(|| crate::fatal("address_space::new_user: out of memory for root PT"));

        let root_virt = phys_to_virt(root_phys);

        // Zero the frame (page table entries are 0 = not-present by default).
        // SAFETY: root_virt is a valid, exclusively-owned kernel virtual address
        // mapped RW in the direct physical map; write_bytes stays within PAGE_SIZE bounds.
        unsafe {
            core::ptr::write_bytes(root_virt as *mut u8, 0, PAGE_SIZE);
        }

        // Copy kernel-half PML4/Sv48 entries (indices 256–511) from the current
        // active page table root so the kernel stays accessible from user mode.
        //
        // On x86-64: read CR3 for the current PML4 physical address.
        // On RISC-V: read satp for the current Sv48 root physical address.
        // SAFETY: root_virt is valid and page-aligned; copy_kernel_entries
        // reads the current root and copies 256 u64 entries within bounds.
        unsafe {
            Self::copy_kernel_entries(root_virt);
        }

        Self {
            root_phys,
            root_virt,
            active_cpus: AtomicU64::new(0),
            pt_lock: AtomicBool::new(false),
        }
    }

    /// Copy entries 256–511 from the currently active page table root into
    /// the new user page table at `new_root_virt`.
    ///
    /// # Safety
    /// Both the current root and `new_root_virt` must be valid, 4 KiB-aligned
    /// kernel virtual addresses mapped R/W in the direct physical map.
    #[cfg(not(test))]
    unsafe fn copy_kernel_entries(new_root_virt: u64)
    {
        use crate::arch::current::paging::read_root_phys;

        // SAFETY: read_root_phys reads CR3/satp; caller contract ensures paging is active.
        let current_root_phys = unsafe { read_root_phys() };
        let current_root_virt = phys_to_virt(current_root_phys);

        // Each entry is 8 bytes; entries 256–511 start at byte offset 2048.
        let src = (current_root_virt + 2048) as *const u64;
        let dst = (new_root_virt + 2048) as *mut u64;

        // SAFETY: both src and dst are valid kernel virtual addresses within
        // 4 KiB page table frames; the 256 u64 copy (2048 bytes) stays within bounds.
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst, 256);
        }
    }

    /// Map `virt` → `phys` as a 4 KiB page with the given permission flags.
    ///
    /// Acquires `pt_lock`, allocates missing intermediate page table frames
    /// from the global frame allocator, and sends TLB shootdown IPIs if this
    /// address space is active on other CPUs.
    ///
    /// # Safety
    /// `virt` must be in the user half (< `0x8000_0000_0000`). `phys` must be
    /// a valid 4 KiB-aligned physical address.
    #[cfg(not(test))]
    pub unsafe fn map_page(
        &self,
        virt: u64,
        phys: u64,
        flags: crate::mm::paging::PageFlags,
    ) -> Result<(), ()>
    {
        use crate::arch::current::paging::{flush_page, map_user_page};

        crate::percpu::preempt_disable();
        self.pt_lock();

        // Allocate intermediate page table frames as needed via the global
        // frame allocator. FRAME_ALLOC_LOCK is acquired and released inside
        // with_frame_allocator — not held across the shootdown.
        // SAFETY: contract passed to caller.
        let result = crate::mm::with_frame_allocator(|alloc| {
            // SAFETY: contract passed to caller; root_virt is valid; virt is
            // in user range; phys is a valid 4 KiB-aligned physical address.
            unsafe { map_user_page(self.root_virt, virt, phys, flags, alloc) }
        });

        if result.is_err()
        {
            self.pt_unlock();
            crate::percpu::preempt_enable();
            return Err(());
        }

        // If this address space is active on other CPUs, they need TLB invalidation
        // for the new mapping (some architectures cache negative lookups).
        // The current CPU is excluded from the remote mask; it invalidates locally below.
        let active = self.active_cpu_mask();
        let current = crate::arch::current::cpu::current_cpu();
        let remote_cpus = active & !(1u64 << current);

        if remote_cpus != 0
        {
            // SAFETY: root_phys is a valid page table root; remote_cpus mask
            // contains only bits for online CPUs (enforced by scheduler).
            // preempt_disable() already called above.
            unsafe {
                crate::mm::tlb_shootdown::shootdown(self.root_phys, remote_cpus, virt);
            }
        }

        // Local TLB invalidation for the mapped page. The current CPU does not
        // send an IPI to itself; it performs the invalidation directly.
        // SAFETY: virt is a valid user virtual address.
        unsafe {
            flush_page(virt);
        }

        self.pt_unlock();
        crate::percpu::preempt_enable();

        Ok(())
    }

    /// Map each page of an ELF LOAD `segment` into this address space.
    ///
    /// Permissions are derived from `segment.flags`:
    /// - `Read`        → R-- (readable, not writable, not executable)
    /// - `ReadWrite`   → RW- (readable, writable; W^X: not executable)
    /// - `ReadExecute` → R-X (readable, executable; W^X: not writable)
    ///
    /// Physical addresses come from `segment.phys_addr`, mapped sequentially
    /// in 4 KiB increments across `segment.size` bytes (rounded up to pages).
    ///
    /// # Safety
    /// `segment` must be a valid, bootloader-provided `InitSegment`.
    #[cfg(not(test))]
    pub unsafe fn map_segment(&self, segment: &InitSegment) -> Result<(), ()>
    {
        let flags = match segment.flags
        {
            SegmentFlags::Read => crate::mm::paging::PageFlags {
                readable: true,
                writable: false,
                executable: false,
                uncacheable: false,
            },
            SegmentFlags::ReadWrite => crate::mm::paging::PageFlags {
                readable: true,
                writable: true,
                executable: false,
                uncacheable: false,
            },
            SegmentFlags::ReadExecute => crate::mm::paging::PageFlags {
                readable: true,
                writable: false,
                executable: true,
                uncacheable: false,
            },
        };

        // Align virt and phys down to 4 KiB page boundaries for page table
        // mapping. The in-page offset is preserved implicitly: the CPU adds
        // (virt_addr & 0xFFF) to the physical frame address at access time.
        //
        // Example: virt_addr=0x201120 (off=0x120), phys_addr=0x1e1a6120
        //   → map virtual page 0x201000 → physical frame 0x1e1a6000
        //   → CPU translates 0x201120 → 0x1e1a6000 + 0x120 = 0x1e1a6120 ✓
        //
        // page_count includes the in-page offset so a segment that crosses a
        // page boundary gets enough pages mapped.
        let in_page_off = (segment.virt_addr & 0xFFF) as usize;
        let page_count = (in_page_off + segment.size as usize)
            .div_ceil(PAGE_SIZE)
            .max(1);
        let virt_base = segment.virt_addr & !0xFFF_u64; // page-aligned virtual
        let phys_base = segment.phys_addr & !0xFFF_u64; // page-aligned physical frame
        for i in 0..page_count
        {
            let virt = virt_base + (i * PAGE_SIZE) as u64;
            let phys = phys_base + (i * PAGE_SIZE) as u64;
            // SAFETY: segment is bootloader-provided; caller's safety contract.
            unsafe {
                self.map_page(virt, phys, flags)?;
            }
        }
        Ok(())
    }

    /// Allocate `pages` physical frames and map them as a user stack.
    ///
    /// The stack occupies virtual addresses `[stack_top - pages * PAGE_SIZE, stack_top)`.
    /// One additional guard page (unmapped) sits below the stack to catch overflows.
    ///
    /// # Safety
    /// `stack_top` must be page-aligned and within the user address range.
    #[cfg(not(test))]
    pub unsafe fn map_stack(&self, stack_top: u64, pages: usize) -> Result<(), ()>
    {
        let rw_flags = crate::mm::paging::PageFlags {
            readable: true,
            writable: true,
            executable: false,
            uncacheable: false,
        };

        for i in 0..pages
        {
            // Allocate one physical frame per page. The frame allocator lock
            // is acquired and released here, independently of map_page's
            // internal lock acquisition for intermediate page table frames.
            let phys = crate::mm::with_frame_allocator(|alloc| alloc.alloc(0)).ok_or(())?;

            // Zero the frame (stack pages should start clean).
            // SAFETY: phys_to_virt gives a valid kernel virtual address.
            unsafe {
                let virt = phys_to_virt(phys);
                core::ptr::write_bytes(virt as *mut u8, 0, PAGE_SIZE);
            }

            // Map at the correct virtual address (stack grows downward).
            let virt = stack_top - ((i + 1) * PAGE_SIZE) as u64;
            // SAFETY: phys is valid and virt is in user range.
            unsafe {
                self.map_page(virt, phys, rw_flags)?;
            }
        }

        // The guard page (one page below the stack) is intentionally left
        // unmapped: accessing it will fault, catching stack overflows.

        Ok(())
    }

    /// Remove the mapping for a single 4 KiB page at `virt`.
    ///
    /// If `virt` is not mapped, this is a no-op (safe to call redundantly).
    /// Does not free intermediate page table frames. Invalidates TLB entries
    /// on all CPUs where this address space is active.
    ///
    /// # Safety
    /// `virt` must be in the user half. Caller must not access `virt` after
    /// this call; the TLB entry is invalidated.
    #[cfg(not(test))]
    pub unsafe fn unmap_page(&self, virt: u64)
    {
        use crate::arch::current::paging::{flush_page, unmap_user_page};

        crate::percpu::preempt_disable();
        self.pt_lock();

        // Remove the mapping via arch-specific page table walk.
        // SAFETY: root_virt is valid; virt is in user range (caller's contract).
        unsafe { unmap_user_page(self.root_virt, virt) };

        // Shootdown remote CPUs. The current CPU is excluded from the mask;
        // it will invalidate locally below (no need to IPI ourselves).
        let active = self.active_cpu_mask();
        let current = crate::arch::current::cpu::current_cpu();
        let remote_cpus = active & !(1u64 << current);

        if remote_cpus != 0
        {
            // SAFETY: root_phys is a valid page table root; remote_cpus mask
            // contains only bits for online CPUs (enforced by scheduler).
            // preempt_disable() already called above.
            unsafe {
                crate::mm::tlb_shootdown::shootdown(self.root_phys, remote_cpus, virt);
            }
        }

        // Local TLB invalidation for the unmapped page. The current CPU does
        // not send an IPI to itself; it performs the invalidation directly.
        // SAFETY: virt is a valid user virtual address.
        unsafe {
            flush_page(virt);
        }

        self.pt_unlock();
        crate::percpu::preempt_enable();
    }

    /// Change the permission flags on an existing 4 KiB leaf mapping at `virt`.
    ///
    /// Returns `Err(PagingError::NotMapped)` if `virt` is not mapped.
    /// Caller is responsible for W^X and rights validation before calling.
    /// Invalidates TLB entries on all CPUs where this address space is active.
    ///
    /// # Safety
    /// `virt` must be in the user half and currently mapped.
    #[cfg(not(test))]
    pub unsafe fn protect_page(
        &self,
        virt: u64,
        flags: crate::mm::paging::PageFlags,
    ) -> Result<(), crate::mm::paging::PagingError>
    {
        use crate::arch::current::paging::{flush_page, protect_user_page};

        crate::percpu::preempt_disable();
        self.pt_lock();

        // Change protection bits via arch-specific page table walk.
        // SAFETY: root_virt is valid; virt is in user range (caller's contract).
        let result = unsafe { protect_user_page(self.root_virt, virt, flags) };

        if let Err(e) = result
        {
            self.pt_unlock();
            crate::percpu::preempt_enable();
            return Err(e);
        }

        // Shootdown remote CPUs. The current CPU is excluded from the mask;
        // it will invalidate locally below (no need to IPI ourselves).
        let active = self.active_cpu_mask();
        let current = crate::arch::current::cpu::current_cpu();
        let remote_cpus = active & !(1u64 << current);

        if remote_cpus != 0
        {
            // SAFETY: root_phys is a valid page table root; remote_cpus mask
            // contains only bits for online CPUs (enforced by scheduler).
            // preempt_disable() already called above.
            unsafe {
                crate::mm::tlb_shootdown::shootdown(self.root_phys, remote_cpus, virt);
            }
        }

        // Local TLB invalidation for the protected page. The current CPU does
        // not send an IPI to itself; it performs the invalidation directly.
        // SAFETY: virt is a valid user virtual address.
        unsafe {
            flush_page(virt);
        }

        self.pt_unlock();
        crate::percpu::preempt_enable();

        Ok(())
    }

    /// Translate a user virtual address to its mapped physical address.
    ///
    /// Performs a read-only page table walk. Returns `Some((phys_addr,
    /// raw_pte_bits))` if the page is present at every level, or `None`
    /// if the address is not mapped.
    ///
    /// The page-alignment of `virt` is not enforced here; the caller is
    /// responsible for aligning to `PAGE_SIZE` before calling if desired.
    #[cfg(not(test))]
    pub fn query_page(&self, virt: u64) -> Option<(u64, u64)>
    {
        use crate::arch::current::paging::translate_user_page;
        // SAFETY: root_virt is the direct-map VA of a valid root page table.
        unsafe { translate_user_page(self.root_virt, virt) }
    }

    /// Activate this address space on the current CPU.
    ///
    /// On x86-64: writes `root_phys` to CR3 (flushes TLB).
    /// On RISC-V: writes the Sv48 SATP value and issues `sfence.vma`.
    ///
    /// # Safety
    /// Must be called at ring 0 / S-mode. After this call, all virtual
    /// addresses are resolved through this address space's page tables.
    #[cfg(not(test))]
    pub unsafe fn activate(&self)
    {
        use crate::arch::current::paging::activate;
        // SAFETY: caller's contract; root_phys is a valid page table root.
        unsafe {
            activate(self.root_phys);
        }
    }

    /// Mark this address space as active on a CPU.
    ///
    /// Called during context switch when switching TO this address space.
    /// Sets bit `cpu` in the `active_cpus` bitmask.
    ///
    /// # Memory Ordering
    /// Uses Release ordering: ensures all prior address space setup (page
    /// table modifications, mappings) is visible to other CPUs before marking
    /// active, so TLB shootdown sees a consistent view when it queries
    /// `active_cpu_mask`.
    pub fn mark_active_on_cpu(&self, cpu: u32)
    {
        // SAFETY: Release ordering ensures prior address space setup (page
        // table modifications) is visible before we mark it active for TLB
        // shootdown purposes. The fetch_or is atomic; no data race on the mask.
        self.active_cpus.fetch_or(1u64 << cpu, Ordering::Release);
    }

    /// Mark this address space as inactive on a CPU.
    ///
    /// Called during context switch when switching FROM this address space.
    /// Clears bit `cpu` in the `active_cpus` bitmask.
    ///
    /// # Memory Ordering
    /// Uses Release ordering: ensures all TLB-dependent operations complete
    /// before clearing the active bit, so concurrent shootdowns see the correct
    /// mask (a CPU remains active until it has fully switched away).
    pub fn mark_inactive_on_cpu(&self, cpu: u32)
    {
        // SAFETY: Release ordering ensures all TLB-dependent operations
        // complete before we mark inactive, so TLB shootdowns see the correct
        // mask. The fetch_and is atomic; no data race on the mask.
        self.active_cpus
            .fetch_and(!(1u64 << cpu), Ordering::Release);
    }

    /// Get the bitmask of CPUs with this address space active.
    ///
    /// Used by TLB shootdown to determine which CPUs need IPIs.
    /// Bit N set = CPU N is currently running threads in this address space.
    ///
    /// # Memory Ordering
    /// Uses Acquire ordering: ensures we observe all prior `mark_active_on_cpu`
    /// calls from other CPUs, giving an accurate snapshot of which CPUs have
    /// cached TLB entries for this address space.
    pub(crate) fn active_cpu_mask(&self) -> u64
    {
        // SAFETY: Acquire ordering ensures we see all mark_active calls from
        // other CPUs. The load is atomic; no data race on the mask.
        self.active_cpus.load(Ordering::Acquire)
    }
}
