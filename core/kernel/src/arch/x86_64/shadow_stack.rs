// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/shadow_stack.rs

//! CET supervisor shadow stacks (SHSTK): the decision to use them, the layout
//! of a shadow-stack page, the per-CPU pages, and the enable sequence
//! (core/kernel/docs/return-address-integrity.md § x86-64 Mechanism).
//!
//! Shadow stacks are on for every CPU or for none, decided once on the BSP in
//! Phase 4 from `CPUID.(EAX=7,ECX=0):ECX[7]` (`CET_SS`) and the Phase-1
//! transient-execution selection, which keeps them off when a selected control
//! rewrites a return, by [`decide`]. With them
//! on, `CALL` pushes each return address to the running shadow stack too and
//! `RET` compares the two copies, raising a control-protection fault (`#CP`,
//! vector 21) on a mismatch. Every shadow stack is one 4 KiB page whose
//! direct-map leaf has the shadow-stack encoding (`paging::PageTableEntry::new_shadow_stack_page`:
//! present, not writable, dirty), so no ordinary store reaches it.
//!
//! A fresh shadow stack whose top is `T` holds three words ([`fresh_words`]):
//! the supervisor token at `T - 8`, the value `IA32_PL0_SSP` names for the
//! thread (its own address, busy bit clear); the address the thread first runs
//! at, at `T - 16`; and a restore token at `T - 24` holding `(T - 16) | 1`,
//! which `context::switch`'s `rstorssp` checks before it moves the shadow-stack
//! pointer (SSP) there. The switch's `saveprevssp` then leaves a restore token
//! on the outgoing stack, one word below its SSP, which is where the outgoing
//! thread's next switch-in finds it.
//!
//! Each CPU keeps [`CPU_PAGES`] pages, carved from its idle-stack block
//! (`sched::idle_block_layout`): the idle thread's shadow stack, the IST1
//! shadow stack (the double-fault and machine-check vectors) with the
//! interrupt SSP table at its base, and the IST2 shadow stack (NMI)
//! ([`cpu_layout`]).

use core::sync::atomic::{AtomicBool, Ordering};

/// Bytes in a shadow-stack page.
const PAGE_BYTES: usize = crate::mm::PAGE_SIZE;
/// [`PAGE_BYTES`] as an address offset.
const PAGE: u64 = PAGE_BYTES as u64;

/// Pages each CPU keeps for its shadow stacks while they are on: the idle
/// thread's, IST1 (with the interrupt SSP table), and IST2.
pub const CPU_PAGES: usize = 3;

/// Bytes of a CPU's IST shadow-stack pages, the ones above the idle thread's.
#[cfg(not(test))]
const IST_PAGES_BYTES: usize = (CPU_PAGES - 1) * PAGE_BYTES;

/// The busy bit of a supervisor shadow-stack token.
#[cfg(test)]
const TOKEN_BUSY: u64 = 1;

/// The mode bit of a restore token: the token was made in 64-bit mode.
const RESTORE_TOKEN_MODE_64: u64 = 1;

/// The shadow-stack state a thread's `SavedState` carries: the SSP its next
/// switch-in restores, through the restore token there, and its supervisor
/// token, which `IA32_PL0_SSP` names while it runs. Both are 0 when shadow
/// stacks are off.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ShadowStack
{
    /// Address of the restore token `rstorssp` loads at switch-in.
    pub ssp: u64,
    /// Address of the supervisor token, the thread's `IA32_PL0_SSP`.
    pub token: u64,
}

/// The value of the supervisor token at `addr`, not busy: its own address.
pub const fn supervisor_token(addr: u64) -> u64
{
    addr
}

/// The value of a restore token at `addr`, made in 64-bit mode: the
/// shadow-stack pointer it restores to sits one word above it.
pub const fn restore_token(addr: u64) -> u64
{
    addr.wrapping_add(8) | RESTORE_TOKEN_MODE_64
}

/// The words of a fresh shadow stack whose top is `top`, a page end, whose
/// thread first runs at `entry`, each as `(address, value)`, and the
/// [`ShadowStack`] its `SavedState` takes.
pub const fn fresh_words(top: u64, entry: u64) -> ([(u64, u64); 3], ShadowStack)
{
    let token = top.wrapping_sub(8);
    let entry_slot = top.wrapping_sub(16);
    let restore = top.wrapping_sub(24);
    (
        [
            (token, supervisor_token(token)),
            (entry_slot, entry),
            (restore, restore_token(restore)),
        ],
        ShadowStack {
            ssp: restore,
            token,
        },
    )
}

/// One CPU's shadow-stack pages, from `base`, the first of [`CPU_PAGES`]
/// contiguous pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuLayout
{
    /// The top of the idle thread's shadow stack.
    pub idle_top: u64,
    /// The interrupt SSP table: eight words at the IST1 page's base.
    pub table: u64,
    /// The IST1 shadow stack's supervisor token, at its page's top.
    pub ist1_token: u64,
    /// The IST2 shadow stack's supervisor token, at its page's top.
    pub ist2_token: u64,
}

/// The layout of the [`CPU_PAGES`] pages at `base`: the idle thread's, IST1
/// (the table at its base), then IST2.
///
/// A shadow stack that outgrows its page runs into the page below it, where
/// no fault stops it when that page is a shadow stack too. The idle thread's,
/// which nests every interrupt taken while the CPU idles, is the lowest, so
/// the page below it is never one of these; the IST stacks hold one event
/// each and stay shallow.
pub const fn cpu_layout(base: u64) -> CpuLayout
{
    CpuLayout {
        idle_top: base.wrapping_add(PAGE),
        table: base.wrapping_add(PAGE),
        ist1_token: base.wrapping_add(2 * PAGE).wrapping_sub(8),
        ist2_token: base.wrapping_add(3 * PAGE).wrapping_sub(8),
    }
}

/// The [`ShadowStack`] of the idle thread of the CPU whose pages are at
/// `base`, as [`init_cpu_pages`] lays it out.
pub const fn idle_stack(base: u64) -> ShadowStack
{
    fresh_words(cpu_layout(base).idle_top, 0).1
}

/// The interrupt SSP table of a CPU whose pages are `layout`: entry `n` is the
/// shadow-stack pointer an event delivered through IST `n` loads, the address
/// of that stack's supervisor token. Entry 0 is unused, and so are the IST
/// indices no IDT gate names (3 to 7; `idt::init` uses IST1 for `#DF` and
/// `#MC`, IST2 for NMI).
pub const fn int_ssp_table(layout: &CpuLayout) -> [u64; 8]
{
    [0, layout.ist1_token, layout.ist2_token, 0, 0, 0, 0, 0]
}

/// Whether the kernel runs on shadow stacks, decided by [`decide`] before any
/// shadow-stack page is laid out. `syscall_entry` reads it, as one byte.
pub(super) static ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether shadow stacks are on.
pub fn enabled() -> bool
{
    ENABLED.load(Ordering::Relaxed)
}

#[cfg(not(test))]
pub(super) use live::IA32_PL0_SSP;
#[cfg(not(test))]
pub use live::{
    decide, enable, init_cpu_pages, init_stack, load_thread_token, prepare_ap, prepare_boot_cpu,
    report_registers,
};

#[cfg(not(test))]
mod live
{
    use core::sync::atomic::Ordering;

    use super::super::cpu;
    use super::{
        ENABLED, IST_PAGES_BYTES, PAGE, PAGE_BYTES, cpu_layout, fresh_words, int_ssp_table,
        supervisor_token,
    };

    /// `IA32_S_CET`: supervisor CET controls.
    const IA32_S_CET: u32 = 0x6A2;
    /// `IA32_S_CET.SH_STK_EN` (bit 0): supervisor shadow stacks on.
    const S_CET_SH_STK_EN: u32 = 1;
    /// `IA32_PL0_SSP`: the SSP a ring-3 to ring-0 transition, and `setssbsy`,
    /// loads. `context::switch` writes it too.
    pub const IA32_PL0_SSP: u32 = 0x6A4;
    /// `IA32_INTERRUPT_SSP_TABLE_ADDR`: the interrupt SSP table.
    const IA32_INTERRUPT_SSP_TABLE_ADDR: u32 = 0x6A8;
    /// `CR4.CET` (bit 23).
    const CR4_CET: u64 = 1 << 23;
    /// `CPUID.(EAX=7,ECX=0):ECX[7]`, `CET_SS`: shadow stacks.
    const CPUID_7_ECX_CET_SS: u32 = 1 << 7;

    /// Whether this CPU reports CET shadow stacks.
    fn has_cet_ss() -> bool
    {
        cpu::cpuid(0).0 >= 7 && cpu::cpuid_subleaf(7, 0).2 & CPUID_7_ECX_CET_SS != 0
    }

    /// Decide, on the BSP, whether the kernel runs on shadow stacks: when the
    /// BSP reports `CET_SS` and no transient-execution control the kernel
    /// selected rewrites a return (`mitigation::Controls::rewrites_returns`).
    /// Every AP must then report `CET_SS` too ([`prepare_ap`]). Logs the
    /// reason when the CPU reports `CET_SS` and the selection keeps shadow
    /// stacks off.
    ///
    /// # Safety
    /// Phase 4, on the single boot thread, once, after Phase 1 installed the
    /// selection and before any per-CPU or Thread shadow-stack page is laid
    /// out.
    pub unsafe fn decide()
    {
        let cet_ss = has_cet_ss();
        let on = cet_ss && !super::super::mitigation::selected().rewrites_returns();
        if cet_ss && !on
        {
            crate::kprintln!(
                "shadow stacks: off, CET_SS reported but the retpoline sequence is selected"
            );
        }
        ENABLED.store(on, Ordering::Relaxed);
    }

    /// Write the [`super::CPU_PAGES`] pages at the direct-map address `base` while
    /// they are still ordinary memory: the idle thread's fresh shadow stack,
    /// which first runs at `idle_entry` ([`super::idle_stack`]), the interrupt
    /// SSP table, and the IST stacks' supervisor tokens.
    ///
    /// # Safety
    /// `base` is the direct-map address of [`super::CPU_PAGES`] RAM pages the caller
    /// owns and has not yet given the shadow-stack encoding.
    pub unsafe fn init_cpu_pages(base: u64, idle_entry: u64)
    {
        let layout = cpu_layout(base);
        // SAFETY: the pages are the caller's and ordinary memory; the idle
        // stack is the first of them.
        unsafe { init_stack(base, idle_entry) };
        // SAFETY: as above; the IST pages are the other two.
        unsafe { core::ptr::write_bytes(layout.table as *mut u8, 0, IST_PAGES_BYTES) };
        let table = int_ssp_table(&layout);
        // SAFETY: as above; the table's eight words lie at the IST1 page's
        // base, which nothing else uses.
        unsafe {
            core::ptr::copy_nonoverlapping(table.as_ptr(), layout.table as *mut u64, table.len());
        }
        for token in [layout.ist1_token, layout.ist2_token]
        {
            // SAFETY: as above; each token is the top word of its IST page.
            unsafe { (token as *mut u64).write(supervisor_token(token)) };
        }
    }

    /// Lay out a fresh shadow stack in the page at the direct-map address
    /// `page` while it is still ordinary memory, for a thread that first runs
    /// at `entry` ([`super::fresh_words`]): the page zeroed, then its three
    /// words. Returns the [`super::ShadowStack`] the thread's `SavedState`
    /// takes.
    ///
    /// # Safety
    /// `page` is the page-aligned direct-map address of a RAM page the caller
    /// owns, writable through the direct map.
    pub unsafe fn init_stack(page: u64, entry: u64) -> super::ShadowStack
    {
        // SAFETY: caller contract.
        unsafe { core::ptr::write_bytes(page as *mut u8, 0, PAGE_BYTES) };
        let (words, stack) = fresh_words(page.wrapping_add(PAGE), entry);
        for (addr, value) in words
        {
            // SAFETY: each word lies in the caller's page (`fresh_words`
            // writes the top three).
            unsafe { (addr as *mut u64).write(value) };
        }
        stack
    }

    /// Point `IA32_PL0_SSP` at `token`, the supervisor token of the thread
    /// this CPU is about to run, when shadow stacks are on: the next
    /// ring-3 to ring-0 transition, and `syscall_entry`'s `setssbsy`, take it.
    /// `context::switch` writes it itself; this is for a first run that is
    /// not a switch-in (`sched::enter`).
    ///
    /// # Safety
    /// Ring 0 with interrupts disabled, on the CPU that runs the thread next.
    pub unsafe fn load_thread_token(token: u64)
    {
        if super::enabled()
        {
            // SAFETY: shadow stacks on, so the MSR exists (`CET_SS`); ring 0.
            unsafe { cpu::write_msr(IA32_PL0_SSP, token) };
        }
    }

    /// Point this CPU's shadow-stack registers at `pl0_ssp`, a supervisor
    /// token `setssbsy` takes, and at the interrupt SSP table of the pages at
    /// `cpu_pages`, and set `CR4.CET`. Shadow stacks stay off until
    /// [`enable`].
    ///
    /// # Safety
    /// Ring 0, interrupts disabled, `CET_SS` present; both addresses name pages
    /// that already have the shadow-stack encoding in this CPU's tables.
    unsafe fn arm(pl0_ssp: u64, cpu_pages: u64)
    {
        // SAFETY: ring 0 and `CET_SS` present (caller contract), so the MSRs
        // exist and CR4.CET may be set; CR0.WP is set (`verify_baseline`, the
        // AP trampoline), which CR4.CET requires.
        unsafe { cpu::write_msr(IA32_PL0_SSP, pl0_ssp) };
        // SAFETY: as above.
        unsafe { cpu::write_msr(IA32_INTERRUPT_SSP_TABLE_ADDR, cpu_layout(cpu_pages).table) };
        // SAFETY: as above.
        unsafe { cpu::write_cr4(cpu::read_cr4() | CR4_CET) };
    }

    /// Print this CPU's CET registers for the kernel exception report, to the
    /// serial console only (the table address and `IA32_PL0_SSP` are kernel
    /// VAs): `IA32_S_CET`, `IA32_INTERRUPT_SSP_TABLE_ADDR`, and
    /// `IA32_PL0_SSP`. Prints nothing while `CR4.CET` is clear, as it is on a
    /// CPU without `CET_SS`, where the MSRs need not exist.
    ///
    /// [`arm`] writes a non-zero table address before it sets `CR4.CET`, and
    /// [`enable`], the only writer of `IA32_S_CET`, sets `SH_STK_EN`. A report
    /// with `CR4.CET` set, `SH_STK_EN` clear, and a zero table address is
    /// therefore of CET state lost outside the kernel, which `cargo xtask
    /// test cet` tells apart from a kernel fault
    /// (core/kernel/docs/return-address-integrity.md § x86-64 Mechanism).
    pub fn report_registers()
    {
        if cpu::read_cr4() & CR4_CET == 0
        {
            return;
        }
        // SAFETY: ring 0; `CR4.CET` is set only by `arm`, on a CPU with
        // `CET_SS`, so the MSR exists.
        let s_cet = unsafe { cpu::read_msr(IA32_S_CET) };
        // SAFETY: as above.
        let table = unsafe { cpu::read_msr(IA32_INTERRUPT_SSP_TABLE_ADDR) };
        // SAFETY: as above.
        let pl0_ssp = unsafe { cpu::read_msr(IA32_PL0_SSP) };
        crate::kprintln_serial!(
            "  cet: s_cet={:#x}  int_ssp_table={:#018x}  pl0_ssp={:#018x}",
            s_cet,
            table,
            pl0_ssp
        );
    }

    /// Prepare the BSP for [`enable`]: give the handoff stack a shadow stack
    /// of its own (a page from `allocator`, kept for good, as the handoff
    /// stack is) and arm the BSP's registers with it and with the interrupt
    /// SSP table of its pages at `cpu_pages`.
    ///
    /// # Safety
    /// Phase 5, on the BSP alone, with interrupts disabled, after `decide`
    /// turned shadow stacks on and after [`init_cpu_pages`] wrote, and the
    /// boot converted, the BSP's pages at `cpu_pages`.
    ///
    /// # Panics
    /// Halts via `crate::fatal` when no page is left or its leaf cannot change.
    pub unsafe fn prepare_boot_cpu(allocator: &mut crate::mm::BuddyAllocator, cpu_pages: u64)
    {
        let phys = allocator
            .alloc(0)
            .unwrap_or_else(|| crate::fatal("Phase 5: out of memory for the handoff shadow stack"));
        let top = crate::mm::paging::phys_to_virt(phys).wrapping_add(PAGE);
        let token = top.wrapping_sub(8);
        // SAFETY: the page is fresh from the buddy, this call's alone, and
        // still ordinary memory.
        unsafe { (token as *mut u64).write(supervisor_token(token)) };
        // SAFETY: only the boot CPU runs; the page is this call's, and nothing
        // stores to it from here on but the shadow-stack accesses enable allows.
        if unsafe { crate::mm::stack_guard::shadow_on_boot_cpu(phys) }.is_err()
        {
            crate::fatal("Phase 5: cannot give the handoff shadow stack its leaf");
        }
        // SAFETY: Phase 5 on the BSP with interrupts disabled; `CET_SS` present
        // (decide); both pages have the shadow-stack encoding.
        unsafe { arm(token, cpu_pages) };
    }

    /// Prepare an AP for [`enable`] on the idle shadow stack of its pages at
    /// `cpu_pages`, which the boot CPU wrote and converted in Phase 4.
    ///
    /// # Safety
    /// On the AP, at ring 0 with interrupts disabled, running on its idle
    /// stack, with shadow stacks on.
    ///
    /// # Panics
    /// Halts via `crate::fatal` when the AP lacks `CET_SS`: a thread migrates
    /// between CPUs with a live call chain, so no CPU may run without them.
    pub unsafe fn prepare_ap(cpu_pages: u64)
    {
        if !has_cet_ss()
        {
            crate::fatal("AP lacks the CET shadow stacks the BSP enabled");
        }
        let idle_token = cpu_layout(cpu_pages).idle_top.wrapping_sub(8);
        // SAFETY: on the AP with interrupts disabled; `CET_SS` present; the pages
        // were converted by the boot CPU before any AP started.
        unsafe { arm(idle_token, cpu_pages) };
    }

    /// Turn shadow stacks on for this CPU: set `IA32_S_CET.SH_STK_EN` and run
    /// `setssbsy`, which takes the supervisor token `IA32_PL0_SSP` names and
    /// starts an empty shadow stack below it.
    ///
    /// Returns with a `jmp` to its return address, not a `ret`, since the new
    /// shadow stack holds no copy of it. No frame that was live before the call
    /// may return afterwards (its `ret` would find no shadow copy): the caller
    /// is `kernel_entry_post_rebase` or `kernel_entry_ap`, which never return.
    ///
    /// # Safety
    /// After `prepare_boot_cpu` or `prepare_ap` on this CPU, with interrupts
    /// disabled, from a function that never returns.
    #[unsafe(naked)]
    pub unsafe extern "C" fn enable()
    {
        core::arch::naked_asm!(
            "pop r11",          // the return address, kept off the shadow stack
            "mov ecx, {s_cet}",
            "mov eax, {sh_stk_en}",
            "xor edx, edx",
            "wrmsr",
            "setssbsy",         // SSP := IA32_PL0_SSP, the token marked busy
            "jmp r11",
            s_cet = const IA32_S_CET,
            sh_stk_en = const S_CET_SH_STK_EN,
        );
    }
}

#[cfg(test)]
mod tests
{
    use std::collections::BTreeMap;

    use super::*;

    /// The shadow-stack instructions `context::switch` runs, over a map of
    /// shadow-stack words, as the Intel SDM states them (`RSTORSSP`,
    /// `SAVEPREVSSP`, `CALL`, `RET`), each returning `Err` where the CPU
    /// raises `#CP`.
    struct Model
    {
        mem: BTreeMap<u64, u64>,
        ssp: u64,
    }

    impl Model
    {
        fn load(&self, addr: u64) -> u64
        {
            *self.mem.get(&addr).unwrap_or(&0)
        }

        fn rstorssp(&mut self, addr: u64) -> Result<(), &'static str>
        {
            let token = self.load(addr);
            if token & 3 != RESTORE_TOKEN_MODE_64 || (token & !3).wrapping_sub(8) != addr
            {
                return Err("rstorssp: no restore token");
            }
            // The previous-SSP token: the old SSP, bit 1 set, the mode bit.
            self.mem.insert(addr, self.ssp | 2 | RESTORE_TOKEN_MODE_64);
            self.ssp = addr;
            Ok(())
        }

        fn saveprevssp(&mut self) -> Result<(), &'static str>
        {
            let prev = self.load(self.ssp);
            if prev & 2 == 0
            {
                return Err("saveprevssp: no previous-SSP token");
            }
            self.ssp += 8;
            let old = prev & !3;
            self.mem.insert(old - 8, restore_token(old - 8));
            Ok(())
        }

        fn call(&mut self, ret: u64)
        {
            self.ssp -= 8;
            self.mem.insert(self.ssp, ret);
        }

        fn ret(&mut self, ret: u64) -> Result<(), &'static str>
        {
            if self.load(self.ssp) != ret
            {
                return Err("ret: shadow copy differs");
            }
            self.ssp += 8;
            Ok(())
        }

        /// The CET half of `context::switch`: save the outgoing SSP minus a
        /// word, switch, and return to `resume` through the shadow stack.
        fn switch(&mut self, next: ShadowStack, resume: u64) -> Result<ShadowStack, &'static str>
        {
            let saved = self.ssp - 8;
            self.rstorssp(next.ssp)?;
            self.saveprevssp()?;
            self.ret(resume)?;
            Ok(ShadowStack {
                ssp: saved,
                token: 0,
            })
        }

        /// `context::switch` from the running thread to itself, which skips
        /// the shadow-stack block.
        fn switch_to_self(&mut self, resume: u64) -> Result<(), &'static str>
        {
            self.ret(resume)
        }

        /// A switch from the running thread to itself that runs the
        /// shadow-stack block, which `context::switch` does not.
        fn unguarded_switch_to_self(&mut self, resume: u64) -> Result<(), &'static str>
        {
            let saved = self.ssp - 8;
            self.rstorssp(saved)?;
            self.saveprevssp()?;
            self.ret(resume)
        }

        fn fresh(&mut self, top: u64, entry: u64) -> ShadowStack
        {
            let (words, stack) = fresh_words(top, entry);
            for (addr, value) in words
            {
                self.mem.insert(addr, value);
            }
            stack
        }
    }

    const A_TOP: u64 = 0x10_0000;
    const B_TOP: u64 = 0x20_0000;
    const ENTRY_A: u64 = 0xffff_ffff_8000_1000;
    const ENTRY_B: u64 = 0xffff_ffff_8000_2000;
    const SCHEDULE_RET: u64 = 0xffff_ffff_8000_3000;

    // The defect caught: a fresh stack whose restore token names the wrong
    // word, or whose entry is not the word the first switch-in's `ret`
    // checks, so the first run of every thread raises #CP.
    #[test]
    fn a_fresh_stack_is_entered_through_its_restore_token()
    {
        let mut m = Model {
            mem: BTreeMap::new(),
            ssp: 0,
        };
        // A running thread at the top of its own stack, mid-call.
        let a = m.fresh(A_TOP, ENTRY_A);
        m.ssp = a.token;
        m.call(SCHEDULE_RET);
        let b = m.fresh(B_TOP, ENTRY_B);
        m.switch(b, ENTRY_B).unwrap();
        assert_eq!(
            m.ssp, b.token,
            "the fresh thread runs from its supervisor token"
        );
        assert_eq!(m.load(b.token), supervisor_token(b.token));
    }

    // The defect caught: an outgoing SSP saved at the wrong word, so its
    // next switch-in finds no restore token, or a resume address checked
    // against the wrong shadow copy.
    #[test]
    fn a_switch_out_and_back_restores_the_ssp_and_checks_the_resume_address()
    {
        let mut m = Model {
            mem: BTreeMap::new(),
            ssp: 0,
        };
        let a = m.fresh(A_TOP, ENTRY_A);
        let b = m.fresh(B_TOP, ENTRY_B);
        m.ssp = a.token;
        m.call(SCHEDULE_RET); // A calls switch from schedule()
        let a_ssp_in_switch = m.ssp;
        let a_saved = m.switch(b, ENTRY_B).unwrap();
        // B runs, then calls switch back to A from schedule().
        m.call(SCHEDULE_RET);
        let b_saved = m.switch(a_saved, SCHEDULE_RET).unwrap();
        assert_eq!(
            m.ssp,
            a_ssp_in_switch + 8,
            "A resumes with switch's frame popped"
        );
        // A corrupted resume address is refused.
        m.call(SCHEDULE_RET);
        assert_eq!(
            m.switch(b_saved, SCHEDULE_RET + 1),
            Err("ret: shadow copy differs")
        );
    }

    // The defect caught: a switch-in at an address that holds no restore
    // token (a stale or zero SSP) goes through instead of faulting.
    #[test]
    fn a_switch_to_a_word_without_a_restore_token_faults()
    {
        let mut m = Model {
            mem: BTreeMap::new(),
            ssp: A_TOP - 8,
        };
        let stale = ShadowStack {
            ssp: B_TOP - 16,
            token: 0,
        };
        assert_eq!(m.switch(stale, ENTRY_B), Err("rstorssp: no restore token"));
    }

    // The defect caught: a switch from a thread to itself (`schedule`'s
    // idle-to-idle fallback) that runs the shadow-stack block, whose
    // `rstorssp` finds no restore token below the running SSP and raises #CP;
    // `context::switch` skips the block when `current` is `next`.
    #[test]
    fn a_switch_to_the_running_thread_keeps_its_shadow_stack()
    {
        let mut m = Model {
            mem: BTreeMap::new(),
            ssp: 0,
        };
        let a = m.fresh(A_TOP, ENTRY_A);
        m.ssp = a.token;
        // The idle loop calls schedule(), which calls switch: two frames, the
        // fresh words below the token long overwritten.
        m.call(ENTRY_A);
        m.call(SCHEDULE_RET);
        let before = m.ssp;
        let mut unguarded = Model {
            mem: m.mem.clone(),
            ssp: m.ssp,
        };
        assert_eq!(
            unguarded.unguarded_switch_to_self(SCHEDULE_RET),
            Err("rstorssp: no restore token")
        );
        m.switch_to_self(SCHEDULE_RET).unwrap();
        assert_eq!(
            m.ssp,
            before + 8,
            "the thread resumes with switch's frame popped"
        );
    }

    #[test]
    fn a_supervisor_token_is_its_own_address_and_not_busy()
    {
        let (words, stack) = fresh_words(A_TOP, ENTRY_A);
        assert_eq!(words[0], (A_TOP - 8, A_TOP - 8));
        assert_eq!(stack.token & TOKEN_BUSY, 0);
        assert_eq!(stack.token, A_TOP - 8);
    }

    // The defect caught: an interrupt SSP table entry that names a word
    // outside its own stack's page, or a supervisor token under the wrong IST
    // index, so an NMI or a double fault switches to another stack.
    #[test]
    fn the_interrupt_ssp_table_names_each_ist_token_in_its_own_page()
    {
        let base = 0xffff_8000_0040_0000;
        let layout = cpu_layout(base);
        let table = int_ssp_table(&layout);
        assert_eq!(table[0], 0);
        assert_eq!(table[1], base + 2 * PAGE - 8);
        assert_eq!(table[2], base + 3 * PAGE - 8);
        assert!(table[3..].iter().all(|&e| e == 0));
        // The table sits at the base of the IST1 page, below its stack, and
        // the idle thread's stack is the page below that.
        assert_eq!(layout.table, base + PAGE);
        assert_eq!(layout.idle_top, base + PAGE);
        for (n, &entry) in table.iter().enumerate().skip(1).take(2)
        {
            // IST n's token is the top word of page n, above the idle page.
            assert_eq!(entry & !(PAGE - 1), base + n as u64 * PAGE);
            assert_eq!(entry % 8, 0);
        }
        // Every page lies inside the CPU's pages.
        assert!(layout.ist2_token < base + CPU_PAGES as u64 * PAGE);
    }
}
