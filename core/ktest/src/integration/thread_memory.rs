// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/thread_memory.rs

//! Integration: a debugger reads and writes another address space's memory
//! through a Thread capability (`SYS_THREAD_READ_MEM`, `SYS_THREAD_WRITE_MEM`;
//! docs/fault-handling.md § Debugging), and every path that exposes code
//! written through a data path synchronises instruction fetch
//! (docs/memory-model.md § Instruction-Fetch Coherence).
//!
//! A thread is created, never started, in a fresh address space B. Pages of
//! B are shared with ktest's own scratch VAs, so each copy is checked from
//! the other side:
//! - a read straddling a page boundary returns what ktest stored, and a
//!   write lands where ktest reads it;
//! - an unmapped page, a kernel-half address, a length of 0 or past
//!   `MAX_THREAD_MEM_COPY`, an undefined flag, and a cap without `CONTROL`
//!   are refused, the write all or nothing;
//! - a text page (mapped executable, frame mapped once) refuses a write
//!   without `THREAD_MEM_TEXT` and takes one with it, and a text page whose
//!   frame ktest also maps refuses it;
//! - `SYS_SYSTEM_INFO(InstructionCacheSyncs)` rises across an executable
//!   `mem_map`, a `mem_protect` to executable (of a read-only page, and of a
//!   page already executable, the route for code written through a writable
//!   alias), the text write, and a data write, whose frame could be mapped
//!   executable elsewhere (the path-taken check: under QEMU a missing
//!   synchronisation does not fail);
//! - a device page (an `Mmio` page ktest maps into B) is refused
//!   (`InvalidAddress`), when the boot hands ktest an `Mmio` of two pages or
//!   more to carve one from;
//! - once B is deleted, its thread is `Exited` and both calls refuse it.
//!
//! A thread in ktest's own address space reads and writes a ktest static the
//! same way, the case where the caller's space is the target's.

use syscall::{
    MAP_EXECUTABLE, MAP_READ, MAP_WRITABLE, cap_create_aspace, cap_create_cspace,
    cap_create_thread, cap_delete, cap_derive, mem_map, mem_protect, mem_unmap, mmio_map,
    mmio_split, system_info, thread_read_mem, thread_write_mem,
};
use syscall_abi::{
    MAX_THREAD_MEM_COPY, RIGHTS_ALL, RIGHTS_THREAD_OBSERVE, SyscallError, SystemInfoType,
    THREAD_MEM_TEXT,
};

use crate::{TestContext, TestResult, spawn};

const PAGE: u64 = 4096;

/// ktest scratch VA of the two shared data pages (crate docs § Scratch VAs).
const KT_DATA: u64 = 0x1_6A00_0000;
/// ktest scratch VA where the text page is written before B maps it.
const KT_TEXT: u64 = 0x1_6B00_0000;
/// ktest scratch VA of the shared text page's second mapping.
const KT_SHARED: u64 = 0x1_6C00_0000;

/// B's VA of the two data pages.
const B_DATA: u64 = 0x4000_0000;
/// B's VA of the text page (frame mapped once).
const B_TEXT: u64 = 0x4010_0000;
/// B's VA of the shared text page (frame also mapped at [`KT_SHARED`]).
const B_SHARED: u64 = 0x4020_0000;
/// B's VA of the page `mem_protect` turns executable.
const B_PROTECT: u64 = 0x4030_0000;
/// An unmapped VA of B.
const B_UNMAPPED: u64 = 0x4040_0000;
/// B's VA of the device page.
const B_DEVICE: u64 = 0x4050_0000;

/// The bytes ktest stores in the text page, then the bytes the text write
/// puts in their place; never executed.
const TEXT_OLD: [u8; 8] = [0x11; 8];
const TEXT_NEW: [u8; 8] = [0xCC; 8];

/// The static the own-space case reads, then writes.
static mut OWN: [u8; 16] = *b"thread_memory!!!";

pub fn run(ctx: &TestContext) -> TestResult
{
    own_space(ctx)?;
    let mut frames = Frames::alloc()?;
    let result = other_space(ctx, &mut frames);
    // SAFETY: KT_DATA and KT_SHARED are scratch VAs (crate docs § Scratch
    // VAs), so the spans hold no Rust object or IPC page of ktest; a failure
    // above may have left them unmapped, which the unmaps tolerate.
    unsafe {
        mem_unmap(ctx.aspace_cap, KT_DATA, 2).ok();
        mem_unmap(ctx.aspace_cap, KT_TEXT, 1).ok();
        mem_unmap(ctx.aspace_cap, KT_SHARED, 1).ok();
    }
    // B was deleted by other_space, or is unreachable on its failure paths
    // only through a leaked cap; either way its mappings are gone or kept
    // with the frames, which `release` returns only on success.
    if result.is_ok()
    {
        // SAFETY: every frame was mapped only in ktest (unmapped above) and in
        // B, which other_space deleted on its success path.
        unsafe { frames.release() };
    }
    result
}

/// The frame-pool pages of the cross-space case: two data pages, the text
/// page, the shared text page, and the page `mem_protect` turns executable.
struct Frames([u64; 5]);

impl Frames
{
    fn alloc() -> Result<Self, &'static str>
    {
        let mut caps = [0u64; 5];
        for (i, c) in caps.iter_mut().enumerate()
        {
            let Some(f) = crate::frame_pool::alloc()
            else
            {
                for f in &caps[..i]
                {
                    // SAFETY: allocated above, never mapped.
                    unsafe { crate::frame_pool::free(*f) };
                }
                return Err("integration::thread_memory: frame pool exhausted");
            };
            *c = f;
        }
        Ok(Self(caps))
    }

    /// Return the frames to the pool.
    ///
    /// # Safety
    /// No address space maps any of them.
    unsafe fn release(&self)
    {
        for f in self.0
        {
            // SAFETY: the caller's contract.
            unsafe { crate::frame_pool::free(f) };
        }
    }
}

/// `Err(code)` as a syscall wrapper returns it.
fn err(e: SyscallError) -> i64
{
    e as i64
}

/// The current `SYS_SYSTEM_INFO(InstructionCacheSyncs)` count.
fn syncs() -> Result<u64, &'static str>
{
    system_info(SystemInfoType::InstructionCacheSyncs as u64)
        .map_err(|_| "integration::thread_memory: system_info(InstructionCacheSyncs) failed")
}

/// A thread in ktest's own space reads and writes a ktest static.
fn own_space(ctx: &TestContext) -> TestResult
{
    let mut child = spawn::new_child(ctx)?;
    let va = core::ptr::addr_of!(OWN) as u64;
    let mut got = [0u8; 16];
    let read = thread_read_mem(child.th, va, &mut got);
    let new = *b"written by cap!!";
    // SAFETY: the range is OWN, which no reference names while the call runs;
    // any bytes are a valid [u8; 16].
    let write = unsafe { thread_write_mem(child.th, va, &new, 0) };
    // SAFETY: OWN is read through a raw pointer, no reference outlives it.
    let after = unsafe { core::ptr::addr_of!(OWN).read_volatile() };
    let ok = child.delete_thread().is_ok() & child.delete_cspace().is_ok();
    if read != Ok(16) || got != *b"thread_memory!!!"
    {
        return Err("integration::thread_memory: own-space read did not return the static");
    }
    if write.is_err() || after != new
    {
        return Err("integration::thread_memory: own-space write did not reach the static");
    }
    if !ok
    {
        return Err("integration::thread_memory: own-space child cleanup failed");
    }
    Ok(())
}

/// The cross-space checks against a thread of a fresh address space B.
fn other_space(ctx: &TestContext, frames: &mut Frames) -> TestResult
{
    let [d0, d1, text, shared, protect] = frames.0;
    let b = cap_create_aspace(ctx.memory_base, 0, 8)
        .map_err(|_| "integration::thread_memory: cap_create_aspace failed")?;
    let Ok(cs) = cap_create_cspace(ctx.memory_base, 0, 4)
    else
    {
        cap_delete(b).ok();
        return Err("integration::thread_memory: cap_create_cspace failed");
    };
    let Ok(th) = cap_create_thread(ctx.memory_base, b, cs, 0, 0)
    else
    {
        cap_delete(cs).ok();
        cap_delete(b).ok();
        return Err("integration::thread_memory: cap_create_thread failed");
    };
    let result = map_all(ctx, b, [d0, d1, text, shared, protect])
        .and_then(|()| data_copies(th))
        .and_then(|()| refusals(th))
        .and_then(|()| text_write(th))
        .and_then(|()| device_refused(ctx, b, th));
    let deleted = cap_delete(b).is_ok();
    // B is gone: its thread is Exited and both calls refuse it.
    let mut buf = [0u8; 8];
    let read_gone = thread_read_mem(th, B_DATA, &mut buf);
    // SAFETY: the thread's space is gone, so the call changes no memory.
    let write_gone = unsafe { thread_write_mem(th, B_DATA, &buf, 0) };
    let ok = cap_delete(th).is_ok() & cap_delete(cs).is_ok();
    result?;
    if !deleted
    {
        return Err("integration::thread_memory: cap_delete(aspace) failed");
    }
    if read_gone != Err(err(SyscallError::InvalidState))
        || write_gone != Err(err(SyscallError::InvalidState))
    {
        return Err("integration::thread_memory: a thread of a deleted space was not refused");
    }
    if !ok
    {
        return Err("integration::thread_memory: thread or CSpace cleanup failed");
    }
    Ok(())
}

/// Map the pages both sides see, and count the synchronisations of the
/// executable `mem_map` and the `mem_protect` to executable.
fn map_all(ctx: &TestContext, b: u64, [d0, d1, text, shared, protect]: [u64; 5]) -> TestResult
{
    // SAFETY: KT_DATA and KT_DATA + PAGE are scratch VAs (crate docs § Scratch
    // VAs), so the spans hold no Rust object or IPC page of ktest.
    unsafe {
        mem_map(d0, ctx.aspace_cap, KT_DATA, 0, 1, MAP_WRITABLE)
            .and_then(|()| mem_map(d1, ctx.aspace_cap, KT_DATA + PAGE, 0, 1, MAP_WRITABLE))
    }
    .map_err(|_| "integration::thread_memory: ktest data mem_map failed")?;
    // SAFETY: `b` is an address space this test created, not ktest's own.
    unsafe {
        mem_map(d0, b, B_DATA, 0, 1, MAP_WRITABLE)
            .and_then(|()| mem_map(d1, b, B_DATA + PAGE, 0, 1, MAP_WRITABLE))
    }
    .map_err(|_| "integration::thread_memory: B data mem_map failed")?;
    for i in 0..2 * PAGE
    {
        // SAFETY: KT_DATA..+2 pages is mapped writable just above.
        // cast_possible_truncation: the pattern keeps the low byte on purpose.
        #[allow(clippy::cast_possible_truncation)]
        unsafe {
            ((KT_DATA + i) as *mut u8).write_volatile(i as u8 ^ 0x5A);
        };
    }

    // The text page: written through ktest's mapping, then mapped executable
    // in B only.
    // SAFETY: KT_TEXT is a scratch VA (crate docs § Scratch VAs).
    unsafe { mem_map(text, ctx.aspace_cap, KT_TEXT, 0, 1, MAP_WRITABLE) }
        .map_err(|_| "integration::thread_memory: ktest text mem_map failed")?;
    for (i, byte) in TEXT_OLD.iter().enumerate()
    {
        // SAFETY: KT_TEXT's page is mapped writable just above; i < 8.
        unsafe { ((KT_TEXT as *mut u8).add(i)).write_volatile(*byte) };
    }
    // SAFETY: KT_TEXT is a scratch VA (crate docs § Scratch VAs).
    unsafe { mem_unmap(ctx.aspace_cap, KT_TEXT, 1) }
        .map_err(|_| "integration::thread_memory: ktest text mem_unmap failed")?;
    let before = syncs()?;
    // SAFETY: `b` is an address space this test created, not ktest's own.
    unsafe { mem_map(text, b, B_TEXT, 0, 1, MAP_EXECUTABLE) }
        .map_err(|_| "integration::thread_memory: B text mem_map failed")?;
    if syncs()? <= before
    {
        return Err("integration::thread_memory: an executable mem_map did not synchronise");
    }

    // The shared text page: executable in B, read-only in ktest too.
    // SAFETY: `b` is an address space this test created, not ktest's own.
    unsafe { mem_map(shared, b, B_SHARED, 0, 1, MAP_EXECUTABLE) }
        .map_err(|_| "integration::thread_memory: B shared mem_map failed")?;
    // SAFETY: KT_SHARED is a scratch VA (crate docs § Scratch VAs).
    unsafe { mem_map(shared, ctx.aspace_cap, KT_SHARED, 0, 1, MAP_READ) }
        .map_err(|_| "integration::thread_memory: ktest shared mem_map failed")?;

    // The protect page: read-only, then executable.
    // SAFETY: `b` is an address space this test created, not ktest's own.
    unsafe { mem_map(protect, b, B_PROTECT, 0, 1, MAP_READ) }
        .map_err(|_| "integration::thread_memory: B protect mem_map failed")?;
    let before = syncs()?;
    // SAFETY: `b` is an address space this test created, not ktest's own.
    unsafe { mem_protect(protect, b, B_PROTECT, 1, MAP_EXECUTABLE) }
        .map_err(|_| "integration::thread_memory: mem_protect to executable failed")?;
    if syncs()? <= before
    {
        return Err("integration::thread_memory: a mem_protect to executable did not synchronise");
    }
    // A protect to executable of a page already executable: the route for
    // code written through a writable alias of an executable frame.
    let before = syncs()?;
    // SAFETY: `b` is an address space this test created, not ktest's own.
    unsafe { mem_protect(text, b, B_TEXT, 1, MAP_EXECUTABLE) }
        .map_err(|_| "integration::thread_memory: mem_protect of an executable page failed")?;
    if syncs()? <= before
    {
        return Err(
            "integration::thread_memory: a mem_protect of an executable page did not synchronise",
        );
    }
    Ok(())
}

/// A read straddling B's two data pages, then a write of a whole
/// `MAX_THREAD_MEM_COPY` across them, each checked from ktest's side.
fn data_copies(th: u64) -> TestResult
{
    let start = B_DATA + PAGE - 100;
    let mut got = [0u8; 200];
    if thread_read_mem(th, start, &mut got) != Ok(200)
    {
        return Err("integration::thread_memory: straddling read failed");
    }
    for (i, byte) in got.iter().enumerate()
    {
        // cast_possible_truncation: the pattern keeps the low byte on purpose.
        #[allow(clippy::cast_possible_truncation)]
        let want = (PAGE - 100 + i as u64) as u8 ^ 0x5A;
        if *byte != want
        {
            return Err("integration::thread_memory: straddling read returned other bytes");
        }
    }

    let before = syncs()?;
    let new = [0xA7u8; MAX_THREAD_MEM_COPY];
    let start = B_DATA + 2048;
    // SAFETY: the thread's space is B, not ktest's.
    unsafe { thread_write_mem(th, start, &new, 0) }
        .map_err(|_| "integration::thread_memory: straddling write failed")?;
    for i in 0..MAX_THREAD_MEM_COPY as u64
    {
        // SAFETY: KT_DATA..+2 pages is mapped; 2048 + i < 2 pages.
        if unsafe { ((KT_DATA + 2048 + i) as *const u8).read_volatile() } != 0xA7
        {
            return Err("integration::thread_memory: straddling write did not land");
        }
    }
    if syncs()? <= before
    {
        return Err("integration::thread_memory: a data-page write did not synchronise");
    }
    Ok(())
}

/// The refusals, each leaving B's memory untouched.
fn refusals(th: u64) -> TestResult
{
    let mut buf = [0u8; 16];
    // A range whose second page is unmapped: the write is all or nothing.
    let last = B_DATA + 2 * PAGE - 8;
    // SAFETY: the thread's space is B, not ktest's.
    let partial = unsafe { thread_write_mem(th, last, &[0x3Cu8; 16], 0) };
    if partial != Err(err(SyscallError::InvalidAddress))
    {
        return Err("integration::thread_memory: a write into an unmapped page was not refused");
    }
    for i in 0..8
    {
        // SAFETY: KT_DATA's second page is mapped; i < 8.
        if unsafe { ((KT_DATA + 2 * PAGE - 8 + i) as *const u8).read_volatile() } == 0x3C
        {
            return Err("integration::thread_memory: a refused write changed memory");
        }
    }
    if thread_read_mem(th, B_UNMAPPED, &mut buf) != Err(err(SyscallError::InvalidAddress))
    {
        return Err("integration::thread_memory: a read of an unmapped page was not refused");
    }
    let kernel_half = 1u64 << 63;
    if thread_read_mem(th, kernel_half, &mut buf) != Err(err(SyscallError::InvalidAddress))
    {
        return Err("integration::thread_memory: a kernel-half read was not refused");
    }
    if thread_read_mem(th, B_DATA, &mut buf[..0]) != Err(err(SyscallError::InvalidArgument))
    {
        return Err("integration::thread_memory: a zero-length read was not refused");
    }
    let mut big = [0u8; MAX_THREAD_MEM_COPY + 1];
    if thread_read_mem(th, B_DATA, &mut big) != Err(err(SyscallError::InvalidArgument))
    {
        return Err("integration::thread_memory: an oversized read was not refused");
    }
    // SAFETY: the thread's space is B, not ktest's.
    if unsafe { thread_write_mem(th, B_DATA, &buf, 1 << 5) }
        != Err(err(SyscallError::InvalidArgument))
    {
        return Err("integration::thread_memory: an undefined flag was not refused");
    }
    let observe = cap_derive(th, RIGHTS_THREAD_OBSERVE)
        .map_err(|_| "integration::thread_memory: cap_derive(OBSERVE) failed")?;
    let refused = thread_read_mem(observe, B_DATA, &mut buf);
    cap_delete(observe).ok();
    if refused != Err(err(SyscallError::InsufficientRights))
    {
        return Err("integration::thread_memory: a read without CONTROL was not refused");
    }
    Ok(())
}

/// The text writes: refused without the flag, taken with it (and
/// synchronised), refused on a frame mapped twice.
fn text_write(th: u64) -> TestResult
{
    let mut got = [0u8; 8];
    if thread_read_mem(th, B_TEXT, &mut got) != Ok(8) || got != TEXT_OLD
    {
        return Err("integration::thread_memory: the text page did not read back");
    }
    // SAFETY: the thread's space is B, not ktest's.
    if unsafe { thread_write_mem(th, B_TEXT, &TEXT_NEW, 0) }
        != Err(err(SyscallError::InsufficientRights))
    {
        return Err("integration::thread_memory: a text write without THREAD_MEM_TEXT was taken");
    }
    let before = syncs()?;
    // SAFETY: the thread's space is B, not ktest's.
    unsafe { thread_write_mem(th, B_TEXT, &TEXT_NEW, THREAD_MEM_TEXT) }
        .map_err(|_| "integration::thread_memory: a text write with THREAD_MEM_TEXT failed")?;
    if syncs()? <= before
    {
        return Err("integration::thread_memory: a text write did not synchronise");
    }
    if thread_read_mem(th, B_TEXT, &mut got) != Ok(8) || got != TEXT_NEW
    {
        return Err("integration::thread_memory: the text write did not land");
    }
    // SAFETY: the thread's space is B, not ktest's.
    if unsafe { thread_write_mem(th, B_SHARED, &TEXT_NEW, THREAD_MEM_TEXT) }
        != Err(err(SyscallError::InvalidState))
    {
        return Err("integration::thread_memory: a text write to a shared frame was taken");
    }
    Ok(())
}

/// A device page of B is refused. ktest carves one page off a copy of the
/// first `Mmio` of two pages or more it holds (a copy, so no mapping of the
/// original is withdrawn) and maps it into B; with none, the case is skipped.
fn device_refused(ctx: &TestContext, b: u64, th: u64) -> TestResult
{
    for slot in 1..=u64::from(crate::unit::hw::scan_bound(ctx))
    {
        let Ok(copy) = cap_derive(slot, RIGHTS_ALL)
        else
        {
            continue;
        };
        let Ok((lo, hi)) = mmio_split(copy, 0x1000)
        else
        {
            cap_delete(copy).ok();
            continue;
        };
        cap_delete(hi).ok();
        // SAFETY: `b` is an address space this test created, not ktest's own.
        let mapped = unsafe { mmio_map(b, lo, B_DEVICE, 0) };
        let mut buf = [0u8; 8];
        let read = mapped.map(|()| thread_read_mem(th, B_DEVICE, &mut buf));
        // Deleting the page's cap withdraws its mapping from B.
        cap_delete(lo).ok();
        return match read
        {
            Err(_) => Err("integration::thread_memory: mmio_map of the device page failed"),
            Ok(r) if r == Err(err(SyscallError::InvalidAddress)) => Ok(()),
            Ok(_) => Err("integration::thread_memory: a device page was not refused"),
        };
    }
    crate::log("ktest: integration::thread_memory device case SKIP (no Mmio >= 2 pages)");
    Ok(())
}
