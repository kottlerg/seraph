// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/single_step.rs

//! Integration (riscv64): a debugger single-steps a thread by planting
//! `c.ebreak` at each successor (docs/fault-handling.md § Debugging).
//!
//! ktest writes [`STUB`] into a page it maps executable in a fresh address
//! space B and starts a thread there, bound to an endpoint for the exception
//! class. The thread stops at the stub's leading `ebreak`. The handler moves
//! its pointer past it, then steps it one instruction at a time: it computes
//! the successor of the instruction at the pointer with `riscv_step` from the
//! thread's registers (`SYS_THREAD_READ_REGS`, `SYS_THREAD_READ_MEM`), plants
//! `c.ebreak` there with `SYS_THREAD_WRITE_MEM` and `THREAD_MEM_TEXT`,
//! resumes the thread, and takes `FAULT_EXC_BREAKPOINT` at the successor, whose
//! bytes it then writes back. The steps cover a fall-through, a not-taken and
//! a taken branch, `jal`, compressed `c.addi`, a not-taken `c.beqz`, `c.j`,
//! `auipc`, and `jalr`, each pointer checked against the stub's layout
//! ([`STEPS`]); at the end the stub reads back as written.

use ipc::IpcMessage;
use syscall::{
    MAP_EXECUTABLE, MAP_WRITABLE, cap_create_aspace, cap_create_cspace, cap_create_endpoint,
    cap_create_thread, cap_delete, mem_map, mem_unmap, thread_configure, thread_read_mem,
    thread_read_regs, thread_start, thread_write_mem, thread_write_regs,
};
use syscall_abi::{
    FAULT_CLASS_EXCEPTION, FAULT_EXC_BREAKPOINT, FAULT_KIND_EXCEPTION, FAULT_LABEL,
    FAULT_REPLY_RESUME, REGS_RISCV64_IP_OFFSET, REGS_RISCV64_SIZE, REGS_RISCV64_X1_OFFSET,
    THREAD_MEM_TEXT,
};

use crate::{TestContext, TestResult};

/// Badge bound with the exception class and delivered in the fault message.
const BADGE: u64 = 0x0DEB_0820;

/// ktest scratch VA the stub is written through (crate docs § Scratch VAs).
const KT_STUB: u64 = 0x1_6D00_0000;

/// B's VA of the stub page.
const B_STUB: u64 = 0x4000_0000;

/// The stepped code, little-endian words and parcels at their offsets. The
/// skipped slots hold `addi a0, a0, 100`, which a wrong step would run.
const STUB: &[(usize, &[u8])] = &[
    (0, &0x0010_0073u32.to_le_bytes()),  // ebreak (the first stop)
    (4, &0x0050_0513u32.to_le_bytes()),  // addi a0, x0, 5
    (8, &0x0005_0463u32.to_le_bytes()),  // beq a0, x0, +8 (not taken)
    (12, &0x0005_1463u32.to_le_bytes()), // bne a0, x0, +8 (taken)
    (16, &0x0645_0513u32.to_le_bytes()), // skipped
    (20, &0x0080_00EFu32.to_le_bytes()), // jal ra, +8
    (24, &0x0645_0513u32.to_le_bytes()), // skipped
    (28, &0x0505u16.to_le_bytes()),      // c.addi a0, 1
    (30, &0xC111u16.to_le_bytes()),      // c.beqz a0, +4 (not taken)
    (32, &0xA011u16.to_le_bytes()),      // c.j +4
    (34, &0x0001u16.to_le_bytes()),      // skipped (c.nop)
    (36, &0x0000_0297u32.to_le_bytes()), // auipc t0, 0
    (40, &0x00C2_8067u32.to_le_bytes()), // jalr x0, 12(t0)
    (44, &0x0645_0513u32.to_le_bytes()), // skipped
    (48, &0x0000_006Fu32.to_le_bytes()), // j . (the end)
];

/// Bytes of [`STUB`].
const STUB_LEN: usize = 52;

/// The stub offsets each step lands on, in order, after the pointer is moved
/// past the leading `ebreak` to offset 4.
const STEPS: [u64; 9] = [8, 12, 20, 28, 30, 32, 36, 40, 48];

pub fn run(ctx: &TestContext) -> TestResult
{
    let frame = crate::frame_pool::alloc()
        .ok_or("integration::single_step: frame_pool::alloc returned None")?;
    let result = with_frame(ctx, frame);
    if result.is_ok()
    {
        // SAFETY: the frame's only mappings, ktest's scratch one and B's,
        // went with the scratch unmap and B's deletion on the success path.
        unsafe { crate::frame_pool::free(frame) };
    }
    result
}

/// Build B around `frame`, step its thread, and tear B down.
fn with_frame(ctx: &TestContext, frame: u64) -> TestResult
{
    write_stub(ctx, frame)?;
    let b = cap_create_aspace(ctx.memory_base, 0, 8)
        .map_err(|_| "integration::single_step: cap_create_aspace failed")?;
    let Ok(cs) = cap_create_cspace(ctx.memory_base, 0, 4)
    else
    {
        cap_delete(b).ok();
        return Err("integration::single_step: cap_create_cspace failed");
    };
    let Ok(ep) = cap_create_endpoint(ctx.memory_base)
    else
    {
        cap_delete(cs).ok();
        cap_delete(b).ok();
        return Err("integration::single_step: cap_create_endpoint failed");
    };
    let result = cap_create_thread(ctx.memory_base, b, cs, 0, 0)
        .map_err(|_| "integration::single_step: cap_create_thread failed")
        .and_then(|th| {
            let stepped = start_and_step(ctx, b, frame, th, ep);
            let deleted = cap_delete(th).is_ok();
            stepped.and(
                if deleted
                {
                    Ok(())
                }
                else
                {
                    Err("integration::single_step: cap_delete(thread) failed")
                },
            )
        });
    let torn = cap_delete(ep).is_ok() & cap_delete(cs).is_ok() & cap_delete(b).is_ok();
    result?;
    if torn
    {
        Ok(())
    }
    else
    {
        Err("integration::single_step: teardown failed")
    }
}

/// Write [`STUB`] into `frame` through ktest's scratch mapping, then unmap
/// it, so B's mapping is the frame's only one and takes a text write.
fn write_stub(ctx: &TestContext, frame: u64) -> TestResult
{
    // SAFETY: KT_STUB is a scratch VA (crate docs § Scratch VAs), so the page
    // holds no Rust object or IPC page of ktest.
    unsafe { mem_map(frame, ctx.aspace_cap, KT_STUB, 0, 1, MAP_WRITABLE) }
        .map_err(|_| "integration::single_step: scratch mem_map failed")?;
    for (at, bytes) in STUB
    {
        for (i, b) in bytes.iter().enumerate()
        {
            // SAFETY: KT_STUB's page is mapped writable just above; at + i is
            // below STUB_LEN, inside the page.
            unsafe { (KT_STUB as *mut u8).add(*at).add(i).write_volatile(*b) };
        }
    }
    // SAFETY: KT_STUB is a scratch VA; no reference into the page is live.
    unsafe { mem_unmap(ctx.aspace_cap, KT_STUB, 1) }
        .map_err(|_| "integration::single_step: scratch mem_unmap failed")
}

/// Map the stub executable in B, start `th` at it, and step it.
fn start_and_step(ctx: &TestContext, b: u64, frame: u64, th: u64, ep: u64) -> TestResult
{
    // SAFETY: `b` is an address space this test created, not ktest's own.
    unsafe { mem_map(frame, b, B_STUB, 0, 1, MAP_EXECUTABLE) }
        .map_err(|_| "integration::single_step: B mem_map failed")?;
    crate::bind_fault_handler_classes(th, ep, BADGE, FAULT_CLASS_EXCEPTION)
        .map_err(|_| "integration::single_step: bind (exception) failed")?;
    // SAFETY: the thread runs in B, not ktest's address space; the stub
    // touches no stack, so any stack pointer serves.
    unsafe { thread_configure(th, B_STUB, B_STUB + 0x800, 0) }
        .map_err(|_| "integration::single_step: thread_configure failed")?;
    thread_start(th).map_err(|_| "integration::single_step: thread_start failed")?;

    if expect_breakpoint(ctx, ep)? != B_STUB
    {
        return Err("integration::single_step: the first ebreak reported the wrong pointer");
    }
    let mut regs = read_regs(th)?;
    set_ip(&mut regs, B_STUB + 4)?;
    // SAFETY: the frame was read from this thread, fault-blocked in B; only
    // its pointer moves, to the next instruction of the stub.
    unsafe { thread_write_regs(th, &regs) }
        .map_err(|_| "integration::single_step: thread_write_regs failed")?;
    for want in STEPS
    {
        let want = B_STUB
            .checked_add(want)
            .ok_or("integration::single_step: a step target overflows")?;
        step(ctx, th, ep, &regs, want)?;
        regs = read_regs(th)?;
        if ip(&regs)? != want
        {
            return Err("integration::single_step: the stepped thread stopped elsewhere");
        }
    }
    let mut text = [0u8; STUB_LEN];
    thread_read_mem(th, B_STUB, &mut text)
        .map_err(|_| "integration::single_step: reading the stub back failed")?;
    if STUB
        .iter()
        .any(|(at, bytes)| text.get(*at..).and_then(|rest| rest.get(..bytes.len())) != Some(*bytes))
    {
        return Err("integration::single_step: a planted breakpoint was left in the text");
    }
    // The thread resumes into the stub's closing `j .` and spins there until
    // its deletion.
    reply_resume(ctx)
}

/// One step of the fault-blocked `th`, whose registers are `regs`: plant
/// `c.ebreak` at the successor `riscv_step` computes, which must be `want`,
/// resume, take the breakpoint there, and restore the bytes.
fn step(ctx: &TestContext, th: u64, ep: u64, regs: &[u8], want: u64) -> TestResult
{
    let pc = ip(regs)?;
    let insn = read_instruction(th, pc)?;
    let gprs = gprs(regs)?;
    // `riscv_step` reads only `x1..=x31` (a 5-bit register field, `x0` apart),
    // all inside `gprs`.
    let next = riscv_step::successor(pc, insn, |n| gprs.get(n as usize).copied().unwrap_or(0))
        .map_err(|_| "integration::single_step: the decoder refused a stub instruction")?;
    if next != want
    {
        return Err("integration::single_step: the decoder gave the wrong successor");
    }
    let mut saved = [0u8; 2];
    thread_read_mem(th, next, &mut saved)
        .map_err(|_| "integration::single_step: saving the successor failed")?;
    // SAFETY: the thread runs in B, not ktest's address space.
    unsafe { thread_write_mem(th, next, &riscv_step::C_EBREAK, THREAD_MEM_TEXT) }
        .map_err(|_| "integration::single_step: planting the breakpoint failed")?;
    reply_resume(ctx)?;
    let reported = expect_breakpoint(ctx, ep)?;
    // SAFETY: as above.
    unsafe { thread_write_mem(th, next, &saved, THREAD_MEM_TEXT) }
        .map_err(|_| "integration::single_step: restoring the successor failed")?;
    if reported != next
    {
        return Err("integration::single_step: the step's breakpoint reported the wrong pointer");
    }
    Ok(())
}

/// The instruction at `pc` in `th`'s address space: its first parcel, and
/// the second only when `riscv_step::instruction_len` says it has one, so a
/// compressed instruction is read without touching the bytes past it.
fn read_instruction(th: u64, pc: u64) -> Result<u32, &'static str>
{
    let mut parcel = [0u8; 2];
    thread_read_mem(th, pc, &mut parcel)
        .map_err(|_| "integration::single_step: reading the instruction failed")?;
    let low = u16::from_le_bytes(parcel);
    let len = riscv_step::instruction_len(low)
        .map_err(|_| "integration::single_step: the decoder refused a stub instruction")?;
    if len == 2
    {
        return Ok(u32::from(low));
    }
    let upper = pc
        .checked_add(2)
        .ok_or("integration::single_step: the instruction's upper parcel overflows")?;
    thread_read_mem(th, upper, &mut parcel)
        .map_err(|_| "integration::single_step: reading the instruction failed")?;
    Ok(u32::from(low) | (u32::from(u16::from_le_bytes(parcel)) << 16))
}

/// Receive a `FAULT_EXC_BREAKPOINT` on `ep`; returns its reported pointer.
fn expect_breakpoint(ctx: &TestContext, ep: u64) -> Result<u64, &'static str>
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "integration::single_step: ipc_recv failed")?;
    if msg.label != FAULT_LABEL
        || msg.badge != BADGE
        || msg.word(0) != FAULT_KIND_EXCEPTION
        || msg.word(1) != FAULT_EXC_BREAKPOINT
    {
        return Err("integration::single_step: unexpected fault message");
    }
    Ok(msg.word(3))
}

/// Reply RESUME to the fault ktest holds.
fn reply_resume(ctx: &TestContext) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| "integration::single_step: reply failed")
}

/// The fault-blocked `th`'s register file.
fn read_regs(th: u64) -> Result<[u8; REGS_RISCV64_SIZE], &'static str>
{
    let mut regs = [0u8; REGS_RISCV64_SIZE];
    thread_read_regs(th, &mut regs)
        .map_err(|_| "integration::single_step: thread_read_regs failed")?;
    Ok(regs)
}

/// The instruction pointer in `regs`.
fn ip(regs: &[u8]) -> Result<u64, &'static str>
{
    crate::spawn::reg_word(regs, REGS_RISCV64_IP_OFFSET)
}

/// Set the instruction pointer in `regs`.
fn set_ip(regs: &mut [u8], value: u64) -> TestResult
{
    crate::spawn::set_reg_word(regs, REGS_RISCV64_IP_OFFSET, value)
}

/// The integer registers in `regs`, `xN` at index `N`, with `x0` as 0.
fn gprs(regs: &[u8]) -> Result<[u64; 32], &'static str>
{
    let mut out = [0u64; 32];
    for (n, slot) in out.iter_mut().enumerate().skip(1)
    {
        let at = n
            .checked_sub(1)
            .and_then(|i| i.checked_mul(8))
            .and_then(|offset| offset.checked_add(REGS_RISCV64_X1_OFFSET))
            .ok_or("integration::single_step: register offset overflows")?;
        *slot = crate::spawn::reg_word(regs, at)?;
    }
    Ok(out)
}
