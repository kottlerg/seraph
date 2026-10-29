// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/page_fault_present_bit.rs

//! Integration (x86-64): a `#PF` fault message reports `FAULT_ACCESS_PRESENT`
//! only for a user-half faulting address.
//!
//! The kernel half is mapped supervisor-only in every address space, so a
//! ring-3 access to a mapped kernel page faults with the hardware P bit set.
//! Passing that bit through would let a process bound as its own fault handler
//! tell mapped kernel VAs from unmapped ones, defeating KASLR
//! (core/kernel/docs/cross-boundary-disclosure.md § Surface inventory, fault
//! messages); `page_fault_handler` (`core/kernel/src/arch/x86_64/idt.rs`) reports
//! it only for a CR2 below `user_va_top`. A child whose faults this thread
//! handles makes two kinds of access:
//!
//!   1. **User half**: a store to a page mapped read-only. The message must
//!      carry `FAULT_ACCESS_PRESENT` (and `FAULT_ACCESS_WRITE`), so the test
//!      fails if the bit is dropped for user faults too.
//!   2. **Kernel half**: a load from the start of every 2 MiB slot of the top
//!      GiB of the kernel image window. Every message must carry the bit clear.
//!      The image slides within the 2 GiB window at 2 MiB granularity
//!      (docs/memory-model.md § x86-64), so on a boot whose slide puts the image
//!      in the top GiB (about half of KASLR boots) some probe lands on a mapped
//!      supervisor page whose fault has P = 1, and a kernel that passed the bit
//!      through fails the test; on the other boots every probe finds an unmapped
//!      page and this half cannot fail. CI boots x86-64 ktest twice per change
//!      (debug and release), so it exercises this half in about three runs of
//!      four until #563's fix lets the probes cover the whole window.
//!
//! The probes do not locate a mapped kernel VA with `SIDT`/`SGDT`, which ring 3
//! can still execute while `CR4.UMIP` is clear (#560): that disclosure is a
//! defect to be closed, and a test built on it would break when it is. Nor do
//! they cover the window's lower GiB: the direct map is bounded only below the
//! slid image (`DIRECT_MAP_GUARD` under its base, abi/boot-protocol
//! `layout::direct_map_slots`), so its top can reach into the lower GiB, and
//! the kernel's spurious-fault check walks a kernel-half CR2 through the direct
//! map's 2 MiB leaves as if they were page tables and can loop on the fault
//! instead of delivering it (#563). The top GiB lies above every direct-map
//! address, and the image is mapped with 4 KiB pages, so every probe here is
//! delivered.
//!
//! Each fault is resumed past its faulting instruction: the child records the
//! instruction's address before the access, and the handler checks the fault IP
//! against it and the two encoding bytes there, then advances the IP by two.

use core::sync::atomic::{AtomicU64, Ordering};

use boot_protocol::layout::{
    DIRECT_MAP_GUARD, IMAGE_SLIDE_ALIGN, IMAGE_WINDOW_SIZE, KERNEL_LINK_BASE,
};
use ipc::IpcMessage;
use syscall::{
    cap_create_endpoint, cap_delete, mem_map, mem_unmap, thread_read_regs,
    thread_set_fault_handler, thread_write_regs,
};
use syscall_abi::{
    FAULT_ACCESS_PRESENT, FAULT_ACCESS_READ, FAULT_ACCESS_WRITE, FAULT_CLASS_ALL, FAULT_KIND_VM,
    FAULT_LABEL, FAULT_REPLY_RESUME, MAP_READ,
};

use super::IP_OFFSET;
use crate::{ChildStack, TestContext, TestResult};

/// User-half VA the read-only page is mapped at. Distinct from every other
/// ktest fixed VA.
const RO_VA: u64 = 0x3E_9000_0000;

/// Kernel-image-window slots probed: one per 2 MiB slide slot of the top GiB.
const PROBES: u64 = DIRECT_MAP_GUARD / IMAGE_SLIDE_ALIGN;

/// The lowest probe address: the image window's top `DIRECT_MAP_GUARD` bytes
/// begin here. The direct map ends at least `DIRECT_MAP_GUARD` below the image
/// base, and the image base lies below the window's end, so no direct-map
/// address reaches this floor.
const PROBE_FLOOR: u64 = KERNEL_LINK_BASE + (IMAGE_WINDOW_SIZE - DIRECT_MAP_GUARD);

/// Badge bound with the handler and delivered in each fault message.
const FAULT_BADGE: u64 = 0x9F_0001;

/// Encoding of the child's store, `mov byte ptr [rdi], al`.
const STORE_ENCODING: [u8; 2] = [0x88, 0x07];

/// Encoding of the child's load, `mov al, byte ptr [rdi]`.
const LOAD_ENCODING: [u8; 2] = [0x8A, 0x07];

/// Register-file buffer size; holds the x86-64 `TrapFrame`.
const BUF: usize = 256;
const _: () = assert!(BUF as u64 >= super::TRAP_FRAME_BYTES);

/// Poll bound for the child's exit: ~2 s at ~1 ms per poll, through
/// [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

/// Address of the instruction the child is about to fault on, written by the
/// child before each access and read by the handler after the fault arrives.
static PROBE_IP: AtomicU64 = AtomicU64::new(0);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    let frame = crate::frame_pool::alloc().ok_or("page_fault_present_bit: frame pool exhausted")?;
    // SAFETY: `RO_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    if unsafe { mem_map(frame, ctx.aspace_cap, RO_VA, 0, 1, MAP_READ) }.is_err()
    {
        // SAFETY: `frame` came from the pool and the map failed, so it is mapped
        // nowhere.
        unsafe { crate::frame_pool::free(frame) };
        return Err("page_fault_present_bit: read-only mem_map failed");
    }

    let result = handle_child(ctx);

    // SAFETY: `RO_VA` is a scratch VA (crate docs § Scratch VAs), so the
    // span holds no Rust object or IPC page of ktest.
    if unsafe { mem_unmap(ctx.aspace_cap, RO_VA, 1) }.is_ok()
    {
        // SAFETY: `frame` came from the pool and its only mapping was just
        // removed; the child that touched it has exited or been deleted.
        unsafe { crate::frame_pool::free(frame) };
    }
    result
}

/// Spawn the probing child with this thread as its fault handler, handle every
/// fault it takes, and wait for it to exit. The child's caps and the endpoint
/// are deleted on every path.
fn handle_child(ctx: &TestContext) -> TestResult
{
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "page_fault_present_bit: cap_create_endpoint failed")?;
    let Ok(child) = crate::spawn::new_child(ctx)
    else
    {
        cap_delete(ep).ok();
        return Err("page_fault_present_bit: spawn::new_child failed");
    };

    let result = thread_set_fault_handler(child.th, ep, FAULT_BADGE, FAULT_CLASS_ALL)
        .map_err(|_| "page_fault_present_bit: thread_set_fault_handler failed")
        .and_then(|()| {
            let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
            // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`,
            // on which no other live thread runs (`ChildStack`'s rule).
            unsafe { crate::spawn::configure_and_start(&child, probe_child, stack_top, 0) }
                .map_err(|_| "page_fault_present_bit: configure_and_start failed")
        })
        .and_then(|()| expect_fault(ctx, ep, child.th, RO_VA, Access::UserStore))
        .and_then(|()| {
            (0..PROBES)
                .try_for_each(|k| expect_fault(ctx, ep, child.th, probe_va(k), Access::KernelLoad))
        })
        .and_then(|()| {
            crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS)).map(|_| ())
        });

    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    cap_delete(ep).ok();
    result
}

/// The access the child faults on next.
#[derive(Clone, Copy)]
enum Access
{
    /// The store to the read-only user page: must report `WRITE` and `PRESENT`.
    UserStore,
    /// A load from a kernel-half probe address: must report `READ` and not
    /// `PRESENT`.
    KernelLoad,
}

impl Access
{
    /// Encoding of the faulting instruction, which the resume steps over.
    fn encoding(self) -> [u8; 2]
    {
        match self
        {
            Access::UserStore => STORE_ENCODING,
            Access::KernelLoad => LOAD_ENCODING,
        }
    }

    /// Check the fault message's access flags against this access.
    fn check(self, access: u64) -> TestResult
    {
        match self
        {
            Access::UserStore
                if access & FAULT_ACCESS_WRITE == 0 || access & FAULT_ACCESS_PRESENT == 0 =>
            {
                Err("page_fault_present_bit: user-half store fault lacks WRITE or PRESENT")
            }
            Access::KernelLoad if access & FAULT_ACCESS_READ == 0 =>
            {
                Err("page_fault_present_bit: kernel-half load fault lacks READ")
            }
            Access::KernelLoad if access & FAULT_ACCESS_PRESENT != 0 =>
            {
                Err("page_fault_present_bit: kernel-half fault reports PRESENT")
            }
            _ => Ok(()),
        }
    }
}

/// Receive the child's next fault on `ep`, check it is `access` at `va`, then
/// resume the child (`child_th`) past the faulting instruction.
fn expect_fault(ctx: &TestContext, ep: u32, child_th: u32, va: u64, access: Access) -> TestResult
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "page_fault_present_bit: ipc_recv failed")?;
    if msg.label != FAULT_LABEL || msg.badge != FAULT_BADGE || msg.word(0) != FAULT_KIND_VM
    {
        return Err("page_fault_present_bit: unexpected fault message");
    }
    if msg.word(1) != va
    {
        return Err("page_fault_present_bit: fault address is not the probed address");
    }
    access.check(msg.word(2))?;

    let ip = msg.word(3);
    if ip == 0 || ip != PROBE_IP.load(Ordering::Acquire)
    {
        return Err("page_fault_present_bit: fault IP is not the recorded probe instruction");
    }
    // SAFETY: `ip` equals the address the child recorded of its own probe
    // instruction, which lies in ktest's image, mapped readable in the address
    // space this thread shares with the child.
    let bytes = unsafe { core::ptr::read_volatile(ip as *const [u8; 2]) };
    if bytes != access.encoding()
    {
        return Err("page_fault_present_bit: probe instruction encoding differs");
    }

    let mut regs = [0u8; BUF];
    thread_read_regs(child_th, &mut regs[..BUF])
        .map_err(|_| "page_fault_present_bit: thread_read_regs failed")?;
    regs[IP_OFFSET..IP_OFFSET + 8].copy_from_slice(&(ip + 2).to_le_bytes());
    // SAFETY: the frame was read from this fault-blocked child and only its IP
    // moves, past the two-byte probe instruction to the next one in the same
    // function, on the child's own stack.
    unsafe { thread_write_regs(child_th, &regs[..BUF]) }
        .map_err(|_| "page_fault_present_bit: thread_write_regs failed")?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| "page_fault_present_bit: ipc_reply(RESUME) failed")
}

/// The `k`th kernel-half probe address: the start of the `k`th 2 MiB slot of
/// the image window's top GiB.
fn probe_va(k: u64) -> u64
{
    PROBE_FLOOR + k * IMAGE_SLIDE_ALIGN
}

/// Child entry: store to the read-only user page, then load from every probe
/// address in the image window's top GiB, then exit. Each access faults and is
/// resumed past by the handler.
extern "C" fn probe_child(_arg: u64) -> !
{
    probe_store(RO_VA);
    for k in 0..PROBES
    {
        probe_load(probe_va(k));
    }
    syscall::thread_exit()
}

/// Record the address of a `mov byte ptr [rdi], al` in [`PROBE_IP`], then
/// execute it with `rdi = addr`.
fn probe_store(addr: u64)
{
    // SAFETY: the store targets a read-only page and faults by design; the
    // bound handler resumes this thread at the instruction after it, so no
    // memory is written. `lea` and the `PROBE_IP` store use the scratch
    // register `t`; rdi carries the address and al the stored byte. No flag
    // is changed and no stack is used.
    unsafe {
        core::arch::asm!(
            "lea {t}, [rip + 2f]",
            "mov qword ptr [{slot}], {t}",
            "2:",
            "mov byte ptr [rdi], al",
            t = out(reg) _,
            slot = in(reg) PROBE_IP.as_ptr(),
            in("rdi") addr,
            in("al") 0u8,
            options(nostack, preserves_flags),
        );
    }
}

/// Record the address of a `mov al, byte ptr [rdi]` in [`PROBE_IP`], then
/// execute it with `rdi = addr`.
fn probe_load(addr: u64)
{
    // SAFETY: the load targets a kernel-half address, which faults from ring 3
    // whether or not it is mapped; the bound handler resumes this thread at the
    // instruction after it, so al keeps an unspecified value, which is
    // discarded. `lea` and the `PROBE_IP` store use the scratch register `t`;
    // rdi carries the address. No flag is changed and no stack is used.
    unsafe {
        core::arch::asm!(
            "lea {t}, [rip + 2f]",
            "mov qword ptr [{slot}], {t}",
            "2:",
            "mov al, byte ptr [rdi]",
            t = out(reg) _,
            slot = in(reg) PROBE_IP.as_ptr(),
            in("rdi") addr,
            out("al") _,
            options(nostack, preserves_flags),
        );
    }
}
