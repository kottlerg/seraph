// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/fault_redirect.rs

//! Integration: a fault handler that replies `FAULT_REPLY_REDIRECT` hands the
//! fault to the endpoint its reply names (docs/fault-handling.md § Reply).
//!
//!   1. **Redirect of a user access.** A page fault reaches the VM endpoint;
//!      its redirect, naming a badged Endpoint cap with no rights and carrying
//!      a word, delivers the same fault message to the named endpoint, with
//!      that cap's badge and the word as data word 4. The thread stays
//!      fault-blocked there: its registers read, and the target backs the page
//!      and resumes it, so the store completes and the thread reports it.
//!   2. **Redirect of a kernel copy.** The fault of a `SYS_GETRANDOM` copy
//!      into an unbacked buffer, redirected the same way, is held by the
//!      target, which backs the buffer and resumes it: the syscall restarts
//!      and succeeds, and the thread reports that rather than being killed or
//!      failing with `InvalidAddress`.
//!   3. **Refused redirect.** A redirect naming a Notification cap fails the
//!      reply with `InvalidCapability`, and the fault takes the unhandled
//!      outcome: the thread exits with the page fault's reason.
//!   4. **Forward from the target.** The target's `FAULT_REPLY_FORWARD` of the
//!      redirected VM-class delivery reaches the exception handler, with the
//!      target's word, not the redirector's, as data word 4.
//!   5. **Rebind after a redirect.** A change of the VM class's binding while
//!      the redirected delivery waits at the target delivers the fault again
//!      under the new binding, with its badge and four data words.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, cap_derive_badge, mem_map,
    mem_unmap, notification_wait_timeout, thread_read_regs, wait_set_add, wait_set_create,
    wait_set_wait,
};
use syscall_abi::{
    EXIT_FAULT_BASE, FAULT_CLASS_EXCEPTION, FAULT_CLASS_VM, FAULT_KIND_VM, FAULT_LABEL,
    FAULT_REDIRECT_WORD, FAULT_REPLY_FORWARD, FAULT_REPLY_KILL, FAULT_REPLY_REDIRECT,
    FAULT_REPLY_RESUME, MAP_WRITABLE, PAGE_SIZE, RIGHTS_NTF_NOTIFY, SyscallError,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Scratch pages (crate docs § Scratch VAs), distinct from other tests' VAs:
/// the user-access phase's page and the kernel-copy phase's page, which the
/// target backs, and the page the other phases fault on, which nothing backs.
const STORE_VA: u64 = 0x3E_F000_0000;
const COPY_VA: u64 = 0x3E_F010_0000;
const UNBACKED_VA: u64 = 0x3E_F020_0000;

/// Badges bound with the VM and the exception endpoint, attached to the
/// redirect target's cap, and bound with the endpoint the VM class is rebound
/// to.
const BADGE_VM: u64 = 0xC0FF_EE2A;
const BADGE_EXC: u64 = 0xC0FF_EE2B;
const BADGE_TARGET: u64 = 0xC0FF_EE2C;
const BADGE_OTHER: u64 = 0xC0FF_EE2D;

/// The word the VM handler's redirect carries, and the reason word the
/// target's forward carries.
const WORD: u64 = 0x5EED_0007;
const REASON: u64 = 0x5EED_0008;

/// The value the user-access child stores, and the bytes the copy-fault
/// child's `SYS_GETRANDOM` asks for.
const PATTERN: u64 = 0xA5A5_5A5A_0F0F_F0F0;
const COPY_LEN: usize = 16;

/// Wait-set badges naming the endpoint a fault reached.
const WS_VM: u64 = 0x01;
const WS_EXC: u64 = 0x02;
const WS_TARGET: u64 = 0x04;

/// The children's reports: the store landed; the copy syscall succeeded; it
/// failed with `InvalidAddress`; it failed otherwise.
const STORE_DONE: u64 = 1 << 0;
const COPY_DONE: u64 = 1 << 1;
const COPY_REFUSED: u64 = 1 << 2;
const COPY_FAILED: u64 = 1 << 3;

/// Bound on the wait for a child to exit, in 1 ms polls. Applied through
/// [`crate::scaled_polls`], which stretches it past [`crate::UNSCALED_CPUS`]
/// CPUs, where a child's CPU waits for a host core.
const EXIT_POLLS: u32 = 2000;

/// Bound, in milliseconds, on the wait for a child's report. Applied through
/// [`crate::scaled_bound`], which stretches it the same way.
const REPORT_MS: u64 = 1000;

/// Register-file buffer size; holds the arch `TrapFrame`.
const BUF: usize = 512;
const _: () = assert!(BUF as u64 >= crate::arch::TRAP_FRAME_BYTES);

/// Bytes of a page, for zeroing a backed one.
#[expect(clippy::cast_possible_truncation, reason = "a page is 4 KiB")]
const PAGE_BYTES: usize = PAGE_SIZE as usize;

/// One child per phase.
const CHILDREN: usize = 5;

/// Pages the target backs: the user-access and the kernel-copy phase's.
const BACKED: usize = 2;

static mut STACKS: [ChildStack; CHILDREN] = [ChildStack::ZERO; CHILDREN];

/// Child cap slot of the report notification, read by the child entries.
static REPORT_SIG: AtomicU64 = AtomicU64::new(0);

/// The caps, children and backed pages the test creates; each is released on
/// every path: the children first, so no thread reaches a page, then the
/// pages, then the caps.
#[derive(Default)]
struct Parts
{
    ep_vm: Option<u64>,
    ep_exc: Option<u64>,
    ep_target: Option<u64>,
    target: Option<u64>,
    ep_other: Option<u64>,
    sig: Option<u64>,
    ws: Option<u64>,
    children: [Option<spawn::SpawnedChild>; CHILDREN],
    /// `(va, frame)` of each page the target backed.
    pages: [Option<(u64, u64)>; BACKED],
}

/// The objects the phases share.
struct Objects
{
    aspace: u64,
    ep_vm: u64,
    ep_exc: u64,
    ep_target: u64,
    /// The badged, rights-less Endpoint cap to `ep_target` the redirects name.
    target: u64,
    ep_other: u64,
    sig: u64,
    ws: u64,
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let mut parts = Parts::default();
    let result = phases(ctx, &mut parts);
    let mut ok = true;
    for child in parts.children.iter_mut().flatten()
    {
        ok &= child.delete_thread().is_ok();
        ok &= child.delete_cspace().is_ok();
    }
    for (va, mem) in parts.pages.iter_mut().filter_map(Option::take)
    {
        // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs) this test
        // mapped, and no thread of the test is left to reach it.
        if unsafe { mem_unmap(ctx.aspace_cap, va, 1) }.is_ok()
        {
            // SAFETY: mem is from the pool and no longer mapped.
            unsafe { crate::frame_pool::free(mem) };
        }
        else
        {
            ok = false;
        }
    }
    for cap in [
        parts.ws,
        parts.target,
        parts.ep_vm,
        parts.ep_exc,
        parts.ep_target,
        parts.ep_other,
        parts.sig,
    ]
    .into_iter()
    .flatten()
    {
        ok &= cap_delete(cap).is_ok();
    }
    result?;
    if ok
    {
        Ok(())
    }
    else
    {
        Err("integration::fault_redirect: teardown failed")
    }
}

fn phases(ctx: &TestContext, parts: &mut Parts) -> TestResult
{
    let fail = |_| "integration::fault_redirect: object creation failed";
    let ep_target = *parts
        .ep_target
        .insert(cap_create_endpoint(ctx.memory_base).map_err(fail)?);
    let objects = Objects {
        aspace: ctx.aspace_cap,
        ep_vm: *parts
            .ep_vm
            .insert(cap_create_endpoint(ctx.memory_base).map_err(fail)?),
        ep_exc: *parts
            .ep_exc
            .insert(cap_create_endpoint(ctx.memory_base).map_err(fail)?),
        ep_target,
        target: *parts
            .target
            .insert(cap_derive_badge(ep_target, 0, BADGE_TARGET).map_err(fail)?),
        ep_other: *parts
            .ep_other
            .insert(cap_create_endpoint(ctx.memory_base).map_err(fail)?),
        sig: *parts
            .sig
            .insert(cap_create_notification(ctx.memory_base).map_err(fail)?),
        ws: *parts
            .ws
            .insert(wait_set_create(ctx.memory_base, crate::WS_CAPACITY).map_err(fail)?),
    };
    for (ep, badge) in [
        (objects.ep_vm, WS_VM),
        (objects.ep_exc, WS_EXC),
        (objects.ep_target, WS_TARGET),
    ]
    {
        wait_set_add(objects.ws, ep, badge)
            .map_err(|_| "integration::fault_redirect: wait_set_add failed")?;
    }
    redirect_user_access(ctx, parts, &objects)?;
    redirect_kernel_copy(ctx, parts, &objects)?;
    refused_redirect(ctx, parts, &objects)?;
    forward_from_target(ctx, parts, &objects)?;
    rebind_after_redirect(ctx, parts, &objects)
}

/// Phase 1: the redirect delivers the fault to the named endpoint, where the
/// thread stays fault-blocked until the target backs the page and resumes it.
fn redirect_user_access(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = spawn_child(ctx, parts, 0, objects)?;
    bind_vm(th, objects)?;
    start_child(parts, 0, report_store_entry, STORE_VA)?;
    let first = expect_fault_at(ctx, objects, WS_VM)?;
    if first.badge != BADGE_VM
        || first.word(0) != FAULT_KIND_VM
        || first.word(1) != STORE_VA
        || first.count != FAULT_REDIRECT_WORD
    {
        return Err("integration::fault_redirect: unexpected VM fault message");
    }
    redirect(ctx, objects.target)?;

    let held = expect_fault_at(ctx, objects, WS_TARGET)?;
    let same_fault = (0..FAULT_REDIRECT_WORD).all(|i| held.word(i) == first.word(i));
    if held.badge != BADGE_TARGET
        || !same_fault
        || held.count != FAULT_REDIRECT_WORD + 1
        || held.word(FAULT_REDIRECT_WORD) != WORD
    {
        return Err("integration::fault_redirect: the redirected message is not the fault's");
    }
    let mut regs = [0u8; BUF];
    thread_read_regs(th, &mut regs[..BUF]).map_err(
        |_| "integration::fault_redirect: thread_read_regs of the redirected fault failed",
    )?;
    back_page(parts, 0, STORE_VA, objects)?;
    reply(ctx, FAULT_REPLY_RESUME)?;
    expect_report(objects, STORE_DONE)
}

/// Phase 2: a redirected kernel-copy fault is held by the target, and its
/// resume restarts the syscall, which then succeeds.
fn redirect_kernel_copy(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = spawn_child(ctx, parts, 1, objects)?;
    bind_vm(th, objects)?;
    start_child(parts, 1, copy_entry, COPY_VA)?;
    let first = expect_fault_at(ctx, objects, WS_VM)?;
    if first.word(0) != FAULT_KIND_VM || first.word(1) != COPY_VA
    {
        return Err("integration::fault_redirect: unexpected copy fault message");
    }
    redirect(ctx, objects.target)?;
    let held = expect_fault_at(ctx, objects, WS_TARGET)?;
    if held.badge != BADGE_TARGET
        || held.word(1) != COPY_VA
        || held.word(FAULT_REDIRECT_WORD) != WORD
    {
        return Err("integration::fault_redirect: the redirected copy fault is not the fault's");
    }
    back_page(parts, 1, COPY_VA, objects)?;
    reply(ctx, FAULT_REPLY_RESUME)?;
    expect_report(objects, COPY_DONE)
}

/// Phase 3: a redirect naming a Notification cap fails the reply, and the
/// fault takes the unhandled outcome.
fn refused_redirect(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = spawn_child(ctx, parts, 2, objects)?;
    bind_vm(th, objects)?;
    start_child(parts, 2, store_entry, UNBACKED_VA)?;
    expect_fault_at(ctx, objects, WS_VM)?;
    let r = send_reply(ctx, FAULT_REPLY_REDIRECT, Some(WORD), Some(objects.sig));
    if r != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("integration::fault_redirect: a redirect to a notification was not refused");
    }
    expect_exit(th, crate::arch::PAGE_FAULT_STORE_VECTOR)
}

/// Phase 4: the target's forward of the redirected VM-class delivery reaches
/// the exception handler with the target's reason.
fn forward_from_target(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = spawn_child(ctx, parts, 3, objects)?;
    bind_vm(th, objects)?;
    crate::bind_fault_handler_classes(th, objects.ep_exc, BADGE_EXC, FAULT_CLASS_EXCEPTION)
        .map_err(|_| "integration::fault_redirect: bind (exception) failed")?;
    start_child(parts, 3, store_entry, UNBACKED_VA)?;
    expect_fault_at(ctx, objects, WS_VM)?;
    redirect(ctx, objects.target)?;
    expect_fault_at(ctx, objects, WS_TARGET)?;
    send_reply(ctx, FAULT_REPLY_FORWARD, Some(REASON), None)
        .map_err(|_| "integration::fault_redirect: reply (forward) failed")?;
    let forwarded = expect_fault_at(ctx, objects, WS_EXC)?;
    if forwarded.badge != BADGE_EXC
        || forwarded.word(1) != UNBACKED_VA
        || forwarded.word(FAULT_REDIRECT_WORD) != REASON
    {
        return Err("integration::fault_redirect: the target's forward is not the fault's");
    }
    reply(ctx, FAULT_REPLY_KILL)?;
    expect_exit(th, crate::arch::PAGE_FAULT_STORE_VECTOR)
}

/// Phase 5: a rebind of the VM class while the redirected delivery is queued
/// at the target delivers it again under the new binding.
fn rebind_after_redirect(ctx: &TestContext, parts: &mut Parts, objects: &Objects) -> TestResult
{
    let th = spawn_child(ctx, parts, 4, objects)?;
    bind_vm(th, objects)?;
    start_child(parts, 4, store_entry, UNBACKED_VA)?;
    expect_fault_at(ctx, objects, WS_VM)?;
    redirect(ctx, objects.target)?;
    // The redirected delivery is queued at the target once the wait set
    // reports it; the rebind then cancels it there.
    let ready = wait_set_wait(objects.ws)
        .map_err(|_| "integration::fault_redirect: wait_set_wait failed")?;
    if ready != WS_TARGET
    {
        return Err("integration::fault_redirect: the redirect reached another endpoint");
    }
    crate::bind_fault_handler_classes(th, objects.ep_other, BADGE_OTHER, FAULT_CLASS_VM)
        .map_err(|_| "integration::fault_redirect: rebind (VM) failed")?;
    let msg = recv_fault(ctx, objects.ep_other)?;
    if msg.badge != BADGE_OTHER
        || msg.word(0) != FAULT_KIND_VM
        || msg.word(1) != UNBACKED_VA
        || msg.count != FAULT_REDIRECT_WORD
    {
        return Err("integration::fault_redirect: the rebound delivery is not the fault's");
    }
    reply(ctx, FAULT_REPLY_KILL)?;
    expect_exit(th, crate::arch::PAGE_FAULT_STORE_VECTOR)
}

/// Spawn child `index` with a copy of the report notification. Returns its
/// Thread cap; the child is configured and started by [`start_child`].
fn spawn_child(
    ctx: &TestContext,
    parts: &mut Parts,
    index: usize,
    objects: &Objects,
) -> Result<u64, &'static str>
{
    let child = parts
        .children
        .get_mut(index)
        .ok_or("integration::fault_redirect: child index out of range")?
        .insert(spawn::new_child(ctx).map_err(|_| "integration::fault_redirect: spawn failed")?);
    let child_sig = cap_copy(objects.sig, child.cs, RIGHTS_NTF_NOTIFY)
        .map_err(|_| "integration::fault_redirect: cap_copy notification failed")?;
    REPORT_SIG.store(child_sig, Ordering::Release);
    Ok(child.th)
}

/// Configure and start child `index` at `entry`, passing it `va`.
fn start_child(parts: &Parts, index: usize, entry: extern "C" fn(u64) -> !, va: u64) -> TestResult
{
    let child = parts
        .children
        .get(index)
        .and_then(Option::as_ref)
        .ok_or("integration::fault_redirect: no child")?;
    // SAFETY: `STACKS` is a static array of stacks, reached only through `addr_of!`.
    let stack = unsafe { ChildStack::top_at(core::ptr::addr_of!(STACKS), index) }?;
    // SAFETY: the stack is `STACKS[index]`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { spawn::configure_and_start(child, entry, stack, va) }
        .map_err(|_| "integration::fault_redirect: start failed")
}

fn bind_vm(th: u64, objects: &Objects) -> TestResult
{
    crate::bind_fault_handler_classes(th, objects.ep_vm, BADGE_VM, FAULT_CLASS_VM)
        .map_err(|_| "integration::fault_redirect: bind (VM) failed")
}

/// The parts of a received fault message the phases check, copied out of the
/// `IpcMessage` so a phase holds none.
struct Fault
{
    badge: u64,
    /// Data words 0 to 4; a word past `count` reads 0.
    words: [u64; FAULT_REDIRECT_WORD + 1],
    count: usize,
}

impl Fault
{
    fn word(&self, index: usize) -> u64
    {
        self.words.get(index).copied().unwrap_or(0)
    }
}

/// Wait for a fault to reach an endpoint, check through the wait set that it
/// is the one `ws_badge` names, and receive it there.
fn expect_fault_at(
    ctx: &TestContext,
    objects: &Objects,
    ws_badge: u64,
) -> Result<Fault, &'static str>
{
    let ready = wait_set_wait(objects.ws)
        .map_err(|_| "integration::fault_redirect: wait_set_wait failed")?;
    if ready != ws_badge
    {
        return Err("integration::fault_redirect: a fault reached another endpoint");
    }
    let ep = match ws_badge
    {
        WS_VM => objects.ep_vm,
        WS_EXC => objects.ep_exc,
        _ => objects.ep_target,
    };
    recv_fault(ctx, ep)
}

/// Receive a fault message on `ep`.
fn recv_fault(ctx: &TestContext, ep: u64) -> Result<Fault, &'static str>
{
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "integration::fault_redirect: ipc_recv failed")?;
    if msg.label != FAULT_LABEL
    {
        return Err("integration::fault_redirect: not a fault message");
    }
    let mut words = [0; FAULT_REDIRECT_WORD + 1];
    for (index, word) in words.iter_mut().enumerate().take(msg.word_count())
    {
        *word = msg.word(index);
    }
    Ok(Fault {
        badge: msg.badge,
        words,
        count: msg.word_count(),
    })
}

/// Reply `label` to the fault the controller holds, with `word` as data word
/// 0 and `cap` as its one capability when given.
#[expect(
    clippy::large_stack_frames,
    reason = "the `IpcMessageBuilder` values its optional steps move and the built `IpcMessage` \
              (about 568 B each); on init's 16 KiB stack"
)]
fn send_reply(ctx: &TestContext, label: u64, word: Option<u64>, cap: Option<u64>)
-> Result<(), i64>
{
    let mut msg = IpcMessage::builder(label);
    if let Some(word) = word
    {
        msg = msg.word(0, word);
    }
    if let Some(cap) = cap
    {
        msg = msg.cap(cap);
    }
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&msg.build(), ctx.ipc_buf) }
}

/// Redirect the fault the controller holds to the endpoint `target` names,
/// with [`WORD`] as data word 0.
fn redirect(ctx: &TestContext, target: u64) -> TestResult
{
    send_reply(ctx, FAULT_REPLY_REDIRECT, Some(WORD), Some(target))
        .map_err(|_| "integration::fault_redirect: reply (redirect) failed")
}

/// Reply `label`, with no words, to the fault the controller holds.
fn reply(ctx: &TestContext, label: u64) -> TestResult
{
    send_reply(ctx, label, None, None).map_err(|_| "integration::fault_redirect: reply failed")
}

/// Back the scratch page at `va` with a zeroed, writable pool frame, held in
/// `parts.pages[slot]` for the teardown.
fn back_page(parts: &mut Parts, slot: usize, va: u64, objects: &Objects) -> TestResult
{
    let entry = parts
        .pages
        .get_mut(slot)
        .ok_or("integration::fault_redirect: page slot out of range")?;
    let mem = crate::frame_pool::alloc()
        .ok_or("integration::fault_redirect: frame_pool::alloc failed")?;
    // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs), so the page
    // holds no Rust object or IPC page of ktest.
    if unsafe { mem_map(mem, objects.aspace, va, 0, 1, MAP_WRITABLE) }.is_err()
    {
        // SAFETY: mem is from the pool and was never mapped.
        unsafe { crate::frame_pool::free(mem) };
        return Err("integration::fault_redirect: mem_map failed");
    }
    *entry = Some((va, mem));
    // SAFETY: the page at `va` is mapped writable just above and holds no Rust
    // object; the only thread that reaches it is fault-blocked until the
    // resume that follows.
    unsafe { core::ptr::write_bytes(va as *mut u8, 0, PAGE_BYTES) };
    Ok(())
}

/// Check that the child reports `bits` within the report bound.
fn expect_report(objects: &Objects, bits: u64) -> TestResult
{
    let got = notification_wait_timeout(objects.sig, crate::scaled_bound(REPORT_MS))
        .map_err(|_| "integration::fault_redirect: report wait failed")?;
    if got != bits
    {
        return Err("integration::fault_redirect: the resumed child reported the wrong outcome");
    }
    Ok(())
}

/// Check that `th` exits with the fault reason of `vector`.
fn expect_exit(th: u64, vector: u64) -> TestResult
{
    let reason = spawn::wait_until_exited(th, crate::scaled_polls(EXIT_POLLS))
        .map_err(|_| "integration::fault_redirect: child never exited")?;
    if Some(reason) != EXIT_FAULT_BASE.checked_add(vector)
    {
        return Err("integration::fault_redirect: child exited with the wrong reason");
    }
    Ok(())
}

/// Report `bits` through the published notification cap, then spin; the loop
/// only satisfies `-> !`.
fn report(bits: u64) -> !
{
    syscall::notification_send(REPORT_SIG.load(Ordering::Acquire), bits).ok();
    loop
    {
        core::hint::spin_loop();
    }
}

/// Child entry: store [`PATTERN`] to `va`, which faults until a handler backs
/// the page, and report [`STORE_DONE`] once the store reads back.
extern "C" fn report_store_entry(va: u64) -> !
{
    let p = va as *mut u64;
    // SAFETY: `va` is a scratch page no Rust object occupies; the store faults
    // until the target backs the page, and completes once it resumes.
    unsafe { p.write_volatile(PATTERN) };
    // SAFETY: the page is backed and mapped, the store above having completed.
    if unsafe { p.read_volatile() } == PATTERN
    {
        report(STORE_DONE);
    }
    report(0)
}

/// Child entry: store to `va`, which nothing backs, so the fault is never
/// resolved. The loop only satisfies `-> !`.
extern "C" fn store_entry(va: u64) -> !
{
    let p = va as *mut u64;
    // SAFETY: deliberately faulting — the fault is never resolved by backing
    // this page.
    unsafe { p.write_volatile(0xDEAD_BEEF) };
    loop
    {
        core::hint::spin_loop();
    }
}

/// Child entry: `SYS_GETRANDOM` into the unbacked page at `va`, whose copy
/// faults; report how the syscall ended.
extern "C" fn copy_entry(va: u64) -> !
{
    // SAFETY: the span is a scratch page no Rust object occupies; the kernel
    // writes it once the target backs it.
    let r = unsafe { syscall::getrandom_raw(va as *mut u8, COPY_LEN) };
    match r
    {
        Ok(_) => report(COPY_DONE),
        Err(e) if e == SyscallError::InvalidAddress as i64 => report(COPY_REFUSED),
        Err(_) => report(COPY_FAILED),
    }
}
