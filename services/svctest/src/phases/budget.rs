// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/budget.rs

//! Create-time memory max: a creator bounds its child's memory through
//! procmgr (`procmgr_labels::CREATE_MEMORY_MAX`), and memmgr holds the child's
//! budget node to it (services/memmgr/docs/memory-pool.md § Distribution
//! policy; services/procmgr/docs/ipc-interface.md § Label 1, **Memory max and
//! reserve**).
//!
//! The phase creates a `budget-child` ([`budget_child_main`]) through a raw
//! `CREATE_FROM_FILE` with a max of [`CHILD_MAX_PAGES`], and checks that procmgr
//! relays the max the child's node took, that the child's run passes every
//! step, and that memmgr's free pool returns to its level after the child's
//! destroy. It also checks procmgr's refusals: `CREATE_RESERVE` from svctest,
//! whose node is outside the system reserve; `CREATE_MEMORY_MAX` without its
//! data word; a create on a destroyed child's process handle, whose badge
//! names no live process; and a max too small for the image to load under,
//! the create's own or that of the node a `CREATE_CHARGE_NODE` handle names,
//! which procmgr answers with its `LIMIT`.

use std::os::seraph::startup_info;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::bootstrap::Caps;
use crate::runner::Phase;

use super::procmgr::{HELLO_PATH, create_call, expect_create, with_head};

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "procmgr_memory_max",
        run: memory_max_phase,
    }]
}

/// Child-mode dispatch for the argv token this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == BUDGET_CHILD_ROLE
    {
        budget_child_main();
    }
}

/// argv[1] of the child [`memory_max_phase`] creates with a max.
const BUDGET_CHILD_ROLE: &str = "budget-child";
/// The max in pages the phase asks for its child: room for the child's
/// image, heap and stacks, and for the grants its fill takes.
const CHILD_MAX_PAGES: u64 = 4096;
/// Exit code: a `QUERY_MEMORY_USAGE` call to memmgr failed or was refused.
const CHILD_USAGE_QUERY_FAILED: i32 = 2;
/// Exit code: the child's node holds a max other than [`CHILD_MAX_PAGES`].
const CHILD_MAX_NOT_TAKEN: i32 = 3;
/// Exit code: the lookup of `/programs/hello` failed.
const CHILD_LOOKUP_FAILED: i32 = 4;
/// Exit code: the grandchild's create call failed or was refused.
const CHILD_GRANDCHILD_REFUSED: i32 = 5;
/// Exit code: the grandchild's node took a max other than what the child's
/// node had left.
const CHILD_GRANDCHILD_NOT_CLAMPED: i32 = 6;
/// Exit code: the destroyed grandchild's charge never left the child's
/// subtree.
const CHILD_GRANDCHILD_STILL_CHARGED: i32 = 7;
/// Exit code: the fault endpoint, the handler thread, its binding or the
/// demand region could not be set up.
const CHILD_SETUP_FAILED: i32 = 8;
/// Exit code: a grant under the max failed, or more grants than
/// [`FILL_MAX_GRANTS`] were needed to reach it.
const CHILD_FILL_FAILED: i32 = 9;
/// Exit code: after the fill, the node's own and subtree usage are not both
/// the max.
const CHILD_FILL_NOT_AT_MAX: i32 = 10;
/// Exit code: a one-page grant past the max was not refused with `LIMIT`.
const CHILD_NO_LIMIT: i32 = 11;
/// Exit code: memmgr's reply to a forged fault on the demand region was not
/// a forward with decline 10.
const CHILD_FORGED_NOT_DECLINED: i32 = 12;
/// Exit code: the touch of the demand region came back with no fault handed
/// to the handler.
const CHILD_TOUCH_NOT_FORWARDED: i32 = 13;
/// Exit code: the handler received a fault other than the touch's, or one
/// whose reason is not decline 10.
const CHILD_WRONG_FAULT: i32 = 14;
/// Exit code: the handler could not return a grant to make room for the
/// touched page.
const CHILD_RELEASE_FAILED: i32 = 15;

/// memmgr's decline code for a fault over a budget node's max
/// (services/memmgr/docs/ipc-interface.md § Kernel-origin fault message).
const DECLINE_OVER_MAX: u64 = 10;
/// Pages of each grant the fill asks for while more than this many are left
/// under the max; halved when memmgr has no contiguous run so long.
const FILL_GRANT_PAGES: u64 = 256;
/// Grants the fill may take before it gives up: far more than the fill
/// needs on any pool that can hold the child.
const FILL_MAX_GRANTS: u32 = 1024;
/// `QUERY_MEMORY_USAGE` polls for the destroyed grandchild's charge to leave
/// the child's subtree. A test wait bound.
const UNCHARGE_POLLS: u32 = 256;
/// Bytes of stack the handler thread touches before the fill, so that its
/// work on the fault faults no stack page in once the child is at its max.
const HANDLER_STACK_TOUCH: usize = 6 * 1024;
/// Badge of the SEND the child binds its main thread's exception class to.
const HANDLER_BADGE: u64 = 0xB06E7;

/// The child's demand region, the page the touch faults on.
static REGION_VA: AtomicU64 = AtomicU64::new(0);
/// The first grant of the fill, `(cap, region id)`, which the handler returns
/// to memmgr to make room for the touched page.
static FIRST_GRANT_CAP: AtomicU64 = AtomicU64::new(0);
static FIRST_GRANT_REGION: AtomicU64 = AtomicU64::new(0);
/// Set by the handler thread once its stack is touched and it is about to
/// receive.
static HANDLER_READY: AtomicBool = AtomicBool::new(false);
/// The handler's verdict on the first fault it received: `0` while none came,
/// [`HANDLED`] for the touch's, else the child's exit code naming what was
/// wrong.
static VERDICT: AtomicI32 = AtomicI32::new(0);
/// [`VERDICT`] for the touch's fault, forwarded with decline 10.
const HANDLED: i32 = -1;

/// Sample windows the phase retries: memmgr's free-pool size is system-wide,
/// and other processes (crasher shares the boot) can move it inside one.
const POOL_WINDOWS: u32 = 8;
/// Pool queries per window after the child's destroy. A test wait bound.
const POOL_POLLS: u32 = 256;
/// How long the phase waits for its child to exit. A test wait bound: the
/// budget child's run is a few hundred IPC calls and the zeroing of its
/// grants, the heap-commit hog's the zeroing of most of RAM.
const CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(120);

/// procmgr's create-time memory max, end to end: the refusals, then a
/// `budget-child` run whose pages memmgr's free pool gets back.
fn memory_max_phase(_: &Caps)
{
    create_reserve_refused();
    memory_max_word_refused();
    max_refusals_answer_limit();
    let reclaimed = (0..POOL_WINDOWS).any(|_| {
        let before = settled_pool_free();
        run_budget_child();
        pool_settles_to(before)
    });
    assert!(
        reclaimed,
        "memmgr's free pool did not return to its level after the budget child's destroy in any \
         of {POOL_WINDOWS} windows"
    );
    std::os::seraph::log!("procmgr_memory_max phase passed");
}

/// The file cap and size of `/<dir>/<name>`.
fn file_at(dir: &[u8], name: &[u8]) -> (u64, u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let root = std::os::seraph::root_dir_cap();
    let (dir_cap, _, _) = crate::ipc_util::ns::ns_lookup(root, dir, 0xFFFF, ipc_buf)
        .expect("ns_lookup of the directory failed");
    let (file, _, size) = crate::ipc_util::ns::ns_lookup(dir_cap, name, 0xFFFF, ipc_buf)
        .expect("ns_lookup of the file failed");
    let _ = syscall::cap_delete(dir_cap);
    (file, size)
}

/// Call `target` with `msg` and return procmgr's reply.
fn call(target: u64, msg: &ipc::IpcMessage, what: &str) -> ipc::IpcMessage
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(target, msg, std::os::seraph::current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("{what}: ipc_call failed ({e})"))
}

/// Call `target` with `msg` and assert procmgr replies `want`.
fn expect_reply(target: u64, msg: &ipc::IpcMessage, want: u64, what: &str)
{
    let reply = call(target, msg, what);
    assert_eq!(reply.label, want, "{what}: procmgr replied {}", reply.label);
}

/// procmgr refuses `CREATE_RESERVE` from svctest with `INVALID_ARGUMENT`:
/// svcmgr starts svctest outside the system reserve, and procmgr honours the
/// flag only from a creator whose node is a reserve node. Both create labels
/// check it before they acquire anything, so a spare cap stands in for
/// `CREATE_PROCESS`'s module.
fn create_reserve_refused()
{
    use ipc::{procmgr_errors, procmgr_labels};

    let procmgr = startup_info().procmgr_endpoint;
    let (file, size) = file_at(b"programs", b"hello");
    expect_create(
        procmgr,
        procmgr_labels::CREATE_FROM_FILE | procmgr_labels::CREATE_RESERVE,
        &[size],
        HELLO_PATH,
        &[file],
        procmgr_errors::INVALID_ARGUMENT,
        "CREATE_FROM_FILE with CREATE_RESERVE from a creator outside the reserve",
    );
    let spare = syscall::cap_derive(procmgr, syscall::RIGHTS_EP_SEND)
        .expect("deriving a spare cap to attach failed");
    expect_create(
        procmgr,
        procmgr_labels::CREATE_PROCESS | procmgr_labels::CREATE_RESERVE,
        &[size],
        HELLO_PATH,
        &[spare],
        procmgr_errors::INVALID_ARGUMENT,
        "CREATE_PROCESS with CREATE_RESERVE from a creator outside the reserve",
    );
}

/// procmgr refuses `CREATE_MEMORY_MAX` whose data word the request does not
/// deliver, with or without the argv/env header before it, with
/// `INVALID_ARGUMENT`.
fn memory_max_word_refused()
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
    use std::os::seraph::process::ArgvEnvCap;

    let procmgr = startup_info().procmgr_endpoint;
    let (file, size) = file_at(b"programs", b"hello");
    expect_reply(
        procmgr,
        &IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE | procmgr_labels::CREATE_MEMORY_MAX)
            .word(0, size)
            .cap(file)
            .build(),
        procmgr_errors::INVALID_ARGUMENT,
        "CREATE_FROM_FILE with CREATE_MEMORY_MAX and no max word",
    );
    let argv_env = ArgvEnvCap::new(b"/programs/hello\0", 1, b"", 0)
        .expect("building the argv/env cap failed")
        .expect("a nonempty argv builds a cap");
    let (file, size) = file_at(b"programs", b"hello");
    expect_reply(
        procmgr,
        &IpcMessage::builder(
            procmgr_labels::CREATE_FROM_FILE
                | procmgr_labels::CREATE_ARGV_ENV
                | procmgr_labels::CREATE_MEMORY_MAX,
        )
        .word(0, size)
        .words(1, &argv_env.header_words())
        .cap(file)
        .cap(argv_env.cap())
        .build(),
        procmgr_errors::INVALID_ARGUMENT,
        "CREATE_FROM_FILE with CREATE_ARGV_ENV, CREATE_MEMORY_MAX and no max word",
    );
}

/// A max too small for the child's image fails its create with procmgr's
/// `LIMIT`, not `OUT_OF_MEMORY`, whether it is the create's own max or the
/// max of the sub-node a `CREATE_CHARGE_NODE` handle names: memmgr refuses
/// procmgr the child's pages with its `LIMIT`. A create charged to another
/// sub-node, with no max, then succeeds.
fn max_refusals_answer_limit()
{
    use super::node_handle::{expect, handle_copy, handle_of, release_refused};
    use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels};

    let procmgr = startup_info().procmgr_endpoint;
    let (file, size) = file_at(b"programs", b"hello");
    expect_create(
        procmgr,
        procmgr_labels::CREATE_FROM_FILE | procmgr_labels::CREATE_MEMORY_MAX,
        &[size, 1],
        HELLO_PATH,
        &[file],
        procmgr_errors::LIMIT,
        "CREATE_FROM_FILE with a one-page max",
    );
    let sub_node = |max: u64, what: &str| {
        let reply = expect(
            startup_info().memmgr_endpoint,
            memmgr_labels::CREATE_SUB_NODE,
            &[max],
            memmgr_errors::SUCCESS,
            what,
        );
        handle_of(&reply, what)
    };
    let small = sub_node(1, "CREATE_SUB_NODE of one page");
    let roomy = sub_node(u64::MAX, "CREATE_SUB_NODE with no max");
    let charged = procmgr_labels::CREATE_FROM_FILE | procmgr_labels::CREATE_CHARGE_NODE;
    let (file, size) = file_at(b"programs", b"hello");
    expect_create(
        procmgr,
        charged,
        &[size],
        HELLO_PATH,
        &[file, handle_copy(small)],
        procmgr_errors::LIMIT,
        "CREATE_FROM_FILE charged to a one-page sub-node",
    );
    let what = "CREATE_FROM_FILE charged to a sub-node with no max";
    let (file, size) = file_at(b"programs", b"hello");
    let reply = create_call(
        procmgr,
        charged,
        &[size],
        HELLO_PATH,
        &[file, handle_copy(roomy)],
    )
    .unwrap_or_else(|e| panic!("{what}: ipc_call failed ({e})"));
    let (procmgr_errors::SUCCESS, &[handle, thread]) = (reply.label, reply.caps())
    else
    {
        panic!(
            "{what}: procmgr replied {} with {} caps",
            reply.label,
            reply.caps().len()
        );
    };
    expect_reply(
        handle,
        &IpcMessage::new(procmgr_labels::DESTROY_PROCESS),
        procmgr_errors::SUCCESS,
        "DESTROY_PROCESS of the child charged to a sub-node with no max",
    );
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(handle);
    release_refused(small, "the one-page sub-node");
    release_refused(roomy, "the sub-node with no max");
}

/// Create a `budget-child` with a max of [`CHILD_MAX_PAGES`], run it to its
/// exit, destroy it, and check its exit code and that procmgr then refuses a
/// create on its handle.
fn run_budget_child()
{
    use ipc::{procmgr_errors, procmgr_labels};

    let (handle, thread) = create_with_max(BUDGET_CHILD_ROLE, CHILD_MAX_PAGES, "the budget child");
    let reason = run_to_exit(handle, "the budget child");
    let (file, size) = file_at(b"programs", b"hello");
    expect_create(
        handle,
        procmgr_labels::CREATE_FROM_FILE,
        &[size],
        HELLO_PATH,
        &[file],
        procmgr_errors::INVALID_ARGUMENT,
        "CREATE_FROM_FILE on a destroyed child's process handle",
    );
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(handle);
    assert_eq!(
        reason, 0,
        "budget child exit reason {reason:#x}: {CHILD_USAGE_QUERY_FAILED}=usage query failed, \
         {CHILD_MAX_NOT_TAKEN}=its node holds another max, {CHILD_LOOKUP_FAILED}=lookup failed, \
         {CHILD_GRANDCHILD_REFUSED}=grandchild create refused, {CHILD_GRANDCHILD_NOT_CLAMPED}=the \
         grandchild's max not clamped to what was left, {CHILD_GRANDCHILD_STILL_CHARGED}=the \
         grandchild's charge stayed, {CHILD_SETUP_FAILED}=setup failed, {CHILD_FILL_FAILED}=a \
         grant under the max failed, {CHILD_FILL_NOT_AT_MAX}=usage not at the max after the fill, \
         {CHILD_NO_LIMIT}=a grant past the max not refused with LIMIT, \
         {CHILD_FORGED_NOT_DECLINED}=a forged fault not declined with 10, \
         {CHILD_TOUCH_NOT_FORWARDED}=the touch reached no handler, {CHILD_WRONG_FAULT}=the \
         handler received another fault or reason, {CHILD_RELEASE_FAILED}=the handler's release \
         failed, a fault reason=the child was killed"
    );
}

/// Configure the namespace of the created child `handle` (`what`, for the
/// messages) to svctest's root, start it, wait for its exit and destroy it;
/// its exit reason.
pub(crate) fn run_to_exit(handle: u64, what: &str) -> u64
{
    start(handle, what);
    finish(handle, what)
}

/// Configure the namespace of the created child `handle` (`what`, for the
/// messages) to svctest's root and start it.
pub(crate) fn start(handle: u64, what: &str)
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

    let root = syscall::cap_copy(
        std::os::seraph::root_dir_cap(),
        startup_info().self_cspace,
        syscall::RIGHTS_EP_SEND,
    )
    .unwrap_or_else(|e| panic!("copying the root cap for {what} failed ({e})"));
    expect_reply(
        handle,
        &IpcMessage::builder(procmgr_labels::CONFIGURE_NAMESPACE)
            .cap(root)
            .build(),
        procmgr_errors::SUCCESS,
        &format!("CONFIGURE_NAMESPACE of {what}"),
    );
    expect_reply(
        handle,
        &IpcMessage::new(procmgr_labels::START_PROCESS),
        procmgr_errors::SUCCESS,
        &format!("START_PROCESS of {what}"),
    );
}

/// Wait for the started child `handle` (`what`, for the messages) to exit and
/// destroy it; its exit reason.
pub(crate) fn finish(handle: u64, what: &str) -> u64
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

    let reason = await_exit(handle, what);
    expect_reply(
        handle,
        &IpcMessage::new(procmgr_labels::DESTROY_PROCESS),
        procmgr_errors::SUCCESS,
        &format!("DESTROY_PROCESS of the exited {what}"),
    );
    reason
}

/// Create `/tests/svctest <role>` (`what`, for the messages) through a raw `CREATE_FROM_FILE` with `CREATE_MEMORY_MAX` of
/// `max` pages after the argv/env header, assert the reply carries the max
/// asked (svctest's node has no max, so memmgr's clamp leaves it), and return
/// `(process handle, thread)`.
pub(crate) fn create_with_max(role: &str, max: u64, what: &str) -> (u64, u64)
{
    let reply = create_role(role, 0, Some(max), None, what);
    assert_eq!(reply.word(0), max, "the node of {what} took another max");
    match reply.caps()
    {
        &[handle, thread] => (handle, thread),
        other => panic!("CREATE_FROM_FILE of {what} replied {} caps", other.len()),
    }
}

/// Create `/tests/svctest <role>` (`what`, for the messages) through a raw
/// `CREATE_FROM_FILE` with the create flags `flags`, and with
/// `CREATE_MEMORY_MAX` of `max` pages after the argv/env header when `max`
/// is given, and with `CREATE_CHARGE_NODE` of the node handle `charge` (moved
/// to procmgr) when it is given; assert procmgr accepts it, and return its
/// reply.
pub(crate) fn create_role(
    role: &str,
    flags: u64,
    max: Option<u64>,
    charge: Option<u64>,
    what: &str,
) -> ipc::IpcMessage
{
    use ipc::{procmgr_errors, procmgr_labels};
    use std::os::seraph::process::ArgvEnvCap;

    let args = format!("/tests/svctest\0{role}\0");
    let argv_env = ArgvEnvCap::new(args.as_bytes(), 2, b"", 0)
        .unwrap_or_else(|e| panic!("building the argv/env cap of {what} failed ({e:?})"))
        .expect("a nonempty argv builds a cap");
    let (file, size) = file_at(b"tests", b"svctest");
    let max_flag = if max.is_some()
    {
        procmgr_labels::CREATE_MEMORY_MAX
    }
    else
    {
        0
    };
    let charge_flag = if charge.is_some()
    {
        procmgr_labels::CREATE_CHARGE_NODE
    }
    else
    {
        0
    };
    let label = procmgr_labels::CREATE_FROM_FILE
        | procmgr_labels::CREATE_ARGV_ENV
        | max_flag
        | charge_flag
        | flags;
    let mut words = with_head(size, &argv_env.header_words());
    words.extend(max);
    // The tail caps in the order procmgr reads them: the file, the charge
    // node's handle, the argv/env cap.
    let caps: Vec<u64> = [Some(file), charge, Some(argv_env.cap())]
        .into_iter()
        .flatten()
        .collect();
    let reply = create_call(
        startup_info().procmgr_endpoint,
        label,
        &words,
        "/tests/svctest",
        &caps,
    );
    argv_env.settle(reply.as_ref().map_or(0, |r| r.label));
    let reply = reply.unwrap_or_else(|e| panic!("CREATE_FROM_FILE of {what} failed ({e})"));
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "CREATE_FROM_FILE of {what} refused"
    );
    reply
}

/// Poll `QUERY_PROCESS` on `handle` (`what`, for the messages) until the
/// process exits; its exit reason.
fn await_exit(handle: u64, what: &str) -> u64
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels, procmgr_process_state};

    let query = IpcMessage::new(procmgr_labels::QUERY_PROCESS);
    let start = Instant::now();
    loop
    {
        let reply = call(handle, &query, "QUERY_PROCESS");
        assert_eq!(
            reply.label,
            procmgr_errors::SUCCESS,
            "QUERY_PROCESS refused the handle of {what}"
        );
        if reply.word(0) == procmgr_process_state::EXITED
        {
            return reply.word(1);
        }
        assert!(
            start.elapsed() < CHILD_EXIT_TIMEOUT,
            "{what} did not exit in {CHILD_EXIT_TIMEOUT:?}"
        );
        std::thread::yield_now();
    }
}

/// memmgr's free pool once its deferred list has settled
/// ([`crate::phases::memmgr::settled_deferred_bytes`]).
pub(crate) fn settled_pool_free() -> u64
{
    let _ = crate::phases::memmgr::settled_deferred_bytes();
    crate::phases::memmgr::pool_free_and_largest().0
}

/// Whether memmgr's free pool reads `level` within [`POOL_POLLS`] polls, each
/// after a recheck of memmgr's deferred list, on which runs of the child's
/// that the kernel still held at its teardown wait.
fn pool_settles_to(level: u64) -> bool
{
    for _ in 0..POOL_POLLS
    {
        crate::phases::memmgr::recheck_deferred();
        if crate::phases::memmgr::pool_free_and_largest().0 == level
        {
            return true;
        }
        std::thread::yield_now();
    }
    false
}

// ── The budget child ─────────────────────────────────────────────────────────

/// Child role: run under a max of [`CHILD_MAX_PAGES`] pages and exit 0 when
/// memmgr holds the child to it at each step, else with the step's exit code:
///
/// 1. `QUERY_MEMORY_USAGE` reports the max.
/// 2. A grandchild created with a larger max takes what the child's node has
///    left, and its charge leaves the child's subtree after its destroy
///    ([`grandchild_clamped`]).
/// 3. Everything the later steps allocate is set up first: a handler thread
///    bound as the main thread's exception handler, and a one-page demand
///    region ([`arm_handler`]).
/// 4. Grants fill the node to its max ([`fill_to_max`]), and one page more is
///    refused with `LIMIT`, not `OUT_OF_MEMORY`.
/// 5. memmgr declines a forged fault on the region with code 10.
/// 6. The touch of the region faults, memmgr declines it with code 10 and the
///    kernel forwards it to the handler, which checks it, returns a grant to
///    make room, and resumes the touch.
///
/// No step after the fill allocates from the heap or grows a stack, since
/// memmgr refuses this process every further page.
fn budget_child_main() -> !
{
    use std::process::exit;

    match memory_usage()
    {
        Some((_, max, _)) if max == CHILD_MAX_PAGES =>
        {}
        Some(_) => exit(CHILD_MAX_NOT_TAKEN),
        None => exit(CHILD_USAGE_QUERY_FAILED),
    }
    grandchild_clamped();
    let va = arm_handler();
    fill_to_max();
    match crate::phases::memmgr::try_request_contiguous(1)
    {
        Err(label) if label == ipc::memmgr_errors::LIMIT =>
        {}
        _ => exit(CHILD_NO_LIMIT),
    }
    if crate::phases::pager::forged_vm_fault(va, syscall_abi::FAULT_ACCESS_WRITE)
        != (syscall_abi::FAULT_REPLY_FORWARD, DECLINE_OVER_MAX)
    {
        exit(CHILD_FORGED_NOT_DECLINED);
    }
    // SAFETY: `va` is the page of a demand region this process registered and
    // owns, which no reference covers; the write is volatile so that it is
    // made, and faults, here.
    unsafe { std::ptr::write_volatile(va as *mut u8, 1) };
    match VERDICT.load(Ordering::Acquire)
    {
        HANDLED => exit(0),
        0 => exit(CHILD_TOUCH_NOT_FORWARDED),
        code => exit(code),
    }
}

/// The child's own usage from memmgr's `QUERY_MEMORY_USAGE`, in pages:
/// `(own, max, subtree)`; `None` when the call fails or is refused.
pub(crate) fn memory_usage() -> Option<(u64, u64, u64)>
{
    let req = ipc::IpcMessage::new(ipc::memmgr_labels::QUERY_MEMORY_USAGE);
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call(
            startup_info().memmgr_endpoint,
            &req,
            std::os::seraph::current_ipc_buf(),
        )
    }
    .ok()?;
    (reply.label == ipc::memmgr_errors::SUCCESS)
        .then(|| (reply.word(0), reply.word(1), reply.word(2)))
}

/// Create `/programs/hello` under the child with a max above the child's
/// own, check its node took what the child's node had left (memmgr's clamp,
/// which procmgr relays in the create reply), destroy it unstarted, and wait
/// until its charge has left the child's subtree.
fn grandchild_clamped()
{
    use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
    use std::process::exit;

    let ipc_buf = std::os::seraph::current_ipc_buf();
    let lookup = |dir: u64, name: &[u8]| {
        crate::ipc_util::ns::ns_lookup(dir, name, 0xFFFF, ipc_buf)
            .unwrap_or_else(|_| exit(CHILD_LOOKUP_FAILED))
    };
    let (programs, _, _) = lookup(std::os::seraph::root_dir_cap(), b"programs");
    let (file, _, size) = lookup(programs, b"hello");
    let _ = syscall::cap_delete(programs);
    let Some((_, _, used)) = memory_usage()
    else
    {
        exit(CHILD_USAGE_QUERY_FAILED)
    };
    let reply = create_call(
        startup_info().procmgr_endpoint,
        procmgr_labels::CREATE_FROM_FILE | procmgr_labels::CREATE_MEMORY_MAX,
        &[size, CHILD_MAX_PAGES * 4],
        HELLO_PATH,
        &[file],
    )
    .unwrap_or_else(|_| exit(CHILD_GRANDCHILD_REFUSED));
    let (procmgr_errors::SUCCESS, &[handle, thread]) = (reply.label, reply.caps())
    else
    {
        exit(CHILD_GRANDCHILD_REFUSED)
    };
    let took = reply.word(0);
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let destroyed = unsafe {
        ipc::ipc_call(
            handle,
            &IpcMessage::new(procmgr_labels::DESTROY_PROCESS),
            ipc_buf,
        )
    };
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(handle);
    if !destroyed.is_ok_and(|r| r.label == procmgr_errors::SUCCESS)
    {
        exit(CHILD_GRANDCHILD_REFUSED);
    }
    if CHILD_MAX_PAGES.checked_sub(used) != Some(took)
    {
        exit(CHILD_GRANDCHILD_NOT_CLAMPED);
    }
    for _ in 0..UNCHARGE_POLLS
    {
        crate::phases::memmgr::recheck_deferred();
        match memory_usage()
        {
            Some((own, _, subtree)) if own == subtree => return,
            Some(_) => std::thread::yield_now(),
            None => exit(CHILD_USAGE_QUERY_FAILED),
        }
    }
    exit(CHILD_GRANDCHILD_STILL_CHARGED);
}

/// Set up the touch's handling before the fill: register a one-page demand
/// region, spawn the handler thread on a fresh endpoint and wait until it has
/// touched its stack, then bind the main thread's exception class to the
/// endpoint, so memmgr's forward of the touch's fault reaches the handler.
/// Returns the region's address.
fn arm_handler() -> u64
{
    use std::process::exit;

    let Ok(region) = std::os::seraph::register_demand_paged(1)
    else
    {
        exit(CHILD_SETUP_FAILED)
    };
    let va = region.va_start();
    REGION_VA.store(va, Ordering::Release);
    let Some(endpoint) =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })
    else
    {
        exit(CHILD_SETUP_FAILED)
    };
    let Ok(send) = syscall::cap_derive_badge(endpoint, syscall::RIGHTS_EP_SEND, HANDLER_BADGE)
    else
    {
        exit(CHILD_SETUP_FAILED)
    };
    if std::thread::Builder::new()
        .spawn(move || handler_main(endpoint))
        .is_err()
    {
        exit(CHILD_SETUP_FAILED);
    }
    while !HANDLER_READY.load(Ordering::Acquire)
    {
        std::thread::yield_now();
    }
    if syscall::thread_set_fault_handler(
        std::os::seraph::thread::current_thread_cap(),
        send,
        syscall_abi::FAULT_CLASS_EXCEPTION,
    )
    .is_err()
    {
        exit(CHILD_SETUP_FAILED);
    }
    va
}

/// Take contiguous grants until the child's subtree reaches its max, keeping
/// the first for the handler to return. Each grant asks for
/// [`FILL_GRANT_PAGES`] pages, or what is left under the max, and for half as
/// many after memmgr finds no run so long. A grant refused with `LIMIT`
/// before the subtree reaches the max fails the fill.
fn fill_to_max()
{
    use std::process::exit;

    let mut ask = FILL_GRANT_PAGES;
    for _ in 0..FILL_MAX_GRANTS
    {
        let Some((own, _, subtree)) = memory_usage()
        else
        {
            exit(CHILD_USAGE_QUERY_FAILED)
        };
        if subtree >= CHILD_MAX_PAGES
        {
            if own != CHILD_MAX_PAGES || subtree != CHILD_MAX_PAGES
            {
                exit(CHILD_FILL_NOT_AT_MAX);
            }
            return;
        }
        let pages = ask.min(CHILD_MAX_PAGES.saturating_sub(subtree));
        let Ok(pages) = u32::try_from(pages)
        else
        {
            exit(CHILD_FILL_FAILED)
        };
        match crate::phases::memmgr::try_request_contiguous(pages)
        {
            Ok((cap, region_id)) =>
            {
                if FIRST_GRANT_CAP.load(Ordering::Relaxed) == 0
                {
                    FIRST_GRANT_REGION.store(region_id, Ordering::Relaxed);
                    FIRST_GRANT_CAP.store(cap, Ordering::Release);
                }
            }
            Err(label) if label != ipc::memmgr_errors::LIMIT && ask > 1 => ask /= 2,
            Err(_) => exit(CHILD_FILL_FAILED),
        }
    }
    exit(CHILD_FILL_FAILED);
}

/// Write `HANDLER_STACK_TOUCH` bytes of the calling thread's stack, so that
/// memmgr backs them now.
#[inline(never)]
fn touch_stack()
{
    let mut pad = [0u8; HANDLER_STACK_TOUCH];
    pad.fill(1);
    std::hint::black_box(&mut pad);
}

/// The handler thread: receive the faults the main thread's exception class
/// is bound to `endpoint` for. The first, the touch's, must be the region's
/// page forwarded by memmgr with decline 10; the handler records its verdict,
/// returns the fill's first grant so that memmgr can back the page, and
/// resumes the main thread, which reads the verdict. A later fault is
/// declined, so a touch memmgr declines again ends the child.
fn handler_main(endpoint: u64)
{
    use syscall_abi::{
        FAULT_FORWARD_REASON_WORD, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_KILL,
        FAULT_REPLY_RESUME, PAGE_SIZE,
    };

    touch_stack();
    HANDLER_READY.store(true, Ordering::Release);
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut first = true;
    loop
    {
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let Ok(fault) = (unsafe { ipc::ipc_recv(endpoint, ipc_buf) })
        else
        {
            return;
        };
        let disposition = if first
        {
            first = false;
            let page = REGION_VA.load(Ordering::Acquire);
            let touch = fault.label == FAULT_LABEL
                && fault.word(0) == FAULT_KIND_VM
                && fault.word(1) & !(PAGE_SIZE - 1) == page
                && fault.word_count() > FAULT_FORWARD_REASON_WORD
                && fault.word(FAULT_FORWARD_REASON_WORD) & 0xFFFF_FFFF == DECLINE_OVER_MAX;
            let verdict = if !touch
            {
                CHILD_WRONG_FAULT
            }
            else if release_first_grant()
            {
                HANDLED
            }
            else
            {
                CHILD_RELEASE_FAILED
            };
            VERDICT.store(verdict, Ordering::Release);
            FAULT_REPLY_RESUME
        }
        else
        {
            FAULT_REPLY_KILL
        };
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&ipc::IpcMessage::new(disposition), ipc_buf) };
    }
}

/// Return the fill's first grant to memmgr: delete the cap, then release its
/// region, which memmgr pools at once and uncharges. Whether it was released.
fn release_first_grant() -> bool
{
    let cap = FIRST_GRANT_CAP.load(Ordering::Acquire);
    let region_id = FIRST_GRANT_REGION.load(Ordering::Relaxed);
    if cap == 0 || syscall::cap_delete(cap).is_err()
    {
        return false;
    }
    let release = ipc::IpcMessage::builder(ipc::memmgr_labels::RELEASE_MEMORY_CAPS)
        .word(0, 1)
        .word(1, region_id)
        .build();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe {
        ipc::ipc_call(
            startup_info().memmgr_endpoint,
            &release,
            std::os::seraph::current_ipc_buf(),
        )
    }
    .is_ok_and(|reply| reply.label == ipc::memmgr_errors::SUCCESS)
}
