// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/node_handle.rs

//! Budget node handles: the capabilities memmgr derives to control one budget
//! node (services/memmgr/docs/ipc-interface.md § Node Handles; § Labels 14 to
//! 19).
//!
//! The phase makes a sub-node of svctest's own node (`CREATE_SUB_NODE`) and
//! checks, over its handle, the node labels, the class refusals of both kinds
//! of badge, the clamp of a sub-node's max, the limit event of a max set at the
//! usage, and that a released handle is refused. It then creates a
//! `node-handle-child` ([`node_child_main`]) with `CREATE_NODE_HANDLE`, sets
//! the child's max through the handle while the child runs, and checks that
//! the child's grants stop at it with `LIMIT`, that the limit event arrives,
//! that lowering the max below the usage reclaims nothing and refuses the next
//! grant, and that the handle, and a sub-node's made through it, are refused
//! once the child is gone.

use std::os::seraph::startup_info;
use std::time::{Duration, Instant};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels};

use crate::bootstrap::Caps;
use crate::phases::budget;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "memmgr_node_handles",
        run: node_handles_phase,
    }]
}

/// Child-mode dispatch for the argv token this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == NODE_CHILD_ROLE
    {
        node_child_main();
    }
}

/// argv[1] of the child the phase controls through its node handle.
const NODE_CHILD_ROLE: &str = "node-handle-child";
/// The max of the phase's own sub-node, in pages.
const SUB_NODE_MAX: u64 = 64;
/// Pages the child's max allows above the child's usage before it starts:
/// room for its start-up and for the grants its fill takes.
const CHILD_HEADROOM_PAGES: u64 = 1024;
/// The bits the phase registers for the limit events it waits on.
const LIMIT_BIT: u64 = 1 << 5;
/// How long the phase waits for a limit event, and the child for its max to
/// be lowered. A test wait bound.
const EVENT_WAIT: Duration = Duration::from_secs(60);
/// Polls for a dead child's handle state to go. A test wait bound.
const STATE_POLLS: u32 = 256;
/// `max` word of a node with no max.
const NO_MAX: u64 = u64::MAX;

/// Exit code: a `QUERY_MEMORY_USAGE` call failed or was refused.
const CHILD_USAGE_QUERY_FAILED: i32 = 2;
/// Exit code: the child started with no max on its node.
const CHILD_NO_MAX: i32 = 3;
/// Exit code: a grant under the max failed, or more grants than
/// [`FILL_MAX_GRANTS`] were needed to reach it.
const CHILD_FILL_FAILED: i32 = 4;
/// Exit code: a grant past the max was not refused with `LIMIT`.
const CHILD_NO_LIMIT: i32 = 5;
/// Exit code: the max was not lowered below the usage within [`EVENT_WAIT`].
const CHILD_NOT_LOWERED: i32 = 6;
/// Exit code: a grant under a max lowered below the usage was not refused
/// with `LIMIT`.
const CHILD_NO_LIMIT_LOWERED: i32 = 7;
/// Exit code: the max was not raised back to the usage within [`EVENT_WAIT`].
const CHILD_NOT_RAISED: i32 = 8;

/// Pages of each grant the fill asks for while more are left under the max;
/// halved when memmgr has no contiguous run so long.
const FILL_GRANT_PAGES: u64 = 128;
/// Grants the fill may take before it gives up: far more than the fill
/// needs on any pool that can hold the child.
const FILL_MAX_GRANTS: u32 = 1024;
/// Bytes of stack the child touches before the fill, so that no later call
/// faults a stack page in once the child is at its max.
const CHILD_STACK_TOUCH: usize = 6 * 1024;

/// memmgr's node handles end to end: the phase's own sub-node, then a child's
/// node controlled while the child runs.
fn node_handles_phase(_: &Caps)
{
    own_sub_node();
    child_node();
    shared_sub_node();
    std::os::seraph::log!("memmgr_node_handles phase passed");
}

/// Call `target` with `msg` and return memmgr's reply.
pub(super) fn call(target: u64, msg: &IpcMessage, what: &str) -> IpcMessage
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(target, msg, std::os::seraph::current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("{what}: ipc_call failed ({e})"))
}

/// Call `target` with the label `label` and the words `words`, and assert
/// memmgr replies `want`; the reply.
pub(super) fn expect(target: u64, label: u64, words: &[u64], want: u64, what: &str) -> IpcMessage
{
    let reply = call(
        target,
        &IpcMessage::builder(label).words(0, words).build(),
        what,
    );
    assert_eq!(reply.label, want, "{what}: memmgr replied {}", reply.label);
    reply
}

/// `NODE_QUERY_USAGE` over `handle`: `(own, max, subtree)`.
fn node_usage(handle: u64, what: &str) -> (u64, u64, u64)
{
    let reply = expect(
        handle,
        memmgr_labels::NODE_QUERY_USAGE,
        &[],
        memmgr_errors::SUCCESS,
        what,
    );
    (reply.word(0), reply.word(1), reply.word(2))
}

/// The one cap of a reply that carries a node handle.
pub(super) fn handle_of(reply: &IpcMessage, what: &str) -> u64
{
    match reply.caps()
    {
        &[handle] => handle,
        other => panic!("{what}: memmgr replied {} caps", other.len()),
    }
}

/// A new Notification, and a Notify-only copy of it to register with memmgr.
fn notification() -> (u64, u64)
{
    let sig =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        })
        .expect("Notification retype");
    let notify = syscall::cap_derive(sig, syscall::RIGHTS_NTF_NOTIFY).expect("cap_derive");
    (sig, notify)
}

/// A copy of svctest's own memmgr SEND, which names svctest as the registrant
/// of a limit registration.
fn own_memmgr_send() -> u64
{
    syscall::cap_copy(
        startup_info().memmgr_endpoint,
        startup_info().self_cspace,
        syscall::RIGHTS_EP_SEND,
    )
    .expect("copying svctest's memmgr SEND")
}

/// Register `notify` for the limit event of `handle`'s node with
/// [`LIMIT_BIT`], svctest the registrant.
fn register_limit(handle: u64, notify: u64, what: &str)
{
    let reply = call(
        handle,
        &IpcMessage::builder(memmgr_labels::NODE_REGISTER_LIMIT)
            .word(0, LIMIT_BIT)
            .cap(notify)
            .cap(own_memmgr_send())
            .build(),
        what,
    );
    assert_eq!(
        reply.label,
        memmgr_errors::SUCCESS,
        "{what}: memmgr replied {}",
        reply.label
    );
}

/// Wait up to [`EVENT_WAIT`] for [`LIMIT_BIT`] on `sig`.
fn await_limit(sig: u64, what: &str)
{
    let ms = u64::try_from(EVENT_WAIT.as_millis()).unwrap_or(u64::MAX - 1);
    let bits = syscall::notification_wait_timeout(sig, ms)
        .unwrap_or_else(|e| panic!("{what}: no limit event in {EVENT_WAIT:?} ({e})"));
    assert_eq!(
        bits & LIMIT_BIT,
        LIMIT_BIT,
        "{what}: limit event bits {bits:#x}"
    );
}

/// svctest's own sub-node: its handle serves the node labels and nothing else,
/// svctest's own badge none of them; a sub-node of it takes no more than it
/// has left; a max set at the usage signals the limit event; a released
/// handle is refused.
fn own_sub_node()
{
    let reply = expect(
        startup_info().memmgr_endpoint,
        memmgr_labels::CREATE_SUB_NODE,
        &[SUB_NODE_MAX],
        memmgr_errors::SUCCESS,
        "CREATE_SUB_NODE",
    );
    assert_eq!(reply.word(0), SUB_NODE_MAX, "the sub-node took another max");
    let node = handle_of(&reply, "CREATE_SUB_NODE");
    assert_eq!(
        node_usage(node, "NODE_QUERY_USAGE of the sub-node"),
        (0, SUB_NODE_MAX, 0)
    );
    class_refusals(node);
    let inner = sub_node_clamped(node);
    limit_on_set_max(node);
    // The inner sub-node first, so that the outer's release leaves no handle
    // state of the phase behind.
    release_refused(inner, "the inner sub-node");
    release_refused(node, "the sub-node");
}

/// Each class of label is served only over its own kind of badge: the node
/// labels over the node handle `node`, and no other label over it.
fn class_refusals(node: u64)
{
    let memmgr = startup_info().memmgr_endpoint;
    let unauthorized = memmgr_errors::UNAUTHORIZED;
    for (target, label, word, what) in [
        (
            memmgr,
            memmgr_labels::NODE_QUERY_USAGE,
            0,
            "NODE_QUERY_USAGE over svctest's own badge",
        ),
        (
            memmgr,
            memmgr_labels::NODE_SET_MAX,
            NO_MAX,
            "NODE_SET_MAX over svctest's own badge",
        ),
        (
            node,
            memmgr_labels::QUERY_MEMORY_USAGE,
            0,
            "QUERY_MEMORY_USAGE over a node handle",
        ),
        (
            node,
            memmgr_labels::REQUEST_MEMORY_CAPS,
            1,
            "REQUEST_MEMORY_CAPS over a node handle",
        ),
        (
            node,
            memmgr_labels::CREATE_SUB_NODE,
            1,
            "CREATE_SUB_NODE over a node handle",
        ),
    ]
    {
        expect(target, label, &[word], unauthorized, what);
    }
}

/// A sub-node made under `node` with a max above `node`'s takes what
/// `node` has left; its handle.
fn sub_node_clamped(node: u64) -> u64
{
    let reply = expect(
        node,
        memmgr_labels::NODE_CREATE,
        &[SUB_NODE_MAX.saturating_mul(2)],
        memmgr_errors::SUCCESS,
        "NODE_CREATE",
    );
    assert_eq!(
        reply.word(0),
        SUB_NODE_MAX,
        "NODE_CREATE: the sub-node's max was not clamped to its parent's"
    );
    handle_of(&reply, "NODE_CREATE")
}

/// Zero bits, a missing registrant and a node handle as the registrant are
/// refused; a max set at the usage of the unused node `node` signals its limit
/// event.
fn limit_on_set_max(node: u64)
{
    let (sig, notify) = notification();
    let node_copy = syscall::cap_copy(node, startup_info().self_cspace, syscall::RIGHTS_EP_SEND)
        .expect("copying the sub-node's handle");
    for (bits, registrant, what) in [
        (
            0,
            Some(own_memmgr_send()),
            "NODE_REGISTER_LIMIT with zero bits",
        ),
        (LIMIT_BIT, None, "NODE_REGISTER_LIMIT without a registrant"),
        (
            LIMIT_BIT,
            Some(node_copy),
            "NODE_REGISTER_LIMIT naming a node handle as the registrant",
        ),
    ]
    {
        let spare = syscall::cap_derive(notify, syscall::RIGHTS_NTF_NOTIFY).expect("cap_derive");
        let mut msg = IpcMessage::builder(memmgr_labels::NODE_REGISTER_LIMIT)
            .word(0, bits)
            .cap(spare);
        if let Some(cap) = registrant
        {
            msg = msg.cap(cap);
        }
        let refused = call(node, &msg.build(), what);
        assert_eq!(refused.label, memmgr_errors::INVALID_ARGUMENT, "{what}");
    }
    register_limit(node, notify, "NODE_REGISTER_LIMIT of the sub-node");
    let reply = expect(
        node,
        memmgr_labels::NODE_SET_MAX,
        &[0],
        memmgr_errors::SUCCESS,
        "NODE_SET_MAX to the usage",
    );
    assert_eq!(
        reply.word(0),
        0,
        "NODE_SET_MAX to the usage took another max"
    );
    await_limit(sig, "NODE_SET_MAX to the usage");
    let _ = syscall::cap_delete(sig);
}

/// Release the sub-node handle `handle` (`what`, for the messages), check
/// that it is refused from then on, and delete it.
pub(super) fn release_refused(handle: u64, what: &str)
{
    let reply = call(
        handle,
        &IpcMessage::new(memmgr_labels::NODE_RELEASE),
        "NODE_RELEASE",
    );
    assert_eq!(
        reply.label,
        memmgr_errors::SUCCESS,
        "NODE_RELEASE of {what}: memmgr replied {}",
        reply.label
    );
    let reply = call(
        handle,
        &IpcMessage::new(memmgr_labels::NODE_QUERY_USAGE),
        "NODE_QUERY_USAGE",
    );
    assert_eq!(
        reply.label,
        memmgr_errors::INVALID_ARGUMENT,
        "NODE_QUERY_USAGE of {what} after its release: memmgr replied {}",
        reply.label
    );
    let _ = syscall::cap_delete(handle);
}

/// A child created with `CREATE_NODE_HANDLE`, controlled through its node
/// handle while it runs ([`node_child_main`]).
fn child_node()
{
    let what = "the node-handle child";
    let (process, thread, node) = spawn_node_child(None, what);
    expect(
        node,
        memmgr_labels::NODE_RELEASE,
        &[],
        memmgr_errors::INVALID_ARGUMENT,
        "NODE_RELEASE of a process's own node",
    );
    let (sig, set, inner) = arm_child_node(node);
    budget::start(process, what);
    let own = at_max(node, sig, set);
    lowered_reclaims_nothing(node, sig, own, set);
    finish_node_child(process, thread, what);
    // The child's handle state, and that of the sub-node made through it, went
    // with the child.
    gone_with_child(node, "the child's node");
    gone_with_child(inner, "the child's sub-node");
    let _ = syscall::cap_delete(sig);
}

/// Two children charged to one sub-node of svctest share its budget: the
/// sub-node holds both children's charges, a max set at their usage signals
/// its limit event, and one child's max cannot then grow past what the other
/// left.
fn shared_sub_node()
{
    let reply = expect(
        startup_info().memmgr_endpoint,
        memmgr_labels::CREATE_SUB_NODE,
        &[NO_MAX],
        memmgr_errors::SUCCESS,
        "CREATE_SUB_NODE for the shared children",
    );
    let shared = handle_of(&reply, "CREATE_SUB_NODE for the shared children");
    let a = spawn_node_child(Some(handle_copy(shared)), "shared child A");
    let b = spawn_node_child(Some(handle_copy(shared)), "shared child B");
    let (own, _, subtree) = node_usage(shared, "NODE_QUERY_USAGE of the shared sub-node");
    let (_, _, sub_a) = node_usage(a.2, "NODE_QUERY_USAGE of shared child A");
    let (_, _, sub_b) = node_usage(b.2, "NODE_QUERY_USAGE of shared child B");
    assert_eq!(own, 0, "the shared sub-node was charged directly");
    assert_eq!(
        Some(subtree),
        sub_a.checked_add(sub_b),
        "the shared sub-node does not hold both children's charges"
    );
    let (sig_a, set_a, inner_a) = arm_child_node(a.2);
    let (sig_b, set_b, inner_b) = arm_child_node(b.2);
    budget::start(a.0, "shared child A");
    budget::start(b.0, "shared child B");
    let own_a = at_max(a.2, sig_a, set_a);
    let own_b = at_max(b.2, sig_b, set_b);
    shared_at_max(shared, a.2, set_a, set_b);
    lowered_reclaims_nothing(a.2, sig_a, own_a, set_a);
    lowered_reclaims_nothing(b.2, sig_b, own_b, set_b);
    finish_node_child(a.0, a.1, "shared child A");
    finish_node_child(b.0, b.1, "shared child B");
    for (handle, whose) in [
        (a.2, "shared child A's node"),
        (inner_a, "shared child A's sub-node"),
        (b.2, "shared child B's node"),
        (inner_b, "shared child B's sub-node"),
    ]
    {
        gone_with_child(handle, whose);
    }
    release_refused(shared, "the shared sub-node");
    let _ = syscall::cap_delete(sig_a);
    let _ = syscall::cap_delete(sig_b);
}

/// Both children under the shared sub-node `shared` are at their maxes
/// `set_a` and `set_b`: the sub-node's subtree is their sum, a max set there
/// signals its limit event, and child A's max, through its handle `node_a`,
/// cannot then grow past its usage, the headroom child B took.
fn shared_at_max(shared: u64, node_a: u64, set_a: u64, set_b: u64)
{
    let (_, _, subtree) = node_usage(shared, "NODE_QUERY_USAGE of the full shared sub-node");
    assert_eq!(
        Some(subtree),
        set_a.checked_add(set_b),
        "the shared sub-node's subtree is not both children's usage"
    );
    let (sig, notify) = notification();
    register_limit(shared, notify, "NODE_REGISTER_LIMIT of the shared sub-node");
    let reply = expect(
        shared,
        memmgr_labels::NODE_SET_MAX,
        &[subtree],
        memmgr_errors::SUCCESS,
        "NODE_SET_MAX of the shared sub-node at its usage",
    );
    assert_eq!(
        reply.word(0),
        subtree,
        "the shared sub-node took another max"
    );
    await_limit(sig, "NODE_SET_MAX of the shared sub-node at its usage");
    let reply = expect(
        node_a,
        memmgr_labels::NODE_SET_MAX,
        &[set_a.saturating_add(1)],
        memmgr_errors::SUCCESS,
        "NODE_SET_MAX of shared child A above its usage",
    );
    assert_eq!(
        reply.word(0),
        set_a,
        "shared child A's max grew past what the shared sub-node had left"
    );
    let _ = syscall::cap_delete(sig);
}

/// A copy of the node handle `handle`, for a create to carry.
pub(super) fn handle_copy(handle: u64) -> u64
{
    syscall::cap_copy(handle, startup_info().self_cspace, syscall::RIGHTS_EP_SEND)
        .expect("copying a node handle")
}

/// Create a [`NODE_CHILD_ROLE`] child (`what`, for the messages) with
/// `CREATE_NODE_HANDLE`, charged to the node handle `charge` when given;
/// its process handle, thread and node handle.
fn spawn_node_child(charge: Option<u64>, what: &str) -> (u64, u64, u64)
{
    let reply = budget::create_role(
        NODE_CHILD_ROLE,
        ipc::procmgr_labels::CREATE_NODE_HANDLE,
        None,
        charge,
        what,
    );
    assert_eq!(reply.word(0), NO_MAX, "the node of {what} took a max");
    let &[process, thread, node] = reply.caps()
    else
    {
        panic!(
            "CREATE_FROM_FILE of {what} replied {} caps",
            reply.caps().len()
        )
    };
    (process, thread, node)
}

/// Wait for the [`NODE_CHILD_ROLE`] child `process` (`what`, for the
/// messages) to exit 0, destroy it, and delete its caps.
fn finish_node_child(process: u64, thread: u64, what: &str)
{
    let reason = budget::finish(process, what);
    let _ = syscall::cap_delete(thread);
    let _ = syscall::cap_delete(process);
    assert_eq!(
        reason, 0,
        "{what} exit reason {reason:#x}: {CHILD_USAGE_QUERY_FAILED}=usage query failed, \
         {CHILD_NO_MAX}=started with no max, {CHILD_FILL_FAILED}=a grant under the max failed, \
         {CHILD_NO_LIMIT}=a grant past the max not refused with LIMIT, \
         {CHILD_NOT_LOWERED}=the max never fell below the usage, {CHILD_NO_LIMIT_LOWERED}=a \
         grant under the lowered max not refused with LIMIT, {CHILD_NOT_RAISED}=the max never \
         rose back to the usage, a fault reason=the child was killed"
    );
}

/// Before the child under the node handle `node` starts: register for its
/// limit event, set its max to [`CHILD_HEADROOM_PAGES`] above its usage, and
/// make a sub-node through the handle, which takes what the node has left and
/// belongs to the child's handle state. Returns the Notification, the max
/// set, and the sub-node's handle.
fn arm_child_node(node: u64) -> (u64, u64, u64)
{
    let (_, max, subtree) = node_usage(node, "NODE_QUERY_USAGE of the child's node");
    assert_eq!(max, NO_MAX, "the child's node has a max before one is set");
    let (sig, notify) = notification();
    register_limit(node, notify, "NODE_REGISTER_LIMIT of the child's node");
    let set = subtree.saturating_add(CHILD_HEADROOM_PAGES);
    let reply = expect(
        node,
        memmgr_labels::NODE_SET_MAX,
        &[set],
        memmgr_errors::SUCCESS,
        "NODE_SET_MAX of the child's node",
    );
    assert_eq!(
        reply.word(0),
        set,
        "NODE_SET_MAX of the child's node took another max"
    );
    let reply = expect(
        node,
        memmgr_labels::NODE_CREATE,
        &[set.saturating_mul(4)],
        memmgr_errors::SUCCESS,
        "NODE_CREATE under the child's node",
    );
    let inner = handle_of(&reply, "NODE_CREATE under the child's node");
    let (_, _, used) = node_usage(node, "NODE_QUERY_USAGE of the child's node");
    assert_eq!(
        Some(reply.word(0)),
        set.checked_sub(used),
        "NODE_CREATE under the child's node: max not clamped to what it has left"
    );
    (sig, set, inner)
}

/// The running child fills its node to the max `set`, which signals the
/// limit event on `sig`, and its usage read through the handle `node` is
/// the max; its own usage.
fn at_max(node: u64, sig: u64, set: u64) -> u64
{
    await_limit(sig, "the child's fill to its max");
    let (own, max, subtree) = node_usage(node, "NODE_QUERY_USAGE at the child's max");
    assert_eq!(max, set, "the child's max moved");
    assert_eq!(
        own, set,
        "the child's own charge is not at its max after the fill"
    );
    assert_eq!(
        subtree, set,
        "the child's subtree is not at its max after the fill"
    );
    own
}

/// Lowering the max of the child at its max `set`, its usage `own`, through
/// its handle `node` below the usage reclaims nothing, and signals the limit
/// event on `sig`. The child stays alive, and its handle state with it, until
/// the max is raised back to `set`; the phase raises it after its last read
/// and once a grant the child asked for under the lowered max was refused,
/// which signals the limit event again, so the child cannot miss the lowering.
fn lowered_reclaims_nothing(node: u64, sig: u64, own: u64, set: u64)
{
    // Bits of an event not taken yet (a max set at the usage) may not stand in
    // for the lowering's own. memmgr signals after its reply, and before it
    // takes the next request, so the read below orders every earlier signal
    // ahead of the drain.
    let (_, max, _) = node_usage(node, "NODE_QUERY_USAGE before the lowering");
    assert_eq!(max, set, "the child's max moved before the lowering");
    let _ = syscall::notification_try_wait(sig);
    let lowered = own / 2;
    let reply = expect(
        node,
        memmgr_labels::NODE_SET_MAX,
        &[lowered],
        memmgr_errors::SUCCESS,
        "NODE_SET_MAX below the child's usage",
    );
    assert_eq!(
        reply.word(0),
        lowered,
        "NODE_SET_MAX below the usage took another max"
    );
    await_limit(sig, "NODE_SET_MAX below the child's usage");
    let (after, max, _) = node_usage(node, "NODE_QUERY_USAGE after the lowering");
    assert_eq!(max, lowered, "the lowered max did not hold");
    assert_eq!(after, own, "lowering the child's max reclaimed pages");
    // The child refuses itself a page under the lowered max until the max is
    // raised, so a later event is one of its refused grants: it has seen the
    // lowering.
    await_limit(sig, "the child's grant under the lowered max");
    expect(
        node,
        memmgr_labels::NODE_SET_MAX,
        &[set],
        memmgr_errors::SUCCESS,
        "NODE_SET_MAX back to the child's max",
    );
}

/// The handle `handle` (`whose`, for the messages) is refused within
/// [`STATE_POLLS`] polls of its owner's destroy; then delete it.
fn gone_with_child(handle: u64, whose: &str)
{
    let query = IpcMessage::new(memmgr_labels::NODE_QUERY_USAGE);
    let gone = (0..STATE_POLLS).any(|_| {
        let reply = call(handle, &query, "NODE_QUERY_USAGE after the child's destroy");
        if reply.label == memmgr_errors::INVALID_ARGUMENT
        {
            return true;
        }
        std::thread::yield_now();
        false
    });
    assert!(
        gone,
        "the handle of {whose} still served after the child's destroy"
    );
    let _ = syscall::cap_delete(handle);
}

// ── The node-handle child ────────────────────────────────────────────────────

/// Child role: fill the node whose max the phase set to that max, wait until
/// the phase lowers the max below the usage, and, until the phase raises the
/// max back to the usage, ask for a page and check that it is refused with
/// `LIMIT`; each refusal signals the node's limit event, which tells the
/// phase the child saw the lowering. At the max again, check that one page
/// more is refused with `LIMIT`. Exits 0, or with the step's exit code.
/// Between the fill and the lowering the child charges nothing, so the only
/// limit events of that span are the phase's own.
///
/// No step after the fill allocates from the heap or grows a stack, since
/// memmgr refuses this process every further page.
fn node_child_main() -> !
{
    use std::process::exit;

    touch_stack();
    let max = match budget::memory_usage()
    {
        Some((_, max, _)) if max != NO_MAX => max,
        Some(_) => exit(CHILD_NO_MAX),
        None => exit(CHILD_USAGE_QUERY_FAILED),
    };
    fill_to(max);
    let start = Instant::now();
    while start.elapsed() < EVENT_WAIT
    {
        match budget::memory_usage()
        {
            Some((own, max, _)) if max < own => await_raised(own),
            Some(_) => std::thread::yield_now(),
            None => exit(CHILD_USAGE_QUERY_FAILED),
        }
    }
    exit(CHILD_NOT_LOWERED);
}

/// Until the child's max is back at or above its usage `own`, ask for a page
/// and exit [`CHILD_NO_LIMIT_LOWERED`] unless it is refused with `LIMIT`.
/// Then, at the max, ask for one more and exit 0 if it is refused with
/// `LIMIT`, [`CHILD_NO_LIMIT`] otherwise. Exit [`CHILD_NOT_RAISED`] after
/// [`EVENT_WAIT`].
fn await_raised(own: u64) -> !
{
    use crate::phases::memmgr::try_request_contiguous;
    use std::process::exit;

    let start = Instant::now();
    while start.elapsed() < EVENT_WAIT
    {
        match budget::memory_usage()
        {
            Some((_, max, _)) if max >= own => exit(
                if try_request_contiguous(1) == Err(memmgr_errors::LIMIT)
                {
                    0
                }
                else
                {
                    CHILD_NO_LIMIT
                },
            ),
            Some(_) if try_request_contiguous(1) != Err(memmgr_errors::LIMIT) =>
            {
                exit(CHILD_NO_LIMIT_LOWERED)
            }
            Some(_) => std::thread::yield_now(),
            None => exit(CHILD_USAGE_QUERY_FAILED),
        }
    }
    exit(CHILD_NOT_RAISED);
}

/// Take contiguous grants until the child's subtree reaches `max`. Each
/// grant asks for [`FILL_GRANT_PAGES`] pages, or what is left under the max,
/// and for half as many after memmgr finds no run so long. A grant refused
/// with `LIMIT` before the subtree reaches the max fails the fill.
fn fill_to(max: u64)
{
    use std::process::exit;

    let mut ask = FILL_GRANT_PAGES;
    for _ in 0..FILL_MAX_GRANTS
    {
        let Some((_, _, subtree)) = budget::memory_usage()
        else
        {
            exit(CHILD_USAGE_QUERY_FAILED)
        };
        if subtree >= max
        {
            return;
        }
        let Ok(pages) = u32::try_from(ask.min(max.saturating_sub(subtree)))
        else
        {
            exit(CHILD_FILL_FAILED)
        };
        match crate::phases::memmgr::try_request_contiguous(pages)
        {
            Ok(_) =>
            {}
            Err(label) if label != memmgr_errors::LIMIT && ask > 1 => ask /= 2,
            Err(_) => exit(CHILD_FILL_FAILED),
        }
    }
    exit(CHILD_FILL_FAILED);
}

/// Write [`CHILD_STACK_TOUCH`] bytes of the calling thread's stack, so that
/// memmgr backs them now.
#[inline(never)]
fn touch_stack()
{
    let mut pad = [0u8; CHILD_STACK_TOUCH];
    pad.fill(1);
    std::hint::black_box(&mut pad);
}
