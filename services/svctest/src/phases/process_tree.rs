// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/process_tree.rs

//! procmgr's process tree (`services/procmgr/docs/ipc-interface.md`
//! § Process Tree): the parent of each process, the destroy of a process
//! with every process below it, the re-parenting of the children of a
//! process that ends, a destroy that follows an end, containment, `LIST_CHILDREN` and `DESTROY_CHILD`, and
//! the one post of each end to the death relay and the end queue.
//!
//! The phases build their trees with raw creates: a create sent on a child's
//! process handle makes a child of that child, so svctest holds the handle,
//! and the death relay, of every process of the tree. Hosts the child-mode
//! entries `end_queue_child_main` (spawned by `end_queue_phase`) and
//! `exit_fault_child_main` (spawned by `end_posted_once_phase`).

use std::os::seraph::process::ChildExt;
use std::os::seraph::startup_info;
use std::sync::atomic::{AtomicBool, Ordering};

use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use syscall::{EXIT_FAULT_BASE, EXIT_KILLED};

use crate::bootstrap::Caps;
use crate::phases::procmgr::{SPAWN_TARGET_PATH, create_call, spawn_target_file};
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "process_tree_destroy",
            run: subtree_destroy_phase,
        },
        Phase {
            name: "process_tree_destroy_child",
            run: destroy_child_phase,
        },
        Phase {
            name: "process_tree_reparent",
            run: reparent_phase,
        },
        Phase {
            name: "process_tree_destroy_after_end",
            run: destroy_after_end_phase,
        },
        Phase {
            name: "process_tree_contain",
            run: contain_phase,
        },
        Phase {
            name: "process_tree_end_queue",
            run: end_queue_phase,
        },
        Phase {
            name: "process_tree_end_posted_once",
            run: end_posted_once_phase,
        },
    ]
}

/// Child-mode dispatch for argv tokens this module owns. A matching arm
/// diverges: the child exits, faults, or parks until its spawner destroys
/// it. On a miss control returns.
pub fn reentry_main(role: &str)
{
    if role == END_QUEUE_ROLE
    {
        end_queue_child_main();
    }
    if role == EXIT_FAULT_ROLE
    {
        exit_fault_child_main();
    }
}

/// Entries the queue behind each death relay and end queue holds: one post
/// is expected, and room for a second lets a duplicate show.
const QUEUE_CAPACITY: u32 = 2;

/// How long a phase waits for an end it expects to be posted. A test wait
/// bound: it limits only how long the phase waits before it fails.
const POST_TIMEOUT_MS: u64 = 10_000;

/// How long a phase waits, after the post it expects, for a second post or
/// a post it does not expect. procmgr makes every post of one end at that
/// end's one teardown, and the expected post has already arrived, so this
/// only guards against a post that should not exist.
const QUIET_MS: u64 = 100;

/// Exit reason of a `/tests/fixtures/programs/spawn-target` that runs to its end.
const SPAWN_TARGET_EXIT_REASON: u64 = 0;

/// Call `target` with `msg` and return the reply.
fn call(target: u64, msg: &IpcMessage, what: &str) -> IpcMessage
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(target, msg, std::os::seraph::current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("process_tree: {what}: ipc_call failed ({e})"))
}

/// Call `target` with `msg` and assert procmgr replies `want`.
fn expect_reply(target: u64, msg: &IpcMessage, want: u64, what: &str)
{
    let reply = call(target, msg, what);
    assert_eq!(
        reply.label, want,
        "process_tree: {what}: procmgr replied {}",
        reply.label
    );
}

/// A fresh event queue with room for [`QUEUE_CAPACITY`] entries.
fn new_queue() -> u64
{
    std::os::seraph::object_slab_retype(
        syscall_abi::event_queue_retype_bytes(u64::from(QUEUE_CAPACITY), 0),
        |slab| syscall::event_queue_create(slab, QUEUE_CAPACITY).ok(),
    )
    .expect("process_tree: event queue creation failed")
}

/// A `POST` copy of `queue`, to hand procmgr as a death relay or an end
/// queue.
fn post_cap(queue: u64) -> u64
{
    syscall::cap_derive(queue, syscall::RIGHTS_EQ_POST)
        .expect("process_tree: deriving a POST cap on a queue failed")
}

/// The next entry posted to `queue`, the end of `what`; panics when none
/// arrives within [`POST_TIMEOUT_MS`].
fn await_entry(queue: u64, what: &str) -> syscall::EventEntry
{
    syscall::event_recv_entry(queue, POST_TIMEOUT_MS)
        .unwrap_or_else(|e| panic!("process_tree: no end of {what} was posted ({e})"))
}

/// Assert `queue` receives no entry within [`QUIET_MS`].
fn expect_no_post(queue: u64, what: &str)
{
    if let Ok(entry) = syscall::event_recv_entry(queue, QUIET_MS)
    {
        panic!(
            "process_tree: {what}: {:#x} was posted (tag {:#x})",
            entry.payload, entry.tag
        );
    }
}

/// Assert the relay `queue` receives the end of `what` once, as `reason`.
fn expect_one_post(queue: u64, reason: u64, what: &str)
{
    let posted = await_entry(queue, what).payload;
    assert_eq!(
        posted, reason,
        "process_tree: the end of {what} was posted as {posted:#x}, not {reason:#x}"
    );
    expect_no_post(queue, &format!("a second end of {what}"));
}

/// One process a phase created: its process handle, its main thread's cap,
/// and the queue its death relay posts to.
struct Node
{
    handle: u64,
    thread: u64,
    relay: u64,
}

impl Node
{
    /// Delete the caps svctest holds for the process.
    fn release(self)
    {
        for cap in [self.thread, self.handle, self.relay]
        {
            let _ = syscall::cap_delete(cap);
        }
    }
}

/// Create a process with a raw `CREATE_FROM_FILE` sent on `on`: svctest's
/// own procmgr cap, which makes a child of svctest, or the process handle of
/// the process that is to be its parent. The process runs `/tests/fixtures/programs/spawn-target`,
/// or `/tests/svctest <role>` when `role` is given; the create carries
/// `flags` and a death relay on a fresh queue. Not started.
fn create(on: u64, role: Option<&str>, flags: u64, what: &str) -> Node
{
    use std::os::seraph::process::ArgvEnvCap;

    let relay = new_queue();
    let reply = match role
    {
        None =>
        {
            let (file, size) = spawn_target_file();
            create_call(
                on,
                procmgr_labels::CREATE_FROM_FILE | procmgr_labels::CREATE_DEATH_RELAY | flags,
                &[size],
                SPAWN_TARGET_PATH,
                &[file, post_cap(relay)],
            )
        }
        Some(role) =>
        {
            let args = format!("/tests/svctest\0{role}\0");
            let argv_env = ArgvEnvCap::new(args.as_bytes(), 2, b"", 0)
                .unwrap_or_else(|e| panic!("process_tree: argv/env cap of {what} ({e:?})"))
                .expect("a nonempty argv builds a cap");
            let (file, size) = svctest_file();
            let mut words = vec![size];
            words.extend(argv_env.header_words());
            let reply = create_call(
                on,
                procmgr_labels::CREATE_FROM_FILE
                    | procmgr_labels::CREATE_ARGV_ENV
                    | procmgr_labels::CREATE_DEATH_RELAY
                    | flags,
                &words,
                "/tests/svctest",
                &[file, argv_env.cap(), post_cap(relay)],
            );
            argv_env.settle(reply.as_ref().map_or(0, |r| r.label));
            reply
        }
    };
    let reply = reply.unwrap_or_else(|e| panic!("process_tree: creating {what} failed ({e})"));
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "process_tree: procmgr refused to create {what}"
    );
    match reply.caps()
    {
        &[handle, thread] => Node {
            handle,
            thread,
            relay,
        },
        other => panic!(
            "process_tree: the create of {what} replied {} caps",
            other.len()
        ),
    }
}

/// The file cap and size of `/tests/svctest`.
fn svctest_file() -> (u64, u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let root = std::os::seraph::root_dir_cap();
    let (tests, _, _) = crate::ipc_util::ns::ns_lookup(root, b"tests", 0xFFFF, ipc_buf)
        .expect("process_tree: ns_lookup /tests failed");
    let (file, _, size) = crate::ipc_util::ns::ns_lookup(tests, b"svctest", 0xFFFF, ipc_buf)
        .expect("process_tree: ns_lookup /tests/svctest failed");
    let _ = syscall::cap_delete(tests);
    (file, size)
}

/// `DESTROY_PROCESS` on `handle`, which procmgr answers `SUCCESS` whether
/// or not the process still lives.
fn destroy(handle: u64, what: &str)
{
    expect_reply(
        handle,
        &IpcMessage::new(procmgr_labels::DESTROY_PROCESS),
        procmgr_errors::SUCCESS,
        &format!("DESTROY_PROCESS of {what}"),
    );
}

/// `LIST_CHILDREN` on `handle`, every page: each child's badge, name and
/// subtree pages, in ascending badge order.
fn list_children(handle: u64, what: &str) -> Vec<(u64, Vec<u8>, u64)>
{
    let mut listed = Vec::new();
    let mut cursor = None;
    loop
    {
        let reply = call(
            handle,
            &IpcMessage::builder(procmgr_labels::LIST_CHILDREN)
                .word(0, u64::from(cursor.is_some()))
                .word(1, cursor.unwrap_or(0))
                .build(),
            "LIST_CHILDREN",
        );
        assert_eq!(
            reply.label,
            procmgr_errors::SUCCESS,
            "process_tree: LIST_CHILDREN of {what} refused"
        );
        let words = reply.words();
        let count = usize::try_from(words.first().copied().unwrap_or(0)).unwrap_or(0);
        let mut name = [0u8; ipc::svcmgr_labels::NAME_MAX];
        for i in 0..count
        {
            let (badge, len, pages) = procmgr_labels::unpack_child_entry(words, i, &mut name)
                .expect("process_tree: a LIST_CHILDREN entry");
            let name = name
                .get(..len)
                .expect("process_tree: a LIST_CHILDREN name within NAME_MAX");
            listed.push((badge, name.to_vec(), pages));
            cursor = Some(badge);
        }
        if count < procmgr_labels::LIST_CHILDREN_PAGE
        {
            return listed;
        }
    }
}

/// The badges `LIST_CHILDREN` lists on `handle`.
fn child_badges(handle: u64, what: &str) -> Vec<u64>
{
    list_children(handle, what)
        .into_iter()
        .map(|(badge, _, _)| badge)
        .collect()
}

/// The badge of the one child `LIST_CHILDREN` lists on `handle`.
fn only_child(handle: u64, what: &str) -> u64
{
    match child_badges(handle, what).as_slice()
    {
        &[badge] => badge,
        other => panic!(
            "process_tree: {what} lists {} children, not one",
            other.len()
        ),
    }
}

/// A `DESTROY_CHILD` request for the child `badge`.
fn destroy_child(badge: u64) -> IpcMessage
{
    IpcMessage::builder(procmgr_labels::DESTROY_CHILD)
        .word(0, badge)
        .build()
}

/// procmgr refuses a create sent on `handle`, whose process a destroy has
/// torn down, as for any badge that names no live process.
fn expect_create_refused(handle: u64, what: &str)
{
    let (file, size) = spawn_target_file();
    crate::phases::procmgr::expect_create(
        handle,
        procmgr_labels::CREATE_FROM_FILE,
        &[size],
        SPAWN_TARGET_PATH,
        &[file],
        procmgr_errors::INVALID_ARGUMENT,
        &format!("a create on the handle of {what}"),
    );
}

/// `DESTROY_PROCESS` destroys a process with every process below it, and
/// nothing else: a root, its child and the child's child, each created on
/// its parent's handle, each post their end to their relay once, as
/// `EXIT_KILLED`, while a sibling of the root posts nothing, and the
/// destroyed processes create nothing more. `LIST_CHILDREN` lists each
/// child with its subtree's pages, and `LIST_CHILDREN` and `DESTROY_CHILD`
/// are refused on any cap but a process handle, `DESTROY_CHILD` of a
/// grandchild, and a `LIST_CHILDREN` cursor mode other than 0 or 1.
pub fn subtree_destroy_phase(_: &Caps)
{
    let procmgr = startup_info().procmgr_endpoint;
    // Never started: their argv gives the root and its child the name
    // LIST_CHILDREN reports, and a test object loads only for a creator that
    // is one.
    let root = create(procmgr, Some(EXIT_FAULT_ROLE), 0, "the root");
    let child = create(root.handle, Some(EXIT_FAULT_ROLE), 0, "the root's child");
    let grandchild = create(child.handle, None, 0, "the root's grandchild");
    let sibling = create(procmgr, None, 0, "the root's sibling");

    let listed = list_children(root.handle, "the root");
    let (child_badge, name, child_pages) = match listed.as_slice()
    {
        [entry] => entry.clone(),
        other => panic!(
            "process_tree: the root lists {} children, not one",
            other.len()
        ),
    };
    assert!(
        name == b"/tests/svctest",
        "process_tree: the root's child is listed as {:?}",
        String::from_utf8_lossy(&name)
    );
    let grandchild_listed = list_children(child.handle, "the root's child");
    let &[(grandchild_badge, _, grandchild_pages)] = grandchild_listed.as_slice()
    else
    {
        panic!("process_tree: the root's child does not list its one child");
    };
    assert!(
        grandchild_pages > 0 && child_pages > grandchild_pages,
        "process_tree: subtree pages: the child's {child_pages}, the grandchild's \
         {grandchild_pages}; the child's subtree holds both images"
    );
    assert_ne!(child_badge, grandchild_badge);

    expect_reply(
        procmgr,
        &destroy_child(child_badge),
        procmgr_errors::UNAUTHORIZED,
        "DESTROY_CHILD on svctest's own procmgr cap",
    );
    expect_reply(
        procmgr,
        &IpcMessage::new(procmgr_labels::LIST_CHILDREN),
        procmgr_errors::UNAUTHORIZED,
        "LIST_CHILDREN on svctest's own procmgr cap",
    );
    expect_reply(
        root.handle,
        &destroy_child(grandchild_badge),
        procmgr_errors::INVALID_BADGE,
        "DESTROY_CHILD of a grandchild",
    );
    expect_reply(
        root.handle,
        &IpcMessage::builder(procmgr_labels::LIST_CHILDREN)
            .word(0, 2)
            .build(),
        procmgr_errors::INVALID_ARGUMENT,
        "LIST_CHILDREN with cursor mode 2",
    );

    destroy(root.handle, "the root");
    expect_one_post(root.relay, EXIT_KILLED, "the destroyed root");
    expect_one_post(child.relay, EXIT_KILLED, "the destroyed root's child");
    expect_one_post(
        grandchild.relay,
        EXIT_KILLED,
        "the destroyed root's grandchild",
    );
    expect_no_post(sibling.relay, "the root's destroy reached its sibling");
    expect_create_refused(grandchild.handle, "the destroyed grandchild");
    expect_reply(
        root.handle,
        &IpcMessage::new(procmgr_labels::LIST_CHILDREN),
        procmgr_errors::INVALID_BADGE,
        "LIST_CHILDREN of the destroyed root",
    );

    destroy(sibling.handle, "the root's sibling");
    expect_one_post(sibling.relay, EXIT_KILLED, "the destroyed sibling");
    for node in [root, child, grandchild, sibling]
    {
        node.release();
    }
    std::os::seraph::log!("process_tree_destroy phase passed");
}

/// `DESTROY_CHILD` destroys the child its badge names with every process
/// below it, on the parent's handle, and leaves the parent and its other
/// children: each destroyed process posts `EXIT_KILLED` to its relay once,
/// the others nothing, and a second `DESTROY_CHILD` of the badge is refused.
pub fn destroy_child_phase(_: &Caps)
{
    let procmgr = startup_info().procmgr_endpoint;
    let parent = create(procmgr, None, 0, "the parent");
    let child = create(parent.handle, None, 0, "the destroyed child");
    let grandchild = create(child.handle, None, 0, "the destroyed child's child");
    let child_badge = only_child(parent.handle, "the parent");
    let kept = create(parent.handle, None, 0, "the parent's other child");
    let kept_badge = child_badges(parent.handle, "the parent")
        .into_iter()
        .find(|&b| b != child_badge)
        .expect("process_tree: the parent does not list its second child");

    expect_reply(
        parent.handle,
        &destroy_child(child_badge),
        procmgr_errors::SUCCESS,
        "DESTROY_CHILD of the parent's child",
    );
    expect_one_post(child.relay, EXIT_KILLED, "the destroyed child");
    expect_one_post(grandchild.relay, EXIT_KILLED, "the destroyed child's child");
    expect_no_post(parent.relay, "DESTROY_CHILD reached the parent");
    expect_no_post(kept.relay, "DESTROY_CHILD reached the parent's other child");
    assert_eq!(
        child_badges(parent.handle, "the parent"),
        [kept_badge],
        "process_tree: the parent lists other than its remaining child"
    );
    expect_reply(
        parent.handle,
        &destroy_child(child_badge),
        procmgr_errors::INVALID_BADGE,
        "DESTROY_CHILD of a child destroyed before",
    );

    destroy(parent.handle, "the parent");
    expect_one_post(parent.relay, EXIT_KILLED, "the destroyed parent");
    expect_one_post(kept.relay, EXIT_KILLED, "the parent's other child");
    for node in [parent, child, grandchild, kept]
    {
        node.release();
    }
    std::os::seraph::log!("process_tree_destroy_child phase passed");
}

/// The children of a process that exits take its parent as theirs: a middle
/// process runs to its exit, which its relay receives once, and its child
/// is then listed under the root. The re-parented child's relay, its
/// creator's, is gone with its creator, so the child's destroy posts nothing
/// to it.
pub fn reparent_phase(_: &Caps)
{
    let procmgr = startup_info().procmgr_endpoint;
    let root = create(procmgr, None, 0, "the root");
    let middle = create(root.handle, None, 0, "the exiting middle process");
    let leaf = create(middle.handle, None, 0, "the middle process's child");
    let leaf_badge = only_child(middle.handle, "the middle process");

    crate::phases::budget::start(middle.handle, "the middle process");
    expect_one_post(
        middle.relay,
        SPAWN_TARGET_EXIT_REASON,
        "the exited middle process",
    );
    assert_eq!(
        child_badges(root.handle, "the root"),
        [leaf_badge],
        "process_tree: the exited process's child is not the root's"
    );
    destroy(leaf.handle, "the re-parented child");
    expect_no_post(
        leaf.relay,
        "the relay of a re-parented child received the child's end",
    );

    destroy(root.handle, "the root");
    expect_one_post(root.relay, EXIT_KILLED, "the destroyed root");
    for node in [root, middle, leaf]
    {
        node.release();
    }
    std::os::seraph::log!("process_tree_reparent phase passed");
}

/// Rounds of [`destroy_after_end_phase`]: each races svctest's destroy
/// against procmgr's reaper for the same end.
const DESTROY_AFTER_END_ROUNDS: usize = 4;

/// A destroy that reaches procmgr after a process has ended, before or after
/// procmgr's reaper takes the end, re-parents its children as the reap does:
/// a middle process runs to its exit, which svctest learns of from its main
/// thread's own death observer and destroys at once, racing the reaper. The
/// middle process's relay receives its exit once, and its child is then
/// listed under the root, its relay given no post.
pub fn destroy_after_end_phase(_: &Caps)
{
    let procmgr = startup_info().procmgr_endpoint;
    for round in 0..DESTROY_AFTER_END_ROUNDS
    {
        let root = create(procmgr, None, 0, "the root");
        let middle = create(root.handle, None, 0, "the ending middle process");
        let leaf = create(middle.handle, None, 0, "the middle process's child");
        let leaf_badge = only_child(middle.handle, "the middle process");

        let observed = std::os::seraph::object_slab_retype(
            syscall_abi::event_queue_retype_bytes(1, 1),
            |slab| syscall::event_queue_create_observed(slab, 1, 1).ok(),
        )
        .expect("process_tree: observed queue creation failed");
        syscall::thread_bind_notification(middle.thread, observed, 0)
            .expect("process_tree: binding the middle process's main thread failed");
        crate::phases::budget::start(middle.handle, "the middle process");
        await_entry(observed, "the middle process's main thread");
        destroy(middle.handle, "the ended middle process");

        expect_one_post(
            middle.relay,
            SPAWN_TARGET_EXIT_REASON,
            "the ended, destroyed middle process",
        );
        assert_eq!(
            child_badges(root.handle, "the root"),
            [leaf_badge],
            "process_tree: round {round}: a destroy after the end took the ended process's child"
        );
        expect_no_post(
            leaf.relay,
            "the relay of a child re-parented by a destroy after its creator's end",
        );

        destroy(root.handle, "the root");
        expect_one_post(root.relay, EXIT_KILLED, "the destroyed root");
        let _ = syscall::cap_delete(observed);
        for node in [root, middle, leaf]
        {
            node.release();
        }
    }
    std::os::seraph::log!("process_tree_destroy_after_end phase passed");
}

/// The end of a process created with `CREATE_CONTAIN` destroys what is left
/// below it: a contained process runs to its exit, its relay receives the
/// exit once, its child and grandchild are destroyed, each posting
/// `EXIT_KILLED` once, and the root lists no child.
pub fn contain_phase(_: &Caps)
{
    let procmgr = startup_info().procmgr_endpoint;
    let root = create(procmgr, None, 0, "the root");
    let contained = create(
        root.handle,
        None,
        procmgr_labels::CREATE_CONTAIN,
        "the contained process",
    );
    let child = create(contained.handle, None, 0, "the contained process's child");
    let grandchild = create(child.handle, None, 0, "the contained process's grandchild");

    crate::phases::budget::start(contained.handle, "the contained process");
    expect_one_post(
        contained.relay,
        SPAWN_TARGET_EXIT_REASON,
        "the exited contained process",
    );
    expect_one_post(child.relay, EXIT_KILLED, "the contained process's child");
    expect_one_post(
        grandchild.relay,
        EXIT_KILLED,
        "the contained process's grandchild",
    );
    assert!(
        child_badges(root.handle, "the root").is_empty(),
        "process_tree: a process below the contained one outlived it"
    );
    expect_create_refused(grandchild.handle, "the destroyed grandchild");

    destroy(root.handle, "the root");
    expect_one_post(root.relay, EXIT_KILLED, "the destroyed root");
    for node in [root, contained, child, grandchild]
    {
        node.release();
    }
    std::os::seraph::log!("process_tree_contain phase passed");
}

/// argv[1] of [`end_queue_child_main`]; argv[2] names how it ends: `exit`,
/// `park` (until its spawner kills it) or `fault` (in a spawned thread).
const END_QUEUE_ROLE: &str = "end-queue-child";

/// The correlator [`end_queue_child_main`] registers its end queue with.
const END_CORRELATOR: u64 = 0xE0D0_C0DE;

/// The code the `exit` mode of [`end_queue_child_main`] exits with.
const END_EXIT_CODE: i32 = 0x2D;

/// Label of the call on which [`end_queue_child_main`] fetches a `POST` cap
/// on its spawner's end queue, through its namespace cap.
const FETCH_QUEUE_LABEL: u64 = 1;

/// Label of the call by which [`end_queue_child_main`] tells its spawner its
/// registrations are done.
const READY_LABEL: u64 = 2;

/// [`end_queue_child_main`] exit codes: fetching a `POST` cap failed;
/// `REGISTER_END_QUEUE` without a cap was not refused; the first
/// registration was refused; the second was not refused with
/// `END_QUEUE_PRESENT`; the ready call failed; the faulting thread did not
/// start.
const END_CHILD_FETCH_FAILED: i32 = 2;
const END_CHILD_NO_CAP_ACCEPTED: i32 = 3;
const END_CHILD_REGISTER_REFUSED: i32 = 4;
const END_CHILD_SECOND_ACCEPTED: i32 = 5;
const END_CHILD_READY_FAILED: i32 = 6;
const END_CHILD_THREAD_FAILED: i32 = 7;

/// Fetch `POST` caps on the spawner's queue through the namespace cap,
/// register one as this process's end queue, check the refusals of a
/// registration without a cap and of a second one, report ready, and end as
/// argv[2] says. Each failed step exits with its code.
fn end_queue_child_main() -> !
{
    use std::process::exit;

    let mode = std::env::args().nth(2).unwrap_or_default();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let spawner = std::os::seraph::root_dir_cap();
    let fetch = || {
        let msg = IpcMessage::new(FETCH_QUEUE_LABEL);
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        unsafe { ipc::ipc_call(spawner, &msg, ipc_buf) }
            .ok()
            .and_then(|reply| reply.caps().first().copied())
            .unwrap_or_else(|| exit(END_CHILD_FETCH_FAILED))
    };
    let procmgr = startup_info().procmgr_endpoint;
    let register = |queue: Option<u64>| {
        let builder =
            IpcMessage::builder(procmgr_labels::REGISTER_END_QUEUE).word(0, END_CORRELATOR);
        let msg = match queue
        {
            Some(queue) => builder.cap(queue).build(),
            None => builder.build(),
        };
        // SAFETY: as above.
        unsafe { ipc::ipc_call(procmgr, &msg, ipc_buf) }.map_or(u64::MAX, |reply| reply.label)
    };
    if register(None) != procmgr_errors::INVALID_ARGUMENT
    {
        exit(END_CHILD_NO_CAP_ACCEPTED);
    }
    if register(Some(fetch())) != procmgr_errors::SUCCESS
    {
        exit(END_CHILD_REGISTER_REFUSED);
    }
    if register(Some(fetch())) != procmgr_errors::END_QUEUE_PRESENT
    {
        exit(END_CHILD_SECOND_ACCEPTED);
    }
    // SAFETY: as above.
    if unsafe { ipc::ipc_call(spawner, &IpcMessage::new(READY_LABEL), ipc_buf) }.is_err()
    {
        exit(END_CHILD_READY_FAILED);
    }
    if mode == "exit"
    {
        exit(END_EXIT_CODE);
    }
    if mode == "fault" && std::thread::Builder::new().spawn(fault_now).is_err()
    {
        exit(END_CHILD_THREAD_FAILED);
    }
    loop
    {
        std::thread::park();
    }
}

/// Take a terminal fault in the calling thread: a write to the null page,
/// which no handler maps.
fn fault_now()
{
    // SAFETY: deliberately invalid: the null write faults, and the fault is
    // terminal for the process.
    unsafe { core::ptr::write_volatile(core::ptr::null_mut::<u8>(), 0x42) };
}

/// Serve [`end_queue_child_main`] on `ep`: answer each fetch with a `POST`
/// cap on `queue`, refuse anything else, and return once the child reports
/// ready. `ready` is set before the reply to the ready call, so it is set
/// before anything the child does after its registrations, its end included.
fn serve_end_queue_child(ep: u64, queue: u64, ready: &AtomicBool)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    loop
    {
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let msg = unsafe { ipc::ipc_recv(ep, ipc_buf) }
            .expect("process_tree: end-queue server: ipc_recv failed");
        for &cap in msg.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        let reply = match msg.label
        {
            FETCH_QUEUE_LABEL => IpcMessage::builder(0).cap(post_cap(queue)).build(),
            READY_LABEL =>
            {
                ready.store(true, Ordering::Release);
                IpcMessage::new(0)
            }
            _ => IpcMessage::new(u64::MAX),
        };
        // SAFETY: as above.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        if msg.label == READY_LABEL
        {
            return;
        }
    }
}

/// Spawn `end_queue_child_main` in `mode` with `queue` its end queue, and
/// return it once its registrations are done.
fn spawn_end_queue_child(mode: &str, queue: u64) -> std::process::Child
{
    use std::os::seraph::process::CommandExt;

    let ep = std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    })
    .expect("process_tree: endpoint creation failed");
    let send = syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND_GRANT)
        .expect("process_tree: deriving the child's SEND failed");
    let ready = std::sync::Arc::new(AtomicBool::new(false));
    let server_ready = std::sync::Arc::clone(&ready);
    let server = std::thread::Builder::new()
        .name("end_queue_server".into())
        .spawn(move || serve_end_queue_child(ep, queue, &server_ready))
        .expect("process_tree: end-queue server spawn failed");
    let mut child = std::process::Command::new("/tests/svctest")
        .arg(END_QUEUE_ROLE)
        .arg(mode)
        .namespace_cap(send)
        .spawn()
        .unwrap_or_else(|e| panic!("process_tree: spawning the {mode} end-queue child: {e}"));
    // The child can end as soon as the server answers its ready call, before
    // the server thread has returned, so an end is early only when the ready
    // flag, set before that answer, is still clear after the end is seen.
    while !ready.load(Ordering::Acquire)
    {
        if let Some(status) = child
            .try_wait()
            .expect("process_tree: try_wait of the end-queue child failed")
        {
            if ready.load(Ordering::Acquire)
            {
                break;
            }
            panic!(
                "process_tree: the {mode} end-queue child exited {status} before it was ready \
                 ({END_CHILD_FETCH_FAILED} = fetch, {END_CHILD_NO_CAP_ACCEPTED} = a register \
                 without a cap accepted, {END_CHILD_REGISTER_REFUSED} = register refused, \
                 {END_CHILD_SECOND_ACCEPTED} = a second register not refused, \
                 {END_CHILD_READY_FAILED} = ready failed)"
            );
        }
        let _ = syscall::thread_yield();
    }
    server
        .join()
        .expect("process_tree: end-queue server panicked");
    let _ = syscall::cap_delete(ep);
    child
}

/// The exit reason `QUERY_PROCESS` reports on `handle`.
fn queried_reason(handle: u64, what: &str) -> u64
{
    let reply = call(
        handle,
        &IpcMessage::new(procmgr_labels::QUERY_PROCESS),
        "QUERY_PROCESS",
    );
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "process_tree: QUERY_PROCESS of {what} refused"
    );
    assert_eq!(
        reply.word(0),
        ipc::procmgr_process_state::EXITED,
        "process_tree: {what} is not reported exited"
    );
    reply.word(1)
}

/// `REGISTER_END_QUEUE`: a process registers an end queue on its own
/// procmgr cap, once; a registration without a cap, a second one, and one
/// sent on a process handle are refused. procmgr posts the process's end to
/// the queue once, with the correlator: its exit reason, `EXIT_KILLED` for
/// a destroy, and for a fault in a spawned thread the fault class, which
/// reaches the spawner's `ExitStatus` through the death relay unchanged
/// and is the reason `QUERY_PROCESS` reports.
pub fn end_queue_phase(_: &Caps)
{
    let queue = new_queue();
    for mode in ["exit", "park", "fault"]
    {
        let mut child = spawn_end_queue_child(mode, queue);
        expect_reply(
            child.process_handle(),
            &IpcMessage::builder(procmgr_labels::REGISTER_END_QUEUE)
                .cap(post_cap(queue))
                .build(),
            procmgr_errors::INVALID_BADGE,
            "REGISTER_END_QUEUE on a process handle",
        );
        if mode == "park"
        {
            child
                .kill()
                .expect("process_tree: killing the parked end-queue child failed");
        }
        let status = child
            .wait()
            .unwrap_or_else(|e| panic!("process_tree: wait of the {mode} child failed: {e}"));
        let code = || {
            status
                .code()
                .and_then(|c| u64::try_from(c).ok())
                .unwrap_or_else(|| panic!("process_tree: the {mode} child's status {status}"))
        };
        let want = match mode
        {
            "exit" =>
            {
                assert_eq!(
                    status.code(),
                    Some(END_EXIT_CODE),
                    "process_tree: the exit child's status"
                );
                code()
            }
            "park" => EXIT_KILLED,
            _ =>
            {
                let code = code();
                assert!(
                    (EXIT_FAULT_BASE..EXIT_KILLED).contains(&code),
                    "process_tree: the faulted child's status {status} is no fault class"
                );
                assert_eq!(
                    queried_reason(child.process_handle(), "the faulted child"),
                    code,
                    "process_tree: the relay's fault class is not the one procmgr records"
                );
                code
            }
        };
        let entry = await_entry(queue, &format!("the {mode} end-queue child"));
        assert_eq!(
            (entry.payload, entry.tag),
            (want, END_CORRELATOR),
            "process_tree: the {mode} child's end queue entry"
        );
        expect_no_post(
            queue,
            &format!("a second end of the {mode} end-queue child"),
        );
    }
    let _ = syscall::cap_delete(queue);
    std::os::seraph::log!("process_tree_end_queue phase passed");
}

/// argv[1] of [`exit_fault_child_main`].
const EXIT_FAULT_ROLE: &str = "exit-fault-child";

/// The code [`exit_fault_child_main`] exits with.
const EXIT_FAULT_CODE: i32 = 0x2F;

/// [`exit_fault_child_main`]'s exit code when its faulting thread did not
/// start.
const EXIT_FAULT_THREAD_FAILED: i32 = 2;

/// Rounds [`end_posted_once_phase`] runs, each a race of its own.
const EXIT_FAULT_ROUNDS: usize = 3;

/// Set by [`exit_fault_child_main`]'s main thread as it exits.
static EXITING: AtomicBool = AtomicBool::new(false);

/// Spawn a thread that waits for the main thread's exit to begin and then
/// faults, and exit: the exit and the fault both end the process, before
/// procmgr tears it down.
fn exit_fault_child_main() -> !
{
    let spawned = std::thread::Builder::new().spawn(|| {
        while !EXITING.load(Ordering::Acquire)
        {
            core::hint::spin_loop();
        }
        fault_now();
    });
    if spawned.is_err()
    {
        std::process::exit(EXIT_FAULT_THREAD_FAILED);
    }
    EXITING.store(true, Ordering::Release);
    std::process::exit(EXIT_FAULT_CODE)
}

/// procmgr posts a process's end to its death relay once, whatever ends it
/// and however many of its threads do: a process whose main thread exits as
/// a spawned thread faults, before procmgr tears it down, posts one end,
/// its exit code or its fault class, whichever procmgr reaped it by.
pub fn end_posted_once_phase(_: &Caps)
{
    let procmgr = startup_info().procmgr_endpoint;
    for round in 0..EXIT_FAULT_ROUNDS
    {
        let what = format!("the exit-and-fault child of round {round}");
        let node = create(procmgr, Some(EXIT_FAULT_ROLE), 0, &what);
        crate::phases::budget::start(node.handle, &what);
        let reason = await_entry(node.relay, &what).payload;
        let exit = u64::try_from(EXIT_FAULT_CODE).expect("the exit code is positive");
        assert!(
            reason == exit || (EXIT_FAULT_BASE..EXIT_KILLED).contains(&reason),
            "process_tree: {what} posted {reason:#x}, neither its exit code nor a fault class"
        );
        expect_no_post(node.relay, &format!("a second end of {what}"));
        std::os::seraph::log!(debug: "{what}: one end posted, {reason:#x}");
        destroy(node.handle, &what);
        expect_no_post(node.relay, &format!("an end of {what} after its destroy"));
        node.release();
    }
    std::os::seraph::log!("process_tree_end_posted_once phase passed");
}
