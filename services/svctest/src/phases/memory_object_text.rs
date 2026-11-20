// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/memory_object_text.rs

//! Executable memory objects and `MAKE_PRIVATE` (`memmgr_labels::ATTACH_OBJECT`,
//! procmgr's `procmgr_labels::MAKE_PRIVATE`;
//! services/memmgr/docs/memory-pool.md § Memory objects).
//!
//! svctest seals one page holding a function that returns [`ANSWER`]
//! ([`seal_code`]) and attaches it executable and shared: the call returns
//! the answer. procmgr refuses `MAKE_PRIVATE` without the debug authority,
//! and for svctest, which declared itself undebuggable. A
//! `memory-object-text` child attaches the object the same way and calls it.
//! A breakpoint written over the function through the kernel's text route is
//! refused `InvalidState`, since memmgr's own view maps the object's frame
//! too; after `MAKE_PRIVATE` of the page the write is made, and the child
//! reads the breakpoint back. A second child, attached after it, and svctest
//! still call the object's function, and the patched child dies of the
//! breakpoint. Last svctest detaches and releases the object.

use std::io::{BufRead, BufReader, Write};
use std::os::seraph::process::{ChildExt, CommandExt};
use std::os::seraph::{current_ipc_buf, startup_info};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels};
use syscall_abi::{MAP_EXECUTABLE, MAP_READ, MAP_WRITABLE, PAGE_SIZE, SyscallError};

use crate::bootstrap::Caps;
use crate::phases::memmgr::try_request_contiguous;
use crate::phases::memory_objects::{FETCH_LABEL, STOP_BADGE, call, handle_copy, serve_handle};
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "memmgr_memory_object_text",
        run: memory_object_text_phase,
    }]
}

/// Child-mode dispatch for the argv token this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == TEXT_CHILD_ROLE
    {
        text_child_main();
    }
}

/// argv[1] of the child that attaches the code object and calls it.
const TEXT_CHILD_ROLE: &str = "memory-object-text";

/// What the sealed function returns.
const ANSWER: u32 = 42;

/// The sealed function: `mov eax, 42; ret`.
#[cfg(target_arch = "x86_64")]
const CODE: &[u8] = &[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3];
/// The sealed function: `addi a0, zero, 42; jalr zero, 0(ra)`.
#[cfg(target_arch = "riscv64")]
const CODE: &[u8] = &[0x13, 0x05, 0xA0, 0x02, 0x67, 0x80, 0x00, 0x00];

/// The breakpoint written over the function's first instruction: `int3`.
#[cfg(target_arch = "x86_64")]
const BREAK: &[u8] = &[0xCC];
/// The breakpoint written over the function's first instruction: `ebreak`.
#[cfg(target_arch = "riscv64")]
const BREAK: &[u8] = &[0x73, 0x00, 0x10, 0x00];

/// Exit code of a child that could not fetch the object handle.
const CHILD_FETCH_FAILED: i32 = 2;
/// Exit code of a child whose attachment memmgr refused.
const CHILD_ATTACH_REFUSED: i32 = 3;
/// Exit code of a child whose call returned other than [`ANSWER`].
const CHILD_WRONG_ANSWER: i32 = 4;
/// Exit code of a child that could not read its command line.
const CHILD_NO_COMMAND: i32 = 5;

/// The phase; see the module documentation.
fn memory_object_text_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "memory_object_text: no debug authority");
    let handle = seal_code();
    let own = std::os::seraph::reserve_pages(1).expect("memory_object_text: reserving a page");
    let own_va = own.va_start();
    let got = attach_code(startup_info().memmgr_endpoint, own_va, handle_copy(handle));
    assert_eq!(
        got,
        memmgr_errors::SUCCESS,
        "memory_object_text: svctest's executable attachment replied {got:#x}"
    );
    assert_eq!(
        call_code(own_va),
        ANSWER,
        "memory_object_text: svctest's call of the object"
    );
    make_private_refusals(authority, own_va);

    let before = super::swap::listed_badges(authority);
    let mut patched = TextChild::spawn(handle);
    let va = patched.ready();
    let new: Vec<u64> = super::swap::listed_badges(authority)
        .into_iter()
        .filter(|badge| !before.contains(badge))
        .collect();
    let [process] = new[..]
    else
    {
        panic!("memory_object_text: LIST_PROCESSES lists {new:#x?} as new since the spawn");
    };
    let thread = patched.child.main_thread_cap();
    // SAFETY: the write lands in the child's address space, not svctest's.
    let refused =
        unsafe { syscall::thread_write_mem(thread, va, BREAK, syscall_abi::THREAD_MEM_TEXT) };
    assert_eq!(
        refused,
        Err(SyscallError::InvalidState as i64),
        "memory_object_text: a text write to a shared executable attachment"
    );
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let private =
        unsafe { ipc::make_private(authority, process, va, PAGE_SIZE, current_ipc_buf()) };
    assert!(
        private,
        "memory_object_text: MAKE_PRIVATE of the child's attachment failed"
    );
    // SAFETY: as above.
    let written =
        unsafe { syscall::thread_write_mem(thread, va, BREAK, syscall_abi::THREAD_MEM_TEXT) };
    assert_eq!(
        written,
        Ok(()),
        "memory_object_text: a text write to the attachment's private page"
    );
    let mut back = [0u8; 4];
    let back = back
        .get_mut(..BREAK.len())
        .expect("the breakpoint fits the buffer");
    syscall::thread_read_mem(thread, va, back)
        .expect("memory_object_text: reading the patched page back failed");
    assert_eq!(&*back, BREAK, "memory_object_text: the patched page reads");

    let mut other = TextChild::spawn(handle);
    let _ = other.ready();
    let status = other.finish();
    assert!(
        status.success(),
        "memory_object_text: the child attached after the patch exited {status} (2 = fetch, \
         3 = attach refused, 4 = wrong answer, 5 = no command)"
    );
    assert_eq!(
        call_code(own_va),
        ANSWER,
        "memory_object_text: svctest's call of the object after the patch"
    );
    let status = patched.finish();
    let code = status.code().and_then(|c| u64::try_from(c).ok());
    assert!(
        code.is_some_and(|c| (syscall::EXIT_FAULT_BASE..syscall::EXIT_KILLED).contains(&c)),
        "memory_object_text: the patched child exited {status}, not by its breakpoint \
         (0 = the call returned the answer)"
    );

    super::heap_commit::expect_region_reply(
        memmgr_labels::UNREGISTER_REGION,
        own_va,
        PAGE_SIZE,
        memmgr_errors::SUCCESS,
        "UNREGISTER_REGION of svctest's executable attachment",
    );
    std::os::seraph::unreserve_pages(own);
    let released = call(
        handle,
        &IpcMessage::new(memmgr_labels::OBJECT_RELEASE),
        "OBJECT_RELEASE",
    )
    .label;
    assert_eq!(
        released,
        memmgr_errors::SUCCESS,
        "memory_object_text: OBJECT_RELEASE replied {released:#x}"
    );
    let _ = syscall::cap_delete(handle);
    std::os::seraph::log!("memmgr_memory_object_text phase passed");
}

/// Write [`CODE`] into a one-page grant, unmap it, and seal it; the object
/// handle.
fn seal_code() -> u64
{
    let aspace = startup_info().self_aspace;
    let (cap, id) = try_request_contiguous(1)
        .unwrap_or_else(|l| panic!("memory_object_text: one-page grant status {l:#x}"));
    let range = std::os::seraph::reserve_pages(1).expect("memory_object_text: reserving a page");
    let va = range.va_start();
    // SAFETY: `range` is a fresh reservation owned here, VA no Rust object
    // occupies.
    unsafe { std::os::seraph::mem_map_funded(cap, aspace, va, 0, 1, MAP_READ | MAP_WRITABLE) }
        .expect("memory_object_text: mapping the grant failed");
    for (i, &byte) in CODE.iter().enumerate()
    {
        // SAFETY: the page is the grant's, mapped writable above; no
        // reference points into it.
        unsafe { std::ptr::write_volatile((va as *mut u8).wrapping_add(i), byte) };
    }
    // SAFETY: as above.
    unsafe { syscall::mem_unmap(aspace, va, 1) }.expect("memory_object_text: unmapping the grant");
    std::os::seraph::unreserve_pages(range);
    let reply = call(
        startup_info().memmgr_endpoint,
        &IpcMessage::builder(memmgr_labels::SEAL_OBJECT)
            .word(0, 1)
            .word(1, id)
            .cap(cap)
            .build(),
        "SEAL_OBJECT",
    );
    assert_eq!(
        reply.label,
        memmgr_errors::SUCCESS,
        "memory_object_text: SEAL_OBJECT replied {:#x}",
        reply.label
    );
    *reply
        .caps()
        .first()
        .expect("memory_object_text: SEAL_OBJECT replied no handle")
}

/// `ATTACH_OBJECT` of the code object's one page at `va`, executable and
/// shared, over `memmgr` with the handle `copy` (memmgr deletes it);
/// memmgr's reply label.
fn attach_code(memmgr: u64, va: u64, copy: u64) -> u64
{
    let msg = IpcMessage::builder(memmgr_labels::ATTACH_OBJECT)
        .word(0, va)
        .word(1, PAGE_SIZE)
        .word(2, MAP_READ | MAP_EXECUTABLE)
        .word(3, 0)
        .word(4, 0)
        .cap(copy)
        .build();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(memmgr, &msg, current_ipc_buf()) }.map_or(u64::MAX, |r| r.label)
}

/// Call the function the code object's page holds at `va`.
fn call_code(va: u64) -> u32
{
    // SAFETY: `va` is an executable attachment of the code object, whose
    // page holds [`CODE`], a function of this signature that touches no
    // memory.
    let f: extern "C" fn() -> u32 = unsafe { core::mem::transmute(va as *const ()) };
    f()
}

/// procmgr's refusals of `MAKE_PRIVATE`: `UNAUTHORIZED` over svctest's
/// procmgr cap, which carries no debug authority, and `NOT_ATTACHABLE` for
/// svctest, which declared itself undebuggable. svctest finds its badge as
/// the one process whose name ends in `svctest` that procmgr refuses so: a
/// re-entry child of an earlier phase still listed would accept the request,
/// and has no attachment at `va` for it to change.
fn make_private_refusals(authority: u64, va: u64)
{
    let request = |target: u64, badge: u64| {
        call(
            target,
            &IpcMessage::builder(procmgr_labels::MAKE_PRIVATE)
                .word(0, badge)
                .word(1, va)
                .word(2, PAGE_SIZE)
                .build(),
            "MAKE_PRIVATE",
        )
        .label
    };
    let got = request(startup_info().procmgr_endpoint, 0);
    assert_eq!(
        got,
        procmgr_errors::UNAUTHORIZED,
        "memory_object_text: MAKE_PRIVATE without the debug authority replied {got:#x}"
    );
    let named = core::cell::RefCell::new(Vec::new());
    let _ = super::crash::find_listed(authority, |badge, name| {
        if name.ends_with(b"svctest")
        {
            named.borrow_mut().push(badge);
        }
        false
    });
    let refused = named
        .into_inner()
        .into_iter()
        .filter(|&badge| request(authority, badge) == procmgr_errors::NOT_ATTACHABLE)
        .count();
    assert_eq!(
        refused, 1,
        "memory_object_text: {refused} svctest processes refused NOT_ATTACHABLE, not one"
    );
}

/// A `memory-object-text` child, its handle server, and its pipes.
struct TextChild
{
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    server: std::thread::JoinHandle<()>,
    stop: u64,
    ep: u64,
}

impl TextChild
{
    /// Spawn a `memory-object-text` child with piped stdin and stdout and
    /// a thread that serves it a copy of `handle`.
    fn spawn(handle: u64) -> Self
    {
        let ep =
            std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
                syscall::cap_create_endpoint(slab).ok()
            })
            .expect("memory_object_text: server endpoint creation failed");
        let root = syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND)
            .expect("memory_object_text: root SEND");
        let stop = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND, STOP_BADGE)
            .expect("memory_object_text: stop SEND");
        let copy = handle_copy(handle);
        let server = std::thread::Builder::new()
            .name("memory_object_text_server".into())
            .spawn(move || serve_handle(ep, copy))
            .expect("memory_object_text: server thread spawn failed");
        let mut child = std::process::Command::new("/tests/svctest")
            .arg(TEXT_CHILD_ROLE)
            .namespace_cap(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("memory_object_text: spawning the child failed");
        let stdin = child.stdin.take().expect("the child's stdin is piped");
        let stdout = BufReader::new(child.stdout.take().expect("the child's stdout is piped"));
        Self {
            child,
            stdin,
            stdout,
            server,
            stop,
            ep,
        }
    }

    /// Read the child's ready line; the address of its attachment.
    fn ready(&mut self) -> u64
    {
        let mut line = String::new();
        let read = self.stdout.read_line(&mut line);
        let va = line
            .trim()
            .strip_prefix("ready ")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok());
        if let (Ok(_), Some(va)) = (read, va)
        {
            return va;
        }
        let status = self.child.wait();
        panic!("memory_object_text: the child printed {line:?}, then exited {status:?}")
    }

    /// Tell the child to call the object again, await its exit, and stop its
    /// server; its exit status.
    fn finish(mut self) -> std::process::ExitStatus
    {
        let _ = self
            .stdin
            .write_all(b"call\n")
            .and_then(|()| self.stdin.flush());
        let status = self
            .child
            .wait()
            .expect("memory_object_text: waiting for the child failed");
        // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer.
        let _ = unsafe { ipc::ipc_call(self.stop, &IpcMessage::new(0), current_ipc_buf()) };
        self.server
            .join()
            .expect("memory_object_text: server thread panicked");
        let _ = syscall::cap_delete(self.stop);
        let _ = syscall::cap_delete(self.ep);
        status
    }
}

/// A `memory-object-text` child: fetch the object handle from the spawner
/// (whose endpoint arrives as this process's namespace cap), attach the
/// object executable and shared, call it, print `ready <va>`, and call it
/// again once a line arrives on stdin. Exit codes as the `CHILD_` constants
/// say, 0 when both calls returned [`ANSWER`].
fn text_child_main() -> !
{
    use std::process::exit;

    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let fetched = unsafe {
        ipc::ipc_call(
            std::os::seraph::root_dir_cap(),
            &IpcMessage::new(FETCH_LABEL),
            current_ipc_buf(),
        )
    };
    let Some(&[handle]) = fetched.as_ref().ok().map(IpcMessage::caps)
    else
    {
        exit(CHILD_FETCH_FAILED)
    };
    let range = std::os::seraph::reserve_pages(1).unwrap_or_else(|_| exit(CHILD_ATTACH_REFUSED));
    let va = range.va_start();
    if attach_code(startup_info().memmgr_endpoint, va, handle) != memmgr_errors::SUCCESS
    {
        exit(CHILD_ATTACH_REFUSED);
    }
    if call_code(va) != ANSWER
    {
        exit(CHILD_WRONG_ANSWER);
    }
    println!("ready {va:x}");
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err()
    {
        exit(CHILD_NO_COMMAND);
    }
    if call_code(va) != ANSWER
    {
        exit(CHILD_WRONG_ANSWER);
    }
    exit(0)
}
