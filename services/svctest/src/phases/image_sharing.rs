// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/image_sharing.rs

//! Image sharing (services/procmgr/README.md § Image Sharing) and a
//! debugger's reach into shared text (memmgr's `MAKE_RESIDENT` and
//! `MAKE_PRIVATE` on an attachment; services/memmgr/docs/ipc-interface.md
//! § Label 21, § Label 30).
//!
//! svctest spawns `image-sharing` children of its own binary, each of which
//! prints its image base and waits for a line on stdin. A text write of a
//! page a default child has run is refused `InvalidState`, since the page is
//! the image object's, which memmgr's own view maps too; the same write is
//! made on a child created with a private image and on a pinned one, whose
//! text is their own. On a text page the default child has not run, which is
//! not present, a plain read fails and `ipc::read_mem_resident` reads
//! svctest's own bytes there. A breakpoint written on another such page is
//! refused `InvalidAddress`, then made after `MAKE_PRIVATE` and read back,
//! while a second default child reads svctest's bytes at the same page, and
//! the original bytes are written back. The free pool is read around the
//! creation of a default child and of a private one; the phase logs what each
//! took and what sharing saved, and checks the shared one took less.

use std::io::{BufRead, BufReader, Write};
use std::os::seraph::process::{ChildExt, CommandExt};
use std::os::seraph::{current_ipc_buf, startup_info};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};

use syscall_abi::{PAGE_SIZE, SyscallError, THREAD_MEM_TEXT};

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "procmgr_image_sharing",
        run: image_sharing_phase,
    }]
}

/// Child-mode dispatch for the argv token this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == CHILD_ROLE
    {
        child_main();
    }
}

/// argv[1] of the child that reports its image base and waits.
const CHILD_ROLE: &str = "image-sharing";

/// The breakpoint written on a page the child has not run: `int3`.
#[cfg(target_arch = "x86_64")]
const BREAK: &[u8] = &[0xCC];
/// The breakpoint written on a page the child has not run: `ebreak`.
#[cfg(target_arch = "riscv64")]
const BREAK: &[u8] = &[0x73, 0x00, 0x10, 0x00];

/// Bytes compared at a page read through `MAKE_RESIDENT`.
const COMPARED: usize = 64;

/// `PT_LOAD` program-header type.
const PT_LOAD: u32 = 1;
/// `PF_X` program-header flag.
const PF_X: u32 = 1;

// lld-synthesized symbol at the ELF header: the image load base.
unsafe extern "C" {
    static __ehdr_start: u8;
}

/// This process's image load base.
fn image_base() -> u64
{
    // Only the linker-synthesized symbol's address is taken, never its value.
    core::ptr::addr_of!(__ehdr_start) as u64
}

/// The whole pages of svctest's largest executable `PT_LOAD` segment, as
/// offsets from the image base, read from its own program headers.
fn text_pages() -> (u64, u64)
{
    let base = image_base();
    // The little-endian field of `len` bytes at `at` from the header.
    let read = |at: u64, len: usize| -> u64 {
        let mut word = [0u8; 8];
        let src = base.wrapping_add(at) as *const u8;
        for (i, byte) in word.iter_mut().take(len).enumerate()
        {
            // SAFETY: every read lies in the image's ELF header or its
            // program headers, which its first load segment maps read-only
            // for the process's lifetime; a byte read needs no alignment.
            *byte = unsafe { core::ptr::read_volatile(src.wrapping_add(i)) };
        }
        u64::from_le_bytes(word)
    };
    let (phoff, phentsize, phnum) = (read(32, 8), read(54, 2), read(56, 2));
    let mut best = (0u64, 0u64);
    for index in 0..phnum
    {
        let at = phoff.saturating_add(index.saturating_mul(phentsize));
        if read(at, 4) != u64::from(PT_LOAD) || read(at.saturating_add(4), 4) & u64::from(PF_X) == 0
        {
            continue;
        }
        let vaddr = read(at.saturating_add(16), 8);
        let memsz = read(at.saturating_add(40), 8);
        let start = vaddr.next_multiple_of(PAGE_SIZE);
        let end = vaddr.saturating_add(memsz) & !(PAGE_SIZE - 1);
        if end.saturating_sub(start) > best.1.saturating_sub(best.0)
        {
            best = (start, end);
        }
    }
    assert!(
        best.1 > best.0,
        "image_sharing: svctest has no executable segment"
    );
    best
}

/// The phase; see the module documentation.
fn image_sharing_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "image_sharing: no debug authority");
    // A page the child runs: its own entry.
    let ran = (child_main as *const () as u64).saturating_sub(image_base()) & !(PAGE_SIZE - 1);

    let first = ImageChild::spawn(Image::Shared, authority);
    assert_eq!(
        first.rewrite(ran),
        Err(SyscallError::InvalidState as i64),
        "image_sharing: a text write to a shared page the child ran"
    );
    let patched = untouched_text(&first, authority);

    // The second child's page is the object's, unchanged; the measured
    // creation is its own.
    let pool = free_bytes();
    let second = ImageChild::spawn(Image::Shared, authority);
    let shared_cost = pool.saturating_sub(free_bytes());
    let mut theirs = [0u8; COMPARED];
    second.read_resident(authority, patched, &mut theirs);
    assert_eq!(
        theirs,
        own_bytes(patched),
        "image_sharing: another child's page under the breakpoint"
    );
    let original = own_bytes(patched);
    let original = original.get(..BREAK.len()).expect("the breakpoint fits");
    assert_eq!(
        first.text_write(patched, original),
        Ok(()),
        "image_sharing: writing the original bytes back"
    );

    let pool = free_bytes();
    let private = ImageChild::spawn(Image::Private, authority);
    let private_cost = pool.saturating_sub(free_bytes());
    let pinned = ImageChild::spawn(Image::Pinned, authority);
    for (child, what) in [(&private, "a private image"), (&pinned, "a pinned child")]
    {
        assert_eq!(
            child.rewrite(ran),
            Ok(()),
            "image_sharing: a text write to {what}"
        );
    }
    std::os::seraph::log!(
        "image_sharing: a shared instance took {} KiB, a private one {} KiB; sharing saved {} KiB",
        shared_cost / 1024,
        private_cost / 1024,
        private_cost.saturating_sub(shared_cost) / 1024
    );
    assert!(
        shared_cost < private_cost,
        "image_sharing: a shared instance took {shared_cost} bytes, a private one {private_cost}"
    );
    for child in [first, second, private, pinned]
    {
        child.finish();
    }
    std::os::seraph::log!("procmgr_image_sharing phase passed");
}

/// The default child `first`'s text it has not run: a page of it that is
/// not present reads svctest's own bytes through `MAKE_RESIDENT` and is
/// present after; a breakpoint on another such page is refused
/// `InvalidAddress`, then made after `MAKE_PRIVATE` and read back. Returns
/// the breakpoint's offset.
fn untouched_text(first: &ImageChild, authority: u64) -> u64
{
    let text = text_pages();
    let unread = first
        .absent_page(text)
        .expect("image_sharing: every text page of the child is present");
    let mut bytes = [0u8; COMPARED];
    first.read_resident(authority, unread, &mut bytes);
    assert_eq!(
        bytes,
        own_bytes(unread),
        "image_sharing: the child's untouched text read through MAKE_RESIDENT"
    );
    let mut again = [0u8; 1];
    first.read(unread, &mut again);

    let patched = first
        .absent_page(text)
        .expect("image_sharing: no other text page of the child is absent");
    assert_eq!(
        first.text_write(patched, BREAK),
        Err(SyscallError::InvalidAddress as i64),
        "image_sharing: a text write to a page the child has not touched"
    );
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let private = unsafe {
        ipc::make_private(
            authority,
            first.process,
            first.at(patched),
            PAGE_SIZE,
            current_ipc_buf(),
        )
    };
    assert!(
        private,
        "image_sharing: MAKE_PRIVATE of an untouched text page failed"
    );
    assert_eq!(
        first.text_write(patched, BREAK),
        Ok(()),
        "image_sharing: a text write to the page MAKE_PRIVATE copied"
    );
    let mut back = [0u8; 4];
    let back = back
        .get_mut(..BREAK.len())
        .expect("the breakpoint fits the buffer");
    first.read(patched, back);
    assert_eq!(&*back, BREAK, "image_sharing: the breakpoint reads back");
    patched
}

/// svctest's own first [`COMPARED`] bytes at `offset` from its image base,
/// which a child of the same binary holds at the same offset.
fn own_bytes(offset: u64) -> [u8; COMPARED]
{
    let mut bytes = [0u8; COMPARED];
    let src = image_base().wrapping_add(offset) as *const u8;
    for (i, byte) in bytes.iter_mut().enumerate()
    {
        // SAFETY: `offset` lies in svctest's executable segment, mapped
        // readable for the process's lifetime.
        *byte = unsafe { core::ptr::read_volatile(src.wrapping_add(i)) };
    }
    bytes
}

/// memmgr's free-pool bytes (`QUERY_POOL_STATUS` word 3).
fn free_bytes() -> u64
{
    let req = ipc::IpcMessage::new(ipc::memmgr_labels::QUERY_POOL_STATUS);
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(startup_info().memmgr_endpoint, &req, current_ipc_buf()) }
        .expect("image_sharing: QUERY_POOL_STATUS failed");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "image_sharing: QUERY_POOL_STATUS status"
    );
    reply.word(3)
}

/// How a child's image is loaded.
#[derive(Clone, Copy)]
enum Image
{
    /// The default: demand-paged, its text and read-only data shared.
    Shared,
    /// Created with `CommandExt::private_image`.
    Private,
    /// Created pinned, which shares nothing.
    Pinned,
}

/// An `image-sharing` child and its pipes.
struct ImageChild
{
    child: Child,
    stdin: ChildStdin,
    /// Its image base.
    base: u64,
    /// Its main thread.
    thread: u64,
    /// Its procmgr badge.
    process: u64,
}

impl ImageChild
{
    /// Spawn an `image-sharing` child, read its ready line, and find its
    /// badge among those `LIST_PROCESSES` lists over `authority`.
    /// Boxed: the child's handle is too large for the phase to hold four
    /// on its stack.
    fn spawn(image: Image, authority: u64) -> Box<Self>
    {
        let before = super::swap::listed_badges(authority);
        let mut command = std::process::Command::new("/tests/svctest");
        command
            .arg(CHILD_ROLE)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        match image
        {
            Image::Shared =>
            {}
            Image::Private =>
            {
                command.private_image(true);
            }
            Image::Pinned =>
            {
                command.pinned(true);
            }
        }
        let mut child = command
            .spawn()
            .expect("image_sharing: spawning the child failed");
        let stdin = child.stdin.take().expect("the child's stdin is piped");
        let mut stdout = BufReader::<ChildStdout>::new(
            child.stdout.take().expect("the child's stdout is piped"),
        );
        let mut line = String::new();
        let read = stdout.read_line(&mut line);
        let Some(base) = line
            .trim()
            .strip_prefix("ready ")
            .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            .filter(|_| read.is_ok())
        else
        {
            let status = child.wait();
            panic!("image_sharing: the child printed {line:?}, then exited {status:?}")
        };
        let new: Vec<u64> = super::swap::listed_badges(authority)
            .into_iter()
            .filter(|badge| !before.contains(badge))
            .collect();
        let [process] = new[..]
        else
        {
            panic!("image_sharing: LIST_PROCESSES lists {new:#x?} as new since the spawn");
        };
        let thread = child.main_thread_cap();
        Box::new(Self {
            child,
            stdin,
            base,
            thread,
            process,
        })
    }

    /// The child's address at `offset` from its image base.
    fn at(&self, offset: u64) -> u64
    {
        self.base.wrapping_add(offset)
    }

    /// Read `buf` at `offset` with a plain read, which needs the page
    /// present.
    fn read(&self, offset: u64, buf: &mut [u8])
    {
        syscall::thread_read_mem(self.thread, self.at(offset), buf)
            .expect("image_sharing: a plain read of a present page failed");
    }

    /// Write `bytes` at `offset` of the child's text, through the kernel's
    /// text route.
    fn text_write(&self, offset: u64, bytes: &[u8]) -> Result<(), i64>
    {
        // SAFETY: the write lands in the child's address space, not svctest's.
        unsafe { syscall::thread_write_mem(self.thread, self.at(offset), bytes, THREAD_MEM_TEXT) }
    }

    /// Write the bytes at `offset` back unchanged, through the text route.
    fn rewrite(&self, offset: u64) -> Result<(), i64>
    {
        let mut saved = [0u8; 4];
        self.read(offset, &mut saved);
        self.text_write(offset, &saved)
    }

    /// Read `buf` at `offset` through procmgr, which has memmgr map a page
    /// that is not present (`ipc::read_mem_resident`).
    fn read_resident(&self, authority: u64, offset: u64, buf: &mut [u8])
    {
        // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
        let read = unsafe {
            ipc::read_mem_resident(
                authority,
                self.process,
                self.thread,
                self.at(offset),
                buf,
                current_ipc_buf(),
            )
        };
        assert_eq!(read, Ok(()), "image_sharing: a read through MAKE_RESIDENT");
    }

    /// The offset of the highest page of `text` that is not present in the
    /// child: one a plain read of fails.
    fn absent_page(&self, text: (u64, u64)) -> Option<u64>
    {
        let mut byte = [0u8; 1];
        let mut offset = text.1;
        while offset > text.0
        {
            offset = offset.saturating_sub(PAGE_SIZE);
            if syscall::thread_read_mem(self.thread, self.at(offset), &mut byte).is_err()
            {
                return Some(offset);
            }
        }
        None
    }

    /// Tell the child to exit and check it exited 0.
    fn finish(mut self: Box<Self>)
    {
        let _ = self
            .stdin
            .write_all(b"exit\n")
            .and_then(|()| self.stdin.flush());
        let status = self
            .child
            .wait()
            .expect("image_sharing: waiting for the child failed");
        assert!(status.success(), "image_sharing: a child exited {status}");
    }
}

/// An `image-sharing` child: print `ready <image base>` and exit 0 once a
/// line arrives on stdin.
fn child_main() -> !
{
    println!("ready {:x}", image_base());
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    std::process::exit(0)
}
