// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/src/live.rs

//! A live core: an ELF core of a process that keeps running, written on a
//! request on crashd's live-core endpoint (`ipc::crashd_labels::LIVE_CORE`)
//! from a procmgr `SNAPSHOT` of the process (services/crashd/docs/operation.md
//! § Live Core; the file is specified in services/crashd/docs/core-format.md).
//!
//! crashd finds the process the request names in procmgr's list and asks
//! procmgr, through its debug authority, for a snapshot charged to the account
//! the requester presents, so the capture's pages are the requester's, not
//! crashd's reserve. procmgr holds the process for the capture alone and
//! records each listed thread's registers as the hold left them; crashd then
//! reads nothing of the process. It attaches the object read-only a window at
//! a time, lays the core out within the per-core budget from the object's
//! layout and thread records, writes it to the core directory as a crash core
//! is written, and releases the object. The whole runs under the dump's bound
//! ([`dump::DUMP_BOUND`]).

use std::fs::File;

use core_file::layout;
use core_file::notes::{self, Auxv, Cause, Process, Thread};
use core_file::snapshot::Snapshot;
use ipc::{
    IpcMessage, crashd_errors, crashd_labels, memmgr_errors, memmgr_labels, procmgr_errors,
    procmgr_labels, procmgr_snapshot, svcmgr_labels,
};
use syscall_abi::{PAGE_SIZE, SyscallError};

use crate::dump::{self, CORE_BYTES_MAX, CORE_THREADS_MAX, EHDR_BYTES, Outcome};
use crate::{Dump, arch, deadline_in, delete_caps, expired, word_at};

/// Pages of the object crashd attaches at once to copy a run's bytes: 64,
/// 256 KiB. Its pages count against crashd's budget node's max while
/// attached (services/memmgr/docs/ipc-interface.md § Label 28:
/// `ATTACH_OBJECT`), so it bounds what a live core holds of crashd's
/// budget besides the layout and the thread records.
const WINDOW_PAGES: u64 = 64;

/// A live core written.
struct Written
{
    /// The process badge.
    process: u64,
    /// The core's file name, its sequence number, and its bytes.
    file: String,
    seq: u64,
    bytes: u64,
    /// Whether the snapshot holds every page it listed.
    complete: bool,
}

/// Why no live core was written, as the reply and the log line give it.
enum Fail
{
    /// No live process carries the name, or it ended before crashd could
    /// check its declarations after the snapshot.
    NotFound,
    /// The process declared that no core of it is written
    /// (`DECLARE_NO_CORE`).
    NoCore,
    /// procmgr refused the snapshot with this label.
    Refused(u64),
    /// The core was not written, for this reason; a `.part` file may remain.
    NotWritten(&'static str),
    /// The bound passed.
    TimedOut,
}

/// Serve the request `msg` from crashd's live-core endpoint and reply to it:
/// write a live core of the process it names when its badge carries the
/// authority, its name block and account are well formed, and `dump` allows
/// a core, then log how it ended. Every cap the request carried is deleted
/// before the reply, the account once procmgr has taken it.
pub fn serve(msg: &IpcMessage, authority: u64, ipc_buf: *mut u64, dump: Dump)
{
    let reply = match check(msg, dump)
    {
        Err(code) =>
        {
            delete_caps(msg.caps());
            IpcMessage::new(code)
        }
        Ok((name, account)) =>
        {
            delete_caps(msg.caps().get(1..).unwrap_or_default());
            let ended = write(&name, account, authority, ipc_buf);
            log(&name, &ended);
            match ended
            {
                Ok(core) => IpcMessage::builder(crashd_errors::SUCCESS)
                    .word(0, core.process)
                    .word(1, core.seq)
                    .word(2, core.bytes)
                    .word(
                        3,
                        u64::from(core.complete) * crashd_labels::LIVE_CORE_COMPLETE,
                    )
                    .build(),
                Err(Fail::NotFound) => IpcMessage::new(crashd_errors::NOT_FOUND),
                Err(Fail::NoCore) => IpcMessage::new(crashd_errors::NO_CORE),
                Err(Fail::Refused(label)) => IpcMessage::builder(crashd_errors::SNAPSHOT_REFUSED)
                    .word(0, label)
                    .build(),
                Err(Fail::NotWritten(_)) => IpcMessage::new(crashd_errors::NOT_WRITTEN),
                Err(Fail::TimedOut) => IpcMessage::new(crashd_errors::TIMED_OUT),
            }
        }
    };
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// The name and the account of a well-formed request crashd may serve now,
/// or the refusal's label.
fn check(msg: &IpcMessage, dump: Dump) -> Result<(Vec<u8>, u64), u64>
{
    if msg.label != crashd_labels::LIVE_CORE
    {
        return Err(crashd_errors::UNKNOWN_OPCODE);
    }
    if msg.badge & crashd_labels::LIVE_CORE_AUTHORITY == 0
    {
        return Err(crashd_errors::UNAUTHORIZED);
    }
    let name = ipc::name_block(msg, 0, svcmgr_labels::NAME_MAX)
        .ok_or(crashd_errors::INVALID_ARGUMENT)?
        .to_vec();
    // The authority carries GRANT, so its holder can pass any cap: only an
    // endpoint SEND goes on to procmgr, which bounds each call on it.
    let account = msg
        .caps()
        .first()
        .copied()
        .filter(|&cap| {
            cap != 0
                && syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS).is_ok_and(|packed| {
                    packed >> 32 == u64::from(syscall::CAP_TAG_ENDPOINT)
                        && packed & syscall::RIGHTS_EP_SEND != 0
                })
        })
        .ok_or(crashd_errors::INVALID_ARGUMENT)?;
    // A core's buffers and file writes need pages: none while memory is
    // critical, as for a crash core.
    let critical = dump == Dump::MemoryCritical
        || matches!(
            std::os::seraph::memory_pressure(),
            Some(std::os::seraph::MemoryPressure::Critical)
        );
    if critical
    {
        return Err(crashd_errors::MEMORY_CRITICAL);
    }
    Ok((name, account))
}

/// Log how the live core of the process named `name` ended.
fn log(name: &[u8], ended: &Result<Written, Fail>)
{
    let name = String::from_utf8_lossy(name);
    crate::bounded(|| match ended
    {
        Ok(core) => std::os::seraph::log!(
            "live core of {name} badge={} written /crash/{} bytes={}{}",
            core.process,
            core.file,
            core.bytes,
            if core.complete { "" } else { " (incomplete)" }
        ),
        Err(Fail::NotFound) =>
        {
            std::os::seraph::log!(warn: "live core of {name} not written: no such process");
        }
        Err(Fail::NoCore) =>
        {
            std::os::seraph::log!(warn: "live core of {name} not written: the process declared no core");
        }
        Err(Fail::Refused(label)) => std::os::seraph::log!(
            warn: "live core of {name} not written: {} (label={label:#x})",
            refusal(*label)
        ),
        Err(Fail::NotWritten(why)) =>
        {
            std::os::seraph::log!(warn: "live core of {name} not written: {why}");
        }
        Err(Fail::TimedOut) =>
        {
            std::os::seraph::log!(warn: "live core of {name} not written: it passed its bound");
        }
    });
}

/// Write a live core of the process named `name`, its snapshot charged to
/// `account`, which this takes, under a call deadline of [`dump::DUMP_BOUND`]
/// of its own. A step that fails because the deadline passed ends
/// [`Fail::TimedOut`].
fn write(name: &[u8], account: u64, authority: u64, ipc_buf: *mut u64) -> Result<Written, Fail>
{
    let (ended, cancelled) =
        std::os::seraph::with_call_deadline(deadline_in(dump::DUMP_BOUND), || {
            let ended = capture(name, account, authority, ipc_buf);
            (ended, expired())
        });
    match ended
    {
        Err(Fail::NotWritten(_) | Fail::NotFound) if cancelled => Err(Fail::TimedOut),
        other => other,
    }
}

/// The live core's steps, in order.
fn capture(name: &[u8], account: u64, authority: u64, ipc_buf: *mut u64) -> Result<Written, Fail>
{
    let (process, listed) = match find_process(name, authority, ipc_buf)
    {
        Ok(found) => found,
        Err(fail) =>
        {
            let _ = syscall::cap_delete(account);
            return Err(fail);
        }
    };
    let object = snapshot(process, account, authority, ipc_buf)?;
    let complete = object.complete;
    let outcome = match read_layout(&object, ipc_buf)
    {
        Ok(layout) => match vet(process, layout.0.load_bias(), authority, ipc_buf)
        {
            Ok(auxv) => write_object(&object, &layout, process, &listed, auxv, ipc_buf),
            Err(fail) =>
            {
                drop(layout);
                object.release(ipc_buf);
                return Err(fail);
            }
        },
        Err(outcome) => outcome,
    };
    object.release(ipc_buf);
    match outcome
    {
        Outcome::Written { name, seq, bytes } => Ok(Written {
            process,
            file: name,
            seq,
            bytes,
            complete,
        }),
        Outcome::Failed(why) => Err(Fail::NotWritten(why)),
        Outcome::Cancelled => Err(Fail::TimedOut),
        Outcome::NotNamed => Err(Fail::NotWritten("the core was not named")),
    }
}

/// The badge and the listed name of the first live process, in badge order,
/// that `name` names: the whole name `LIST_PROCESSES` lists, or its last path
/// component, as the `CORE_DUMP` setting names processes
/// ([`core_file::policy::names`]). Each page is asked for with the time left of
/// the deadline as its timeout, and an interrupted call is sent again; a list
/// is a read, which procmgr may serve twice.
fn find_process(name: &[u8], authority: u64, ipc_buf: *mut u64) -> Result<(u64, Vec<u8>), Fail>
{
    let mut cursor = None;
    loop
    {
        let request = IpcMessage::builder(procmgr_labels::LIST_PROCESSES)
            .word(0, u64::from(cursor.is_some()))
            .word(1, cursor.unwrap_or(0))
            .build();
        let reply = loop
        {
            let left = std::os::seraph::call_time_left();
            // SAFETY: ipc_buf is the registered IPC buffer page.
            match unsafe { ipc::ipc_call_within(authority, &request, ipc_buf, left) }
            {
                Err(e) if e == SyscallError::Interrupted as i64 =>
                {}
                Err(e) if e == SyscallError::WouldBlock as i64 => return Err(Fail::TimedOut),
                Ok(r) if r.label == procmgr_errors::SUCCESS => break r,
                _ => return Err(Fail::NotWritten("the process list was not read")),
            }
        };
        let words = reply.words();
        let count = usize::try_from(words.first().copied().unwrap_or(0)).unwrap_or(0);
        let mut listed = [0u8; svcmgr_labels::NAME_MAX];
        for index in 0..count
        {
            let Some((badge, len)) = procmgr_labels::unpack_list_entry(words, index, &mut listed)
            else
            {
                return Err(Fail::NotWritten("the process list does not decode"));
            };
            let listed = listed.get(..len).unwrap_or_default();
            if core_file::policy::names(name, listed)
            {
                return Ok((badge, listed.to_vec()));
            }
            cursor = Some(badge);
        }
        if count < procmgr_labels::LIST_PROCESSES_PAGE
        {
            return Err(Fail::NotFound);
        }
    }
}

/// The object a `SNAPSHOT` returned: its handle and its pages.
struct Object
{
    handle: u64,
    pages: u64,
    /// Whether no run of its layout is absent.
    complete: bool,
}

impl Object
{
    /// Drop the object (`OBJECT_RELEASE`) and delete its handle, so its
    /// pages go back to the account once no window attaches them.
    fn release(self, ipc_buf: *mut u64)
    {
        // A release the deadline cut off leaves the object to the account's
        // owner: memmgr drops it when the requester exits.
        let msg = IpcMessage::new(memmgr_labels::OBJECT_RELEASE);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe {
            ipc::ipc_call_within(
                self.handle,
                &msg,
                ipc_buf,
                std::os::seraph::call_time_left(),
            )
        };
        let _ = syscall::cap_delete(self.handle);
    }
}

/// Ask procmgr for a snapshot of `process` on `account`, which the call
/// takes.
fn snapshot(process: u64, account: u64, authority: u64, ipc_buf: *mut u64) -> Result<Object, Fail>
{
    let msg = IpcMessage::builder(procmgr_labels::SNAPSHOT)
        .word(0, process)
        .cap(account)
        .build();
    // A snapshot is not asked for twice: a call that failed may have been
    // served, and its object would be charged to the account until the
    // requester exits.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call_within(authority, &msg, ipc_buf, std::os::seraph::call_time_left())
    };
    let _ = syscall::cap_delete(account);
    let reply = match reply
    {
        Ok(reply) => reply,
        Err(e) if e == SyscallError::WouldBlock as i64 => return Err(Fail::TimedOut),
        Err(_) => return Err(Fail::NotWritten("the snapshot call failed")),
    };
    match (reply.label, reply.caps())
    {
        (procmgr_errors::SUCCESS, &[handle]) => Ok(Object {
            handle,
            pages: reply.word(0),
            complete: reply.word(1) & procmgr_snapshot::SNAPSHOT_COMPLETE != 0,
        }),
        (procmgr_errors::SUCCESS, caps) =>
        {
            delete_caps(caps);
            Err(Fail::NotWritten("the snapshot reply carried no object"))
        }
        (procmgr_errors::INVALID_BADGE, caps) =>
        {
            delete_caps(caps);
            Err(Fail::NotFound)
        }
        (code, caps) =>
        {
            delete_caps(caps);
            Err(Fail::Refused(code))
        }
    }
}

/// Why procmgr refused a snapshot, for the log line.
fn refusal(code: u64) -> &'static str
{
    match code
    {
        procmgr_errors::NOT_ATTACHABLE => "the process declared itself undebuggable",
        procmgr_errors::SPACE_HELD => "the process is held by another capture",
        procmgr_errors::OUT_OF_MEMORY => "the account did not fund the snapshot",
        _ => "the snapshot was refused",
    }
}

/// Lay out and write the core of `object`, the snapshot of the process
/// `process` named `name`, whose checked layout `layout` holds, with the
/// auxiliary vector `auxv`.
fn write_object(
    object: &Object,
    layout: &(Snapshot, Window),
    process: u64,
    name: &[u8],
    auxv: Option<Auxv>,
    ipc_buf: *mut u64,
) -> Outcome
{
    let (snap, window) = layout;
    let Ok(records) = snap.threads(window.bytes())
    else
    {
        return Outcome::Failed("the snapshot's thread records do not decode");
    };
    let threads: Vec<Thread<'_>> = records
        .iter()
        .take(CORE_THREADS_MAX)
        .map(|r| Thread {
            // The list index, 0 for the main thread, made nonzero.
            tid: u32::try_from(r.index.saturating_add(1)).unwrap_or(u32::MAX),
            regs: r.regs,
            ext: r.ext,
        })
        .collect();
    // The main thread's instruction first, then each thread's stack: the
    // layout keeps the runs holding them first.
    let first: Vec<u64> = threads
        .first()
        .map(|t| word_at(t.regs, arch::current::IP_OFFSET))
        .into_iter()
        .chain(
            threads
                .iter()
                .map(|t| word_at(t.regs, arch::current::SP_OFFSET)),
        )
        .collect();
    let notes = notes::encode(
        arch::current::MACHINE,
        &Process {
            pid: u32::try_from(process & u64::from(u32::MAX)).unwrap_or(0),
            name,
            cause: Cause::Live,
            auxv,
        },
        &threads,
    );
    let runs: Vec<layout::Run> = snap.runs().collect();
    let Ok(core) = layout::plan(
        arch::current::MACHINE,
        &notes,
        &runs,
        &first,
        CORE_BYTES_MAX,
    )
    else
    {
        return Outcome::Failed("the notes alone exceed the core budget");
    };
    dump::write_core(&core, name, |file| {
        write_loads(file, &core, object, snap, ipc_buf)
    })
}

/// The object's layout, checked, and the window that holds it: its first
/// page, for the header, then all its layout pages.
fn read_layout(object: &Object, ipc_buf: *mut u64) -> Result<(Snapshot, Window), Outcome>
{
    let pages = {
        let head = Window::attach(object, 0, 1, ipc_buf)?;
        ipc::procmgr_snapshot::Header::decode(head.bytes())
            .ok_or(Outcome::Failed("the snapshot's layout does not decode"))?
            .layout_pages
    };
    let layout = Window::attach(object, 0, pages, ipc_buf)?;
    let snap = Snapshot::decode(layout.bytes(), object.pages)
        .map_err(|_| Outcome::Failed("the snapshot's layout does not decode"))?;
    Ok((snap, layout))
}

/// Check, after the capture, that the process `process` allows a core, and
/// read its image's placement for `NT_AUXV` from the ELF header at the load
/// bias `bias` (procmgr's `ATTACH_PROCESS`, then
/// `ipc::read_mem_resident_bounded` through its main thread, as for a crash
/// core: the header lies on the image's shared pages, which the snapshot
/// names but does not hold, and which no process writes without taking a page
/// of its own). A declaration the process made before the capture's hold is
/// always seen here. The caps the attach returns are deleted.
///
/// # Errors
/// [`Fail::NoCore`] when the process declared no core; [`Fail::NotFound`]
/// when it ended before the attach, its declarations then unknown;
/// [`Fail::TimedOut`] when the bound passed first.
fn vet(process: u64, bias: u64, authority: u64, ipc_buf: *mut u64) -> Result<Option<Auxv>, Fail>
{
    let reply = match crate::attach(process, 0, authority, ipc_buf)
    {
        Ok(reply) => reply,
        Err(crate::AttachFailed::Expired) => return Err(Fail::TimedOut),
        Err(crate::AttachFailed::Refused) => return Err(Fail::NotFound),
    };
    let no_core =
        reply.word(procmgr_labels::ATTACH_WORD_FLAGS) & procmgr_labels::ATTACH_FLAG_NO_CORE != 0;
    let auxv = match reply.caps().first()
    {
        Some(&reader) if !no_core =>
        {
            let mut header = [0u8; EHDR_BYTES];
            let mut bound = ipc::ResidentBound::new(&std::os::seraph::call_time_left);
            // SAFETY: ipc_buf is the registered IPC buffer page.
            unsafe {
                ipc::read_mem_resident_bounded(
                    authority,
                    process,
                    reader,
                    bias,
                    &mut header,
                    ipc_buf,
                    &mut bound,
                )
            }
            .ok()
            .and_then(|()| Auxv::from_header(&header, bias))
        }
        _ => None,
    };
    delete_caps(reply.caps());
    if no_core
    {
        return Err(Fail::NoCore);
    }
    Ok(auxv)
}

/// Write the file bytes of each load of `core` to `file`, from the object
/// pages the snapshot holds them in, a window at a time. Loads are in the
/// runs' order, so load `i` is run `i` of the snapshot.
fn write_loads(
    file: &mut File,
    core: &layout::Core,
    object: &Object,
    snap: &Snapshot,
    ipc_buf: *mut u64,
) -> Result<(), Outcome>
{
    for (index, load) in core
        .loads
        .iter()
        .enumerate()
        .filter(|(_, l)| l.file_bytes > 0)
    {
        let Some(base) = snap.object_page(index)
        else
        {
            return Err(Outcome::Failed("a kept run has no bytes in the snapshot"));
        };
        let pages = load.file_bytes / PAGE_SIZE;
        let mut done = 0u64;
        while done < pages
        {
            if expired()
            {
                return Err(Outcome::Cancelled);
            }
            let count = pages.saturating_sub(done).min(WINDOW_PAGES);
            let window = Window::attach(object, base.saturating_add(done), count, ipc_buf)?;
            dump::write_bounded(file, window.bytes())?;
            done = done.saturating_add(count);
        }
    }
    Ok(())
}

/// Pages of the object attached read-only in crashd's space, detached when
/// the value drops.
struct Window
{
    range: Option<std::os::seraph::ReservedRange>,
    pages: u64,
    ipc_buf: *mut u64,
}

impl Window
{
    /// Attach `pages` pages of `object` from object page `first` (none for
    /// `pages` 0), shared and read-only.
    fn attach(object: &Object, first: u64, pages: u64, ipc_buf: *mut u64) -> Result<Self, Outcome>
    {
        let mut window = Self {
            range: None,
            pages: 0,
            ipc_buf,
        };
        if pages == 0
        {
            return Ok(window);
        }
        let range = std::os::seraph::reserve_pages(pages)
            .map_err(|_| Outcome::Failed("no address range for the snapshot"))?;
        let len = pages.saturating_mul(PAGE_SIZE);
        let Ok(handle) = syscall::cap_copy(
            object.handle,
            std::os::seraph::startup_info().self_cspace,
            syscall::RIGHTS_EP_SEND,
        )
        else
        {
            std::os::seraph::unreserve_pages(range);
            return Err(Outcome::Failed("the object handle was not copied"));
        };
        let msg = IpcMessage::builder(memmgr_labels::ATTACH_OBJECT)
            .word(0, range.va_start())
            .word(1, len)
            .word(2, syscall_abi::MAP_READ)
            .word(3, first)
            .word(4, 0)
            .cap(handle)
            .build();
        let memmgr = std::os::seraph::startup_info().memmgr_endpoint;
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let reply = unsafe {
            ipc::ipc_call_within(memmgr, &msg, ipc_buf, std::os::seraph::call_time_left())
        };
        match reply
        {
            Ok(r) if r.label == memmgr_errors::SUCCESS =>
            {
                window.range = Some(range);
                window.pages = pages;
                Ok(window)
            }
            other =>
            {
                // memmgr took the handle copy, or the call never sent it.
                let _ = syscall::cap_delete(handle);
                std::os::seraph::unreserve_pages(range);
                Err(match other
                {
                    Err(e) if e == syscall_abi::SyscallError::WouldBlock as i64 =>
                    {
                        Outcome::Cancelled
                    }
                    _ => Outcome::Failed("the snapshot was not attached"),
                })
            }
        }
    }

    /// The window's bytes.
    fn bytes(&self) -> &[u8]
    {
        let Some(range) = self.range.as_ref()
        else
        {
            return &[];
        };
        let len = usize::try_from(self.pages.saturating_mul(PAGE_SIZE)).unwrap_or(0);
        // SAFETY: the range's `pages` pages are attached read-only to the
        // object, which is immutable and lives while attached; they stay
        // attached while `self` lives, and the slice borrows it.
        unsafe { core::slice::from_raw_parts(range.va_start() as *const u8, len) }
    }
}

impl Drop for Window
{
    fn drop(&mut self)
    {
        let Some(range) = self.range.take()
        else
        {
            return;
        };
        let msg = IpcMessage::builder(memmgr_labels::UNREGISTER_REGION)
            .word(0, range.va_start())
            .word(1, self.pages.saturating_mul(PAGE_SIZE))
            .build();
        let memmgr = std::os::seraph::startup_info().memmgr_endpoint;
        // The detach is not bounded by the dump's deadline: a range left
        // attached would hold the object, and crashd's budget, for good.
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let detached = unsafe { ipc::ipc_call(memmgr, &msg, self.ipc_buf) }
            .is_ok_and(|r| r.label == memmgr_errors::SUCCESS);
        // A range memmgr did not detach stays reserved, so no later
        // reservation lands on an attached page.
        if detached
        {
            std::os::seraph::unreserve_pages(range);
        }
    }
}
