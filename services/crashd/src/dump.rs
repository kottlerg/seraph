// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/src/dump.rs

//! The core dump: once the report block is logged, write an ELF core of the
//! faulting process to the core directory, under the dump's own bound, when
//! the `CORE_DUMP` setting names the process and the process did not declare
//! itself on the core path (services/crashd/docs/operation.md § Core Dump;
//! the file is specified in services/crashd/docs/core-format.md).
//!
//! The capture stops every listed thread but the faulting one, reads each
//! held thread's registers and extended state, lists the space's pages,
//! lays the core out within its byte budget, makes room in the directory by
//! deleting the oldest cores, and writes the file under a `.part` name,
//! renamed once complete. The dump runs under a call deadline of its bound
//! (`std::os::seraph::with_call_deadline`): each request it makes, its own
//! and those the runtime makes for it (a file's write, its close as it is
//! dropped), carries the time left as its timeout, and none is sent once the
//! deadline has passed, so the dump ends within the bound whatever the
//! process or the storage path does.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::time::Duration;

use core_file::layout::{self, Run};
use core_file::notes::{self, Auxv, Cause, Process, Thread};
use core_file::policy::Policy;
use core_file::store::{self, Entry, StoreError};
use ipc::{IpcMessage, procmgr_errors, procmgr_labels, svcmgr_labels};
use syscall_abi::{MAX_PAGE_RUNS, MAX_THREAD_MEM_COPY, PAGE_SIZE, PageRun, SyscallError};

use crate::{AttachFailed, arch, attach, deadline_in, expired, word_at};

/// How long one dump may take: the call deadline it runs under, which ends
/// the request it waits in. The faulting thread stays held for its length, so the bound
/// is the most a dump delays the process's teardown. It covers a core of
/// [`CORE_BYTES_MAX`] written at half the slowest rate measured through the
/// FAT driver, about 75 KB/s under QEMU, one page per write
/// (services/crashd/docs/operation.md § Bounds).
pub const DUMP_BOUND: Duration = Duration::from_secs(60);

/// Most bytes of one core: its head (headers and notes) and the page runs
/// it keeps, sized to what [`DUMP_BOUND`] writes.
pub const CORE_BYTES_MAX: u64 = 2 << 20;

/// Most bytes of the cores the directory holds together; the oldest are
/// deleted until a new core fits.
pub const CORE_DIR_BYTES_MAX: u64 = 64 << 20;

/// Most threads a core records: the faulting thread, then the others in
/// list order. Each listed thread is stopped whether or not it is recorded.
pub const CORE_THREADS_MAX: usize = 256;

/// The core directory, the root of crashd's namespace (its recipe's
/// `subtree:/crash`).
const CORE_DIR: &str = "/";

/// Bytes copied per write: 16 pages, one `SYS_THREAD_READ_MEM` each.
const COPY_BYTES: usize = 16 * MAX_THREAD_MEM_COPY;

/// Bytes of the ELF header read at the load bias for `NT_AUXV`.
const EHDR_BYTES: usize = 64;

/// The faulting process, as the fault message and the report's attach give
/// it.
pub struct Target
{
    /// The fault message's badge: the process badge, or the crash badge of
    /// the registered thread that faulted.
    pub fault_badge: u64,
    /// The process badge.
    pub process: u64,
    /// The faulting instruction's address.
    pub ip: u64,
    /// Why the process dies.
    pub cause: Cause,
    /// The image's load bias.
    pub load_bias: u64,
    /// Whether the process declared itself on the core path: no core of it
    /// is written, since the dump would wait on it.
    pub no_core: bool,
    /// Whether a core may be written at all.
    pub dump: crate::Dump,
}

/// How a dump ended, for its log line.
pub enum Outcome
{
    /// The policy does not name the process.
    NotNamed,
    /// The core was written under this name, this many bytes long.
    Written(String, u64),
    /// No core was written, for this reason; a `.part` file may remain.
    Failed(&'static str),
    /// The bound passed; a `.part` file may remain.
    Cancelled,
}

/// Dump `target` under `policy`, under a call deadline of [`DUMP_BOUND`] of
/// its own. A dump that fails because the deadline passed ends
/// [`Outcome::Cancelled`].
pub fn dump(policy: &Policy, target: &Target, authority: u64, ipc_buf: *mut u64) -> Outcome
{
    let mut held = Vec::new();
    let (outcome, cancelled) = std::os::seraph::with_call_deadline(deadline_in(DUMP_BOUND), || {
        let outcome = capture(policy, target, authority, ipc_buf, &mut held);
        (outcome, expired())
    });
    for thread in &held
    {
        let _ = syscall::cap_delete(thread.cap);
    }
    match outcome
    {
        Outcome::Failed(_) | Outcome::Cancelled if cancelled => Outcome::Cancelled,
        Outcome::Written(..) | Outcome::NotNamed | Outcome::Failed(_) | Outcome::Cancelled =>
        {
            outcome
        }
    }
}

/// One thread the core records.
struct Held
{
    cap: u64,
    regs: Vec<u8>,
    ext: Vec<u8>,
}

/// The dump's steps, in order; the caps of the threads it holds are left in
/// `held` for the caller to delete.
fn capture(
    policy: &Policy,
    target: &Target,
    authority: u64,
    ipc_buf: *mut u64,
    held: &mut Vec<Held>,
) -> Outcome
{
    let name = match process_name(target.process, authority, ipc_buf)
    {
        Ok(name) => name,
        Err(outcome) => return outcome,
    };
    if !policy.dumps(&name)
    {
        return Outcome::NotNamed;
    }
    if target.no_core
    {
        return Outcome::Failed("the process is on the core path");
    }
    if target.dump == crate::Dump::MemoryCritical
    {
        return Outcome::Failed("memory is critical");
    }
    match hold_threads(target, authority, ipc_buf, held)
    {
        Ok(true) => (),
        Ok(false) => return Outcome::Failed("the faulting thread is not listed"),
        Err(outcome) => return outcome,
    }
    let Some(reader) = held.first().map(|t| t.cap)
    else
    {
        return Outcome::Failed("no thread of the process could be read");
    };
    // The fault's instruction first, then each thread's stack: the layout
    // keeps the runs holding them first.
    let first: Vec<u64> = core::iter::once(target.ip)
        .chain(
            held.iter()
                .map(|t| word_at(&t.regs, arch::current::SP_OFFSET)),
        )
        .collect();
    // One bound for every resident request of the dump: a swap service that
    // is down costs the dump one bound's pauses, about a second, each request
    // carries the time left of the dump's deadline, and none is sent once it
    // has passed.
    let mut bound = ipc::ResidentBound::new(&std::os::seraph::call_time_left);
    // The list holds only mapped pages: first have memmgr restore, with the
    // threads held, what the core keeps first.
    restore_first(&first, target.process, authority, ipc_buf, &mut bound);
    let runs = match list_runs(reader)
    {
        Ok(runs) => runs,
        Err(outcome) => return outcome,
    };

    // The header lies on the image's shared read-only data, which the process
    // may never have read, so memmgr maps it first when it is not present.
    let mut header = [0u8; EHDR_BYTES];
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let auxv = unsafe {
        ipc::read_mem_resident_bounded(
            authority,
            target.process,
            reader,
            target.load_bias,
            &mut header,
            ipc_buf,
            &mut bound,
        )
    }
    .ok()
    .and_then(|()| Auxv::from_header(&header, target.load_bias));
    let threads: Vec<Thread<'_>> = held
        .iter()
        .zip(1u32..)
        .map(|(t, tid)| Thread {
            tid,
            regs: &t.regs,
            ext: &t.ext,
        })
        .collect();
    let notes = notes::encode(
        arch::current::MACHINE,
        &Process {
            pid: u32::try_from(target.process & u64::from(u32::MAX)).unwrap_or(0),
            name: &name,
            cause: target.cause,
            auxv,
        },
        &threads,
    );
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
    let source = Source {
        reader,
        process: target.process,
        authority,
        ipc_buf,
    };
    write_core(&core, &name, &source, &mut bound)
}

/// Have memmgr restore the chunks it evicted of `process` from the page of
/// each address of `first` up, an equal share of the core's budget each
/// (`ipc::make_resident_bounded`), so the list of mapped pages holds them and
/// the core records them. A chunk on disk memmgr asks the swap service to
/// restore, and this pauses and asks again under the dump's `bound`, which
/// the dump's reads of its pages share ([`write_loads`]): at most
/// `ipc::PENDING_TRIES` pauses over the whole dump; a chunk the swap service
/// does not restore by then is left out, as one not present, and the rest of
/// each range is still restored. No more is restored: the core keeps at most
/// [`CORE_BYTES_MAX`] of pages, and a restore for a process about to die
/// spends the free pages, and other processes' idle chunks, that memmgr keeps
/// for restores. A chunk memmgr cannot restore, for want of memory, is left
/// out of the list, as it is not present. The bound stops once the dump's
/// deadline has passed, so a dump past its bound starts no more requests.
fn restore_first(
    first: &[u64],
    process: u64,
    authority: u64,
    ipc_buf: *mut u64,
    bound: &mut ipc::ResidentBound<'_>,
)
{
    let anchors = u64::try_from(first.len()).unwrap_or(u64::MAX);
    let share = CORE_BYTES_MAX
        .checked_div(anchors)
        .unwrap_or(CORE_BYTES_MAX)
        .max(PAGE_SIZE)
        & !(PAGE_SIZE - 1);
    for &anchor in first
    {
        let at = anchor & !(PAGE_SIZE - 1);
        let len = at.saturating_add(share).saturating_sub(at);
        // memmgr does a bounded part of the range per request and replies
        // where it stopped; a refusal, a reply that made no progress, or the
        // bound's stop ends this range, and once the dump's pauses are spent
        // its chunks on disk are passed over.
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::make_resident_bounded(authority, process, at, len, ipc_buf, bound) };
        if bound.stopped()
        {
            return;
        }
    }
}

/// Where a dump reads the process's pages: through the held thread `reader`,
/// asking procmgr through `authority` to make a page memmgr evicted since
/// the pages were listed resident again, under the dump's bound
/// ([`ipc::read_mem_resident_bounded`]).
struct Source
{
    reader: u64,
    /// The process badge.
    process: u64,
    authority: u64,
    ipc_buf: *mut u64,
}

/// The name of the process `badge` names, from `LIST_PROCESSES`, sent with
/// the time left of the dump's deadline as its timeout.
fn process_name(badge: u64, authority: u64, ipc_buf: *mut u64) -> Result<Vec<u8>, Outcome>
{
    // A page that resumes after `badge - 1` starts at `badge` while it lives.
    let request = IpcMessage::builder(procmgr_labels::LIST_PROCESSES)
        .word(0, 1)
        .word(1, badge.wrapping_sub(1))
        .build();
    let reply = loop
    {
        let left = std::os::seraph::call_time_left();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        match unsafe { ipc::ipc_call_within(authority, &request, ipc_buf, left) }
        {
            Err(e) if e == SyscallError::Interrupted as i64 =>
            {}
            Err(e) if e == SyscallError::WouldBlock as i64 => return Err(Outcome::Cancelled),
            Ok(r) if r.label == procmgr_errors::SUCCESS => break r,
            _ => return Err(Outcome::Failed("the process list was not read")),
        }
    };
    let mut name = [0u8; svcmgr_labels::NAME_MAX];
    match procmgr_labels::unpack_list_entry(reply.words(), 0, &mut name)
    {
        Some((listed, len)) if listed == badge => Ok(name.get(..len).unwrap_or_default().to_vec()),
        _ => Err(Outcome::Failed("the process is no longer listed")),
    }
}

/// Stop every thread the attach lists but the faulting one, and read the
/// registers and extended state of each, at most [`CORE_THREADS_MAX`], the
/// faulting thread first; whether the faulting thread was among them. The
/// faulting thread is the one the fault's badge names when it is held at the
/// fault's instruction; a stop of it would
/// cancel its fault. A thread that never registered faults under its
/// spawner's badge and is not listed, so it is neither stopped nor recorded.
fn hold_threads(
    target: &Target,
    authority: u64,
    ipc_buf: *mut u64,
    held: &mut Vec<Held>,
) -> Result<bool, Outcome>
{
    let mut first: u64 = 0;
    let mut found = false;
    loop
    {
        let reply = match attach(target.fault_badge, first, authority, ipc_buf)
        {
            Ok(reply) => reply,
            Err(AttachFailed::Expired) => return Err(Outcome::Cancelled),
            Err(AttachFailed::Refused) => return Err(Outcome::Failed("the attach was refused")),
        };
        let count = reply.word(0);
        let named = reply.word(procmgr_labels::ATTACH_WORD_NAMED_THREAD);
        let caps = reply.caps();
        for (&cap, index) in caps.iter().zip(first..)
        {
            let faulting = index == named && held_at(cap, target.ip);
            if !faulting
            {
                // A thread already stopped, or exiting, is refused and read
                // as it is.
                let _ = syscall::thread_stop(cap);
            }
            if (faulting || held.len() < CORE_THREADS_MAX)
                && let Some(thread) = read_thread(cap)
            {
                if faulting
                {
                    found = true;
                    held.insert(0, thread);
                    if held.len() > CORE_THREADS_MAX
                        && let Some(dropped) = held.pop()
                    {
                        let _ = syscall::cap_delete(dropped.cap);
                    }
                }
                else
                {
                    held.push(thread);
                }
                continue;
            }
            let _ = syscall::cap_delete(cap);
        }
        first = first.saturating_add(caps.len() as u64);
        if caps.is_empty() || first >= count
        {
            return Ok(found);
        }
    }
}

/// Whether the thread `cap` names is held at `ip`: its registers read as a
/// stopped or fault-blocked thread's, with its instruction pointer at `ip`. A
/// running thread's registers do not read, and a thread blocked in a syscall
/// reads as such, its frame naming that syscall, not a fault.
fn held_at(cap: u64, ip: u64) -> bool
{
    let mut file = [0u8; arch::current::REGS_SIZE];
    syscall::thread_read_regs(cap, &mut file)
        .is_ok_and(|(_, held)| held != syscall_abi::THREAD_REGS_SYSCALL)
        && word_at(&file, arch::current::IP_OFFSET) == ip
}

/// The registers and extended state of the held thread `cap`; `None` when
/// its registers cannot be read. Extended state that cannot be read is left
/// empty, and the core then carries the general registers alone.
fn read_thread(cap: u64) -> Option<Held>
{
    let mut regs = vec![0u8; arch::current::REGS_SIZE];
    syscall::thread_read_regs(cap, &mut regs).ok()?;
    let mut ext = Vec::new();
    let mut chunk = [0u8; MAX_THREAD_MEM_COPY];
    loop
    {
        let offset = ext.len() as u64;
        match syscall::thread_read_ext_regs(cap, offset, &mut chunk)
        {
            Ok((copied, size)) if copied > 0 =>
            {
                // `copied` is at most the chunk's length.
                let copied = usize::try_from(copied).unwrap_or(0);
                ext.extend_from_slice(chunk.get(..copied).unwrap_or_default());
                if ext.len() as u64 >= size
                {
                    break;
                }
            }
            Ok(_) => break,
            Err(_) =>
            {
                ext.clear();
                break;
            }
        }
    }
    Some(Held { cap, regs, ext })
}

/// The mapped pages of the space `reader` executes in, as runs in address
/// order, the runs two calls split joined.
fn list_runs(reader: u64) -> Result<Vec<Run>, Outcome>
{
    let mut runs: Vec<Run> = Vec::new();
    let mut page = vec![PageRun::default(); usize::try_from(MAX_PAGE_RUNS).unwrap_or(1)];
    let mut start = 0;
    loop
    {
        if expired()
        {
            return Err(Outcome::Cancelled);
        }
        let Ok((n, resume)) = syscall::thread_list_pages(reader, start, &mut page)
        else
        {
            return Err(Outcome::Failed("the pages were not listed"));
        };
        for listed in page.get(..n).unwrap_or_default()
        {
            match runs.last_mut()
            {
                Some(last)
                    if last.prot == listed.prot
                        && last.va.saturating_add(last.pages.saturating_mul(PAGE_SIZE))
                            == listed.va =>
                {
                    last.pages = last.pages.saturating_add(listed.pages);
                }
                _ => runs.push(Run {
                    va: listed.va,
                    pages: listed.pages,
                    prot: listed.prot,
                }),
            }
        }
        if (n == 0 && resume == start) || runs.len() >= layout::MAX_LOADS
        {
            return Ok(runs);
        }
        start = resume;
    }
}

/// Write `core` for the process named `name`, reading its pages from
/// `source` under the dump's `bound`: make room for it, write it under its
/// `.part` name, and rename it once complete.
fn write_core(
    core: &layout::Core,
    name: &[u8],
    source: &Source,
    bound: &mut ipc::ResidentBound<'_>,
) -> Outcome
{
    let seq = match make_room(core.size)
    {
        Ok(seq) => seq,
        Err(outcome) => return outcome,
    };
    let (core_name, partial_name) = store::names(seq, name);
    let partial = format!("{CORE_DIR}{partial_name}");
    if expired()
    {
        return Outcome::Cancelled;
    }
    let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
    else
    {
        return Outcome::Failed("the core file was not created");
    };
    if let Err(outcome) = write_bounded(&mut file, &core.head)
    {
        return outcome;
    }
    if let Err(outcome) = write_loads(&mut file, core, source, bound)
    {
        return outcome;
    }
    drop(file);
    if expired()
    {
        return Outcome::Cancelled;
    }
    if fs::rename(&partial, format!("{CORE_DIR}{core_name}")).is_err()
    {
        return Outcome::Failed("the core file was not renamed");
    }
    Outcome::Written(core_name, core.size)
}

/// Delete the `.part` files earlier dumps left and the oldest cores until a
/// core of `size` bytes fits [`CORE_DIR_BYTES_MAX`]; the new core's sequence
/// number.
fn make_room(size: u64) -> Result<u64, Outcome>
{
    if expired()
    {
        return Err(Outcome::Cancelled);
    }
    let Ok(dir) = fs::read_dir(CORE_DIR)
    else
    {
        return Err(Outcome::Failed("the core directory was not read"));
    };
    let mut entries = Vec::new();
    let mut cores = Vec::new();
    for item in dir
    {
        if expired()
        {
            return Err(Outcome::Cancelled);
        }
        let Ok(item) = item
        else
        {
            continue;
        };
        let file = item.file_name();
        let Some(entry) = file.to_str().and_then(store::classify)
        else
        {
            continue;
        };
        entries.push(entry);
        let path = format!("{CORE_DIR}{}", file.to_string_lossy());
        match entry
        {
            Entry::Partial(_) =>
            {
                let _ = fs::remove_file(&path);
            }
            Entry::Core(seq) =>
            {
                let bytes = item.metadata().map_or(0, |m| m.len());
                cores.push((seq, bytes, path));
            }
        }
    }
    let sizes: Vec<(u64, u64)> = cores.iter().map(|(seq, bytes, _)| (*seq, *bytes)).collect();
    let evicted = match store::evict(&sizes, size, CORE_DIR_BYTES_MAX)
    {
        Ok(evicted) => evicted,
        Err(StoreError::TooLarge) =>
        {
            return Err(Outcome::Failed("the core exceeds the directory budget"));
        }
    };
    for (seq, _, path) in &cores
    {
        if evicted.contains(seq)
        {
            if expired()
            {
                return Err(Outcome::Cancelled);
            }
            if fs::remove_file(path).is_err()
            {
                return Err(Outcome::Failed("an older core was not deleted"));
            }
        }
    }
    Ok(store::next_seq(&entries))
}

/// Write the file bytes of each load of `core` to `file`, reading them from
/// `source` one page at a time; a page the kernel refuses to copy, and
/// procmgr cannot make resident under the dump's `bound`, is written as
/// zeros. The bound's pauses are the dump's ([`restore_first`]), and once the
/// dump's deadline has passed no page is asked for: the next write ends the
/// dump.
fn write_loads(
    file: &mut File,
    core: &layout::Core,
    source: &Source,
    bound: &mut ipc::ResidentBound<'_>,
) -> Result<(), Outcome>
{
    let mut buf = vec![0u8; COPY_BYTES];
    for load in core.loads.iter().filter(|l| l.file_bytes > 0)
    {
        let mut va = load.run.va;
        let end = va.saturating_add(load.file_bytes);
        while va < end
        {
            let len = usize::try_from(end.saturating_sub(va))
                .map_or(buf.len(), |left| left.min(buf.len()));
            let Some(part) = buf.get_mut(..len)
            else
            {
                break;
            };
            for (page, at) in part
                .chunks_mut(MAX_THREAD_MEM_COPY)
                .zip((va..).step_by(MAX_THREAD_MEM_COPY))
            {
                // SAFETY: `source.ipc_buf` is the registered IPC buffer page.
                let read = unsafe {
                    ipc::read_mem_resident_bounded(
                        source.authority,
                        source.process,
                        source.reader,
                        at,
                        page,
                        source.ipc_buf,
                        bound,
                    )
                };
                if read.is_err()
                {
                    page.fill(0);
                }
            }
            write_bounded(file, part)?;
            va = va.saturating_add(len as u64);
        }
    }
    Ok(())
}

/// Write all of `bytes` to `file`, under the dump's deadline: a write the
/// deadline ends fails `TimedOut` and ends the dump [`Outcome::Cancelled`],
/// and any other failure ends it too.
fn write_bounded(file: &mut File, mut bytes: &[u8]) -> Result<(), Outcome>
{
    while !bytes.is_empty()
    {
        match file.write(bytes)
        {
            Ok(n) if n > 0 => bytes = bytes.get(n..).unwrap_or_default(),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err(Outcome::Cancelled);
            }
            _ => return Err(Outcome::Failed("the core file was not written")),
        }
    }
    Ok(())
}
