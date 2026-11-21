// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/src/main.rs

//! The crash service: reports each process that dies on a fault to the
//! system log, then ends the faulting thread as the kernel would have.
//!
//! crashd receives on procmgr's crash endpoint, which every process procmgr
//! creates has its exception class bound to and memmgr forwards its
//! unresolvable page faults to. For each fault it attaches to the process
//! (procmgr's `ATTACH_PROCESS`), reads what it can of the faulting thread,
//! logs the report block (services/crashd/docs/block-format.md), writes a
//! core of it to `/crash` when its `CORE_DUMP` setting names the process
//! (services/crashd/docs/core-format.md), and declines the fault with the
//! report's id as the reason.
//!
//! When its `CRASHD_OOM_STALL_MS` setting gives a stall, crashd holds a page
//! fault memmgr declined for want of memory instead (the `hold` module): it
//! redirects the fault to one of its hold endpoints, where it waits with its
//! thread fault-blocked, resumes it when memmgr's memory is there (the level
//! below `CRITICAL`, or for a commit overrun the draw room open), and reports
//! and declines it when the stall passes first. The mechanism and its limits
//! are in services/crashd/docs/operation.md.

mod arch;
mod dump;
mod hold;

use std::os::seraph::call_time_left;
use std::time::{Duration, Instant};

use core_file::notes::Cause;
use core_file::policy::Policy;
use crash_report::{Access, Fault, Image, Report, Status, Thread};
use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use syscall_abi::{
    FAULT_FORWARD_REASON_WORD, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_KILL, MAX_THREAD_MEM_COPY,
    PAGE_SIZE, SyscallError,
};

/// How long the reading and logging of one fault may take: the call
/// deadline its calls carry the time left of
/// (`std::os::seraph::with_call_deadline`), the attach, which can wait on a
/// procmgr that is itself waiting on the faulting process, and the log
/// writes, which can wait on a driver logd writes through.
const FAULT_BOUND: Duration = Duration::from_millis(2000);

/// Bytes of stack the walk scans, from the stack pointer up.
const STACK_SCAN_BYTES: u64 = 8192;

/// Bytes of heap crashd touches at start when it holds faults, so a report
/// made while memory is critical finds its heap pages backed: several times
/// a report's peak, the stack scan's buffer and the block's lines.
const HEAP_TOUCH_BYTES: usize = 64 * 1024;

/// Bytes of stack crashd's thread touches when it starts holding faults,
/// below the frame that starts its work, for the same reason: more than a
/// report goes down.
const STACK_TOUCH_BYTES: usize = 32 * 1024;

/// The instant `bound` from now, the deadline of a step of a fault's
/// handling ([`FAULT_BOUND`], [`dump::DUMP_BOUND`]).
fn deadline_in(bound: Duration) -> Instant
{
    let now = Instant::now();
    now.checked_add(bound).unwrap_or(now)
}

/// Whether the calling thread's call deadline has passed: the step under way
/// ran out of its bound, and none of its calls is made any more.
fn expired() -> bool
{
    call_time_left().is_some_and(|left| left.is_zero())
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"crashd");
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // A debug-authority holder must not be stopped by another, nor bound to
    // the endpoint it receives on.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe {
        ipc::ipc_call(
            info.procmgr_endpoint,
            &IpcMessage::new(procmgr_labels::DECLARE_NO_DEBUG),
            ipc_buf,
        )
    };

    // The recipe's `debug_authority = yes` delivers the authority cap in the
    // slot after the (absent) seeds.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let authority =
        match unsafe { ipc::bootstrap::request_slots::<1>(info.creator_endpoint, ipc_buf) }
        {
            Ok([cap]) if cap != 0 => cap,
            _ =>
            {
                std::os::seraph::log!(error: "no debug authority delivered; not reporting crashes");
                syscall::thread_exit();
            }
        };
    let policy = core_policy();
    let stall_ms = stall_ms();
    let Some(endpoint) = register(authority, ipc_buf)
    else
    {
        syscall::thread_exit();
    };
    if stall_ms != 0
    {
        hold::serve(stall_ms, endpoint, &policy, authority, ipc_buf);
    }
    std::os::seraph::log!("reporting crashes");

    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let msg = match unsafe { ipc::ipc_recv(endpoint, ipc_buf) }
        {
            Ok(msg) =>
            {
                guard.on_success();
                msg
            }
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        if msg.label != FAULT_LABEL
        {
            // Only procmgr holds a SEND on the endpoint, and it sends crashd
            // none; answer anything else without acting on it.
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_KILL), ipc_buf) };
            continue;
        }
        handle_fault(&msg, &policy, authority, ipc_buf, Dump::Allowed);
    }
}

/// [`ipc::recv_guard::RecvGuard`] hook of crashd's receive loop: log the first
/// failure of a streak and the fatal one.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!(warn: "ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!(error: "ipc_recv wedged (err={err}); exiting");
        }
    }
}

/// Register as the crash service: returns the `RECV` cap on procmgr's crash
/// endpoint, or `None`, logged, when procmgr refuses.
fn register(authority: u64, ipc_buf: *mut u64) -> Option<u64>
{
    let Ok(thread) = syscall::cap_derive(
        std::os::seraph::thread::current_thread_cap(),
        syscall_abi::RIGHTS_THREAD_OBSERVE,
    )
    else
    {
        std::os::seraph::log!(error: "register: thread cap not derived");
        return None;
    };
    let msg = IpcMessage::builder(procmgr_labels::REGISTER_CRASH_SERVICE)
        .cap(thread)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(authority, &msg, ipc_buf) };
    match reply
    {
        Ok(r)
            if r.label == procmgr_errors::SUCCESS
                && r.caps().split_first().is_some_and(|(&c, _)| c != 0) =>
        {
            let (first, rest) = r.caps().split_first()?;
            delete_caps(rest);
            Some(*first)
        }
        Ok(r) =>
        {
            delete_caps(r.caps());
            std::os::seraph::log!(error: "register refused (label={:#x})", r.label);
            None
        }
        Err(e) =>
        {
            let _ = syscall::cap_delete(thread);
            std::os::seraph::log!(error: "register call failed (err={e})");
            None
        }
    }
}

/// The `CORE_DUMP` setting of crashd's environment, logged; a value that
/// does not parse writes no core.
fn core_policy() -> Policy
{
    let value = std::env::var("CORE_DUMP").ok();
    match Policy::parse(value.as_deref())
    {
        Ok(Policy::Off) =>
        {
            std::os::seraph::log!("core dumps off");
            Policy::Off
        }
        Ok(policy) =>
        {
            std::os::seraph::log!("core dumps for {}", value.unwrap_or_default());
            policy
        }
        Err(_) =>
        {
            std::os::seraph::log!(warn: "CORE_DUMP holds an empty name; core dumps off");
            Policy::Off
        }
    }
}

/// The stall of crashd's `CRASHD_OOM_STALL_MS` setting, in milliseconds,
/// logged when it is clamped or does not parse; 0, which holds no fault, when
/// it is absent or does not parse.
fn stall_ms() -> u64
{
    let value = std::env::var("CRASHD_OOM_STALL_MS").ok();
    let Ok(stall) = oom_hold::parse_stall(value.as_deref())
    else
    {
        std::os::seraph::log!(
            warn: "CRASHD_OOM_STALL_MS is not a number of milliseconds; no fault held"
        );
        return 0;
    };
    if stall.clamped
    {
        std::os::seraph::log!(
            warn: "CRASHD_OOM_STALL_MS clamped to {} ms",
            oom_hold::STALL_MAX_MS
        );
    }
    stall.ms
}

/// Touch [`STACK_TOUCH_BYTES`] of the calling thread's stack below this
/// frame, so its pages are backed before memory can run out.
#[inline(never)]
#[expect(
    clippy::large_stack_arrays,
    clippy::large_stack_frames,
    reason = "the probe exists to occupy and touch this much of the stack"
)]
fn touch_stack()
{
    let mut probe = [0u8; STACK_TOUCH_BYTES];
    std::hint::black_box(&mut probe);
}

/// Touch [`HEAP_TOUCH_BYTES`] of heap and free them: the allocator keeps
/// the pages, and places later requests first fit from the heap's bottom.
fn touch_heap()
{
    drop(std::hint::black_box(vec![1u8; HEAP_TOUCH_BYTES]));
}

/// Whether a report may write a core of its process.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Dump
{
    /// As the policy says.
    Allowed,
    /// None: memory is critical while crashd holds faults, and a dump's
    /// buffers and file writes would need pages a report's do not.
    MemoryCritical,
}

/// Report the fault `msg` and decline it: read what the attach request
/// reaches and log the block, under a call deadline of [`FAULT_BOUND`],
/// write a core of the process when `policy` may name it, `dump` allows
/// one, and the report read it whole, under the dump's own deadline, and log
/// the dump's line, then end the thread with the report id as the decline
/// reason. The block and the dump's line are logged before the decline, so
/// the kernel's serial diagnostic of the kill, which the decline triggers,
/// does not land among them. A report that passes its deadline ends there:
/// the thread is declined at once, with no dump, and the block's remaining
/// lines follow, when nothing can wait on the faulting thread any more.
fn handle_fault(msg: &IpcMessage, policy: &Policy, authority: u64, ipc_buf: *mut u64, dump: Dump)
{
    let id = report_id();
    let ip = msg.word(3);
    let (fault, cause) = decode(msg);
    let (gathered, lines, logged, cancelled) =
        std::os::seraph::with_call_deadline(deadline_in(FAULT_BOUND), || {
            let gathered = gather(msg.badge, ip, authority, ipc_buf);
            let report = Report {
                id,
                badge: gathered.badge,
                arch: arch::current::ARCH,
                thread: gathered.thread,
                status: gathered.status,
                fault,
                ip,
                image: gathered.image,
                regs: &gathered.regs,
                code: &gathered.code,
                frames: &gathered.frames,
            };
            let mut lines: Vec<String> = Vec::new();
            report.emit(|line| lines.push(line.to_string()));
            let mut logged = 0usize;
            for line in &lines
            {
                if expired()
                {
                    break;
                }
                std::os::seraph::log!("{}", line);
                // `line` came from `lines`, so `logged` stays at most
                // `lines.len()`.
                logged = logged.saturating_add(1);
            }
            let cancelled = expired();
            (gathered, lines, logged, cancelled)
        });

    // A dump only after a report that ran within its bound and read the
    // process: a step that ran out waits on something a dump would wait on
    // too.
    let core = match (&gathered.image, policy)
    {
        (_, Policy::Off) => None,
        (Some(image), _) if !cancelled && matches!(gathered.status, Status::Complete) =>
        {
            Some(dump::dump(
                policy,
                &dump::Target {
                    fault_badge: msg.badge,
                    process: gathered.badge,
                    ip,
                    cause,
                    load_bias: image.load_bias,
                    no_core: gathered.no_core,
                    dump,
                },
                authority,
                ipc_buf,
            ))
        }
        _ => None,
    };

    // A dump ran only after a report within its bound, so its line, too,
    // precedes the decline and the kernel's diagnostic.
    if let Some(outcome) = core
    {
        log_core(id, &outcome);
    }

    let decline = IpcMessage::builder(FAULT_REPLY_KILL).word(0, id).build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&decline, ipc_buf) };

    // A write the deadline cut short is written again, with the rest; a
    // reader counts a line written twice once.
    let resume = if cancelled
    {
        logged.saturating_sub(1)
    }
    else
    {
        lines.len()
    };
    for line in lines.iter().skip(resume)
    {
        std::os::seraph::log!("{line}");
    }
}

/// The fault `msg` reports, and the cause the core records for it.
fn decode(msg: &IpcMessage) -> (Fault, Cause)
{
    if msg.word(0) == FAULT_KIND_VM
    {
        let fault = Fault::Vm {
            access: Access::from_flags(msg.word(2)),
            addr: msg.word(1),
            pager_reason: (msg.word_count() > FAULT_FORWARD_REASON_WORD)
                .then(|| msg.word(FAULT_FORWARD_REASON_WORD)),
        };
        (fault, Cause::Vm)
    }
    else
    {
        let code = msg.word(1);
        let fault = Fault::Exception {
            code,
            aux: msg.word(2),
        };
        (fault, Cause::Exception(code))
    }
}

/// Log how the dump for the report `id` ended, after its block; a process
/// the policy does not name gets no line.
fn log_core(id: u64, outcome: &dump::Outcome)
{
    match outcome
    {
        dump::Outcome::Written(name, bytes) =>
        {
            std::os::seraph::log!("core id={id:016x} written /crash/{name} bytes={bytes}");
        }
        dump::Outcome::Failed(why) =>
        {
            std::os::seraph::log!(warn: "core id={id:016x} not written: {why}");
        }
        dump::Outcome::Cancelled =>
        {
            std::os::seraph::log!(warn: "core id={id:016x} not written: the dump passed its bound");
        }
        dump::Outcome::NotNamed => (),
    }
}

/// What [`gather`] read of a faulting process.
struct Gathered
{
    /// The process badge the attach reply names; the fault's own badge when
    /// no attach succeeded.
    badge: u64,
    status: Status,
    thread: Thread,
    image: Option<Image>,
    /// Whether the attach reply carried `ATTACH_FLAG_NO_CORE`: the process
    /// is on the core path, and no core of it is written.
    no_core: bool,
    regs: Vec<u64>,
    code: Vec<u8>,
    frames: Vec<u64>,
}

/// Why [`attach`] returned no reply.
enum AttachFailed
{
    /// procmgr refused, or the call failed.
    Refused,
    /// The calling thread's call deadline passed first.
    Expired,
}

/// Send `ATTACH_PROCESS` for `badge` from thread `first`, with the time
/// left of the calling thread's call deadline as the call's timeout, so no
/// attach waits past the bound, and none is sent once it has passed. An
/// interrupted call is sent again; an attach is a read, which procmgr may
/// serve twice.
fn attach(
    badge: u64,
    first: u64,
    authority: u64,
    ipc_buf: *mut u64,
) -> Result<IpcMessage, AttachFailed>
{
    let request = IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
        .word(0, badge)
        .word(1, first)
        .build();
    let reply = loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        match unsafe { ipc::ipc_call_within(authority, &request, ipc_buf, call_time_left()) }
        {
            Err(e) if e == SyscallError::Interrupted as i64 =>
            {}
            other => break other,
        }
    };
    match reply
    {
        Ok(r) if r.label == procmgr_errors::SUCCESS => Ok(r),
        Ok(r) =>
        {
            delete_caps(r.caps());
            Err(AttachFailed::Refused)
        }
        Err(e) if e == SyscallError::WouldBlock as i64 => Err(AttachFailed::Expired),
        Err(_) => Err(AttachFailed::Refused),
    }
}

/// Attach to the process the fault's `badge` names and read its faulting
/// thread: the thread the badge names, which the reply's named-thread word
/// gives the index of (the main thread for a process badge, a registered
/// thread for its crash badge), with its registers and stack walk when it is
/// stopped at `ip`, and the bytes at `ip`
/// (services/crashd/docs/operation.md § Per Fault).
fn gather(badge: u64, ip: u64, authority: u64, ipc_buf: *mut u64) -> Gathered
{
    let mut out = Gathered {
        badge,
        status: Status::Unattached,
        thread: Thread::Unidentified,
        image: None,
        no_core: false,
        regs: Vec::new(),
        code: Vec::new(),
        frames: Vec::new(),
    };
    let reply = match attach(badge, 0, authority, ipc_buf)
    {
        Ok(r) => r,
        Err(AttachFailed::Expired) =>
        {
            out.status = Status::Timeout;
            return out;
        }
        Err(AttachFailed::Refused) => return out,
    };
    out.status = Status::Complete;
    out.badge = reply.word(procmgr_labels::ATTACH_WORD_PROCESS_BADGE);
    out.image = Some(Image {
        load_bias: reply.word(1),
        text_start: reply.word(2),
        text_end: reply.word(3),
    });
    out.no_core =
        reply.word(procmgr_labels::ATTACH_WORD_FLAGS) & procmgr_labels::ATTACH_FLAG_NO_CORE != 0;
    let named = reply.word(procmgr_labels::ATTACH_WORD_NAMED_THREAD);
    let kind = if named == 0
    {
        Thread::Main
    }
    else
    {
        Thread::Spawned
    };
    let Some(&first) = reply.caps().first()
    else
    {
        return out;
    };
    // The named thread's cap: in this page, or first in the page that starts
    // at it.
    let in_page = usize::try_from(named)
        .ok()
        .and_then(|i| reply.caps().get(i).copied());
    let thread = match in_page
    {
        Some(thread) => Some(thread),
        None => match page_at_named(badge, named, authority, ipc_buf)
        {
            Ok(thread) => thread,
            Err(AttachFailed::Expired) =>
            {
                out.status = Status::Timeout;
                None
            }
            Err(AttachFailed::Refused) => None,
        },
    };
    match thread
    {
        Some(thread) => read_thread(thread, ip, kind, authority, ipc_buf, &mut out),
        // The bytes at `ip` through any thread: the threads share the space.
        None => out.code = read_code(first, ip),
    }
    delete_caps(reply.caps());
    if let Some(thread) = thread.filter(|t| !reply.caps().contains(t))
    {
        let _ = syscall::cap_delete(thread);
    }
    out
}

/// Attaches a named thread's index is chased through, at most: its index
/// moves only when threads listed before it exit between two attaches.
const NAMED_PAGE_TRIES: usize = 3;

/// The cap of the thread `named` indexes, from an attach whose page starts
/// at it; `Ok(None)` when the thread is not listed, or still moves after
/// [`NAMED_PAGE_TRIES`] attaches. A fault-blocked thread is never swept out
/// of the list, so its index moves only down, when threads before it exit,
/// and each reply's named-thread word gives where it is then.
fn page_at_named(
    badge: u64,
    mut named: u64,
    authority: u64,
    ipc_buf: *mut u64,
) -> Result<Option<u64>, AttachFailed>
{
    for _ in 0..NAMED_PAGE_TRIES
    {
        if named == procmgr_labels::ATTACH_NO_THREAD
        {
            return Ok(None);
        }
        let reply = attach(badge, named, authority, ipc_buf)?;
        let now = reply.word(procmgr_labels::ATTACH_WORD_NAMED_THREAD);
        match reply.caps().split_first()
        {
            Some((&thread, rest)) if now == named =>
            {
                delete_caps(rest);
                return Ok(Some(thread));
            }
            _ => delete_caps(reply.caps()),
        }
        named = now;
    }
    Ok(None)
}

/// Read the faulting thread `thread`, of kind `kind`, of the process
/// `out.badge` names, into `out`: its registers and stack walk when it is
/// stopped at `ip`, which checks the thread its badge named (a thread that
/// never registered carries its spawner's badge), and the bytes at `ip` in
/// any case, through the address space every thread of the process shares.
/// A stack page memmgr evicted is made resident through the debug authority
/// `authority` for the walk ([`read_stack`]), under a bound of the fault's:
/// at most `ipc::PENDING_TRIES` pauses over the whole walk, each request
/// under the fault's call deadline, and none once it has passed.
fn read_thread(
    thread: u64,
    ip: u64,
    kind: Thread,
    authority: u64,
    ipc_buf: *mut u64,
    out: &mut Gathered,
)
{
    let mut file = [0u8; arch::current::REGS_SIZE];
    // A thread blocked in a syscall reads too, its frame naming that syscall
    // rather than a fault, so only a stopped or fault-blocked read counts.
    let stopped_at_ip = syscall::thread_read_regs(thread, &mut file)
        .is_ok_and(|(_, held)| held != syscall_abi::THREAD_REGS_SYSCALL)
        && word_at(&file, arch::current::IP_OFFSET) == ip;
    out.code = read_code(thread, ip);
    if !stopped_at_ip
    {
        return;
    }
    out.thread = kind;
    out.regs = file
        .as_chunks::<8>()
        .0
        .iter()
        .map(|&word| u64::from_le_bytes(word))
        .collect();
    out.frames.push(ip);
    if let Some(image) = out.image
    {
        let process = out.badge;
        let mut bound = ipc::ResidentBound::new(&call_time_left);
        let stack = read_stack(word_at(&file, arch::current::SP_OFFSET), |at, part| {
            // SAFETY: ipc_buf is the registered IPC buffer page.
            unsafe {
                ipc::read_mem_resident_bounded(
                    authority, process, thread, at, part, ipc_buf, &mut bound,
                )
            }
            .is_ok()
        });
        out.frames.extend(crash_report::walk::scan(
            &stack,
            image.text_start,
            image.text_end,
            crash_report::MAX_FRAMES - 1,
        ));
    }
}

/// The bytes at `ip`, at most `MAX_CODE_BYTES`, stopping at the end of its
/// page when the next page is not present; empty when `ip`'s own page is
/// not.
fn read_code(thread: u64, ip: u64) -> Vec<u8>
{
    let mut buf = [0u8; crash_report::MAX_CODE_BYTES];
    if syscall::thread_read_mem(thread, ip, &mut buf).is_ok()
    {
        return buf.to_vec();
    }
    let to_page_end =
        usize::try_from(PAGE_SIZE.saturating_sub(ip % PAGE_SIZE)).unwrap_or(buf.len());
    let len = to_page_end.min(buf.len());
    if let Some(head) = buf.get_mut(..len)
        && syscall::thread_read_mem(thread, ip, head).is_ok()
    {
        return head.to_vec();
    }
    Vec::new()
}

/// The stack from `sp` (rounded down to a word) up, at most
/// [`STACK_SCAN_BYTES`], read a page at a time with `read`, stopping at the
/// first page it does not read: one not present, which procmgr could not
/// make resident within the fault's bound ([`ipc::read_mem_resident_bounded`]).
fn read_stack(sp: u64, mut read: impl FnMut(u64, &mut [u8]) -> bool) -> Vec<u8>
{
    let mut stack = Vec::new();
    let mut at = sp & !7;
    let end = at.saturating_add(STACK_SCAN_BYTES);
    let mut chunk = [0u8; MAX_THREAD_MEM_COPY];
    while at < end
    {
        let page_end = (at | (PAGE_SIZE - 1)).saturating_add(1);
        // At most one page: a page's bytes fit `chunk` and a `usize`.
        let span = page_end.min(end).saturating_sub(at);
        let Ok(len) = usize::try_from(span)
        else
        {
            break;
        };
        let Some(part) = chunk.get_mut(..len)
        else
        {
            break;
        };
        if !read(at, part)
        {
            break;
        }
        stack.extend_from_slice(part);
        at = at.saturating_add(span);
    }
    stack
}

/// The register-file word at byte `offset`.
fn word_at(file: &[u8], offset: usize) -> u64
{
    offset
        .checked_add(8)
        .and_then(|end| file.get(offset..end))
        .map_or(0, le_word)
}

/// A little-endian word from 8 bytes.
fn le_word(bytes: &[u8]) -> u64
{
    let mut word = [0u8; 8];
    word.copy_from_slice(bytes);
    u64::from_le_bytes(word)
}

/// Delete each nonzero cap of `caps`.
fn delete_caps(caps: &[u64])
{
    for &cap in caps
    {
        if cap != 0
        {
            let _ = syscall::cap_delete(cap);
        }
    }
}

/// A fresh report id from the kernel's entropy; a time-derived one when the
/// draw fails, which still tells two blocks of one boot apart.
fn report_id() -> u64
{
    let mut bytes = [0u8; 8];
    if syscall::getrandom(&mut bytes).is_ok()
    {
        u64::from_le_bytes(bytes)
    }
    else
    {
        now_ms().rotate_left(32) ^ 0x5eed
    }
}

/// Milliseconds since the first call.
fn now_ms() -> u64
{
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}
