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
//! logs the report block (services/crashd/docs/block-format.md), and
//! declines the fault with the report's id as the reason. The mechanism and
//! its limits are in services/crashd/README.md.

// cast_possible_truncation: targets are 64-bit; u64/usize conversions are
// lossless.
#![allow(clippy::cast_possible_truncation)]

mod arch;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crash_report::{Access, Fault, Image, Report, Status, Thread};
use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use syscall_abi::{
    FAULT_FORWARD_REASON_WORD, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_KILL, MAX_THREAD_MEM_COPY,
    PAGE_SIZE, SyscallError,
};

/// How long the reading of one fault may take before the watchdog cancels
/// it. Only the attach request can block, on a procmgr that is itself waiting
/// on the faulting process; the cancellation breaks that wait.
const FAULT_BOUND: Duration = Duration::from_secs(2);

/// How often the watchdog checks the bound.
const WATCHDOG_TICK: Duration = Duration::from_millis(100);

/// Bytes of stack the walk scans, from the stack pointer up.
const STACK_SCAN_BYTES: u64 = 8192;

/// The thread that receives faults, which the watchdog stops and starts
/// again to cancel a blocked request.
static RECEIVER: AtomicU64 = AtomicU64::new(0);

/// Milliseconds since [`epoch`] when the current fault's reading began; 0
/// while none is being read.
static ARMED_AT_MS: AtomicU64 = AtomicU64::new(0);

/// Whether the watchdog cancelled the current fault's reading.
static FIRED: AtomicBool = AtomicBool::new(false);

fn main() -> !
{
    std::os::seraph::log::register_name(b"crashd");
    let info = std::os::seraph::startup_info();
    // cast_ptr_alignment: the IPC buffer page is 4 KiB-aligned.
    #[allow(clippy::cast_ptr_alignment)]
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
                std::os::seraph::log!("no debug authority delivered; not reporting crashes");
                syscall::thread_exit();
            }
        };
    let Some(endpoint) = register(authority, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    RECEIVER.store(
        std::os::seraph::thread::current_thread_cap(),
        Ordering::Release,
    );
    if std::thread::Builder::new()
        .name("watchdog".into())
        .spawn(watchdog)
        .is_err()
    {
        std::os::seraph::log!("watchdog not started; a fault's reading is unbounded");
    }
    std::os::seraph::log!("reporting crashes");

    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let Ok(msg) = (unsafe { ipc::ipc_recv(endpoint, ipc_buf) })
        else
        {
            continue;
        };
        if msg.label != FAULT_LABEL
        {
            // Only procmgr holds a SEND on the endpoint, and it sends none;
            // answer anything else without acting on it.
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_KILL), ipc_buf) };
            continue;
        }
        handle_fault(&msg, authority, ipc_buf);
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
        std::os::seraph::log!("register: thread cap not derived");
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
            if r.label == procmgr_errors::SUCCESS && r.caps().first().is_some_and(|&c| c != 0) =>
        {
            Some(r.caps()[0])
        }
        Ok(r) =>
        {
            std::os::seraph::log!("register refused (label={:#x})", r.label);
            None
        }
        Err(e) =>
        {
            let _ = syscall::cap_delete(thread);
            std::os::seraph::log!("register call failed (err={e})");
            None
        }
    }
}

/// Report the fault `msg` and decline it: read what the attach request
/// reaches and log the block, under the watchdog's bound, then end the
/// thread with the report id as the decline reason. The block is logged
/// before the decline, so the kernel's serial diagnostic of the kill, which
/// the decline triggers, does not land among its lines. A request the
/// watchdog cancels ends the bound: the thread is declined at once, and the
/// block's remaining lines follow the decline, when nothing can wait on the
/// faulting thread any more.
fn handle_fault(msg: &IpcMessage, authority: u64, ipc_buf: *mut u64)
{
    let id = report_id();
    let ip = msg.word(3);
    let fault = if msg.word(0) == FAULT_KIND_VM
    {
        Fault::Vm {
            access: Access::from_flags(msg.word(2)),
            addr: msg.word(1),
            pager_reason: (msg.word_count() > FAULT_FORWARD_REASON_WORD)
                .then(|| msg.word(FAULT_FORWARD_REASON_WORD)),
        }
    }
    else
    {
        Fault::Exception {
            code: msg.word(1),
            aux: msg.word(2),
        }
    };

    FIRED.store(false, Ordering::Release);
    ARMED_AT_MS.store(now_ms().max(1), Ordering::Release);
    let gathered = gather(msg.badge, ip, authority, ipc_buf);
    let report = Report {
        id,
        badge: msg.badge,
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
    let mut logged = 0;
    while logged < lines.len() && !FIRED.load(Ordering::Acquire)
    {
        std::os::seraph::log!("{}", lines[logged]);
        logged += 1;
    }
    ARMED_AT_MS.store(0, Ordering::Release);

    let decline = IpcMessage::builder(FAULT_REPLY_KILL).word(0, id).build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&decline, ipc_buf) };

    // A write the watchdog cancelled is written again, with the rest.
    let resume = if FIRED.load(Ordering::Acquire)
    {
        logged.saturating_sub(1)
    }
    else
    {
        lines.len()
    };
    for line in &lines[resume..]
    {
        std::os::seraph::log!("{line}");
    }
}

/// What [`gather`] read of a faulting process.
struct Gathered
{
    status: Status,
    thread: Thread,
    image: Option<Image>,
    regs: Vec<u64>,
    code: Vec<u8>,
    frames: Vec<u64>,
}

/// Attach to the process `badge` names and read its faulting thread: the
/// main thread's registers when the main thread is the one stopped at `ip`,
/// the bytes at `ip`, and the stack walk.
fn gather(badge: u64, ip: u64, authority: u64, ipc_buf: *mut u64) -> Gathered
{
    let mut out = Gathered {
        status: Status::Unattached,
        thread: Thread::Unidentified,
        image: None,
        regs: Vec::new(),
        code: Vec::new(),
        frames: Vec::new(),
    };
    let request = IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
        .word(0, badge)
        .word(1, 0)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(authority, &request, ipc_buf) };
    let reply = match reply
    {
        Ok(r) if r.label == procmgr_errors::SUCCESS => r,
        Ok(r) =>
        {
            for &cap in r.caps()
            {
                let _ = syscall::cap_delete(cap);
            }
            return out;
        }
        Err(e) =>
        {
            if e == SyscallError::Interrupted as i64 || FIRED.load(Ordering::Acquire)
            {
                out.status = Status::Timeout;
            }
            return out;
        }
    };
    out.status = Status::Complete;
    out.image = Some(Image {
        load_bias: reply.word(1),
        text_start: reply.word(2),
        text_end: reply.word(3),
    });
    let Some(&thread) = reply.caps().first()
    else
    {
        return out;
    };
    read_thread(thread, ip, &mut out);
    let _ = syscall::cap_delete(thread);
    out
}

/// Read the main thread `thread` into `out`: its registers and stack walk
/// when it is the thread stopped at `ip`, and the bytes at `ip` whichever
/// thread faulted, through the address space they share.
fn read_thread(thread: u64, ip: u64, out: &mut Gathered)
{
    let mut file = [0u8; arch::current::REGS_SIZE];
    let main_faulted = syscall::thread_read_regs(thread, &mut file).is_ok()
        && word_at(&file, arch::current::IP_OFFSET) == ip;
    out.code = read_code(thread, ip);
    if !main_faulted
    {
        return;
    }
    out.thread = Thread::Main;
    out.regs = file.chunks_exact(8).map(le_word).collect();
    out.frames.push(ip);
    if let Some(image) = out.image
    {
        let stack = read_stack(thread, word_at(&file, arch::current::SP_OFFSET));
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
    let to_page_end = (PAGE_SIZE - (ip % PAGE_SIZE)) as usize;
    let len = to_page_end.min(buf.len());
    if syscall::thread_read_mem(thread, ip, &mut buf[..len]).is_ok()
    {
        return buf[..len].to_vec();
    }
    Vec::new()
}

/// The stack from `sp` (rounded down to a word) up, at most
/// [`STACK_SCAN_BYTES`], stopping at the first page that is not present.
fn read_stack(thread: u64, sp: u64) -> Vec<u8>
{
    let mut stack = Vec::new();
    let mut at = sp & !7;
    let end = at.saturating_add(STACK_SCAN_BYTES);
    let mut chunk = [0u8; MAX_THREAD_MEM_COPY];
    while at < end
    {
        let page_end = (at | (PAGE_SIZE - 1)).saturating_add(1);
        let len = (page_end.min(end) - at) as usize;
        if syscall::thread_read_mem(thread, at, &mut chunk[..len]).is_err()
        {
            break;
        }
        stack.extend_from_slice(&chunk[..len]);
        at += len as u64;
    }
    stack
}

/// The register-file word at byte `offset`.
fn word_at(file: &[u8], offset: usize) -> u64
{
    le_word(&file[offset..offset + 8])
}

/// A little-endian word from 8 bytes.
fn le_word(bytes: &[u8]) -> u64
{
    let mut word = [0u8; 8];
    word.copy_from_slice(bytes);
    u64::from_le_bytes(word)
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

/// The watchdog: once a fault's reading has run past [`FAULT_BOUND`], stop
/// the receiving thread and start it again, which cancels the request it is
/// blocked in (`Interrupted`); the thread keeps the fault it holds, since a
/// stop cancels no pending reply.
fn watchdog()
{
    loop
    {
        std::thread::sleep(WATCHDOG_TICK);
        let armed = ARMED_AT_MS.load(Ordering::Acquire);
        if armed == 0 || now_ms().saturating_sub(armed) < FAULT_BOUND.as_millis() as u64
        {
            continue;
        }
        if FIRED.swap(true, Ordering::AcqRel)
        {
            continue;
        }
        let receiver = RECEIVER.load(Ordering::Acquire);
        let _ = syscall::thread_stop(receiver);
        let _ = syscall::thread_start(receiver);
        std::os::seraph::log!("a fault's reading passed its bound; reporting what was read");
    }
}
