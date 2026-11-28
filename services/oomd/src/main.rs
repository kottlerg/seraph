// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/oomd/src/main.rs

//! The out-of-memory policy service: when memmgr's pressure level has read
//! `CRITICAL` for a grace period, oomd stops one candidate of its stop
//! sources, a session's program before any service that opted in to being
//! stopped, and the one using the most memory within its class, at most one
//! per cooldown (services/oomd/docs/operation.md).
//!
//! oomd waits on the runtime's memory-pressure Notification, with a timeout
//! of the next act's deadline, and reads the level from memmgr's
//! `QUERY_POOL_STATUS`. Its decisions are [`policy`]'s, host-tested: the
//! configuration, the ladder over the level, and the order of the candidates
//! the stop sources list ([`source`]). It stops through the stop authority
//! svcmgr delivers to its recipe (`stop_authority = yes`), and holds no process
//! handle. Its recipe sets `reserve = yes`, and it touches its stack and heap
//! and funds its `CSpace` headroom for a walk's caps at start, and allocates
//! nothing after, so it runs while the pool outside the reserve is spent.

mod source;

use std::time::Instant;

use policy::{Act, Config, Ladder, Level, Mode, Read, Transition};
use syscall_abi::SyscallError;

/// Bytes of stack oomd touches at start, below the frame of its loop: more
/// than a walk of the stop sources and a log line go down.
const STACK_TOUCH_BYTES: usize = 32 * 1024;

/// Bytes of heap oomd touches at start: what the runtime's first uses of
/// the heap after start can ask for. oomd itself allocates nothing after.
const HEAP_TOUCH_BYTES: usize = 16 * 1024;

/// How long oomd waits before it waits on the Notification again after the
/// wait failed with an error a retry does not clear at once.
const WAIT_RETRY_MS: u64 = 100;

fn main() -> !
{
    std::os::seraph::log::register_name(b"oomd");
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // The recipe's `stop_authority = yes` delivers the stop authority in the
    // slot after the (absent) seeds and debug authority.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let stop = match unsafe { ipc::bootstrap::request_slots::<1>(info.creator_endpoint, ipc_buf) }
    {
        Ok([cap]) if cap != 0 => cap,
        _ =>
        {
            std::os::seraph::log!(error: "no stop authority delivered; stopping nothing");
            syscall::thread_exit();
        }
    };
    let Some(pressure) = std::os::seraph::memory_pressure_notification()
    else
    {
        std::os::seraph::log!(error: "no memory-pressure registration; stopping nothing");
        syscall::thread_exit();
    };
    let config = config();
    let _ = now_ms();
    std::os::seraph::thread::touch_stack::<STACK_TOUCH_BYTES>();
    touch_heap();
    // A walk receives at most a page of sources' caps beside the one it
    // keeps; with this much headroom no walk grows the CSpace.
    if !std::os::seraph::fund_cspace_slot_budget(info.self_cspace, source::WALK_CAPS_MAX as u64)
    {
        std::os::seraph::log!(warn: "CSpace headroom for a walk not funded");
    }
    let mode = match config.mode
    {
        Mode::Stop => "stopping",
        Mode::Advise => "advising only (OOMD_STOP=no)",
    };
    std::os::seraph::log!(
        "watching memory: {mode} after {} ms critical, one per {} ms",
        config.grace_ms,
        config.cooldown_ms
    );
    serve(config, pressure, stop, ipc_buf)
}

/// oomd's configuration from its environment, each setting that is clamped
/// or does not parse logged.
fn config() -> Config
{
    let grace = policy::parse_ms(
        std::env::var("OOMD_GRACE_MS").ok().as_deref(),
        policy::GRACE_DEFAULT_MS,
    );
    warn_ms("OOMD_GRACE_MS", grace);
    let cooldown = policy::parse_ms(
        std::env::var("OOMD_COOLDOWN_MS").ok().as_deref(),
        policy::COOLDOWN_DEFAULT_MS,
    );
    warn_ms("OOMD_COOLDOWN_MS", cooldown);
    let stop = policy::parse_stop(std::env::var("OOMD_STOP").ok().as_deref());
    if stop.read == Read::Invalid
    {
        std::os::seraph::log!(warn: "OOMD_STOP is neither yes nor no; advising only");
    }
    Config {
        grace_ms: grace.value,
        cooldown_ms: cooldown.value,
        mode: stop.value,
    }
}

/// Log the duration setting `name` when it was clamped or did not parse.
fn warn_ms(name: &str, setting: policy::Setting<u64>)
{
    match setting.read
    {
        Read::Invalid =>
        {
            std::os::seraph::log!(
                warn: "{name} is not a number of milliseconds; {} ms",
                setting.value
            );
        }
        Read::Clamped =>
        {
            std::os::seraph::log!(warn: "{name} clamped to {} ms", setting.value);
        }
        Read::Given | Read::Absent =>
        {}
    }
}

/// Follow the level for good: take each reading into the ladder, log each
/// change, act on each act it asks for, and wait for a change of the level
/// or the next act's deadline.
fn serve(config: Config, pressure: u64, authority: u64, ipc_buf: *mut u64) -> !
{
    let mut ladder = Ladder::new(config);
    // A change signalled before now is in the level read here.
    let _ = syscall::notification_try_wait(pressure);
    let mut level = read_level();
    loop
    {
        let step = ladder.observe(now_ms(), level);
        if let Some(transition) = step.transition
        {
            log_transition(transition);
        }
        if let Some(act) = step.act
        {
            act_on(act, authority, ipc_buf);
        }
        // 0 waits without bound; a deadline due within the millisecond
        // waits one.
        let timeout = ladder
            .next_deadline()
            .map_or(0, |at| at.saturating_sub(now_ms()).max(1));
        match syscall::notification_wait_timeout(pressure, timeout)
        {
            // A change of level, an opening of the draw room, or the deadline
            // (no bits): the level is read below.
            Ok(_) =>
            {}
            Err(e)
                if e == SyscallError::WouldBlock as i64
                    || e == SyscallError::Interrupted as i64 =>
            {}
            Err(e) =>
            {
                std::os::seraph::log!(warn: "pressure wait failed (err={e})");
                std::thread::sleep(std::time::Duration::from_millis(WAIT_RETRY_MS));
            }
        }
        level = read_level();
    }
}

/// Log the change `transition` of the level.
fn log_transition(transition: Transition)
{
    match transition
    {
        Transition::Began(Level::Critical) | Transition::Critical =>
        {
            std::os::seraph::log!("memory critical");
        }
        Transition::Began(_) =>
        {
            std::os::seraph::log!("memory low");
        }
        Transition::Eased { critical_ms } =>
        {
            std::os::seraph::log!("memory low after {critical_ms} ms critical");
        }
        Transition::Ended { episode_ms } =>
        {
            std::os::seraph::log!("memory normal after {episode_ms} ms");
        }
    }
}

/// Act on `act`: walk the stop sources svcmgr lists on the stop authority
/// `stop`, and svcmgr's own candidates, and stop the candidate stopped first,
/// or with `OOMD_STOP=no` name it, while the level still reads `CRITICAL`.
/// The stop is made before its line is logged, so a log write that waits
/// does not delay it. The cap of the candidate's source is released after.
fn act_on(act: Act, stop: u64, ipc_buf: *mut u64)
{
    let Some((order, candidate)) = source::walk(stop, ipc_buf)
    else
    {
        if act.first
        {
            std::os::seraph::log!(
                "memory critical for {} ms: nothing to stop",
                act.critical_ms
            );
        }
        return;
    };
    // The walk takes calls to each source: a level that fell meanwhile needs
    // no stop.
    if read_level() != Level::Critical
    {
        candidate.release();
        return;
    }
    let name = candidate.name();
    let pages = order.pages;
    let critical_ms = act.critical_ms;
    match act.mode
    {
        Mode::Advise =>
        {
            std::os::seraph::log!(
                "would stop {name}: {pages} pages, memory critical for {critical_ms} ms \
                 (OOMD_STOP=no)"
            );
        }
        Mode::Stop => match source::stop(&candidate, ipc_buf)
        {
            Ok(()) =>
            {
                std::os::seraph::log!(
                    "stopped {name}: {pages} pages, memory critical for {critical_ms} ms"
                );
            }
            Err(why) =>
            {
                std::os::seraph::log!(warn: "stop of {name} failed: {why}");
            }
        },
    }
    candidate.release();
}

/// memmgr's level; [`Level::Unknown`] when memmgr does not answer.
fn read_level() -> Level
{
    match std::os::seraph::memory_pressure()
    {
        Some(std::os::seraph::MemoryPressure::Normal) => Level::Normal,
        Some(std::os::seraph::MemoryPressure::Low) => Level::Low,
        Some(std::os::seraph::MemoryPressure::Critical) => Level::Critical,
        Some(_) | None => Level::Unknown,
    }
}

/// Milliseconds since oomd first asked, which `main` does before its
/// touches, so the clock's state is made before memory can run out.
fn now_ms() -> u64
{
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Touch [`HEAP_TOUCH_BYTES`] of heap and free them: the allocator keeps
/// the pages.
fn touch_heap()
{
    drop(std::hint::black_box(vec![1u8; HEAP_TOUCH_BYTES]));
}
