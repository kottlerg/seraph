// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/entropyd/src/main.rs

//! Seraph entropy contributor.
//!
//! Holds the one `EntropyControl` capability svcmgr gives (recipe key
//! `entropy_authority = yes`) and the `hwrng` class SEND its recipe seeds.
//! At start and then every [`PACE`], it walks the class's ordinals with
//! [`devmgr_labels::QUERY_DEVICE`](ipc::devmgr_labels::QUERY_DEVICE), asks
//! each live driver for [`READ_BYTES`] bytes with
//! [`hwrng_protocol::READ`], and mixes them into the kernel pool with
//! `SYS_ENTROPY_CONTRIBUTE`, which gives them no entropy credit. While the
//! class serves no live driver it waits on a
//! [`WATCH_CLASS`](ipc::devmgr_labels::WATCH_CLASS) watch. The figures and
//! what entropyd never does are specified in `services/entropyd/README.md`.

use std::time::Duration;

use ipc::{ClassCallError, IpcMessage, devmgr_errors};
use std::os::seraph::startup_info;

/// The time between two contribution passes while the class serves a live
/// driver. See the README's § Pacing.
const PACE: Duration = Duration::from_secs(10);

/// The bytes asked of each driver per pass, and contributed in one call: one
/// absorb under the pool's 136-byte sponge rate, and below
/// `MAX_ENTROPY_CONTRIBUTE_LEN` (256). See the README's § Pacing.
const READ_BYTES: usize = 64;

const _: () = assert!(READ_BYTES <= hwrng_protocol::MAX_READ_BYTES);
const _: () = assert!(READ_BYTES <= syscall_abi::MAX_ENTROPY_CONTRIBUTE_LEN);

/// The bound on one `READ` call: the driver answers within its own 1 s wait
/// bound, so twice that leaves its reply room and keeps a driver that never
/// answers from stalling the pass.
const READ_TIMEOUT_MS: u64 = 2_000;

/// The line logged on the first contribution the kernel accepts, which
/// svctest's `entropyd_contribution` phase awaits.
const FIRST_LINE: &str = "entropy contribution accepted";

// ── Bootstrap ──────────────────────────────────────────────────────────────

struct BootCaps
{
    /// `devmgr.class.hwrng`: the `hwrng` class SEND.
    hwrng_class: u64,
    /// The `EntropyControl` capability carrying `Contribute`.
    entropy: u64,
}

/// Take the bootstrap round: the class SEND the recipe seeds, then the
/// `EntropyControl` copy svcmgr derives for the `entropy_authority` service.
/// Both slots are required.
fn bootstrap_caps(creator_endpoint: u64, ipc_buf: *mut u64) -> Option<BootCaps>
{
    if creator_endpoint == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    // Only the present caps ride, named by each round's presence word; an
    // absent slot decodes as `0`.
    let [hwrng_class, entropy] =
        unsafe { ipc::bootstrap::request_slots::<2>(creator_endpoint, ipc_buf) }.ok()?;
    if hwrng_class == 0 || entropy == 0
    {
        return None;
    }
    Some(BootCaps {
        hwrng_class,
        entropy,
    })
}

// ── One pass ───────────────────────────────────────────────────────────────

/// What a pass found.
struct Pass
{
    /// The live drivers it reached, whether or not each yielded bytes.
    live: usize,
}

/// Why a driver yielded no contribution, for the failure log.
enum Failure
{
    /// `QUERY_DEVICE` refused other than `WITHDRAWN` or `NO_DEVICE`, or failed.
    Query(ClassCallError),
    /// The `READ` call failed or timed out, with this syscall error.
    Call(i64),
    /// The driver replied this label other than `SUCCESS`.
    Refused(u64),
    /// The `SUCCESS` reply's words do not decode.
    Malformed,
    /// `SYS_ENTROPY_CONTRIBUTE` failed with this error.
    Contribute(i64),
}

/// The failure and contribution log state across passes: one line for the
/// first accepted contribution, and one for the first failure of each run of
/// failures, so a driver that keeps failing does not flood the log.
#[derive(Default)]
struct Log
{
    accepted: bool,
    failing: bool,
}

impl Log
{
    fn accepted(&mut self, ordinal: u64, bytes: usize)
    {
        if !self.accepted
        {
            std::os::seraph::log!("{FIRST_LINE}: {bytes} bytes from hwrng ordinal {ordinal}");
            self.accepted = true;
        }
        self.failing = false;
    }

    fn failed(&mut self, ordinal: u64, failure: &Failure)
    {
        if self.failing
        {
            return;
        }
        self.failing = true;
        match failure
        {
            Failure::Query(e) =>
            {
                std::os::seraph::log!(warn: "QUERY_DEVICE at ordinal {ordinal} failed: {e:?}");
            }
            Failure::Call(e) =>
            {
                std::os::seraph::log!(warn: "READ at hwrng ordinal {ordinal} failed (err={e})");
            }
            Failure::Refused(label) =>
            {
                std::os::seraph::log!(warn: "READ at hwrng ordinal {ordinal} refused ({label})");
            }
            Failure::Malformed =>
            {
                std::os::seraph::log!(warn: "READ at hwrng ordinal {ordinal}: malformed reply");
            }
            Failure::Contribute(e) =>
            {
                std::os::seraph::log!(warn: "entropy contribution refused (err={e})");
            }
        }
    }
}

/// Read [`READ_BYTES`] from the driver `driver` and contribute them through
/// `entropy`. Returns the bytes contributed, which may be fewer than asked
/// when the device produced fewer.
fn feed(driver: u64, entropy: u64, ipc_buf: *mut u64) -> Result<usize, Failure>
{
    let request = IpcMessage::builder(hwrng_protocol::READ)
        .word(0, READ_BYTES as u64)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call_timeout(driver, &request, ipc_buf, READ_TIMEOUT_MS) }
        .map_err(Failure::Call)?;
    if reply.label != hwrng_protocol::errors::SUCCESS
    {
        return Err(Failure::Refused(reply.label));
    }
    let mut bytes = [0u8; READ_BYTES];
    let result = match hwrng_protocol::decode_reply(reply.words(), &mut bytes)
    {
        Some(count) => bytes.get(..count).map_or(Err(Failure::Malformed), |taken| {
            syscall::entropy_contribute(entropy, taken)
                .map(|()| count)
                .map_err(Failure::Contribute)
        }),
        None => Err(Failure::Malformed),
    };
    // Best effort: the bytes are the pool's now, so entropyd keeps no copy it
    // can help. The reply's own copy is overwritten by the next call.
    bytes.fill(0);
    std::hint::black_box(&mut bytes);
    result
}

/// Walk the class's ordinals from 0: pass a `WITHDRAWN` ordinal, stop at
/// `NO_DEVICE` (past the last served driver) or any other refusal, and feed
/// each live driver once. The driver's SEND is deleted after its read, so
/// entropyd holds no driver cap between passes.
fn pass(caps: &BootCaps, ipc_buf: *mut u64, log: &mut Log) -> Pass
{
    let mut found = Pass { live: 0 };
    let mut ordinal = 0u64;
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        match unsafe { ipc::query_device(caps.hwrng_class, ordinal, ipc_buf) }
        {
            Ok(driver) =>
            {
                found.live = found.live.saturating_add(1);
                match feed(driver, caps.entropy, ipc_buf)
                {
                    Ok(bytes) => log.accepted(ordinal, bytes),
                    Err(failure) => log.failed(ordinal, &failure),
                }
                let _ = syscall::cap_delete(driver);
            }
            Err(ClassCallError::Refused(devmgr_errors::WITHDRAWN)) =>
            {}
            Err(ClassCallError::Refused(devmgr_errors::NO_DEVICE)) => return found,
            Err(e) =>
            {
                log.failed(ordinal, &Failure::Query(e));
                return found;
            }
        }
        let Some(next) = ordinal.checked_add(1)
        else
        {
            return found;
        };
        ordinal = next;
    }
}

// ── Entry ──────────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"entropyd");
    let info = startup_info();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(caps) = bootstrap_caps(info.creator_endpoint, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "bootstrap missing caps");
        syscall::thread_exit();
    };

    // Registered before the first pass, so a driver served after the pass's
    // last query signals it.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let watch = match unsafe { ipc::watch_class(caps.hwrng_class, ipc_buf) }
    {
        Ok(watch) => Some(watch),
        Err(e) =>
        {
            std::os::seraph::log!(warn: "WATCH_CLASS failed ({e:?}); no driver served later is fed");
            None
        }
    };

    let mut log = Log::default();
    loop
    {
        if pass(&caps, ipc_buf, &mut log).live != 0
        {
            std::thread::sleep(PACE);
            continue;
        }
        // No live driver: wait for the class to change, never polling
        // QUERY_DEVICE (devmgr_errors::NO_DEVICE).
        let Some(watch) = watch
        else
        {
            std::os::seraph::log!("no hwrng driver and no class watch; exiting");
            syscall::thread_exit();
        };
        loop
        {
            match syscall::notification_wait_timeout(watch.note, 0)
            {
                Ok(_) => break,
                Err(e) if e == syscall_abi::SyscallError::Interrupted as i64 =>
                {}
                Err(e) =>
                {
                    std::os::seraph::log!(error: "class watch wait failed (err={e}); exiting");
                    std::process::exit(1);
                }
            }
        }
    }
}
