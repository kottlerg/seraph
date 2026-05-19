// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Threading / per-thread state surface: Mutex+Arc multi-threading,
//! per-thread stdio IPC buffer, per-thread allocator grows, the
//! `thread_local!` macro, and `Condvar::wait_timeout`.

use std::cell::Cell;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "threading",
            run: threading_phase,
        },
        Phase {
            name: "stdio_spawned",
            run: stdio_spawned_phase,
        },
        Phase {
            name: "alloc_spawned",
            run: alloc_spawned_phase,
        },
        Phase {
            name: "tls_macro",
            run: tls_macro_phase,
        },
        Phase {
            name: "timeout",
            run: timeout_phase,
        },
    ]
}

pub fn threading_phase(_: &Caps)
{
    const ITERS: u32 = 1_000;
    let counter = Arc::new(Mutex::new(0u32));

    let handles: Vec<_> = (0..2)
        .map(|_| {
            let c = counter.clone();
            thread::spawn(move || {
                for _ in 0..ITERS
                {
                    let mut guard = c.lock().expect("mutex poisoned");
                    *guard += 1;
                }
            })
        })
        .collect();

    for h in handles
    {
        h.join().expect("worker thread panicked");
    }

    let final_value = *counter.lock().expect("mutex poisoned");
    std::os::seraph::log!(
        "threading workers joined, counter={:#018x} expected={:#018x}",
        u64::from(final_value),
        u64::from(2 * ITERS),
    );
    assert_eq!(
        final_value,
        2 * ITERS,
        "threading test: counter mismatch (expected {})",
        2 * ITERS
    );
    std::os::seraph::log!("threading phase passed");
}

pub fn stdio_spawned_phase(_: &Caps)
{
    let handle = thread::spawn(|| {
        std::os::seraph::log!("stdio_spawned marker line");
    });
    handle.join().expect("stdio_spawned worker thread panicked");
    std::os::seraph::log!("stdio_spawned phase passed");
}

#[allow(clippy::cast_possible_truncation)]
pub fn alloc_spawned_phase(_: &Caps)
{
    const BIG: usize = 600 * 1024;

    let handle = thread::spawn(|| {
        let mut v: Vec<u8> = Vec::with_capacity(BIG);
        for i in 0..BIG
        {
            v.push((i & 0xFF) as u8);
        }
        assert_eq!(v.len(), BIG, "spawned-grow push count mismatch");
        for &idx in &[0, 4095, 4096, 65_535, BIG / 2, BIG - 1]
        {
            let expected = (idx & 0xFF) as u8;
            assert_eq!(v[idx], expected, "spawned-grow buffer[{idx}] mismatch");
        }
    });
    handle.join().expect("alloc_spawned worker thread panicked");
    std::os::seraph::log!("alloc_spawned phase passed ({BIG} bytes)");
}

pub fn tls_macro_phase(_: &Caps)
{
    std::thread_local! {
        static COUNTER: Cell<Vec<u32>> = const { Cell::new(Vec::new()) };
    }

    COUNTER.with(|c| {
        let mut v = c.take();
        for i in 0..8u32
        {
            v.push(i);
        }
        c.set(v);
    });
    let sum: u32 = COUNTER.with(|c| {
        let v = c.take();
        let s = v.iter().sum();
        c.set(v);
        s
    });
    std::os::seraph::log!("thread_local! Vec<u32> sum(0..8)={sum:#018x}");
    assert_eq!(sum, 28, "thread_local! macro sum mismatch");

    let handle = thread::spawn(|| {
        COUNTER.with(|c| {
            let v = c.take();
            let was_empty = v.is_empty();
            let mut w = v;
            w.push(0xAAu32);
            w.push(0xBBu32);
            c.set(w);
            let got: u32 = COUNTER.with(|c2| {
                let v2 = c2.take();
                let s = v2.iter().sum();
                c2.set(v2);
                s
            });
            (was_empty, got)
        })
    });
    let (was_empty, got) = handle.join().expect("tls_macro child panicked");
    assert!(was_empty, "child thread_local! should start empty");
    assert_eq!(got, 0xAAu32 + 0xBBu32, "child thread_local! sum mismatch");
    std::os::seraph::log!("thread_local! child sum={got:#018x}");
    std::os::seraph::log!("thread_local! macro phase passed");
}

pub fn timeout_phase(_: &Caps)
{
    let cv = Condvar::new();
    let m = Mutex::new(());
    let guard = m.lock().expect("mutex poisoned");
    let t0 = Instant::now();
    let (_guard, result) = cv
        .wait_timeout(guard, Duration::from_millis(50))
        .expect("wait_timeout failed");
    let elapsed = t0.elapsed();
    assert!(result.timed_out(), "expected timeout but got early wake");
    assert!(
        elapsed >= Duration::from_millis(40),
        "timeout returned too early: {elapsed:?}",
    );
    std::os::seraph::log!(
        "wait_timeout: timed_out after {:#x} us",
        u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
    );

    let pair: Arc<(Mutex<bool>, Condvar)> = Arc::new((Mutex::new(false), Condvar::new()));
    let pair2 = pair.clone();
    let _notifier = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        let (lock, cv) = &*pair2;
        let mut flag = lock.lock().expect("mutex poisoned");
        *flag = true;
        cv.notify_one();
    });

    let (lock, cv) = &*pair;
    let flag = lock.lock().expect("mutex poisoned");
    let t0 = Instant::now();
    let (flag, result) = cv
        .wait_timeout_while(flag, Duration::from_secs(1), |f| !*f)
        .expect("wait_timeout_while failed");
    let elapsed = t0.elapsed();
    assert!(*flag, "notifier flag not set on wake");
    assert!(
        !result.timed_out(),
        "wait woke but wait_timeout_while reports timeout",
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "notify did not wake early: {elapsed:?}",
    );
    std::os::seraph::log!(
        "wait_timeout: notified after {:#x} us",
        u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
    );
    std::os::seraph::log!("timeout phase passed");
}
