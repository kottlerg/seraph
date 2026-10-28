// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/threading.rs

//! Threading / per-thread state surface: Mutex+Arc multi-threading,
//! per-thread stdio IPC buffer, per-thread allocator grows, the
//! `thread_local!` macro and its destructors at a spawned thread's exit, a
//! spawned thread's identity and park/unpark through its handle, `RwLock`
//! wakes for several queued readers and its non-blocking paths, `Condvar`
//! `notify_all` and `Once` completion waking every queued waiter, a timed
//! `Condvar` waiter leaving the middle of the queue, and
//! `Condvar::wait_timeout`.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
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
            name: "thread_identity",
            run: thread_identity_phase,
        },
        Phase {
            name: "tls_destructors",
            run: tls_destructors_phase,
        },
        Phase {
            name: "rwlock_queued_readers",
            run: rwlock_queued_readers_phase,
        },
        Phase {
            name: "condvar_notify_all_fanout",
            run: condvar_notify_all_fanout_phase,
        },
        Phase {
            name: "once_waiter_fanout",
            run: once_waiter_fanout_phase,
        },
        Phase {
            name: "condvar_timed_middle_waiter",
            run: condvar_timed_middle_waiter_phase,
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

/// A spawned thread's `thread::current()` is the thread its `JoinHandle`
/// names: the same id, the `Builder` name, and the Parker that
/// `JoinHandle::thread().unpark()` releases.
pub fn thread_identity_phase(_: &Caps)
{
    // The child parks for at most `BOUND`; the unpark lands at about 50 ms,
    // so a wake later than `WOKEN_BY` means the unpark was lost and the park
    // ran out its timeout.
    const BOUND: Duration = Duration::from_secs(5);
    const WOKEN_BY: Duration = Duration::from_secs(1);

    let released = Arc::new(AtomicBool::new(false));
    let child_released = released.clone();
    let handle = thread::Builder::new()
        .name("svctest-identity".into())
        .spawn(move || {
            let me = thread::current();
            let start = Instant::now();
            // Park until the main thread's unpark through the handle lands;
            // `park_timeout` bounds the wait so a lost unpark fails the
            // phase instead of hanging it.
            while !child_released.load(Ordering::Acquire)
            {
                let Some(left) = BOUND.checked_sub(start.elapsed())
                else
                {
                    break;
                };
                thread::park_timeout(left);
            }
            (me.id(), me.name().map(String::from), start.elapsed())
        })
        .expect("thread_identity spawn failed");
    let handle_id = handle.thread().id();

    thread::sleep(Duration::from_millis(50));
    released.store(true, Ordering::Release);
    handle.thread().unpark();
    let (child_id, child_name, parked_for) = handle.join().expect("thread_identity child panicked");

    assert_eq!(
        child_id, handle_id,
        "child thread::current().id() differs from its handle's"
    );
    assert_eq!(
        child_name.as_deref(),
        Some("svctest-identity"),
        "Builder name not visible"
    );
    assert!(
        parked_for < WOKEN_BY,
        "unpark through the handle did not wake the child's park"
    );
    std::os::seraph::log!(
        "thread_identity: unparked after {:#x} us",
        u64::try_from(parked_for.as_micros()).unwrap_or(u64::MAX)
    );
    std::os::seraph::log!("thread_identity phase passed");
}

/// A spawned thread's `thread_local!` destructors run when it exits, before
/// `join` returns.
pub fn tls_destructors_phase(_: &Caps)
{
    struct SetOnDrop(Arc<AtomicBool>);
    impl Drop for SetOnDrop
    {
        fn drop(&mut self)
        {
            self.0.store(true, Ordering::Release);
        }
    }
    std::thread_local! {
        static GUARD: Cell<Option<SetOnDrop>> = const { Cell::new(None) };
    }

    let dropped = Arc::new(AtomicBool::new(false));
    let flag = dropped.clone();
    thread::spawn(move || GUARD.with(|g| g.set(Some(SetOnDrop(flag)))))
        .join()
        .expect("tls_destructors child panicked");
    assert!(
        dropped.load(Ordering::Acquire),
        "a spawned thread's thread_local! value was not dropped at exit"
    );
    std::os::seraph::log!("tls_destructors phase passed");
}

/// Two readers queued behind a held write lock both acquire once it is
/// released: each woken waiter passes the wake on, so none is stranded.
pub fn rwlock_queued_readers_phase(_: &Caps)
{
    const READERS: usize = 2;
    const BOUND: Duration = Duration::from_secs(5);

    let lock = Arc::new(RwLock::new(0u32));
    let (acquired, acquisitions) = mpsc::channel();
    let write = lock.write().expect("rwlock poisoned");
    let readers: Vec<_> = (0..READERS)
        .map(|_| {
            let lock = lock.clone();
            let acquired = acquired.clone();
            thread::spawn(move || {
                let value = *lock.read().expect("rwlock poisoned");
                let _ = acquired.send(value);
            })
        })
        .collect();
    // Let both readers reach the contended path and park behind the writer.
    thread::sleep(Duration::from_millis(100));
    drop(write);

    for i in 0..READERS
    {
        let value = acquisitions
            .recv_timeout(BOUND)
            .unwrap_or_else(|_| panic!("queued reader {i} never acquired the read lock"));
        assert_eq!(value, 0, "reader saw a value no writer stored");
    }
    for r in readers
    {
        r.join().expect("rwlock reader panicked");
    }

    // After contended readers and writer, the free lock must still be taken
    // by the non-blocking paths.
    let held = lock
        .try_write()
        .expect("try_write on a free lock after contended readers");
    drop(held);
    let shared = lock.try_read().expect("try_read on a free lock");
    drop(shared);
    std::os::seraph::log!("rwlock_queued_readers phase passed");
}

/// Waiters the fan-out phases queue: more than the 16 wakes a bounded
/// burst on one shared notification would deliver, so a burst strands some.
const FANOUT_WAITERS: usize = 24;

/// How long each fan-out phase waits for one woken waiter to report.
const FANOUT_BOUND: Duration = Duration::from_secs(5);

/// `FANOUT_WAITERS` threads blocked in an untimed `Condvar::wait` all return
/// after one `notify_all`.
pub fn condvar_notify_all_fanout_phase(_: &Caps)
{
    // (threads queued on the condvar, released) under one mutex.
    let shared = Arc::new((Mutex::new((0usize, false)), Condvar::new()));
    let (woke, wakes) = mpsc::channel();
    let waiters: Vec<_> = (0..FANOUT_WAITERS)
        .map(|_| {
            let shared = shared.clone();
            let woke = woke.clone();
            thread::spawn(move || {
                let (lock, cv) = &*shared;
                let mut state = lock.lock().expect("mutex poisoned");
                state.0 += 1;
                // `wait_while` queues this thread before it unlocks the mutex,
                // so a count the main thread reads under the lock counts only
                // queued waiters.
                let state = cv.wait_while(state, |s| !s.1).expect("mutex poisoned");
                drop(state);
                let _ = woke.send(());
            })
        })
        .collect();

    let (lock, cv) = &*shared;
    let start = Instant::now();
    loop
    {
        let mut state = lock.lock().expect("mutex poisoned");
        if state.0 == FANOUT_WAITERS
        {
            state.1 = true;
            cv.notify_all();
            break;
        }
        drop(state);
        assert!(
            start.elapsed() < FANOUT_BOUND,
            "condvar_notify_all_fanout: waiters never all queued"
        );
        thread::sleep(Duration::from_millis(10));
    }

    for i in 0..FANOUT_WAITERS
    {
        wakes
            .recv_timeout(FANOUT_BOUND)
            .unwrap_or_else(|_| panic!("notify_all woke only {i} of {FANOUT_WAITERS} waiters"));
    }
    for w in waiters
    {
        w.join().expect("condvar waiter panicked");
    }
    std::os::seraph::log!("condvar_notify_all_fanout phase passed");
}

/// `FANOUT_WAITERS` threads blocked on a `OnceLock` whose initialiser is
/// running all return once it completes: half wait through `wait`, half
/// through a contending `get_or_init`, the two `Once` waiting paths.
pub fn once_waiter_fanout_phase(_: &Caps)
{
    const VALUE: u32 = 7;

    let cell = Arc::new(OnceLock::new());
    let (started, init_running) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let initialiser = {
        let cell = cell.clone();
        thread::spawn(move || {
            *cell.get_or_init(|| {
                let _ = started.send(());
                let _ = released.recv();
                VALUE
            })
        })
    };
    init_running
        .recv_timeout(FANOUT_BOUND)
        .expect("once_waiter_fanout: initialiser never started");

    let (arriving, arrivals) = mpsc::channel();
    let (got, values) = mpsc::channel();
    let waiters: Vec<_> = (0..FANOUT_WAITERS)
        .map(|i| {
            let cell = cell.clone();
            let arriving = arriving.clone();
            let got = got.clone();
            thread::spawn(move || {
                let _ = arriving.send(());
                let value = if i % 2 == 0
                {
                    *cell.wait()
                }
                else
                {
                    *cell.get_or_init(|| 0)
                };
                let _ = got.send(value);
            })
        })
        .collect();
    for _ in 0..FANOUT_WAITERS
    {
        arrivals
            .recv_timeout(FANOUT_BOUND)
            .expect("once_waiter_fanout: a waiter never started");
    }
    // Let every waiter reach the `Once` and queue behind the initialiser. No
    // API shows a waiter queued, so this is a wait, not a check: a waiter that
    // has not reached the `Once` by the release finds it complete, which
    // weakens the phase on a very slow host rather than failing it.
    thread::sleep(Duration::from_millis(300));
    let _ = release.send(());

    for i in 0..FANOUT_WAITERS
    {
        let value = values.recv_timeout(FANOUT_BOUND).unwrap_or_else(|_| {
            panic!("Once completion woke only {i} of {FANOUT_WAITERS} waiters")
        });
        assert_eq!(
            value, VALUE,
            "a waiter saw a value the initialiser did not store"
        );
    }
    assert_eq!(
        initialiser.join().expect("once initialiser panicked"),
        VALUE,
        "the initialiser's get_or_init returned another value"
    );
    for w in waiters
    {
        w.join().expect("once waiter panicked");
    }
    std::os::seraph::log!("once_waiter_fanout phase passed");
}

/// Shared state of `condvar_timed_middle_waiter`: threads that have queued on
/// the condvar, and wake tokens the main thread has handed out.
#[derive(Default)]
struct MiddleWaiterState
{
    queued: usize,
    tokens: usize,
}

/// Wait until `queued` threads have queued on `cv`, failing after
/// `FANOUT_BOUND`. A waiter counts itself under the lock before it waits, and
/// the wait queues it before unlocking, so the count covers queued waiters only.
fn await_queued(shared: &(Mutex<MiddleWaiterState>, Condvar), queued: usize)
{
    let start = Instant::now();
    while shared.0.lock().expect("mutex poisoned").queued < queued
    {
        assert!(
            start.elapsed() < FANOUT_BOUND,
            "condvar_timed_middle_waiter: {queued} waiters never queued"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

/// A `wait_timeout` waiter queued between untimed waiters times out and
/// leaves the queue from its middle, and one `notify_one` per untimed waiter
/// then wakes each of them: none is lost to a broken link.
pub fn condvar_timed_middle_waiter_phase(_: &Caps)
{
    const UNTIMED_AFTER: usize = 2;
    const TIMED_WAIT: Duration = Duration::from_secs(2);

    let shared = Arc::new((Mutex::new(MiddleWaiterState::default()), Condvar::new()));
    let (woke, wakes) = mpsc::channel();
    let untimed = |shared: Arc<(Mutex<MiddleWaiterState>, Condvar)>, woke: mpsc::Sender<()>| {
        thread::spawn(move || {
            let (lock, cv) = &*shared;
            let mut state = lock.lock().expect("mutex poisoned");
            state.queued += 1;
            let mut state = cv
                .wait_while(state, |s| s.tokens == 0)
                .expect("mutex poisoned");
            state.tokens -= 1;
            drop(state);
            let _ = woke.send(());
        })
    };

    // Queue order: one untimed waiter, the timed one, then the rest untimed.
    let mut waiters = vec![untimed(shared.clone(), woke.clone())];
    await_queued(&shared, 1);
    let (timed_tx, timed_rx) = mpsc::channel();
    let timed = {
        let shared = shared.clone();
        thread::spawn(move || {
            let (lock, cv) = &*shared;
            let mut state = lock.lock().expect("mutex poisoned");
            state.queued += 1;
            let (state, result) = cv
                .wait_timeout_while(state, TIMED_WAIT, |s| s.tokens == 0)
                .expect("mutex poisoned");
            drop(state);
            let _ = timed_tx.send(result.timed_out());
        })
    };
    await_queued(&shared, 2);
    for _ in 0..UNTIMED_AFTER
    {
        waiters.push(untimed(shared.clone(), woke.clone()));
    }
    await_queued(&shared, 2 + UNTIMED_AFTER);
    assert!(
        timed_rx.try_recv().is_err(),
        "condvar_timed_middle_waiter: the timed waiter expired before the later waiters \
         queued, so it did not leave the queue's middle"
    );

    let timed_out = timed_rx
        .recv_timeout(TIMED_WAIT + FANOUT_BOUND)
        .expect("condvar_timed_middle_waiter: the timed waiter never returned");
    assert!(timed_out, "the timed waiter was woken with no notify");
    timed.join().expect("condvar timed waiter panicked");

    let (lock, cv) = &*shared;
    for i in 0..waiters.len()
    {
        lock.lock().expect("mutex poisoned").tokens += 1;
        cv.notify_one();
        wakes.recv_timeout(FANOUT_BOUND).unwrap_or_else(|_| {
            panic!("notify_one {i} woke no waiter after the timed waiter left the queue")
        });
    }
    for w in waiters
    {
        w.join().expect("condvar untimed waiter panicked");
    }
    std::os::seraph::log!("condvar_timed_middle_waiter phase passed");
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
