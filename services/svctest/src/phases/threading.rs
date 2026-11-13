// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/threading.rs

//! Threading / per-thread state surface: Mutex+Arc multi-threading,
//! per-thread stdio IPC buffer, per-thread allocator grows, the
//! `thread_local!` macro and its destructors at a spawned thread's exit, a
//! spawned thread's identity and park/unpark through its handle, `RwLock`
//! wakes for several queued readers and its non-blocking paths, `Condvar`
//! `notify_all` and `Once` completion waking every queued waiter, a timed
//! `Condvar` waiter leaving the middle of the queue, `Condvar::wait_timeout`,
//! sustained contended handoffs of `Mutex`, `Condvar`, and `RwLock`,
//! spawn-time placement through `BuilderExt::spawn_at_priority`, and the
//! byte heap's lock contended by a strict-priority thread against a
//! fair-class holder on the same CPU.

use std::cell::Cell;
use std::io;
use std::os::seraph::thread::BuilderExt;
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
        Phase {
            name: "sync_handoff_stress",
            run: sync_handoff_stress_phase,
        },
        Phase {
            name: "spawn_at_priority",
            run: spawn_at_priority_phase,
        },
        Phase {
            name: "heap_lock_priority_contention",
            run: heap_lock_priority_contention_phase,
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
                    *guard = guard.checked_add(1).expect("mutex counter overflowed");
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

#[expect(
    clippy::cast_possible_truncation,
    reason = "every cast to u8 in the phase takes an index masked to its low byte, so none drops a \
              bit"
)]
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
            assert_eq!(
                *v.get(idx)
                    .expect("spawned-grow buffer index within the pushed length"),
                expected,
                "spawned-grow buffer[{idx}] mismatch"
            );
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
                state.0 = state
                    .0
                    .checked_add(1)
                    .expect("condvar waiter count overflowed");
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
            state.queued = state
                .queued
                .checked_add(1)
                .expect("queued waiter count overflowed");
            let mut state = cv
                .wait_while(state, |s| s.tokens == 0)
                .expect("mutex poisoned");
            state.tokens = state
                .tokens
                .checked_sub(1)
                .expect("a waiter woke with no token to take");
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
            state.queued = state
                .queued
                .checked_add(1)
                .expect("queued waiter count overflowed");
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
        .recv_timeout(
            TIMED_WAIT
                .checked_add(FANOUT_BOUND)
                .expect("timed wait plus fanout bound overflowed"),
        )
        .expect("condvar_timed_middle_waiter: the timed waiter never returned");
    assert!(timed_out, "the timed waiter was woken with no notify");
    timed.join().expect("condvar timed waiter panicked");

    let (lock, cv) = &*shared;
    for i in 0..waiters.len()
    {
        {
            let mut state = lock.lock().expect("mutex poisoned");
            state.tokens = state.tokens.checked_add(1).expect("token count overflowed");
        }
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

/// How long `sync_handoff_stress` waits for one of its workers to report: far
/// over its whole run, a few seconds on slow TCG.
const STRESS_BOUND: Duration = Duration::from_mins(1);

/// Spawn `f` on a new thread that reports on `done` once `f` returns.
fn spawn_reporting<F>(done: &mpsc::Sender<()>, f: F) -> thread::JoinHandle<()>
where
    F: FnOnce() + Send + 'static,
{
    let done = done.clone();
    thread::spawn(move || {
        f();
        let _ = done.send(());
    })
}

/// Wait for one report on `reports` per handle, failing after
/// [`STRESS_BOUND`] for any one, then join every handle. A lost wake leaves a
/// worker parked for good, so the bound turns that hang into a failure that
/// names `what`.
fn await_workers(what: &str, reports: &mpsc::Receiver<()>, handles: Vec<thread::JoinHandle<()>>)
{
    for i in 0..handles.len()
    {
        reports.recv_timeout(STRESS_BOUND).unwrap_or_else(|_| {
            panic!(
                "{what}: only {i} of {} workers finished; a wake was lost",
                handles.len()
            )
        });
    }
    for h in handles
    {
        h.join()
            .unwrap_or_else(|_| panic!("{what}: a worker panicked"));
    }
}

/// Sustained contended handoffs of `Mutex`, `Condvar`, and `RwLock`, each
/// worker's completion bounded so a lost wake fails the phase rather than
/// hanging it.
pub fn sync_handoff_stress_phase(_: &Caps)
{
    mutex_handoff_stress();
    condvar_ping_pong_stress();
    rwlock_handoff_stress();
    std::os::seraph::log!("sync_handoff_stress phase passed");
}

/// Workers increment one `Mutex` counter, each yielding with the lock held
/// every few increments so the others spin out and park on it. Every
/// increment lands, and every parked waiter is woken by an unlock.
fn mutex_handoff_stress()
{
    const THREADS: u32 = 4;
    const ITERS: u32 = 2_000;
    const YIELD_EVERY: u32 = 8;

    let counter = Arc::new(Mutex::new(0u32));
    let (done, reports) = mpsc::channel();
    let handles = (0..THREADS)
        .map(|_| {
            let counter = counter.clone();
            spawn_reporting(&done, move || {
                for i in 0..ITERS
                {
                    let mut guard = counter.lock().expect("mutex poisoned");
                    *guard = guard.checked_add(1).expect("mutex counter overflowed");
                    if i % YIELD_EVERY == 0
                    {
                        thread::yield_now();
                    }
                }
            })
        })
        .collect();
    await_workers("mutex handoff", &reports, handles);
    let total = *counter.lock().expect("mutex poisoned");
    assert_eq!(
        total,
        THREADS * ITERS,
        "mutex handoff: increments lost under contention"
    );
}

/// Two threads hand a turn back and forth through one `Condvar` with
/// `notify_one`, each waiting for its own turn: every notify reaches the one
/// waiter, or the exchange stops.
fn condvar_ping_pong_stress()
{
    const ROUNDS: u32 = 1_000;

    // (whose turn, 0 or 1; handoffs made) under one mutex.
    let shared = Arc::new((Mutex::new((0u32, 0u32)), Condvar::new()));
    let (done, reports) = mpsc::channel();
    let handles = (0..2u32)
        .map(|me| {
            let shared = shared.clone();
            spawn_reporting(&done, move || {
                let (lock, cv) = &*shared;
                for _ in 0..ROUNDS
                {
                    let state = lock.lock().expect("mutex poisoned");
                    let mut state = cv.wait_while(state, |s| s.0 != me).expect("mutex poisoned");
                    state.0 = me ^ 1;
                    state.1 = state.1.checked_add(1).expect("handoff count overflowed");
                    drop(state);
                    cv.notify_one();
                }
            })
        })
        .collect();
    await_workers("condvar ping-pong", &reports, handles);
    let handoffs = shared.0.lock().expect("mutex poisoned").1;
    assert_eq!(handoffs, 2 * ROUNDS, "condvar ping-pong: handoffs lost");
}

/// Writers bump a pair of counters together under the write lock, yielding
/// between the two stores every few writes, while readers, yielding between
/// reads, check under the read lock that the pair is equal. No reader sees a
/// write in progress, every write lands, and no queued reader or writer is
/// stranded.
fn rwlock_handoff_stress()
{
    const WRITERS: u32 = 2;
    const READERS: u32 = 2;
    const WRITES: u32 = 1_000;
    const READS: u32 = 2_000;
    const YIELD_EVERY: u32 = 4;

    let pair = Arc::new(RwLock::new((0u32, 0u32)));
    let (done, reports) = mpsc::channel();
    let writers = (0..WRITERS).map(|_| {
        let pair = pair.clone();
        spawn_reporting(&done, move || {
            for i in 0..WRITES
            {
                let mut guard = pair.write().expect("rwlock poisoned");
                guard.0 = guard.0.checked_add(1).expect("write count overflowed");
                if i % YIELD_EVERY == 0
                {
                    thread::yield_now();
                }
                guard.1 = guard.1.checked_add(1).expect("write count overflowed");
            }
        })
    });
    let readers = (0..READERS).map(|_| {
        let pair = pair.clone();
        spawn_reporting(&done, move || {
            for _ in 0..READS
            {
                let guard = pair.read().expect("rwlock poisoned");
                assert_eq!(guard.0, guard.1, "rwlock: a reader saw a write in progress");
                drop(guard);
                thread::yield_now();
            }
        })
    });
    let handles = writers.chain(readers).collect();
    await_workers("rwlock handoff", &reports, handles);
    let (a, b) = *pair.read().expect("rwlock poisoned");
    assert_eq!(
        (a, b),
        (WRITERS * WRITES, WRITERS * WRITES),
        "rwlock handoff: writes lost under contention"
    );
}

/// `BuilderExt::spawn_at_priority` refuses a level of 0 before any spawn and
/// fails a level above the band at the kernel's refusal, and neither leaves
/// the thread-local spawn level behind: a plain `Builder::spawn` after both
/// places its child at the process's own level and runs, where a stale level
/// above the band would make the kernel refuse it too. A level within the
/// band spawns and runs.
pub fn spawn_at_priority_phase(_: &Caps)
{
    // svctest.svc gives svctest `priority = 10` and `sched_max = 21`: the band
    // is [1, 21] and its initial thread runs at 10.
    const INITIAL_LEVEL: u8 = 10;
    const BAND_MAX: u8 = 21;
    let info = std::os::seraph::startup_info();
    assert_ne!(
        info.sched_control_cap, 0,
        "svctest holds no SchedControl cap"
    );
    assert_eq!(
        info.initial_priority, INITIAL_LEVEL,
        "svctest's initial level is not its recipe's"
    );

    match thread::Builder::new().spawn_at_priority(0, || ())
    {
        Err(e) => assert_eq!(
            e.kind(),
            io::ErrorKind::InvalidInput,
            "level 0 refused with the wrong kind: {e}"
        ),
        Ok(_) => panic!("spawn_at_priority(0) spawned a thread"),
    }
    assert!(
        thread::Builder::new()
            .spawn_at_priority(BAND_MAX + 1, || ())
            .is_err(),
        "spawn_at_priority({}) above the band spawned a thread",
        BAND_MAX + 1
    );

    let plain = thread::Builder::new()
        .spawn(|| 7u32)
        .expect("plain spawn after the refusals failed: stale spawn level");
    assert_eq!(plain.join().expect("plain child panicked"), 7);

    let within = thread::Builder::new()
        .spawn_at_priority(5, || 5u32)
        .expect("spawn_at_priority(5) within the band failed");
    assert_eq!(within.join().expect("level-5 child panicked"), 5);
    std::os::seraph::log!("spawn_at_priority phase passed");
}

/// Pin the calling thread to `cpu` and yield, so the pin takes effect before
/// the caller goes on (a running thread moves at its next schedule).
fn pin_self(cpu: u32)
{
    let cap = std::os::seraph::thread::current_thread_cap();
    assert_ne!(cap, 0, "no Thread cap for the calling thread");
    syscall::thread_set_affinity(cap, cpu)
        .unwrap_or_else(|e| panic!("thread_set_affinity({cpu}) failed: {e}"));
    thread::yield_now();
}

/// A strict-priority thread contending for the byte heap's lock with a
/// fair-class thread that allocates in a loop on the same CPU still finishes,
/// and the allocating thread still runs.
///
/// The kernel runs a CPU's strict-priority thread before any fair one
/// (core/kernel/docs/scheduler.md § Scheduling Classes). Each time the
/// waiter wakes from its sleep, it preempts the allocating thread at the
/// next tick, often while that thread holds the heap lock. The holder can
/// release the lock only if the waiter leaves the CPU, which std's
/// `SpinMutex` does by sleeping once its spin bound is spent. A waiter that
/// only spun would hold the CPU forever, and this phase would never end.
pub fn heap_lock_priority_contention_phase(_: &Caps)
{
    // Generous over the phase's time, a few seconds on slow TCG.
    const BOUND: Duration = Duration::from_mins(1);

    let cpus = syscall::system_info(syscall_abi::SystemInfoType::CpuCount as u64)
        .expect("CPU count query failed");
    // The highest CPU: away from CPU 0, which the boot's own threads favour.
    let cpu = u32::try_from(cpus.saturating_sub(1)).expect("CPU index above u32");

    let stop = Arc::new(AtomicBool::new(false));
    let holder = spawn_allocating_holder(cpu, Arc::clone(&stop));
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let waiter = spawn_contending_waiter(cpu, done_tx);

    let finished = done_rx.recv_timeout(BOUND);
    stop.store(true, Ordering::Relaxed);
    assert!(
        finished.is_ok(),
        "level-{CONTENDER_LEVEL} waiter did not finish {CONTENDER_ROUNDS} heap allocations \
         against a same-CPU fair-class allocator within {BOUND:?}"
    );
    waiter.join().expect("waiter panicked");
    let allocations = holder.join().expect("allocating thread panicked");
    std::os::seraph::log!(
        "heap_lock_priority_contention: cpu {} waiter rounds {} holder allocations {:#x}",
        u64::from(cpu),
        u64::from(CONTENDER_ROUNDS),
        allocations
    );
    std::os::seraph::log!("heap_lock_priority_contention phase passed");
}

/// The contending waiter's level: the floor of the strict-priority class, and
/// the top of svctest's band (svctest.svc's `sched_max`). The allocating
/// thread runs at svctest's initial level, 10, in the fair class.
const CONTENDER_LEVEL: u8 = 21;

/// Wake-and-allocate rounds of the contending waiter.
const CONTENDER_ROUNDS: u32 = 100;

/// Spawn the fair-class thread that allocates and frees in a loop on `cpu`
/// until `stop` is set, returning its allocation count; returns once it is
/// pinned.
fn spawn_allocating_holder(cpu: u32, stop: Arc<AtomicBool>) -> thread::JoinHandle<u64>
{
    let (pinned_tx, pinned_rx) = mpsc::channel::<()>();
    let holder = thread::spawn(move || {
        pin_self(cpu);
        pinned_tx.send(()).expect("pinned signal lost");
        let mut allocations = 0u64;
        while !stop.load(Ordering::Relaxed)
        {
            // Sizes vary so the first-fit walk does real work under the lock.
            let v: Vec<u8> = Vec::with_capacity(
                64usize
                    .checked_add((allocations % 1024) as usize)
                    .expect("allocation size overflowed"),
            );
            std::hint::black_box(&v);
            drop(v);
            allocations = allocations
                .checked_add(1)
                .expect("allocation count overflowed");
        }
        allocations
    });
    pinned_rx
        .recv()
        .expect("allocating thread ended before pinning");
    holder
}

/// Spawn the [`CONTENDER_LEVEL`] thread that, pinned to `cpu`, sleeps 1 ms
/// and allocates [`CONTENDER_ROUNDS`] times, then signals `done`.
fn spawn_contending_waiter(cpu: u32, done: mpsc::Sender<()>) -> thread::JoinHandle<()>
{
    thread::Builder::new()
        .spawn_at_priority(CONTENDER_LEVEL, move || {
            pin_self(cpu);
            for round in 0..CONTENDER_ROUNDS
            {
                let _ = syscall::thread_sleep(1);
                let b = Box::new(round);
                std::hint::black_box(&b);
            }
            done.send(()).expect("done signal lost");
        })
        .expect("spawn_at_priority of the contending waiter failed")
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
