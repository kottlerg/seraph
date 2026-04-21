// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// base/usertest/src/main.rs

//! Generic userspace test driver.
//!
//! First std-built consumer of the `ruststd` overlay. Exercises the full
//! std bring-up path end-to-end: the `_start` entry in `std::os::seraph`,
//! `println!` through the log endpoint, the `System` allocator over a
//! procmgr-mapped heap, and (P4) `std::thread::spawn` + `std::sync::Mutex`
//! across two worker threads. Failures trigger a panic — our overlay's
//! panic handler exits the thread cleanly, making them visible in the log.
//!
//! Kept deliberately open-ended so new userspace checks can be added here
//! during ongoing work without minting a fresh service each time.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. Every std-built service on
// seraph carries this preamble; RUSTC_BOOTSTRAP=1 (set by xtask for StdUser
// builds) lets the attribute compile without a nightly-tagged toolchain.
#![feature(restricted_std)]
#![feature(thread_local)]
// usertest is an integration test harness: a standalone binary that panics
// on failure so faults surface in the log. `expect`/`unwrap` are the
// intended idiom here (coding-standards §D permits them in test code and §E
// permits narrowly-justified blanket allows).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::cell::Cell;
use std::collections::BTreeMap;
use std::os::seraph::startup_info;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// Native TLS probe statics. `TLS_INIT` is const-initialised (lives in
// `.tdata` of the PT_TLS template) so readback of the initial value
// exercises the template-copy path in procmgr/alloc_thread_tls. `TLS_BSS`
// has no initialiser on the RHS (lives in `.tbss`) so readback exercises
// the zero-fill tail past filesz up to memsz. `TLS_COUNTER` is a Cell so
// we can exercise writes through `%fs:TPOFF`.
#[thread_local]
static TLS_INIT: u64 = 0xDEAD_BEEF_CAFE_BABE;
#[thread_local]
static TLS_BSS: u64 = 0;
#[thread_local]
static TLS_COUNTER: Cell<u32> = Cell::new(0);

fn main()
{
    // std::os::seraph::_start wires log_endpoint + heap from ProcessInfo
    // (universal caps), so `println!` and the System allocator are live on
    // entry. init still serves an empty terminal bootstrap round for
    // protocol parity; we consume it to keep the creator from hanging on a
    // pending REQUEST.
    let info = startup_info();
    if info.creator_endpoint != 0
    {
        // SAFETY: IPC buffer is registered by `_start` and page-aligned by
        // the boot protocol.
        let ipc = unsafe { ipc::IpcBuf::from_bytes(info.ipc_buffer) };
        let _ = ipc::bootstrap::request_round(info.creator_endpoint, ipc);
    }

    println!("usertest: starting");

    args_phase();
    env_phase();
    tls_main_phase();
    alloc_phase();
    churn_phase();
    alloc_grow_phase();
    threading_phase();
    tls_macro_phase();
    timeout_phase();
    spawn_phase();
    stack_overflow_phase();
    shmem_phase();

    println!("usertest: PASS");
}

/// Verify the main-thread stack guard page. Spawns `/bin/stackoverflow`
/// (a deliberate recursive stack consumer), waits for death, and asserts
/// the kernel reported a fault exit reason (`>= 0x1000`, the
/// `EXIT_FAULT_BASE` encoding used by both arches). Confirms that stack
/// overflow lands on `PROCESS_STACK_GUARD_VA` rather than corrupting
/// adjacent mappings.
// cast_sign_loss: ExitStatus::code() returns i32; exit_reason is always
// non-negative in practice (kernel-set 0, clean-exit 0, fault 0x1000+vec,
// killed 0x2000). Casting to u64 is safe.
#[allow(clippy::cast_sign_loss)]
fn stack_overflow_phase()
{
    use std::process::Command;

    // `EXIT_FAULT_BASE` from `syscall_abi` — any fault reports
    // `EXIT_FAULT_BASE + vector`. x86-64 page fault = 0x100E;
    // RISC-V store page fault = 0x100F; load page fault = 0x100D.
    // Accept any fault in the 0x1000..0x2000 range.
    const EXIT_FAULT_BASE: u64 = 0x1000;
    const EXIT_KILLED: u64 = 0x2000;

    let mut child = Command::new("/bin/stackoverflow")
        .spawn()
        .expect("spawn /bin/stackoverflow failed");

    let id = child.id();
    println!("usertest: spawned /bin/stackoverflow handle={id:#x}");

    let status = child.wait().expect("stackoverflow wait failed");
    println!("usertest: stackoverflow exited: {status}");

    assert!(
        !status.success(),
        "stackoverflow child must not exit cleanly: {status}"
    );

    let raw = status
        .code()
        .expect("stackoverflow ExitStatus must carry a code") as u64;
    assert!(
        (EXIT_FAULT_BASE..EXIT_KILLED).contains(&raw),
        "expected fault exit_reason in 0x1000..0x2000, got {raw:#x}"
    );

    println!("usertest: stack_overflow phase passed (exit_reason={raw:#x})");
}

/// Sanity-check the `shmem::SpscRing` in-process: build a ring over a
/// stack-owned byte buffer, push a pattern, pop it back, assert equality.
/// Cross-process integration (pipes) is out of scope; this exercises only
/// the producer/consumer math and the atomic header.
fn shmem_phase()
{
    use shmem::{SpscHeader, SpscReader, SpscWriter};

    const CAP: usize = 64;
    #[repr(C, align(8))]
    struct Buf
    {
        header: SpscHeader,
        body: [u8; CAP],
    }
    #[allow(clippy::cast_possible_truncation)]
    let mut buf = Buf {
        header: SpscHeader {
            head: core::sync::atomic::AtomicU32::new(0),
            tail: core::sync::atomic::AtomicU32::new(0),
            capacity: CAP as u32,
            _reserved: 0,
        },
        body: [0u8; CAP],
    };

    let region_vaddr = &raw mut buf as u64;
    // SAFETY: `buf` lives for the whole phase; header is pre-initialised by
    // the `Buf` literal above, so Init's job is already done.
    let (mut writer, mut reader): (SpscWriter<'_>, SpscReader<'_>) =
        unsafe { shmem::spsc_pair(region_vaddr) };

    let payload: [u8; 10] = [0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6];
    let n = writer.write(&payload);
    assert_eq!(n, payload.len(), "writer.write full payload");

    let mut out = [0u8; 10];
    let m = reader.read(&mut out);
    assert_eq!(m, payload.len(), "reader.read full payload");
    assert_eq!(out, payload, "shmem round-trip mismatch");
    assert!(reader.is_empty(), "ring must be empty after full drain");

    // Fill-to-capacity and confirm further writes return zero.
    let big = [0xAAu8; CAP + 8];
    let pushed = writer.write(&big);
    assert_eq!(pushed, CAP, "writer must cap at ring capacity");
    assert_eq!(writer.write(&[0x11]), 0, "writer must reject when full");

    // Drain fully and re-check empty.
    let mut sink = [0u8; CAP];
    let drained = reader.read(&mut sink);
    assert_eq!(drained, CAP, "reader must drain capacity");
    assert!(sink.iter().all(|&b| b == 0xAA), "drained bytes mismatch");

    println!("usertest: shmem phase passed");
}

/// Verify `std::env::args()` returns exactly what init wrote into the
/// `CREATE_PROCESS` argv blob: `["usertest", "run"]`. Exercises the
/// end-to-end argv plumbing (init → procmgr → `ProcessInfo` page →
/// `_start` → `std::env::args`).
fn args_phase()
{
    let collected: Vec<String> = std::env::args().collect();
    for (i, a) in collected.iter().enumerate()
    {
        println!("usertest: argv[{i}]={a:?}");
    }
    assert_eq!(
        collected.len(),
        2,
        "expected 2 args, got {}",
        collected.len()
    );
    assert_eq!(collected[0], "usertest", "argv[0] mismatch");
    assert_eq!(collected[1], "run", "argv[1] mismatch");
    println!("usertest: args phase passed");
}

/// Exercise `std::env::{var, vars, set_var, remove_var}`.
///
/// Init seeds the env blob with `SERAPH_TEST=1` and `SERAPH_MODE=boot`; the
/// first half of the phase asserts both are visible straight from startup,
/// proving the `ProcessInfo` → `_start::env_blob` → `BTreeMap` seed path.
/// The second half exercises in-process mutation (`set_var`, overwrite,
/// `remove_var`) on top of that seed.
fn env_phase()
{
    use std::env;

    // Init-seeded values — must be visible without any set_var call.
    assert_eq!(
        env::var("SERAPH_TEST").unwrap_or_default(),
        "1",
        "init-seeded SERAPH_TEST missing"
    );
    assert_eq!(
        env::var("SERAPH_MODE").unwrap_or_default(),
        "boot",
        "init-seeded SERAPH_MODE missing"
    );
    assert!(
        env::var("SERAPH_NOPE").is_err(),
        "unset key must return Err"
    );
    assert_eq!(env::vars().count(), 2, "expected 2 seeded entries");

    // In-process mutation on top of seed.
    // SAFETY: usertest is single-threaded at this point in main.
    unsafe {
        env::set_var("FOO", "bar");
        env::set_var("BAZ", "qux");
    }
    assert_eq!(env::var("FOO").unwrap_or_default(), "bar");
    assert_eq!(env::var("BAZ").unwrap_or_default(), "qux");

    // Overwrite semantics on a seeded key.
    // SAFETY: still single-threaded.
    unsafe {
        env::set_var("SERAPH_MODE", "test");
    }
    assert_eq!(env::var("SERAPH_MODE").unwrap_or_default(), "test");

    // Iterator must enumerate all current entries.
    let all: Vec<(String, String)> = env::vars().collect();
    assert_eq!(all.len(), 4, "expected 4 entries, got {}", all.len());

    // SAFETY: single-threaded.
    unsafe {
        env::remove_var("FOO");
    }
    assert!(env::var("FOO").is_err(), "removed key must return Err");
    assert_eq!(env::vars().count(), 3, "three entries must remain");

    println!("usertest: env phase passed");
}

/// Verify the main thread sees the template-initialised value of a
/// `#[thread_local]` `.tdata` static, a zero for a `.tbss` static, and
/// can write through a `Cell<u32>` in TLS. Runs before any spawn so the
/// only TLS setup exercised is procmgr's main-thread block.
fn tls_main_phase()
{
    let init = TLS_INIT;
    let bss = TLS_BSS;
    println!("usertest: TLS_INIT ={init:#018x}");
    println!("usertest: TLS_BSS  ={bss:#018x}");
    assert_eq!(init, 0xDEAD_BEEF_CAFE_BABE, "TLS_INIT tdata readback");
    assert_eq!(bss, 0, "TLS_BSS tbss readback");
    for i in 1..=4u32
    {
        TLS_COUNTER.set(i);
        assert_eq!(TLS_COUNTER.get(), i, "TLS_COUNTER set/get");
    }
    println!("usertest: TLS main-thread phase passed");
}

/// Exercise the allocator across the canonical collection types.
fn alloc_phase()
{
    let boxed: Box<u64> = Box::new(0xDEAD_BEEF_CAFE_BABE);
    println!("usertest: Box<u64>={:#018x}", *boxed);

    let mut v: Vec<u64> = Vec::new();
    for i in 0u64..64
    {
        v.push(i);
    }
    let sum: u64 = v.iter().sum();
    println!("usertest: Vec sum(0..64)={sum:#018x}");
    let popped = v.pop().unwrap_or(0);
    println!("usertest: Vec::pop={popped:#018x}");

    let mut s = String::new();
    for _ in 0..8
    {
        s.push_str("seraph ");
    }
    println!("usertest: String::len={:#018x}", s.len() as u64);

    let mut m: BTreeMap<u64, u64> = BTreeMap::new();
    for k in 0u64..16
    {
        m.insert(k, k * 100);
    }
    println!("usertest: BTreeMap::len={:#018x}", m.len() as u64);
    if let Some(&v10) = m.get(&10)
    {
        println!("usertest: BTreeMap[10]={v10:#018x}");
    }

    drop(boxed);
    drop(v);
    drop(s);
    drop(m);
    println!("usertest: dealloc churn complete");
}

/// Stress-test the free-list allocator across many alloc/dealloc pairs at
/// varying non-multiple-of-`NODE_ALIGN` sizes. Guards against regression of
/// the `Heap::alloc` split-remainder alignment fix: without
/// `align_up(want, NODE_ALIGN)`, `Vec::push`-driven grows on `Vec<u8>`
/// tripped `ptr::write`'s alignment precondition under build-std debug and
/// silently aborted.
fn churn_phase()
{
    const ITERS: u32 = 10_000;
    let mut seed: u32 = 0x1337_BEEF;
    let mut keep: Vec<Vec<u8>> = Vec::with_capacity(8);
    for i in 0..ITERS
    {
        // xorshift32 — deterministic and free of allocation.
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        let size: usize = match seed & 0xF
        {
            0 => 1,
            1 => 5,
            2 => 10,
            3 => 17,
            4 => 23,
            5 => 31,
            6 => 63,
            7 => 77,
            8 => 128,
            9 => 200,
            10 => 500,
            11 => 777,
            _ => ((seed >> 4) & 0x3FF) as usize + 1,
        };
        // Start from a smaller capacity so `push` exercises `grow_amortized`
        // with odd-size Layouts — that is the precise path that exposed the
        // alignment bug.
        let mut v: Vec<u8> = Vec::with_capacity(size / 2 + 1);
        for b in 0..size
        {
            #[allow(clippy::cast_possible_truncation)]
            v.push((b & 0xFF) as u8);
        }
        assert_eq!(v.len(), size, "push count mismatch at iter {i}");
        if i.trailing_zeros() >= 3
        {
            keep.push(v);
            if keep.len() > 8
            {
                // Drop-from-front exercises frees interleaved with the live
                // set, so coalescing has to reunite non-adjacent blocks.
                let _ = keep.remove(0);
            }
        }
    }
    drop(keep);
    println!("usertest: churn phase passed ({ITERS} iters)");
}

/// Exercise the allocator's grow-on-failure path. Allocates a buffer
/// larger than `HEAP_INITIAL_PAGES * PAGE_SIZE`, forcing the first-fit
/// search to fail and the retry in `System::alloc` to request fresh
/// frames from procmgr, map them above `mapped_end`, extend the free
/// list, and re-serve the allocation. Without the grow path this
/// allocation aborts the process before reaching `usertest: PASS`.
// cast_possible_truncation: index-to-u8 casts use `& 0xFF` or small counts;
// truncation is the intended identity fingerprint for spot-checks.
#[allow(clippy::cast_possible_truncation)]
fn alloc_grow_phase()
{
    // Initial heap is 128 pages (512 KiB). Allocate 600 KiB — large
    // enough to miss first-fit against the initial heap and force the
    // allocator's grow path, small enough to stay within one
    // `GROW_MAX_PAGES` increment (64 pages = 256 KiB) and well within
    // the usertest CSpace's remaining cap-slot headroom. Pushing the
    // upper bound higher exposes the CSpace-exhaustion wedge documented
    // in `ruststd/src/sys/alloc/seraph.rs` at the grow-path comment.
    const BIG: usize = 600 * 1024;

    let mut big: Vec<u8> = Vec::with_capacity(BIG);
    for i in 0..BIG
    {
        big.push((i & 0xFF) as u8);
    }
    assert_eq!(big.len(), BIG, "grow-path push count mismatch");

    // Spot-check a handful of indices to catch any corruption in the
    // grown region (e.g. misaligned free-list insert).
    for &idx in &[0, 1, 4095, 4096, 65_535, 65_536, BIG / 2, BIG - 1]
    {
        let expected = (idx & 0xFF) as u8;
        assert_eq!(big[idx], expected, "grow buffer[{idx}] mismatch");
    }

    // Interleave smaller allocations against the live big buffer so
    // coalescing across a grow-boundary has to work.
    let mut small: Vec<Vec<u8>> = Vec::with_capacity(8);
    for k in 0..8usize
    {
        small.push(vec![k as u8; 1024]);
    }
    for (k, v) in small.iter().enumerate()
    {
        assert_eq!(v.len(), 1024);
        assert_eq!(v[0], k as u8);
    }

    drop(small);
    drop(big);

    // Heap must still be usable after the grow + drop cycle.
    let post: Vec<u32> = (0..4096u32).collect();
    assert_eq!(post.last().copied(), Some(4095));

    println!("usertest: alloc_grow phase passed ({BIG} bytes + 8 KiB interleaved)");
}

/// Minimum-viable threading test: two workers each increment a shared
/// `Mutex<u32>` `ITERS` times; joined total must equal `2 * ITERS`. Folded
/// into usertest rather than a dedicated crate because usertest is the
/// generic test driver — a second crate for one assertion is churn.
fn threading_phase()
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
    println!(
        "usertest: threading workers joined, counter={:#018x} expected={:#018x}",
        u64::from(final_value),
        u64::from(2 * ITERS),
    );
    assert_eq!(
        final_value,
        2 * ITERS,
        "threading test: counter mismatch (expected {})",
        2 * ITERS
    );
    println!("usertest: threading phase passed");
}

/// Exercise the `thread_local!` macro. This drives the `LazyStorage` +
/// `destructors::register` path (unlike the raw `#[thread_local]` statics in
/// `tls_main_phase`, which skip the lazy wrapper). The inner type is `Drop`
/// so every access triggers first-time destructor registration against
/// `DTORS: #[thread_local] RefCell<Vec<_, System>>`, which was the specific
/// failure mode during the native-TLS bring-up.
fn tls_macro_phase()
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
    println!("usertest: thread_local! Vec<u32> sum(0..8)={sum:#018x}");
    assert_eq!(sum, 28, "thread_local! macro sum mismatch");

    let handle = thread::spawn(|| {
        COUNTER.with(|c| {
            let v = c.take();
            // Fresh thread → fresh thread_local → empty Vec.
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
    println!("usertest: thread_local! child sum={got:#018x}");
    println!("usertest: thread_local! macro phase passed");
}

/// Exercise `Condvar::wait_timeout` over the kernel's `SYS_SIGNAL_WAIT`
/// timeout path. Two sub-checks:
///
/// 1. A wait on a `Condvar` that nobody notifies returns after the full
///    timeout and reports `timed_out() == true`.
/// 2. A wait that a second thread notifies partway through returns
///    early with `timed_out() == false` — proves the signal path still
///    wakes the waiter before the timer fires.
fn timeout_phase()
{
    // (1) True timeout — no notifier.
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
    println!(
        "usertest: wait_timeout: timed_out after {:#x} us",
        u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
    );

    // (2) Early wake — a notifier fires inside the timeout window.
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
    println!(
        "usertest: wait_timeout: notified after {:#x} us",
        u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
    );
    println!("usertest: timeout phase passed");
}

/// Exercise `std::process::Command::spawn` + `Child::wait`.
///
/// Spawns `/bin/hello` (a minimal cap-oblivious tier-2 binary that prints a
/// line and exits), then blocks on `wait()`. Kernel posts the child's exit
/// reason to a death-notification `EventQueue` procmgr bound at spawn time;
/// `wait()` dequeues it and reports it as an `ExitStatus`. Clean thread
/// exit (`SYS_THREAD_EXIT`) surfaces as reason 0 ⇒ `status.success()`.
///
/// Also passes a non-empty argv and env so the `CREATE_FROM_VFS` wire
/// format (extended to mirror `CREATE_PROCESS`'s argv/env encoding) is
/// exercised end-to-end. `hello` ignores its argv/env — we only assert a
/// clean exit here; the packing + procmgr parsing path is what's under
/// test, not the receiving side.
fn spawn_phase()
{
    use std::process::Command;

    // Exercises the full spawn wire: argv blob + env blob end up in the
    // child's ProcessInfo page. /bin/hello ignores them and exits cleanly;
    // assertion here is on the spawn-side round-trip (no crash, clean
    // exit), not on the child's receipt.
    let mut child = Command::new("/bin/hello")
        .arg("one")
        .arg("two")
        .env("SPAWNED_BY", "usertest")
        .spawn()
        .expect("spawn /bin/hello failed");

    let id = child.id();
    println!("usertest: spawned /bin/hello handle={id:#x}");

    // Exercise procmgr's QUERY_PROCESS IPC before reaping: the child is
    // post-spawn, pre-drop, so procmgr's ProcessTable still has an entry
    // with `started=true`, which maps to `ALIVE`.
    {
        let info = startup_info();
        // SAFETY: IPC buffer is the kernel-registered, page-aligned buffer
        // installed by `_start`.
        let ipc_raw = unsafe { ipc::IpcBuf::from_bytes(info.ipc_buffer) };
        let id = child.id();
        let (reply_label, _) = syscall::ipc_call(id, ipc::procmgr_labels::QUERY_PROCESS, 0, &[])
            .expect("QUERY_PROCESS call failed");
        assert_eq!(
            reply_label,
            ipc::procmgr_errors::SUCCESS,
            "QUERY_PROCESS non-success label"
        );
        // ipc_call's secondary "data_count" is unused in this ABI — the
        // reply data lives in the registered IPC buffer regardless.
        let state = ipc_raw.read_word(0);
        let exit_reason = ipc_raw.read_word(1);
        assert_eq!(
            state,
            ipc::procmgr_process_state::ALIVE,
            "expected ALIVE for live child, got {state}"
        );
        assert_eq!(exit_reason, 0, "ALIVE process must report exit_reason=0");
        println!("usertest: query_process (ALIVE) passed");
    }

    let status = child.wait().expect("child wait failed");
    println!("usertest: child exited: {status}");
    assert!(
        status.success(),
        "child /bin/hello did not exit cleanly: {status}"
    );

    // After wait() has consumed the exit, try_wait must surface the cached
    // status non-blockingly (Ok(Some(_))).
    let again = child.try_wait().expect("try_wait after wait failed");
    assert!(
        again.is_some(),
        "try_wait after wait must surface cached status"
    );
    println!("usertest: try_wait phase passed");

    println!("usertest: spawn phase passed");
}
