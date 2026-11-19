// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/commit_swap.rs

//! Commitments backed by the swap slots: the overcommit allowance A
//! (services/memmgr/docs/memory-pool.md § Commit, Overcommit), beside the
//! real swap service, which registered every slot of the swap partition.
//!
//! The phase requires:
//!
//! * `QUERY_POOL_STATUS` `data[14]` to be A as memmgr derives it from the
//!   same reply: [`CHUNK_PAGES`] pages a free slot (`data[13]`), less the
//!   pages compression freed from the evicted chunks not on disk, and above 0;
//! * a committed registration of more pages than memmgr can hold free pages
//!   for, within what A adds, admitted, and one past what A adds refused with
//!   `OUT_OF_MEMORY_BEST_EFFORT` ([`admission`]);
//! * when crashd runs with a stall, a `commit-swap-toucher` child
//!   ([`toucher_main`]) that commits [`PAST_FREE_PAGES`] pages more than
//!   memmgr can hold free pages for, writes every page of them with a pattern
//!   compression cannot shrink, and reads each back, to exit 0: a fault memmgr
//!   cannot back at once is declined with code 11, which crashd holds, and
//!   resumes once swapd's writes free pages. crashd must log at least one
//!   such hold and one resume while the child runs, and no hold that timed
//!   out. Without crashd a declined fault kills the child, so the boot that
//!   stages none (the gating svctest boot) runs the first two checks alone and
//!   logs that it skipped the touch.

use std::process::exit;
use std::time::{Duration, Instant};

use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use syscall_abi::PAGE_SIZE;

use crate::bootstrap::Caps;
use crate::phases::heap_commit::{
    CHUNK_PAGES, HOG_BALLAST_BYTES, HOG_MARGIN_PAGES, POOL_WINDOWS, allowance_pages, memmgr_label,
    page_bytes, pool_status, promise_room, uncommitted_available,
};
use crate::runner::Phase;

/// The phase's name, in its messages.
const PHASE: &str = "memmgr_commit_swap";

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: PHASE,
        run: commit_swap_phase,
    }]
}

/// Child-mode dispatch for the argv tokens this module owns. A match
/// diverges; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == TOUCHER_ROLE
    {
        toucher_main();
    }
}

/// argv[1] of the child that writes past the free pages.
const TOUCHER_ROLE: &str = "commit-swap-toucher";

/// Pages the toucher commits and writes past what memmgr can hold free pages
/// for: 256 chunks, which leave RAM only through the swap slots, since their
/// pattern does not compress.
const PAST_FREE_PAGES: u64 = 256 * CHUNK_PAGES;

/// crashd's recipe, when the image starts crashd.
const CRASHD_RECIPE: &str = "/config/svcmgr/services/crashd.svc";
/// The part of crashd's line for a fault it holds.
const HELD_LINE: &[u8] = b"held: memory critical";
/// The part of crashd's line for a held fault it resumed.
const RESUMED_LINE: &[u8] = b"resumed after";
/// The part of crashd's line for a hold whose stall ran out.
const TIMED_OUT_LINE: &[u8] = b"hold timed out";
/// How long the phase waits for crashd's lines to reach logd's history after
/// the toucher exits. A test wait bound.
const LOG_WAIT: Duration = Duration::from_secs(10);

/// Exit code: a `QUERY_POOL_STATUS` call to memmgr failed or was refused.
const TOUCHER_STATUS_FAILED: i32 = 2;
/// Exit code: memmgr's allowance left no room past the free pages.
const TOUCHER_NO_ROOM: i32 = 3;
/// Exit code: the commitment was refused in every attempt.
const TOUCHER_NOT_COMMITTED: i32 = 4;
/// Exit code: a page read back other than written.
const TOUCHER_CORRUPT: i32 = 5;
/// Exit code: the ballast's allocation failed.
const TOUCHER_BALLAST_FAILED: i32 = 6;

/// The phase: the allowance as memmgr reports it, the admission past the
/// free pages, and, with crashd holding, the touch past them.
fn commit_swap_phase(caps: &Caps)
{
    let allowance = reported_allowance();
    admission();
    let Some(stall_ms) = crashd_stall()
    else
    {
        std::os::seraph::log!(
            "{PHASE}: crashd is not staged with a stall, so a fault memmgr cannot back would \
             kill the toucher: the touch past the free pages is not run"
        );
        std::os::seraph::log!("{PHASE} phase passed (allowance {allowance} pages; no touch)");
        return;
    };
    let (held, resumed) = touch_past_free(caps);
    std::os::seraph::log!(
        "{PHASE} phase passed (allowance {allowance} pages; {PAST_FREE_PAGES} pages written past \
         the free pages and read back; crashd, stalling {stall_ms} ms, held {held} faults and \
         resumed {resumed})"
    );
}

/// `QUERY_POOL_STATUS` `data[14]`, in pages, after checking it against the
/// derivation from the same reply, and that it is above 0.
fn reported_allowance() -> u64
{
    let reply = pool_status().unwrap_or_else(|| panic!("{PHASE}: QUERY_POOL_STATUS failed"));
    let freed = reply
        .word(10)
        .saturating_sub(reply.word(12))
        .saturating_sub(reply.word(9))
        / PAGE_SIZE;
    let derived = reply
        .word(13)
        .saturating_mul(CHUNK_PAGES)
        .saturating_sub(freed);
    let reported = allowance_pages(&reply);
    assert_eq!(
        reported,
        derived,
        "{PHASE}: data[14] reports an allowance of {reported} pages, where {} free slots less \
         {freed} pages compression freed give {derived}",
        reply.word(13)
    );
    assert!(
        reported > 0,
        "{PHASE}: the allowance is 0 ({} free slots): no swap service registered its slots",
        reply.word(13)
    );
    reported
}

/// A committed registration past what memmgr can hold free pages for, within
/// what its allowance adds, admitted, and one a chunk past that refused with
/// `OUT_OF_MEMORY_BEST_EFFORT`. Other processes move the totals between the
/// read and the registration, so each is tried in up to [`POOL_WINDOWS`]
/// windows.
fn admission()
{
    let admitted = (0..POOL_WINDOWS).any(|_| {
        let backed = uncommitted_available();
        let room = promise_room().unwrap_or_else(|| panic!("{PHASE}: QUERY_POOL_STATUS failed"));
        let past = backed.saturating_add(room.saturating_sub(backed) / 2);
        let pages = past.saturating_sub(past.checked_rem(CHUNK_PAGES).unwrap_or(0));
        pages > backed && register(pages) == memmgr_errors::SUCCESS
    });
    assert!(
        admitted,
        "{PHASE}: a commitment past the free pages, within the allowance, was refused in every \
         window"
    );
    let refused = (0..POOL_WINDOWS).any(|_| {
        let room = promise_room().unwrap_or_else(|| panic!("{PHASE}: QUERY_POOL_STATUS failed"));
        let pages = room
            .saturating_add(CHUNK_PAGES)
            .next_multiple_of(CHUNK_PAGES);
        match register(pages)
        {
            memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT => true,
            memmgr_errors::SUCCESS => false,
            got => panic!("{PHASE}: a commitment past the allowance: memmgr replied {got:#x}"),
        }
    });
    assert!(
        refused,
        "{PHASE}: a commitment a chunk past the allowance was admitted in every window"
    );
}

/// Register a committed region of `pages` pages, untouched, and unregister
/// it again when memmgr admits it; memmgr's reply label.
fn register(pages: u64) -> u64
{
    let range = std::os::seraph::reserve_pages(pages)
        .unwrap_or_else(|e| panic!("{PHASE}: reserving {pages} pages failed: {e:?}"));
    let base = range.va_start();
    let len = pages.saturating_mul(PAGE_SIZE);
    let register = IpcMessage::builder(memmgr_labels::REGISTER_REGION)
        .word(0, base)
        .word(1, len)
        .word(2, syscall::MAP_WRITABLE)
        .word(3, memmgr_labels::REGION_COMMIT)
        .build();
    let got = memmgr_label(&register, "REGISTER_REGION with REGION_COMMIT");
    if got == memmgr_errors::SUCCESS
    {
        let unregister = IpcMessage::builder(memmgr_labels::UNREGISTER_REGION)
            .word(0, base)
            .word(1, len)
            .build();
        let freed = memmgr_label(&unregister, "UNREGISTER_REGION");
        assert_eq!(
            freed,
            memmgr_errors::SUCCESS,
            "{PHASE}: UNREGISTER_REGION of an admitted commitment: memmgr replied {freed:#x}"
        );
    }
    std::os::seraph::unreserve_pages(range);
    got
}

/// crashd's stall, when crashd runs and holds a fault declined for want of
/// memory: its recipe is staged and sets a non-zero `CRASHD_OOM_STALL_MS`.
fn crashd_stall() -> Option<u64>
{
    if !super::svcmgr::recipe_staged(CRASHD_RECIPE, PHASE)
    {
        return None;
    }
    let recipe = std::fs::read_to_string(CRASHD_RECIPE)
        .unwrap_or_else(|e| panic!("{PHASE}: read {CRASHD_RECIPE}: {e:?}"));
    recipe
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(name, _)| name.trim() == "env")
        .flat_map(|(_, value)| value.split_whitespace())
        .find_map(|pair| {
            pair.strip_prefix("CRASHD_OOM_STALL_MS=")?
                .parse::<u64>()
                .ok()
        })
        .filter(|&ms| ms != 0)
}

/// Run the toucher to its exit, require it to exit 0, and require crashd to
/// have logged a hold and a resume, and no hold that timed out, meanwhile.
/// Returns the holds and the resumes counted.
fn touch_past_free(caps: &Caps) -> (usize, usize)
{
    let before = CrashdLines::read(caps.logd_query);
    let status = std::process::Command::new("/tests/svctest")
        .arg(TOUCHER_ROLE)
        .status()
        .unwrap_or_else(|e| panic!("{PHASE}: spawning the toucher failed: {e}"));
    assert!(
        status.success(),
        "{PHASE}: the toucher exited {status:?}: {TOUCHER_STATUS_FAILED}=QUERY_POOL_STATUS \
         failed, {TOUCHER_NO_ROOM}=no allowance past the free pages, \
         {TOUCHER_NOT_COMMITTED}=its commitment was refused, {TOUCHER_CORRUPT}=a page read \
         back other than written, {TOUCHER_BALLAST_FAILED}=its ballast's allocation failed, a \
         fault=a fault on a committed page was declined"
    );
    let start = Instant::now();
    let after = loop
    {
        let now = CrashdLines::read(caps.logd_query);
        if (now.held > before.held && now.resumed > before.resumed) || start.elapsed() > LOG_WAIT
        {
            break now;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let held = after.held.saturating_sub(before.held);
    let resumed = after.resumed.saturating_sub(before.resumed);
    assert!(
        held > 0,
        "{PHASE}: crashd held none of the toucher's faults: every write past the free pages \
         found a page"
    );
    assert!(
        resumed > 0,
        "{PHASE}: crashd held {held} of the toucher's faults and resumed none"
    );
    assert_eq!(
        after.timed_out, before.timed_out,
        "{PHASE}: a hold of crashd timed out while the toucher ran"
    );
    (held, resumed)
}

/// crashd's lines in logd's history: its holds, resumes, and holds that
/// timed out.
struct CrashdLines
{
    held: usize,
    resumed: usize,
    timed_out: usize,
}

impl CrashdLines
{
    /// The counts in logd's history now, read through `query`.
    fn read(query: u64) -> Self
    {
        let history = super::procmgr::logd_history(query, None);
        let count = |needle: &[u8]| {
            history
                .iter()
                .filter(|(_, bytes)| bytes.windows(needle.len()).any(|w| w == needle))
                .count()
        };
        Self {
            held: count(HELD_LINE),
            resumed: count(RESUMED_LINE),
            timed_out: count(TIMED_OUT_LINE),
        }
    }
}

// ── The child ────────────────────────────────────────────────────────────────

/// Child role: commit, through the heap, [`PAST_FREE_PAGES`] pages more than
/// memmgr can hold free pages for, within what its allowance adds less
/// [`HOG_MARGIN_PAGES`]; write every page of them with [`pattern_word`], read
/// every page back, and exit 0. A fault memmgr declined that no crashd held
/// would kill the child. As the heap-commit hog does, it first fills what its
/// heap's floor has free with a ballast, so the commitment lies above it.
fn toucher_main() -> !
{
    let mut ballast: Vec<u8> = Vec::new();
    if ballast.try_reserve_exact(HOG_BALLAST_BYTES).is_err()
    {
        exit(TOUCHER_BALLAST_FAILED);
    }
    ballast.resize(HOG_BALLAST_BYTES, 1);
    let mut block: Vec<u8> = Vec::new();
    let mut pages = 0;
    for _ in 0..POOL_WINDOWS
    {
        let backed = uncommitted_available();
        let Some(room) = promise_room()
        else
        {
            exit(TOUCHER_STATUS_FAILED)
        };
        pages = backed
            .saturating_add(PAST_FREE_PAGES)
            .min(room.saturating_sub(HOG_MARGIN_PAGES));
        if pages <= backed.saturating_add(PAST_FREE_PAGES / 2)
        {
            exit(TOUCHER_NO_ROOM);
        }
        if block.try_reserve_exact(page_bytes(pages)).is_ok()
        {
            break;
        }
        pages = 0;
    }
    if pages == 0
    {
        exit(TOUCHER_NOT_COMMITTED);
    }
    let page_len = page_bytes(1);
    for (page, bytes) in (0..pages).zip(block.spare_capacity_mut().chunks_exact_mut(page_len))
    {
        let mut state = seed(page);
        for word in bytes.as_chunks_mut::<8>().0
        {
            for (byte, value) in word.iter_mut().zip(pattern_word(&mut state).to_le_bytes())
            {
                byte.write(value);
            }
        }
    }
    let len = page_bytes(pages);
    // SAFETY: the loop above wrote every byte of the first `len` bytes of the
    // block's capacity, which is at least `len`.
    unsafe { block.set_len(len) };
    for (page, bytes) in (0..pages).zip(block.chunks_exact(page_len))
    {
        let mut state = seed(page);
        for word in bytes.as_chunks::<8>().0
        {
            if *word != pattern_word(&mut state).to_le_bytes()
            {
                exit(TOUCHER_CORRUPT);
            }
        }
    }
    exit(0);
}

/// The state page `page`'s pattern starts from: distinct and never 0.
const fn seed(page: u64) -> u64
{
    page.wrapping_add(1).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1
}

/// The next word of a page's pattern: an xorshift64 step, whose output no
/// compressor shrinks.
fn pattern_word(state: &mut u64) -> u64
{
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
