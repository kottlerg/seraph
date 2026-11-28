// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/src/disk.rs

//! The disk tier's interface to the swap service
//! (services/memmgr/docs/memory-pool.md § Disk tier;
//! services/memmgr/docs/ipc-interface.md § Labels 22 to 26): its registration,
//! the chunks it takes for its swap slots and their bytes, the end of each
//! write, the restore of a slot's bytes, and the redirect of a fault on a chunk
//! on disk to it.
//!
//! memmgr performs no device I/O and waits on no peer: every label here is a
//! request the swap service makes, and the redirect is a fault reply. The
//! bytes memmgr hands the swap service are sealed in memmgr's own buffer
//! ([`free_pool::disk::seal`], or [`free_pool::disk::seal_detached`] for a
//! raw chunk's pages) under a key drawn at start that never leaves
//! memmgr, and copied out only once sealed; the bytes the swap service hands
//! back are copied into the same buffer before their tag is checked, so the
//! check and the decryption read one snapshot the swap service can no longer
//! change. memmgr reaches a buffer of the swap service's only through a Memory
//! cap it maps itself at [`SWAP_WINDOW_VA`], from its own page tables, which
//! a revoke of the cap does not withdraw (core/kernel/docs/syscalls.md
//! § `SYS_CAP_REVOKE`), so a copy into or out of it neither faults nor blocks.

use free_pool::disk::{self, KEY_BYTES, Registered, SLOT_WORDS_PER_PAGE, SlotError};
use free_pool::lock::{Claim, Claimed};
use free_pool::{CHUNK_BYTES, ClockHand, FaultPath, Fit, NodeIdx, SwapError};
use free_pool::{WANT_WORDS, WantList};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use syscall_abi::{MAP_READ, PAGE_SIZE};

use crate::{
    Answer, FaultDecline, MemLedger, coalesce, ensure_slots, evict, map_self, map_self_with,
    return_taken, select, self_aspace,
};

/// The window where memmgr maps a buffer of the swap service's for one
/// request: a chunk, after the eviction windows (the zone map in main.rs).
pub(crate) const SWAP_WINDOW_VA: u64 = evict::EVICT_ZONE_END;

/// Exclusive end of the swap window.
pub(crate) const SWAP_WINDOW_END: u64 = SWAP_WINDOW_VA + CHUNK_BYTES;

/// Base of the swap slot map's words ([`free_pool::SwapSlots`]), grown one
/// page at a time from the pool as far as the highest slot taken.
/// Deterministic: it holds only arena indices.
pub(crate) const SWAP_SLOTS_VA: u64 = 0x0000_0001_8000_0000;

/// Exclusive end of the slot map's window (2 GiB, 2^28 slots of a chunk each,
/// 16 TiB of swap): the most slots memmgr uses, whatever a registration names.
pub(crate) const SWAP_SLOTS_END: u64 = 0x0000_0002_0000_0000;

/// The most slots memmgr uses: the words the slot map's window holds.
const MAX_SLOTS: u64 = (SWAP_SLOTS_END - SWAP_SLOTS_VA) / 8;
const _: () = assert!(SLOT_WORDS_PER_PAGE * 8 == PAGE_SIZE);
const _: () = assert!(MAX_SLOTS <= disk::WORD_SLOTS);

/// Steps of the walk one `SWAP_TAKE` makes for a compressed or raw chunk
/// ([`free_pool::Ledger::next_to_write`]): a chunk visited, or a region or
/// record passed. A tuning value that bounds the request's turn as a slice of
/// the clock is bounded; a walk that finds none replies `NOTHING_TO_TAKE`,
/// and the next request goes on from where it stopped.
const TAKE_STEPS: u64 = 512;

/// Bytes of memmgr's own swap buffer: a slot.
const BUF_BYTES: usize = CHUNK_BYTES as usize;

/// The decline detail of a chunk on disk with no swap service registered.
pub(crate) const DETAIL_UNREGISTERED: u64 = 0;

/// The decline detail of a chunk whose slot failed authentication: lost.
pub(crate) const DETAIL_LOST: u64 = 1;

/// The decline detail of a chunk on disk whose redirect memmgr could not make:
/// its own `CSpace` had no slot for the reply's copy of the swap service's
/// endpoint ([`reply_fault`]). The chunk stays on disk.
const DETAIL_NO_SLOT: u64 = 3;

/// memmgr's buffer for a slot's bytes: the chunk's stream, or a raw chunk's
/// pages, sealed in place before it is copied out, or a slot's bytes copied in before they are opened
/// in place. Reached only by G's holder.
#[repr(C, align(16))]
struct Buf([u8; BUF_BYTES]);

static BUF: Claim<Buf> = Claim::new(Buf([0; BUF_BYTES]));

/// The disk tier's state: the per-boot key (`None` when its draw failed, and
/// the disk tier then stays off), the next nonce, the swap service's endpoint
/// (`0` while none is registered), its want Notification and the bits to
/// send on it (`0` while it registered none), the slot words
/// `MAKE_RESIDENT` posted for it to restore, and the hand of the walk
/// `SWAP_TAKE` makes. Reached only by G's holder.
struct Disk
{
    key: Option<[u8; KEY_BYTES]>,
    nonce: u64,
    endpoint: u64,
    want: u64,
    want_bits: u64,
    wants: WantList,
    hand: ClockHand,
}

static DISK: Claim<Disk> = Claim::new(Disk {
    key: None,
    nonce: 0,
    endpoint: 0,
    want: 0,
    want_bits: 0,
    wants: WantList::new(),
    hand: ClockHand::START,
});

const _: () = assert!(WANT_WORDS as u64 == memmgr_labels::SWAP_WANTED_WORDS);

/// The disk tier's state, claimed until the guard drops; G's holder alone
/// calls it, and no caller holds the guard across another call.
fn state() -> Claimed<'static, Disk>
{
    DISK.claim()
}

/// memmgr's swap buffer, claimed until the guard drops, as [`state`].
fn buf() -> Claimed<'static, Buf>
{
    BUF.claim()
}

/// Draw the per-boot key from the kernel's entropy pool (`SYS_GETRANDOM`).
/// Called once at start. A failed draw, a kernel-contract violation, leaves
/// the disk tier off: `SWAP_REGISTER` is refused.
pub(crate) fn init()
{
    let mut key = [0u8; KEY_BYTES];
    let (words, _) = key.as_chunks_mut::<8>();
    let drawn = words.iter_mut().all(|word| {
        syscall::random_u64().is_ok_and(|r| {
            *word = r.to_le_bytes();
            true
        })
    });
    state().key = drawn.then_some(key);
}

/// Hand a swap label's request to its handler, with the caps its contract
/// keeps (`crate::dispatch`).
pub(crate) fn route(
    l: &mut MemLedger,
    opcode: u64,
    req: &IpcMessage,
    kept: &[u64],
    answer: &mut Answer,
    service_ep: u64,
)
{
    match opcode
    {
        memmgr_labels::SWAP_REGISTER => handle_register(l, req, kept, answer, service_ep),
        memmgr_labels::SWAP_TAKE => handle_take(l, kept, answer),
        memmgr_labels::SWAP_DONE => handle_done(l, req, answer),
        memmgr_labels::SWAP_RESTORE => handle_restore(l, req, kept, answer),
        memmgr_labels::SWAP_WANTED => handle_wanted(answer),
        _ => answer.set_status(memmgr_errors::INVALID_ARGUMENT),
    }
}

/// Whether a swap service is registered.
pub(crate) fn registered() -> Registered
{
    if state().endpoint == 0
    {
        Registered::No
    }
    else
    {
        Registered::Yes
    }
}

/// Whether a registered swap service can be asked to restore a chunk on disk
/// ahead of a fault: it registered a want Notification.
pub(crate) fn wants_registered() -> Registered
{
    let s = state();
    if s.endpoint != 0 && s.want != 0
    {
        Registered::Yes
    }
    else
    {
        Registered::No
    }
}

/// Post the slot word of the chunk on disk whose disk node is `disk` for the
/// swap service to restore (`MAKE_RESIDENT`, services/memmgr/docs/memory-pool.md
/// § Eviction, Debugger reads), and send the want bits on its Notification
/// when the word is new. The send never blocks; one that fails, to a cap the
/// swap service revoked, is dropped. `false` when `disk` names no disk node.
pub(crate) fn post_want(l: &MemLedger, disk: Option<NodeIdx>) -> bool
{
    let Some(n) = disk.and_then(|s| l.disk_node(s))
    else
    {
        return false;
    };
    let mut s = state();
    if s.wants.post(disk::slot_word(n.slot, n.len, n.nonce)) == free_pool::Posted::Added
    {
        let _ = syscall::notification_send(s.want, s.want_bits);
    }
    true
}

/// Whether an evicted chunk whose stream gains nothing is kept raw for a swap
/// slot (services/memmgr/docs/memory-pool.md § Eviction, States): a swap
/// service is registered, the key was drawn, and the free swap slots exceed
/// the raw chunks waiting for one. `SWAP_TAKE` takes compressed chunks from
/// the same slots and a new registration can lower them, so a raw chunk can
/// still wait for a slot.
pub(crate) fn takes_raw(l: &MemLedger) -> bool
{
    let s = state();
    s.key.is_some() && s.endpoint != 0 && l.slots.free() > l.raw_chunks()
}

/// The swap slots free, `0` while no swap service is registered
/// (`QUERY_POOL_STATUS` `data[13]`).
pub(crate) fn free_slots(l: &MemLedger) -> u64
{
    match registered()
    {
        Registered::Yes => l.slots.free(),
        Registered::No => 0,
    }
}

/// The fault reason word of a decline, as [`crate::decline_fault`] sends it.
const fn decline_word(reason: FaultDecline, detail: u64) -> u64
{
    (detail << 32) | reason as u64
}

/// Reply to a fault on the chunk whose entry names the disk node `disk`
/// by its path ([`free_pool::fault_path`]): redirect it to the swap
/// service's endpoint with the slot word ([`disk::slot_word`]), or
/// decline it with code 12. Returns `false` for a path that is not the disk
/// tier's, replying nothing.
pub(crate) fn reply_fault(
    l: &MemLedger,
    path: FaultPath,
    disk: Option<NodeIdx>,
    answer: &mut Answer,
) -> bool
{
    match path
    {
        FaultPath::Redirect =>
        {
            let Some(n) = disk.and_then(|s| l.disk_node(s))
            else
            {
                crate::decline_fault(answer, FaultDecline::OnDiskChunk, DETAIL_UNREGISTERED);
                return true;
            };
            // A copy for this reply alone: the reply is sent with G released,
            // when another receive thread's `SWAP_REGISTER` can replace the
            // registered endpoint and delete its slot.
            let Ok(ep) = syscall::cap_derive(state().endpoint, syscall::RIGHTS_ALL)
            else
            {
                crate::decline_fault(answer, FaultDecline::OnDiskChunk, DETAIL_NO_SLOT);
                return true;
            };
            let reply = IpcMessage::builder(syscall_abi::FAULT_REPLY_REDIRECT)
                .word(0, disk::slot_word(n.slot, n.len, n.nonce))
                .cap(ep)
                .build();
            // The kernel resolves the cap without moving it; the answer deletes
            // the copy once the reply is sent.
            answer.set_naming(reply, ep);
            true
        }
        FaultPath::DeclineUnregistered =>
        {
            crate::decline_fault(answer, FaultDecline::OnDiskChunk, DETAIL_UNREGISTERED);
            true
        }
        FaultPath::DeclineLost =>
        {
            crate::decline_fault(answer, FaultDecline::OnDiskChunk, DETAIL_LOST);
            true
        }
        FaultPath::Back | FaultPath::Remap | FaultPath::RestoreFromStore => false,
    }
}

/// Reply `label` with the words `words` and the cap `cap` moved back to the
/// caller; a reply that cannot reach it deletes the cap.
fn reply_with_cap(answer: &mut Answer, label: u64, words: &[u64], cap: u64)
{
    answer.set_or_delete_caps(IpcMessage::builder(label).words(0, words).cap(cap).build());
}

/// Whether `cap` is an Endpoint cap.
fn is_endpoint_cap(cap: u64) -> bool
{
    syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS)
        .is_ok_and(|packed| packed >> 32 == u64::from(syscall::CAP_TAG_ENDPOINT))
}

/// Whether `cap` is a Memory cap of at least `bytes` bytes.
fn is_memory_of(cap: u64, bytes: u64) -> bool
{
    syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS)
        .is_ok_and(|packed| packed >> 32 == u64::from(syscall::CAP_TAG_MEMORY))
        && syscall::cap_info(cap, syscall::CAP_INFO_MEMORY_SIZE).is_ok_and(|size| size >= bytes)
}

/// Unmap the first `pages` pages of the swap window.
fn unmap_window(pages: u64)
{
    // SAFETY: the swap window is memmgr's own zone (the zone map in main.rs).
    let _ = unsafe { syscall::mem_unmap(self_aspace(), SWAP_WINDOW_VA, pages) };
}

/// `SWAP_REGISTER` (services/memmgr/docs/ipc-interface.md § Label 22):
/// `caps[0]` a SEND on the swap service's restore endpoint, `data[0]` its
/// slot count, and, optional, `caps[1]` the Notification memmgr sends
/// `data[1]` on when `MAKE_RESIDENT` posts a slot word for it (refused unless
/// it is a Notification with the Notify right and `data[1]` is nonzero). memmgr refuses a cap that is no Endpoint cap or names its own
/// endpoint `service_ep` (a fault redirected there would reach memmgr with the
/// badge of the cap, a process's, and be served in the wrong address space),
/// and a count of 0 or below a slot ever taken (one on the free list
/// included): a registration is never withdrawn
/// ([`free_pool::Ledger::overcommits`]). A
/// registration replaces the one before it, whose cap is deleted, and ends
/// every write in flight ([`free_pool::Ledger::end_writes`]): a new swap
/// service knows nothing of its predecessor's. The reply's `data[0]` is the
/// slots memmgr uses, the count clamped to [`MAX_SLOTS`].
fn handle_register(
    l: &mut MemLedger,
    req: &IpcMessage,
    caps: &[u64],
    answer: &mut Answer,
    service_ep: u64,
)
{
    let Some(&cap) = caps.first()
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let want = caps.get(1).copied().unwrap_or(0);
    let want_bits = req.word(1);
    let total = req.word(0).min(MAX_SLOTS);
    let ours = syscall::endpoint_badge(service_ep, cap).is_ok();
    let want_ok = want == 0 || (want_bits != 0 && crate::is_notify_cap(want));
    if state().key.is_none()
        || ours
        || !is_endpoint_cap(cap)
        || !want_ok
        || !l.slots.set_total(total)
    {
        let _ = syscall::cap_delete(cap);
        if want != 0
        {
            let _ = syscall::cap_delete(want);
        }
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    }
    let mut s = state();
    for prior in [
        core::mem::replace(&mut s.endpoint, cap),
        core::mem::replace(&mut s.want, want),
    ]
    {
        if prior != 0
        {
            let _ = syscall::cap_delete(prior);
        }
    }
    s.want_bits = if want == 0 { 0 } else { want_bits };
    // Words posted for the swap service before it registered stay posted: a
    // restarted swap service restores them as its predecessor would have.
    if want != 0 && !s.wants.is_empty()
    {
        let _ = syscall::notification_send(want, want_bits);
    }
    let _ = l.end_writes();
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, total)
        .build();
    answer.set(reply);
}

/// Give the slot map the page its next slot needs, from the pool: mapped at
/// the next page of [`SWAP_SLOTS_VA`]. The page leaves the pool for good and
/// stays in `pool_total` as memmgr's metadata, as an index page does.
/// `false` when it cannot.
fn grow_slots(l: &mut MemLedger) -> bool
{
    if !l.slots.wants_page()
    {
        return true;
    }
    let va = SWAP_SLOTS_VA.saturating_add(l.slots.pages().saturating_mul(PAGE_SIZE));
    if va >= SWAP_SLOTS_END
    {
        return false;
    }
    let Ok(grant) = select(l, 1, Fit::Contiguous)
    else
    {
        return false;
    };
    let (outer, _, phys) = grant.entries[0];
    // SAFETY: `va` is slot-map page `pages()`, the next one, below
    // `SWAP_SLOTS_END` and not yet mapped.
    if unsafe { map_self(l, outer, va, 0, 1) }.is_err()
    {
        return_taken(l, outer, 1, phys);
        return false;
    }
    // SAFETY: slot-map page `pages()` is now mapped read-write at `va`, the
    // `SLOT_WORDS_PER_PAGE` words from `pages() * SLOT_WORDS_PER_PAGE` at the
    // store's base, and is used by nothing but the map.
    unsafe { l.slots.add_page() };
    true
}

/// `SWAP_TAKE` (services/memmgr/docs/ipc-interface.md § Label 23): take the
/// next compressed or raw chunk for a swap slot. `caps[0]` is the swap
/// service's buffer, a Memory cap of at least a chunk, moved back on every
/// reply. memmgr copies the chunk's stream from its store runs, or a raw
/// chunk's backed pages from its runs, into its own buffer, seals it there
/// under the next nonce, a raw chunk's tag kept on its entry, takes a slot and
/// a disk node, and only then writes the slot's bytes into the swap service's
/// buffer, mapped at the swap window. The chunk is writing: its store runs, or
/// its runs, stay until `SWAP_DONE`, so a fault meanwhile restores from them,
/// or maps them back. Reply: `SUCCESS` with `data[0]` the
/// slot, `data[1]` its byte count and `data[2]` its slot word
/// ([`disk::slot_word`]); `INVALID_ARGUMENT` for a missing or
/// small cap, one memmgr cannot map, or with no swap service registered;
/// `SWAP_FULL` when every registered slot is taken; `NOTHING_TO_TAKE` when
/// the walk finds no compressed or raw chunk within [`TAKE_STEPS`]; `QUOTA` when the
/// arena or the slot map cannot grow.
///
/// Its time in memmgr's loop is bounded: a walk of at most [`TAKE_STEPS`]
/// steps, one copy of the stream or the pages (at most a chunk's bytes), one
/// seal of it, and one copy of the sealed bytes out.
fn handle_take(l: &mut MemLedger, caps: &[u64], answer: &mut Answer)
{
    let Some(&cap) = caps.first()
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let (label, words) = take(l, cap);
    reply_with_cap(answer, label, &words, cap);
}

/// [`handle_take`]'s work: its reply label and words.
fn take(l: &mut MemLedger, cap: u64) -> (u64, [u64; 3])
{
    let key = {
        let s = state();
        s.key.filter(|_| s.endpoint != 0)
    };
    let Some(key) = key
    else
    {
        return (memmgr_errors::INVALID_ARGUMENT, [0; 3]);
    };
    if !is_memory_of(cap, CHUNK_BYTES)
    {
        return (memmgr_errors::INVALID_ARGUMENT, [0; 3]);
    }
    if l.slots.free() == 0
    {
        return (memmgr_errors::SWAP_FULL, [0; 3]);
    }
    if !grow_slots(l) || !ensure_slots(l, 1)
    {
        return (memmgr_errors::QUOTA, [0; 3]);
    }
    let Some(v) = l.next_to_write(&mut state().hand, TAKE_STEPS)
    else
    {
        return (memmgr_errors::NOTHING_TO_TAKE, [0; 3]);
    };
    let entry = l.chunk_at(v.reg, v.page_base);
    let raw = entry.is_raw();
    let mut buf = buf();
    let buf = &mut buf.0;
    let read = if raw
    {
        evict::read_raw(l, v.rec, v.reg, v.page_base, buf)
    }
    else
    {
        evict::read_store(l, entry, buf)
    };
    let Some(len) = read
    else
    {
        return (memmgr_errors::QUOTA, [0; 3]);
    };
    let nonce = {
        let mut s = state();
        let nonce = s.nonce;
        // A nonce is used once under the key, whatever follows: 2^64 seals
        // never run out within a boot.
        s.nonce = s.nonce.wrapping_add(1);
        nonce
    };
    let sealed = if raw
    {
        disk::seal_detached(&key, nonce, buf, len).map(|tag| (len, Some(tag)))
    }
    else
    {
        disk::seal(&key, nonce, buf, len).map(|total| (total, None))
    };
    let Ok((total, tag)) = sealed
    else
    {
        return (memmgr_errors::QUOTA, [0; 3]);
    };
    let pages = u64::try_from(total).unwrap_or(u64::MAX).div_ceil(PAGE_SIZE);
    // SAFETY: the swap window is memmgr's own zone, which every use leaves
    // unmapped, a failed map included; `pages` is at most a chunk's, the
    // window's size.
    if unsafe { map_self(l, cap, SWAP_WINDOW_VA, 0, pages) }.is_err()
    {
        return (memmgr_errors::INVALID_ARGUMENT, [0; 3]);
    }
    let Some(sealed) = buf.get(..total)
    else
    {
        unmap_window(pages);
        return (memmgr_errors::QUOTA, [0; 3]);
    };
    // SAFETY: `pages` pages of the swap service's buffer are mapped
    // read-write at the swap window, which nothing else in memmgr refers to,
    // and `sealed` fits them. Through memmgr's own mapping the stores neither
    // fault nor block. The unmap below is inline assembly without `nomem`, so
    // the stores are made before it.
    unsafe {
        core::ptr::copy_nonoverlapping(sealed.as_ptr(), SWAP_WINDOW_VA as *mut u8, total);
    }
    unmap_window(pages);
    // `total` is at most a slot's bytes.
    let Ok(len32) = u32::try_from(total)
    else
    {
        return (memmgr_errors::QUOTA, [0; 3]);
    };
    match l.begin_write(v.rec, v.reg, v.page_base, nonce, len32, tag)
    {
        Ok(slot) => (
            memmgr_errors::SUCCESS,
            [
                u64::from(slot),
                u64::from(len32),
                disk::slot_word(slot, len32, nonce),
            ],
        ),
        Err(SwapError::NoSwapSlot) => (memmgr_errors::SWAP_FULL, [0; 3]),
        Err(_) => (memmgr_errors::QUOTA, [0; 3]),
    }
}

/// `SWAP_DONE` (services/memmgr/docs/ipc-interface.md § Label 24): `data[0]`
/// the slot, `data[1]` `0` when its write ended well. A written chunk is on
/// disk and its store runs, or a raw chunk's runs, return to the pool
/// ([`free_pool::Ledger::finish_write`]); an unwritten one is compressed, or
/// raw, again on them ([`free_pool::Ledger::abandon_write`]); a write a restore or a
/// teardown cancelled meanwhile frees its slot either way. Reply: `SUCCESS`,
/// or `INVALID_ARGUMENT` for a slot that holds no write in flight.
fn handle_done(l: &mut MemLedger, req: &IpcMessage, answer: &mut Answer)
{
    let done = u32::try_from(req.word(0)).is_ok_and(|slot| {
        if req.word(1) == 0
        {
            l.finish_write(slot, crate::quiescent).is_ok()
        }
        else
        {
            l.abandon_write(slot).is_ok()
        }
    });
    if done
    {
        coalesce(l);
    }
    answer.set_status(
        if done
        {
            memmgr_errors::SUCCESS
        }
        else
        {
            memmgr_errors::INVALID_ARGUMENT
        },
    );
}

/// `SWAP_WANTED` (services/memmgr/docs/ipc-interface.md § Label 26): reply the
/// slot words `MAKE_RESIDENT` posted for the swap service, oldest first, and
/// empty the list. The words name uses of slots that may have ended since: a
/// `SWAP_RESTORE` of one replies `RESTORE_STALE` then, and changes nothing.
fn handle_wanted(answer: &mut Answer)
{
    let mut words = [0u64; WANT_WORDS];
    let n = state().wants.take(&mut words);
    let taken = words.get(..n).unwrap_or(&[]);
    let reply = IpcMessage::builder(memmgr_errors::SUCCESS)
        .word(0, u64::try_from(n).unwrap_or(0))
        .words(1, taken)
        .build();
    answer.set(reply);
}

/// `SWAP_RESTORE` (services/memmgr/docs/ipc-interface.md § Label 25):
/// `data[0]` the slot word of a fault's redirect or of `SWAP_TAKE`'s reply
/// ([`disk::slot_word`]), `caps[0]` a Memory cap holding the slot's bytes
/// from offset 0, moved back on every reply. A word that names no chunk on
/// disk ([`free_pool::Ledger::on_disk_named`]), its slot holding none or a
/// later seal's, replies `RESTORE_STALE` and changes nothing: the request
/// was made for a use of the slot that has ended, and the swap service
/// resumes the held fault, which faults again and is served as its chunk now
/// stands. Otherwise memmgr maps the cap read-only at the swap
/// window, copies the slot's bytes into its own buffer, and opens them there
/// under the nonce of the chunk's last seal, a raw chunk's against the tag
/// kept on its entry: on a tag failure the chunk is
/// lost ([`free_pool::Ledger::lose_chunk`]), and the reply is
/// `RESTORE_DECLINED` with `data[0]` the code-12 word of detail 1, which the
/// swap service forwards the held fault with, so the faulting thread is
/// killed, as every later fault on the chunk is. Otherwise the chunk is
/// restored from the opened stream as from the store, or from a raw chunk's
/// opened pages (`evict::restore`):
/// admitted, its pages filled and mapped, its slot freed. A restore memmgr
/// cannot make replies `RESTORE_DECLINED` with that restore's decline word,
/// the chunk staying on disk. Reply: `SUCCESS`; `RESTORE_DECLINED`;
/// `RESTORE_STALE`; or `INVALID_ARGUMENT` for a missing or small cap, or
/// one memmgr cannot map.
fn handle_restore(l: &mut MemLedger, req: &IpcMessage, caps: &[u64], answer: &mut Answer)
{
    let Some(&cap) = caps.first()
    else
    {
        answer.set_status(memmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let (label, word) = restore(l, req.word(0), cap);
    reply_with_cap(answer, label, &[word], cap);
}

/// [`handle_restore`]'s work: its reply label and word.
fn restore(l: &mut MemLedger, word: u64, cap: u64) -> (u64, u64)
{
    let Some(key) = state().key
    else
    {
        return (memmgr_errors::INVALID_ARGUMENT, 0);
    };
    let Some(n) = l.on_disk_named(word)
    else
    {
        return (memmgr_errors::RESTORE_STALE, 0);
    };
    let slot = n.slot;
    let tag = l.chunk_at(n.reg, n.page_base).tag();
    let Ok(total) = usize::try_from(n.len)
    else
    {
        return (memmgr_errors::INVALID_ARGUMENT, 0);
    };
    let bytes = u64::from(n.len);
    if !is_memory_of(cap, bytes)
    {
        return (memmgr_errors::INVALID_ARGUMENT, 0);
    }
    let pages = bytes.div_ceil(PAGE_SIZE);
    // SAFETY: the swap window is memmgr's own zone, which every use leaves
    // unmapped, a failed map included; `pages` is at most a chunk's, the
    // window's size.
    if unsafe { map_self_with(l, cap, SWAP_WINDOW_VA, 0, pages, MAP_READ) }.is_err()
    {
        return (memmgr_errors::INVALID_ARGUMENT, 0);
    }
    let mut buf = buf();
    let buf = &mut buf.0;
    if let Some(dst) = buf.get_mut(..total)
    {
        // SAFETY: `pages` pages of the swap service's buffer are mapped
        // read-only at the swap window, which nothing else in memmgr refers
        // to, and `dst` fits them. Through memmgr's own mapping the loads
        // neither fault nor block; what the swap service writes meanwhile
        // changes only what the tag check below refuses.
        unsafe {
            core::ptr::copy_nonoverlapping(SWAP_WINDOW_VA as *const u8, dst.as_mut_ptr(), total);
        }
    }
    unmap_window(pages);
    let opened = match tag
    {
        Some(tag) => disk::open_detached(&key, n.nonce, buf, total, &tag).map(|()| total),
        None => disk::open(&key, n.nonce, buf, total),
    };
    let stream = match opened
    {
        Ok(len) => len,
        Err(SlotError::Tampered | SlotError::Size) =>
        {
            let _ = l.lose_chunk(slot);
            return (
                memmgr_errors::RESTORE_DECLINED,
                decline_word(FaultDecline::OnDiskChunk, DETAIL_LOST),
            );
        }
    };
    let Some((reg, region)) = l.region_for(n.rec, n.page_base)
    else
    {
        return (
            memmgr_errors::RESTORE_DECLINED,
            decline_word(FaultDecline::NoRegion, 0),
        );
    };
    let aspace = l.aspace_cap(n.rec);
    if aspace == 0 || reg != n.reg
    {
        return (
            memmgr_errors::RESTORE_DECLINED,
            decline_word(FaultDecline::NoAspace, 0),
        );
    }
    let bytes = buf.get(..stream).unwrap_or(&[]);
    let source = if tag.is_some()
    {
        evict::Source::Pages(bytes)
    }
    else
    {
        evict::Source::Stream(bytes)
    };
    match evict::restore(l, n.rec, reg, &region, n.page_base, aspace, source)
    {
        Ok(()) => (memmgr_errors::SUCCESS, 0),
        Err((reason, detail)) => (
            memmgr_errors::RESTORE_DECLINED,
            decline_word(reason, detail),
        ),
    }
}
