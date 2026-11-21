// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/snapshot.rs

//! `SNAPSHOT` and `CHECKPOINT`: capture a live process's pages into a memory
//! object charged to the snapshotter (services/procmgr/docs/ipc-interface.md
//! § Label 33: `SNAPSHOT`, § Label 35: `CHECKPOINT`). A checkpoint is the
//! same capture, with the process's consent checked under the hold and a
//! checkpoint section in the layout ([`Consent`]).
//!
//! Every request to memmgr names the target's image object, when procmgr
//! shares one with it (`memmgr_labels::CAPTURE_IMAGE`), so memmgr reports the
//! pages the target attaches of it, and has no copy of, by their image page
//! instead of their bytes. Before the hold, procmgr has memmgr post the
//! target's chunks on disk to the swap service and count the pages of its
//! regions it would write that no mapping shows
//! (`memmgr_labels::CAPTURE_COUNT`), waits a bounded time while the swap
//! service restores them, lists the target's mapped pages, and requests frames
//! for both on the snapshotter's account. It then holds the target's address
//! space (`SYS_ASPACE_HOLD`), so no thread of it runs, registered or not, and
//! lists the pages again. memmgr describes every region of the target and
//! writes what it holds of each into the frames
//! (`memmgr_labels::CAPTURE_CHUNKS`), from wherever it holds each chunk in that
//! turn, so no eviction meanwhile can move a chunk's content out of the
//! capture; a chunk still on disk it posts to the swap service, and procmgr
//! asks for it again after a pause, waiting a bounded time while the swap
//! service restores it. procmgr copies every listed page outside the regions
//! with `SYS_THREAD_READ_MEM` into the next frames, reads each thread it holds a
//! cap to (the main thread, then each registered one) into its heap
//! (`SYS_THREAD_READ_REGS`, `SYS_THREAD_READ_EXT_REGS`), and releases the
//! space. After the release it builds the layout
//! (`process_table::snapshot::layout`), writes it and the thread records into
//! frames of its own grant, and seals the layout and the data, in that order,
//! into one memory object on the account.
//!
//! The account is a memmgr SEND the snapshotter presents, which the request
//! carries: procmgr cannot tell that it names memmgr, so every call on it
//! is bounded ([`ACCOUNT_CALL_TIMEOUT_MS`]), and the first failure fails the
//! capture, releasing the hold and every grant taken. Under the hold procmgr
//! calls only memmgr, on its own endpoint and on the account, waits on the
//! swap service at most [`CAPTURE_STALL_PAUSES`] pauses in a row that restore
//! nothing, and writes no log line, so a held target that serves procmgr
//! (logd among them) or the swap service cannot stall the capture.

use crate::process::CapGuard;
use ipc::memmgr_capture::{
    Chunk, DESCRIPTOR_WORDS, DESCRIPTORS_MAX, Descriptor, REPLY_WORDS, REQUEST_WORDS,
};
use ipc::procmgr_snapshot::{
    CHECKPOINT_BYTES, Checkpoint, Header, IMAGE_HASH_BYTES, Image, SNAPSHOT_CHECKPOINT,
    SNAPSHOT_COMPLETE, SNAPSHOT_IMAGE, ThreadRecord, threads_offset,
};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors};
use process_table::snapshot::{Described, Layout, Listing, Placed, copied_pages, layout, outside};
use std::collections::TryReserveError;
use std::os::seraph::{ReservedRange, reserve_pages, unreserve_pages};
use std::time::Duration;
use syscall_abi::{
    MAX_PAGE_RUNS, MAX_THREAD_MEM_COPY, MSG_CAP_SLOTS_MAX, PAGE_RUN_NO_COPY, PAGE_SIZE, PageRun,
    REGS_RISCV64_SIZE, REGS_X86_64_SIZE, SyscallError,
};

/// How long procmgr waits, at most, on each call it makes on the
/// snapshotter's account (`REQUEST_MEMORY_CAPS`, `RELEASE_MEMORY_CAPS`,
/// `SEAL_OBJECT`, `OBJECT_RELEASE`): 10 s, as for a caller's file cap. The
/// account is a cap the caller presents, so a server behind it that never
/// answers fails the capture, and releases a held target, once the bound
/// passes, instead of holding the request worker and the target for good.
pub const ACCOUNT_CALL_TIMEOUT_MS: u32 = 10_000;

/// Pages of procmgr's address space through which the copy maps the data
/// frames, a window at a time: 64, 256 KiB. It bounds procmgr's own
/// reservation and page tables for a capture of any size.
const WINDOW_PAGES: u64 = 64;

// `SYS_THREAD_READ_MEM` copies at most `MAX_THREAD_MEM_COPY` bytes a call,
// and the copy reads a page a call.
const _: () = assert!(MAX_THREAD_MEM_COPY as u64 == PAGE_SIZE);

/// Bytes of the buffer a thread's register file is read into: the larger
/// architecture's file.
const REGS_BUF_BYTES: usize = if REGS_X86_64_SIZE > REGS_RISCV64_SIZE
{
    REGS_X86_64_SIZE
}
else
{
    REGS_RISCV64_SIZE
};

/// Destination caps one `CAPTURE_CHUNKS` request carries at most: all of a
/// message's cap slots but the last, which carries the image's handle.
const DEST_CAPS: usize = MSG_CAP_SLOTS_MAX - 1;

/// Region ids one `RELEASE_MEMORY_CAPS` names: every data word after the count.
const RELEASE_IDS_PER_CALL: usize = syscall_abi::MSG_DATA_WORDS_MAX - 1;

/// Milliseconds procmgr pauses before it asks memmgr again for the target's
/// chunks on disk, whose slot words memmgr posted to the swap service: a
/// tuning value of the order of a swap slot's read and restore.
const CAPTURE_PAUSE_MS: u64 = 10;

/// Pauses in a row that restore no chunk on disk after which procmgr waits
/// no longer for the swap service, the chunks still on disk then absent: 100,
/// a second of [`CAPTURE_PAUSE_MS`]. It bounds how long a swap service that
/// does not answer, or is the held target or waits on it, holds a capture,
/// before the hold and under it.
const CAPTURE_STALL_PAUSES: u32 = 100;

/// What a capture needs of procmgr.
pub struct Context
{
    /// procmgr's own address space, where the frames are mapped to be filled.
    pub self_aspace: u64,
    /// procmgr's SEND on memmgr, for `CAPTURE_CHUNKS`.
    pub memmgr_ep: u64,
    /// The calling worker's IPC buffer.
    pub ipc_buf: *mut u64,
}

/// The target of a capture, its caps derived under the table lock so a
/// teardown meanwhile leaves caps that name the same objects, or that the
/// kernel refuses, never a slot another cap took.
pub struct Target
{
    /// The target's `AddressSpace`, with the Control right the hold takes.
    pub aspace: CapGuard,
    /// The target's main thread, through which its space is listed and read,
    /// and whose state is recorded at index 0.
    pub thread: CapGuard,
    /// The target's registered threads whose caps were derived, each with
    /// its index in the `ATTACH_PROCESS` list, ascending.
    pub registered: Vec<TargetThread>,
    /// The target's memmgr badge, which names it to `CAPTURE_CHUNKS`.
    pub memmgr_badge: u64,
    /// The target's image load bias, as `ATTACH_PROCESS` reports it.
    pub load_bias: u64,
    /// The image the target attaches, when procmgr shares one with it.
    pub image: Option<TargetImage>,
}

/// A registered thread of the target, whose state a capture records.
pub struct TargetThread
{
    /// The thread's index in the `ATTACH_PROCESS` list: 1 for the first
    /// registered thread.
    pub index: u64,
    /// The thread's cap, with Observe.
    pub cap: CapGuard,
}

/// The image a target attaches (services/procmgr/README.md § Image
/// Sharing): a copy of its object's handle, taken under the image cache's
/// lock, and the body it is the image of, which the layout's header names.
pub struct TargetImage
{
    /// A SEND copy of the object's handle.
    pub handle: CapGuard,
    /// The body's SHA-512 and length.
    pub image: Image,
}

/// What a `CHECKPOINT` adds to a capture (docs/checkpoint-restore.md
/// § Checkpoint).
pub struct Consent<'a>
{
    /// Called under the hold: a copy of the Notification of the quiesce point
    /// the request found, while the process is still at it; `NOT_QUIESCED`
    /// when it left it, `INVALID_BADGE` when it ended, `OUT_OF_MEMORY` when
    /// the copy cannot be had.
    pub check: &'a mut dyn FnMut() -> Result<CapGuard, u64>,
    /// The checkpoint section from the process's entry; the capture reads
    /// the words its `ProcessInfo` names under the hold.
    pub section: Checkpoint,
}

/// A capture's object: its handle, its pages, and whether no run is absent.
pub struct Captured
{
    /// The object handle, in procmgr's `CSpace`.
    pub handle: u64,
    /// The object's pages.
    pub pages: u64,
    /// No run of the layout is absent.
    pub complete: bool,
    /// For a checkpoint, the copy of the quiesce point's Notification
    /// ([`Consent::check`]); none for a `SNAPSHOT`.
    pub notify: CapGuard,
}

/// Capture `target` into a memory object sealed on `account`, a memmgr
/// SEND the snapshotter presents, which stays the caller's. With `consent`
/// the capture is a checkpoint: right after the hold is taken it calls
/// [`Consent::check`] and reads the target's `ProcessInfo`, and the layout
/// carries the checkpoint section.
///
/// # Errors
/// [`Consent::check`]'s code; `SPACE_HELD` when the target's space is held already or the hold was
/// interrupted; `INVALID_BADGE` when the target ended before or during the
/// capture; `LIMIT` when the max of the account's budget node or of an
/// ancestor refused its frames ([`Grants::cover`]); `OUT_OF_MEMORY` when
/// the account refused otherwise or failed a call,
/// granted a run procmgr refuses, or the object would take more grants than
/// one seal names, when memmgr failed a request, or when procmgr's heap or
/// address space refused the capture's own memory.
pub fn capture(
    ctx: &Context,
    target: &Target,
    account: u64,
    consent: Option<&mut Consent<'_>>,
) -> Result<Captured, u64>
{
    let account = Account {
        cap: account,
        ipc_buf: ctx.ipc_buf,
    };
    let top = syscall::user_va_top().map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    // Before the hold: the chunks on disk asked for and waited on, and the
    // frames for what is mapped and what memmgr holds evicted then. Each
    // chunk is read under the hold, wherever memmgr holds it then.
    let unmapped = survey(ctx, target, top)?;
    let mut data = Grants::new(&account);
    data.cover(
        list(target.thread.cap(), top)?
            .copied_pages()
            .saturating_add(unmapped),
    )?;
    let mut window = Window::new(ctx.self_aspace)?;

    let hold = Hold::take(target.aspace.cap())?;
    // The process cannot leave its quiesce point while held: one that left it
    // before may have written its memory since.
    let (notify, checkpoint) = match consent
    {
        Some(consent) =>
        {
            let notify = (consent.check)()?;
            let section = read_bootstrap(target.thread.cap(), consent.section)?;
            (notify, Some(section))
        }
        None => (CapGuard::new(0), None),
    };
    let listing = list(target.thread.cap(), top)?;
    let mut inside = Capture::default();
    inside.walk(ctx, target, (0, top), &mut data)?;
    inside.await_disk(ctx, target, &mut data)?;
    let outside = outside(listing.runs(), &inside.described.regions).map_err(runs_code)?;
    data.cover(inside.filled.saturating_add(copied_pages(&outside)))?;
    let failed = copy(
        target.thread.cap(),
        &outside,
        inside.filled,
        &data,
        &mut window,
    )?;
    let threads = read_threads(target)?;
    drop(hold);
    drop(window);

    let section_bytes = if checkpoint.is_some()
    {
        CHECKPOINT_BYTES as u64
    }
    else
    {
        0
    };
    let tail_bytes = threads
        .bytes()
        .and_then(|n| n.checked_add(section_bytes))
        .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    let layout = layout(
        &outside,
        inside.filled,
        &failed,
        &inside.described,
        tail_bytes,
    )
    .map_err(runs_code)?;
    data.keep(layout.data_pages);
    let mut head = Grants::new(&account);
    head.cover(layout.layout_pages)?;
    let about = About {
        image: target.image.as_ref().map(|i| i.image),
        load_bias: target.load_bias,
        threads: &threads,
        checkpoint,
    };
    write_layout(ctx.self_aspace, &head, &layout, &about)?;
    let (handle, pages) = seal(&account, head, data)?;
    Ok(Captured {
        handle,
        pages,
        complete: layout.complete,
        notify,
    })
}

/// `section` with the words the target's `ProcessInfo` names, read at
/// `section.process_info_va` through its thread `thread`: its main
/// thread's IPC buffer and its argv and env header. procmgr alone writes the
/// page, which the process maps read-only.
///
/// # Errors
/// `INVALID_BADGE` when the target ended; `OUT_OF_MEMORY` when the page
/// cannot be read otherwise.
fn read_bootstrap(thread: u64, section: Checkpoint) -> Result<Checkpoint, u64>
{
    let mut info = core::mem::MaybeUninit::<process_abi::ProcessInfo>::zeroed();
    let len = core::mem::size_of::<process_abi::ProcessInfo>();
    // SAFETY: the span is `info`'s own, `len` bytes, no Rust reference names
    // it while the kernel writes it, and every field of `ProcessInfo` is an
    // integer, valid for any byte value.
    let copied = unsafe {
        syscall::thread_read_mem_raw(
            thread,
            section.process_info_va,
            info.as_mut_ptr().cast(),
            len,
        )
    }
    .map_err(target_code)?;
    if copied != len as u64
    {
        return Err(procmgr_errors::OUT_OF_MEMORY);
    }
    // SAFETY: zeroed, then written in full, and any byte value is valid.
    let info = unsafe { info.assume_init() };
    Ok(Checkpoint {
        ipc_buffer_va: info.ipc_buffer_vaddr,
        args_offset: info.args_offset,
        args_bytes: info.args_bytes,
        args_count: info.args_count,
        env_offset: info.env_offset,
        env_bytes: info.env_bytes,
        env_count: info.env_count,
        ..section
    })
}

/// The reply code of runs procmgr's heap refused.
fn runs_code(_: TryReserveError) -> u64
{
    procmgr_errors::OUT_OF_MEMORY
}

/// The reply code of a syscall on the target's caps that failed with `err`:
/// a cap the kernel refuses, or a thread or space that ended, means the
/// target ended (`INVALID_BADGE`); anything else, `OUT_OF_MEMORY`.
fn target_code(err: i64) -> u64
{
    if err == SyscallError::InvalidCapability as i64 || err == SyscallError::InvalidState as i64
    {
        procmgr_errors::INVALID_BADGE
    }
    else
    {
        procmgr_errors::OUT_OF_MEMORY
    }
}

/// Call memmgr with `msg` on procmgr's own endpoint: its reply when it
/// succeeded; `INVALID_BADGE` when memmgr knows the target's badge no more,
/// the target torn down; else `OUT_OF_MEMORY`.
fn memmgr_call(ctx: &Context, msg: &IpcMessage) -> Result<IpcMessage, u64>
{
    // SAFETY: `ipc_buf` is the calling worker's registered IPC buffer.
    match unsafe { ipc::ipc_call(ctx.memmgr_ep, msg, ctx.ipc_buf) }
    {
        Ok(reply) if reply.label == memmgr_errors::SUCCESS => Ok(reply),
        Ok(reply) if reply.label == memmgr_errors::INVALID_ARGUMENT =>
        {
            Err(procmgr_errors::INVALID_BADGE)
        }
        _ => Err(procmgr_errors::OUT_OF_MEMORY),
    }
}

/// Have memmgr post every chunk of the target on disk to the swap service and
/// count the pages it would write that no mapping shows (`CAPTURE_COUNT`),
/// over the user half up to `top`, again after each pause of
/// [`CAPTURE_PAUSE_MS`] while chunks on disk remain, until none does or
/// [`CAPTURE_STALL_PAUSES`] pauses in a row leave no fewer. Returns the pages
/// memmgr counted last.
fn survey(ctx: &Context, target: &Target, top: u64) -> Result<u64, u64>
{
    let (mut fewest, mut stalled) = (u64::MAX, 0u32);
    loop
    {
        let (unmapped, on_disk) = count(ctx, target, top)?;
        if on_disk < fewest
        {
            fewest = on_disk;
            stalled = 0;
        }
        else
        {
            stalled = stalled.saturating_add(1);
        }
        if on_disk == 0 || stalled >= CAPTURE_STALL_PAUSES
        {
            return Ok(unmapped);
        }
        std::thread::sleep(Duration::from_millis(CAPTURE_PAUSE_MS));
    }
}

/// One `CAPTURE_COUNT` pass over the user half up to `top`: the pages memmgr
/// would write of the target's regions that no mapping shows, and its chunks
/// on disk memmgr posted.
fn count(ctx: &Context, target: &Target, top: u64) -> Result<(u64, u64), u64>
{
    let (mut unmapped, mut on_disk, mut at) = (0u64, 0u64, 0u64);
    while at < top
    {
        let (flags, image) = image_arg(target)?;
        let words = [
            target.memmgr_badge,
            at,
            top,
            memmgr_labels::CAPTURE_COUNT | flags,
        ];
        let reply = call_with(ctx, &words, &[], image)?;
        let (next, pages, posted) = (reply.word(0), reply.word(1), reply.word(2));
        unmapped = unmapped.saturating_add(pages);
        on_disk = on_disk.saturating_add(posted);
        // memmgr moves forward on every reply; one that did not would loop.
        if next <= at
        {
            return Err(procmgr_errors::OUT_OF_MEMORY);
        }
        at = next;
    }
    Ok((unmapped, on_disk))
}

/// Call memmgr on procmgr's own endpoint ([`memmgr_call`]) with a
/// `CAPTURE_CHUNKS` request of the data words `words`, carrying the caps
/// `caps`, then `image` when there is one, and return the reply. A call that fails deletes the caps: one refused before memmgr
/// received it leaves them procmgr's, and a handle the call moved is stale,
/// its delete failing harmlessly.
fn call_with(
    ctx: &Context,
    words: &[u64],
    caps: &[u64],
    image: Option<u64>,
) -> Result<IpcMessage, u64>
{
    let mut msg = IpcMessage::builder(memmgr_labels::CAPTURE_CHUNKS).words(0, words);
    for &cap in caps.iter().chain(image.as_slice())
    {
        msg = msg.cap(cap);
    }
    let reply = memmgr_call(ctx, &msg.build());
    if reply.is_err()
    {
        crate::release_caps(caps);
        crate::release_caps(image.as_slice());
    }
    reply
}

/// The `CAPTURE_IMAGE` flag and a SEND copy of the image's handle for one
/// `CAPTURE_CHUNKS` request on `target`, which memmgr deletes; no flag and
/// no cap for a target with no image.
///
/// # Errors
/// `OUT_OF_MEMORY` when the handle cannot be copied.
fn image_arg(target: &Target) -> Result<(u64, Option<u64>), u64>
{
    let Some(image) = &target.image
    else
    {
        return Ok((0, None));
    };
    let cap = syscall::cap_derive(image.handle.cap(), syscall::RIGHTS_EP_SEND)
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    Ok((memmgr_labels::CAPTURE_IMAGE, Some(cap)))
}

/// What memmgr described of the target's regions under the hold, in address
/// order, and the data pages before the next chunk's: those the chunks it
/// wrote took, and any passed over because the grants that held them could
/// not hold a chunk in one request.
#[derive(Default)]
struct Capture
{
    described: Described,
    filled: u64,
}

impl Capture
{
    /// Have memmgr describe every region of `range` and write what it holds
    /// of each into the data frames after those filled (`CAPTURE_CHUNKS`),
    /// covering more frames on the account when memmgr needs them, and add
    /// each descriptor.
    ///
    /// # Errors
    /// As [`memmgr_call`]; [`Grants::cover`]'s code when the account refuses
    /// the frames; `OUT_OF_MEMORY` when procmgr's heap refuses the descriptors, or memmgr's reply
    /// names one out of order or of no kind, or pages it did not write.
    fn walk(
        &mut self,
        ctx: &Context,
        target: &Target,
        range: (u64, u64),
        data: &mut Grants<'_>,
    ) -> Result<(), u64>
    {
        let (mut at, end) = range;
        while at < end
        {
            let reply = self.request(ctx, target, (at, end), data)?;
            let (next, used, need) = (reply.word(0), reply.word(1), reply.word(2));
            let count = usize::try_from(reply.word(3)).unwrap_or(usize::MAX);
            if count > DESCRIPTORS_MAX
            {
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
            let (mut page, mut reached) = (self.filled, at);
            for i in 0..count
            {
                let word = REPLY_WORDS.saturating_add(i.saturating_mul(DESCRIPTOR_WORDS));
                let words = [0, 1, 2, 3].map(|k| reply.word(word.saturating_add(k)));
                let d = Descriptor::decode(words).ok_or(procmgr_errors::OUT_OF_MEMORY)?;
                reached = self.add(d, reached, &mut page)?;
            }
            if page != self.filled.saturating_add(used)
            {
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
            self.filled = page;
            if need > 0
            {
                // memmgr stopped at a chunk that needs more frames than the
                // caps it was given hold. One that stopped with room for it,
                // having written nothing, would loop; after chunks it wrote,
                // the next request's caps start further on.
                if used == 0 && data.holds(self.filled, need)
                {
                    return Err(procmgr_errors::OUT_OF_MEMORY);
                }
                self.make_room(need, data)?;
            }
            else if next <= at
            {
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
            at = next;
        }
        Ok(())
    }

    /// Add the descriptor `d`, which starts at or past `reached`, its
    /// written pages from data page `page`, which moves past them. Returns
    /// where the next descriptor starts at the earliest: a region's base, for
    /// its first chunk or range, or the end of a chunk or range.
    ///
    /// # Errors
    /// `OUT_OF_MEMORY` when `d` starts below `reached` or procmgr's heap
    /// refuses it.
    fn add(&mut self, d: Descriptor, reached: u64, page: &mut u64) -> Result<u64, u64>
    {
        let list = &mut self.described;
        let reserved = match d
        {
            Descriptor::Region(_) => list.regions.try_reserve(1),
            Descriptor::Chunk(_) => list.chunks.try_reserve(1),
            Descriptor::Range { .. } => list.ranges.try_reserve(1),
        };
        reserved.map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        let (va, past) = match d
        {
            Descriptor::Region(r) => (r.va, r.va),
            Descriptor::Chunk(c) => (c.va, c.end()),
            Descriptor::Range { va, pages } =>
            {
                (va, va.saturating_add(pages.saturating_mul(PAGE_SIZE)))
            }
        };
        if va < reached
        {
            return Err(procmgr_errors::OUT_OF_MEMORY);
        }
        match d
        {
            Descriptor::Region(r) => list.regions.push(r),
            Descriptor::Chunk(chunk) =>
            {
                list.chunks.push(Placed { chunk, data: *page });
                *page = page.saturating_add(chunk.written_pages());
            }
            Descriptor::Range { va, pages } => list.ranges.push((va, pages)),
        }
        Ok(past)
    }

    /// Cover frames on the account, and pass over the data pages up to the
    /// next grant's first while needed, until the grants one request carries
    /// from the next data page hold `need` pages: a request carries at most
    /// [`DEST_CAPS`] destination caps, so a chunk can need more pages than the
    /// grants from a page in a short grant hold, its rest passed over and left
    /// unused in the object.
    ///
    /// # Errors
    /// [`Grants::cover`]'s: `LIMIT` or `OUT_OF_MEMORY` when the account
    /// refuses the frames, `OUT_OF_MEMORY` when the grants would be more than
    /// one seal names.
    fn make_room(&mut self, need: u64, data: &mut Grants<'_>) -> Result<(), u64>
    {
        data.cover(self.filled.saturating_add(need))?;
        while !data.holds(self.filled, need)
        {
            self.filled = data.next_grant(self.filled);
            data.cover(self.filled.saturating_add(need))?;
        }
        Ok(())
    }

    /// One `CAPTURE_CHUNKS` request over `[at, end)`, carrying caps derived
    /// from the grants that hold the data pages after those filled, at most
    /// [`DEST_CAPS`], then the image's handle when the target has one, and
    /// memmgr's reply.
    fn request(
        &self,
        ctx: &Context,
        target: &Target,
        (at, end): (u64, u64),
        data: &Grants<'_>,
    ) -> Result<IpcMessage, u64>
    {
        let (grants, offset) = data.at_page(self.filled);
        let (flags, image) = image_arg(target)?;
        // The request's words: the target, the range, the flags, the offset
        // into the first grant, then the pages of each grant from there.
        let mut words = [0u64; REQUEST_WORDS + DEST_CAPS];
        let (head, pages) = words.split_at_mut(REQUEST_WORDS);
        for (slot, word) in head
            .iter_mut()
            .zip([target.memmgr_badge, at, end, flags, offset])
        {
            *slot = word;
        }
        let mut derived = [0u64; DEST_CAPS];
        for (i, (grant, (slot, count))) in grants
            .iter()
            .zip(derived.iter_mut().zip(pages.iter_mut()))
            .enumerate()
        {
            let Ok(cap) = syscall::cap_derive(grant.cap, syscall::RIGHTS_MEM_MAP_RW)
            else
            {
                crate::release_caps(&derived);
                crate::release_caps(image.as_slice());
                return Err(procmgr_errors::OUT_OF_MEMORY);
            };
            *slot = cap;
            *count = if i == 0
            {
                grant.pages.saturating_sub(offset)
            }
            else
            {
                grant.pages
            };
        }
        let n = grants.len().min(DEST_CAPS);
        call_with(
            ctx,
            words.get(..REQUEST_WORDS.saturating_add(n)).unwrap_or(&[]),
            derived.get(..n).unwrap_or(&[]),
            image,
        )
    }

    /// Ask memmgr again, after each pause of [`CAPTURE_PAUSE_MS`], for each
    /// chunk on disk it posted to the swap service, until none is left or
    /// [`CAPTURE_STALL_PAUSES`] pauses in a row restore none; one still on disk
    /// then has its backed pages absent.
    fn await_disk(
        &mut self,
        ctx: &Context,
        target: &Target,
        data: &mut Grants<'_>,
    ) -> Result<(), u64>
    {
        let mut stalled = 0u32;
        while stalled < CAPTURE_STALL_PAUSES
            && self.described.chunks.iter().any(|p| p.chunk.pending)
        {
            std::thread::sleep(Duration::from_millis(CAPTURE_PAUSE_MS));
            let mut restored = false;
            for i in 0..self.described.chunks.len()
            {
                let Some(placed) = self
                    .described
                    .chunks
                    .get(i)
                    .copied()
                    .filter(|p| p.chunk.pending)
                else
                {
                    continue;
                };
                let chunk = placed.chunk;
                let mut again = Self {
                    described: Described::default(),
                    filled: self.filled,
                };
                again.walk(ctx, target, (chunk.va, chunk.end()), data)?;
                self.filled = again.filled;
                // A chunk memmgr names no more holds no page of its own: each
                // is what its region's origin gives.
                let now = again
                    .described
                    .chunks
                    .into_iter()
                    .find(|p| p.chunk.va == chunk.va)
                    .unwrap_or(Placed {
                        chunk: Chunk {
                            backed: 0,
                            written: 0,
                            pending: false,
                            ..chunk
                        },
                        data: placed.data,
                    });
                restored |= !now.chunk.pending;
                if let Some(slot) = self.described.chunks.get_mut(i)
                {
                    *slot = now;
                }
            }
            stalled = if restored
            {
                0
            }
            else
            {
                stalled.saturating_add(1)
            };
        }
        Ok(())
    }
}

/// The mapped pages of the space `thread` executes in, below `top`, the top
/// of the user half.
fn list(thread: u64, top: u64) -> Result<Listing, u64>
{
    let mut listing = Listing::default();
    let mut page = Vec::new();
    page.try_reserve_exact(usize::try_from(MAX_PAGE_RUNS).unwrap_or(1))
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    page.resize(page.capacity(), PageRun::default());
    let mut start = 0;
    loop
    {
        let (n, resume) =
            syscall::thread_list_pages(thread, start, &mut page).map_err(target_code)?;
        listing
            .push(page.get(..n).unwrap_or_default())
            .map_err(runs_code)?;
        // The listing is complete at the top of the user half; a call that
        // did not move on would loop.
        if resume >= top || resume <= start
        {
            return Ok(listing);
        }
        start = resume;
    }
}

/// Copy every page of `runs` but those of `PAGE_RUN_NO_COPY` runs into the
/// data frames, in address order, each into the next data page from `first`;
/// a page whose copy fails takes none. Returns the addresses of those pages,
/// ascending.
fn copy(
    thread: u64,
    runs: &[PageRun],
    first: u64,
    data: &Grants<'_>,
    window: &mut Window,
) -> Result<Vec<u64>, u64>
{
    let mut failed = Vec::new();
    let mut dst = first;
    for run in runs.iter().filter(|r| r.prot & PAGE_RUN_NO_COPY == 0)
    {
        for i in 0..run.pages
        {
            let va = run.va.saturating_add(i.saturating_mul(PAGE_SIZE));
            let page = window.page(data, dst)?;
            // SAFETY: `page` is a page of the window, mapped writable to a
            // frame of the capture's grants that procmgr alone holds; no Rust
            // object lives there, and any byte value is valid where the seal
            // hands the frame on.
            match unsafe { syscall::thread_read_mem_raw(thread, va, page, MAX_THREAD_MEM_COPY) }
            {
                Ok(_) => dst = dst.saturating_add(1),
                // A page unmapped since the listing: recorded absent.
                Err(e) if e == SyscallError::InvalidAddress as i64 =>
                {
                    failed
                        .try_reserve(1)
                        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
                    failed.push(va);
                }
                Err(e) => return Err(target_code(e)),
            }
        }
    }
    Ok(failed)
}

/// One thread's state as the hold left it, in procmgr's heap.
struct ThreadState
{
    index: u64,
    state: u64,
    regs: [u8; REGS_BUF_BYTES],
    regs_len: usize,
    ext: Vec<u8>,
}

impl ThreadState
{
    /// The record the layout holds of the thread.
    fn record(&self) -> ThreadRecord<'_>
    {
        ThreadRecord {
            index: self.index,
            state: self.state,
            regs: self.regs.get(..self.regs_len).unwrap_or_default(),
            ext: &self.ext,
        }
    }
}

/// The threads a capture read, in ascending index order.
struct Threads(Vec<ThreadState>);

impl Threads
{
    /// Bytes of their records together; `None` on overflow.
    fn bytes(&self) -> Option<u64>
    {
        self.0
            .iter()
            .try_fold(0u64, |n, t| n.checked_add(t.record().bytes()?))
    }
}

/// Under the hold, read the state of each of the target's threads it holds
/// a cap to: the main thread, then each registered one. A thread whose
/// register file cannot be read (it exited, or its cap was revoked) has no
/// record; one whose extended state cannot be read has a record with none.
///
/// # Errors
/// `OUT_OF_MEMORY` when procmgr's heap refuses the states.
fn read_threads(target: &Target) -> Result<Threads, u64>
{
    let mut out = Vec::new();
    out.try_reserve_exact(target.registered.len().saturating_add(1))
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    let all = core::iter::once((0, target.thread.cap()))
        .chain(target.registered.iter().map(|t| (t.index, t.cap.cap())));
    for (index, cap) in all
    {
        let mut regs = [0u8; REGS_BUF_BYTES];
        let Ok((len, state)) = syscall::thread_read_regs(cap, &mut regs)
        else
        {
            continue;
        };
        let regs_len = usize::try_from(len)
            .unwrap_or(usize::MAX)
            .min(REGS_BUF_BYTES);
        out.push(ThreadState {
            index,
            state,
            regs,
            regs_len,
            ext: read_ext(cap)?,
        });
    }
    Ok(Threads(out))
}

/// The extended-state image of the thread `cap` names: empty when the
/// thread has none or it cannot be read whole.
///
/// # Errors
/// `OUT_OF_MEMORY` when procmgr's heap refuses the image.
fn read_ext(cap: u64) -> Result<Vec<u8>, u64>
{
    let mut image = Vec::new();
    let mut chunk = [0u8; MAX_THREAD_MEM_COPY];
    loop
    {
        let Ok((copied, size)) = syscall::thread_read_ext_regs(cap, image.len() as u64, &mut chunk)
        else
        {
            return Ok(Vec::new());
        };
        let part = usize::try_from(copied)
            .ok()
            .and_then(|n| chunk.get(..n))
            .unwrap_or_default();
        if part.is_empty()
        {
            // An offset at the image's end: whole when it is the size.
            let whole = u64::try_from(image.len()).is_ok_and(|len| len == size);
            return Ok(if whole { image } else { Vec::new() });
        }
        image
            .try_reserve(part.len())
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        image.extend_from_slice(part);
        if u64::try_from(image.len()).is_ok_and(|len| len >= size)
        {
            image.truncate(usize::try_from(size).unwrap_or(0));
            return Ok(image);
        }
    }
}

/// The target's space held (`SYS_ASPACE_HOLD`) until the value drops,
/// which releases it on every path.
struct Hold
{
    aspace: u64,
}

impl Hold
{
    /// Hold the space `aspace` names.
    fn take(aspace: u64) -> Result<Self, u64>
    {
        match syscall::aspace_hold(aspace)
        {
            Ok(()) => Ok(Self { aspace }),
            Err(e)
                if e == SyscallError::InvalidState as i64
                    || e == SyscallError::Interrupted as i64 =>
            {
                Err(procmgr_errors::SPACE_HELD)
            }
            Err(e) => Err(target_code(e)),
        }
    }
}

impl Drop for Hold
{
    fn drop(&mut self)
    {
        // A space whose teardown began refuses nothing here: its release is a
        // no-op, and a revoked cap fails the call harmlessly.
        let _ = syscall::aspace_release(self.aspace);
    }
}

/// The snapshotter's memmgr SEND, on which every call is bounded.
struct Account
{
    cap: u64,
    ipc_buf: *mut u64,
}

impl Account
{
    /// Call the account with `msg`, waiting at most
    /// [`ACCOUNT_CALL_TIMEOUT_MS`].
    fn call(&self, msg: &IpcMessage) -> Result<IpcMessage, u64>
    {
        bounded_call(self.cap, msg, self.ipc_buf)
    }
}

/// Call `cap` with `msg`, waiting at most [`ACCOUNT_CALL_TIMEOUT_MS`];
/// `OUT_OF_MEMORY` when the call fails or the bound passes.
fn bounded_call(cap: u64, msg: &IpcMessage, ipc_buf: *mut u64) -> Result<IpcMessage, u64>
{
    // SAFETY: `ipc_buf` is the calling worker's registered IPC buffer.
    unsafe { ipc::ipc_call_timeout(cap, msg, ipc_buf, ACCOUNT_CALL_TIMEOUT_MS) }
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)
}

/// One grant of the account: its Memory cap in procmgr's `CSpace`, 0 once
/// deleted, its region id, and its pages.
struct Grant
{
    cap: u64,
    region: u64,
    pages: u64,
}

/// Grants taken on the account, in the order of the object's pages.
///
/// Invariant: every grant received is in `list` from the moment its reply
/// arrives, so [`Drop`] deletes procmgr's caps and returns each to the
/// account whatever step failed.
struct Grants<'a>
{
    account: &'a Account,
    list: Vec<Grant>,
    /// Pages of every grant in `list`.
    pages: u64,
}

impl<'a> Grants<'a>
{
    fn new(account: &'a Account) -> Self
    {
        Self {
            account,
            list: Vec::new(),
            pages: 0,
        }
    }

    /// Request frames on the account until the grants hold at least `pages`
    /// pages, as many runs as memmgr has.
    ///
    /// # Errors
    /// `LIMIT` when memmgr refuses a request for the max of the account's
    /// budget node or of an ancestor ([`process_table::memmgr_refusal`]);
    /// `OUT_OF_MEMORY` when a call fails, memmgr refuses a request otherwise, a
    /// grant's cap does not cover the pages its reply names, or the grants would
    /// be more than one seal names.
    fn cover(&mut self, pages: u64) -> Result<(), u64>
    {
        while self.pages < pages
        {
            let want = pages.saturating_sub(self.pages).min(u64::from(u32::MAX));
            let msg = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
                .word(0, want)
                .build();
            let reply = self.account.call(&msg)?;
            if reply.label != memmgr_errors::SUCCESS
            {
                crate::release_caps(reply.caps());
                return Err(process_table::memmgr_refusal(reply.label));
            }
            let Some((counts, regions)) = ipc::memmgr_grant_layout(&reply)
            else
            {
                crate::release_caps(reply.caps());
                return Err(procmgr_errors::OUT_OF_MEMORY);
            };
            if reply.caps().len() != regions.len() || self.list.try_reserve(regions.len()).is_err()
            {
                // The grants of a reply that is not kept go back at once:
                // none of them is in `list` for `Drop` to return.
                crate::release_caps(reply.caps());
                release_regions(self.account, regions.iter().copied());
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
            let mut whole = true;
            for ((&cap, &count), &region) in reply.caps().iter().zip(counts).zip(regions)
            {
                whole &= count != 0
                    && syscall::cap_info(cap, syscall_abi::CAP_INFO_MEMORY_SIZE)
                        .is_ok_and(|size| count.checked_mul(PAGE_SIZE) == Some(size));
                self.list.push(Grant {
                    cap,
                    region,
                    pages: count,
                });
                self.pages = self.pages.saturating_add(count);
            }
            if !whole || self.list.len() as u64 > memmgr_labels::SEAL_OBJECT_MAX_GRANTS
            {
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
        }
        Ok(())
    }

    /// Return to the account every grant past the first `pages` pages, so
    /// the object holds no whole grant it does not use.
    fn keep(&mut self, pages: u64)
    {
        let mut held = 0u64;
        let first = self
            .list
            .iter()
            .position(|g| {
                let past = held >= pages;
                held = held.saturating_add(g.pages);
                past
            })
            .unwrap_or(self.list.len());
        let rest = self.list.get(first..).unwrap_or(&[]);
        self.pages = self
            .pages
            .saturating_sub(rest.iter().fold(0, |n, g| n.saturating_add(g.pages)));
        release(self.account, rest);
        self.list.truncate(first);
    }

    /// The grants from the one holding page `index` of the grants, at most
    /// [`DEST_CAPS`], and the page's offset in the first: none when the
    /// grants hold no page `index`.
    fn at_page(&self, index: u64) -> (&[Grant], u64)
    {
        let mut base = 0u64;
        for (i, grant) in self.list.iter().enumerate()
        {
            if index < base.saturating_add(grant.pages)
            {
                let end = i.saturating_add(DEST_CAPS).min(self.list.len());
                return (
                    self.list.get(i..end).unwrap_or(&[]),
                    index.saturating_sub(base),
                );
            }
            base = base.saturating_add(grant.pages);
        }
        (&[], 0)
    }

    /// Whether the grants one request carries from page `index` ([`at_page`])
    /// hold `count` pages from it.
    fn holds(&self, index: u64, count: u64) -> bool
    {
        let (grants, offset) = self.at_page(index);
        grants
            .iter()
            .fold(0u64, |n, g| n.saturating_add(g.pages))
            .saturating_sub(offset)
            >= count
    }

    /// The first page of the grant after the one holding page `index`: the
    /// grants' pages when it is in the last, or past them.
    fn next_grant(&self, index: u64) -> u64
    {
        let mut end = 0u64;
        for grant in &self.list
        {
            end = end.saturating_add(grant.pages);
            if index < end
            {
                return end;
            }
        }
        self.pages.max(index.saturating_add(1))
    }

    /// The grant holding page `index` of the grants, and the page's offset in
    /// it.
    fn locate(&self, index: u64) -> Option<(&Grant, u64)>
    {
        let mut base = 0u64;
        for grant in &self.list
        {
            if index < base.saturating_add(grant.pages)
            {
                return Some((grant, index.saturating_sub(base)));
            }
            base = base.saturating_add(grant.pages);
        }
        None
    }
}

impl Drop for Grants<'_>
{
    fn drop(&mut self)
    {
        release(self.account, &self.list);
    }
}

/// Delete procmgr's caps to `grants` and return them to the account
/// (`RELEASE_MEMORY_CAPS`), which takes each back once no cap names it and
/// nothing maps it.
fn release(account: &Account, grants: &[Grant])
{
    for grant in grants.iter().filter(|g| g.cap != 0)
    {
        let _ = syscall::cap_delete(grant.cap);
    }
    release_regions(account, grants.iter().map(|g| g.region));
}

/// Return the regions `ids` to the account (`RELEASE_MEMORY_CAPS`), as
/// many to a call as one names. It allocates nothing, so it runs after a
/// heap refusal too.
fn release_regions(account: &Account, mut ids: impl Iterator<Item = u64>)
{
    let mut batch = [0u64; RELEASE_IDS_PER_CALL];
    loop
    {
        let n = batch
            .iter_mut()
            .zip(ids.by_ref())
            .map(|(slot, id)| *slot = id)
            .count();
        let Some(ids) = batch.get(..n).filter(|ids| !ids.is_empty())
        else
        {
            return;
        };
        let msg = IpcMessage::builder(memmgr_labels::RELEASE_MEMORY_CAPS)
            .word(0, n as u64)
            .words(1, ids)
            .build();
        let _ = account.call(&msg);
    }
}

/// A reservation of procmgr's address space through which the copy maps the
/// data frames, [`WINDOW_PAGES`] at a time.
struct Window
{
    range: Option<ReservedRange>,
    self_aspace: u64,
    /// The data page mapped at the window's first page, and the pages mapped.
    mapped: Option<(u64, u64)>,
}

impl Window
{
    fn new(self_aspace: u64) -> Result<Self, u64>
    {
        let range = reserve_pages(WINDOW_PAGES).map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        Ok(Self {
            range: Some(range),
            self_aspace,
            mapped: None,
        })
    }

    fn va(&self) -> u64
    {
        self.range.as_ref().map_or(0, ReservedRange::va_start)
    }

    /// The address in the window of data page `index` of `data`, mapping
    /// the pages of its grant from it, up to the window's size, when they are
    /// not mapped.
    fn page(&mut self, data: &Grants<'_>, index: u64) -> Result<*mut u8, u64>
    {
        if let Some((first, count)) = self.mapped
            && index >= first
            && index < first.saturating_add(count)
        {
            let offset = index.saturating_sub(first).saturating_mul(PAGE_SIZE);
            return Ok(self.va().saturating_add(offset) as *mut u8);
        }
        self.unmap()?;
        let (grant, offset) = data.locate(index).ok_or(procmgr_errors::OUT_OF_MEMORY)?;
        let count = grant.pages.saturating_sub(offset).min(WINDOW_PAGES);
        // Recorded before the map, which can fail with pages before the
        // failing one mapped: `unmap` then covers them, and a window that
        // will not unmap them stays reserved.
        self.mapped = Some((index, count));
        // SAFETY: the window's pages are unmapped (`unmap` above) pages of its
        // own reservation, and `count` is at most its size; no Rust object or
        // IPC page occupies them.
        let map = unsafe {
            std::os::seraph::mem_map_funded(
                grant.cap,
                self.self_aspace,
                self.va(),
                offset,
                count,
                syscall::MAP_WRITABLE,
            )
        };
        if map.is_err()
        {
            let _ = self.unmap();
            return Err(procmgr_errors::OUT_OF_MEMORY);
        }
        Ok(self.va() as *mut u8)
    }

    /// Unmap the window's pages, so a grant mapped through it passes memmgr's
    /// quiescence check.
    fn unmap(&mut self) -> Result<(), u64>
    {
        if let Some((_, count)) = self.mapped
        {
            // SAFETY: the span is the window's own reservation, whose pages
            // hold no Rust object.
            unsafe { syscall::mem_unmap(self.self_aspace, self.va(), count) }
                .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
            self.mapped = None;
        }
        Ok(())
    }
}

impl Drop for Window
{
    fn drop(&mut self)
    {
        // A window that will not unmap stays reserved, so no later
        // reservation lands on a mapped page.
        if self.unmap().is_ok()
            && let Some(range) = self.range.take()
        {
            unreserve_pages(range);
        }
    }
}

/// What the layout's header, thread records and checkpoint section say
/// besides the runs: the image the capture names, the load bias, the threads
/// read, and a checkpoint's section.
struct About<'a>
{
    image: Option<Image>,
    load_bias: u64,
    threads: &'a Threads,
    checkpoint: Option<Checkpoint>,
}

/// Write `layout`, with what `about` says, into the frames of `head`,
/// mapped together for the write.
fn write_layout(
    self_aspace: u64,
    head: &Grants<'_>,
    layout: &Layout,
    about: &About<'_>,
) -> Result<(), u64>
{
    let pages = head.pages;
    let range = reserve_pages(pages).map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    let va = range.va_start();
    let mut mapped = 0u64;
    let mut result = Ok(());
    for grant in &head.list
    {
        let at = va.saturating_add(mapped.saturating_mul(PAGE_SIZE));
        // SAFETY: the grant's pages land on unmapped pages of this
        // reservation, which `head.pages` sized to every grant.
        let map = unsafe {
            std::os::seraph::mem_map_funded(
                grant.cap,
                self_aspace,
                at,
                0,
                grant.pages,
                syscall::MAP_WRITABLE,
            )
        };
        if map.is_err()
        {
            result = Err(procmgr_errors::OUT_OF_MEMORY);
            break;
        }
        mapped = mapped.saturating_add(grant.pages);
    }
    if result.is_ok()
    {
        let len = usize::try_from(pages.saturating_mul(PAGE_SIZE)).unwrap_or(0);
        // SAFETY: the reservation's `pages` pages are mapped writable to frames
        // procmgr alone holds, and the slice ends before they are unmapped.
        let bytes = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len) };
        result = encode(bytes, layout, about);
    }
    // SAFETY: the span is this reservation, and the slice over it has ended.
    if unsafe { syscall::mem_unmap(self_aspace, va, pages) }.is_ok()
    {
        unreserve_pages(range);
    }
    else
    {
        result = Err(procmgr_errors::OUT_OF_MEMORY);
    }
    result
}

/// Encode `layout`, with what `about` says, at the start of `bytes`: the
/// header, the regions, the runs, the thread records, then a checkpoint's
/// section.
fn encode(bytes: &mut [u8], layout: &Layout, about: &About<'_>) -> Result<(), u64>
{
    let image = about.image;
    let mut flags = if layout.complete
    {
        SNAPSHOT_COMPLETE
    }
    else
    {
        0
    };
    if image.is_some()
    {
        flags |= SNAPSHOT_IMAGE;
    }
    if about.checkpoint.is_some()
    {
        flags |= SNAPSHOT_CHECKPOINT;
    }
    let regions = layout.regions.len() as u64;
    let header = Header {
        flags,
        layout_pages: layout.layout_pages,
        data_pages: layout.data_pages,
        region_count: regions,
        run_count: layout.runs.len() as u64,
        image: image.unwrap_or(Image {
            hash: [0; IMAGE_HASH_BYTES],
            len: 0,
        }),
        load_bias: about.load_bias,
        thread_count: about.threads.0.len() as u64,
        thread_bytes: about.threads.bytes().ok_or(procmgr_errors::OUT_OF_MEMORY)?,
    };
    header.encode(bytes).ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    for (i, region) in layout.regions.iter().enumerate()
    {
        region
            .encode(bytes, i)
            .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    }
    for (i, run) in layout.runs.iter().enumerate()
    {
        run.encode(bytes, regions, i)
            .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    }
    let mut at = threads_offset(regions.saturating_add(layout.runs.len() as u64))
        .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    for thread in &about.threads.0
    {
        at = thread
            .record()
            .encode(bytes, at)
            .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    }
    // The section follows the thread records (`procmgr_snapshot::checkpoint_offset`).
    if let Some(section) = about.checkpoint
    {
        section
            .encode(bytes, at)
            .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    }
    Ok(())
}

/// Seal `head` and `data`, in that order, into one memory object on the
/// account (`memmgr_labels::SEAL_OBJECT`), and return its handle and pages.
/// procmgr's caps are deleted first, so the frames pass memmgr's quiescence
/// check; a seal that fails returns the grants to the account.
fn seal(account: &Account, mut head: Grants<'_>, mut data: Grants<'_>) -> Result<(u64, u64), u64>
{
    let count = head.list.len().saturating_add(data.list.len());
    if count as u64 > memmgr_labels::SEAL_OBJECT_MAX_GRANTS
    {
        return Err(procmgr_errors::OUT_OF_MEMORY);
    }
    let mut msg = IpcMessage::builder(memmgr_labels::SEAL_OBJECT).word(0, count as u64);
    for (i, grant) in head.list.iter_mut().chain(&mut data.list).enumerate()
    {
        // Zeroed once deleted: a slot freed here may hold another worker's cap
        // by the time a failed seal's grants are released.
        let _ = syscall::cap_delete(grant.cap);
        grant.cap = 0;
        // `i` is below `count`, at most `SEAL_OBJECT_MAX_GRANTS`.
        msg = msg.word(i.saturating_add(1), grant.region);
    }
    let reply = account.call(&msg.build())?;
    if reply.label != memmgr_errors::SUCCESS
    {
        crate::release_caps(reply.caps());
        return Err(procmgr_errors::OUT_OF_MEMORY);
    }
    // The grants are the object's now, and their ids name nothing.
    head.list.clear();
    data.list.clear();
    match *reply.caps()
    {
        [handle] => Ok((handle, reply.word(0))),
        ref caps =>
        {
            crate::release_caps(caps);
            Err(procmgr_errors::OUT_OF_MEMORY)
        }
    }
}

/// Drop the object `handle` names (`OBJECT_RELEASE`) and delete the handle:
/// the reply that would have carried it did not reach the snapshotter.
pub fn release_object(handle: u64, ipc_buf: *mut u64)
{
    let _ = bounded_call(
        handle,
        &IpcMessage::builder(memmgr_labels::OBJECT_RELEASE).build(),
        ipc_buf,
    );
    let _ = syscall::cap_delete(handle);
}
