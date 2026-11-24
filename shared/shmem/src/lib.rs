// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/shmem/src/lib.rs

//! Shared-memory byte transport for Seraph userspace.
//!
//! [`SharedBuffer`] maps Memory caps received from a peer; [`SpscHeader`],
//! [`SpscWriter`], and [`SpscReader`] form a single-producer,
//! single-consumer byte ring over any mapped shared region. The two layers,
//! the ring's header layout, and its ordering are described in
//! `shared/shmem/README.md`.
//!
//! Index ordering is Acquire/Release, which suffices on both x86-64 (TSO)
//! and RISC-V (RVWMO) for data published before the index store to be
//! observed after the index load. Blocking and wake-up use a notification
//! cap out of band (pipes); this crate holds the doorbell protocol that says
//! when an end must ring it (the header's waiter words and a `SeqCst` fence
//! pair), not the notification itself.

// Under `rustc-dep-of-std` (build-std), use the core facade and no_core
// so this crate can sit inside std's dep graph. Mirrors abi/syscall,
// shared/syscall, shared/ipc, shared/log. Normal userspace builds (no
// feature) retain `#![no_std]`.
#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(
    feature = "rustc-dep-of-std",
    expect(
        internal_features,
        reason = "`no_core` is an internal feature, needed to build as a dependency of std"
    )
)]
#![cfg_attr(not(any(feature = "rustc-dep-of-std", test)), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

// Cargo records no source file of a `-Z build-std` unit, only the environment variables it
// reads: reading xtask's digest of the sources of every crate std depends on makes a change to
// any of them rebuild this unit (docs/build-system.md § Build Output: the Sysroot).
#[cfg(feature = "rustc-dep-of-std")]
const _: &str = core::env!("SERAPH_STD_DEPS_DIGEST");

#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use core::sync::atomic::{AtomicU32, Ordering, fence};

/// Page size on both supported architectures.
const PAGE_SIZE: u64 = 4096;

/// One Memory cap a peer shares and the number of pages it covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedRegion
{
    /// Memory cap slot; the buffer maps it through a derived read-write cap,
    /// so the slot stays with the caller.
    pub cap: u64,
    /// Pages the cap covers, all of which are mapped.
    pub pages: u64,
}

/// Errors that can surface from [`SharedBuffer`] operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShmemError
{
    /// No region was supplied, a region covers zero pages, or the total
    /// span overflows the address space.
    InvalidPageCount,
    /// Deriving a mapping cap or `sys_mem_map` failed partway through —
    /// pages already mapped are unmapped before the error surfaces.
    MapFailed,
}

/// A contiguous, page-aligned region of shared memory mapped into the
/// caller's address space. Memory caps are either still held by this
/// process (for share with a peer) or already moved.
pub struct SharedBuffer
{
    vaddr: u64,
    page_count: u64,
    aspace: u64,
}

/// Total pages `regions` cover, or `None` when there is no region, a region
/// is empty, or the span from `vaddr` would overflow.
fn total_pages(regions: &[SharedRegion], vaddr: u64) -> Option<u64>
{
    if regions.is_empty()
    {
        return None;
    }
    let mut total: u64 = 0;
    for region in regions
    {
        if region.pages == 0
        {
            return None;
        }
        total = total.checked_add(region.pages)?;
    }
    vaddr.checked_add(total.checked_mul(PAGE_SIZE)?)?;
    Some(total)
}

impl SharedBuffer
{
    /// Attach to a shared buffer using memory caps received from the peer.
    /// Maps `regions` back to back read-write at `vaddr` in `aspace`, each
    /// cap with one map of all its pages, so a buffer is as large as the
    /// caps it is given and a peer may share it as one multi-page cap or as
    /// several; dropping the buffer unmaps the span.
    ///
    /// # Safety
    /// When `aspace` names the calling program's own address space, no page of
    /// the span (`vaddr` up by the regions' total pages) may hold a live Rust
    /// object or registered IPC buffer page, from this call until the buffer
    /// is dropped: the map replaces what the span held and the drop unmaps it
    /// (the contracts of `syscall::mem_map` and `syscall::mem_unmap`).
    ///
    /// # Errors
    /// [`ShmemError::InvalidPageCount`] if `regions` is empty, a region
    /// covers zero pages, or the span overflows;
    /// [`ShmemError::MapFailed`] if deriving a mapping cap or any map call
    /// fails (a cap covering fewer pages than its region claims among them).
    pub unsafe fn attach(
        regions: &[SharedRegion],
        aspace: u64,
        vaddr: u64,
    ) -> Result<Self, ShmemError>
    {
        let total = total_pages(regions, vaddr).ok_or(ShmemError::InvalidPageCount)?;
        // `total_pages` checked that `vaddr` plus the whole span fits a `u64`,
        // and `mapped` plus one region's pages stays within the span, so none
        // of the saturating operations below saturates.
        let mut mapped: u64 = 0;
        for region in regions
        {
            let Ok(rw) = syscall::cap_derive(region.cap, syscall::RIGHTS_MEM_MAP_RW)
            else
            {
                // SAFETY: the first `mapped` pages were mapped by this call,
                // inside the span the caller's contract dedicates.
                unsafe { unmap_range(aspace, vaddr, mapped) };
                return Err(ShmemError::MapFailed);
            };
            // SAFETY: the region's pages lie in the span the caller's
            // contract keeps off live Rust objects and registered IPC pages.
            let ok = unsafe {
                syscall::mem_map(
                    rw,
                    aspace,
                    vaddr.saturating_add(mapped.saturating_mul(PAGE_SIZE)),
                    0,
                    region.pages,
                    syscall::MAP_WRITABLE,
                )
            }
            .is_ok();
            let _ = syscall::cap_delete(rw);
            if !ok
            {
                // SAFETY: the first `mapped` pages were mapped by this call,
                // and a failed map of this region leaves its pages for the
                // same unmap, inside the dedicated span.
                unsafe { unmap_range(aspace, vaddr, mapped.saturating_add(region.pages)) };
                return Err(ShmemError::MapFailed);
            }
            mapped = mapped.saturating_add(region.pages);
        }

        Ok(SharedBuffer {
            vaddr,
            page_count: total,
            aspace,
        })
    }

    /// Virtual address the buffer is mapped at in this process.
    #[must_use]
    pub fn vaddr(&self) -> u64
    {
        self.vaddr
    }

    /// Total size in bytes.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "userspace targets are 64-bit only, so usize holds every u64 byte count, and \
                  `attach` checked the span fits the address space"
    )]
    pub fn size(&self) -> usize
    {
        // `attach` checked that the span's byte count fits a `u64`.
        self.page_count.saturating_mul(PAGE_SIZE) as usize
    }

    /// Number of pages.
    #[must_use]
    pub fn pages(&self) -> u64
    {
        self.page_count
    }

    /// View the region as a mutable byte slice.
    ///
    /// # Safety
    /// The buffer must have been attached in the calling program's own
    /// address space (otherwise `vaddr` names no memory of this program).
    /// Only one thread in this process may hold a mutable slice at a time;
    /// the underlying memory is shared with another process via raw Memory
    /// caps and does not enforce aliasing.
    pub unsafe fn as_bytes_mut(&mut self) -> &mut [u8]
    {
        // SAFETY: the caller's contract puts the region in this program's
        // address space, where `attach` mapped it writable and contiguous for
        // `size` bytes; the caller upholds the aliasing discipline.
        unsafe { core::slice::from_raw_parts_mut(self.vaddr as *mut u8, self.size()) }
    }
}

impl Drop for SharedBuffer
{
    fn drop(&mut self)
    {
        // SAFETY: `attach`'s contract dedicates the span to this buffer until
        // it is dropped, so no live Rust object or IPC page lies in it.
        let _ = unsafe { syscall::mem_unmap(self.aspace, self.vaddr, self.page_count) };
    }
}

/// Best-effort unmap of `count` pages starting at `vaddr`, one call for the
/// whole span (unmapping a page that holds no mapping is harmless). Used
/// during failure cleanup; errors are swallowed.
///
/// # Safety
/// The contract of `syscall::mem_unmap` for the `count` pages at `vaddr`.
unsafe fn unmap_range(aspace: u64, vaddr: u64, count: u64)
{
    if count != 0
    {
        // SAFETY: the span is the one the caller's contract covers.
        let _ = unsafe { syscall::mem_unmap(aspace, vaddr, count) };
    }
}

// ── SPSC byte ring ───────────────────────────────────────────────────────────

/// Fixed in-memory header at the start of an SPSC shared region.
///
/// Two atomic indices plus an atomic `capacity` (byte buffer length, must be a
/// power of two), a `closed` flag used by pipe peers to signal EOF, and one
/// waiter word per direction for the doorbell protocol (`shared/shmem/README.md`
/// § Doorbell protocol). The byte buffer follows immediately after this
/// struct, at offset [`SpscHeader::SIZE`].
#[repr(C)]
pub struct SpscHeader
{
    /// Reader's index into the buffer (bytes consumed, mod capacity).
    /// Written by the reader, read by the writer.
    pub head: AtomicU32,
    /// Writer's index into the buffer (bytes produced, mod capacity).
    /// Written by the writer, read by the reader.
    ///
    /// Both indices run free and wrap at `u32`: the ends mask them to a slot
    /// and take the fill level as `tail.wrapping_sub(head)`, which stays
    /// correct across the wrap for any capacity up to 2^31, so the width
    /// bounds no transfer volume.
    pub tail: AtomicU32,
    /// Capacity of the byte buffer. Power of two. `u32` is the width the
    /// `repr(C)` header both peers map fixes.
    ///
    /// Atomic because it lies in memory the peer can write: each end reads it
    /// only to compare against the capacity it mapped (see
    /// [`SpscWriter::from_raw`]), never to size an access.
    pub capacity: AtomicU32,
    /// Closer flag: set to 1 (Release) by whichever peer drops first
    /// (writer drop → reader sees EOF; reader drop → writer sees
    /// `BrokenPipe`). Read by the surviving peer (Acquire) after a
    /// zero-progress read/write to disambiguate "ring empty/full" from
    /// "peer gone". Reset to 0 by `init`.
    pub closed: AtomicU32,
    /// The reader's waiter word: set to 1 by a reader that found the ring
    /// empty and is about to wait for bytes ([`SpscReader::prepare_wait`]);
    /// cleared by the writer that claims it to ring the reader's doorbell
    /// ([`SpscWriter::take_waiting_reader`]), or by the reader itself when
    /// bytes arrived before it blocked or its wait has returned. Reset to 0 by
    /// `init`.
    pub reader_waiting: AtomicU32,
    /// The writer's waiter word: the same for a writer that found the ring
    /// full and is about to wait for space ([`SpscWriter::prepare_wait`]),
    /// claimed by the reader ([`SpscReader::take_waiting_writer`]).
    pub writer_waiting: AtomicU32,
}

impl SpscHeader
{
    /// Size of the header in bytes. Usable bytes for the ring start at
    /// `vaddr + SpscHeader::SIZE` and run for `capacity` bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Initialise a fresh header at `ptr` with `capacity` bytes of ring
    /// storage. `capacity` must be a non-zero power of two.
    ///
    /// # Panics
    /// Panics if `capacity` is not a non-zero power of two.
    ///
    /// # Safety
    /// `ptr` must be valid, writable, and aligned for `SpscHeader` (4 bytes).
    /// The caller is the unique initialiser of the header; no other thread
    /// on either side of the shared region may be reading the header yet.
    pub unsafe fn init(ptr: *mut Self, capacity: u32)
    {
        assert!(capacity.is_power_of_two(), "SPSC capacity must be pow2");
        // SAFETY: the caller promises `ptr` is valid, writable and aligned,
        // and the header's fields are atomics, so a shared reference admits
        // the stores below.
        let header = unsafe { &*ptr };
        header.head.store(0, Ordering::Relaxed);
        header.tail.store(0, Ordering::Relaxed);
        header.capacity.store(capacity, Ordering::Relaxed);
        header.closed.store(0, Ordering::Relaxed);
        header.reader_waiting.store(0, Ordering::Relaxed);
        header.writer_waiting.store(0, Ordering::Relaxed);
    }

    /// Mark the ring closed. Called by whichever peer drops first.
    /// Idempotent; later loads with [`Self::is_closed`] observe the flag
    /// via Acquire ordering.
    pub fn mark_closed(&self)
    {
        self.closed.store(1, Ordering::Release);
    }

    /// Returns `true` if the ring has been marked closed by either peer.
    /// Reader EOF and writer `BrokenPipe` are derived from this plus a
    /// zero-progress read/write.
    #[must_use]
    pub fn is_closed(&self) -> bool
    {
        self.closed.load(Ordering::Acquire) != 0
    }
}

/// SPSC byte ring writer. One writer per ring; producing concurrent writes
/// from multiple threads is undefined.
pub struct SpscWriter<'a>
{
    header: &'a SpscHeader,
    buf: *mut u8,
    mask: u32,
}

/// SPSC byte ring reader. One reader per ring.
pub struct SpscReader<'a>
{
    header: &'a SpscHeader,
    buf: *const u8,
    mask: u32,
}

// SAFETY: the header is shared between processes via a Memory-cap mapping;
// the raw pointers point into that shared region. Send across threads in
// one process is fine because all reads/writes through the raw pointers
// go through the atomic indices in the header.
unsafe impl Send for SpscWriter<'_> {}
// SAFETY: same rationale as `SpscWriter`.
unsafe impl Send for SpscReader<'_> {}

/// Construct a `(SpscWriter, SpscReader)` pair over a pre-initialised
/// shared region.
///
/// `region_vaddr` must point at an already-mapped shared buffer laid out
/// as `SpscHeader` followed by `capacity` bytes. Returns `None` when
/// `capacity` is not a non-zero power of two or the header's `capacity`
/// field differs from it (see [`SpscWriter::from_raw`]).
///
/// Splitting into writer + reader halves from the same call site is
/// convenient for in-process testing. In production the two ends live in
/// different address spaces — each process builds its own half directly
/// with [`SpscWriter::from_raw`] / [`SpscReader::from_raw`].
///
/// # Safety
/// The contract of [`SpscWriter::from_raw`] and [`SpscReader::from_raw`]:
/// the region (header plus `capacity` body bytes) must be mapped readable
/// and writable and 4-byte aligned, its header initialised by
/// [`SpscHeader::init`], and the region must stay mapped and valid for `'a`.
/// Only one `SpscWriter` and one `SpscReader` may exist at a time for it.
#[must_use]
pub unsafe fn spsc_pair<'a>(
    region_vaddr: u64,
    capacity: u32,
) -> Option<(SpscWriter<'a>, SpscReader<'a>)>
{
    // SAFETY: this function's contract is `SpscWriter::from_raw`'s, and it
    // creates the region's only writer.
    let writer = unsafe { SpscWriter::from_raw(region_vaddr, capacity) }?;
    // SAFETY: this function's contract is `SpscReader::from_raw`'s, and it
    // creates the region's only reader.
    let reader = unsafe { SpscReader::from_raw(region_vaddr, capacity) }?;
    Some((writer, reader))
}

/// Check `capacity` against the ring header at `region_vaddr` and return
/// the index mask for it.
///
/// The capacity comes from the caller, who knows the size it mapped. The
/// header's `capacity` field lies in memory the peer can write, so it is read
/// once, atomically, and only compared: it never sizes an access.
///
/// # Safety
/// `region_vaddr` must point at a mapped, readable, 4-byte aligned
/// [`SpscHeader`].
unsafe fn checked_mask(region_vaddr: u64, capacity: u32) -> Option<u32>
{
    if !capacity.is_power_of_two()
    {
        return None;
    }
    let header = region_vaddr as *const SpscHeader;
    // SAFETY: the caller's contract makes the header readable and aligned;
    // the field is atomic, so a concurrent peer write is no data race.
    let shared = unsafe { (*header).capacity.load(Ordering::Acquire) };
    // A power of two is at least 1, so the subtraction does not saturate; the
    // mask is at most `2^31 - 1`, so `mask + 1` below does not saturate either.
    (shared == capacity).then_some(capacity.saturating_sub(1))
}

impl SpscWriter<'_>
{
    /// Wrap a pre-initialised shared region as a writer.
    ///
    /// `capacity` is the ring body size the caller mapped after the header.
    /// Returns `None` when `capacity` is not a non-zero power of two, or when
    /// the header's `capacity` field differs from it, so a peer that rewrites
    /// the field cannot steer the writer past the mapped body.
    ///
    /// # Safety
    /// The region at `region_vaddr` (an initialised [`SpscHeader`] plus
    /// `capacity` body bytes) must be mapped readable and writable and 4-byte
    /// aligned, and must stay mapped and valid for `'a`. Only one writer may
    /// exist at a time.
    #[must_use]
    pub unsafe fn from_raw(region_vaddr: u64, capacity: u32) -> Option<Self>
    {
        // SAFETY: caller contract: the header is mapped, readable and aligned.
        let mask = unsafe { checked_mask(region_vaddr, capacity) }?;
        // SAFETY: caller contract: the header stays mapped and valid for `'a`.
        let header = unsafe { &*(region_vaddr as *const SpscHeader) };
        Some(Self {
            header,
            // The caller's contract maps the body after the header, so the
            // address does not wrap.
            buf: region_vaddr.wrapping_add(SpscHeader::SIZE as u64) as *mut u8,
            mask,
        })
    }

    /// Write up to `data.len()` bytes into the ring, returning the number
    /// actually written (zero if the ring is full). Non-blocking.
    pub fn write(&mut self, data: &[u8]) -> usize
    {
        let capacity = self.mask.saturating_add(1);
        let head = self.header.head.load(Ordering::Acquire);
        let tail = self.header.tail.load(Ordering::Relaxed);
        // The peer writes `head`; saturate so a value past the ring's bounds
        // reads as a full ring rather than underflowing.
        let used = tail.wrapping_sub(head);
        let free = capacity.saturating_sub(used);
        if free == 0
        {
            return 0;
        }
        let n = free.min(u32::try_from(data.len()).unwrap_or(u32::MAX));
        for (offset, &byte) in (0..n).zip(data)
        {
            let slot = tail.wrapping_add(offset) & self.mask;
            // SAFETY: `slot <= mask < capacity`, and buf..buf+capacity is the
            // ring body, so the offset stays inside it.
            let dst = unsafe { self.buf.add(slot as usize) };
            // SAFETY: `from_raw`'s contract keeps the ring body mapped and
            // writable for `'a`, and `dst` lies inside it.
            unsafe {
                *dst = byte;
            }
        }
        self.header
            .tail
            .store(tail.wrapping_add(n), Ordering::Release);
        n as usize
    }

    /// Make ready to wait for space after a [`write`](Self::write) found the
    /// ring full: set this writer's waiter word, fence, and look again.
    ///
    /// Returns `true` when the ring is still full: the caller blocks on the
    /// notification the reader rings for space, and calls
    /// [`end_wait`](Self::end_wait) once that wait returns, whatever it
    /// returned. Returns `false` when the reader freed space meanwhile; the
    /// word is cleared again and the caller writes instead of waiting.
    #[must_use]
    pub fn prepare_wait(&self) -> bool
    {
        announce_wait(self)
    }

    /// Clear this writer's waiter word after its wait returned, so a reader
    /// that frees space later rings no doorbell for a wait already over.
    pub fn end_wait(&self)
    {
        self.withdraw();
    }

    /// After a [`write`](Self::write) that stored bytes: fence, then claim the
    /// reader's waiter word.
    ///
    /// Returns `true` when the reader had announced a wait, which this call
    /// cleared: the caller rings the reader's doorbell (the notification it
    /// waits on for bytes). `false` means no reader waits, and nothing need
    /// be rung.
    #[must_use]
    pub fn take_waiting_reader(&self) -> bool
    {
        take_waiting_peer(self)
    }

    /// How many bytes are currently in the ring (from this writer's view).
    #[must_use]
    pub fn used(&self) -> usize
    {
        let head = self.header.head.load(Ordering::Relaxed);
        let tail = self.header.tail.load(Ordering::Relaxed);
        tail.wrapping_sub(head) as usize
    }

    /// Capacity of the ring in bytes.
    #[must_use]
    pub fn capacity(&self) -> usize
    {
        self.mask.saturating_add(1) as usize
    }
}

impl SpscReader<'_>
{
    /// Wrap a pre-initialised shared region as a reader.
    ///
    /// `capacity` and the `None` cases are as for [`SpscWriter::from_raw`].
    ///
    /// # Safety
    /// The region at `region_vaddr` (an initialised [`SpscHeader`] plus
    /// `capacity` body bytes) must be mapped readable and writable and 4-byte
    /// aligned, and must stay mapped and valid for `'a`. Only one reader may
    /// exist at a time.
    #[must_use]
    pub unsafe fn from_raw(region_vaddr: u64, capacity: u32) -> Option<Self>
    {
        // SAFETY: caller contract: the header is mapped, readable and aligned.
        let mask = unsafe { checked_mask(region_vaddr, capacity) }?;
        // SAFETY: caller contract: the header stays mapped and valid for `'a`.
        let header = unsafe { &*(region_vaddr as *const SpscHeader) };
        Some(Self {
            header,
            // The caller's contract maps the body after the header, so the
            // address does not wrap.
            buf: region_vaddr.wrapping_add(SpscHeader::SIZE as u64) as *const u8,
            mask,
        })
    }

    /// Read up to `dst.len()` bytes from the ring, returning the number
    /// actually read (zero if the ring is empty). Non-blocking.
    pub fn read(&mut self, dst: &mut [u8]) -> usize
    {
        let head = self.header.head.load(Ordering::Relaxed);
        let tail = self.header.tail.load(Ordering::Acquire);
        // The peer writes `tail`; clamp so a value past the ring's bounds
        // reads as a full ring rather than reading slots more than once.
        let used = tail.wrapping_sub(head).min(self.mask.saturating_add(1));
        if used == 0
        {
            return 0;
        }
        let n = used.min(u32::try_from(dst.len()).unwrap_or(u32::MAX));
        for (offset, out) in (0..n).zip(dst.iter_mut())
        {
            let slot = head.wrapping_add(offset) & self.mask;
            // SAFETY: `slot <= mask < capacity`, and buf..buf+capacity is the
            // ring body, so the offset stays inside it.
            let src = unsafe { self.buf.add(slot as usize) };
            // SAFETY: `from_raw`'s contract keeps the ring body mapped and
            // readable for `'a`, and `src` lies inside it.
            unsafe {
                *out = *src;
            }
        }
        self.header
            .head
            .store(head.wrapping_add(n), Ordering::Release);
        n as usize
    }

    /// Make ready to wait for bytes after a [`read`](Self::read) found the
    /// ring empty: set this reader's waiter word, fence, and look again.
    ///
    /// Returns `true` when the ring is still empty: the caller blocks on the
    /// notification the writer rings for bytes, and calls
    /// [`end_wait`](Self::end_wait) once that wait returns, whatever it
    /// returned. Returns `false` when bytes arrived meanwhile; the word is
    /// cleared again and the caller reads instead of waiting.
    #[must_use]
    pub fn prepare_wait(&self) -> bool
    {
        announce_wait(self)
    }

    /// Clear this reader's waiter word after its wait returned, so a writer
    /// that stores bytes later rings no doorbell for a wait already over.
    pub fn end_wait(&self)
    {
        self.withdraw();
    }

    /// After a [`read`](Self::read) that consumed bytes: fence, then claim the
    /// writer's waiter word.
    ///
    /// Returns `true` when the writer had announced a wait, which this call
    /// cleared: the caller rings the writer's doorbell (the notification it
    /// waits on for space). `false` means no writer waits, and nothing need
    /// be rung.
    #[must_use]
    pub fn take_waiting_writer(&self) -> bool
    {
        take_waiting_peer(self)
    }

    /// Whether the ring currently has any bytes to consume.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        let head = self.header.head.load(Ordering::Relaxed);
        let tail = self.header.tail.load(Ordering::Acquire);
        head == tail
    }
}

// ── Doorbell protocol ────────────────────────────────────────────────────────
//
// shared/shmem/README.md § Doorbell protocol states the protocol and why the
// fence pair makes a lost wake impossible. The two steps below are generic over
// `DoorbellEnd` so the host test runs these same functions over a model memory
// that reorders a store past a later load, as a store buffer does.

/// One ring end's shared-word operations, as the doorbell protocol uses them.
trait DoorbellEnd
{
    /// Set this end's waiter word.
    fn announce(&self);
    /// Clear this end's waiter word.
    fn withdraw(&self);
    /// Order this thread's earlier stores before its later loads: a `SeqCst`
    /// fence, the one store-load barrier the protocol needs.
    fn fence(&self);
    /// Whether the peer has made progress this end can use since it last
    /// looked: bytes to read for a reader, space to write for a writer.
    fn peer_progressed(&self) -> bool;
    /// Whether the peer's waiter word is set.
    fn peer_waiting(&self) -> bool;
    /// Clear the peer's waiter word, returning whether it was set.
    fn take_peer_word(&self) -> bool;
}

/// The waiting side's step: announce the wait, fence, and look again.
/// Returns `true` when the caller must block, `false` (with the announcement
/// withdrawn) when the peer's progress arrived first.
fn announce_wait<E: DoorbellEnd>(end: &E) -> bool
{
    end.announce();
    end.fence();
    if end.peer_progressed()
    {
        end.withdraw();
        return false;
    }
    true
}

/// The progressing side's step, after it published its index: fence, then
/// claim the peer's waiter word. Returns `true` when the caller must ring the
/// peer's doorbell. The plain load first keeps the common case, no waiter, a
/// read of the line rather than a write to it.
fn take_waiting_peer<E: DoorbellEnd>(end: &E) -> bool
{
    end.fence();
    end.peer_waiting() && end.take_peer_word()
}

impl DoorbellEnd for SpscWriter<'_>
{
    fn announce(&self)
    {
        self.header.writer_waiting.store(1, Ordering::Relaxed);
    }

    fn withdraw(&self)
    {
        self.header.writer_waiting.store(0, Ordering::Relaxed);
    }

    fn fence(&self)
    {
        fence(Ordering::SeqCst);
    }

    fn peer_progressed(&self) -> bool
    {
        // Acquire: a write that follows reuses the slots the reader released.
        let head = self.header.head.load(Ordering::Acquire);
        let tail = self.header.tail.load(Ordering::Relaxed);
        tail.wrapping_sub(head) < self.mask.saturating_add(1)
    }

    fn peer_waiting(&self) -> bool
    {
        self.header.reader_waiting.load(Ordering::Relaxed) != 0
    }

    fn take_peer_word(&self) -> bool
    {
        self.header.reader_waiting.swap(0, Ordering::Relaxed) != 0
    }
}

impl DoorbellEnd for SpscReader<'_>
{
    fn announce(&self)
    {
        self.header.reader_waiting.store(1, Ordering::Relaxed);
    }

    fn withdraw(&self)
    {
        self.header.reader_waiting.store(0, Ordering::Relaxed);
    }

    fn fence(&self)
    {
        fence(Ordering::SeqCst);
    }

    fn peer_progressed(&self) -> bool
    {
        !self.is_empty()
    }

    fn peer_waiting(&self) -> bool
    {
        self.header.writer_waiting.load(Ordering::Relaxed) != 0
    }

    fn take_peer_word(&self) -> bool
    {
        self.header.writer_waiting.swap(0, Ordering::Relaxed) != 0
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const CAP: u32 = 64;

    // Defect guarded: a buffer size capped by one page per cap (the old
    // `MAX_PAGES` of four single-page caps), or a span check that lets an
    // empty region or an overflowing total through to the map loop.
    #[test]
    fn shared_span_sums_multi_page_regions_and_refuses_bad_ones()
    {
        let region = |pages| SharedRegion { cap: 1, pages };
        assert_eq!(total_pages(&[region(1024), region(3)], 0x1000), Some(1027));
        assert_eq!(total_pages(&[], 0x1000), None);
        assert_eq!(total_pages(&[region(2), region(0)], 0x1000), None);
        assert_eq!(total_pages(&[region(u64::MAX), region(1)], 0x1000), None);
        assert_eq!(total_pages(&[region(u64::MAX / PAGE_SIZE)], 0x1000), None);
    }

    /// A ring region in ordinary memory: header plus a `CAP`-byte body.
    #[repr(C, align(8))]
    struct Region
    {
        header: SpscHeader,
        body: [u8; CAP as usize],
    }

    fn region(header_capacity: u32) -> Region
    {
        let r = Region {
            header: SpscHeader {
                head: AtomicU32::new(0),
                tail: AtomicU32::new(0),
                capacity: AtomicU32::new(0),
                closed: AtomicU32::new(0),
                reader_waiting: AtomicU32::new(0),
                writer_waiting: AtomicU32::new(0),
            },
            body: [0; CAP as usize],
        };
        r.header.capacity.store(header_capacity, Ordering::Relaxed);
        r
    }

    #[test]
    fn ring_halves_refuse_a_header_capacity_the_peer_rewrote()
    {
        // The peer grew the shared field past the mapped body; trusting it
        // would let the writer index beyond `body`.
        let mut r = region(CAP * 4);
        let va = &raw mut r as u64;
        // SAFETY: `r` is a live, aligned header plus `CAP` body bytes.
        assert!(unsafe { SpscWriter::from_raw(va, CAP) }.is_none());
        // SAFETY: as above; the writer was refused, so no half of the region
        // exists.
        assert!(unsafe { SpscReader::from_raw(va, CAP) }.is_none());
    }

    #[test]
    fn ring_halves_refuse_a_capacity_that_is_not_a_power_of_two()
    {
        // A zero capacity would underflow the index mask; a non-power-of-two
        // one would mask indices outside the body.
        for bad in [0, 48]
        {
            let mut r = region(bad);
            let va = &raw mut r as u64;
            // SAFETY: `r` is a live, aligned header plus `CAP` body bytes;
            // `bad <= CAP`.
            assert!(unsafe { spsc_pair(va, bad) }.is_none());
        }
    }

    #[test]
    fn ring_built_with_the_mapped_capacity_round_trips_bytes()
    {
        let mut r = region(CAP);
        let va = &raw mut r as u64;
        // SAFETY: `r` is a live, aligned header plus `CAP` body bytes and
        // outlives both halves.
        let (mut w, mut rd) = unsafe { spsc_pair(va, CAP) }.expect("matching capacity");
        assert_eq!(w.write(&[0xAB; CAP as usize + 8]), CAP as usize);
        let mut out = [0u8; CAP as usize];
        assert_eq!(rd.read(&mut out), CAP as usize);
        assert!(out.iter().all(|&b| b == 0xAB));
        assert!(rd.is_empty());
    }

    // ── Doorbell protocol model ──────────────────────────────────────────────
    //
    // The explorer below runs the protocol's own steps, `announce_wait` and
    // `take_waiting_peer`, on a writer and a reader thread over a model memory
    // with a store buffer per thread (x86-64's TSO, and the store-load reordering
    // RISC-V's RVWMO also allows: a store stays invisible to the other thread
    // until its buffer drains, while the thread's later loads go ahead). A fence
    // drains the issuing thread's buffer, a swap is a locked instruction that does
    // too, and a notification is the kernel's sticky bit: a send sets it, a wait
    // takes it, or blocks until a send sets it. Every step waits for a grant from
    // the explorer, which chooses among the enabled steps and buffer drains, and
    // runs every schedule depth first, so the exploration is deterministic.

    use std::cell::Cell;
    use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

    const WRITER: usize = 0;
    const READER: usize = 1;

    /// A shared word of the model.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Var
    {
        /// The writer's index: bytes published.
        Tail,
        /// The reader's waiter word.
        ReaderWaiting,
    }

    /// One step a model thread asks to take.
    #[derive(Clone, Copy, Debug)]
    enum Op
    {
        Store(Var, u32),
        Load(Var),
        Swap(Var, u32),
        Fence,
        Send,
        Wait,
    }

    /// A move of the explorer: grant a thread its step, or drain the oldest
    /// store of a thread's buffer to memory.
    #[derive(Clone, Copy)]
    enum Move
    {
        Step(usize),
        Drain(usize),
    }

    /// Whether the model's fence and swap drain the store buffer, as the
    /// hardware's do, or (the control) leave it.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Fences
    {
        Order,
        Ignore,
    }

    #[derive(Default)]
    struct World
    {
        tail: u32,
        reader_waiting: u32,
        buffers: [Vec<(Var, u32)>; 2],
        /// The data notification's pending bit.
        pending: bool,
        /// The step each thread waits to take, if it waits for one.
        parked: [Option<Op>; 2],
        done: [bool; 2],
        grant: Option<usize>,
        /// Set when the explorer ends a run with a thread still parked; its
        /// steps then return at once and the thread runs to its end.
        aborted: bool,
        announces: u32,
        sends: u32,
    }

    impl World
    {
        fn memory(&mut self, var: Var) -> &mut u32
        {
            match var
            {
                Var::Tail => &mut self.tail,
                Var::ReaderWaiting => &mut self.reader_waiting,
            }
        }

        fn load(&mut self, me: usize, var: Var) -> u32
        {
            let buffered = self.buffers[me].iter().rev().find(|(v, _)| *v == var);
            match buffered
            {
                Some(&(_, value)) => value,
                None => *self.memory(var),
            }
        }

        fn drain_one(&mut self, me: usize)
        {
            let (var, value) = self.buffers[me].remove(0);
            *self.memory(var) = value;
        }

        fn enabled(&self, me: usize, op: Op, fences: Fences) -> bool
        {
            let drained = self.buffers[me].is_empty() || fences == Fences::Ignore;
            match op
            {
                Op::Fence | Op::Swap(..) | Op::Send => drained,
                Op::Wait => drained && self.pending,
                Op::Store(..) | Op::Load(_) => true,
            }
        }

        fn apply(&mut self, me: usize, op: Op) -> u32
        {
            match op
            {
                Op::Store(var, value) => self.buffers[me].push((var, value)),
                Op::Load(var) => return self.load(me, var),
                Op::Swap(var, value) =>
                {
                    let old = self.load(me, var);
                    *self.memory(var) = value;
                    return old;
                }
                Op::Fence =>
                {}
                Op::Send =>
                {
                    self.sends += 1;
                    self.pending = true;
                }
                Op::Wait => self.pending = false,
            }
            0
        }

        /// The explorer's moves. A step no other thread can observe, a store
        /// into the buffer or a fence free to pass, is taken at once, since it
        /// commutes with every move of the other thread. A drain is offered
        /// only where it can be seen: when the other thread waits to read a
        /// word the buffer holds a store to, or when the buffer's own thread
        /// waits for it to drain. A drain put off to such a point changes
        /// nothing any thread reads. So every schedule left out is equivalent
        /// to one kept.
        fn moves(&self, fences: Fences) -> Vec<Move>
        {
            for me in [WRITER, READER]
            {
                if let Some(op @ (Op::Store(..) | Op::Fence)) = self.parked[me]
                    && self.enabled(me, op, fences)
                {
                    return vec![Move::Step(me)];
                }
            }
            let mut moves = Vec::new();
            for me in [WRITER, READER]
            {
                let parked = self.parked[me];
                if let Some(op) = parked
                    && self.enabled(me, op, fences)
                {
                    moves.push(Move::Step(me));
                }
                let other = 1 - me;
                let observed = match self.parked[other]
                {
                    Some(Op::Load(var) | Op::Swap(var, _)) =>
                    {
                        self.buffers[me].iter().any(|&(v, _)| v == var)
                    }
                    _ => false,
                };
                let needed = matches!(parked, Some(Op::Fence | Op::Swap(..) | Op::Send | Op::Wait));
                if !self.buffers[me].is_empty() && (observed || needed)
                {
                    moves.push(Move::Drain(me));
                }
            }
            moves
        }

        fn settled(&self) -> bool
        {
            self.grant.is_none() && (0..2).all(|t| self.done[t] || self.parked[t].is_some())
        }
    }

    struct Model
    {
        world: Mutex<World>,
        changed: Condvar,
    }

    impl Model
    {
        fn lock(&self) -> MutexGuard<'_, World>
        {
            self.world.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn wait<'a>(&self, guard: MutexGuard<'a, World>) -> MutexGuard<'a, World>
        {
            self.changed
                .wait(guard)
                .unwrap_or_else(PoisonError::into_inner)
        }

        /// Take one step as thread `me`, once the explorer grants it.
        fn step(&self, me: usize, op: Op) -> u32
        {
            let mut world = self.lock();
            world.parked[me] = Some(op);
            self.changed.notify_all();
            while world.grant != Some(me) && !world.aborted
            {
                world = self.wait(world);
            }
            world.parked[me] = None;
            if world.aborted
            {
                return 0;
            }
            world.grant = None;
            let value = world.apply(me, op);
            drop(world);
            self.changed.notify_all();
            value
        }

        fn finish(&self, me: usize)
        {
            self.lock().done[me] = true;
            self.changed.notify_all();
        }

        fn aborted(&self) -> bool
        {
            self.lock().aborted
        }
    }

    /// The writer's end over the model: only the progressing side's operations
    /// are reached, since a writer that never fills the ring never waits.
    struct ModelWriter<'a>(&'a Model);

    impl DoorbellEnd for ModelWriter<'_>
    {
        fn announce(&self)
        {
            unreachable!("the model's writer never waits");
        }

        fn withdraw(&self)
        {
            unreachable!("the model's writer never waits");
        }

        fn fence(&self)
        {
            self.0.step(WRITER, Op::Fence);
        }

        fn peer_progressed(&self) -> bool
        {
            unreachable!("the model's writer never waits");
        }

        fn peer_waiting(&self) -> bool
        {
            self.0.step(WRITER, Op::Load(Var::ReaderWaiting)) != 0
        }

        fn take_peer_word(&self) -> bool
        {
            self.0.step(WRITER, Op::Swap(Var::ReaderWaiting, 0)) != 0
        }
    }

    /// The reader's end over the model; `consumed` is its private head.
    struct ModelReader<'a>
    {
        model: &'a Model,
        consumed: Cell<u32>,
    }

    impl DoorbellEnd for ModelReader<'_>
    {
        fn announce(&self)
        {
            self.model.lock().announces += 1;
            self.model.step(READER, Op::Store(Var::ReaderWaiting, 1));
        }

        fn withdraw(&self)
        {
            self.model.step(READER, Op::Store(Var::ReaderWaiting, 0));
        }

        fn fence(&self)
        {
            self.model.step(READER, Op::Fence);
        }

        fn peer_progressed(&self) -> bool
        {
            self.model.step(READER, Op::Load(Var::Tail)) != self.consumed.get()
        }

        fn peer_waiting(&self) -> bool
        {
            unreachable!("the model's writer never waits");
        }

        fn take_peer_word(&self) -> bool
        {
            unreachable!("the model's writer never waits");
        }
    }

    /// The pipe's write loop over the model: publish each of `items` bytes,
    /// ringing the reader when `take_waiting_peer` says it waits.
    fn model_writer(model: &Model, items: u32)
    {
        let end = ModelWriter(model);
        for published in 1..=items
        {
            model.step(WRITER, Op::Store(Var::Tail, published));
            if take_waiting_peer(&end)
            {
                model.step(WRITER, Op::Send);
            }
        }
        model.finish(WRITER);
    }

    /// The pipe's read loop over the model: take what the ring holds, and when
    /// it is empty wait through `announce_wait` until `items` bytes are read.
    fn model_reader(model: &Model, items: u32)
    {
        let end = ModelReader {
            model,
            consumed: Cell::new(0),
        };
        while end.consumed.get() < items && !model.aborted()
        {
            let tail = model.step(READER, Op::Load(Var::Tail));
            if tail != end.consumed.get()
            {
                end.consumed.set(tail);
                continue;
            }
            if announce_wait(&end)
            {
                model.step(READER, Op::Wait);
                end.withdraw();
            }
        }
        model.finish(READER);
    }

    /// How one schedule ended.
    struct Outcome
    {
        /// Both threads ran to their end.
        completed: bool,
        announces: u32,
        sends: u32,
    }

    /// Run one schedule: at each decision take `prefix[d]` (0 past its end),
    /// and record each decision's choice and the number of moves it had.
    fn run_schedule(prefix: &[usize], items: u32, fences: Fences)
    -> (Outcome, Vec<(usize, usize)>)
    {
        let model = Model {
            world: Mutex::new(World::default()),
            changed: Condvar::new(),
        };
        let mut taken = Vec::new();
        let outcome = std::thread::scope(|scope| {
            scope.spawn(|| model_writer(&model, items));
            scope.spawn(|| model_reader(&model, items));
            let mut world = model.lock();
            loop
            {
                while !world.settled()
                {
                    world = model.wait(world);
                }
                let moves = world.moves(fences);
                if moves.is_empty()
                {
                    break;
                }
                let choice = prefix.get(taken.len()).copied().unwrap_or(0);
                taken.push((choice, moves.len()));
                match moves[choice]
                {
                    Move::Step(thread) => world.grant = Some(thread),
                    Move::Drain(thread) => world.drain_one(thread),
                }
                model.changed.notify_all();
            }
            let outcome = Outcome {
                completed: world.done.iter().all(|&d| d),
                announces: world.announces,
                sends: world.sends,
            };
            world.aborted = true;
            drop(world);
            model.changed.notify_all();
            outcome
        });
        (outcome, taken)
    }

    /// Run every schedule of a writer publishing `items` bytes one by one and
    /// a reader taking them, and return the outcomes.
    fn explore(items: u32, fences: Fences) -> Vec<Outcome>
    {
        let mut outcomes = Vec::new();
        let mut prefix = Vec::new();
        loop
        {
            let (outcome, taken) = run_schedule(&prefix, items, fences);
            outcomes.push(outcome);
            // The next schedule: the last decision with a move left untried
            // takes its next move; the decisions before it are replayed.
            let Some(depth) = taken
                .iter()
                .rposition(|&(choice, count)| choice + 1 < count)
            else
            {
                return outcomes;
            };
            prefix = taken[..depth].iter().map(|&(choice, _)| choice).collect();
            prefix.push(taken[depth].0 + 1);
        }
    }

    // Defect guarded: a lost wake, the reader blocked on an empty-looking ring
    // while the writer, not seeing its waiter word, rang nothing (a fence
    // missing or out of place in `announce_wait` or `take_waiting_peer`), and
    // a doorbell rung more often than the reader announced a wait (a waiter
    // word the writer reads without claiming it).
    #[test]
    fn doorbell_protocol_loses_no_wake_in_any_interleaving()
    {
        let outcomes = explore(2, Fences::Order);
        assert!(
            outcomes.len() > 1000,
            "explored {} schedules",
            outcomes.len()
        );
        for outcome in &outcomes
        {
            assert!(
                outcome.completed,
                "a schedule ended with the reader blocked"
            );
            assert!(
                outcome.sends <= outcome.announces,
                "{} doorbells for {} announced waits",
                outcome.sends,
                outcome.announces
            );
        }
    }

    // Defect guarded: a model too weak to see the store-load race, which would
    // pass the test above whatever the protocol's fences. Without them the
    // explorer must find the schedule that loses the wake.
    #[test]
    fn doorbell_model_finds_the_lost_wake_without_the_fences()
    {
        let outcomes = explore(1, Fences::Ignore);
        assert!(outcomes.iter().any(|outcome| !outcome.completed));
    }

    #[test]
    fn ring_indices_a_peer_corrupted_stay_within_one_capacity()
    {
        // A peer that pushes `tail` more than a capacity past `head` must
        // not make the writer underflow its free count or the reader take
        // more than one ring's worth of bytes.
        let mut r = region(CAP);
        r.header.tail.store(CAP * 3, Ordering::Relaxed);
        let va = &raw mut r as u64;
        // SAFETY: `r` is a live, aligned header plus `CAP` body bytes and
        // outlives both halves.
        let (mut w, mut rd) = unsafe { spsc_pair(va, CAP) }.expect("matching capacity");
        assert_eq!(w.write(&[1, 2, 3]), 0);
        let mut out = [0u8; CAP as usize * 2];
        assert_eq!(rd.read(&mut out), CAP as usize);
    }
}
