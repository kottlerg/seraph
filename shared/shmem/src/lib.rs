// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/shmem/src/lib.rs

//! Shared-memory byte transport for Seraph userspace.
//!
//! Two-layer helper:
//!
//! 1. [`SharedBuffer`] — request N frames from procmgr, map them contiguous
//!    at a chosen VA. Caller moves the frame caps to a peer over IPC; the
//!    peer calls [`SharedBuffer::attach`] to map them at its own VA.
//! 2. [`SpscRing`] — single-producer / single-consumer byte ring over a
//!    [`SharedBuffer`]. Classic Lamport layout: two `AtomicU32` indices at
//!    the head of the region, followed by a power-of-two-sized byte buffer.
//!    Writer and reader may run on different CPUs; ordering is Acquire/
//!    Release on the indices, which is sufficient on both x86-64 (TSO) and
//!    RISC-V (RVWMO) for data published before the index store to be
//!    observed after the index load.
//!
//! This crate holds only the userspace mechanism. Blocking/notification —
//! "reader waits until writer has pushed N bytes" — is out of scope; use a
//! signal cap out-of-band when that is wanted (pipes).

// Under `rustc-dep-of-std` (build-std), use the core facade and no_core
// so this crate can sit inside std's dep graph. Mirrors abi/syscall,
// shared/syscall, shared/ipc, shared/log. Normal userspace builds (no
// feature) retain `#![no_std]`.
#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]
// Clippy pedantic concessions for this small helper crate:
// - from_raw constructors are documented as unsafe via `# Safety` and
//   return types that hold raw pointers; clippy flags ctor methods that
//   "might deref a raw ptr" but they are all already `unsafe fn`.
// - Index-based loops are natural for the byte-ring math; iterator form
//   reads worse here.
#![allow(
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc,
    clippy::needless_range_loop,
    clippy::needless_lifetimes,
    clippy::elidable_lifetime_names,
    clippy::single_match_else,
    clippy::manual_memcpy,
    clippy::must_use_candidate,
    clippy::missing_safety_doc,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::unused_self,
    clippy::pub_underscore_fields,
    clippy::used_underscore_binding,
    clippy::used_underscore_items,
    clippy::manual_let_else
)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

use core::sync::atomic::{AtomicU32, Ordering};

/// Page size on both supported architectures.
const PAGE_SIZE: u64 = 4096;

/// Maximum number of pages per `SharedBuffer`.
///
/// Bounded by `procmgr_labels::REQUEST_FRAMES`'s 4-caps-per-call limit and
/// `MSG_CAP_SLOTS_MAX` on IPC transfer. Keep in lockstep with procmgr.
pub const MAX_PAGES: u32 = 4;

/// Errors that can surface from [`SharedBuffer`] operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShmemError
{
    /// `pages` is zero or exceeds [`MAX_PAGES`].
    InvalidPageCount,
    /// procmgr rejected the frame request (OOM, or no procmgr endpoint).
    RequestFailed,
    /// `sys_mem_map` failed partway through — pages already mapped are
    /// unmapped before the error surfaces.
    MapFailed,
    /// `sys_cap_delete` failed while releasing a frame cap we obtained
    /// from procmgr. Returned only when cleaning up an error path.
    CapDeleteFailed,
}

/// A contiguous, page-aligned region of shared memory mapped into the
/// caller's address space. Frame caps are either still held by this
/// process (for share with a peer) or already moved.
pub struct SharedBuffer
{
    vaddr: u64,
    page_count: u32,
    aspace: u32,
}

impl SharedBuffer
{
    /// Allocate `pages` pages via procmgr's `REQUEST_FRAMES` and map them
    /// read-write at `vaddr` in `aspace`. Returns the handle plus the
    /// frame caps; the caller moves those caps to the peer (e.g. via
    /// `ipc_call` with caps attached) and the peer calls
    /// [`SharedBuffer::attach`].
    ///
    /// # Errors
    /// * [`ShmemError::InvalidPageCount`] if `pages == 0` or `> MAX_PAGES`.
    /// * [`ShmemError::RequestFailed`] if procmgr rejects the request.
    /// * [`ShmemError::MapFailed`] if mapping the returned frames fails.
    pub fn create(
        procmgr_ep: u32,
        aspace: u32,
        vaddr: u64,
        pages: u32,
        ipc_buf: *mut u64,
    ) -> Result<(Self, [u32; MAX_PAGES as usize]), ShmemError>
    {
        if pages == 0 || pages > MAX_PAGES
        {
            return Err(ShmemError::InvalidPageCount);
        }

        // Ask procmgr for `pages` frames. REQUEST_FRAMES returns up to 4
        // in one round; for our MAX_PAGES=4 cap, one round is sufficient.
        let request = ipc::IpcMessage::builder(ipc::procmgr_labels::REQUEST_FRAMES)
            .word(0, u64::from(pages))
            .build();
        // SAFETY: ipc_buf is the caller's registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(procmgr_ep, &request, ipc_buf) }
            .map_err(|_| ShmemError::RequestFailed)?;
        if reply.label != ipc::procmgr_errors::SUCCESS
        {
            return Err(ShmemError::RequestFailed);
        }
        let granted = if reply.word_count() >= 1
        {
            reply.word(0) as u32
        }
        else
        {
            0
        };
        let caps = reply.caps();
        if granted < pages
        {
            // Partial grant — release what we got, report failure.
            for &c in caps.iter().take(granted as usize)
            {
                let _ = syscall::cap_delete(c);
            }
            return Err(ShmemError::RequestFailed);
        }

        let mut frames = [0u32; MAX_PAGES as usize];
        for i in 0..pages as usize
        {
            frames[i] = caps[i];
        }

        // Map each frame sequentially at vaddr + i*PAGE_SIZE.
        for i in 0..pages
        {
            let rw = match syscall::cap_derive(frames[i as usize], syscall::RIGHTS_MAP_RW)
            {
                Ok(c) => c,
                Err(_) =>
                {
                    unmap_range(aspace, vaddr, i);
                    return Err(ShmemError::MapFailed);
                }
            };
            if syscall::mem_map(
                rw,
                aspace,
                vaddr + u64::from(i) * PAGE_SIZE,
                0,
                1,
                syscall::MAP_WRITABLE,
            )
            .is_err()
            {
                let _ = syscall::cap_delete(rw);
                unmap_range(aspace, vaddr, i);
                return Err(ShmemError::MapFailed);
            }
            let _ = syscall::cap_delete(rw);
        }

        Ok((
            SharedBuffer {
                vaddr,
                page_count: pages,
                aspace,
            },
            frames,
        ))
    }

    /// Attach to a shared buffer using frame caps received from the peer.
    /// Maps `frames[..pages]` sequentially read-write at `vaddr`.
    ///
    /// # Errors
    /// [`ShmemError::MapFailed`] if any map call rejects.
    pub fn attach(frames: &[u32], pages: u32, aspace: u32, vaddr: u64) -> Result<Self, ShmemError>
    {
        if pages == 0 || pages > MAX_PAGES || frames.len() < pages as usize
        {
            return Err(ShmemError::InvalidPageCount);
        }
        for i in 0..pages
        {
            let rw = match syscall::cap_derive(frames[i as usize], syscall::RIGHTS_MAP_RW)
            {
                Ok(c) => c,
                Err(_) =>
                {
                    unmap_range(aspace, vaddr, i);
                    return Err(ShmemError::MapFailed);
                }
            };
            if syscall::mem_map(
                rw,
                aspace,
                vaddr + u64::from(i) * PAGE_SIZE,
                0,
                1,
                syscall::MAP_WRITABLE,
            )
            .is_err()
            {
                let _ = syscall::cap_delete(rw);
                unmap_range(aspace, vaddr, i);
                return Err(ShmemError::MapFailed);
            }
            let _ = syscall::cap_delete(rw);
        }

        Ok(SharedBuffer {
            vaddr,
            page_count: pages,
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
    pub fn size(&self) -> usize
    {
        (self.page_count as usize) * (PAGE_SIZE as usize)
    }

    /// Number of pages.
    #[must_use]
    pub fn pages(&self) -> u32
    {
        self.page_count
    }

    /// View the region as a mutable byte slice.
    ///
    /// # Safety
    /// Only one thread in this process may hold a mutable slice at a time;
    /// the underlying memory is shared with another process via raw frame
    /// caps and does not enforce aliasing.
    pub unsafe fn as_bytes_mut(&mut self) -> &mut [u8]
    {
        // SAFETY: region is mapped writable and contiguous for `size`
        // bytes; caller upholds aliasing discipline.
        unsafe { core::slice::from_raw_parts_mut(self.vaddr as *mut u8, self.size()) }
    }
}

impl Drop for SharedBuffer
{
    fn drop(&mut self)
    {
        let _ = syscall::mem_unmap(self.aspace, self.vaddr, u64::from(self.page_count));
    }
}

/// Best-effort unmap of `count` pages starting at `vaddr`. Used during
/// failure cleanup; errors are swallowed.
fn unmap_range(aspace: u32, vaddr: u64, count: u32)
{
    for i in 0..count
    {
        let _ = syscall::mem_unmap(aspace, vaddr + u64::from(i) * PAGE_SIZE, 1u64);
    }
}

// ── SPSC byte ring ───────────────────────────────────────────────────────────

/// Fixed in-memory header at the start of an SPSC shared region.
///
/// Two atomic indices plus a u32 `capacity` (byte buffer length, must be a
/// power of two) and a `closed` flag used by pipe peers to signal EOF.
/// The byte buffer follows immediately after this struct, aligned to the
/// ring's alignment (u64 is enough for our use case).
#[repr(C)]
pub struct SpscHeader
{
    /// Reader's index into the buffer (bytes consumed, mod capacity).
    /// Written by the reader, read by the writer.
    pub head: AtomicU32,
    /// Writer's index into the buffer (bytes produced, mod capacity).
    /// Written by the writer, read by the reader.
    pub tail: AtomicU32,
    /// Capacity of the byte buffer. Power of two.
    pub capacity: u32,
    /// Closer flag: set to 1 (Release) by whichever peer drops first
    /// (writer drop → reader sees EOF; reader drop → writer sees
    /// `BrokenPipe`). Read by the surviving peer (Acquire) after a
    /// zero-progress read/write to disambiguate "ring empty/full" from
    /// "peer gone". Reset to 0 by `init`.
    pub closed: AtomicU32,
}

impl SpscHeader
{
    /// Size of the header in bytes. Usable bytes for the ring start at
    /// `vaddr + HEADER_SIZE` and run for `capacity` bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Initialise a fresh header at `ptr` with `capacity` bytes of ring
    /// storage. `capacity` must be a non-zero power of two.
    ///
    /// # Safety
    /// `ptr` must be valid, writable, and aligned for `SpscHeader` (u64).
    /// The caller is the unique initialiser of the header; no other thread
    /// on either side of the shared region may be reading the header yet.
    pub unsafe fn init(ptr: *mut Self, capacity: u32)
    {
        assert!(capacity.is_power_of_two(), "SPSC capacity must be pow2");
        // SAFETY: pointer validity promised by the caller.
        unsafe {
            (*ptr).head.store(0, Ordering::Relaxed);
            (*ptr).tail.store(0, Ordering::Relaxed);
            core::ptr::write(&raw mut (*ptr).capacity, capacity);
            (*ptr).closed.store(0, Ordering::Relaxed);
        }
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

// SAFETY: the header is shared between processes via a frame-cap mapping;
// the raw pointers point into that shared region. Send across threads in
// one process is fine because all reads/writes through the raw pointers
// go through the atomic indices in the header.
unsafe impl<'a> Send for SpscWriter<'a> {}
// SAFETY: same rationale as `SpscWriter`.
unsafe impl<'a> Send for SpscReader<'a> {}

/// Construct a `(SpscWriter, SpscReader)` pair over a pre-initialised
/// shared region.
///
/// `region_vaddr` must point at an already-mapped shared buffer laid out
/// as `SpscHeader` followed by `header.capacity` bytes.
///
/// Splitting into writer + reader halves from the same call site is
/// convenient for in-process testing. In production the two ends live in
/// different address spaces — each process builds its own half directly
/// with [`SpscWriter::from_raw`] / [`SpscReader::from_raw`].
///
/// # Safety
/// The header at `region_vaddr` must have been initialised by
/// [`SpscHeader::init`]. Only one `SpscWriter` and one `SpscReader` may
/// exist at a time for a given shared region.
pub unsafe fn spsc_pair<'a>(region_vaddr: u64) -> (SpscWriter<'a>, SpscReader<'a>)
{
    // SAFETY: caller contract.
    unsafe {
        (
            SpscWriter::from_raw(region_vaddr),
            SpscReader::from_raw(region_vaddr),
        )
    }
}

impl<'a> SpscWriter<'a>
{
    /// Wrap a pre-initialised shared region as a writer.
    ///
    /// # Safety
    /// The region must start with an initialised [`SpscHeader`]. Only one
    /// writer may exist at a time.
    pub unsafe fn from_raw(region_vaddr: u64) -> Self
    {
        // SAFETY: caller contract.
        let header = unsafe { &*(region_vaddr as *const SpscHeader) };
        let capacity = header.capacity;
        Self {
            header,
            buf: (region_vaddr + SpscHeader::SIZE as u64) as *mut u8,
            mask: capacity - 1,
        }
    }

    /// Write up to `data.len()` bytes into the ring, returning the number
    /// actually written (zero if the ring is full). Non-blocking.
    pub fn write(&mut self, data: &[u8]) -> usize
    {
        let capacity = self.mask + 1;
        let head = self.header.head.load(Ordering::Acquire);
        let tail = self.header.tail.load(Ordering::Relaxed);
        let used = tail.wrapping_sub(head);
        let free = capacity - used;
        if free == 0
        {
            return 0;
        }
        let n = core::cmp::min(data.len(), free as usize);
        for i in 0..n
        {
            let slot = (tail.wrapping_add(i as u32)) & self.mask;
            // SAFETY: slot < capacity; buf..buf+capacity is the ring body.
            unsafe {
                *self.buf.add(slot as usize) = data[i];
            }
        }
        self.header
            .tail
            .store(tail.wrapping_add(n as u32), Ordering::Release);
        n
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
        (self.mask + 1) as usize
    }
}

impl<'a> SpscReader<'a>
{
    /// Wrap a pre-initialised shared region as a reader.
    ///
    /// # Safety
    /// The region must start with an initialised [`SpscHeader`]. Only one
    /// reader may exist at a time.
    pub unsafe fn from_raw(region_vaddr: u64) -> Self
    {
        // SAFETY: caller contract.
        let header = unsafe { &*(region_vaddr as *const SpscHeader) };
        let capacity = header.capacity;
        Self {
            header,
            buf: (region_vaddr + SpscHeader::SIZE as u64) as *const u8,
            mask: capacity - 1,
        }
    }

    /// Read up to `dst.len()` bytes from the ring, returning the number
    /// actually read (zero if the ring is empty). Non-blocking.
    pub fn read(&mut self, dst: &mut [u8]) -> usize
    {
        let head = self.header.head.load(Ordering::Relaxed);
        let tail = self.header.tail.load(Ordering::Acquire);
        let used = tail.wrapping_sub(head);
        if used == 0
        {
            return 0;
        }
        let n = core::cmp::min(dst.len(), used as usize);
        for i in 0..n
        {
            let slot = (head.wrapping_add(i as u32)) & self.mask;
            // SAFETY: slot < capacity; buf..buf+capacity is the ring body.
            unsafe {
                dst[i] = *self.buf.add(slot as usize);
            }
        }
        self.header
            .head
            .store(head.wrapping_add(n as u32), Ordering::Release);
        n
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
