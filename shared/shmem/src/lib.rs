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
//! cap out of band (pipes); this crate holds only the mechanism.

// Under `rustc-dep-of-std` (build-std), use the core facade and no_core
// so this crate can sit inside std's dep graph. Mirrors abi/syscall,
// shared/syscall, shared/ipc, shared/log. Normal userspace builds (no
// feature) retain `#![no_std]`.
#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(any(feature = "rustc-dep-of-std", test)), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

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
/// Bounded by `MSG_CAP_SLOTS_MAX` on IPC transfer (each Memory cap travels in
/// its own cap slot when the peer attaches). Keep in lockstep with the
/// IPC abi.
pub const MAX_PAGES: u32 = 4;

/// Errors that can surface from [`SharedBuffer`] operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShmemError
{
    /// `pages` is zero, exceeds [`MAX_PAGES`], or exceeds the number of
    /// Memory caps supplied.
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
    page_count: u32,
    aspace: u32,
}

impl SharedBuffer
{
    /// Attach to a shared buffer using memory caps received from the peer.
    /// Maps `memory_caps[..pages]` sequentially read-write at `vaddr` in
    /// `aspace`; dropping the buffer unmaps the span.
    ///
    /// # Safety
    /// When `aspace` names the calling program's own address space, no page of
    /// `[vaddr, vaddr + pages * 4096)` may hold a live Rust object or a
    /// registered IPC buffer page, from this call until the buffer is dropped:
    /// the map replaces what the span held and the drop unmaps it (the
    /// contracts of `syscall::mem_map` and `syscall::mem_unmap`).
    ///
    /// # Errors
    /// [`ShmemError::InvalidPageCount`] if `pages` is zero, exceeds
    /// [`MAX_PAGES`], or exceeds `memory_caps.len()`;
    /// [`ShmemError::MapFailed`] if deriving a mapping cap or any map call
    /// fails.
    pub unsafe fn attach(
        memory_caps: &[u32],
        pages: u32,
        aspace: u32,
        vaddr: u64,
    ) -> Result<Self, ShmemError>
    {
        if pages == 0 || pages > MAX_PAGES || memory_caps.len() < pages as usize
        {
            return Err(ShmemError::InvalidPageCount);
        }
        for i in 0..pages
        {
            let rw = match syscall::cap_derive(memory_caps[i as usize], syscall::RIGHTS_MEM_MAP_RW)
            {
                Ok(c) => c,
                Err(_) =>
                {
                    // SAFETY: pages `0..i` were mapped by this call, inside the
                    // span the caller's contract dedicates.
                    unsafe { unmap_range(aspace, vaddr, i) };
                    return Err(ShmemError::MapFailed);
                }
            };
            // SAFETY: page `i` lies in the span the caller's contract keeps
            // off live Rust objects and registered IPC pages.
            let mapped = unsafe {
                syscall::mem_map(
                    rw,
                    aspace,
                    vaddr + u64::from(i) * PAGE_SIZE,
                    0,
                    1,
                    syscall::MAP_WRITABLE,
                )
            };
            if mapped.is_err()
            {
                let _ = syscall::cap_delete(rw);
                // SAFETY: pages `0..i` were mapped by this call, inside the
                // dedicated span.
                unsafe { unmap_range(aspace, vaddr, i) };
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
        let _ = unsafe { syscall::mem_unmap(self.aspace, self.vaddr, u64::from(self.page_count)) };
    }
}

/// Best-effort unmap of `count` pages starting at `vaddr`. Used during
/// failure cleanup; errors are swallowed.
///
/// # Safety
/// The contract of `syscall::mem_unmap` for the `count` pages at `vaddr`.
unsafe fn unmap_range(aspace: u32, vaddr: u64, count: u32)
{
    for i in 0..count
    {
        // SAFETY: page `i` is in the span the caller's contract covers.
        let _ = unsafe { syscall::mem_unmap(aspace, vaddr + u64::from(i) * PAGE_SIZE, 1u64) };
    }
}

// ── SPSC byte ring ───────────────────────────────────────────────────────────

/// Fixed in-memory header at the start of an SPSC shared region.
///
/// Two atomic indices plus an atomic `capacity` (byte buffer length, must be a
/// power of two) and a `closed` flag used by pipe peers to signal EOF.
/// The byte buffer follows immediately after this struct, at offset
/// [`SpscHeader::SIZE`].
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
}

impl SpscHeader
{
    /// Size of the header in bytes. Usable bytes for the ring start at
    /// `vaddr + SpscHeader::SIZE` and run for `capacity` bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Initialise a fresh header at `ptr` with `capacity` bytes of ring
    /// storage. `capacity` must be a non-zero power of two.
    ///
    /// # Safety
    /// `ptr` must be valid, writable, and aligned for `SpscHeader` (4 bytes).
    /// The caller is the unique initialiser of the header; no other thread
    /// on either side of the shared region may be reading the header yet.
    pub unsafe fn init(ptr: *mut Self, capacity: u32)
    {
        assert!(capacity.is_power_of_two(), "SPSC capacity must be pow2");
        // SAFETY: pointer validity promised by the caller.
        unsafe {
            (*ptr).head.store(0, Ordering::Relaxed);
            (*ptr).tail.store(0, Ordering::Relaxed);
            (*ptr).capacity.store(capacity, Ordering::Relaxed);
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

// SAFETY: the header is shared between processes via a Memory-cap mapping;
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
pub unsafe fn spsc_pair<'a>(
    region_vaddr: u64,
    capacity: u32,
) -> Option<(SpscWriter<'a>, SpscReader<'a>)>
{
    // SAFETY: caller contract.
    unsafe {
        Some((
            SpscWriter::from_raw(region_vaddr, capacity)?,
            SpscReader::from_raw(region_vaddr, capacity)?,
        ))
    }
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
    (shared == capacity).then_some(capacity - 1)
}

impl<'a> SpscWriter<'a>
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
    pub unsafe fn from_raw(region_vaddr: u64, capacity: u32) -> Option<Self>
    {
        // SAFETY: caller contract: the header is mapped, readable and aligned.
        let mask = unsafe { checked_mask(region_vaddr, capacity) }?;
        // SAFETY: caller contract: the header stays mapped and valid for `'a`.
        let header = unsafe { &*(region_vaddr as *const SpscHeader) };
        Some(Self {
            header,
            buf: (region_vaddr + SpscHeader::SIZE as u64) as *mut u8,
            mask,
        })
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
    /// `capacity` and the `None` cases are as for [`SpscWriter::from_raw`].
    ///
    /// # Safety
    /// The region at `region_vaddr` (an initialised [`SpscHeader`] plus
    /// `capacity` body bytes) must be mapped readable and writable and 4-byte
    /// aligned, and must stay mapped and valid for `'a`. Only one reader may
    /// exist at a time.
    pub unsafe fn from_raw(region_vaddr: u64, capacity: u32) -> Option<Self>
    {
        // SAFETY: caller contract: the header is mapped, readable and aligned.
        let mask = unsafe { checked_mask(region_vaddr, capacity) }?;
        // SAFETY: caller contract: the header stays mapped and valid for `'a`.
        let header = unsafe { &*(region_vaddr as *const SpscHeader) };
        Some(Self {
            header,
            buf: (region_vaddr + SpscHeader::SIZE as u64) as *const u8,
            mask,
        })
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

#[cfg(test)]
mod tests
{
    use super::*;

    const CAP: u32 = 64;

    /// A ring region in ordinary memory: header plus a `CAP`-byte body.
    #[repr(C, align(8))]
    struct Region
    {
        header: SpscHeader,
        body: [u8; CAP as usize],
    }

    fn region(header_capacity: u32) -> Box<Region>
    {
        let mut r = Box::new(Region {
            header: SpscHeader {
                head: AtomicU32::new(0),
                tail: AtomicU32::new(0),
                capacity: AtomicU32::new(0),
                closed: AtomicU32::new(0),
            },
            body: [0; CAP as usize],
        });
        r.header.capacity.store(header_capacity, Ordering::Relaxed);
        r
    }

    #[test]
    fn ring_halves_refuse_a_header_capacity_the_peer_rewrote()
    {
        // The peer grew the shared field past the mapped body; trusting it
        // would let the writer index beyond `body`.
        let mut r = region(CAP * 4);
        let va = &raw mut *r as u64;
        // SAFETY: `r` is a live, aligned header plus `CAP` body bytes.
        unsafe {
            assert!(SpscWriter::from_raw(va, CAP).is_none());
            assert!(SpscReader::from_raw(va, CAP).is_none());
        }
    }

    #[test]
    fn ring_halves_refuse_a_capacity_that_is_not_a_power_of_two()
    {
        // A zero capacity would underflow the index mask; a non-power-of-two
        // one would mask indices outside the body.
        for bad in [0, 48]
        {
            let mut r = region(bad);
            let va = &raw mut *r as u64;
            // SAFETY: `r` is a live, aligned header plus `CAP` body bytes;
            // `bad <= CAP`.
            assert!(unsafe { spsc_pair(va, bad) }.is_none());
        }
    }

    #[test]
    fn ring_built_with_the_mapped_capacity_round_trips_bytes()
    {
        let mut r = region(CAP);
        let va = &raw mut *r as u64;
        // SAFETY: `r` is a live, aligned header plus `CAP` body bytes and
        // outlives both halves.
        let (mut w, mut rd) = unsafe { spsc_pair(va, CAP) }.expect("matching capacity");
        assert_eq!(w.write(&[0xAB; CAP as usize + 8]), CAP as usize);
        let mut out = [0u8; CAP as usize];
        assert_eq!(rd.read(&mut out), CAP as usize);
        assert!(out.iter().all(|&b| b == 0xAB));
        assert!(rd.is_empty());
    }
}
