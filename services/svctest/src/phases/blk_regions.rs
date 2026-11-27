// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/blk_regions.rs

//! virtio-blk's registered DMA regions, against the driver of the first live
//! block device (`services/drivers/virtio/blk/README.md` § Label 6 to § Label 9).
//!
//! svctest holds that device's whole-disk cap through its `devmgr.class.block`
//! seed and registers a scratch partition in the gap between the GPT's entry
//! array and the first partition ([`SCRATCH_BASE`] to [`SCRATCH_END`]),
//! whose blocks it reads first and writes back before it unregisters its
//! regions. On that partition:
//!
//! - a pattern written from one page of a region reads back into another page
//!   of it;
//! - a run past the region's end, an offset that is not a multiple of the
//!   block size, and a read into a region the device only reads are refused
//!   `INVALID_MEMORY_CAP`, and a run past the partition's end `OUT_OF_BOUNDS`;
//! - a region cap names its own region alone: each region's write takes that
//!   region's contents to disk, and each region's read lands in that region;
//! - a fifth region on the partition is refused `REGION_LIMIT`;
//! - `BLK_UNREGISTER_REGION` revokes the region and liveness caps svctest
//!   held, so a request on the region cap fails, while another region still
//!   transfers;
//! - a child that registers a region of its own grant and is killed ends the
//!   registration with no request of anyone's: svctest's copy of the child's
//!   region cap is revoked, and the child's pages leave memmgr's deferred
//!   list.

use std::os::seraph::{current_ipc_buf, startup_info};
use std::time::{Duration, Instant};

use ipc::{IpcMessage, blk_errors, blk_labels};

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "blk_regions",
        run: blk_regions_phase,
    }]
}

/// Byte offset on the disk of the scratch partition: past the GPT's entry
/// array, which ends by 17 KiB on a 512-byte disk and 24 KiB on a 4096-byte
/// one.
const SCRATCH_BASE: u64 = 512 * 1024;

/// Byte offset on the disk where the scratch partition ends: the first
/// partition's start (`xtask/src/disk.rs`).
const SCRATCH_END: u64 = 1024 * 1024;

/// Pages of each region svctest registers.
const REGION_PAGES: u32 = 2;

/// virtio-blk's bound on the regions registered on one partition at once
/// (`MAX_REGIONS_PER_PARTITION`, docs/limits.md).
const MAX_REGIONS_PER_PARTITION: usize = 4;

/// Role token for [`region_child_main`].
const REGION_CHILD_ROLE: &str = "blk-region-child";

/// Label of the call a `blk-region-child` makes on its namespace cap, which
/// carries SEND only, to fetch its caps.
const CHILD_FETCH_LABEL: u64 = 0x6272_6731;

/// Label of the call a `blk-region-child` makes on the fetched hand-off SEND,
/// carrying a copy of its region cap.
const CHILD_HAND_LABEL: u64 = 0x6272_6732;

/// Badge of the hand-off SEND (with GRANT) a `blk-region-child` fetches.
const CHILD_HAND_BADGE: u64 = 0x5B01;

/// Badge of the SEND that stops [`serve_region_child`].
const CHILD_STOP_BADGE: u64 = 0x5B02;

/// How long svctest waits for the driver to end a dead child's registration.
/// A test wait bound.
const REVOKE_WAIT: Duration = Duration::from_secs(60);

/// Child-mode dispatch for the argv token this module owns. A
/// `blk-region-child` parks until its spawner kills it; on a miss control
/// returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == REGION_CHILD_ROLE
    {
        region_child_main();
    }
}

/// The page size, in bytes, as a `usize`.
fn page() -> usize
{
    usize::try_from(syscall_abi::PAGE_SIZE).expect("blk_regions: the page size fits a usize")
}

/// `ipc_call` on `cap` from this thread; panics naming `what` when the call
/// itself fails.
fn call(cap: u64, msg: &IpcMessage, what: &str) -> IpcMessage
{
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    unsafe { ipc::ipc_call(cap, msg, current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("blk_regions: {what}: ipc_call failed ({e})"))
}

/// The caller's `BLK_LABELS_VERSION`, as the first word of every request.
fn version() -> u64
{
    u64::from(ipc::BLK_LABELS_VERSION)
}

/// `BLK_GET_GEOMETRY` on `cap`: the logical block size and the caller's
/// length in blocks.
fn geometry(cap: u64, what: &str) -> (u64, u64)
{
    let msg = IpcMessage::builder(blk_labels::BLK_GET_GEOMETRY)
        .word(0, version())
        .build();
    let reply = call(cap, &msg, what);
    assert_eq!(
        reply.label,
        blk_errors::SUCCESS,
        "blk_regions: {what}: BLK_GET_GEOMETRY status"
    );
    (reply.word(0), reply.word(1))
}

/// Whether `cap` names no capability in svctest's `CSpace`.
fn gone(cap: u64) -> bool
{
    syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS).is_err()
}

/// A region svctest registered: its region and liveness caps, the grant it
/// covers, and where svctest maps that grant.
struct Region
{
    cap: u64,
    liveness: u64,
    grant: u64,
    grant_id: u64,
    range: std::os::seraph::ReservedRange,
}

impl Region
{
    /// Register a region of a fresh [`REGION_PAGES`]-page grant on
    /// `partition` with the device's `access`: the region, or the
    /// driver's refusal label, the grant then released.
    fn register(partition: u64, access: u64, what: &str) -> Result<Self, u64>
    {
        let (grant, grant_id) = super::memmgr::try_request_contiguous(REGION_PAGES)
            .unwrap_or_else(|label| panic!("blk_regions: {what}: grant refused ({label:#x})"));
        let pages = u64::from(REGION_PAGES);
        let range = std::os::seraph::reserve_pages(pages)
            .unwrap_or_else(|_| panic!("blk_regions: {what}: reserving {pages} pages failed"));
        // SAFETY: `range` is a fresh reservation from the per-process arena,
        // owned here: VA no Rust object or IPC page occupies.
        unsafe {
            std::os::seraph::mem_map_funded(
                grant,
                startup_info().self_aspace,
                range.va_start(),
                0,
                pages,
                syscall::MAP_READ | syscall::MAP_WRITABLE,
            )
        }
        .unwrap_or_else(|e| panic!("blk_regions: {what}: mapping the grant failed ({e})"));
        let rights = if access == blk_labels::REGION_DEVICE_READS
        {
            syscall::RIGHTS_MEM_MAP
        }
        else
        {
            syscall::RIGHTS_MEM_MAP_RW
        };
        let lent = syscall::cap_derive(grant, rights)
            .unwrap_or_else(|e| panic!("blk_regions: {what}: deriving the lent cap failed ({e})"));
        let msg = IpcMessage::builder(blk_labels::BLK_REGISTER_REGION)
            .word(0, version())
            .word(1, access)
            .cap(lent)
            .build();
        let reply = call(partition, &msg, what);
        let region = Self {
            cap: 0,
            liveness: 0,
            grant,
            grant_id,
            range,
        };
        match (reply.label, reply.caps())
        {
            (blk_errors::SUCCESS, &[cap, liveness]) => Ok(Self {
                cap,
                liveness,
                ..region
            }),
            (blk_errors::SUCCESS, caps) =>
            {
                panic!(
                    "blk_regions: {what}: BLK_REGISTER_REGION replied {} caps",
                    caps.len()
                )
            }
            (label, _) =>
            {
                region.release(what);
                Err(label)
            }
        }
    }

    /// `BLK_READ_REGION` or `BLK_WRITE_REGION` (`label`) of `count` blocks at
    /// partition LBA `lba` and byte `offset` in the region: the reply label.
    fn transfer(&self, label: u64, lba: u64, count: u64, offset: u64, what: &str) -> u64
    {
        let msg = IpcMessage::builder(label)
            .word(0, version())
            .word(1, lba)
            .word(2, count)
            .word(3, offset)
            .build();
        call(self.cap, &msg, what).label
    }

    /// `label`'s transfer, which must succeed.
    fn transfer_ok(&self, label: u64, lba: u64, count: u64, offset: u64, what: &str)
    {
        assert_eq!(
            self.transfer(label, lba, count, offset, what),
            blk_errors::SUCCESS,
            "blk_regions: {what}"
        );
    }

    /// The address of byte `offset` of the region in svctest's mapping, with
    /// `len` bytes from it inside the region.
    fn at(&self, offset: usize, len: usize) -> *mut u8
    {
        let end = offset
            .checked_add(len)
            .expect("blk_regions: region span overflowed");
        let size = page()
            .checked_mul(usize::try_from(REGION_PAGES).expect("REGION_PAGES fits a usize"))
            .expect("blk_regions: region size overflowed");
        assert!(end <= size, "blk_regions: a copy past the region's end");
        let base = usize::try_from(self.range.va_start()).expect("a VA fits a usize");
        base.checked_add(offset)
            .expect("blk_regions: region address overflowed") as *mut u8
    }

    /// Copy `data` into the region at byte `offset`.
    fn put(&self, offset: usize, data: &[u8])
    {
        let to = self.at(offset, data.len());
        // SAFETY: `at` checked that the span lies in the region, which this
        // process maps read-write; no Rust reference points into it, and no
        // transfer of the region is in flight (each is a synchronous call).
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), to, data.len()) };
    }

    /// The `len` bytes of the region at byte `offset`.
    fn get(&self, offset: usize, len: usize) -> Vec<u8>
    {
        let from = self.at(offset, len);
        let mut out = vec![0u8; len];
        // SAFETY: as in `put`.
        unsafe { core::ptr::copy_nonoverlapping(from, out.as_mut_ptr(), len) };
        out
    }

    /// `BLK_UNREGISTER_REGION`, which must succeed and revoke svctest's
    /// region and liveness caps; then release the grant.
    fn unregister(self, what: &str)
    {
        let msg = IpcMessage::builder(blk_labels::BLK_UNREGISTER_REGION)
            .word(0, version())
            .build();
        assert_eq!(
            call(self.cap, &msg, what).label,
            blk_errors::SUCCESS,
            "blk_regions: {what}: BLK_UNREGISTER_REGION status"
        );
        assert!(
            gone(self.cap) && gone(self.liveness),
            "blk_regions: {what}: a cap of the unregistered region survived its unregistration"
        );
        self.release(what);
    }

    /// Unmap the grant, release it, and give back the reservation.
    fn release(self, what: &str)
    {
        // SAFETY: `range` is the span `register` mapped in this process's
        // own address space, and no Rust reference points into it.
        unsafe {
            syscall::mem_unmap(
                startup_info().self_aspace,
                self.range.va_start(),
                self.range.page_count(),
            )
        }
        .unwrap_or_else(|e| panic!("blk_regions: {what}: mem_unmap failed ({e})"));
        std::os::seraph::unreserve_pages(self.range);
        super::memmgr::release_grant(self.grant, self.grant_id);
    }
}

/// One page of bytes counting up from `seed`.
fn pattern(seed: u8) -> Vec<u8>
{
    (0..=u8::MAX)
        .cycle()
        .take(page())
        .map(|i| seed.wrapping_add(i))
        .collect()
}

/// The registered-region labels against the first block device's driver; see
/// the module documentation for the cases.
fn blk_regions_phase(caps: &Caps)
{
    assert_ne!(
        caps.block_class, 0,
        "blk_regions: no devmgr.class.block seed"
    );
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let disk = unsafe { ipc::first_device(caps.block_class, current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("blk_regions: QUERY_DEVICE on the block class ({e:?})"));
    let (partition, block, blocks) = scratch_partition(disk);
    let per_page = syscall_abi::PAGE_SIZE
        .checked_div(block)
        .expect("block size checked nonzero");
    let span = per_page
        .checked_mul(u64::from(REGION_PAGES))
        .expect("blk_regions: region span overflowed");

    let a = Region::register(
        partition,
        blk_labels::REGION_DEVICE_READS_WRITES,
        "region a",
    )
    .unwrap_or_else(|label| panic!("blk_regions: region a refused ({label:#x})"));
    a.transfer_ok(
        blk_labels::BLK_READ_REGION,
        0,
        span,
        0,
        "saving the scratch blocks",
    );
    let saved = a.get(0, page().checked_mul(2).expect("two pages fit a usize"));

    round_trip(&a, per_page);
    refusals(&a, per_page, blocks);
    let (b, read_only) = own_regions(&a, partition, per_page);
    region_limit(partition);

    a.put(0, &saved);
    a.transfer_ok(
        blk_labels::BLK_WRITE_REGION,
        0,
        span,
        0,
        "restoring the scratch blocks",
    );
    unregistration(&a, b, per_page);
    read_only.unregister("read-only region");
    a.unregister("region a");

    dead_childs_region(partition);

    let _ = syscall::cap_delete(partition);
    let _ = syscall::cap_delete(disk);
    std::os::seraph::log!("blk_regions phase passed ({block}-byte blocks)");
}

/// Register the scratch partition on the whole-disk cap `disk`: the
/// partition cap, the block size, and the partition's length in blocks.
fn scratch_partition(disk: u64) -> (u64, u64, u64)
{
    let (block, disk_blocks) = geometry(disk, "whole disk");
    assert!(
        block != 0 && syscall_abi::PAGE_SIZE.is_multiple_of(block),
        "blk_regions: a block size of {block} bytes does not divide a page"
    );
    let in_blocks = |bytes: u64| {
        bytes
            .checked_div(block)
            .expect("block size checked nonzero")
    };
    let blocks = in_blocks(SCRATCH_END - SCRATCH_BASE);
    assert!(
        disk_blocks >= in_blocks(SCRATCH_END),
        "blk_regions: the disk's {disk_blocks} blocks end before the scratch range"
    );
    let msg = IpcMessage::builder(blk_labels::REGISTER_PARTITION)
        .word(0, version())
        .word(1, in_blocks(SCRATCH_BASE))
        .word(2, blocks)
        .build();
    let reply = call(disk, &msg, "REGISTER_PARTITION");
    let partition = match (reply.label, reply.caps())
    {
        (blk_errors::SUCCESS, &[cap]) => cap,
        (label, caps) => panic!(
            "blk_regions: REGISTER_PARTITION status {label:#x} with {} caps",
            caps.len()
        ),
    };
    assert_eq!(
        geometry(partition, "scratch partition"),
        (block, blocks),
        "blk_regions: the scratch partition's geometry"
    );
    (partition, block, blocks)
}

/// With three regions on `partition`, a fourth registers and a fifth is
/// refused `REGION_LIMIT`; the fourth is then unregistered.
fn region_limit(partition: u64)
{
    let extra = Region::register(
        partition,
        blk_labels::REGION_DEVICE_READS_WRITES,
        "region 4",
    )
    .unwrap_or_else(|label| panic!("blk_regions: a fourth region refused ({label:#x})"));
    match Region::register(
        partition,
        blk_labels::REGION_DEVICE_READS_WRITES,
        "region 5",
    )
    {
        Err(label) => assert_eq!(
            label,
            blk_errors::REGION_LIMIT,
            "blk_regions: a region past {MAX_REGIONS_PER_PARTITION} on one partition"
        ),
        Ok(_) => panic!(
            "blk_regions: a region past {MAX_REGIONS_PER_PARTITION} on one partition was \
             registered"
        ),
    }
    extra.unregister("region 4");
}

/// Unregister `b`: a read on its region cap must fail to be delivered, and
/// `a`, beside it, must still read.
fn unregistration(a: &Region, b: Region, per_page: u64)
{
    let b_cap = b.cap;
    b.unregister("region b");
    let dead = IpcMessage::builder(blk_labels::BLK_READ_REGION)
        .word(0, version())
        .word(1, 0)
        .word(2, per_page)
        .word(3, 0)
        .build();
    // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer page.
    let after = unsafe { ipc::ipc_call(b_cap, &dead, current_ipc_buf()) };
    assert!(
        after.is_err(),
        "blk_regions: a read on an unregistered region's cap was delivered"
    );
    a.transfer_ok(
        blk_labels::BLK_READ_REGION,
        0,
        per_page,
        0,
        "a read on a region beside an unregistered one",
    );
}

/// A pattern written from page 1 of `a` reads back into page 0.
fn round_trip(a: &Region, per_page: u64)
{
    let want = pattern(0x31);
    a.put(page(), &want);
    a.transfer_ok(
        blk_labels::BLK_WRITE_REGION,
        0,
        per_page,
        syscall_abi::PAGE_SIZE,
        "a write",
    );
    a.put(0, &vec![0u8; page()]);
    a.transfer_ok(blk_labels::BLK_READ_REGION, 0, per_page, 0, "a read");
    assert!(
        a.get(0, page()) == want,
        "blk_regions: a read did not return what the write before it wrote"
    );
}

/// Transfers on `a` that the driver must refuse: past the region's end, at
/// an unaligned offset, and past the partition's end (`blocks` long).
fn refusals(a: &Region, per_page: u64, blocks: u64)
{
    let region_bytes = syscall_abi::PAGE_SIZE
        .checked_mul(u64::from(REGION_PAGES))
        .expect("blk_regions: region size overflowed");
    let cases = [
        (
            "a run past the region's end",
            blk_labels::BLK_WRITE_REGION,
            0,
            per_page
                .checked_add(1)
                .expect("a page's blocks plus one fit"),
            syscall_abi::PAGE_SIZE,
            blk_errors::INVALID_MEMORY_CAP,
        ),
        (
            "a run at the region's end",
            blk_labels::BLK_READ_REGION,
            0,
            1,
            region_bytes,
            blk_errors::INVALID_MEMORY_CAP,
        ),
        (
            "an offset off a block boundary",
            blk_labels::BLK_READ_REGION,
            0,
            1,
            1,
            blk_errors::INVALID_MEMORY_CAP,
        ),
        (
            "a run past the partition's end",
            blk_labels::BLK_READ_REGION,
            blocks
                .checked_sub(1)
                .expect("the scratch partition is not empty"),
            2,
            0,
            blk_errors::OUT_OF_BOUNDS,
        ),
    ];
    for (what, label, lba, count, offset, want) in cases
    {
        assert_eq!(
            a.transfer(label, lba, count, offset, what),
            want,
            "blk_regions: {what}"
        );
    }
}

/// Register region b and a region the device only reads, beside `a`, and
/// check that each region cap names its own region: a write through each
/// takes that region's page to disk, and a read through each lands in that
/// region. Returns b and the read-only region.
fn own_regions(a: &Region, partition: u64, per_page: u64) -> (Region, Region)
{
    let b = Region::register(
        partition,
        blk_labels::REGION_DEVICE_READS_WRITES,
        "region b",
    )
    .unwrap_or_else(|label| panic!("blk_regions: region b refused ({label:#x})"));
    let read_only = Region::register(partition, blk_labels::REGION_DEVICE_READS, "read-only")
        .unwrap_or_else(|label| panic!("blk_regions: a read-only region refused ({label:#x})"));
    assert_eq!(
        read_only.transfer(
            blk_labels::BLK_READ_REGION,
            0,
            per_page,
            0,
            "read-only read"
        ),
        blk_errors::INVALID_MEMORY_CAP,
        "blk_regions: a read into a region the device only reads"
    );

    let (in_a, in_b, in_ro) = (pattern(0x41), pattern(0x62), pattern(0x93));
    a.put(0, &in_a);
    b.put(0, &in_b);
    read_only.put(0, &in_ro);
    a.transfer_ok(
        blk_labels::BLK_WRITE_REGION,
        0,
        per_page,
        0,
        "region a's write",
    );
    b.transfer_ok(
        blk_labels::BLK_WRITE_REGION,
        per_page,
        per_page,
        0,
        "region b's write",
    );
    read_only.transfer_ok(
        blk_labels::BLK_WRITE_REGION,
        0,
        per_page,
        0,
        "read-only write",
    );
    a.put(0, &vec![0u8; page()]);
    b.put(0, &vec![0u8; page()]);
    a.transfer_ok(
        blk_labels::BLK_READ_REGION,
        per_page,
        per_page,
        0,
        "region a's read",
    );
    b.transfer_ok(
        blk_labels::BLK_READ_REGION,
        0,
        per_page,
        0,
        "region b's read",
    );
    assert!(
        a.get(0, page()) == in_b,
        "blk_regions: region a's read did not land region b's write in region a"
    );
    assert!(
        b.get(0, page()) == in_ro,
        "blk_regions: region b's read did not land the read-only region's write in region b"
    );
    (b, read_only)
}

/// A child registers a region of its own grant on a copy of `partition`,
/// hands svctest a copy of its region cap, and is killed. The driver must end
/// the registration with no request: svctest's copy is revoked, and the
/// child's pages leave memmgr's deferred list.
fn dead_childs_region(partition: u64)
{
    let baseline = super::memmgr::settled_deferred_bytes();
    let child_partition = syscall::cap_derive(partition, syscall::RIGHTS_EP_SEND_GRANT)
        .expect("blk_regions: partition cap copy");
    let (mut child, copy) = spawn_region_child(child_partition);
    assert!(
        !gone(copy),
        "blk_regions: the live child's region cap copy is gone"
    );
    child
        .kill()
        .expect("blk_regions: killing blk-region-child failed");
    let _ = child.wait();
    let start = Instant::now();
    while !gone(copy)
    {
        assert!(
            start.elapsed() < REVOKE_WAIT,
            "blk_regions: the dead child's region outlived its death"
        );
        std::thread::yield_now();
    }
    super::memmgr::await_deferred_at_most(
        baseline,
        "blk_regions: the dead child's region pages after its registration ended",
    );
}

/// A `blk-region-child`: fetch a partition cap and a hand-off SEND from the
/// spawner (whose endpoint arrives as this process's namespace cap), register
/// a region of a grant of its own, hand the spawner a copy of the region cap,
/// and park until killed. Exit codes: 2 = the fetch failed, 3 = the grant was
/// refused, 4 = `BLK_REGISTER_REGION` failed, 5 = the copy failed, 6 = the
/// hand-off call failed.
fn region_child_main() -> !
{
    let ipc_buf = current_ipc_buf();
    let fetch = IpcMessage::new(CHILD_FETCH_LABEL);
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let fetched = unsafe { ipc::ipc_call(std::os::seraph::root_dir_cap(), &fetch, ipc_buf) };
    let Some(&[partition, hand]) = fetched.as_ref().ok().map(IpcMessage::caps)
    else
    {
        std::process::exit(2)
    };
    let Ok((grant, _)) = super::memmgr::try_request_contiguous(REGION_PAGES)
    else
    {
        std::process::exit(3)
    };
    let register = IpcMessage::builder(blk_labels::BLK_REGISTER_REGION)
        .word(0, version())
        .word(1, blk_labels::REGION_DEVICE_READS_WRITES)
        .cap(grant)
        .build();
    // SAFETY: as above.
    let reply = unsafe { ipc::ipc_call(partition, &register, ipc_buf) };
    let Some(&[region, _liveness]) = reply
        .as_ref()
        .ok()
        .filter(|r| r.label == blk_errors::SUCCESS)
        .map(IpcMessage::caps)
    else
    {
        std::process::exit(4)
    };
    let Ok(copy) = syscall::cap_derive(region, syscall::RIGHTS_EP_SEND)
    else
    {
        std::process::exit(5)
    };
    let msg = IpcMessage::builder(CHILD_HAND_LABEL).cap(copy).build();
    // SAFETY: as above.
    if unsafe { ipc::ipc_call(hand, &msg, ipc_buf) }.is_err()
    {
        std::process::exit(6);
    }
    loop
    {
        std::thread::park();
    }
}

/// Serve `ep` for a `blk-region-child`: answer its fetch with `partition`
/// and a hand-off SEND badged [`CHILD_HAND_BADGE`], and return the region
/// cap copy its hand-off carries, or `None` once the stop badge arrives. Any
/// other call is refused and its caps deleted.
fn serve_region_child(ep: u64, partition: u64) -> Option<u64>
{
    let ipc_buf = current_ipc_buf();
    let mut grant = Some(partition);
    loop
    {
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let msg = unsafe { ipc::ipc_recv(ep, ipc_buf) }.expect("blk_regions server: ipc_recv");
        let handed = (msg.badge == CHILD_HAND_BADGE && msg.label == CHILD_HAND_LABEL)
            .then(|| msg.caps().first().copied())
            .flatten();
        for &cap in msg.caps().iter().skip(usize::from(handed.is_some()))
        {
            let _ = syscall::cap_delete(cap);
        }
        let done = msg.badge == CHILD_STOP_BADGE || handed.is_some();
        let reply = match grant
        {
            Some(partition) if !done && msg.label == CHILD_FETCH_LABEL =>
            {
                grant = None;
                let hand =
                    syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND_GRANT, CHILD_HAND_BADGE)
                        .expect("blk_regions server: hand-off SEND derive");
                IpcMessage::builder(0).cap(partition).cap(hand).build()
            }
            _ if done => IpcMessage::new(0),
            _ => IpcMessage::new(u64::MAX),
        };
        // SAFETY: as above.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        if done
        {
            return handed;
        }
    }
}

/// Spawn a `blk-region-child` on `partition` and return it with the copy of
/// its region cap it hands back.
fn spawn_region_child(partition: u64) -> (std::process::Child, u64)
{
    use std::os::seraph::process::CommandExt;

    let ep = std::os::seraph::create_endpoint().expect("blk_regions: server endpoint creation");
    let root = syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND).expect("blk_regions: root SEND");
    let stop = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND, CHILD_STOP_BADGE)
        .expect("blk_regions: stop SEND");
    let server = std::thread::Builder::new()
        .name("blk_regions_server".into())
        .spawn(move || serve_region_child(ep, partition))
        .expect("blk_regions: server thread spawn failed");
    let mut child = std::process::Command::new("/tests/svctest")
        .arg(REGION_CHILD_ROLE)
        .namespace_cap(root)
        .spawn()
        .expect("blk_regions: spawning blk-region-child failed");
    while !server.is_finished()
    {
        if let Some(status) = child.try_wait().expect("blk_regions: try_wait failed")
        {
            // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer.
            let _ = unsafe { ipc::ipc_call(stop, &IpcMessage::new(0), current_ipc_buf()) };
            let _ = server.join();
            panic!(
                "blk_regions: blk-region-child exited {status} before handing its region (2 = \
                 fetch, 3 = grant, 4 = BLK_REGISTER_REGION, 5 = copy, 6 = hand-off failed)"
            );
        }
        let _ = syscall::thread_yield();
    }
    let copy = server
        .join()
        .expect("blk_regions: server thread panicked")
        .expect("blk_regions: no region cap handed over");
    let _ = syscall::cap_delete(stop);
    let _ = syscall::cap_delete(ep);
    (child, copy)
}
