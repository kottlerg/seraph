// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/blk/src/lib.rs

//! Host-testable request logic of the `VirtIO` block driver.
//!
//! The driver binary (`main.rs`, `io.rs`) owns the device, the virtqueue,
//! and the IPC loop. This library holds the pure decisions those paths
//! make on client- and device-supplied values: the device geometry the
//! driver serves in logical blocks, the transfer length a client's block
//! count asks for, the grants ([`Grants`]): the partition badges the driver
//! minted and the regions registered through them, and
//! the reply label a request's outcome maps to. Each is a wire-contract
//! decision (`shared/ipc::blk_labels`, `shared/ipc::blk_errors`), so they
//! live where a host test can pin them. It also holds the registered regions
//! ([`RegionTable`]): their slots and generations, the per-partition bound,
//! the badge a region cap carries and the correlator its liveness binding
//! posts, and the offset and length checks of a region transfer; and the
//! record of a request's time ([`RequestTiming`]), from which the driver logs
//! a request slower than [`SLOW_REQUEST`].

use core::fmt;
use core::time::Duration;

use ipc::blk_errors;

/// Bytes per `VirtIO` block sector: the unit of a request header's `sector`
/// field and of the `capacity` config field, whatever the device's logical
/// block size (`VirtIO` 1.2 §5.2.4, §5.2.6).
pub const VIRTIO_SECTOR_SIZE: u64 = 512;

/// Largest logical block size the driver serves: one page, the unit every
/// client reads into (a cache page, a GPT read buffer).
pub const MAX_BLOCK_SIZE: u32 = 4096;

/// `VIRTIO_BLK_F_BLK_SIZE` feature bit: the device reports its logical block
/// size in the `blk_size` config field (`VirtIO` 1.2 §5.2.3).
pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;

/// Byte offset of the `blk_size` field in the device config (`VirtIO` 1.2
/// §5.2.4: after `capacity`, `size_max`, `seg_max`, and `geometry`).
pub const CONFIG_BLK_SIZE_OFFSET: u32 = 20;

/// Device status byte: request completed (`VIRTIO_BLK_S_OK`, `VirtIO` 1.2 §5.2.6).
pub const VIRTIO_BLK_S_OK: u8 = 0;
/// Device status byte: I/O error (`VIRTIO_BLK_S_IOERR`).
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
/// Device status byte: request type unsupported (`VIRTIO_BLK_S_UNSUPP`).
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// The device geometry the driver serves: its logical block size, and its
/// capacity in those blocks. Every LBA and count on the wire is in logical
/// blocks; the driver converts to `VirtIO`'s 512-byte sectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry
{
    /// Logical block size in bytes: a power of two from 512 to
    /// [`MAX_BLOCK_SIZE`].
    pub block_size: u32,
    /// Device capacity in logical blocks.
    pub capacity: u64,
}

impl Geometry
{
    /// The geometry of a device reporting `capacity_sectors` 512-byte
    /// sectors, and, when it offered [`VIRTIO_BLK_F_BLK_SIZE`] (`blk_size`
    /// is `Some`), that logical block size. A device without the feature has
    /// 512-byte blocks.
    ///
    /// Returns `None` for a reported block size the driver cannot serve: not
    /// a power of two, below 512, or above [`MAX_BLOCK_SIZE`]. The value is
    /// device-written, so it is checked rather than trusted.
    #[must_use]
    pub fn new(capacity_sectors: u64, blk_size: Option<u32>) -> Option<Self>
    {
        let block_size = blk_size.unwrap_or(512);
        if !block_size.is_power_of_two() || !(512..=MAX_BLOCK_SIZE).contains(&block_size)
        {
            return None;
        }
        Some(Self {
            block_size,
            // At least 1 sector per block: the size is at least 512.
            capacity: capacity_sectors.checked_div(self::sectors_per_block(block_size))?,
        })
    }

    /// The `VirtIO` sector a logical block starts at. Exact for every LBA
    /// below `capacity`, which the driver checks before converting; `None`
    /// for an LBA whose sector is past `u64`.
    #[must_use]
    pub fn device_sector(self, lba: u64) -> Option<u64>
    {
        lba.checked_mul(sectors_per_block(self.block_size))
    }

    /// Byte length of a transfer of `block_count` blocks, as the `u32` a
    /// `VirtIO` descriptor carries.
    ///
    /// Returns `None` when `block_count` is 0, when the byte count
    /// overflows `u64`, or when it exceeds `u32::MAX`; the driver answers
    /// each with `blk_errors::INVALID_MEMORY_CAP`, as the wire contract
    /// states.
    #[must_use]
    pub fn transfer_len(self, block_count: u64) -> Option<u32>
    {
        if block_count == 0
        {
            return None;
        }
        block_count
            .checked_mul(u64::from(self.block_size))
            .and_then(|n| u32::try_from(n).ok())
    }
}

/// 512-byte sectors per logical block of `block_size` bytes.
fn sectors_per_block(block_size: u32) -> u64
{
    u64::from(block_size) / VIRTIO_SECTOR_SIZE
}

/// Per-badge partition bound: the LBA range, in logical blocks, a
/// partition-badged caller may access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartitionBound
{
    pub badge: u64,
    pub base_lba: u64,
    pub length_lba: u64,
}

/// The partition grants registered on the driver, keyed by partition badge.
///
/// Each registration is one grant and takes a fresh badge, one no earlier
/// registration had, whether or not its range is already registered; a
/// retire ([`Grants::retire`]) removes the entry, and its badge
/// names nothing from then on. The table holds one entry per live grant. It
/// grows on the heap with them; nothing in it is fixed-size.
#[derive(Default)]
pub struct PartitionTable
{
    entries: Vec<PartitionBound>,
    /// Next fresh partition badge. It only grows, so no badge is minted
    /// twice. Badges stay in the low 62 bits, so they are bit-disjoint from
    /// `blk_labels::MOUNT_AUTHORITY` and from [`REGION_BADGE`] by
    /// construction; reaching bit 62 takes 2^62 registrations.
    next_badge: u64,
}

impl PartitionTable
{
    #[must_use]
    pub fn new() -> Self
    {
        Self {
            entries: Vec::new(),
            next_badge: 1,
        }
    }

    /// The bound registered for `badge`, if any: `None` for a badge never
    /// minted or retired. Badge 0 (unbadged) never names one.
    #[must_use]
    pub fn lookup(&self, badge: u64) -> Option<PartitionBound>
    {
        if badge == 0
        {
            return None;
        }
        self.entries.iter().copied().find(|b| b.badge == badge)
    }

    /// Register the range `[base_lba, base_lba + length_lba)` as a new grant
    /// and return its fresh badge.
    ///
    /// Returns `None` for an empty range, when the fresh-badge counter has
    /// reached [`REGION_BADGE`], or when the heap cannot grow the table. The
    /// caller checks the range against the device capacity first.
    pub fn register(&mut self, base_lba: u64, length_lba: u64) -> Option<u64>
    {
        if length_lba == 0
        {
            return None;
        }
        let badge = self.next_badge;
        if badge >= REGION_BADGE
        {
            return None;
        }
        self.entries.try_reserve(1).ok()?;
        // Below REGION_BADGE (bit 62), checked above: no saturation.
        self.next_badge = badge.saturating_add(1);
        self.entries.push(PartitionBound {
            badge,
            base_lba,
            length_lba,
        });
        Some(badge)
    }

    /// Remove the grant `badge` names; `false` when it names none.
    fn remove(&mut self, badge: u64) -> bool
    {
        let before = self.entries.len();
        self.entries.retain(|b| b.badge != badge || badge == 0);
        self.entries.len() != before
    }
}

// ── Registered regions ─────────────────────────────────────────────────────

/// Regions one partition holds at once (`BLK_REGISTER_REGION`); the
/// whole-disk badge counts as one partition. swapd's three staging buffers
/// are the most one client registers; `docs/limits.md` classifies the bound.
pub const MAX_REGIONS_PER_PARTITION: usize = 4;

/// Region slots of the driver, over every partition: the slots its event
/// queue holds one sole-reference observer node for, since a queue's node
/// pool is fixed when the queue is made. Eight partitions' worth of
/// [`MAX_REGIONS_PER_PARTITION`]; `docs/limits.md` classifies the bound.
pub const MAX_REGIONS: usize = 32;

/// Badge bit of every capability the driver mints for a region, and of the
/// sweeper's own SEND ([`SWEEPER_BADGE`]). Partition badges stay below it
/// ([`PartitionTable::register`]), and devmgr's whole-disk badge carries
/// `blk_labels::MOUNT_AUTHORITY` (bit 63), so no other badge has it alone.
pub const REGION_BADGE: u64 = 1 << 62;

/// Low bits of a region badge, and of a correlator, that hold the slot.
const SLOT_BITS: u32 = 8;
/// Mask of the slot field.
const SLOT_MASK: u64 = (1 << SLOT_BITS) - 1;
/// Slot field of [`SWEEPER_BADGE`], above every region slot.
const SWEEPER_SLOT: u64 = SLOT_MASK;
/// Largest generation: the bits of a region badge between the slot field and
/// [`REGION_BADGE`].
const GENERATION_MASK: u64 = (REGION_BADGE - 1) >> SLOT_BITS;

/// Badge of the SEND on its own service endpoint through which the driver's
/// sweeper thread hands the service loop each sole-reference post, so every
/// change to the region table is made on the service loop's thread.
pub const SWEEPER_BADGE: u64 = REGION_BADGE | SWEEPER_SLOT;

/// Label of the sweeper thread's request to the service loop, `data[0]` the
/// correlator of a sole-reference post its event queue received. Honoured
/// only from [`SWEEPER_BADGE`]: any other sender is answered
/// `blk_errors::UNKNOWN_OPCODE`. Above every `blk_labels` label.
pub const SWEEP: u64 = 0x100;

// Every slot index fits the slot field below the sweeper's.
const _: () = assert!((MAX_REGIONS as u64) < SWEEPER_SLOT);

/// One registration of one region slot: the slot, and the generation the
/// slot had when the region was registered. A slot's generation advances at
/// each registration, so an identifier of an earlier registration names
/// nothing once the slot is reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionId
{
    /// Index into the driver's [`MAX_REGIONS`] slots.
    pub slot: usize,
    /// The slot's generation at the registration; never 0.
    pub generation: u64,
}

impl RegionId
{
    /// The badge of the region cap: [`REGION_BADGE`] over the correlator.
    #[must_use]
    pub fn badge(self) -> u64
    {
        REGION_BADGE | self.correlator()
    }

    /// The correlator the region's sole-reference binding posts: the
    /// generation above the slot.
    #[must_use]
    pub fn correlator(self) -> u64
    {
        (self.generation << SLOT_BITS) | self.slot as u64
    }

    /// The registration a correlator (or a region badge with
    /// [`REGION_BADGE`] cleared) names, or `None` for a value no
    /// registration produces: a slot past [`MAX_REGIONS`], generation 0, or
    /// bits above the generation field.
    #[must_use]
    pub fn from_correlator(correlator: u64) -> Option<Self>
    {
        let slot = usize::try_from(correlator & SLOT_MASK).ok()?;
        let generation = correlator >> SLOT_BITS;
        if slot >= MAX_REGIONS || generation == 0 || generation > GENERATION_MASK
        {
            return None;
        }
        Some(Self { slot, generation })
    }
}

/// Who sent a request, as its badge says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Caller
{
    /// No badge; the driver serves no such caller.
    Unbadged,
    /// A whole-disk cap: `blk_labels::MOUNT_AUTHORITY` set. The badge is the
    /// partition key its regions count against.
    WholeDisk(u64),
    /// A partition badge the driver minted at `REGISTER_PARTITION`.
    Partition(u64),
    /// A region cap's badge.
    Region(RegionId),
    /// The driver's own sweeper thread ([`SWEEPER_BADGE`]).
    Sweeper,
    /// A badge with [`REGION_BADGE`] that names no registration the driver
    /// can make.
    Unknown,
}

impl Caller
{
    /// Classify `badge`.
    #[must_use]
    pub fn of(badge: u64) -> Self
    {
        if badge == 0
        {
            Caller::Unbadged
        }
        else if badge & ipc::blk_labels::MOUNT_AUTHORITY != 0
        {
            Caller::WholeDisk(badge)
        }
        else if badge == SWEEPER_BADGE
        {
            Caller::Sweeper
        }
        else if badge & REGION_BADGE != 0
        {
            RegionId::from_correlator(badge & !REGION_BADGE).map_or(Caller::Unknown, Caller::Region)
        }
        else
        {
            Caller::Partition(badge)
        }
    }
}

/// The device's access to a region, as `BLK_REGISTER_REGION`'s `data[1]`
/// names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionAccess
{
    /// `blk_labels::REGION_DEVICE_READS`: the device only reads the region,
    /// which serves `BLK_WRITE_REGION` alone.
    DeviceReads,
    /// `blk_labels::REGION_DEVICE_READS_WRITES`: the device reads and writes
    /// it, which serves both transfer labels.
    DeviceReadsWrites,
}

impl RegionAccess
{
    /// The access a request word names, or `None` for any other value.
    #[must_use]
    pub fn from_wire(word: u64) -> Option<Self>
    {
        match word
        {
            ipc::blk_labels::REGION_DEVICE_READS => Some(RegionAccess::DeviceReads),
            ipc::blk_labels::REGION_DEVICE_READS_WRITES => Some(RegionAccess::DeviceReadsWrites),
            _ => None,
        }
    }

    /// Whether the device may write the region, as a `BLK_READ_REGION`
    /// needs.
    #[must_use]
    pub fn device_writes(self) -> bool
    {
        self == RegionAccess::DeviceReadsWrites
    }
}

/// A registered region: the partition whose badge registered it, where the
/// device reaches it, its length, and the device's access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region
{
    /// The registering badge: a partition badge or a whole-disk badge. A
    /// transfer on the region is bounded by that badge's range.
    pub partition: u64,
    /// Device address of the region's first byte, which devmgr returned.
    pub device_addr: u64,
    /// The region's length in bytes, the size of its Memory cap.
    pub len: u64,
    /// The device's access.
    pub access: RegionAccess,
}

impl Region
{
    /// The device address and byte length of a transfer of `block_count`
    /// blocks at byte `offset` in the region.
    ///
    /// Returns `None` when `offset` is not a multiple of the logical block
    /// size, when the count is refused by [`Geometry::transfer_len`], or when
    /// the run passes the region's end; the driver answers each with
    /// `blk_errors::INVALID_MEMORY_CAP`.
    #[must_use]
    pub fn span(&self, geometry: Geometry, offset: u64, block_count: u64) -> Option<(u64, u32)>
    {
        if !offset.is_multiple_of(u64::from(geometry.block_size))
        {
            return None;
        }
        let len = geometry.transfer_len(block_count)?;
        if offset.checked_add(u64::from(len))? > self.len
        {
            return None;
        }
        Some((self.device_addr.checked_add(offset)?, len))
    }
}

/// One region slot's state.
enum SlotState<K>
{
    /// Free for the next registration.
    Free,
    /// A registered region, with what the driver keeps for it (`K`: its
    /// capabilities).
    Live
    {
        region: Region, kept: K
    },
    /// Unregistered by its client, and waiting for the one post its
    /// sole-reference binding still owes, which frees it. Until then the slot
    /// holds its observer node, so it is not reused.
    Retiring,
}

/// One region slot.
struct Slot<K>
{
    /// Generation of the slot's latest registration; 0 before the first.
    generation: u64,
    state: SlotState<K>,
}

/// What a sole-reference post did to the region table
/// ([`RegionTable::post`]).
#[derive(Debug, PartialEq, Eq)]
pub enum Post<K>
{
    /// The region was live: its client holds no liveness cap any more. The
    /// slot is free; the caller unregisters the returned region.
    Ended(Region, K),
    /// The region's client had unregistered it; the slot is free.
    Retired,
    /// The post names no registration the table holds.
    Stale,
}

/// The driver's registered regions, in [`MAX_REGIONS`] slots.
///
/// A registration is admitted ([`RegionTable::admit`]) and then inserted
/// once the driver has mapped the region and made its capabilities
/// ([`RegionTable::insert`]). A region leaves the table by its client's
/// unregistration ([`RegionTable::remove`]), after which its slot retires
/// until its sole-reference post, or by that post while it is live, the end
/// of its client's lease ([`RegionTable::post`]). Each slot therefore has
/// at most one binding awaiting its post, so one observer node per slot
/// covers every binding. Only the service loop's thread touches the table.
pub struct RegionTable<K>
{
    slots: [Slot<K>; MAX_REGIONS],
}

impl<K> Default for RegionTable<K>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<K> RegionTable<K>
{
    /// An empty table: every slot free, before its first registration.
    #[must_use]
    pub fn new() -> Self
    {
        Self {
            slots: core::array::from_fn(|_| Slot {
                generation: 0,
                state: SlotState::Free,
            }),
        }
    }

    /// The identifier a registration for `partition` would take: a free
    /// slot, at its next generation. `None` when `partition` already holds
    /// [`MAX_REGIONS_PER_PARTITION`] live regions or no slot is free (a
    /// retiring slot is not). Changes nothing; [`RegionTable::insert`]
    /// takes the slot.
    #[must_use]
    pub fn admit(&self, partition: u64) -> Option<RegionId>
    {
        if self.live_of(partition) >= MAX_REGIONS_PER_PARTITION
        {
            return None;
        }
        let (slot, free) = self
            .slots
            .iter()
            .enumerate()
            .find(|(_, s)| matches!(s.state, SlotState::Free))?;
        // At most 2^54 - 1 registrations of one slot before it reuses a
        // generation; at one registration a microsecond that is over 500
        // years.
        let next = free.generation.wrapping_add(1) & GENERATION_MASK;
        Some(RegionId {
            slot,
            generation: next.max(1),
        })
    }

    /// Make `region` live in the slot `id` names, at `id`'s generation,
    /// keeping `kept` with it. `id` is one [`RegionTable::admit`] returned
    /// with no change to the table since; `Err` hands `kept` back when the
    /// slot is not free.
    ///
    /// # Errors
    /// `kept`, when the slot `id` names is not free.
    pub fn insert(&mut self, id: RegionId, region: Region, kept: K) -> Result<(), K>
    {
        let Some(slot) = self.slots.get_mut(id.slot)
        else
        {
            return Err(kept);
        };
        if !matches!(slot.state, SlotState::Free)
        {
            return Err(kept);
        }
        slot.generation = id.generation;
        slot.state = SlotState::Live { region, kept };
        Ok(())
    }

    /// The live region `id` names, or `None` for an unregistered region or
    /// an earlier generation of its slot.
    #[must_use]
    pub fn get(&self, id: RegionId) -> Option<&Region>
    {
        let slot = self.slots.get(id.slot)?;
        match &slot.state
        {
            SlotState::Live { region, .. } if slot.generation == id.generation => Some(region),
            SlotState::Live { .. } | SlotState::Free | SlotState::Retiring => None,
        }
    }

    /// What was kept with the live region `id` names, or `None` for an
    /// unregistered region or an earlier generation of its slot.
    #[must_use]
    pub fn kept(&self, id: RegionId) -> Option<&K>
    {
        let slot = self.slots.get(id.slot)?;
        match &slot.state
        {
            SlotState::Live { kept, .. } if slot.generation == id.generation => Some(kept),
            SlotState::Live { .. } | SlotState::Free | SlotState::Retiring => None,
        }
    }

    /// Unregister one live region registered for `partition`, as
    /// [`RegionTable::remove`] does: its slot retires until its
    /// sole-reference post. Returns the region and what was kept with it, or
    /// `None` once `partition` holds no live region; [`Grants::retire`]
    /// calls it until `None`.
    pub fn remove_one_of(&mut self, partition: u64) -> Option<(Region, K)>
    {
        let slot = self.slots.iter_mut().find(
            |s| matches!(&s.state, SlotState::Live { region, .. } if region.partition == partition),
        )?;
        match core::mem::replace(&mut slot.state, SlotState::Retiring)
        {
            SlotState::Live { region, kept } => Some((region, kept)),
            // Found Live just above, with `&mut` held throughout.
            SlotState::Free | SlotState::Retiring => None,
        }
    }

    /// Live regions registered for `partition`.
    #[must_use]
    pub fn live_of(&self, partition: u64) -> usize
    {
        self.slots
            .iter()
            .filter(|s| matches!(&s.state, SlotState::Live { region, .. } if region.partition == partition))
            .count()
    }

    /// Unregister the live region `id` names, returning it and what was kept
    /// with it; its slot retires until its sole-reference post. `None` when
    /// `id` names no live region.
    pub fn remove(&mut self, id: RegionId) -> Option<(Region, K)>
    {
        let slot = self.slots.get_mut(id.slot)?;
        if slot.generation != id.generation || !matches!(slot.state, SlotState::Live { .. })
        {
            return None;
        }
        match core::mem::replace(&mut slot.state, SlotState::Retiring)
        {
            SlotState::Live { region, kept } => Some((region, kept)),
            // Matched as Live just above, with `&mut` held throughout.
            SlotState::Free | SlotState::Retiring => None,
        }
    }

    /// Apply a sole-reference post carrying `correlator`: end the live
    /// region it names, or free the retiring slot it names. Every other
    /// value is [`Post::Stale`] and changes nothing.
    pub fn post(&mut self, correlator: u64) -> Post<K>
    {
        let Some(id) = RegionId::from_correlator(correlator)
        else
        {
            return Post::Stale;
        };
        let Some(slot) = self.slots.get_mut(id.slot)
        else
        {
            return Post::Stale;
        };
        if slot.generation != id.generation || matches!(slot.state, SlotState::Free)
        {
            return Post::Stale;
        }
        match core::mem::replace(&mut slot.state, SlotState::Free)
        {
            SlotState::Live { region, kept } => Post::Ended(region, kept),
            SlotState::Retiring | SlotState::Free => Post::Retired,
        }
    }
}

// ── Grants: partition badges and their regions ─────────────────────────────

/// What a request's badge reaches, as [`Grants::scope`] resolves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope
{
    /// A whole-disk cap: the whole device.
    WholeDisk,
    /// A registered partition grant: its range.
    Partition(PartitionBound),
}

/// Why [`Grants::admit_region`] refused a registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionRefusal
{
    /// The badge reaches nothing: unbadged, a region's or the sweeper's, or
    /// a partition badge never minted or retired (`blk_errors::OUT_OF_BOUNDS`).
    NoScope,
    /// The badge's regions or the driver's slots are at their bound
    /// (`blk_errors::REGION_LIMIT`).
    Limit,
}

/// The driver's grants: the partition badges it minted
/// ([`PartitionTable`]) and the regions registered through them and through
/// whole-disk badges ([`RegionTable`]), with the decisions the service loop
/// makes on them (README § Grants and regions).
///
/// A partition badge is registered or retired, and a retired badge never
/// returns: [`Grants::register_partition`] mints a fresh one for every
/// grant. A region belongs to the one badge it was registered through and
/// cannot outlive it. The invariants, which the host tests drive in every
/// order of a retire against requests sent before it:
///
/// - no request carrying a retired badge is served, whenever it was sent:
///   [`Grants::scope`] and [`Grants::admit_region`] refuse it, and a
///   region transfer is served only while its region is live and its badge
///   still scopes ([`Grants::region`]);
/// - a retire leaves no live region of the badge: each is handed to the
///   caller to unmap and release, and its slot retires until the
///   sole-reference post its release owes, naming no badge meanwhile;
/// - no badge is minted twice: a retired badge never names a grant again,
///   and a range registered again takes a new badge.
pub struct Grants<K>
{
    partitions: PartitionTable,
    regions: RegionTable<K>,
}

impl<K> Default for Grants<K>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<K> Grants<K>
{
    /// No grant and no region.
    #[must_use]
    pub fn new() -> Self
    {
        Self {
            partitions: PartitionTable::new(),
            regions: RegionTable::new(),
        }
    }

    /// `REGISTER_PARTITION`: grant `[base_lba, base_lba + length_lba)` under
    /// a fresh badge ([`PartitionTable::register`]).
    pub fn register_partition(&mut self, base_lba: u64, length_lba: u64) -> Option<u64>
    {
        self.partitions.register(base_lba, length_lba)
    }

    /// What a request carrying `badge` reaches; `None` for every badge
    /// that reaches nothing, a retired partition badge among them.
    #[must_use]
    pub fn scope(&self, badge: u64) -> Option<Scope>
    {
        match Caller::of(badge)
        {
            Caller::WholeDisk(_) => Some(Scope::WholeDisk),
            Caller::Partition(badge) => self.partitions.lookup(badge).map(Scope::Partition),
            Caller::Unbadged | Caller::Region(_) | Caller::Sweeper | Caller::Unknown => None,
        }
    }

    /// Retire the partition grant `badge` names: remove the badge, so no
    /// later request carrying it is served, and end every live region
    /// registered through it, each handed to `release` to unmap and to
    /// release its capabilities. `false`, changing nothing, when `badge`
    /// is no live partition badge (a whole-disk badge, a retired one).
    pub fn retire(&mut self, badge: u64, mut release: impl FnMut(Region, K)) -> bool
    {
        if !matches!(Caller::of(badge), Caller::Partition(_)) || !self.partitions.remove(badge)
        {
            return false;
        }
        while let Some((region, kept)) = self.regions.remove_one_of(badge)
        {
            release(region, kept);
        }
        true
    }

    /// The identifier a region registered through `badge` would take, and
    /// the badge it counts against.
    ///
    /// # Errors
    /// [`RegionRefusal`]: the badge reaches nothing, or its bound or the
    /// driver's is reached.
    pub fn admit_region(&self, badge: u64) -> Result<RegionId, RegionRefusal>
    {
        self.scope(badge).ok_or(RegionRefusal::NoScope)?;
        self.regions.admit(badge).ok_or(RegionRefusal::Limit)
    }

    /// Make `region` live under `id` ([`RegionTable::insert`]), `id` one
    /// [`Grants::admit_region`] returned with no change since.
    ///
    /// # Errors
    /// `kept`, when the slot is not free.
    pub fn insert_region(&mut self, id: RegionId, region: Region, kept: K) -> Result<(), K>
    {
        self.regions.insert(id, region, kept)
    }

    /// The live region `id` names and what was kept with it, while the badge
    /// it was registered through still scopes; `None` otherwise.
    #[must_use]
    pub fn region(&self, id: RegionId) -> Option<(&Region, &K)>
    {
        let region = self.regions.get(id)?;
        self.scope(region.partition)?;
        Some((region, self.regions.kept(id)?))
    }

    /// Unregister the live region `id` names ([`RegionTable::remove`]).
    pub fn remove_region(&mut self, id: RegionId) -> Option<(Region, K)>
    {
        self.regions.remove(id)
    }

    /// Apply a sole-reference post ([`RegionTable::post`]).
    pub fn post(&mut self, correlator: u64) -> Post<K>
    {
        self.regions.post(correlator)
    }

    /// Live regions registered through `badge`.
    #[must_use]
    pub fn regions_of(&self, badge: u64) -> usize
    {
        self.regions.live_of(badge)
    }
}

/// How a submitted block request ended, as the driver observed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoOutcome
{
    /// The device completed the request and wrote `status` into the
    /// status byte.
    Completed
    {
        /// The status byte the device wrote.
        status: u8,
    },
    /// The descriptor chain could not be queued; the device never saw the
    /// request.
    NotQueued,
    /// The device did not complete the request within the timeout, or
    /// published a completion the virtqueue refused or that names another
    /// chain. The request may still be in flight, so the device may still
    /// access the request's data buffer.
    Lost,
}

impl IoOutcome
{
    /// The reply label for this outcome.
    ///
    /// A completion maps its status byte explicitly: `VIRTIO_BLK_S_OK` to
    /// `SUCCESS`, `VIRTIO_BLK_S_IOERR` to `DEVICE_STATUS_IOERR`,
    /// `VIRTIO_BLK_S_UNSUPP` to `DEVICE_STATUS_UNSUPP`. Every other outcome,
    /// a status byte outside the spec's set included, is `DEVICE_FAULT`; the
    /// raw byte is never forwarded, so it cannot alias another code.
    #[must_use]
    pub fn reply_label(self) -> u64
    {
        match self
        {
            IoOutcome::Completed {
                status: VIRTIO_BLK_S_OK,
            } => blk_errors::SUCCESS,
            IoOutcome::Completed {
                status: VIRTIO_BLK_S_IOERR,
            } => blk_errors::DEVICE_STATUS_IOERR,
            IoOutcome::Completed {
                status: VIRTIO_BLK_S_UNSUPP,
            } => blk_errors::DEVICE_STATUS_UNSUPP,
            IoOutcome::Completed { .. } | IoOutcome::NotQueued | IoOutcome::Lost =>
            {
                blk_errors::DEVICE_FAULT
            }
        }
    }
}

/// A request that takes this long or longer, from the start of its data
/// segment's map for the device to the end of its unmap, is logged with
/// where the time went ([`RequestTiming`]).
///
/// A fifth of vfsd's `FS_UNMOUNT_TIMEOUT_MS` (5 s,
/// `services/vfsd/src/main.rs`), the tightest bound a client puts on a call
/// that waits on a filesystem driver and so on this driver: a filesystem
/// request makes several block calls, so one block request this slow already
/// spends a fifth of that bound. A request takes milliseconds otherwise, so
/// the line is quiet unless a layer of the request path stalls. A diagnostic
/// bound that bounds no capacity: it decides only which requests are logged.
pub const SLOW_REQUEST: Duration = Duration::from_secs(1);

/// What ended the last completion wait before the poll that found a
/// request's completion, or before the request's bound ran out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionWake
{
    /// No wait: the first poll after the submission found the completion.
    FirstPoll,
    /// The completion notification was signalled: the interrupt-service
    /// thread relayed an interrupt.
    Interrupt,
    /// The wait ran to its bound with no signal.
    WaitEnd,
    /// The wait failed on the cap path.
    WaitFailed,
}

impl fmt::Display for CompletionWake
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(match self
        {
            CompletionWake::FirstPoll => "the first poll",
            CompletionWake::Interrupt => "interrupt",
            CompletionWake::WaitEnd => "the wait's end",
            CompletionWake::WaitFailed => "a failed wait",
        })
    }
}

/// The completion waits of one request: how many it made, and what ended
/// the last of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitTrace
{
    /// Completion waits made.
    pub waits: u32,
    /// What ended the last one ([`CompletionWake::FirstPoll`] before any).
    pub last: CompletionWake,
}

impl Default for WaitTrace
{
    fn default() -> Self
    {
        Self {
            waits: 0,
            last: CompletionWake::FirstPoll,
        }
    }
}

impl WaitTrace
{
    /// Record one completion wait's result as `SYS_NOTIFICATION_WAIT` with a
    /// timeout returns it: `Ok(0)` when the bound passed (a send carries at
    /// least one bit), `Ok(bits)` when the notification was signalled, `Err`
    /// when the wait failed.
    pub fn record(&mut self, result: Result<u64, i64>)
    {
        self.waits = self.waits.saturating_add(1);
        self.last = match result
        {
            Ok(0) => CompletionWake::WaitEnd,
            Ok(_) => CompletionWake::Interrupt,
            Err(_) => CompletionWake::WaitFailed,
        };
    }
}

/// Where one request's time went: the map of its data segment for the
/// device, the device's work from the submission to the completion (or to
/// the bound, for a lost request), and the unmap. A lost request's device
/// reset falls between the device wait and the unmap and is in none of them;
/// it logs its own line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestTiming
{
    /// The `DMA_MAP` call on devmgr's DMA thread.
    pub map: Duration,
    /// From the submission to the poll that ended the request.
    pub device: Duration,
    /// The `DMA_UNMAP` call on devmgr's DMA thread.
    pub unmap: Duration,
    /// The completion waits made during `device`.
    pub waits: WaitTrace,
}

impl RequestTiming
{
    /// The request's time: its map, its device wait and its unmap.
    #[must_use]
    pub fn total(&self) -> Duration
    {
        self.map
            .saturating_add(self.device)
            .saturating_add(self.unmap)
    }

    /// Whether the request took [`SLOW_REQUEST`] or longer, and is logged.
    #[must_use]
    pub fn is_slow(&self) -> bool
    {
        self.total() >= SLOW_REQUEST
    }
}

impl fmt::Display for RequestTiming
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(
            f,
            "{} ms: map {} ms, device {} ms (completion by {}, wait count {}), unmap {} ms",
            self.total().as_millis(),
            self.map.as_millis(),
            self.device.as_millis(),
            self.waits.last,
            self.waits.waits,
            self.unmap.as_millis(),
        )
    }
}

/// How long, in milliseconds, a request's completion is waited for once
/// `elapsed` of its `timeout` has passed: what is left of it, rounded up, so
/// the wait never ends before the bound. Never 0, which waits with no bound,
/// nor `u64::MAX`, which only tries once (`SYS_NOTIFICATION_WAIT`'s
/// sentinels). `None` once the bound has passed.
#[must_use]
pub fn completion_wait_ms(
    timeout: core::time::Duration,
    elapsed: core::time::Duration,
) -> Option<u64>
{
    let left = timeout.checked_sub(elapsed).filter(|d| !d.is_zero())?;
    let ms = left.as_nanos().div_ceil(1_000_000);
    Some(u64::try_from(ms).unwrap_or(u64::MAX).clamp(1, u64::MAX - 1))
}

#[cfg(test)]
mod tests
{
    #[test]
    fn a_wait_trace_names_what_ended_the_last_wait_and_counts_the_waits()
    {
        let mut trace = WaitTrace::default();
        assert_eq!(trace.last, CompletionWake::FirstPoll);
        trace.record(Ok(0));
        assert_eq!((trace.waits, trace.last), (1, CompletionWake::WaitEnd));
        trace.record(Ok(1));
        assert_eq!((trace.waits, trace.last), (2, CompletionWake::Interrupt));
        trace.record(Err(-3));
        assert_eq!((trace.waits, trace.last), (3, CompletionWake::WaitFailed));
    }

    #[test]
    fn a_request_is_slow_once_its_map_device_and_unmap_reach_the_bound()
    {
        use core::time::Duration;
        let timing = |unmap| RequestTiming {
            map: Duration::from_millis(300),
            device: Duration::from_millis(300),
            unmap,
            waits: WaitTrace::default(),
        };
        // Each part alone is under the bound; their sum decides.
        assert!(!timing(Duration::from_micros(399_999)).is_slow());
        assert!(timing(Duration::from_millis(400)).is_slow());
    }

    #[test]
    fn a_completion_wait_lasts_what_is_left_of_the_bound()
    {
        use core::time::Duration;
        let bound = Duration::from_secs(50);
        assert_eq!(completion_wait_ms(bound, Duration::ZERO), Some(50_000));
        assert_eq!(
            completion_wait_ms(bound, Duration::from_millis(49_990)),
            Some(10)
        );
        // A partial millisecond rounds up, so the wait reaches the bound.
        assert_eq!(
            completion_wait_ms(bound, Duration::from_micros(49_999_500)),
            Some(1)
        );
        assert_eq!(completion_wait_ms(bound, bound), None);
        assert_eq!(completion_wait_ms(bound, Duration::from_secs(60)), None);
    }

    use super::*;

    fn geometry(block_size: u32) -> Geometry
    {
        Geometry::new(1 << 20, Some(block_size)).expect("supported block size")
    }

    #[test]
    fn transfer_len_rejects_zero_overflowing_and_oversized_counts()
    {
        let g = geometry(512);
        assert_eq!(g.transfer_len(0), None);
        // 2^55 * 512 overflows u64: a bare multiply aborts the driver in a
        // dev build and wraps to 0 in release.
        assert_eq!(g.transfer_len(1 << 55), None);
        assert_eq!(g.transfer_len(u64::MAX), None);
        // One block past the u32 descriptor-length bound.
        assert_eq!(g.transfer_len(u64::from(u32::MAX) / 512 + 1), None);
    }

    #[test]
    fn transfer_len_counts_logical_blocks_up_to_the_descriptor_bound()
    {
        assert_eq!(geometry(512).transfer_len(1), Some(512));
        let g = geometry(4096);
        assert_eq!(g.transfer_len(1), Some(4096));
        let max = u64::from(u32::MAX) / 4096;
        assert_eq!(g.transfer_len(max).map(u64::from), Some(max * 4096));
        assert_eq!(g.transfer_len(max + 1), None);
    }

    #[test]
    fn geometry_without_the_feature_is_512_byte_blocks_over_the_sector_capacity()
    {
        let g = Geometry::new(1000, None).expect("default block size");
        assert_eq!((g.block_size, g.capacity), (512, 1000));
        assert_eq!(g.device_sector(7), Some(7));
    }

    #[test]
    fn geometry_of_a_4kn_device_counts_and_addresses_4096_byte_blocks()
    {
        // 1001 sectors hold 125 whole 4 KiB blocks; the partial tail block
        // is not addressable.
        let g = Geometry::new(1001, Some(4096)).expect("4Kn");
        assert_eq!((g.block_size, g.capacity), (4096, 125));
        // LBA 1, where a GPT header sits, is VirtIO sector 8.
        assert_eq!(g.device_sector(1), Some(8));
        // An LBA whose sector would wrap past u64 has none.
        assert_eq!(g.device_sector(u64::MAX / 8 + 1), None);
        assert_eq!(g.device_sector(u64::MAX / 8), Some(u64::MAX / 8 * 8));
    }

    #[test]
    fn geometry_refuses_block_sizes_the_driver_cannot_serve()
    {
        for bad in [0, 256, 1536, 8192]
        {
            assert_eq!(Geometry::new(1000, Some(bad)), None, "block size {bad}");
        }
    }

    // Defect caught: a second grant of a range sharing the first's badge, so
    // retiring one grant would cut off the other, or a retired badge minted
    // again for a later grant, reaching its holder's late requests.
    #[test]
    fn every_registration_is_a_fresh_badge_and_a_removed_one_names_nothing()
    {
        let mut t = PartitionTable::new();
        let a = t.register(2048, 100).expect("fresh range");
        let b = t.register(2048, 100).expect("the same range again");
        assert_ne!(a, b);
        assert_eq!(t.entries.len(), 2);
        assert_eq!(
            t.lookup(a),
            Some(PartitionBound {
                badge: a,
                base_lba: 2048,
                length_lba: 100
            })
        );
        assert!(t.remove(a));
        assert!(!t.remove(a));
        assert_eq!(t.lookup(a), None);
        assert!(t.lookup(b).is_some());
        let c = t.register(2048, 100).expect("the range after its retire");
        assert!(c != a && c != b);
        assert_eq!(t.entries.len(), 2);
    }

    #[test]
    fn partition_table_refuses_empty_ranges_and_never_names_badge_zero()
    {
        let mut t = PartitionTable::new();
        assert_eq!(t.register(10, 0), None);
        assert_eq!(t.lookup(0), None);
        let a = t.register(10, 1).expect("fresh range");
        assert_ne!(a, 0);
        assert_eq!(t.lookup(a + 1), None);
    }

    #[test]
    fn partition_badges_stop_short_of_the_region_and_mount_authority_bits()
    {
        let mut t = PartitionTable::new();
        t.next_badge = REGION_BADGE - 1;
        let last = t.register(0, 1).expect("last fresh badge");
        assert_eq!(last & (ipc::blk_labels::MOUNT_AUTHORITY | REGION_BADGE), 0);
        assert_eq!(Caller::of(last), Caller::Partition(last));
        assert_eq!(t.register(1, 1), None);
        assert_eq!(t.register(0, 1), None);
        assert!(t.lookup(last).is_some());
    }

    #[test]
    fn reply_label_maps_spec_status_bytes_to_their_blk_errors()
    {
        let completed = |status| IoOutcome::Completed { status }.reply_label();
        assert_eq!(completed(VIRTIO_BLK_S_OK), blk_errors::SUCCESS);
        assert_eq!(
            completed(VIRTIO_BLK_S_IOERR),
            blk_errors::DEVICE_STATUS_IOERR
        );
        assert_eq!(
            completed(VIRTIO_BLK_S_UNSUPP),
            blk_errors::DEVICE_STATUS_UNSUPP
        );
    }

    #[test]
    fn reply_label_is_device_fault_for_every_other_outcome()
    {
        // 0xFF is the driver's not-completed sentinel: forwarded raw it read
        // as UNKNOWN_OPCODE.
        for outcome in [
            IoOutcome::Completed { status: 0xFF },
            IoOutcome::Completed { status: 3 },
            IoOutcome::NotQueued,
            IoOutcome::Lost,
        ]
        {
            assert_eq!(outcome.reply_label(), blk_errors::DEVICE_FAULT);
        }
    }

    fn region(partition: u64) -> Region
    {
        Region {
            partition,
            device_addr: 0x10_0000,
            len: 0x1_0000,
            access: RegionAccess::DeviceReadsWrites,
        }
    }

    #[test]
    fn a_region_badge_and_its_correlator_round_trip_and_name_one_registration()
    {
        let id = RegionId {
            slot: 5,
            generation: 7,
        };
        assert_eq!(id.badge() & !REGION_BADGE, id.correlator());
        assert_eq!(Caller::of(id.badge()), Caller::Region(id));
        assert_eq!(RegionId::from_correlator(id.correlator()), Some(id));
        // The same slot at another generation is another registration.
        let next = RegionId {
            slot: 5,
            generation: 8,
        };
        assert_ne!(id.badge(), next.badge());
        // The largest generation still decodes.
        let last = RegionId {
            slot: MAX_REGIONS - 1,
            generation: GENERATION_MASK,
        };
        assert_eq!(Caller::of(last.badge()), Caller::Region(last));
    }

    #[test]
    fn a_correlator_no_registration_produces_names_no_region()
    {
        // Generation 0, a slot past the table, and the sweeper's slot.
        assert_eq!(RegionId::from_correlator(3), None);
        assert_eq!(
            RegionId::from_correlator((1 << SLOT_BITS) | MAX_REGIONS as u64),
            None
        );
        assert_eq!(
            RegionId::from_correlator((1 << SLOT_BITS) | SWEEPER_SLOT),
            None
        );
        assert_eq!(Caller::of(REGION_BADGE | 3), Caller::Unknown);
    }

    #[test]
    fn a_badge_classifies_by_its_high_bits()
    {
        let whole = ipc::blk_labels::MOUNT_AUTHORITY;
        assert_eq!(Caller::of(0), Caller::Unbadged);
        assert_eq!(Caller::of(whole), Caller::WholeDisk(whole));
        assert_eq!(Caller::of(1), Caller::Partition(1));
        assert_eq!(Caller::of(SWEEPER_BADGE), Caller::Sweeper);
        // MOUNT_AUTHORITY decides, whatever else is set.
        assert_eq!(
            Caller::of(whole | REGION_BADGE | 1),
            Caller::WholeDisk(whole | REGION_BADGE | 1)
        );
    }

    #[test]
    fn region_access_reads_only_the_two_wire_values()
    {
        assert_eq!(RegionAccess::from_wire(1), Some(RegionAccess::DeviceReads));
        assert_eq!(
            RegionAccess::from_wire(3),
            Some(RegionAccess::DeviceReadsWrites)
        );
        for word in [0, 2, 4, u64::MAX]
        {
            assert_eq!(RegionAccess::from_wire(word), None);
        }
        assert!(!RegionAccess::DeviceReads.device_writes());
        assert!(RegionAccess::DeviceReadsWrites.device_writes());
    }

    #[test]
    fn a_region_transfer_lies_within_the_region_at_a_block_multiple_offset()
    {
        let g = Geometry {
            block_size: 512,
            capacity: 1 << 20,
        };
        let r = region(1);
        assert_eq!(r.span(g, 0, 1), Some((0x10_0000, 512)));
        assert_eq!(r.span(g, 0x200, 2), Some((0x10_0200, 1024)));
        // The last block, and a run that ends exactly at the region's end.
        assert_eq!(r.span(g, 0xFE00, 1), Some((0x10_FE00, 512)));
        assert_eq!(r.span(g, 0, 128), Some((0x10_0000, 0x1_0000)));
        // Past the end, by one block or by an offset at the end.
        assert_eq!(r.span(g, 0xFE00, 2), None);
        assert_eq!(r.span(g, 0x1_0000, 1), None);
        // A misaligned offset, an empty count, and an overflowing offset.
        assert_eq!(r.span(g, 0x100, 1), None);
        assert_eq!(r.span(g, 0, 0), None);
        assert_eq!(r.span(g, u64::MAX - 511, 1), None);
        // A 4096-byte block size measures offsets in its own blocks.
        let g4 = Geometry {
            block_size: 4096,
            capacity: 1 << 20,
        };
        assert_eq!(r.span(g4, 0x200, 1), None);
        assert_eq!(r.span(g4, 0xF000, 1), Some((0x10_F000, 4096)));
    }

    #[test]
    fn a_partition_holds_at_most_its_bound_of_live_regions()
    {
        let mut t: RegionTable<u32> = RegionTable::new();
        for n in 0..MAX_REGIONS_PER_PARTITION
        {
            let id = t.admit(1).expect("under the partition's bound");
            t.insert(id, region(1), u32::try_from(n).unwrap())
                .expect("free slot");
        }
        assert_eq!(t.admit(1), None);
        // Another partition, and the whole-disk badge, each count alone.
        assert!(t.admit(2).is_some());
        assert!(t.admit(ipc::blk_labels::MOUNT_AUTHORITY).is_some());
        // Unregistering one frees room for the partition, though its slot
        // retires.
        let first = RegionId {
            slot: 0,
            generation: 1,
        };
        assert_eq!(t.remove(first), Some((region(1), 0)));
        let id = t.admit(1).expect("room after an unregistration");
        assert_ne!(id.slot, 0, "a retiring slot is not reused");
    }

    #[test]
    fn the_table_holds_at_most_max_regions_live_or_retiring()
    {
        let mut t: RegionTable<()> = RegionTable::new();
        let mut ids = [None; MAX_REGIONS];
        for (n, slot) in ids.iter_mut().enumerate()
        {
            let partition = (n / MAX_REGIONS_PER_PARTITION) as u64 + 1;
            let id = t.admit(partition).expect("a free slot");
            t.insert(id, region(partition), ()).expect("free slot");
            *slot = Some(id);
        }
        assert_eq!(t.admit(1000), None);
        // A retiring slot still holds its observer node.
        let id = ids[3].unwrap();
        assert!(t.remove(id).is_some());
        assert_eq!(t.admit(1000), None);
        // Its post frees it.
        assert_eq!(t.post(id.correlator()), Post::Retired);
        assert_eq!(t.admit(1000).map(|n| n.slot), Some(3));
    }

    #[test]
    fn a_reused_slot_takes_a_new_generation_and_the_old_identifier_names_nothing()
    {
        let mut t: RegionTable<u8> = RegionTable::new();
        let old = t.admit(1).unwrap();
        t.insert(old, region(1), 1).unwrap();
        assert!(t.get(old).is_some());
        assert!(t.remove(old).is_some());
        assert_eq!(t.get(old), None, "unregistered");
        assert_eq!(t.remove(old), None, "a second unregistration finds nothing");
        assert_eq!(t.post(old.correlator()), Post::Retired);
        let new = t.admit(1).unwrap();
        assert_eq!((new.slot, new.generation), (old.slot, old.generation + 1));
        t.insert(new, region(1), 2).unwrap();
        assert_eq!(t.get(old), None);
        assert_eq!(t.remove(old), None);
        assert_eq!(t.post(old.correlator()), Post::Stale);
        assert_eq!(t.get(new), Some(&region(1)));
    }

    #[test]
    fn a_post_for_a_live_region_ends_it_and_frees_its_slot()
    {
        let mut t: RegionTable<u8> = RegionTable::new();
        let id = t.admit(9).unwrap();
        t.insert(id, region(9), 4).unwrap();
        assert_eq!(t.post(id.correlator()), Post::Ended(region(9), 4));
        assert_eq!(t.get(id), None);
        // The slot is free at once: an ended region's binding posts no more.
        assert_eq!(t.admit(9).map(|n| n.slot), Some(id.slot));
        assert_eq!(t.post(id.correlator()), Post::Stale);
    }

    #[test]
    fn a_post_that_names_no_registration_changes_nothing()
    {
        let mut t: RegionTable<u8> = RegionTable::new();
        let id = t.admit(1).unwrap();
        // The slot is free: no binding of it is pending.
        assert_eq!(t.post(id.correlator()), Post::Stale);
        t.insert(id, region(1), 0).unwrap();
        for c in [
            0,
            3,
            (2 << SLOT_BITS) | id.slot as u64,
            (1 << SLOT_BITS) | SWEEPER_SLOT,
        ]
        {
            assert_eq!(t.post(c), Post::Stale);
        }
        assert!(t.get(id).is_some());
    }

    #[test]
    fn insert_refuses_a_slot_that_is_not_free()
    {
        let mut t: RegionTable<u8> = RegionTable::new();
        let id = t.admit(1).unwrap();
        t.insert(id, region(1), 1).unwrap();
        assert_eq!(t.insert(id, region(1), 2), Err(2));
        let past = RegionId {
            slot: MAX_REGIONS,
            generation: 1,
        };
        assert_eq!(t.insert(past, region(1), 3), Err(3));
    }

    #[test]
    fn generations_wrap_past_zero()
    {
        let mut t: RegionTable<()> = RegionTable::new();
        t.slots[0].generation = GENERATION_MASK;
        let id = t.admit(1).unwrap();
        assert_eq!((id.slot, id.generation), (0, 1));
    }

    #[test]
    fn kept_names_only_the_live_registration()
    {
        let mut t: RegionTable<u8> = RegionTable::new();
        let id = t.admit(3).unwrap();
        assert_eq!(t.kept(id), None);
        t.insert(id, region(3), 7).unwrap();
        assert_eq!(t.kept(id), Some(&7));
        assert_eq!(
            t.kept(RegionId {
                generation: id.generation + 1,
                ..id
            }),
            None
        );
        t.remove(id).unwrap();
        assert_eq!(t.kept(id), None);
    }

    /// Register a region through `badge` in `g`, keeping `kept` with it.
    fn grant_region(g: &mut Grants<u8>, badge: u64, kept: u8) -> RegionId
    {
        let id = g.admit_region(badge).expect("region admitted");
        g.insert_region(id, region(badge), kept)
            .expect("admitted slot free");
        id
    }

    /// Retire `badge` in `g`, returning what was kept with each region it
    /// ended, sorted, or `None` when the retire was refused.
    fn retire(g: &mut Grants<u8>, badge: u64) -> Option<Vec<u8>>
    {
        let mut ended = Vec::new();
        let done = g.retire(badge, |r, kept| {
            assert_eq!(r.partition, badge, "a retire ended another badge's region");
            ended.push(kept);
        });
        ended.sort_unstable();
        done.then_some(ended)
    }

    // Defect caught: a partition grant revoked by its granter leaving the
    // revoked holder's regions live, or ending another grant's.
    #[test]
    fn a_retire_ends_every_region_of_its_badge_and_no_other()
    {
        let mut g: Grants<u8> = Grants::new();
        let a = g.register_partition(0, 64).unwrap();
        let b = g.register_partition(64, 64).unwrap();
        let disk = ipc::blk_labels::MOUNT_AUTHORITY | 1;
        let ids: Vec<RegionId> = [(1, a), (2, b), (3, a), (4, disk), (5, a)]
            .into_iter()
            .map(|(kept, badge)| grant_region(&mut g, badge, kept))
            .collect();
        assert_eq!(retire(&mut g, a), Some(vec![1, 3, 5]));
        assert_eq!(g.regions_of(a), 0);
        assert_eq!(g.region(ids[1]).map(|(_, k)| *k), Some(2));
        assert_eq!(g.region(ids[3]).map(|(_, k)| *k), Some(4));
        for &i in &[ids[0], ids[2], ids[4]]
        {
            assert!(g.region(i).is_none());
            // Retiring until the post its release owes, which frees the slot.
            assert_eq!(g.post(i.correlator()), Post::Retired);
            assert_eq!(g.post(i.correlator()), Post::Stale);
        }
        // A whole-disk badge, a retired one, and a region's are not retired.
        assert_eq!(retire(&mut g, disk), None);
        assert_eq!(retire(&mut g, a), None);
        assert_eq!(retire(&mut g, ids[1].badge()), None);
        assert_eq!(g.regions_of(disk), 1);
    }

    /// One request of a cut-off holder of a partition grant, sent before
    /// the granter's retire and served at any point around it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Late
    {
        /// `BLK_REGISTER_REGION` on the partition cap.
        Register,
        /// `BLK_READ_INTO_MEMORY` or another request scoped by the badge.
        Transfer,
        /// `BLK_READ_REGION` on a region registered before any of these.
        RegionTransfer,
        /// A second `BLK_RETIRE_PARTITION` on the badge.
        Retire,
    }

    /// Every ordering of `items`.
    fn orderings<T: Copy>(items: &[T]) -> Vec<Vec<T>>
    {
        if items.len() <= 1
        {
            return vec![items.to_vec()];
        }
        let mut out = Vec::new();
        for i in 0..items.len()
        {
            let mut rest = items.to_vec();
            let first = rest.remove(i);
            for mut tail in orderings(&rest)
            {
                tail.insert(0, first);
                out.push(tail);
            }
        }
        out
    }

    // Defect caught: a request the cut-off holder sent before the retire and
    // the driver served after it (a registration that resolved its cap
    // before the revoke and queued after the retire), leaving the holder a
    // region, a transfer, or an effect on the next grant of the range.
    #[test]
    fn no_request_carrying_a_retired_badge_is_served_in_any_order()
    {
        // `None` marks the granter's retire; the rest are the holder's.
        let mut events: Vec<Option<Late>> = vec![None];
        events.extend(
            [
                Late::Register,
                Late::Transfer,
                Late::RegionTransfer,
                Late::Retire,
            ]
            .map(Some),
        );
        for order in orderings(&events)
        {
            let mut g: Grants<u8> = Grants::new();
            let other = g.register_partition(0, 64).unwrap();
            let kept_other = grant_region(&mut g, other, 9);
            let badge = g.register_partition(0, 64).unwrap();
            let early = grant_region(&mut g, badge, 1);
            let mut retired = false;
            for event in &order
            {
                match event
                {
                    None =>
                    {
                        let ended = retire(&mut g, badge);
                        // A late retire that came first took the regions.
                        assert_eq!(ended.is_some(), !retired, "{order:?}");
                        retired = true;
                    }
                    Some(Late::Register) =>
                    {
                        let admitted = g.admit_region(badge);
                        assert_eq!(admitted.is_ok(), !retired, "{order:?}");
                        if let Ok(id) = admitted
                        {
                            g.insert_region(id, region(badge), 2).unwrap();
                        }
                    }
                    Some(Late::Transfer) =>
                    {
                        assert_eq!(g.scope(badge).is_some(), !retired, "{order:?}");
                    }
                    Some(Late::RegionTransfer) =>
                    {
                        assert_eq!(g.region(early).is_some(), !retired, "{order:?}");
                    }
                    Some(Late::Retire) =>
                    {
                        let ended = retire(&mut g, badge);
                        assert_eq!(ended.is_some(), !retired, "{order:?}");
                        retired = true;
                    }
                }
            }
            assert!(retired);
            assert_eq!(g.regions_of(badge), 0, "{order:?}");
            assert_eq!(g.scope(badge), None, "{order:?}");
            assert_eq!(
                g.admit_region(badge),
                Err(RegionRefusal::NoScope),
                "{order:?}"
            );
            // The other grant of the same range is untouched.
            assert_eq!(g.region(kept_other).map(|(_, k)| *k), Some(9));
            // The granter grants the range again under a new badge.
            let again = g.register_partition(0, 64).unwrap();
            assert!(again != badge && again != other, "{order:?}");
            grant_region(&mut g, again, 3);
            assert_eq!(g.scope(badge), None, "{order:?}");
        }
    }

    #[test]
    fn a_retired_badge_never_scopes_even_one_minted_past_it()
    {
        let mut g: Grants<u8> = Grants::new();
        let a = g.register_partition(0, 8).unwrap();
        assert!(retire(&mut g, a).is_some());
        for _ in 0..16
        {
            let b = g.register_partition(0, 8).unwrap();
            assert_ne!(b, a);
            assert_eq!(g.scope(a), None);
        }
        assert_eq!(g.scope(0), None);
        assert_eq!(
            g.scope(ipc::blk_labels::MOUNT_AUTHORITY | 7),
            Some(Scope::WholeDisk)
        );
    }
}
