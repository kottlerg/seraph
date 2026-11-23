// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/fat-parse/src/file_write.rs

//! The sector walk of a file write, gathered into runs of contiguous sectors.
//!
//! [`write_range`] writes a file's bytes from its old size, or from the
//! payload's offset when that is lower, to the payload's end: zeros up to the
//! offset, then the payload, each sector's share as [`sector_write`] gives
//! it. It composes each sector in a run buffer, reading first a sector that
//! holds old bytes of the file the share leaves, and hands the buffer to
//! [`SectorIo::write_run`] as one device write when the next sector does not
//! follow the run's last on the device (the end of an extent, at a cluster
//! boundary whose next cluster lies elsewhere) or the buffer is full, and at
//! the end of the write. Clusters at consecutive sectors join one run. Each
//! block request pays a fixed cost (the driver's DMA mapping through devmgr,
//! the interrupt, the IPC round trips) that a run pays once for its sectors.
//!
//! The chain walk, the allocation of a cluster at the chain's end, and the
//! device I/O stay with the caller, behind [`SectorIo`].

use crate::{file_position, sector_write};

/// The I/O and the chain walk a file write needs from the driver.
pub trait SectorIo
{
    /// The driver's error, which [`write_range`] returns as it is.
    type Error;

    /// The cluster after `cluster` in the file's chain; at the chain's end, a
    /// cluster newly allocated and linked after it.
    ///
    /// # Errors
    /// The driver's, for a chain it cannot read or a volume with no free
    /// cluster.
    fn next_cluster(&mut self, cluster: u32) -> Result<u32, Self::Error>;

    /// The first sector of data cluster `cluster`.
    fn cluster_sector(&self, cluster: u32) -> u64;

    /// Read sector `lba` into `buf`, which is one sector long.
    ///
    /// # Errors
    /// The driver's, for a failed read.
    fn read_sector(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Write `sectors`, whole sectors from `lba` on, in one device write.
    ///
    /// # Errors
    /// The driver's, for a write the device refused.
    fn write_run(&mut self, lba: u64, sectors: &[u8]) -> Result<(), Self::Error>;
}

/// The volume's cluster geometry, from its BPB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry
{
    pub sectors_per_cluster: u8,
    pub bytes_per_sector: u16,
}

/// One write of a file: `data` at byte `offset`, into a file that held
/// `old_size` bytes before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileWrite<'a>
{
    pub offset: u64,
    pub old_size: u64,
    pub data: &'a [u8],
}

/// Why [`write_range`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError<E>
{
    /// The geometry places no byte (a zero sector or cluster size), the run
    /// buffer holds no whole sector, or the write ends past `u64::MAX`; no
    /// I/O was made.
    Geometry,
    /// A [`SectorIo`] call failed with this error. The runs written before it
    /// stay written.
    Io(E),
}

/// Sectors composed in the run buffer and not yet written: `len` sectors from
/// `first` on.
#[derive(Clone, Copy, Default)]
struct PendingRun
{
    first: u64,
    len: usize,
}

impl PendingRun
{
    /// Whether sector `lba` can join the run, which holds at most `capacity`
    /// sectors: the run is empty, or it has room and `lba` follows its last
    /// sector on the device.
    fn takes(self, lba: u64, capacity: usize) -> bool
    {
        self.len == 0
            || (self.len < capacity
                && u64::try_from(self.len)
                    .ok()
                    .and_then(|len| self.first.checked_add(len))
                    == Some(lba))
    }
}

/// Write `write`, whose first byte written (the old size, or the offset when
/// lower) lies in `cluster`, through `io`, in runs of at most the whole
/// sectors `run` holds (module docs). A write of no bytes writes nothing.
///
/// The runs are written in file order, each through before the next sector
/// is composed past it, so the device holds the write once this returns
/// `Ok`.
///
/// # Errors
/// [`WriteError::Geometry`] before any I/O when the geometry or the run
/// buffer cannot hold a sector or the write's end overflows;
/// [`WriteError::Io`] with the first failed [`SectorIo`] call's error, which
/// ends the write there.
pub fn write_range<I: SectorIo>(
    io: &mut I,
    geometry: Geometry,
    cluster: u32,
    write: &FileWrite<'_>,
    run: &mut [u8],
) -> Result<(), WriteError<I::Error>>
{
    let bytes_per_sector = usize::from(geometry.bytes_per_sector);
    let capacity = run
        .len()
        .checked_div(bytes_per_sector)
        .filter(|&sectors| sectors > 0)
        .ok_or(WriteError::Geometry)?;
    let end = u64::try_from(write.data.len())
        .ok()
        .and_then(|len| write.offset.checked_add(len))
        .ok_or(WriteError::Geometry)?;
    if write.data.is_empty()
    {
        return Ok(());
    }
    let place = |at: u64| {
        file_position(at, geometry.sectors_per_cluster, geometry.bytes_per_sector)
            .ok_or(WriteError::Geometry)
    };
    let mut at = write.offset.min(write.old_size);
    let mut cluster = cluster;
    let mut cluster_index = place(at)?.cluster_index;
    let mut pending = PendingRun::default();
    let mut rest = write.data;
    while at < end
    {
        let pos = place(at)?;
        // The previous sector ended its cluster: move on to the next one.
        if pos.cluster_index != cluster_index
        {
            cluster = io.next_cluster(cluster).map_err(WriteError::Io)?;
            cluster_index = pos.cluster_index;
        }
        let lba = io
            .cluster_sector(cluster)
            .checked_add(u64::from(pos.sector_in_cluster))
            .ok_or(WriteError::Geometry)?;
        let share = sector_write(&pos, at, write.offset, end, write.old_size)
            .ok_or(WriteError::Geometry)?;
        if !pending.takes(lba, capacity)
        {
            flush(io, &mut pending, run, bytes_per_sector)?;
        }
        if pending.len == 0
        {
            pending.first = lba;
        }
        let sector = sector_slot(run, pending.len, bytes_per_sector).ok_or(WriteError::Geometry)?;
        // Read-modify-write the sector only when it holds old bytes of the
        // file the share leaves; any other sector is written from zeros.
        if share.read_first
        {
            io.read_sector(lba, sector).map_err(WriteError::Io)?;
        }
        else
        {
            sector.fill(0);
        }
        // The share ends at or before the sector's end.
        let (gap, payload) = sector
            .get_mut(pos.offset_in_sector..)
            .and_then(|dst| dst.split_at_mut_checked(share.zeros))
            .ok_or(WriteError::Geometry)?;
        gap.fill(0);
        let (chunk, tail) = rest.split_at_checked(share.data).unwrap_or((rest, &[]));
        for (d, &b) in payload.iter_mut().zip(chunk)
        {
            *d = b;
        }
        rest = tail;
        // Below `capacity`, a `usize`: `takes` admitted the sector.
        pending.len = pending.len.saturating_add(1);
        // The share is at most the sector's bytes left and ends at or before
        // `end`, so neither step saturates, and each moves `at` forward.
        at = at
            .saturating_add(share.zeros as u64)
            .saturating_add(share.data as u64);
    }
    flush(io, &mut pending, run, bytes_per_sector)
}

/// Sector `index` of the run buffer `run`, of `bytes_per_sector` bytes;
/// `None` past the buffer.
fn sector_slot(run: &mut [u8], index: usize, bytes_per_sector: usize) -> Option<&mut [u8]>
{
    let start = index.checked_mul(bytes_per_sector)?;
    run.get_mut(start..start.checked_add(bytes_per_sector)?)
}

/// Write the pending run, if it holds a sector, and empty it.
fn flush<I: SectorIo>(
    io: &mut I,
    pending: &mut PendingRun,
    run: &[u8],
    bytes_per_sector: usize,
) -> Result<(), WriteError<I::Error>>
{
    if pending.len == 0
    {
        return Ok(());
    }
    let sectors = pending
        .len
        .checked_mul(bytes_per_sector)
        .and_then(|bytes| run.get(..bytes))
        .ok_or(WriteError::Geometry)?;
    io.write_run(pending.first, sectors)
        .map_err(WriteError::Io)?;
    pending.len = 0;
    Ok(())
}

#[cfg(test)]
mod tests
{
    use std::collections::BTreeMap;

    use super::*;

    /// First sector of cluster 2 on the model volume.
    const DATA_START: u64 = 100;

    /// A volume a write runs against: the file's chain, the clusters an
    /// allocation takes next, the sectors written, and a log of the I/O.
    struct Model
    {
        geometry: Geometry,
        chain: Vec<u32>,
        free: Vec<u32>,
        sectors: BTreeMap<u64, Vec<u8>>,
        /// `(first sector, sectors)` of each run written, in order.
        runs: Vec<(u64, usize)>,
        reads: Vec<u64>,
        /// A run write starting at this sector fails.
        refuse_write_at: Option<u64>,
        /// A read of this sector fails.
        refuse_read_at: Option<u64>,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum ModelError
    {
        Refused,
        NoSpace,
    }

    impl Model
    {
        fn new(sectors_per_cluster: u8, bytes_per_sector: u16, chain: &[u32]) -> Self
        {
            Self {
                geometry: Geometry {
                    sectors_per_cluster,
                    bytes_per_sector,
                },
                chain: chain.to_vec(),
                free: Vec::new(),
                sectors: BTreeMap::new(),
                runs: Vec::new(),
                reads: Vec::new(),
                refuse_write_at: None,
                refuse_read_at: None,
            }
        }

        fn sector_size(&self) -> usize
        {
            usize::from(self.geometry.bytes_per_sector)
        }

        /// The file's byte `at`, as the device holds it.
        fn file_byte(&self, at: u64) -> u8
        {
            let bps = u64::from(self.geometry.bytes_per_sector);
            let cluster_bytes = bps * u64::from(self.geometry.sectors_per_cluster);
            let cluster = self.chain[idx(at / cluster_bytes)];
            let lba = self.cluster_sector(cluster) + (at % cluster_bytes) / bps;
            self.sectors.get(&lba).map_or(0, |s| s[idx(at % bps)])
        }

        /// Fill the file's first `len` bytes, on its chain, with `byte`.
        fn fill_file(&mut self, len: u64, byte: u8)
        {
            let bps = u64::from(self.geometry.bytes_per_sector);
            let sectors = len.div_ceil(bps);
            let per_cluster = u64::from(self.geometry.sectors_per_cluster);
            for s in 0..sectors
            {
                let lba = self.cluster_sector(self.chain[idx(s / per_cluster)]) + s % per_cluster;
                self.sectors.insert(lba, vec![byte; self.sector_size()]);
            }
        }
    }

    impl SectorIo for Model
    {
        type Error = ModelError;

        fn next_cluster(&mut self, cluster: u32) -> Result<u32, ModelError>
        {
            let at = self.chain.iter().position(|&c| c == cluster).unwrap();
            if let Some(&next) = self.chain.get(at + 1)
            {
                return Ok(next);
            }
            if self.free.is_empty()
            {
                return Err(ModelError::NoSpace);
            }
            let next = self.free.remove(0);
            self.chain.push(next);
            Ok(next)
        }

        fn cluster_sector(&self, cluster: u32) -> u64
        {
            DATA_START + u64::from(cluster - 2) * u64::from(self.geometry.sectors_per_cluster)
        }

        fn read_sector(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), ModelError>
        {
            if self.refuse_read_at == Some(lba)
            {
                return Err(ModelError::Refused);
            }
            self.reads.push(lba);
            match self.sectors.get(&lba)
            {
                Some(s) => buf.copy_from_slice(s),
                None => buf.fill(0),
            }
            Ok(())
        }

        fn write_run(&mut self, lba: u64, sectors: &[u8]) -> Result<(), ModelError>
        {
            if self.refuse_write_at == Some(lba)
            {
                return Err(ModelError::Refused);
            }
            let size = self.sector_size();
            assert_eq!(sectors.len() % size, 0, "a run holds whole sectors");
            for (i, sector) in sectors.chunks(size).enumerate()
            {
                self.sectors.insert(lba + i as u64, sector.to_vec());
            }
            self.runs.push((lba, sectors.len() / size));
            Ok(())
        }
    }

    fn idx(at: u64) -> usize
    {
        usize::try_from(at).unwrap()
    }

    fn pattern(len: usize) -> Vec<u8>
    {
        (0..len)
            .map(|i| u8::try_from(i % 251 + 1).unwrap())
            .collect()
    }

    fn run(
        model: &mut Model,
        first_cluster: u32,
        offset: u64,
        old_size: u64,
        data: &[u8],
        buffer: usize,
    ) -> Result<(), WriteError<ModelError>>
    {
        let mut run = vec![0u8; buffer];
        let geometry = model.geometry;
        write_range(
            model,
            geometry,
            first_cluster,
            &FileWrite {
                offset,
                old_size,
                data,
            },
            &mut run,
        )
    }

    #[test]
    fn a_page_over_consecutive_clusters_is_one_run()
    {
        let mut model = Model::new(1, 512, &[2, 3, 4, 5, 6, 7, 8, 9]);
        model.fill_file(4096, 0xAA);
        let data = pattern(4096);
        run(&mut model, 2, 0, 4096, &data, 4096).unwrap();
        assert_eq!(model.runs, vec![(DATA_START, 8)]);
        assert!(model.reads.is_empty(), "whole sectors are not read first");
        assert!((0..4096).all(|i| model.file_byte(i) == data[idx(i)]));
    }

    #[test]
    fn a_run_ends_where_the_chain_leaves_consecutive_sectors()
    {
        // Two sectors per cluster; clusters 2 and 3 are adjacent, 5 is not.
        let mut model = Model::new(2, 512, &[2, 3, 5]);
        let data = pattern(3 * 1024);
        run(&mut model, 2, 0, 3 * 1024, &data, 4096).unwrap();
        let fifth = model.cluster_sector(5);
        assert_eq!(model.runs, vec![(DATA_START, 4), (fifth, 2)]);
        assert!((0..3 * 1024).all(|i| model.file_byte(i) == data[idx(i)]));
    }

    #[test]
    fn partial_first_and_last_sectors_keep_the_bytes_the_write_leaves()
    {
        let mut model = Model::new(4, 512, &[2]);
        model.fill_file(2048, 0xAA);
        let data = pattern(1000);
        run(&mut model, 2, 100, 2048, &data, 4096).unwrap();
        // Sectors 0 to 2 of the file, the first and last read first.
        assert_eq!(model.runs, vec![(DATA_START, 3)]);
        assert_eq!(model.reads, vec![DATA_START, DATA_START + 2]);
        for i in 0..2048u64
        {
            let want = if (100..1100).contains(&i)
            {
                data[idx(i - 100)]
            }
            else
            {
                0xAA
            };
            assert_eq!(model.file_byte(i), want, "file byte {i}");
        }
    }

    #[test]
    fn a_write_longer_than_the_run_buffer_splits_into_buffer_runs()
    {
        // A write past the end: zeros from the old size 0 to offset 3000,
        // then 4096 bytes, 14 sectors over consecutive clusters.
        let mut model = Model::new(1, 512, &[2]);
        model.free = (3..20).collect();
        let data = pattern(4096);
        run(&mut model, 2, 3000, 0, &data, 4096).unwrap();
        assert_eq!(model.runs, vec![(DATA_START, 8), (DATA_START + 8, 6)]);
        assert!(model.reads.is_empty(), "no sector holds old bytes");
        for i in 0..7096u64
        {
            let want = if i < 3000 { 0 } else { data[idx(i - 3000)] };
            assert_eq!(model.file_byte(i), want, "file byte {i}");
        }
    }

    #[test]
    fn a_cluster_allocated_at_the_chain_end_joins_the_run_when_adjacent()
    {
        let mut model = Model::new(1, 512, &[2]);
        model.free = vec![3, 9];
        model.fill_file(512, 0xAA);
        let data = pattern(1536);
        run(&mut model, 2, 0, 512, &data, 4096).unwrap();
        assert_eq!(model.chain, vec![2, 3, 9]);
        assert_eq!(
            model.runs,
            vec![(DATA_START, 2), (model.cluster_sector(9), 1)]
        );
    }

    #[test]
    fn a_one_sector_buffer_writes_each_sector_alone()
    {
        // 4096-byte sectors: one fills the page-sized run buffer.
        let mut model = Model::new(1, 4096, &[2, 3]);
        let data = pattern(8192);
        run(&mut model, 2, 0, 8192, &data, 4096).unwrap();
        assert_eq!(model.runs, vec![(DATA_START, 1), (DATA_START + 1, 1)]);
    }

    #[test]
    fn a_refused_run_write_ends_the_write_there()
    {
        let mut model = Model::new(1, 512, &[2, 3, 7]);
        model.refuse_write_at = Some(DATA_START);
        let data = pattern(1536);
        assert_eq!(
            run(&mut model, 2, 0, 1536, &data, 4096),
            Err(WriteError::Io(ModelError::Refused))
        );
        assert!(model.runs.is_empty(), "no run after the refused one");
        assert!(model.sectors.is_empty());
    }

    #[test]
    fn a_failed_read_or_allocation_ends_the_write_with_its_error()
    {
        let mut model = Model::new(1, 512, &[2]);
        model.fill_file(512, 0xAA);
        model.refuse_read_at = Some(DATA_START);
        assert_eq!(
            run(&mut model, 2, 10, 512, &pattern(10), 4096),
            Err(WriteError::Io(ModelError::Refused))
        );
        assert_eq!(model.runs, Vec::new());

        // The chain ends after the first cluster and no cluster is free: the
        // allocation at the boundary fails before the first cluster's run,
        // still pending, is written.
        let mut model = Model::new(1, 512, &[2]);
        assert_eq!(
            run(&mut model, 2, 0, 0, &pattern(1024), 4096),
            Err(WriteError::Io(ModelError::NoSpace))
        );
        assert!(
            model.runs.is_empty(),
            "the pending run is not written past a failed step"
        );
    }

    #[test]
    fn a_geometry_that_places_no_sector_makes_no_io()
    {
        let mut zero = Model::new(0, 512, &[2]);
        assert_eq!(
            run(&mut zero, 2, 0, 0, &pattern(10), 4096),
            Err(WriteError::Geometry)
        );
        let mut short = Model::new(1, 512, &[2]);
        assert_eq!(
            run(&mut short, 2, 0, 0, &pattern(10), 256),
            Err(WriteError::Geometry)
        );
        assert!(zero.runs.is_empty() && short.runs.is_empty() && short.reads.is_empty());
    }

    #[test]
    fn an_empty_write_writes_nothing()
    {
        let mut model = Model::new(1, 512, &[2]);
        run(&mut model, 2, 4096, 0, &[], 4096).unwrap();
        assert_eq!(model.runs, Vec::new());
    }
}
