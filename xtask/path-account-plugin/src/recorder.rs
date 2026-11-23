// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/path-account-plugin/src/recorder.rs

//! The recorder's state, apart from QEMU: the plugin's callbacks
//! (`crate::qemu`) call one method each, so the segments, the histograms and
//! the events are tested on the host.
//!
//! Each translated instruction gets a slot, shared by every translation of the
//! same bytes at the same address, and its callbacks carry the slot's index.
//! The plugin registers, on every instruction and in this order: the value
//! callback (only while a read's value is due), the read callback (on a
//! user-mode counter read), and the execution callback. QEMU calls an
//! instruction's callbacks before it executes, so a read closes the segment
//! before the read is counted, and the read opens the next.

use std::collections::HashMap;
use std::io::{self, Write};

use crate::class::{Arch, Class, Dest, classify, user_half};
use crate::record::Event;

/// The longest instruction a slot's key holds: x86-64's.
pub const INSN_MAX: usize = 15;

/// One instruction's slot.
struct Slot
{
    pc: u64,
    class: Class,
    /// Times it ran in the segment `segment` names.
    count: u64,
    /// The segment `count` is of; a slot first run in a new segment joins
    /// that segment's list.
    segment: u64,
}

/// A read whose value is due at the next instruction.
#[derive(Clone, Copy)]
struct Pending
{
    pc: u64,
    hist: u64,
    dest: Dest,
}

/// The recorder: the slots, the open segment, and the record being written.
pub struct Recorder<W: Write>
{
    arch: Arch,
    out: W,
    slots: Vec<Slot>,
    keys: HashMap<(u64, [u8; INSN_MAX]), u32>,
    /// The open segment's number.
    segment: u64,
    /// The slots run in the open segment.
    touched: Vec<u32>,
    /// The slot executed last, until a trap's discontinuity is seen.
    last: Option<u32>,
    pending: Option<Pending>,
    /// Each histogram written, by the hash of its entries.
    hists: HashMap<u128, u64>,
    /// The first write error; nothing is written after it.
    error: Option<io::Error>,
}

/// 128-bit FNV-1a over the entries' addresses and counts.
fn hash(entries: &[(u64, u64)]) -> u128
{
    const OFFSET: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    const PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
    let mut h = OFFSET;
    for (pc, count) in entries
    {
        for byte in pc.to_le_bytes().into_iter().chain(count.to_le_bytes())
        {
            h ^= u128::from(byte);
            h = h.wrapping_mul(PRIME);
        }
    }
    h
}

impl<W: Write> Recorder<W>
{
    /// A recorder for `arch` writing to `out`, which it starts with the
    /// header.
    pub fn new(arch: Arch, out: W) -> Self
    {
        let mut recorder = Self {
            arch,
            out,
            slots: Vec::new(),
            keys: HashMap::new(),
            segment: 0,
            touched: Vec::new(),
            last: None,
            pending: None,
            hists: HashMap::new(),
            error: None,
        };
        recorder.emit(&Event::Header { arch });
        recorder
    }

    /// Write `event` as one line, unless a write has failed.
    fn emit(&mut self, event: &Event)
    {
        if self.error.is_none()
            && let Err(e) = writeln!(self.out, "{event}")
        {
            self.error = Some(e);
        }
    }

    /// The slot of the instruction at `pc` whose bytes `bytes` starts with,
    /// made on its first translation, and its class; `None` once the slots
    /// outnumber a callback's index.
    pub fn slot(&mut self, pc: u64, bytes: &[u8]) -> Option<(u32, Class)>
    {
        let mut key = [0; INSN_MAX];
        for (k, b) in key.iter_mut().zip(bytes)
        {
            *k = *b;
        }
        if let Some(&index) = self.keys.get(&(pc, key))
        {
            return self
                .slots
                .get(index as usize)
                .map(|slot| (index, slot.class));
        }
        let index = u32::try_from(self.slots.len()).ok()?;
        let class = classify(self.arch, bytes);
        self.slots.push(Slot {
            pc,
            class,
            count: 0,
            segment: u64::MAX,
        });
        self.keys.insert((pc, key), index);
        Some((index, class))
    }

    /// Whether the plugin registers the read callback on a slot: a counter
    /// read in the user half.
    #[must_use]
    pub fn is_user_read(&self, index: u32) -> bool
    {
        self.slots
            .get(index as usize)
            .is_some_and(|s| matches!(s.class, Class::Read(_)) && user_half(s.pc))
    }

    /// The execution callback: the slot's instruction runs.
    pub fn exec(&mut self, index: u32)
    {
        let segment = self.segment;
        if let Some(slot) = self.slots.get_mut(index as usize)
        {
            if slot.segment != segment
            {
                slot.segment = segment;
                slot.count = 0;
                self.touched.push(index);
            }
            slot.count = slot.count.wrapping_add(1);
            self.last = Some(index);
        }
    }

    /// The read callback: a user-mode counter read is about to run. It closes
    /// the open segment, unless the previous read's value is still due (the
    /// read began again: [`Event::Retry`]).
    pub fn read(&mut self, index: u32)
    {
        let Some(slot) = self.slots.get(index as usize)
        else
        {
            return;
        };
        let (pc, class) = (slot.pc, slot.class);
        let Class::Read(dest) = class
        else
        {
            return;
        };
        if let Some(pending) = self.pending
        {
            self.emit(&Event::Retry { pc: pending.pc });
            return;
        }
        let hist = self.close();
        self.pending = Some(Pending { pc, hist, dest });
    }

    /// Where the due read left its value, while one is due.
    #[must_use]
    pub fn due(&self) -> Option<Dest>
    {
        self.pending.map(|p| p.dest)
    }

    /// The value callback: the due read's `value` (`None` when the plugin
    /// could not read its registers, which ends the record with the error).
    pub fn value(&mut self, value: Option<u64>)
    {
        let Some(pending) = self.pending.take()
        else
        {
            return;
        };
        match value
        {
            Some(value) =>
            {
                self.emit(&Event::Read {
                    pc: pending.pc,
                    hist: pending.hist,
                    value,
                });
                // The guest is killed when the trace has what it needs: what a
                // read completed is on disk.
                if self.error.is_none()
                    && let Err(e) = self.out.flush()
                {
                    self.error = Some(e);
                }
            }
            None =>
            {
                if self.error.is_none()
                {
                    self.error = Some(io::Error::other(format!(
                        "the registers of the read at {:#x} could not be read",
                        pending.pc
                    )));
                }
            }
        }
    }

    /// The discontinuity callback: control left the instruction stream from
    /// `from`. When `from` is the instruction executed last and it does not
    /// trap by design, a trap interrupted it: [`Event::Attempt`]. The next
    /// attempt then needs a new execution, so a trap that QEMU reports twice
    /// from the instruction is one attempt; a report from another address (a
    /// block's start, or the next instruction, which an interrupt between
    /// instructions names) leaves the instruction executed last as it was.
    pub fn discon(&mut self, from: u64)
    {
        let Some(index) = self.last
        else
        {
            return;
        };
        let attempt = self
            .slots
            .get(index as usize)
            .is_some_and(|s| s.pc == from && s.class != Class::Trap);
        if attempt
        {
            self.last = None;
            self.emit(&Event::Attempt { pc: from });
        }
    }

    /// Close the open segment: write its histogram if no earlier segment had
    /// the same, and open the next. Returns the histogram's identifier.
    fn close(&mut self) -> u64
    {
        let mut entries: Vec<(u64, u64)> = self
            .touched
            .iter()
            .filter_map(|&i| self.slots.get(i as usize))
            .map(|s| (s.pc, s.count))
            .collect();
        self.touched.clear();
        self.segment = self.segment.wrapping_add(1);
        entries.sort_unstable();
        // Two slots at one address (two images' bytes there) count as one.
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(entries.len());
        for (pc, count) in entries
        {
            match merged.last_mut()
            {
                Some(last) if last.0 == pc => last.1 = last.1.wrapping_add(count),
                _ => merged.push((pc, count)),
            }
        }
        let key = hash(&merged);
        if let Some(&id) = self.hists.get(&key)
        {
            return id;
        }
        let id = self.hists.len() as u64;
        self.hists.insert(key, id);
        self.emit(&Event::Hist {
            id,
            entries: merged,
        });
        id
    }

    /// Flush the record; the first error met writing it, if any.
    ///
    /// # Errors
    /// The first write error, or the read whose registers failed.
    pub fn finish(&mut self) -> io::Result<()>
    {
        if let Some(e) = self.error.take()
        {
            return Err(e);
        }
        self.out.flush()
    }
}

#[cfg(test)]
mod tests
{
    use super::Recorder;
    use crate::class::{Arch, Class, Dest};
    use crate::record::{Event, parse};

    /// The events `recorder` wrote, header first.
    fn events(recorder: &mut Recorder<Vec<u8>>) -> Vec<Event>
    {
        recorder.finish().unwrap();
        String::from_utf8(recorder.out.clone())
            .unwrap()
            .lines()
            .map(|l| parse(l).unwrap())
            .collect()
    }

    const RDTSC: [u8; 2] = [0x0f, 0x31];
    const NOP: [u8; 1] = [0x90];
    const SYSCALL: [u8; 2] = [0x0f, 0x05];

    #[test]
    fn a_read_closes_the_segment_and_counts_itself_in_the_next()
    {
        let mut r = Recorder::new(Arch::X86_64, Vec::new());
        let (read, class) = r.slot(0x1000, &RDTSC).unwrap();
        assert_eq!(class, Class::Read(Dest::EdxEax));
        assert!(r.is_user_read(read));
        let (nop, _) = r.slot(0x1002, &NOP).unwrap();
        let (kernel, _) = r.slot(0xffff_ffff_8000_0000, &NOP).unwrap();
        assert!(!r.is_user_read(nop));
        // Before the first read: one segment, then the read.
        r.exec(nop);
        r.read(read);
        r.exec(read);
        assert_eq!(r.due(), Some(Dest::EdxEax));
        r.value(Some(100));
        assert_eq!(r.due(), None);
        r.exec(nop);
        r.exec(kernel);
        r.exec(nop);
        r.read(read);
        r.exec(read);
        r.value(Some(104));
        assert_eq!(
            events(&mut r),
            [
                Event::Header { arch: Arch::X86_64 },
                Event::Hist {
                    id: 0,
                    entries: vec![(0x1002, 1)]
                },
                Event::Read {
                    pc: 0x1000,
                    hist: 0,
                    value: 100
                },
                Event::Hist {
                    id: 1,
                    entries: vec![(0x1000, 1), (0x1002, 2), (0xffff_ffff_8000_0000, 1)]
                },
                Event::Read {
                    pc: 0x1000,
                    hist: 1,
                    value: 104
                },
            ]
        );
    }

    #[test]
    fn a_repeated_segment_names_its_first_histogram()
    {
        let mut r = Recorder::new(Arch::X86_64, Vec::new());
        let (read, _) = r.slot(0x1000, &RDTSC).unwrap();
        let (nop, _) = r.slot(0x1002, &NOP).unwrap();
        for value in [10, 20, 30]
        {
            r.read(read);
            r.exec(read);
            r.value(Some(value));
            r.exec(nop);
        }
        let got = events(&mut r);
        let hists: Vec<u64> = got
            .iter()
            .filter_map(|e| match e
            {
                Event::Read { hist, .. } => Some(*hist),
                Event::Header { .. }
                | Event::Hist { .. }
                | Event::Attempt { .. }
                | Event::Retry { .. } => None,
            })
            .collect();
        // The first segment is empty; the next two are the read and the nop.
        assert_eq!(hists, [0, 1, 1]);
        assert_eq!(
            got.iter()
                .filter(|e| matches!(e, Event::Hist { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn a_translation_of_the_same_bytes_shares_the_slot()
    {
        let mut r = Recorder::new(Arch::Riscv64, Vec::new());
        let a = r.slot(0x2000, &0x0000_0013u32.to_le_bytes()).unwrap();
        let b = r.slot(0x2000, &0x0000_0013u32.to_le_bytes()).unwrap();
        let c = r.slot(0x2000, &0x0000_0073u32.to_le_bytes()).unwrap();
        assert_eq!(a, b);
        assert_ne!(a.0, c.0);
        assert_eq!(c.1, Class::Trap);
    }

    #[test]
    fn two_slots_at_one_address_count_as_one_entry()
    {
        let mut r = Recorder::new(Arch::Riscv64, Vec::new());
        let (read, _) = r.slot(0x1000, &0xc000_2573u32.to_le_bytes()).unwrap();
        let (one, _) = r.slot(0x2000, &0x0000_0013u32.to_le_bytes()).unwrap();
        let (two, _) = r.slot(0x2000, &0x0010_0093u32.to_le_bytes()).unwrap();
        r.exec(one);
        r.exec(two);
        r.exec(two);
        r.read(read);
        r.exec(read);
        r.value(Some(1));
        assert!(events(&mut r).contains(&Event::Hist {
            id: 0,
            entries: vec![(0x2000, 3)]
        }));
    }

    #[test]
    fn a_trap_after_an_instruction_that_began_is_an_attempt()
    {
        let mut r = Recorder::new(Arch::X86_64, Vec::new());
        let (store, _) = r.slot(0x1004, &[0x89, 0x07]).unwrap();
        let (sys, _) = r.slot(0x1008, &SYSCALL).unwrap();
        // A fault reported twice: once from the block's start, once from the
        // store; one attempt.
        r.exec(store);
        r.discon(0x1000);
        r.discon(0x1004);
        // A system call retires: no attempt.
        r.exec(sys);
        r.discon(0x1008);
        // A fault from the store itself, reported first.
        r.exec(store);
        r.discon(0x1004);
        r.discon(0x1004);
        // An interrupt between instructions names the next one.
        r.exec(store);
        r.discon(0x1006);
        assert_eq!(
            events(&mut r),
            [
                Event::Header { arch: Arch::X86_64 },
                Event::Attempt { pc: 0x1004 },
                Event::Attempt { pc: 0x1004 },
            ]
        );
    }

    #[test]
    fn a_read_begun_again_is_a_retry_in_the_same_segment()
    {
        let mut r = Recorder::new(Arch::X86_64, Vec::new());
        let (read, _) = r.slot(0x1000, &RDTSC).unwrap();
        r.read(read);
        r.exec(read);
        r.read(read);
        r.exec(read);
        r.value(Some(5));
        assert_eq!(
            events(&mut r),
            [
                Event::Header { arch: Arch::X86_64 },
                Event::Hist {
                    id: 0,
                    entries: Vec::new()
                },
                Event::Retry { pc: 0x1000 },
                Event::Read {
                    pc: 0x1000,
                    hist: 0,
                    value: 5
                },
            ]
        );
    }

    #[test]
    fn a_read_whose_registers_fail_ends_the_record_with_an_error()
    {
        let mut r = Recorder::new(Arch::X86_64, Vec::new());
        let (read, _) = r.slot(0x1000, &RDTSC).unwrap();
        r.read(read);
        r.value(None);
        r.read(read);
        r.value(Some(1));
        assert!(r.finish().is_err());
        let text = String::from_utf8(r.out.clone()).unwrap();
        assert!(!text.contains("R 1000"), "{text}");
    }
}
