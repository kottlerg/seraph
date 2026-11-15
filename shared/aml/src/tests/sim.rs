// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/tests/sim.rs

//! A simulated QEMU machine behind the [`Host`] trait: the registers the
//! captured tables' code reaches, modelled as QEMU's devices implement them.
//!
//! - ACPI PCI hotplug (`hw/acpi/pcihp.c`) at port 0xCC0 on q35: `PCIU` and
//!   `PCID` report the slots of the bus `BNUM` selects, `PCIU` clearing as
//!   it is read; `B0EJ` ejects.
//! - CPU hotplug (`hw/acpi/cpu.c`) at port 0xCD8: the selector, the flags
//!   byte (enabled, inserting, removing; writing 1 to a pending bit clears
//!   it), the command byte and the data dword; command 0 selects the next
//!   CPU with a pending event.
//! - The HPET's capability registers at 0xFED00000.
//! - The ICH9 LPC bridge's PIRQ routing registers (00:1f.0, 0x60 and 0x68)
//!   and the `PCIe` root port's header type and secondary bus (00:1c.0).
//!
//! Every other register reads as the bytes last written to it, 0 at first.
//! Each access is checked against the region span the evaluator passes, and
//! logged.

use std::collections::BTreeMap;

use crate::encoding::Seg;
use crate::host::{Host, HostError, PciAddress, Span, Width};

/// The address spaces of [`Access`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Space
{
    Io,
    Mem,
    Pci(PciAddress),
}

/// One region access the evaluator made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Access
{
    pub space: Space,
    pub addr: u64,
    pub width: Width,
    /// The value written; `None` for a read.
    pub write: Option<u64>,
}

/// The ACPI PCI hotplug registers' base port on q35.
pub(super) const PCIHP: u64 = 0xCC0;
/// The CPU hotplug registers' base port on q35.
pub(super) const CPUHP: u64 = 0xCD8;
/// The number of CPUs of the captured machines.
pub(super) const CPUS: usize = 4;

/// The LPC bridge, 00:1f.0.
pub(super) const LPC: PciAddress = PciAddress {
    segment: 0,
    bus: 0,
    device: 0x1F,
    function: 0,
};

/// The simulated machine.
#[derive(Debug, Default)]
pub(super) struct Sim
{
    io: BTreeMap<u64, u8>,
    mem: BTreeMap<u64, u8>,
    pci: BTreeMap<(u16, u8, u8, u8, u64), u8>,
    /// Every region access, in order.
    pub log: Vec<Access>,
    /// Every `Notify`: the object's path, as `\_SB_.PCI0`, and the value.
    pub notes: Vec<(String, u64)>,
    /// The slots each hotplug bus reports added (`PCIU`), by `BNUM`.
    pub up: BTreeMap<u32, u32>,
    /// The slots each hotplug bus reports to remove (`PCID`).
    pub down: BTreeMap<u32, u32>,
    /// The hotplug bus selector.
    pub bnum: u32,
    /// The `B0EJ` writes: the bus selected and the slot mask.
    pub ejected: Vec<(u32, u32)>,
    /// The CPU hotplug selector, the last command, and each CPU's pending
    /// insert and remove.
    pub cpu_sel: u32,
    pub cpu_cmd: u8,
    pub inserting: [bool; CPUS],
    pub removing: [bool; CPUS],
    /// The global lock: held now, and the acquisitions and releases made.
    pub gl_held: bool,
    pub gl_acquires: u32,
    pub gl_releases: u32,
    /// The global lock acquisition fails.
    pub gl_refuse: bool,
    /// The timeout of each request for the global lock.
    pub gl_waits: Vec<u16>,
    /// How long a granted request waits first, in milliseconds, at most its
    /// timeout.
    pub gl_grant_ms: u64,
    /// The time slept and stalled.
    pub slept_ms: u64,
    pub stalled_us: u64,
    timer: u64,
    /// The interfaces `_OSI` reports.
    pub osi: Vec<Vec<u8>>,
    /// Refuse every access to this address space.
    pub refuse: Option<u8>,
}

/// The ASL path of `path`.
pub(super) fn path_text(path: &[Seg]) -> String
{
    let mut s = String::from("\\");
    let segs: Vec<String> = path
        .iter()
        .map(|g| String::from_utf8_lossy(g).into_owned())
        .collect();
    s.push_str(&segs.join("."));
    s
}

impl Sim
{
    /// The machine at reset, as the firmware leaves it: the HPET present,
    /// PIRQ A-H routed to IRQs 10, 10, 11, 11, the root port's secondary
    /// bus 1.
    pub(super) fn new() -> Self
    {
        let mut sim = Self::default();
        sim.put_mem(0xFED0_0000, 4, 0x8086_A201);
        sim.put_mem(0xFED0_0004, 4, 10_000_000);
        for (i, irq) in [10u8, 10, 11, 11].into_iter().enumerate()
        {
            sim.put_pci(LPC, 0x60 + i as u64, irq);
            sim.put_pci(LPC, 0x68 + i as u64, irq);
        }
        let rootport = PciAddress {
            segment: 0,
            bus: 0,
            device: 0x1C,
            function: 0,
        };
        sim.put_pci(rootport, 0x0E, 0x81);
        sim.put_pci(rootport, 0x19, 1);
        sim.osi = vec![b"Windows 2015".to_vec(), b"Module Device".to_vec()];
        sim
    }

    pub(super) fn put_mem(&mut self, addr: u64, n: u64, v: u64)
    {
        for i in 0..n
        {
            self.mem
                .insert(addr + i, u8::try_from((v >> (8 * i)) & 0xFF).unwrap());
        }
    }

    pub(super) fn put_pci(&mut self, f: PciAddress, off: u64, v: u8)
    {
        self.pci
            .insert((f.segment, f.bus, f.device, f.function, off), v);
    }

    pub(super) fn io_byte(&self, port: u64) -> u8
    {
        self.io.get(&port).copied().unwrap_or(0)
    }

    pub(super) fn mem_byte(&self, addr: u64) -> u8
    {
        self.mem.get(&addr).copied().unwrap_or(0)
    }

    /// The writes to I/O ports, in order: port and value.
    pub(super) fn io_writes(&self) -> Vec<(u64, u64)>
    {
        self.log
            .iter()
            .filter(|a| a.space == Space::Io)
            .filter_map(|a| a.write.map(|v| (a.addr, v)))
            .collect()
    }

    fn check(span: Span, addr: u64, width: Width)
    {
        assert!(
            addr >= span.base && addr + width.bytes() <= span.base + span.len,
            "access {addr:#x}/{width:?} outside its region {span:?}"
        );
    }

    fn get(map: &BTreeMap<u64, u8>, addr: u64, width: Width) -> u64
    {
        (0..width.bytes()).fold(0, |v, i| {
            v | (u64::from(map.get(&(addr + i)).copied().unwrap_or(0)) << (8 * i))
        })
    }

    fn set(map: &mut BTreeMap<u64, u8>, addr: u64, width: Width, v: u64)
    {
        for i in 0..width.bytes()
        {
            map.insert(addr + i, u8::try_from((v >> (8 * i)) & 0xFF).unwrap());
        }
    }

    /// The CPU hotplug flags byte of the selected CPU.
    fn cpu_flags(&self) -> u64
    {
        let i = self.cpu_sel as usize;
        if i >= CPUS
        {
            return 0;
        }
        1 | (u64::from(self.inserting[i]) << 1) | (u64::from(self.removing[i]) << 2)
    }

    fn io_reg_read(&mut self, port: u64, width: Width) -> u64
    {
        match port
        {
            p if p == PCIHP => self.up.insert(self.bnum, 0).unwrap_or(0).into(),
            p if p == PCIHP + 4 => self.down.get(&self.bnum).copied().unwrap_or(0).into(),
            p if p == PCIHP + 0x10 => self.bnum.into(),
            p if p == CPUHP + 4 => self.cpu_flags(),
            p if p == CPUHP + 8 => self.cpu_sel.into(),
            _ => Self::get(&self.io, port, width),
        }
    }

    fn io_reg_write(&mut self, port: u64, width: Width, v: u64)
    {
        match port
        {
            p if p == PCIHP + 8 => self
                .ejected
                .push((self.bnum, u32::try_from(v & 0xFFFF_FFFF).unwrap())),
            p if p == PCIHP + 0x10 => self.bnum = u32::try_from(v & 0xFFFF_FFFF).unwrap(),
            p if p == CPUHP => self.cpu_sel = u32::try_from(v & 0xFFFF_FFFF).unwrap(),
            p if p == CPUHP + 4 =>
            {
                let i = self.cpu_sel as usize;
                if i < CPUS
                {
                    if v & 2 != 0
                    {
                        self.inserting[i] = false;
                    }
                    if v & 4 != 0
                    {
                        self.removing[i] = false;
                    }
                }
                // A write to the flags of a word or wider access reaches the
                // command byte too.
                if width != Width::Byte
                {
                    self.io_reg_write(CPUHP + 5, Width::Byte, v >> 8);
                }
            }
            p if p == CPUHP + 5 =>
            {
                self.cpu_cmd = u8::try_from(v & 0xFF).unwrap();
                if self.cpu_cmd == 0
                {
                    let from = self.cpu_sel as usize;
                    if let Some(i) = (from..CPUS).find(|&i| self.inserting[i] || self.removing[i])
                    {
                        self.cpu_sel = u32::try_from(i).unwrap();
                    }
                }
            }
            _ => Self::set(&mut self.io, port, width, v),
        }
    }
}

impl Host for Sim
{
    fn io_read(&mut self, region: Span, port: u64, width: Width) -> Result<u64, HostError>
    {
        Self::check(region, port, width);
        if self.refuse == Some(1)
        {
            return Err(HostError::Refused);
        }
        let v = self.io_reg_read(port, width);
        self.log.push(Access {
            space: Space::Io,
            addr: port,
            width,
            write: None,
        });
        Ok(v)
    }

    fn io_write(
        &mut self,
        region: Span,
        port: u64,
        width: Width,
        value: u64,
    ) -> Result<(), HostError>
    {
        Self::check(region, port, width);
        assert_eq!(value & !width.mask(), 0, "a write wider than its access");
        if self.refuse == Some(1)
        {
            return Err(HostError::Refused);
        }
        self.io_reg_write(port, width, value);
        self.log.push(Access {
            space: Space::Io,
            addr: port,
            width,
            write: Some(value),
        });
        Ok(())
    }

    fn mem_read(&mut self, region: Span, addr: u64, width: Width) -> Result<u64, HostError>
    {
        Self::check(region, addr, width);
        if self.refuse == Some(0)
        {
            return Err(HostError::Refused);
        }
        self.log.push(Access {
            space: Space::Mem,
            addr,
            width,
            write: None,
        });
        Ok(Self::get(&self.mem, addr, width))
    }

    fn mem_write(
        &mut self,
        region: Span,
        addr: u64,
        width: Width,
        value: u64,
    ) -> Result<(), HostError>
    {
        Self::check(region, addr, width);
        if self.refuse == Some(0)
        {
            return Err(HostError::Refused);
        }
        self.log.push(Access {
            space: Space::Mem,
            addr,
            width,
            write: Some(value),
        });
        Self::set(&mut self.mem, addr, width, value);
        Ok(())
    }

    fn pci_read(
        &mut self,
        function: PciAddress,
        offset: u64,
        width: Width,
    ) -> Result<u64, HostError>
    {
        assert!(offset + width.bytes() <= 4096, "config offset {offset:#x}");
        if self.refuse == Some(2)
        {
            return Err(HostError::Refused);
        }
        self.log.push(Access {
            space: Space::Pci(function),
            addr: offset,
            width,
            write: None,
        });
        Ok((0..width.bytes()).fold(0, |v, i| {
            let b = self
                .pci
                .get(&(
                    function.segment,
                    function.bus,
                    function.device,
                    function.function,
                    offset + i,
                ))
                .copied()
                .unwrap_or(0);
            v | (u64::from(b) << (8 * i))
        }))
    }

    fn pci_write(
        &mut self,
        function: PciAddress,
        offset: u64,
        width: Width,
        value: u64,
    ) -> Result<(), HostError>
    {
        assert!(offset + width.bytes() <= 4096, "config offset {offset:#x}");
        if self.refuse == Some(2)
        {
            return Err(HostError::Refused);
        }
        self.log.push(Access {
            space: Space::Pci(function),
            addr: offset,
            width,
            write: Some(value),
        });
        for i in 0..width.bytes()
        {
            self.put_pci(
                function,
                offset + i,
                u8::try_from((value >> (8 * i)) & 0xFF).unwrap(),
            );
        }
        Ok(())
    }

    fn notify(&mut self, path: &[Seg], value: u64) -> Result<(), HostError>
    {
        self.notes.push((path_text(path), value));
        Ok(())
    }

    fn sleep(&mut self, ms: u64)
    {
        self.slept_ms += ms;
    }

    fn stall(&mut self, us: u64)
    {
        self.stalled_us += us;
    }

    fn timer(&mut self) -> u64
    {
        self.timer += 10;
        self.timer
    }

    fn acquire_global_lock(&mut self, timeout_ms: u16) -> Result<bool, HostError>
    {
        assert!(!self.gl_held, "the global lock acquired twice");
        self.gl_waits.push(timeout_ms);
        if self.gl_refuse
        {
            return Ok(false);
        }
        self.timer += u64::from(timeout_ms).min(self.gl_grant_ms) * 10_000;
        self.gl_held = true;
        self.gl_acquires += 1;
        Ok(true)
    }

    fn release_global_lock(&mut self) -> Result<(), HostError>
    {
        assert!(self.gl_held, "the global lock released while free");
        self.gl_held = false;
        self.gl_releases += 1;
        Ok(())
    }

    fn osi(&mut self, name: &[u8]) -> bool
    {
        self.osi.iter().any(|o| o == name)
    }
}
