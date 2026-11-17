// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/sim.rs

//! Test support: the captured QEMU tables of `shared/aml/fixtures`, AML
//! tables built by hand, and a simulated machine behind [`aml::Host`] with
//! the registers the start-up evaluation reaches, as the firmware leaves
//! them: the ICH9 LPC bridge's PIRQ routing registers (00:1f.0, 0x60 and
//! 0x68) routing PIRQ A-H to IRQs 10, 10, 11, 11. Every other register reads
//! as the bytes last written to it, 0 at first, and the global lock is
//! refused, as acpid refuses it.

use std::collections::BTreeMap;
use std::path::Path;

use aml::encoding::Seg;
use aml::host::{Host, HostError, PciAddress, Span, Width};
use aml::{Evaluator, Namespace};

/// The simulated machine.
#[derive(Debug, Default)]
pub struct Sim
{
    io: BTreeMap<u64, u8>,
    mem: BTreeMap<u64, u8>,
    pci: BTreeMap<(u16, u8, u8, u8, u64), u8>,
}

impl Sim
{
    /// The machine as the firmware hands it over.
    pub fn new() -> Self
    {
        let mut sim = Self::default();
        for (i, irq) in [10u8, 10, 11, 11].into_iter().enumerate()
        {
            for base in [0x60, 0x68]
            {
                sim.pci.insert((0, 0, 0x1F, 0, base + i as u64), irq);
            }
        }
        sim
    }

    fn get<K: Ord + Copy>(map: &BTreeMap<K, u8>, key: impl Fn(u64) -> K, width: Width) -> u64
    {
        (0..width.bytes()).fold(0, |v, i| {
            v | (u64::from(map.get(&key(i)).copied().unwrap_or(0)) << (8 * i))
        })
    }

    fn set<K: Ord + Copy>(map: &mut BTreeMap<K, u8>, key: impl Fn(u64) -> K, width: Width, v: u64)
    {
        for i in 0..width.bytes()
        {
            map.insert(key(i), u8::try_from((v >> (8 * i)) & 0xFF).unwrap());
        }
    }
}

fn pci_key(f: PciAddress, offset: u64) -> impl Fn(u64) -> (u16, u8, u8, u8, u64)
{
    move |i| (f.segment, f.bus, f.device, f.function, offset + i)
}

impl Host for Sim
{
    fn io_read(&mut self, _: Span, port: u64, width: Width) -> Result<u64, HostError>
    {
        Ok(Self::get(&self.io, |i| port + i, width))
    }

    fn io_write(&mut self, _: Span, port: u64, width: Width, value: u64) -> Result<(), HostError>
    {
        Self::set(&mut self.io, |i| port + i, width, value);
        Ok(())
    }

    fn mem_read(&mut self, _: Span, addr: u64, width: Width) -> Result<u64, HostError>
    {
        Ok(Self::get(&self.mem, |i| addr + i, width))
    }

    fn mem_write(&mut self, _: Span, addr: u64, width: Width, value: u64) -> Result<(), HostError>
    {
        Self::set(&mut self.mem, |i| addr + i, width, value);
        Ok(())
    }

    fn pci_read(
        &mut self,
        function: PciAddress,
        offset: u64,
        width: Width,
    ) -> Result<u64, HostError>
    {
        Ok(Self::get(&self.pci, pci_key(function, offset), width))
    }

    fn pci_write(
        &mut self,
        function: PciAddress,
        offset: u64,
        width: Width,
        value: u64,
    ) -> Result<(), HostError>
    {
        Self::set(&mut self.pci, pci_key(function, offset), width, value);
        Ok(())
    }

    fn notify(&mut self, _: &[Seg], _: u64) -> Result<(), HostError>
    {
        Ok(())
    }

    fn sleep(&mut self, _: u64) {}

    fn stall(&mut self, _: u64) {}

    fn timer(&mut self) -> u64
    {
        0
    }

    fn acquire_global_lock(&mut self, _: u16) -> Result<bool, HostError>
    {
        Err(HostError::Refused)
    }

    fn release_global_lock(&mut self) -> Result<(), HostError>
    {
        Err(HostError::Refused)
    }

    fn osi(&mut self, _: &[u8]) -> bool
    {
        false
    }
}

/// A namespace of the tables `tables`, loaded and parsed without fault.
pub fn namespace(tables: &[Vec<u8>]) -> Namespace
{
    let mut ns = Namespace::new().unwrap();
    for t in tables
    {
        assert_eq!(ns.load_table(t).unwrap().faults, 0);
    }
    assert_eq!(ns.parse_methods().1, 0);
    ns
}

/// The namespace of the captured configuration `name`: its DSDT, then its
/// SSDTs in number order.
pub fn fixture(name: &str) -> Namespace
{
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../shared/aml/fixtures")
        .join(name);
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| {
            Path::new(n)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("aml"))
        })
        .collect();
    files.sort_by_key(|n| (n != "DSDT.aml", n.clone()));
    let tables: Vec<Vec<u8>> = files
        .iter()
        .map(|n| std::fs::read(dir.join(n)).unwrap())
        .collect();
    namespace(&tables)
}

/// Run the module-level code of `ns` on `sim`, as acpid does after the load.
pub fn run_module_code(ns: &mut Namespace, sim: &mut Sim)
{
    Evaluator::new(ns, sim).run_module_code();
}

/// The `PkgLength` encoding of a package whose body is `body`, then `body`.
pub fn pkg(body: &[u8]) -> Vec<u8>
{
    let mut out = Vec::new();
    let n = body.len();
    if n + 1 < 0x40
    {
        out.push(u8::try_from(n + 1).unwrap());
    }
    else
    {
        let n = n + 2;
        assert!(n < 0x1000);
        out.push(0x40 | u8::try_from(n & 0xF).unwrap());
        out.push(u8::try_from(n >> 4).unwrap());
    }
    out.extend_from_slice(body);
    out
}

/// A DSDT whose AML is `body`.
pub fn table(body: &[u8]) -> Vec<u8>
{
    let mut t = b"DSDT".to_vec();
    t.extend(u32::try_from(36 + body.len()).unwrap().to_le_bytes());
    t.push(2);
    t.resize(36, 0);
    t.extend_from_slice(body);
    t
}

/// `Device (name) { body }`.
pub fn device(name: &[u8], body: &[u8]) -> Vec<u8>
{
    let mut out = vec![0x5B, 0x82];
    out.extend(pkg(&[name, body].concat()));
    out
}

/// `Method (name, 0) { body }`.
pub fn method(name: &[u8], body: &[u8]) -> Vec<u8>
{
    let mut out = vec![0x14];
    out.extend(pkg(&[name, &[0], body].concat()));
    out
}

/// `Name (name, data)`.
pub fn name(name: &[u8], data: &[u8]) -> Vec<u8>
{
    [&[0x08], name, data].concat()
}

/// A `DWordConst`.
pub fn dword(v: u32) -> Vec<u8>
{
    [&[0x0C][..], &v.to_le_bytes()].concat()
}

/// `Buffer () { bytes }`.
pub fn buffer(bytes: &[u8]) -> Vec<u8>
{
    let len = u16::try_from(bytes.len()).unwrap().to_le_bytes();
    let mut out = vec![0x11];
    out.extend(pkg(&[&[0x0B, len[0], len[1]][..], bytes].concat()));
    out
}

/// `Package () { elements }`.
pub fn package(elements: &[Vec<u8>]) -> Vec<u8>
{
    let mut body = vec![u8::try_from(elements.len()).unwrap()];
    for e in elements
    {
        body.extend_from_slice(e);
    }
    let mut out = vec![0x12];
    out.extend(pkg(&body));
    out
}
