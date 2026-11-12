// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/platform.rs

//! The ACPI Serial Port Console Redirection table (SPCR) and the platform
//! description table.
//!
//! The SPCR names the console UART's interface type, base address, and
//! interrupt. The platform description table is a text file in the `.svc`
//! grammar of the device class files: line-oriented `key = value`, `#` starts
//! a comment line, blank lines are skipped. It lists the devices a machine
//! has that no firmware table describes, keyed by the XSDT's OEM table ID.
//!
//! ```text
//! # <comment>
//! oem_table_id = BXPC
//! device = google,goldfish-rtc mmio 0x101000 0x1000 wired 11 level-high
//! ```

extern crate alloc;

use alloc::vec::Vec;

use crate::acpi::sdt_signature;

// ── SPCR ──────────────────────────────────────────────────────────────

/// Smallest SPCR this parser reads.
const SPCR_MIN_LEN: usize = 80;
const SPCR_OFF_INTERFACE: usize = 36;
const SPCR_OFF_SPACE_ID: usize = 40;
const SPCR_OFF_ADDRESS: usize = 44;
const SPCR_OFF_INT_TYPE: usize = 52;
const SPCR_OFF_IRQ: usize = 53;
const SPCR_OFF_GSI: usize = 54;

/// What the SPCR names: the console UART's interface type and base address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spcr
{
    /// The SPCR interface type.
    pub interface: u8,
    /// The UART's register base.
    pub base: SpcrBase,
    /// The UART's interrupt, if the table names one.
    pub interrupt: Option<SpcrInterrupt>,
}

/// Where the UART's registers are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpcrBase
{
    /// A system-memory address.
    Mmio(u64),
    /// A system I/O port base.
    IoPort(u16),
}

/// The UART's interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpcrInterrupt
{
    /// The ISA IRQ number or the GSI / APLIC source.
    pub line: u32,
    /// Whether `line` is an ISA IRQ number (dual-8259).
    pub isa: bool,
}

fn rd_u64(buf: &[u8], off: usize) -> Option<u64>
{
    Some(u64::from_le_bytes(
        buf.get(off..off.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn rd_u32(buf: &[u8], off: usize) -> Option<u32>
{
    Some(u32::from_le_bytes(
        buf.get(off..off.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// Parse an SPCR (signature `SPCR`, length >= 80): the interface type, the
/// base address Generic Address Structure (system memory or system I/O; a
/// zero address is none), and the interrupt (bit 0 of the interrupt type is
/// the dual-8259 ISA IRQ, any of bits 1 to 4 a GSI or APLIC source).
/// An I/O base above 0xFFFF, another space id, a wrong signature, or a short
/// table gives `None`.
#[must_use]
pub fn spcr(table: &[u8]) -> Option<Spcr>
{
    if table.len() < SPCR_MIN_LEN || &sdt_signature(table) != b"SPCR"
    {
        return None;
    }
    let interface = *table.get(SPCR_OFF_INTERFACE)?;
    let address = rd_u64(table, SPCR_OFF_ADDRESS)?;
    if address == 0
    {
        return None;
    }
    let base = match *table.get(SPCR_OFF_SPACE_ID)?
    {
        0 => SpcrBase::Mmio(address),
        1 => SpcrBase::IoPort(u16::try_from(address).ok()?),
        _ => return None,
    };
    let int_type = *table.get(SPCR_OFF_INT_TYPE)?;
    let interrupt = if int_type & 1 != 0
    {
        Some(SpcrInterrupt {
            line: u32::from(*table.get(SPCR_OFF_IRQ)?),
            isa: true,
        })
    }
    else if int_type & 0x1E != 0
    {
        Some(SpcrInterrupt {
            line: rd_u32(table, SPCR_OFF_GSI)?,
            isa: false,
        })
    }
    else
    {
        None
    };
    Some(Spcr {
        interface,
        base,
        interrupt,
    })
}

// ── Platform description table ────────────────────────────────────────

/// Devices one platform table lists.
pub const MAX_PLATFORM_DEVICES: usize = 16;
/// Longest platform key, in bytes.
pub const MAX_PLATFORM_KEY_BYTES: usize = 32;
/// Resources one platform device lists.
pub const MAX_PLATFORM_RESOURCES: usize = 4;
/// Longest platform description table, in bytes: room for
/// [`MAX_PLATFORM_DEVICES`] device lines of every resource with comments to
/// spare. A longer table is rejected whole.
pub const MAX_TABLE_BYTES: usize = 8192;
/// Longest `oem_table_id`, in bytes.
const OEM_ID_BYTES: usize = 8;

const _: () = assert!(MAX_PLATFORM_KEY_BYTES == driver_binding::decl::MAX_PLATFORM_KEY_BYTES);

/// One resource of a platform device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformResource
{
    /// A memory range.
    Mmio
    {
        /// Physical base.
        base: u64,
        /// Size in bytes.
        size: u64,
    },
    /// An I/O port range.
    IoPort
    {
        /// First port.
        base: u16,
        /// Number of ports.
        count: u16,
    },
    /// A wired interrupt line.
    Wired
    {
        /// The GSI / APLIC source.
        line: u32,
        /// `IRQ_MODE_*` bits.
        mode: u64,
    },
}

/// One device a platform table lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformDevice
{
    key: [u8; MAX_PLATFORM_KEY_BYTES],
    key_len: u8,
    resources: [Option<PlatformResource>; MAX_PLATFORM_RESOURCES],
}

impl PlatformDevice
{
    /// The device's platform key.
    #[must_use]
    pub fn key(&self) -> &[u8]
    {
        self.key.get(..usize::from(self.key_len)).unwrap_or(&[])
    }

    /// The device's resources, in table order.
    pub fn resources(&self) -> impl Iterator<Item = PlatformResource> + '_
    {
        self.resources.iter().flatten().copied()
    }
}

/// A parsed platform description table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformTable
{
    oem_table_id: [u8; OEM_ID_BYTES],
    id_len: u8,
    devices: Vec<PlatformDevice>,
}

/// Drop trailing spaces and NULs.
fn trim_field(field: &[u8]) -> &[u8]
{
    let end = field
        .iter()
        .rposition(|b| *b != b' ' && *b != 0)
        .map_or(0, |i| i.saturating_add(1));
    field.get(..end).unwrap_or(&[])
}

impl PlatformTable
{
    /// Whether this table is for the machine whose XSDT OEM table ID field is
    /// `field` (8 bytes, space-padded): equal once trailing spaces and NULs
    /// are dropped from both.
    #[must_use]
    pub fn is_for(&self, field: &[u8]) -> bool
    {
        let id = self
            .oem_table_id
            .get(..usize::from(self.id_len))
            .unwrap_or(&[]);
        trim_field(id) == trim_field(field)
    }

    /// The devices the table lists.
    #[must_use]
    pub fn devices(&self) -> &[PlatformDevice]
    {
        &self.devices
    }
}

/// Why a platform description table did not parse. Line numbers are 1-based.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError
{
    /// The table is longer than [`MAX_TABLE_BYTES`].
    TooLarge,
    /// A line has no `=`.
    MissingEquals(usize),
    /// A line names an unknown key.
    UnknownKey(usize),
    /// A key other than `device` repeats.
    DuplicateKey(usize),
    /// A required key is absent.
    MissingKey(&'static str),
    /// A value is malformed.
    InvalidValue(usize, &'static str),
    /// The device list could not grow.
    NoMemory,
}

fn number(token: Option<&str>) -> Option<u64>
{
    let token = token?;
    if !token.as_bytes().first()?.is_ascii_digit()
    {
        return None;
    }
    match token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => token.parse().ok(),
    }
}

fn printable(bytes: &[u8]) -> bool
{
    bytes.iter().all(u8::is_ascii_graphic)
}

fn parse_device(value: &str, line: usize) -> Result<PlatformDevice, TableError>
{
    let bad = |why| TableError::InvalidValue(line, why);
    let mut tokens = value.split_whitespace();
    let key = tokens.next().ok_or_else(|| bad("missing key"))?.as_bytes();
    if key.len() > MAX_PLATFORM_KEY_BYTES || !printable(key)
    {
        return Err(bad("bad key"));
    }
    let mut dev = PlatformDevice {
        key: [0; MAX_PLATFORM_KEY_BYTES],
        key_len: u8::try_from(key.len()).map_err(|_| bad("bad key"))?,
        resources: [None; MAX_PLATFORM_RESOURCES],
    };
    dev.key
        .get_mut(..key.len())
        .ok_or_else(|| bad("bad key"))?
        .copy_from_slice(key);
    let mut count = 0;
    while let Some(group) = tokens.next()
    {
        let slot = dev
            .resources
            .get_mut(count)
            .ok_or_else(|| bad("too many resources"))?;
        *slot = Some(match group
        {
            "mmio" =>
            {
                let base = number(tokens.next()).ok_or_else(|| bad("bad mmio base"))?;
                let size = number(tokens.next()).ok_or_else(|| bad("bad mmio size"))?;
                if size == 0 || base.checked_add(size).is_none()
                {
                    return Err(bad("bad mmio range"));
                }
                PlatformResource::Mmio { base, size }
            }
            "io" =>
            {
                let base = number(tokens.next())
                    .and_then(|v| u16::try_from(v).ok())
                    .ok_or_else(|| bad("bad io base"))?;
                let n = number(tokens.next())
                    .and_then(|v| u16::try_from(v).ok())
                    .ok_or_else(|| bad("bad io count"))?;
                if n == 0 || u32::from(base).saturating_add(u32::from(n)) > 0x1_0000
                {
                    return Err(bad("bad io range"));
                }
                PlatformResource::IoPort { base, count: n }
            }
            "wired" =>
            {
                let l = number(tokens.next())
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(|| bad("bad wired line"))?;
                let mode = match tokens.next()
                {
                    Some("edge-high") => 0,
                    Some("edge-low") => syscall_abi::IRQ_MODE_ACTIVE_LOW,
                    Some("level-high") => syscall_abi::IRQ_MODE_LEVEL,
                    Some("level-low") =>
                    {
                        syscall_abi::IRQ_MODE_LEVEL | syscall_abi::IRQ_MODE_ACTIVE_LOW
                    }
                    _ => return Err(bad("bad wired mode")),
                };
                PlatformResource::Wired { line: l, mode }
            }
            _ => return Err(bad("unknown resource group")),
        });
        // `get_mut(count)` above bounds `count` by the resource array.
        count = count.saturating_add(1);
    }
    Ok(dev)
}

/// Parse a platform description table, read through the `.svc` line
/// grammar (`svc_grammar::entries`).
///
/// # Errors
/// A table longer than [`MAX_TABLE_BYTES`], a line without `=`, an unknown
/// or repeated key, a missing `oem_table_id`, a malformed value, or an
/// allocation failure.
pub fn parse_table(contents: &str) -> Result<PlatformTable, TableError>
{
    if contents.len() > MAX_TABLE_BYTES
    {
        return Err(TableError::TooLarge);
    }
    let mut oem: Option<([u8; OEM_ID_BYTES], u8)> = None;
    let mut devices: Vec<PlatformDevice> = Vec::new();
    for entry in svc_grammar::entries(contents)
    {
        let svc_grammar::Entry { line, key, value } =
            entry.map_err(|svc_grammar::MissingEquals(l)| TableError::MissingEquals(l))?;
        match key
        {
            "oem_table_id" =>
            {
                if oem.is_some()
                {
                    return Err(TableError::DuplicateKey(line));
                }
                let bytes = value.as_bytes();
                if bytes.is_empty() || bytes.len() > OEM_ID_BYTES || !printable(bytes)
                {
                    return Err(TableError::InvalidValue(line, "bad oem_table_id"));
                }
                let mut id = [0u8; OEM_ID_BYTES];
                if let Some(dst) = id.get_mut(..bytes.len())
                {
                    dst.copy_from_slice(bytes);
                }
                oem = Some((id, u8::try_from(bytes.len()).unwrap_or(0)));
            }
            "device" =>
            {
                if devices.len() >= MAX_PLATFORM_DEVICES
                {
                    return Err(TableError::InvalidValue(line, "too many devices"));
                }
                let dev = parse_device(value, line)?;
                devices.try_reserve(1).map_err(|_| TableError::NoMemory)?;
                devices.push(dev);
            }
            _ => return Err(TableError::UnknownKey(line)),
        }
    }
    let (oem_table_id, id_len) = oem.ok_or(TableError::MissingKey("oem_table_id"))?;
    Ok(PlatformTable {
        oem_table_id,
        id_len,
        devices,
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn spcr_bytes() -> Vec<u8>
    {
        let mut t = vec![0u8; 80];
        t[..4].copy_from_slice(b"SPCR");
        t[4..8].copy_from_slice(&80_u32.to_le_bytes());
        t[36] = 3;
        t
    }

    #[test]
    fn spcr_memory_base_and_interrupts()
    {
        let mut t = spcr_bytes();
        t[40] = 0;
        t[44..52].copy_from_slice(&0x1000_0000_u64.to_le_bytes());
        assert_eq!(
            spcr(&t),
            Some(Spcr {
                interface: 3,
                base: SpcrBase::Mmio(0x1000_0000),
                interrupt: None
            })
        );
        t[52] = 1;
        t[53] = 4;
        assert_eq!(
            spcr(&t).and_then(|s| s.interrupt),
            Some(SpcrInterrupt { line: 4, isa: true })
        );
        for ty in [2_u8, 4, 8, 16]
        {
            t[52] = ty;
            t[54..58].copy_from_slice(&33_u32.to_le_bytes());
            assert_eq!(
                spcr(&t).and_then(|s| s.interrupt),
                Some(SpcrInterrupt {
                    line: 33,
                    isa: false
                }),
                "type {ty}"
            );
        }
    }

    #[test]
    fn spcr_io_base_and_rejects()
    {
        let mut t = spcr_bytes();
        t[40] = 1;
        t[44..52].copy_from_slice(&0x3F8_u64.to_le_bytes());
        assert_eq!(spcr(&t).map(|s| s.base), Some(SpcrBase::IoPort(0x3F8)));
        t[44..52].copy_from_slice(&0x1_0000_u64.to_le_bytes());
        assert_eq!(spcr(&t), None);
        t[44..52].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(spcr(&t), None);
        t[40] = 2;
        t[44] = 1;
        assert_eq!(spcr(&t), None);
        t[40] = 0;
        assert!(spcr(&t).is_some());
        assert_eq!(spcr(&t[..79]), None);
        t[..4].copy_from_slice(b"SPCX");
        assert_eq!(spcr(&t), None);
    }

    #[test]
    fn table_example()
    {
        let src = "# comment\n\noem_table_id = BXPC\n\
                   device = google,goldfish-rtc mmio 0x101000 0x1000 wired 11 level-high\n\
                   device = uart io 0x3f8 8\n";
        let t = parse_table(src).unwrap();
        assert!(t.is_for(b"BXPC    "));
        assert!(t.is_for(b"BXPC"));
        assert!(t.is_for(b"BXPC\0\0\0\0"));
        assert!(!t.is_for(b"BXPD    "));
        assert!(!t.is_for(b""));
        assert_eq!(t.devices().len(), 2);
        let d = &t.devices()[0];
        assert_eq!(d.key(), b"google,goldfish-rtc");
        assert_eq!(
            d.resources().collect::<Vec<_>>(),
            vec![
                PlatformResource::Mmio {
                    base: 0x10_1000,
                    size: 0x1000
                },
                PlatformResource::Wired {
                    line: 11,
                    mode: syscall_abi::IRQ_MODE_LEVEL
                },
            ]
        );
        assert_eq!(
            t.devices()[1].resources().next(),
            Some(PlatformResource::IoPort {
                base: 0x3F8,
                count: 8
            })
        );
    }

    #[test]
    fn wired_modes()
    {
        let t = parse_table(
            "oem_table_id=X\ndevice = k wired 1 edge-high wired 2 edge-low wired 3 level-high \
             wired 4 level-low\n",
        )
        .unwrap();
        let modes: Vec<u64> = t.devices()[0]
            .resources()
            .map(|r| match r
            {
                PlatformResource::Wired { mode, .. } => mode,
                _ => u64::MAX,
            })
            .collect();
        assert_eq!(
            modes,
            vec![
                0,
                syscall_abi::IRQ_MODE_ACTIVE_LOW,
                syscall_abi::IRQ_MODE_LEVEL,
                syscall_abi::IRQ_MODE_LEVEL | syscall_abi::IRQ_MODE_ACTIVE_LOW
            ]
        );
    }

    #[test]
    fn table_key_errors()
    {
        assert_eq!(
            parse_table("device = k\n"),
            Err(TableError::MissingKey("oem_table_id"))
        );
        assert_eq!(parse_table(""), Err(TableError::MissingKey("oem_table_id")));
        assert_eq!(
            parse_table("oem_table_id = A\n\noem_table_id = B\n"),
            Err(TableError::DuplicateKey(3))
        );
        assert_eq!(
            parse_table("oem_table_id = A\nfoo = 1\n"),
            Err(TableError::UnknownKey(2))
        );
        assert_eq!(
            parse_table("oem_table_id = A\njunk\n"),
            Err(TableError::MissingEquals(2))
        );
        assert!(matches!(
            parse_table("oem_table_id = \n"),
            Err(TableError::InvalidValue(1, _))
        ));
        assert!(matches!(
            parse_table("oem_table_id = ABCDEFGHI\n"),
            Err(TableError::InvalidValue(1, _))
        ));
    }

    #[test]
    fn bad_device_values()
    {
        let long_key = "k".repeat(MAX_PLATFORM_KEY_BYTES + 1);
        let cases = [
            "device = ".to_string(),
            "device = k mmio zz 4".to_string(),
            "device = k mmio 0x10 0".to_string(),
            "device = k mmio 0xFFFFFFFFFFFFFFFF 2".to_string(),
            "device = k io 0x10000 1".to_string(),
            "device = k io 0xFFFF 2".to_string(),
            "device = k io 0x10 0".to_string(),
            "device = k bogus 1".to_string(),
            "device = k wired 1 sideways".to_string(),
            "device = k wired 1".to_string(),
            "device = k wired 0x100000000 level-high".to_string(),
            format!("device = {long_key}"),
            "device = k wired 1 edge-high wired 2 edge-high wired 3 edge-high wired 4 \
             edge-high wired 5 edge-high"
                .to_string(),
        ];
        for c in cases
        {
            assert_eq!(
                parse_table(&format!("oem_table_id = A\n{c}\n")).map_err(|e| match e
                {
                    TableError::InvalidValue(l, _) => l,
                    _ => 0,
                }),
                Err(2),
                "{c}"
            );
        }
        let mut many = String::from("oem_table_id = A\n");
        for _ in 0..=MAX_PLATFORM_DEVICES
        {
            many.push_str("device = k\n");
        }
        assert_eq!(
            parse_table(&many),
            Err(TableError::InvalidValue(
                MAX_PLATFORM_DEVICES + 2,
                "too many devices"
            ))
        );
        let mut full = String::from("oem_table_id = A\n");
        for _ in 0..MAX_PLATFORM_DEVICES
        {
            full.push_str("device = k\n");
        }
        assert_eq!(
            parse_table(&full).unwrap().devices().len(),
            MAX_PLATFORM_DEVICES
        );
    }
}
