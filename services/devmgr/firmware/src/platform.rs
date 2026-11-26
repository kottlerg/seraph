// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/platform.rs

//! The platform description table.
//!
//! The ACPI Serial Port Console Redirection table (SPCR), which names the
//! console UART, is [`firmware_tables::spcr`]'s. The platform description
//! table is a text file in the `.svc` grammar of the device class files:
//! line-oriented `key = value`, `#` starts a comment line, blank lines are
//! skipped. It lists the devices a machine
//! has that no firmware table describes, and whether the machine grants
//! devmgr native control of its PCI Express hotplug slots, keyed by the
//! XSDT's OEM table ID. It is a signed object (docs/signing.md) whose body
//! is the table. devmgr reads it from the root filesystem through procmgr's
//! verified read, which returns the verified body alone, parsed by
//! [`parse_body`]; a table in the bundle reaches devmgr as a boot module,
//! which [`parse_module`] takes through the parse-only `objsig::split`, since
//! the bootloader verified the module before it exposed it.
//!
//! ```text
//! # <comment>
//! oem_table_id = BXPC
//! pcie_native_hotplug = yes
//! device = google,goldfish-rtc mmio 0x101000 0x1000 wired 11 level-high
//! ```

extern crate alloc;

use alloc::vec::Vec;

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
    /// `pcie_native_hotplug = yes`: the machine grants devmgr native
    /// control of its PCI Express hotplug slots.
    native_hotplug: bool,
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

    /// Whether the table grants devmgr native control of the machine's PCI
    /// Express hotplug slots (`pcie_native_hotplug = yes`; absent, no).
    #[must_use]
    pub const fn pcie_native_hotplug(&self) -> bool
    {
        self.native_hotplug
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

/// Why a platform description table's boot module, or the body of one,
/// did not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleError
{
    /// The module's signature trailer does not parse; its body was not read.
    /// Only [`parse_module`] reports it.
    Trailer(objsig::ParseError),
    /// The module's body is not UTF-8 text.
    NotText,
    /// The body is not a table ([`parse_table`]).
    Table(TableError),
}

/// Parse the boot module `module` of a platform description table: the table
/// its body holds, after the trailer the bootloader verified, split off with
/// the parse checks alone (docs/signing.md § Verifier Discipline).
///
/// # Errors
/// A trailer that does not parse (an unsigned module among them), a body that
/// is not UTF-8, or the [`TableError`] of a body that is not a table.
pub fn parse_module(module: &[u8]) -> Result<PlatformTable, ModuleError>
{
    let signed = objsig::split(module).map_err(ModuleError::Trailer)?;
    parse_body(signed.body())
}

/// Parse `body`, the body of a platform description table a verifier has
/// already checked, its trailer excluded: what procmgr's verified read
/// returns (docs/signing.md § Verifier Discipline).
///
/// # Errors
/// A body that is not UTF-8, or the [`TableError`] of a body that is not a
/// table.
pub fn parse_body(body: &[u8]) -> Result<PlatformTable, ModuleError>
{
    let text = core::str::from_utf8(body).map_err(|_| ModuleError::NotText)?;
    parse_table(text).map_err(ModuleError::Table)
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
    let mut native_hotplug: Option<bool> = None;
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
            "pcie_native_hotplug" =>
            {
                if native_hotplug.is_some()
                {
                    return Err(TableError::DuplicateKey(line));
                }
                native_hotplug = Some(match value
                {
                    "yes" => true,
                    "no" => false,
                    _ => return Err(TableError::InvalidValue(line, "bad pcie_native_hotplug")),
                });
            }
            _ => return Err(TableError::UnknownKey(line)),
        }
    }
    let (oem_table_id, id_len) = oem.ok_or(TableError::MissingKey("oem_table_id"))?;
    Ok(PlatformTable {
        oem_table_id,
        id_len,
        devices,
        native_hotplug: native_hotplug.unwrap_or(false),
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// `body` with a trailer that parses: one record whose signature is not
    /// checked, as the parse-only split does not check it.
    fn signed(body: &[u8]) -> Vec<u8>
    {
        let record = objsig::RecordSpec {
            signer_key_id: [1; objsig::KEY_ID_LEN],
            attrs: objsig::Attributes {
                body_len: u64::try_from(body.len()).unwrap(),
                security_version: 1,
                roles: objsig::RoleSet::of(&[objsig::Role::BootModule]),
                arch: objsig::Arch::Riscv64,
                body_hash: [0; 64],
                name: b"/config/devmgr/platform/qemu-virt.platform",
            },
            certificate: None,
            signature: &[0; objsig::composite::SIGNATURE_LEN],
        };
        let mut trailer = vec![0u8; objsig::trailer_len(&[record]).unwrap()];
        objsig::encode_trailer(body, &[record], &mut trailer).unwrap();
        [body, trailer.as_slice()].concat()
    }

    // Defect caught: a table module whose trailer is read as table lines (a
    // table refused at every boot), or an unsigned module read as a table.
    #[test]
    fn a_table_module_s_body_is_its_table()
    {
        let table = parse_module(&signed(b"oem_table_id = BXPC\n")).unwrap();
        assert!(table.is_for(b"BXPC"));
        assert_eq!(
            parse_module(b"oem_table_id = BXPC\n").map(|_| ()),
            Err(ModuleError::Trailer(objsig::ParseError::Magic))
        );
        assert_eq!(
            parse_module(&signed(b"\xff\xfe")).map(|_| ()),
            Err(ModuleError::NotText)
        );
        assert_eq!(
            parse_module(&signed(b"junk\n")).map(|_| ()),
            Err(ModuleError::Table(TableError::MissingEquals(1)))
        );
    }

    // Defect caught: a verified body read as a signed object (a table from
    // the root filesystem refused at every boot).
    #[test]
    fn a_verified_body_is_its_table()
    {
        let table = parse_body(b"oem_table_id = BXPC\npcie_native_hotplug = yes\n").unwrap();
        assert!(table.is_for(b"BXPC"));
        assert!(table.pcie_native_hotplug());
        assert_eq!(
            parse_body(b"\xff\xfe").map(|_| ()),
            Err(ModuleError::NotText)
        );
        assert_eq!(
            parse_body(b"junk\n").map(|_| ()),
            Err(ModuleError::Table(TableError::MissingEquals(1)))
        );
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
    fn the_native_hotplug_key_grants_only_when_yes()
    {
        let table = |key: &str| parse_table(&format!("oem_table_id = BXPC\n{key}")).unwrap();
        assert!(table("pcie_native_hotplug = yes\n").pcie_native_hotplug());
        assert!(!table("pcie_native_hotplug = no\n").pcie_native_hotplug());
        assert!(!table("").pcie_native_hotplug());
        assert_eq!(
            parse_table("oem_table_id = A\npcie_native_hotplug = on\n"),
            Err(TableError::InvalidValue(2, "bad pcie_native_hotplug"))
        );
        assert_eq!(
            parse_table("oem_table_id = A\npcie_native_hotplug = yes\npcie_native_hotplug = no\n"),
            Err(TableError::DuplicateKey(3))
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
                PlatformResource::Mmio { .. } | PlatformResource::IoPort { .. } => u64::MAX,
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
                    TableError::TooLarge
                    | TableError::MissingEquals(_)
                    | TableError::UnknownKey(_)
                    | TableError::DuplicateKey(_)
                    | TableError::MissingKey(_)
                    | TableError::NoMemory => 0,
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
