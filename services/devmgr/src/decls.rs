// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/decls.rs

//! Driver declarations read from the binaries devmgr may start
//! ([docs/driver-binding.md](../../../docs/driver-binding.md) § Driver
//! Declarations): the `.note.seraph.driver` note of a boot module devmgr
//! holds, and of each entry of the `/services/drivers/` directory svcmgr
//! hands it at `SET_DRIVERS_DIR`. devmgr parses no byte of a
//! drivers-directory entry that a key did not sign
//! ([docs/signing.md](../../../docs/signing.md) § Verifier Discipline):
//! [`verified_decl`] has procmgr read the file once and verify it as a driver
//! image under its install path, and reads the note from that verified run,
//! which the driver is then created from ([`VerifiedImage`]).
//!
//! init forwards its boot modules untagged; [`classify_modules`] tells each
//! by its content: an ELF executable is a driver module, and text named
//! under `boot_protocol::bundle::PLATFORM_TABLE_PREFIX` a platform
//! description table (`firmware::platform`), the name binding it to the
//! boot-module role the bootloader verified it in (docs/signing.md
//! § Configuration); anything else is released. The one exception is the
//! boot-time policy (`boot_protocol::bundle::POLICY_ENTRY_NAME`), which
//! it tells by its name and reads into `caps::DevmgrCaps::dma_confinement`
//! (docs/device-management.md § DMA Safety Model).
//!
//! The reads are bounded, as § Declaration Bounds requires: the ELF header
//! page, the section header table, the section name table, and the one note
//! section, which is read only up to [`NOTE_SECTION_BYTES`], each within the
//! module's bytes or the verified body. A binary that is not an executable of
//! this machine, or carries no declaration note, has no declaration and is
//! passed over unlogged; a note whose descriptor does not decode is logged
//! and the binary passed over.

use std::io::ErrorKind;
use std::os::seraph::{VerifiedData, VerifiedRole, reserve_pages};
use std::sync::Arc;

use driver_binding::DRIVER_NOTE_SECTION;
use driver_binding::decl::DriverDecl;
use firmware::platform::{ModuleError, PlatformTable};
use ipc::IpcMessage;
use process_abi::{NT_SERAPH_DRIVER, SERAPH_NOTE_OWNER};
use syscall_abi::PAGE_SIZE;

use crate::{arch, caps, spawn};

/// The largest declaration note section devmgr reads: one note's 20-byte
/// header and owner plus the largest descriptor the format admits, with
/// room to spare. A larger section is not read and its binary has no
/// declaration.
const NOTE_SECTION_BYTES: usize = 1024;

/// Bytes of the ELF header read: the header page, which holds the ELF
/// header and the program header table a valid executable starts with.
const HEADER_BYTES: usize = 4096;

/// The most drivers-directory entries devmgr lists: a directory server that
/// never answers `END_OF_DIR` ends the listing here.
const MAX_DIR_ENTRIES: u32 = 4096;

/// The longest entry name devmgr walks to: the namespace's own bound on a
/// name.
const MAX_ENTRY_NAME: usize = 255;

/// The first bytes of an ELF file, by which a boot module is told to be a
/// driver module rather than a platform description table.
const ELF_MAGIC: &[u8] = b"\x7fELF";

/// A drivers-directory entry procmgr read once and verified as a driver
/// image under its install path (`procmgr_labels::READ_VERIFIED` in the
/// driver role): the run that holds the file, which no process but memmgr can
/// write, the file's size in bytes, and the install path. devmgr reads the
/// declaration from the run's verified body and creates the driver from the
/// same run, which procmgr copies and verifies again, so the bytes the
/// binding chose on are the bytes that run. Dropping it unmaps the run and
/// returns it to devmgr's account.
pub struct VerifiedImage
{
    run: VerifiedData,
    size: u64,
    name: Box<[u8]>,
}

/// Where devmgr starts a driver from, with the exact size and the name
/// procmgr verifies its signature under.
pub enum Binary
{
    /// A boot module, or devmgr's own copy of one: devmgr's Memory cap on it,
    /// its size in bytes, and its bundle entry name.
    Module
    {
        cap: u64,
        size: u64,
        name: Box<[u8]>,
    },
    /// A drivers-directory entry, verified: shared by the match table and a
    /// queued create retry, and released when the last of them drops it.
    Verified(Arc<VerifiedImage>),
}

impl Binary
{
    /// A copy of the binary for one driver's create call, which consumes
    /// the cap copy; the name is borrowed. `None` when the copy cannot be
    /// derived.
    pub fn source_copy(&self) -> Option<spawn::CreateSource<'_>>
    {
        let (cap, size, name) = match self
        {
            Self::Module { cap, size, name } => (*cap, *size, &**name),
            Self::Verified(image) => (image.run.cap(), image.size, &*image.name),
        };
        syscall::cap_derive(cap, syscall::RIGHTS_ALL)
            .ok()
            .map(|cap| spawn::CreateSource { cap, size, name })
    }

    /// Delete devmgr's cap on a boot module. A retained module cap pins the
    /// donated pool run it was derived from, so every module cap is released
    /// once the boot pass ends. A verified image is released when it is
    /// dropped, so this does nothing for one.
    pub fn release(&self)
    {
        let cap = self.module_cap();
        if cap != 0
        {
            let _ = syscall::cap_delete(cap);
        }
    }

    /// The binary's name: a boot module's bundle entry name, a file's
    /// install path. A boot module is named by its install path too
    /// (docs/boot-media.md), so either is where the driver is installed.
    pub fn name(&self) -> &[u8]
    {
        match self
        {
            Self::Module { name, .. } => name,
            Self::Verified(image) => &image.name,
        }
    }

    /// devmgr's cap on a boot module, which [`Self::release`] deletes; `0`
    /// for a verified image, which holds no cap a caller deletes.
    pub const fn module_cap(&self) -> u64
    {
        match self
        {
            Self::Module { cap, .. } => *cap,
            Self::Verified(_) => 0,
        }
    }
}

/// The declaration of the binary `bytes`, a boot module's bytes or a
/// verified image's body, read within § Declaration Bounds. `name` labels
/// the log line of a rejected declaration, and of one the heap has no room to
/// read.
///
/// The header page and the note section are read into heap buffers, freed on
/// return: on the stack, their 5 KiB would sit in the frame of every caller
/// the function is inlined into, beside that caller's own spawn and listing
/// locals, on devmgr's 32 KiB main-thread stack.
fn read_decl(name: &str, bytes: &[u8]) -> Option<DriverDecl>
{
    let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let read_at = |offset: u64, dst: &mut [u8]| {
        let start = usize::try_from(offset).ok()?;
        let src = bytes.get(start..start.checked_add(dst.len())?)?;
        dst.copy_from_slice(src);
        Some(dst.len())
    };
    let mut header = zeroed(name, HEADER_BYTES)?;
    let header_len = usize::try_from(size).map_or(HEADER_BYTES, |s| s.min(HEADER_BYTES));
    let read = read_at(0, header.get_mut(..header_len)?)?;
    let (ehdr, _) = elf::validate_executable(
        header.get(..read.min(header_len))?,
        arch::current::ELF_MACHINE,
    )
    .ok()?;
    let mut section = zeroed(name, NOTE_SECTION_BYTES)?;
    let desc = elf::find_note_streaming(
        &ehdr,
        size,
        DRIVER_NOTE_SECTION,
        SERAPH_NOTE_OWNER,
        NT_SERAPH_DRIVER,
        &mut section,
        read_at,
    )?;
    match driver_binding::decl::decode(section.get(desc)?)
    {
        Ok(decl) => Some(decl),
        Err(e) =>
        {
            std::os::seraph::log!(warn: "{}: driver declaration rejected ({:?})", name, e);
            None
        }
    }
}

/// A heap buffer of `len` zero bytes for [`read_decl`]; `None`, logged with
/// `name`, when the heap cannot hold it.
fn zeroed(name: &str, len: usize) -> Option<Vec<u8>>
{
    let mut buf = Vec::new();
    if buf.try_reserve_exact(len).is_err()
    {
        std::os::seraph::log!(warn: "{}: no memory to read the driver declaration", name);
        return None;
    }
    buf.resize(len, 0);
    Some(buf)
}

/// The boot modules init forwarded, told apart by their content
/// ([`classify_modules`]).
pub struct BootModules
{
    /// Each driver module with its declaration, as a [`Binary::Module`] of
    /// its size and bundle entry name; devmgr keeps the module cap until a
    /// bind pass consumes or releases it.
    pub drivers: Vec<(DriverDecl, Binary)>,
    /// Each platform description table, parsed; its module cap is released.
    pub tables: Vec<PlatformTable>,
}

/// Take every boot module of `caps` and tell each by its content and
/// name: an ELF executable is a driver module, kept with its declaration; a
/// module named under `boot_protocol::bundle::PLATFORM_TABLE_PREFIX` is a
/// platform description table, parsed from its body
/// ([`firmware::platform::parse_module`]) and released. The name binds a
/// table to the boot-module role the bootloader verified it in, so a key
/// trusted for configuration alone supplies none. A driver module with
/// no declaration, and a module that is neither, are logged and released, as
/// is every module when the lists cannot grow. The boot-time policy module,
/// told by its name, sets `caps.dma_confinement` and is released; with none,
/// or one that does not parse, the setting stays required
/// (`boot_policy::Policy::FAIL_CLOSED`). The setting is logged.
pub fn classify_modules(caps: &mut caps::DevmgrCaps) -> BootModules
{
    let mut out = BootModules {
        drivers: Vec::new(),
        tables: Vec::new(),
    };
    let mut policy = None;
    let mut policy_seen = false;
    for module in core::mem::take(&mut caps.modules)
    {
        let module_cap = module.cap;
        if *module.name == *boot_protocol::bundle::POLICY_ENTRY_NAME
        {
            policy_seen = true;
            policy = with_module(caps, module_cap, module.size, read_policy).flatten();
            let _ = syscall::cap_delete(module_cap);
            continue;
        }
        match with_module(caps, module_cap, module.size, |bytes| {
            classify(&module.name, bytes)
        })
        {
            Some(Classified::Driver(decl)) if out.drivers.try_reserve(1).is_ok() =>
            {
                out.drivers.push((
                    decl,
                    Binary::Module {
                        cap: module_cap,
                        size: module.size,
                        name: module.name,
                    },
                ));
                continue;
            }
            Some(Classified::Table(table)) if out.tables.try_reserve(1).is_ok() =>
            {
                out.tables.push(table);
            }
            Some(Classified::Driver(_) | Classified::Table(_)) =>
            {
                std::os::seraph::log!(warn: "boot module: no memory to record it; released");
            }
            Some(Classified::Neither) | None =>
            {}
        }
        let _ = syscall::cap_delete(module_cap);
    }
    if !policy_seen
    {
        std::os::seraph::log!(error: "boot policy: no policy module; every requirement on");
    }
    let policy = policy.unwrap_or(boot_policy::Policy::FAIL_CLOSED);
    caps.dma_confinement = policy.dma_confinement;
    std::os::seraph::log!(
        "boot policy: {} = {}",
        boot_policy::DmaConfinement::KEY,
        policy.dma_confinement.value()
    );
    out
}

/// The boot-time policy the policy module `bytes` holds; `None`, logged,
/// when it is refused, so every requirement holds.
fn read_policy(bytes: &[u8]) -> Option<boot_policy::Policy>
{
    match boot_policy::parse_module(bytes)
    {
        Ok(policy) => Some(policy),
        Err(boot_policy::ModuleError::Trailer(e)) =>
        {
            std::os::seraph::log!(
                error: "boot policy: not a signed object ({:?}); every requirement on",
                e
            );
            None
        }
        Err(boot_policy::ModuleError::Policy(e)) =>
        {
            std::os::seraph::log!(error: "boot policy: refused ({}); every requirement on", e);
            None
        }
    }
}

/// What a boot module's content is.
#[expect(
    clippy::large_enum_variant,
    reason = "one value lives at a time, on the stack, for one module; boxing the declaration \
              would add an allocation that cannot fail softly"
)]
enum Classified
{
    Driver(DriverDecl),
    Table(PlatformTable),
    /// Logged by [`classify`].
    Neither,
}

/// Tell the boot module `name` by its bytes: an ELF executable by its
/// magic, its declaration read within § Declaration Bounds; a module named
/// as a platform description table (`bundle::is_platform_table`) as one,
/// the body of a signed object; anything else as neither.
fn classify(name: &[u8], bytes: &[u8]) -> Classified
{
    if bytes.starts_with(ELF_MAGIC)
    {
        if let Some(decl) = read_decl("boot module", bytes)
        {
            return Classified::Driver(decl);
        }
        std::os::seraph::log!(warn: "boot module: an executable with no declaration; released");
        return Classified::Neither;
    }
    if !boot_protocol::bundle::is_platform_table(name)
    {
        std::os::seraph::log!(
            warn: "boot module: neither an executable nor named as a platform table; released"
        );
        return Classified::Neither;
    }
    match firmware::platform::parse_module(bytes)
    {
        Ok(table) => Classified::Table(table),
        Err(ModuleError::Trailer(e)) =>
        {
            std::os::seraph::log!(
                warn: "boot module: neither an executable nor a signed table ({:?}); released",
                e
            );
            Classified::Neither
        }
        Err(ModuleError::NotText) =>
        {
            std::os::seraph::log!(
                warn: "boot module: neither an executable nor a text table; released"
            );
            Classified::Neither
        }
        Err(ModuleError::Table(e)) =>
        {
            std::os::seraph::log!(warn: "boot module: platform table rejected ({:?}); released", e);
            Classified::Neither
        }
    }
}

/// Call `read` on the `module_bytes` bytes of the boot module `module_cap`,
/// mapped read-only, whole, for the call and unmapped after; `None`, logged,
/// when the module cannot be mapped. The cap covers whole pages: the bytes
/// past `module_bytes` are not the module's, and `read` never sees them.
pub fn with_module<R>(
    caps: &caps::DevmgrCaps,
    module_cap: u64,
    module_bytes: u64,
    read: impl FnOnce(&[u8]) -> R,
) -> Option<R>
{
    let size = syscall::cap_info(module_cap, syscall::CAP_INFO_MEMORY_SIZE).ok()?;
    let pages = size.div_ceil(PAGE_SIZE);
    let span = usize::try_from(module_bytes.min(size)).ok()?;
    if pages == 0
    {
        return None;
    }
    let Ok(range) = reserve_pages(pages)
    else
    {
        std::os::seraph::log!(warn: "boot module: no VA to read it");
        return None;
    };
    let va = range.va_start();
    // SAFETY: `range` is a fresh reservation of `pages` pages from the
    // per-process arena, owned here: VA no Rust object or IPC page occupies.
    let mapped = unsafe {
        std::os::seraph::mem_map_funded(
            module_cap,
            caps.self_aspace,
            va,
            0,
            pages,
            syscall_abi::MAP_READ,
        )
    };
    if mapped.is_err()
    {
        std::os::seraph::log!(warn: "boot module: not mapped; not read");
        // SAFETY: the span is this call's own reservation, which no
        // reference reaches.
        unsafe { crate::unmap_window(caps.self_aspace, range) };
        return None;
    }
    // SAFETY: `span` bytes, at most `pages` pages, are mapped read-only from
    // `va` above, and nothing writes the module while it is mapped: init
    // handed devmgr the module and keeps no writable mapping of it.
    let bytes = unsafe { core::slice::from_raw_parts(va as *const u8, span) };
    let out = read(bytes);
    // SAFETY: the span is this call's own reservation, and `bytes`, the only
    // reference into it, is not used past `read`, whose result borrows none
    // of it.
    unsafe { crate::unmap_window(caps.self_aspace, range) };
    Some(out)
}

/// Have procmgr read the drivers-directory entry `file_cap`, `size` bytes
/// long (the walk's size hint), and verify it as a driver image under its
/// install path `install` (`std::os::seraph::read_verified` in
/// [`VerifiedRole::Driver`]), then read its declaration from the verified
/// body alone. The file cap moves to procmgr on every path. `label` names
/// the entry in the log.
///
/// Returns the declaration and the image as a [`Binary::Verified`] the
/// driver is created from. `None` when the file does not verify, which
/// procmgr logs, so devmgr adds no line of its own; when it is empty or past
/// `READ_VERIFIED_IMAGE_MAX` by the size hint, or cannot be read, logged; or
/// when its body declares no driver ([`read_decl`]), the run then released.
pub fn verified_decl(
    label: &str,
    file_cap: u64,
    size: u64,
    install: Box<[u8]>,
) -> Option<(DriverDecl, Binary)>
{
    if size == 0 || size > ipc::procmgr_labels::READ_VERIFIED_IMAGE_MAX
    {
        std::os::seraph::log!(warn: "{}: {} bytes, past a driver image's bound; skipped", label, size);
        let _ = syscall::cap_delete(file_cap);
        return None;
    }
    let Ok(path) = core::str::from_utf8(&install)
    else
    {
        std::os::seraph::log!(warn: "{}: install path not UTF-8; skipped", label);
        let _ = syscall::cap_delete(file_cap);
        return None;
    };
    let run = match std::os::seraph::read_verified(file_cap, size, path, VerifiedRole::Driver)
    {
        Ok(run) => run,
        Err(e) if e.kind() == ErrorKind::InvalidData => return None,
        Err(e) =>
        {
            std::os::seraph::log!(warn: "{}: driver image not read ({:?}); skipped", label, e.kind());
            return None;
        }
    };
    let decl = read_decl(label, run.bytes())?;
    let image = VerifiedImage {
        run,
        size,
        name: install,
    };
    Some((decl, Binary::Verified(Arc::new(image))))
}

/// Call `visit` with the name of each entry of the directory `dir_cap`
/// names, in the server's order (`NS_READDIR`), up to [`MAX_DIR_ENTRIES`];
/// the listing ends at `END_OF_DIR` or any error reply.
pub fn list_dir(dir_cap: u64, ipc_buf: *mut u64, mut visit: impl FnMut(&[u8]))
{
    for index in 0..MAX_DIR_ENTRIES
    {
        let msg = IpcMessage::builder(ipc::ns_labels::NS_READDIR)
            .word(0, u64::from(index))
            .build();
        // SAFETY: `ipc_buf` is devmgr's registered IPC buffer.
        let Ok(reply) = (unsafe { ipc::ipc_call(dir_cap, &msg, ipc_buf) })
        else
        {
            return;
        };
        for &cap in reply.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        if reply.label != 0
        {
            return;
        }
        let name_len = usize::try_from(reply.word(1)).unwrap_or(usize::MAX);
        let data = reply.data_bytes();
        let Some(name) = data
            .get(core::mem::size_of::<[u64; 2]>()..)
            .and_then(|bytes| bytes.get(..name_len))
            .filter(|name| !name.is_empty() && name.len() <= MAX_ENTRY_NAME)
        else
        {
            continue;
        };
        let mut copy = [0u8; MAX_ENTRY_NAME];
        let Some(out) = copy.get_mut(..name.len())
        else
        {
            continue;
        };
        out.copy_from_slice(name);
        visit(out);
    }
}
