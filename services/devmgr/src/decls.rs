// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/decls.rs

//! Driver declarations read from the binaries devmgr may start
//! ([docs/driver-binding.md](../../../docs/driver-binding.md) § Driver
//! Declarations): the `.note.seraph.driver` note of a boot module devmgr
//! holds, and of each entry of the `/services/drivers/` directory svcmgr
//! hands it at `SET_DRIVERS_DIR`.
//!
//! init forwards its boot modules untagged; [`classify_modules`] tells each
//! by its content: an ELF executable is a driver module, anything else a
//! platform description table (`firmware::platform`).
//!
//! The reads are bounded, as § Declaration Bounds requires: the ELF header
//! page, the section header table, the section name table, and the one note
//! section, which is read only up to [`NOTE_SECTION_BYTES`]. A binary that is
//! not an executable of this machine, or carries no declaration note, has no
//! declaration and is passed over unlogged; a note whose descriptor does not
//! decode is logged and the binary passed over.

use driver_binding::DRIVER_NOTE_SECTION;
use driver_binding::decl::DriverDecl;
use firmware::platform::{ModuleError, PlatformTable};
use ipc::{IpcMessage, memmgr_errors, memmgr_labels};
use process_abi::{NT_SERAPH_DRIVER, SERAPH_NOTE_OWNER};
use std::os::seraph::{reserve_pages, startup_info};
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

/// Payload bytes one `FS_READ` reply carries: the IPC data words less the
/// count word.
const FS_READ_CHUNK: usize = 504;

/// The most drivers-directory entries devmgr lists: a directory server that
/// never answers `END_OF_DIR` ends the listing here.
const MAX_DIR_ENTRIES: u32 = 4096;

/// The longest entry name devmgr walks to: the namespace's own bound on a
/// name.
const MAX_ENTRY_NAME: usize = 255;

/// The first bytes of an ELF file, by which a boot module is told to be a
/// driver module rather than a platform description table.
const ELF_MAGIC: &[u8] = b"\x7fELF";

/// Where devmgr starts a driver from, with the exact size and the name
/// procmgr verifies its signature under.
pub enum Binary
{
    /// A boot module: devmgr's Memory cap on it (the module's own, or a
    /// derivation of the copy devmgr keeps of it, [`BootImage`]), its size
    /// in bytes, and its bundle entry name.
    Module
    {
        cap: u64,
        size: u64,
        name: Box<[u8]>,
    },
    /// A drivers-directory entry: the file node cap the walk returned, its
    /// size, and its install path (the directory's path and the entry name).
    File
    {
        cap: u64,
        size: u64,
        name: Box<[u8]>,
    },
}

impl Binary
{
    /// A copy of the binary for one driver's create call, which consumes
    /// the cap copy; the name is borrowed. `None` when the copy cannot be
    /// derived.
    pub fn source_copy(&self) -> Option<spawn::CreateSource<'_>>
    {
        match self
        {
            Self::Module { cap, size, name } => syscall::cap_derive(*cap, syscall::RIGHTS_ALL)
                .ok()
                .map(|cap| spawn::CreateSource::Module {
                    cap,
                    size: *size,
                    name,
                }),
            Self::File { cap, size, name } => syscall::cap_derive(*cap, syscall::RIGHTS_ALL)
                .ok()
                .map(|file_cap| spawn::CreateSource::File {
                    file_cap,
                    size: *size,
                    name,
                }),
        }
    }

    /// Delete devmgr's cap on the binary. A retained module cap pins the
    /// donated pool run it was derived from, so every module cap is released
    /// once the boot pass ends; a derivation of a kept boot image is released
    /// once the pass it was made for ends ([`BootImage::module`]).
    pub fn release(&self)
    {
        let _ = syscall::cap_delete(self.cap());
    }

    /// devmgr's cap on the binary.
    pub const fn cap(&self) -> u64
    {
        match self
        {
            Self::Module { cap, .. } | Self::File { cap, .. } => *cap,
        }
    }
}

/// The declaration of a binary of `size` bytes that `read_at` reads,
/// `read_at(offset, dst)` filling `dst` from byte `offset` and returning the
/// bytes it copied. `name` labels the log line of a rejected declaration, and
/// of one the heap has no room to read.
///
/// The header page and the note section are read into heap buffers, freed on
/// return: on the stack, their 5 KiB would sit in the frame of every caller
/// the function is inlined into, beside that caller's own spawn and listing
/// locals, on devmgr's 32 KiB main-thread stack.
fn read_decl(
    name: &str,
    size: u64,
    mut read_at: impl FnMut(u64, &mut [u8]) -> Option<usize>,
) -> Option<DriverDecl>
{
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

/// Take every boot module of `caps` and tell each by its content: an ELF
/// executable is a driver module, kept with its declaration; any other
/// module is a platform description table, parsed from its body
/// ([`firmware::platform::parse_module`]) and released. A driver module with
/// no declaration, and a module that is neither, are logged and released, as
/// is every module when the lists cannot grow.
pub fn classify_modules(caps: &mut caps::DevmgrCaps) -> BootModules
{
    let mut out = BootModules {
        drivers: Vec::new(),
        tables: Vec::new(),
    };
    for module in core::mem::take(&mut caps.modules)
    {
        let module_cap = module.cap;
        match with_module(caps, module_cap, module.size, classify)
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
    out
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

/// Tell a boot module by its bytes: an ELF executable by its magic, its
/// declaration read within § Declaration Bounds; anything else as a
/// platform description table, the body of a signed object.
fn classify(bytes: &[u8]) -> Classified
{
    if bytes.starts_with(ELF_MAGIC)
    {
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let decl = read_decl("boot module", size, |offset, dst| {
            let start = usize::try_from(offset).ok()?;
            let src = bytes.get(start..start.checked_add(dst.len())?)?;
            dst.copy_from_slice(src);
            Some(dst.len())
        });
        if let Some(decl) = decl
        {
            return Classified::Driver(decl);
        }
        std::os::seraph::log!(warn: "boot module: an executable with no declaration; released");
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
fn with_module<R>(
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

/// A boot driver module devmgr keeps for its life, so that a function a
/// hotplug arrival appends is bound from the boot bundle's declarations as it
/// would have been at boot ([docs/driver-binding.md](../../../docs/driver-binding.md)
/// § Hotplug): a copy of the module's signed object, in one contiguous grant
/// devmgr takes from memmgr, with the module's declaration and bundle entry
/// name ([`keep_images`]). The module cap itself is released with the others
/// when the boot pass ends, since held it would pin the pool run init donated
/// it from (`spawn::ModuleCapGuard`). procmgr copies every create's object
/// into frames of its own and verifies the copy under the name the create
/// gives (docs/signing.md § Verifier Discipline), so a driver started from the
/// copy is verified as one started from the module: the signed boot object
/// under its bundle entry name, or nothing.
pub struct BootImage
{
    decl: DriverDecl,
    /// devmgr's cap on the grant that holds the copy.
    cap: u64,
    /// The object's size in bytes, the module's.
    size: u64,
    /// The module's bundle entry name.
    name: Box<[u8]>,
}

impl BootImage
{
    /// The image's declaration with a [`Binary::Module`] on a derivation of
    /// its copy, for one bind pass, which releases the derivation
    /// (`bind::boot_pass`); `None`, logged, when the derivation or the
    /// name's copy cannot be had.
    pub fn module(&self) -> Option<(DriverDecl, Binary)>
    {
        let mut name = Vec::new();
        if name.try_reserve_exact(self.name.len()).is_err()
        {
            std::os::seraph::log!(
                warn: "{}: no memory to consider the boot image; not bound",
                self.decl.name.as_str()
            );
            return None;
        }
        name.extend_from_slice(&self.name);
        let Ok(cap) = syscall::cap_derive(self.cap, syscall::RIGHTS_ALL)
        else
        {
            std::os::seraph::log!(
                warn: "{}: boot image not derived; not bound",
                self.decl.name.as_str()
            );
            return None;
        };
        Some((
            self.decl,
            Binary::Module {
                cap,
                size: self.size,
                name: name.into_boxed_slice(),
            },
        ))
    }
}

/// Keep a copy ([`BootImage`]) of each boot driver module of `modules` whose
/// declaration carries a PCI key ([`firmware::binding::pci_keyed`]), the
/// only declarations a hot-added function's record can match. A module that
/// cannot be copied (memmgr refuses the grant, or a mapping fails) is logged
/// and not kept: its boot devices are bound as before, and a hot-added
/// function only from the drivers directory. `ipc_buf` is devmgr's
/// registered IPC buffer.
pub fn keep_images(
    caps: &caps::DevmgrCaps,
    modules: &[(DriverDecl, Binary)],
    ipc_buf: *mut u64,
) -> Vec<BootImage>
{
    let mut images = Vec::new();
    for (decl, binary) in modules
    {
        let Binary::Module { cap, size, name } = binary
        else
        {
            continue;
        };
        if !firmware::binding::pci_keyed(decl)
        {
            continue;
        }
        if images.try_reserve(1).is_err()
        {
            std::os::seraph::log!(
                warn: "{}: no memory to keep the boot image; a hot-added device binds only from \
                       the drivers directory",
                decl.name.as_str()
            );
            continue;
        }
        if let Some(image) = copy_module(caps, decl, *cap, *size, name, ipc_buf)
        {
            std::os::seraph::log!(
                debug: "{}: boot image kept ({} bytes)",
                decl.name.as_str(),
                size
            );
            images.push(image);
        }
    }
    images
}

/// Copy the `size`-byte object of the boot module `module_cap` into one
/// contiguous grant from memmgr (`REQUIRE_CONTIGUOUS`, so the copy is one
/// Memory cap, as a `CREATE_PROCESS` object is), the grant mapped writable
/// for the copy and unmapped after. `None`, logged under the declaration's
/// name, when memmgr refuses the grant or answers it malformed, or a mapping
/// fails; a grant taken is returned to memmgr.
fn copy_module(
    caps: &caps::DevmgrCaps,
    decl: &DriverDecl,
    module_cap: u64,
    size: u64,
    name: &[u8],
    ipc_buf: *mut u64,
) -> Option<BootImage>
{
    let label = decl.name.as_str();
    let pages = size.div_ceil(PAGE_SIZE);
    let mut kept_name = Vec::new();
    let want = u32::try_from(pages).ok().filter(|&p| p != 0);
    let (Some(want), Ok(())) = (want, kept_name.try_reserve_exact(name.len()))
    else
    {
        std::os::seraph::log!(warn: "{}: boot image not kept (size or memory)", label);
        return None;
    };
    kept_name.extend_from_slice(name);
    let msg = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(
            0,
            u64::from(want) | (u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32),
        )
        .build();
    // SAFETY: `ipc_buf` is devmgr's registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(startup_info().memmgr_endpoint, &msg, ipc_buf) })
    else
    {
        std::os::seraph::log!(warn: "{}: boot image not kept: memmgr call failed", label);
        return None;
    };
    let layout = ipc::memmgr_grant_layout(&reply);
    let grant = match (layout, reply.caps())
    {
        (Some((&[count], &[region])), &[cap]) if count == pages => Some((cap, region)),
        _ => None,
    };
    let Some((cap, region)) = grant
    else
    {
        for &c in reply.caps()
        {
            let _ = syscall::cap_delete(c);
        }
        if let Some((_, regions)) = layout
        {
            release_regions(regions, ipc_buf);
        }
        if reply.label == memmgr_errors::SUCCESS
        {
            std::os::seraph::log!(warn: "{}: boot image not kept: malformed memmgr grant", label);
        }
        else
        {
            std::os::seraph::log!(
                warn: "{}: boot image not kept: memmgr refused {} contiguous pages ({})",
                label,
                pages,
                reply.label
            );
        }
        return None;
    };
    let copied = with_module(caps, module_cap, size, |bytes| {
        u64::try_from(bytes.len()) == Ok(size) && fill(caps.self_aspace, cap, pages, bytes)
    });
    if copied != Some(true)
    {
        let _ = syscall::cap_delete(cap);
        release_regions(&[region], ipc_buf);
        std::os::seraph::log!(warn: "{}: boot image not kept: the copy failed", label);
        return None;
    }
    Some(BootImage {
        decl: *decl,
        cap,
        size,
        name: kept_name.into_boxed_slice(),
    })
}

/// Map the `pages`-page grant `cap` writable in devmgr's address space
/// `aspace` at fresh VA, copy `bytes` to its start, and unmap it. Returns
/// whether the copy was made: `false` when `bytes` exceeds the grant, or
/// the reservation or the mapping fails.
fn fill(aspace: u64, cap: u64, pages: u64, bytes: &[u8]) -> bool
{
    let fits = u64::try_from(bytes.len())
        .ok()
        .zip(pages.checked_mul(PAGE_SIZE))
        .is_some_and(|(len, room)| len <= room);
    if !fits
    {
        return false;
    }
    let Ok(range) = reserve_pages(pages)
    else
    {
        return false;
    };
    let va = range.va_start();
    // SAFETY: `range` is a fresh reservation of `pages` pages from the
    // per-process arena, owned here: VA no Rust object or IPC page occupies.
    let mapped = unsafe {
        std::os::seraph::mem_map_funded(cap, aspace, va, 0, pages, syscall::MAP_WRITABLE)
    };
    if mapped.is_ok()
    {
        // SAFETY: the grant's `pages` pages are mapped writable from `va`,
        // and `bytes.len()` is within them; the grant is devmgr's alone, so
        // nothing else maps it, and `bytes`, the module's read-only mapping,
        // lies in another reservation, so the two do not overlap.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), va as *mut u8, bytes.len()) };
    }
    // SAFETY: the span is this call's own reservation, which no reference
    // reaches: the copy above wrote it through a raw pointer.
    unsafe { crate::unmap_window(aspace, range) };
    mapped.is_ok()
}

/// Return the memmgr grants `regions` names (`RELEASE_MEMORY_CAPS`), every
/// cap on them already deleted; memmgr takes a region back once no cap names
/// it and it is mapped nowhere.
fn release_regions(regions: &[u64], ipc_buf: *mut u64)
{
    if regions.is_empty()
    {
        return;
    }
    let msg = IpcMessage::builder(memmgr_labels::RELEASE_MEMORY_CAPS)
        .word(0, u64::try_from(regions.len()).unwrap_or(0))
        .words(1, regions)
        .build();
    // SAFETY: `ipc_buf` is devmgr's registered IPC buffer.
    let _ = unsafe { ipc::ipc_call(startup_info().memmgr_endpoint, &msg, ipc_buf) };
}

/// The declaration of the drivers-directory entry `name`, whose file node
/// cap `file_cap` (of `size` bytes) the walk returned; read through
/// `FS_READ` on the node cap.
pub fn file_decl(name: &str, file_cap: u64, size: u64, ipc_buf: *mut u64) -> Option<DriverDecl>
{
    read_decl(name, size, |offset, dst| {
        firmware::image::fill(dst, offset, FS_READ_CHUNK, |at, window| {
            fs_read(file_cap, at, window, ipc_buf)
        })
    })
}

/// One `FS_READ` of `dst.len()` bytes at `offset` on `file_cap`: copies at
/// most `dst.len()` payload bytes into `dst` and returns the count the
/// server reported. Any cap the untrusted reply carries is deleted.
fn fs_read(file_cap: u64, offset: u64, dst: &mut [u8], ipc_buf: *mut u64) -> Option<usize>
{
    let msg = IpcMessage::builder(ipc::fs_labels::FS_READ)
        .word(0, offset)
        .word(1, u64::try_from(dst.len()).ok()?)
        .build();
    // SAFETY: `ipc_buf` is devmgr's registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) }.ok()?;
    for &cap in reply.caps()
    {
        let _ = syscall::cap_delete(cap);
    }
    if reply.label != 0
    {
        return None;
    }
    let reported = usize::try_from(reply.word(0)).ok()?;
    let data = reply.data_bytes();
    let payload = data.get(core::mem::size_of::<u64>()..).unwrap_or(&[]);
    let copied = reported.min(dst.len()).min(payload.len());
    if let (Some(out), Some(src)) = (dst.get_mut(..copied), payload.get(..copied))
    {
        out.copy_from_slice(src);
    }
    Some(reported)
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
