// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/symbolize/store.rs

//! The symbols store: the unstripped link output of every image a build
//! installs, each in a file named by the image's build id, and a manifest
//! naming the store file of each installed image (docs/build-system.md
//! § Symbols Store).
//!
//! The build installs every image but the kernel and the bootloader without
//! its symbol table and debug information, so a host tool that resolves an
//! address in an installed image reads the symbols here: it takes the
//! image's build id from the GNU build-id note the linker writes into every
//! ELF image, and reads `<build-id>.elf`, refused unless that file's own
//! build id is the image's ([`symbols_for`]). The x86-64 bootloader, a PE
//! image whose symbols are in its PDB, is keyed by the `CodeView` record the
//! linker writes into it, the PDB's GUID and age, and its PDB is kept as
//! `<key>.pdb`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use object::{BinaryFormat, Object as _};

use crate::arch::Arch;
use crate::error::{Context as _, Result, bail};

/// The manifest's file name in the store.
pub const MANIFEST: &str = "manifest";

/// The start of the manifest's first line, which the architecture follows.
const ARCH_LINE: &str = "arch ";

/// The build id of the ELF image `data`, the descriptor of its GNU build-id
/// note in lowercase hex; `None` for data that is not an ELF image or that
/// carries no such note. Data past the ELF's own, such as a signature
/// trailer, is ignored.
pub fn build_id(data: &[u8]) -> Option<String>
{
    let file = object::File::parse(data).ok()?;
    if file.format() != BinaryFormat::Elf
    {
        return None;
    }
    let id = file.build_id().ok()??;
    (!id.is_empty()).then(|| lower_hex(id))
}

/// The key of the PE image `data`: the GUID of its `CodeView` record in the
/// form symbol servers name a PDB by (its first three fields as
/// little-endian integers, then its last eight bytes, in uppercase hex),
/// followed by the record's age; `None` for data that is not a PE image or
/// that carries no such record.
pub fn pdb_key(data: &[u8]) -> Option<String>
{
    let file = object::File::parse(data).ok()?;
    if file.format() != BinaryFormat::Pe
    {
        return None;
    }
    let info = file.pdb_info().ok()??;
    let guid = info.guid();
    let (first, rest) = guid.split_first_chunk::<4>()?;
    let (second, rest) = rest.split_first_chunk::<2>()?;
    let (third, last) = rest.split_first_chunk::<2>()?;
    Some(format!(
        "{:08X}{:04X}{:04X}{}{:X}",
        u32::from_le_bytes(*first),
        u16::from_le_bytes(*second),
        u16::from_le_bytes(*third),
        lower_hex(last).to_uppercase(),
        info.age()
    ))
}

/// `bytes` in lowercase hex.
pub fn lower_hex(bytes: &[u8]) -> String
{
    bytes.iter().fold(String::new(), |mut text, b| {
        let _ = write!(text, "{b:02x}");
        text
    })
}

/// Whether the ELF image `data` carries symbols of its own: a symbol table
/// or DWARF.
pub fn has_symbols(data: &[u8]) -> bool
{
    object::File::parse(data).is_ok_and(|file| {
        file.symbol_table().is_some() || file.section_by_name(".debug_info").is_some()
    })
}

/// The store file name of the ELF image whose build id is `id`.
pub fn elf_name(id: &str) -> String
{
    format!("{id}.elf")
}

/// Where the symbols of an image were found.
#[derive(Debug, PartialEq, Eq)]
pub enum Symbols
{
    /// In the store's file `name`, whose bytes are `elf`.
    Store
    {
        name: String, elf: Vec<u8>
    },
    /// In the image itself, which carries its own symbol table or DWARF.
    Image,
}

/// The symbols of the ELF image `image`: the image itself when it carries
/// its own symbol table or DWARF, as the kernel's installed image does;
/// otherwise the store file of its build id, which `read` returns
/// (`Ok(None)` when the store has none), accepted only when its own build id
/// is the image's.
///
/// # Errors
///
/// The image carries neither symbols nor a build id; the store has no file
/// of its build id, or that file carries another build id or none; `read`
/// fails.
pub fn symbols_for(
    image: &[u8],
    read: impl FnOnce(&str) -> std::result::Result<Option<Vec<u8>>, String>,
) -> std::result::Result<Symbols, String>
{
    if has_symbols(image)
    {
        return Ok(Symbols::Image);
    }
    let Some(id) = build_id(image)
    else
    {
        return Err("the image carries no symbols and no build-id note".to_owned());
    };
    let name = elf_name(&id);
    let Some(elf) = read(&name)?
    else
    {
        return Err(format!(
            "the image carries no symbols, and the symbols store has no {name}"
        ));
    };
    match build_id(&elf)
    {
        Some(stored) if stored == id => Ok(Symbols::Store { name, elf }),
        Some(stored) => Err(format!(
            "the symbols store's {name} has build id {stored}, not the image's: it holds another \
             image's symbols"
        )),
        None => Err(format!(
            "the symbols store's {name} carries no build-id note"
        )),
    }
}

/// The store's manifest: the architecture of its images, and the store
/// file of each installed image, by install path.
#[derive(Debug, PartialEq, Eq)]
pub struct Manifest
{
    pub arch: String,
    pub files: BTreeMap<String, String>,
}

impl Manifest
{
    /// Parse the manifest text: the line `arch <arch>`, then one line per
    /// image, its install path and its store file name.
    ///
    /// # Errors
    ///
    /// The first line is not the architecture's, or a later line is not
    /// two words.
    pub fn parse(text: &str) -> std::result::Result<Self, String>
    {
        let mut lines = text.lines();
        let arch = lines
            .next()
            .and_then(|line| line.strip_prefix(ARCH_LINE))
            .filter(|arch| !arch.is_empty() && !arch.contains(' '))
            .ok_or("the manifest does not start with its architecture line")?
            .to_owned();
        let mut files = BTreeMap::new();
        for line in lines
        {
            let mut words = line.split(' ');
            match (words.next(), words.next(), words.next())
            {
                (Some(path), Some(file), None) if !path.is_empty() && !file.is_empty() =>
                {
                    files.insert(path.to_owned(), file.to_owned());
                }
                _ =>
                {
                    return Err(format!(
                        "a manifest line is not a path and a file: {line:?}"
                    ));
                }
            }
        }
        Ok(Manifest { arch, files })
    }

    /// The manifest's text, as [`Manifest::parse`] reads it, its images in
    /// install-path order.
    pub fn render(&self) -> String
    {
        let mut text = format!("{ARCH_LINE}{}\n", self.arch);
        for (path, file) in &self.files
        {
            let _ = writeln!(text, "{path} {file}");
        }
        text
    }
}

/// A symbols store: a directory of symbol files and its [`MANIFEST`].
pub struct Store
{
    dir: PathBuf,
}

impl Store
{
    pub fn at(dir: impl Into<PathBuf>) -> Self
    {
        Store { dir: dir.into() }
    }

    /// The store file `name`'s bytes, `Ok(None)` when the store has none.
    ///
    /// # Errors
    ///
    /// The file exists but cannot be read.
    pub fn read(&self, name: &str) -> std::result::Result<Option<Vec<u8>>, String>
    {
        let path = self.dir.join(name);
        match std::fs::read(&path)
        {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(format!("cannot read {}: {err}", path.display())),
        }
    }

    /// The symbols of the ELF image `image` in this store ([`symbols_for`]).
    ///
    /// # Errors
    ///
    /// As [`symbols_for`].
    pub fn symbols(&self, image: &[u8]) -> std::result::Result<Symbols, String>
    {
        symbols_for(image, |name| self.read(name))
    }

    /// The path of the ELF that holds the symbols of the image at `image`:
    /// its file in this store, or `image` itself ([`symbols_for`]).
    ///
    /// # Errors
    ///
    /// The image cannot be read, or [`symbols_for`] fails.
    pub fn symbols_path(&self, image: &Path) -> Result<PathBuf>
    {
        let data = std::fs::read(image).with_context(|| format!("reading {}", image.display()))?;
        match self.symbols(&data)
        {
            Ok(Symbols::Store { name, .. }) => Ok(self.dir.join(name)),
            Ok(Symbols::Image) => Ok(image.to_path_buf()),
            Err(reason) => bail!("no symbols for {}: {reason}", image.display()),
        }
    }

    /// Keep the ELF link output `elf` as the symbols of the image a build
    /// for `arch` installs at `install` (an install path, `/services/procmgr`)
    /// and record it in the manifest; return its store file's name.
    ///
    /// # Errors
    ///
    /// `elf` carries no build id, or the store cannot be written.
    pub fn keep_elf(&self, arch: Arch, install: &str, elf: &[u8]) -> Result<String>
    {
        let Some(id) = build_id(elf)
        else
        {
            bail!("the link output of {install} carries no build-id note");
        };
        let name = elf_name(&id);
        self.keep(arch, install, &name, elf)?;
        Ok(name)
    }

    /// Keep the PDB `pdb` as the symbols of the PE image `pe` a build for
    /// `arch` installs at `install`, under the image's [`pdb_key`], and record
    /// it in the manifest; return its store file's name.
    ///
    /// # Errors
    ///
    /// `pe` carries no `CodeView` record, or the store cannot be written.
    pub fn keep_pdb(&self, arch: Arch, install: &str, pe: &[u8], pdb: &[u8]) -> Result<String>
    {
        let Some(key) = pdb_key(pe)
        else
        {
            bail!("the PE image {install} carries no CodeView record");
        };
        let name = format!("{key}.pdb");
        self.keep(arch, install, &name, pdb)?;
        Ok(name)
    }

    /// Write `bytes` as the store file `name` and name it in the manifest
    /// as `install`'s, the manifest's architecture `arch`. The file the
    /// manifest named for `install` before, when no other image's entry names
    /// it, is removed: the store holds the symbols of the images installed
    /// now, which a release archives whole.
    fn keep(&self, arch: Arch, install: &str, name: &str, bytes: &[u8]) -> Result<()>
    {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        write_whole(&self.dir.join(name), bytes)?;
        let mut manifest = match self.manifest()?
        {
            Some(manifest) if manifest.arch == arch.to_string() => manifest,
            _ => Manifest {
                arch: arch.to_string(),
                files: BTreeMap::new(),
            },
        };
        let replaced = manifest.files.insert(install.to_owned(), name.to_owned());
        write_whole(&self.dir.join(MANIFEST), manifest.render().as_bytes())?;
        if let Some(old) = replaced
            && !manifest.files.values().any(|file| *file == old)
        {
            let path = self.dir.join(&old);
            match std::fs::remove_file(&path)
            {
                Ok(()) =>
                {}
                Err(err) if err.kind() == ErrorKind::NotFound =>
                {}
                Err(err) => bail!("cannot remove {}: {err}", path.display()),
            }
        }
        Ok(())
    }

    /// The store's manifest, `Ok(None)` when it has none.
    ///
    /// # Errors
    ///
    /// The manifest exists but cannot be read or parsed.
    pub fn manifest(&self) -> Result<Option<Manifest>>
    {
        let path = self.dir.join(MANIFEST);
        let text = match std::fs::read_to_string(&path)
        {
            Ok(text) => text,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => bail!("cannot read {}: {err}", path.display()),
        };
        Manifest::parse(&text)
            .map(Some)
            .map_err(|reason| crate::error::err!("{}: {reason}", path.display()))
    }
}

/// Write `bytes` to `path` through a temporary file beside it, so a reader
/// never sees a part of it.
fn write_whole(path: &Path, bytes: &[u8]) -> Result<()>
{
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".new");
    let temporary = PathBuf::from(temporary);
    std::fs::write(&temporary, bytes)
        .with_context(|| format!("writing {}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .with_context(|| format!("renaming {} to {}", temporary.display(), path.display()))
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::symbolize::fixture::{
        Architecture, Debug, FIXTURE_BUILD_ID, USER_BASE, fixture, stripped, with_build_id,
    };

    /// [`FIXTURE_BUILD_ID`] as [`build_id`] renders it.
    fn fixture_id() -> String
    {
        lower_hex(&FIXTURE_BUILD_ID)
    }

    /// A scratch store directory for `tag`, empty.
    fn scratch(tag: &str) -> PathBuf
    {
        let dir = std::env::temp_dir().join(format!("seraph-symbols-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_build_id_is_read_from_the_note_and_a_trailer_past_the_elf_is_ignored()
    {
        let mut image = stripped(Architecture::Riscv64);
        assert_eq!(build_id(&image), Some(fixture_id()));
        image.extend_from_slice(b"a signature trailer");
        assert_eq!(build_id(&image), Some(fixture_id()));
        assert_eq!(build_id(b"not an ELF image"), None);
        assert_eq!(build_id(&pe(&[7; 16], 3)), None);
    }

    #[test]
    fn a_stripped_image_resolves_to_the_store_file_of_its_build_id()
    {
        let image = stripped(Architecture::X86_64);
        let elf = fixture(Architecture::X86_64, USER_BASE, Debug::Dwarf);
        let found = symbols_for(&image, |name| {
            assert_eq!(name, format!("{}.elf", fixture_id()));
            Ok(Some(elf.clone()))
        });
        assert_eq!(
            found,
            Ok(Symbols::Store {
                name: elf_name(&fixture_id()),
                elf
            })
        );
    }

    #[test]
    fn a_store_file_of_another_build_is_refused()
    {
        let image = stripped(Architecture::X86_64);
        let other = with_build_id(
            fixture(Architecture::X86_64, USER_BASE, Debug::Dwarf),
            b"another-build-id-002",
        );
        let err = symbols_for(&image, |_| Ok(Some(other))).unwrap_err();
        assert!(
            err.contains(&format!(
                "has build id {}, not the image's",
                lower_hex(b"another-build-id-002")
            )),
            "{err}"
        );
        let err = symbols_for(&image, |_| Ok(Some(b"not an ELF image".to_vec()))).unwrap_err();
        assert!(err.contains("carries no build-id note"), "{err}");
    }

    #[test]
    fn an_image_with_its_own_symbols_resolves_to_itself_and_a_stripped_one_needs_its_file()
    {
        let unstripped = fixture(Architecture::X86_64, USER_BASE, Debug::SymbolsOnly);
        let found = symbols_for(&unstripped, |_| panic!("the store is not read"));
        assert_eq!(found, Ok(Symbols::Image));
        let err = symbols_for(&stripped(Architecture::X86_64), |_| Ok(None)).unwrap_err();
        assert_eq!(
            err,
            format!(
                "the image carries no symbols, and the symbols store has no {}.elf",
                fixture_id()
            )
        );
        let err = symbols_for(b"not an ELF image", |_| Ok(None)).unwrap_err();
        assert_eq!(err, "the image carries no symbols and no build-id note");
        let err = symbols_for(
            &stripped(Architecture::X86_64),
            |_| Err("denied".to_owned()),
        )
        .unwrap_err();
        assert_eq!(err, "denied");
    }

    #[test]
    fn a_manifest_renders_what_it_parses_and_refuses_a_malformed_line()
    {
        let text = "arch riscv64\n/boot/kernel ab.elf\n/services/procmgr cd.elf\n";
        let manifest = Manifest::parse(text).unwrap();
        assert_eq!(manifest.arch, "riscv64");
        assert_eq!(manifest.files["/services/procmgr"], "cd.elf");
        assert_eq!(manifest.render(), text);
        for bad in [
            "",
            "/boot/kernel ab.elf\n",
            "arch \n",
            "arch riscv64\n/boot/kernel\n",
            "arch riscv64\n/boot/kernel ab.elf extra\n",
        ]
        {
            Manifest::parse(bad).unwrap_err();
        }
    }

    #[test]
    fn a_kept_image_is_found_by_its_build_id_and_named_in_the_manifest()
    {
        let dir = scratch("keep");
        let store = Store::at(&dir);
        assert_eq!(store.manifest().unwrap(), None);
        let elf = fixture(Architecture::Riscv64, USER_BASE, Debug::Dwarf);
        let name = store
            .keep_elf(Arch::Riscv64, "/programs/hello", &elf)
            .unwrap();
        assert_eq!(name, elf_name(&fixture_id()));
        assert_eq!(std::fs::read(dir.join(&name)).unwrap(), elf);

        let installed = dir.join("installed");
        std::fs::write(&installed, stripped(Architecture::Riscv64)).unwrap();
        assert_eq!(store.symbols_path(&installed).unwrap(), dir.join(&name));

        let pdb = store
            .keep_pdb(Arch::Riscv64, "/boot/boot.efi", &pe(&[7; 16], 3), b"pdb")
            .unwrap();
        let manifest = store.manifest().unwrap().unwrap();
        assert_eq!(manifest.arch, "riscv64");
        assert_eq!(manifest.files["/programs/hello"], name);
        assert_eq!(manifest.files["/boot/boot.efi"], pdb);

        // A rebuild of an image replaces its file; a file another image's
        // entry names stays.
        let rebuilt = with_build_id(elf.clone(), b"rebuilt-build-id-003");
        store
            .keep_elf(Arch::Riscv64, "/programs/copy", &elf)
            .unwrap();
        let new = store
            .keep_elf(Arch::Riscv64, "/programs/hello", &rebuilt)
            .unwrap();
        assert!(dir.join(&name).exists());
        assert!(dir.join(&new).exists());
        store
            .keep_elf(Arch::Riscv64, "/programs/copy", &rebuilt)
            .unwrap();
        assert!(!dir.join(&name).exists());

        // A build for another architecture starts the manifest again.
        store
            .keep_elf(Arch::X86_64, "/programs/other", &elf)
            .unwrap();
        let manifest = store.manifest().unwrap().unwrap();
        assert_eq!(manifest.arch, "x86_64");
        assert_eq!(manifest.files.len(), 1);

        store
            .keep_elf(Arch::X86_64, "/programs/none", b"not an ELF image")
            .unwrap_err();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_pe_image_is_keyed_by_its_codeview_guid_and_age()
    {
        let guid = [
            0x8b, 0xc1, 0x54, 0xfa, 0xee, 0xa4, 0x15, 0x31, 0x4c, 0x4c, 0x44, 0x20, 0x50, 0x44,
            0x42, 0x2e,
        ];
        assert_eq!(
            pdb_key(&pe(&guid, 1)).as_deref(),
            Some("FA54C18BA4EE31154C4C44205044422E1")
        );
        assert_eq!(pdb_key(&stripped(Architecture::X86_64)), None);
        assert_eq!(pdb_key(b"MZ"), None);
    }

    /// Write `bytes` at `at` in `out`.
    fn put(out: &mut [u8], at: usize, bytes: &[u8])
    {
        out[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// A PE32+ image with one section, `.rdata` at RVA 0x1000, which opens
    /// with one debug directory entry of type `CodeView` whose `RSDS` record,
    /// `guid` and `age` and the name `boot.pdb`, follows it at 0x1020.
    fn pe(guid: &[u8; 16], age: u32) -> Vec<u8>
    {
        let mut out = vec![0u8; 0x600];
        put(&mut out, 0, b"MZ");
        put(&mut out, 0x3c, &64u32.to_le_bytes());
        put(&mut out, 64, b"PE\0\0");
        // The COFF header: machine, one section, the optional header's size,
        // characteristics.
        put(&mut out, 68, &0x8664u16.to_le_bytes());
        put(&mut out, 70, &1u16.to_le_bytes());
        put(&mut out, 84, &240u16.to_le_bytes());
        put(&mut out, 86, &0x22u16.to_le_bytes());
        // The optional header: magic, image base, alignments, image and
        // header sizes, subsystem, and the count of data directories.
        let opt = 88;
        put(&mut out, opt, &0x20bu16.to_le_bytes());
        put(&mut out, opt + 24, &0x1_4000_0000u64.to_le_bytes());
        put(&mut out, opt + 32, &0x1000u32.to_le_bytes());
        put(&mut out, opt + 36, &0x200u32.to_le_bytes());
        put(&mut out, opt + 56, &0x2000u32.to_le_bytes());
        put(&mut out, opt + 60, &0x400u32.to_le_bytes());
        put(&mut out, opt + 68, &10u16.to_le_bytes());
        put(&mut out, opt + 108, &16u32.to_le_bytes());
        // The debug data directory.
        put(&mut out, opt + 112 + 6 * 8, &0x1000u32.to_le_bytes());
        put(&mut out, opt + 112 + 6 * 8 + 4, &28u32.to_le_bytes());
        // The section table: `.rdata`, its sizes, RVA and file offset.
        let at = opt + 240;
        put(&mut out, at, b".rdata");
        put(&mut out, at + 8, &0x200u32.to_le_bytes());
        put(&mut out, at + 12, &0x1000u32.to_le_bytes());
        put(&mut out, at + 16, &0x200u32.to_le_bytes());
        put(&mut out, at + 20, &0x400u32.to_le_bytes());
        put(&mut out, at + 36, &0x4000_0040u32.to_le_bytes());
        // The debug directory entry: type `CodeView`, its data's size, RVA
        // and file offset; then the record.
        let record_len = 4 + 16 + 4 + b"boot.pdb\0".len();
        put(&mut out, 0x40c, &2u32.to_le_bytes());
        put(
            &mut out,
            0x410,
            &u32::try_from(record_len).unwrap().to_le_bytes(),
        );
        put(&mut out, 0x414, &0x1020u32.to_le_bytes());
        put(&mut out, 0x418, &0x420u32.to_le_bytes());
        put(&mut out, 0x420, b"RSDS");
        put(&mut out, 0x424, guid);
        put(&mut out, 0x434, &age.to_le_bytes());
        put(&mut out, 0x438, b"boot.pdb\0");
        out
    }
}
