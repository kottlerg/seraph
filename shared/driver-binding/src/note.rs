// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/driver-binding/src/note.rs

//! The `.note.seraph.driver` ELF note and the [`driver_declaration!`] macro
//! that places it in a driver binary.
//!
//! The note is a standard ELF note record: `namesz` 7, `descsz` the encoded
//! descriptor's length, type `process_abi::NT_SERAPH_DRIVER`, owner
//! `seraph` (NUL-terminated, padded to four bytes), then the descriptor
//! padded to four bytes. The linker keeps it as it keeps
//! `.note.seraph.stack`: a section whose name starts `.note` is a note
//! section, which section garbage collection retains.
//!
//! [`driver_declaration!`]: crate::driver_declaration

use process_abi::{NT_SERAPH_DRIVER, SERAPH_NOTE_NAME};

use crate::decl::EncodedDesc;

/// A driver's declaration note, `N` being its descriptor's length padded to
/// four bytes.
#[repr(C, align(4))]
pub struct DriverNote<const N: usize>
{
    /// Length of the owner, `seraph` and its NUL.
    pub namesz: u32,
    /// Length of the descriptor, without its padding.
    pub descsz: u32,
    /// `NT_SERAPH_DRIVER`.
    pub ntype: u32,
    /// The owner, NUL-terminated and padded to four bytes.
    pub name: [u8; 8],
    /// The descriptor, zero-padded to four bytes.
    pub desc: [u8; N],
}

impl<const N: usize> DriverNote<N>
{
    /// The note carrying `desc`.
    ///
    /// # Panics
    /// When `N` is not `desc`'s padded length; in the `const` the macro
    /// builds, a compile error.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a descriptor is at most MAX_DESC_BYTES (512) long, which a u32 holds"
    )]
    pub const fn new(desc: &EncodedDesc) -> Self
    {
        assert!(
            desc.padded_len() == N,
            "driver note: N is not the descriptor's padded length"
        );
        let mut bytes = [0u8; N];
        let mut dst: &mut [u8] = &mut bytes;
        let mut i = 0;
        while let [d, rest @ ..] = dst
        {
            *d = desc.byte(i);
            // `i` counts the `N` bytes of `bytes`, so it cannot saturate.
            i = i.saturating_add(1);
            dst = rest;
        }
        Self {
            namesz: 7,
            descsz: desc.len() as u32,
            ntype: NT_SERAPH_DRIVER,
            name: SERAPH_NOTE_NAME,
            desc: bytes,
        }
    }
}

/// Place `$decl`, a [`Declaration`](crate::decl::Declaration) constant
/// expression, in this binary's `.note.seraph.driver` section. The
/// declaration is encoded at compile time, so one that breaks a bound of the
/// format fails the build. Invoke once, at a binary's crate root.
#[macro_export]
macro_rules! driver_declaration {
    ($decl:expr) => {
        const __SERAPH_DRIVER_DESC: $crate::decl::EncodedDesc = $crate::decl::encode(&$decl);
        #[used]
        #[unsafe(link_section = ".note.seraph.driver")]
        static __SERAPH_DRIVER_NOTE: $crate::note::DriverNote<
            { __SERAPH_DRIVER_DESC.padded_len() },
        > = $crate::note::DriverNote::new(&__SERAPH_DRIVER_DESC);
    };
}

#[cfg(test)]
mod tests
{
    use crate::decl::{Declaration, Interrupt, Match, Reset, Tier, decode};

    // The macro as a driver invokes it, in a module standing for a crate root.
    mod declared
    {
        use crate::decl::{Declaration, Interrupt, Match, Reset, Tier};

        crate::driver_declaration!(Declaration {
            name: "test-driver",
            class: Some("block"),
            matches: &[Match::PciId {
                vendor: 0x1AF4,
                device: 0x1042
            }],
            instance_limit: None,
            interrupt: Interrupt::REQUIRED,
            dma: true,
            dma_width: None,
            phys_access: false,
            reset: Reset::VirtioStatus,
            tier: Tier::Boot,
        });

        pub fn note_bytes() -> &'static [u8]
        {
            // SAFETY: `__SERAPH_DRIVER_NOTE` is a `#[repr(C)]` struct of
            // integers and byte arrays with no padding (every field ends on
            // a four-byte boundary), so each of its bytes is initialised.
            unsafe {
                core::slice::from_raw_parts(
                    core::ptr::from_ref(&__SERAPH_DRIVER_NOTE).cast::<u8>(),
                    core::mem::size_of_val(&__SERAPH_DRIVER_NOTE),
                )
            }
        }
    }

    fn word(bytes: &[u8], at: usize) -> u32
    {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    }

    #[test]
    fn the_macro_emits_a_standard_note_record_that_decodes()
    {
        let note = declared::note_bytes();
        assert_eq!(word(note, 0), 7, "namesz");
        let descsz = word(note, 4) as usize;
        assert_eq!(word(note, 8), process_abi::NT_SERAPH_DRIVER);
        assert_eq!(&note[12..20], b"seraph\0\0");
        assert_eq!(note.len(), 20 + descsz.next_multiple_of(4));
        assert!(note[20 + descsz..].iter().all(|&b| b == 0), "zero padding");
        let decl = decode(&note[20..20 + descsz]).expect("the emitted note decodes");
        assert_eq!(decl.name.as_str(), "test-driver");
        assert_eq!(decl.interrupt, Interrupt::REQUIRED);
        assert_eq!(decl.reset, Reset::VirtioStatus);
        assert_eq!(decl.tier, Tier::Boot);
        assert!(decl.dma);
    }

    #[test]
    #[should_panic(expected = "padded length")]
    fn a_note_of_the_wrong_size_is_refused()
    {
        let desc = crate::decl::encode(&Declaration {
            name: "d",
            class: None,
            matches: &[Match::Spcr(0)],
            instance_limit: None,
            interrupt: Interrupt::NONE,
            dma: false,
            dma_width: None,
            phys_access: false,
            reset: Reset::None,
            tier: Tier::Auxiliary,
        });
        let _ = super::DriverNote::<4>::new(&desc);
    }
}
