// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/gdb-rsp/src/target.rs

//! The target description a stub serves each architecture with, and the
//! register layout it implies.
//!
//! GDB reads the description through `qXfer:features:read:target.xml`
//! ([`TARGET_XML_ANNEX`]). Its registers, in document order, are the
//! protocol's register numbers (`p`, `P`) and the order of the register
//! block `g` and `G` carry, each register's bytes in target order
//! (little-endian on both architectures). The descriptions carry GDB's
//! standard feature names, so GDB applies its own knowledge of each
//! architecture: on x86-64 `org.gnu.gdb.i386.core` (the general, segment, and
//! x87 registers) and `org.gnu.gdb.i386.sse`, on riscv64
//! `org.gnu.gdb.riscv.cpu` and `org.gnu.gdb.riscv.fpu`. A stub that cannot
//! read a register sends its bytes as unavailable
//! ([`crate::frame::PacketWriter::unavailable`]).

use core::ops::Range;

/// The annex GDB names the target description by.
pub const TARGET_XML_ANNEX: &[u8] = b"target.xml";

/// The architectures a stub serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch
{
    X86_64,
    Riscv64,
}

/// One register of a target description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Register
{
    /// The name GDB knows it by.
    pub name: &'static str,
    /// Its size in the register block, in bytes.
    pub bytes: usize,
}

impl Arch
{
    /// The registers, in protocol register-number order.
    #[must_use]
    pub fn registers(self) -> &'static [Register]
    {
        match self
        {
            Self::X86_64 => X86_64_REGISTERS,
            Self::Riscv64 => RISCV64_REGISTERS,
        }
    }

    /// The target description document.
    #[must_use]
    pub fn target_xml(self) -> &'static [u8]
    {
        match self
        {
            Self::X86_64 => X86_64_XML.as_bytes(),
            Self::Riscv64 => RISCV64_XML.as_bytes(),
        }
    }

    /// The register number of the program counter: `rip` on x86-64, `pc` on
    /// riscv64.
    #[must_use]
    pub fn pc_regnum(self) -> usize
    {
        match self
        {
            Self::X86_64 => 16,
            Self::Riscv64 => 32,
        }
    }

    /// The length of the register block `g` sends and `G` takes, in bytes.
    #[must_use]
    pub fn register_block_len(self) -> usize
    {
        self.registers().iter().map(|r| r.bytes).sum()
    }

    /// Where register `regnum` lies in the register block, in bytes; `None`
    /// for a number past the last register.
    #[must_use]
    pub fn register_span(self, regnum: usize) -> Option<Range<usize>>
    {
        let regs = self.registers();
        let reg = regs.get(regnum)?;
        let start: usize = regs[..regnum].iter().map(|r| r.bytes).sum();
        Some(start..start + reg.bytes)
    }
}

const X86_64_REGISTERS: &[Register] = &[
    Register {
        name: "rax",
        bytes: 8,
    },
    Register {
        name: "rbx",
        bytes: 8,
    },
    Register {
        name: "rcx",
        bytes: 8,
    },
    Register {
        name: "rdx",
        bytes: 8,
    },
    Register {
        name: "rsi",
        bytes: 8,
    },
    Register {
        name: "rdi",
        bytes: 8,
    },
    Register {
        name: "rbp",
        bytes: 8,
    },
    Register {
        name: "rsp",
        bytes: 8,
    },
    Register {
        name: "r8",
        bytes: 8,
    },
    Register {
        name: "r9",
        bytes: 8,
    },
    Register {
        name: "r10",
        bytes: 8,
    },
    Register {
        name: "r11",
        bytes: 8,
    },
    Register {
        name: "r12",
        bytes: 8,
    },
    Register {
        name: "r13",
        bytes: 8,
    },
    Register {
        name: "r14",
        bytes: 8,
    },
    Register {
        name: "r15",
        bytes: 8,
    },
    Register {
        name: "rip",
        bytes: 8,
    },
    Register {
        name: "eflags",
        bytes: 4,
    },
    Register {
        name: "cs",
        bytes: 4,
    },
    Register {
        name: "ss",
        bytes: 4,
    },
    Register {
        name: "ds",
        bytes: 4,
    },
    Register {
        name: "es",
        bytes: 4,
    },
    Register {
        name: "fs",
        bytes: 4,
    },
    Register {
        name: "gs",
        bytes: 4,
    },
    Register {
        name: "st0",
        bytes: 10,
    },
    Register {
        name: "st1",
        bytes: 10,
    },
    Register {
        name: "st2",
        bytes: 10,
    },
    Register {
        name: "st3",
        bytes: 10,
    },
    Register {
        name: "st4",
        bytes: 10,
    },
    Register {
        name: "st5",
        bytes: 10,
    },
    Register {
        name: "st6",
        bytes: 10,
    },
    Register {
        name: "st7",
        bytes: 10,
    },
    Register {
        name: "fctrl",
        bytes: 4,
    },
    Register {
        name: "fstat",
        bytes: 4,
    },
    Register {
        name: "ftag",
        bytes: 4,
    },
    Register {
        name: "fiseg",
        bytes: 4,
    },
    Register {
        name: "fioff",
        bytes: 4,
    },
    Register {
        name: "foseg",
        bytes: 4,
    },
    Register {
        name: "fooff",
        bytes: 4,
    },
    Register {
        name: "fop",
        bytes: 4,
    },
    Register {
        name: "xmm0",
        bytes: 16,
    },
    Register {
        name: "xmm1",
        bytes: 16,
    },
    Register {
        name: "xmm2",
        bytes: 16,
    },
    Register {
        name: "xmm3",
        bytes: 16,
    },
    Register {
        name: "xmm4",
        bytes: 16,
    },
    Register {
        name: "xmm5",
        bytes: 16,
    },
    Register {
        name: "xmm6",
        bytes: 16,
    },
    Register {
        name: "xmm7",
        bytes: 16,
    },
    Register {
        name: "xmm8",
        bytes: 16,
    },
    Register {
        name: "xmm9",
        bytes: 16,
    },
    Register {
        name: "xmm10",
        bytes: 16,
    },
    Register {
        name: "xmm11",
        bytes: 16,
    },
    Register {
        name: "xmm12",
        bytes: 16,
    },
    Register {
        name: "xmm13",
        bytes: 16,
    },
    Register {
        name: "xmm14",
        bytes: 16,
    },
    Register {
        name: "xmm15",
        bytes: 16,
    },
    Register {
        name: "mxcsr",
        bytes: 4,
    },
];

const RISCV64_REGISTERS: &[Register] = &[
    Register {
        name: "zero",
        bytes: 8,
    },
    Register {
        name: "ra",
        bytes: 8,
    },
    Register {
        name: "sp",
        bytes: 8,
    },
    Register {
        name: "gp",
        bytes: 8,
    },
    Register {
        name: "tp",
        bytes: 8,
    },
    Register {
        name: "t0",
        bytes: 8,
    },
    Register {
        name: "t1",
        bytes: 8,
    },
    Register {
        name: "t2",
        bytes: 8,
    },
    Register {
        name: "fp",
        bytes: 8,
    },
    Register {
        name: "s1",
        bytes: 8,
    },
    Register {
        name: "a0",
        bytes: 8,
    },
    Register {
        name: "a1",
        bytes: 8,
    },
    Register {
        name: "a2",
        bytes: 8,
    },
    Register {
        name: "a3",
        bytes: 8,
    },
    Register {
        name: "a4",
        bytes: 8,
    },
    Register {
        name: "a5",
        bytes: 8,
    },
    Register {
        name: "a6",
        bytes: 8,
    },
    Register {
        name: "a7",
        bytes: 8,
    },
    Register {
        name: "s2",
        bytes: 8,
    },
    Register {
        name: "s3",
        bytes: 8,
    },
    Register {
        name: "s4",
        bytes: 8,
    },
    Register {
        name: "s5",
        bytes: 8,
    },
    Register {
        name: "s6",
        bytes: 8,
    },
    Register {
        name: "s7",
        bytes: 8,
    },
    Register {
        name: "s8",
        bytes: 8,
    },
    Register {
        name: "s9",
        bytes: 8,
    },
    Register {
        name: "s10",
        bytes: 8,
    },
    Register {
        name: "s11",
        bytes: 8,
    },
    Register {
        name: "t3",
        bytes: 8,
    },
    Register {
        name: "t4",
        bytes: 8,
    },
    Register {
        name: "t5",
        bytes: 8,
    },
    Register {
        name: "t6",
        bytes: 8,
    },
    Register {
        name: "pc",
        bytes: 8,
    },
    Register {
        name: "ft0",
        bytes: 8,
    },
    Register {
        name: "ft1",
        bytes: 8,
    },
    Register {
        name: "ft2",
        bytes: 8,
    },
    Register {
        name: "ft3",
        bytes: 8,
    },
    Register {
        name: "ft4",
        bytes: 8,
    },
    Register {
        name: "ft5",
        bytes: 8,
    },
    Register {
        name: "ft6",
        bytes: 8,
    },
    Register {
        name: "ft7",
        bytes: 8,
    },
    Register {
        name: "fs0",
        bytes: 8,
    },
    Register {
        name: "fs1",
        bytes: 8,
    },
    Register {
        name: "fa0",
        bytes: 8,
    },
    Register {
        name: "fa1",
        bytes: 8,
    },
    Register {
        name: "fa2",
        bytes: 8,
    },
    Register {
        name: "fa3",
        bytes: 8,
    },
    Register {
        name: "fa4",
        bytes: 8,
    },
    Register {
        name: "fa5",
        bytes: 8,
    },
    Register {
        name: "fa6",
        bytes: 8,
    },
    Register {
        name: "fa7",
        bytes: 8,
    },
    Register {
        name: "fs2",
        bytes: 8,
    },
    Register {
        name: "fs3",
        bytes: 8,
    },
    Register {
        name: "fs4",
        bytes: 8,
    },
    Register {
        name: "fs5",
        bytes: 8,
    },
    Register {
        name: "fs6",
        bytes: 8,
    },
    Register {
        name: "fs7",
        bytes: 8,
    },
    Register {
        name: "fs8",
        bytes: 8,
    },
    Register {
        name: "fs9",
        bytes: 8,
    },
    Register {
        name: "fs10",
        bytes: 8,
    },
    Register {
        name: "fs11",
        bytes: 8,
    },
    Register {
        name: "ft8",
        bytes: 8,
    },
    Register {
        name: "ft9",
        bytes: 8,
    },
    Register {
        name: "ft10",
        bytes: 8,
    },
    Register {
        name: "ft11",
        bytes: 8,
    },
    Register {
        name: "fflags",
        bytes: 4,
    },
    Register {
        name: "frm",
        bytes: 4,
    },
    Register {
        name: "fcsr",
        bytes: 4,
    },
];

const X86_64_XML: &str = concat!(
    "<?xml version=\"1.0\"?>",
    "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">",
    "<target version=\"1.0\">",
    "<architecture>i386:x86-64</architecture>",
    "<feature name=\"org.gnu.gdb.i386.core\">",
    "<reg name=\"rax\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"rbx\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"rcx\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"rdx\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"rsi\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"rdi\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"rbp\" bitsize=\"64\" type=\"data_ptr\"/>",
    "<reg name=\"rsp\" bitsize=\"64\" type=\"data_ptr\"/>",
    "<reg name=\"r8\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"r9\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"r10\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"r11\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"r12\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"r13\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"r14\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"r15\" bitsize=\"64\" type=\"int64\"/>",
    "<reg name=\"rip\" bitsize=\"64\" type=\"code_ptr\"/>",
    "<reg name=\"eflags\" bitsize=\"32\" type=\"int32\"/>",
    "<reg name=\"cs\" bitsize=\"32\" type=\"int32\"/>",
    "<reg name=\"ss\" bitsize=\"32\" type=\"int32\"/>",
    "<reg name=\"ds\" bitsize=\"32\" type=\"int32\"/>",
    "<reg name=\"es\" bitsize=\"32\" type=\"int32\"/>",
    "<reg name=\"fs\" bitsize=\"32\" type=\"int32\"/>",
    "<reg name=\"gs\" bitsize=\"32\" type=\"int32\"/>",
    "<reg name=\"st0\" bitsize=\"80\" type=\"i387_ext\"/>",
    "<reg name=\"st1\" bitsize=\"80\" type=\"i387_ext\"/>",
    "<reg name=\"st2\" bitsize=\"80\" type=\"i387_ext\"/>",
    "<reg name=\"st3\" bitsize=\"80\" type=\"i387_ext\"/>",
    "<reg name=\"st4\" bitsize=\"80\" type=\"i387_ext\"/>",
    "<reg name=\"st5\" bitsize=\"80\" type=\"i387_ext\"/>",
    "<reg name=\"st6\" bitsize=\"80\" type=\"i387_ext\"/>",
    "<reg name=\"st7\" bitsize=\"80\" type=\"i387_ext\"/>",
    "<reg name=\"fctrl\" bitsize=\"32\" type=\"int\"/>",
    "<reg name=\"fstat\" bitsize=\"32\" type=\"int\"/>",
    "<reg name=\"ftag\" bitsize=\"32\" type=\"int\"/>",
    "<reg name=\"fiseg\" bitsize=\"32\" type=\"int\"/>",
    "<reg name=\"fioff\" bitsize=\"32\" type=\"int\"/>",
    "<reg name=\"foseg\" bitsize=\"32\" type=\"int\"/>",
    "<reg name=\"fooff\" bitsize=\"32\" type=\"int\"/>",
    "<reg name=\"fop\" bitsize=\"32\" type=\"int\"/>",
    "</feature>",
    "<feature name=\"org.gnu.gdb.i386.sse\">",
    "<vector id=\"v4f\" type=\"ieee_single\" count=\"4\"/>",
    "<vector id=\"v2d\" type=\"ieee_double\" count=\"2\"/>",
    "<vector id=\"v16i8\" type=\"int8\" count=\"16\"/>",
    "<vector id=\"v8i16\" type=\"int16\" count=\"8\"/>",
    "<vector id=\"v4i32\" type=\"int32\" count=\"4\"/>",
    "<vector id=\"v2i64\" type=\"int64\" count=\"2\"/>",
    "<union id=\"vec128\">",
    "<field name=\"v4_float\" type=\"v4f\"/>",
    "<field name=\"v2_double\" type=\"v2d\"/>",
    "<field name=\"v16_int8\" type=\"v16i8\"/>",
    "<field name=\"v8_int16\" type=\"v8i16\"/>",
    "<field name=\"v4_int32\" type=\"v4i32\"/>",
    "<field name=\"v2_int64\" type=\"v2i64\"/>",
    "<field name=\"uint128\" type=\"uint128\"/>",
    "</union>",
    "<reg name=\"xmm0\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm1\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm2\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm3\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm4\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm5\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm6\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm7\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm8\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm9\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm10\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm11\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm12\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm13\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm14\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"xmm15\" bitsize=\"128\" type=\"vec128\"/>",
    "<reg name=\"mxcsr\" bitsize=\"32\" type=\"int\"/>",
    "</feature>",
    "</target>",
);

const RISCV64_XML: &str = concat!(
    "<?xml version=\"1.0\"?>",
    "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">",
    "<target version=\"1.0\">",
    "<architecture>riscv:rv64</architecture>",
    "<feature name=\"org.gnu.gdb.riscv.cpu\">",
    "<reg name=\"zero\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"ra\" bitsize=\"64\" type=\"code_ptr\"/>",
    "<reg name=\"sp\" bitsize=\"64\" type=\"data_ptr\"/>",
    "<reg name=\"gp\" bitsize=\"64\" type=\"data_ptr\"/>",
    "<reg name=\"tp\" bitsize=\"64\" type=\"data_ptr\"/>",
    "<reg name=\"t0\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"t1\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"t2\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"fp\" bitsize=\"64\" type=\"data_ptr\"/>",
    "<reg name=\"s1\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"a0\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"a1\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"a2\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"a3\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"a4\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"a5\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"a6\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"a7\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"s2\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"s3\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"s4\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"s5\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"s6\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"s7\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"s8\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"s9\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"s10\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"s11\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"t3\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"t4\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"t5\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"t6\" bitsize=\"64\" type=\"int\"/>",
    "<reg name=\"pc\" bitsize=\"64\" type=\"code_ptr\"/>",
    "</feature>",
    "<feature name=\"org.gnu.gdb.riscv.fpu\">",
    "<union id=\"riscv_double\">",
    "<field name=\"float\" type=\"ieee_single\"/>",
    "<field name=\"double\" type=\"ieee_double\"/>",
    "</union>",
    "<reg name=\"ft0\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"ft1\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"ft2\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"ft3\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"ft4\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"ft5\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"ft6\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"ft7\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fs0\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fs1\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fa0\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fa1\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fa2\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fa3\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fa4\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fa5\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fa6\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fa7\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fs2\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fs3\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fs4\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fs5\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fs6\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fs7\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fs8\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fs9\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fs10\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fs11\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"ft8\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"ft9\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"ft10\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"ft11\" bitsize=\"64\" type=\"riscv_double\"/>",
    "<reg name=\"fflags\" bitsize=\"32\" type=\"int\"/>",
    "<reg name=\"frm\" bitsize=\"32\" type=\"int\"/>",
    "<reg name=\"fcsr\" bitsize=\"32\" type=\"int\"/>",
    "</feature>",
    "</target>",
);

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::PACKET_SIZE;

    extern crate std;
    use std::vec::Vec;

    /// The `(name, bitsize)` of every `<reg>` element of `xml`, in order.
    fn described_registers(xml: &str) -> Vec<(&str, usize)>
    {
        xml.split("<reg ")
            .skip(1)
            .map(|reg| {
                let attr = |key: &str| {
                    let start = reg.find(key).unwrap() + key.len();
                    let len = reg[start..].find('"').unwrap();
                    &reg[start..start + len]
                };
                (attr("name=\""), attr("bitsize=\"").parse().unwrap())
            })
            .collect()
    }

    #[test]
    fn each_description_lists_the_register_layout_in_order()
    {
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            let xml = core::str::from_utf8(arch.target_xml()).unwrap();
            let layout: Vec<(&str, usize)> = arch
                .registers()
                .iter()
                .map(|r| (r.name, r.bytes * 8))
                .collect();
            assert_eq!(described_registers(xml), layout, "{arch:?}");
        }
    }

    #[test]
    fn register_offsets_match_the_block_gdb_lays_out_from_the_description()
    {
        // GDB 18.1's `maint print remote-registers` for each description:
        // the register number, and the g/G offset and size it gives it.
        let gdb = [
            (Arch::X86_64, "rip", 16, 128, 8),
            (Arch::X86_64, "eflags", 17, 136, 4),
            (Arch::X86_64, "st0", 24, 164, 10),
            (Arch::X86_64, "fop", 39, 272, 4),
            (Arch::X86_64, "xmm15", 55, 516, 16),
            (Arch::X86_64, "mxcsr", 56, 532, 4),
            (Arch::Riscv64, "pc", 32, 256, 8),
            (Arch::Riscv64, "ft0", 33, 264, 8),
            (Arch::Riscv64, "fcsr", 67, 528, 4),
        ];
        for (arch, name, regnum, offset, size) in gdb
        {
            assert_eq!(arch.registers()[regnum].name, name);
            assert_eq!(arch.register_span(regnum), Some(offset..offset + size));
        }
        assert_eq!(Arch::X86_64.register_block_len(), 536);
        assert_eq!(Arch::Riscv64.register_block_len(), 532);
    }

    #[test]
    fn a_register_number_past_the_last_has_no_span()
    {
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            let n = arch.registers().len();
            assert!(arch.register_span(n - 1).is_some());
            assert_eq!(arch.register_span(n), None);
        }
    }

    #[test]
    fn the_program_counter_number_names_the_program_counter()
    {
        assert_eq!(
            Arch::X86_64.registers()[Arch::X86_64.pc_regnum()].name,
            "rip"
        );
        assert_eq!(
            Arch::Riscv64.registers()[Arch::Riscv64.pc_regnum()].name,
            "pc"
        );
    }

    #[test]
    fn a_write_of_every_register_fits_one_packet()
    {
        // The body: `G` and the block in hex.
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            assert!(1 + arch.register_block_len() * 2 <= PACKET_SIZE);
        }
    }
}
