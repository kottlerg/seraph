// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/gdbstub/src/regs.rs

//! The map between the kernel's register file, as `SYS_THREAD_READ_REGS`
//! fills it (`abi/syscall` § Register file), and GDB's register block, as
//! the target description lays it out (`shared/gdb-rsp` `target::Arch`).

use gdb_rsp::frame::PacketWriter;
use gdb_rsp::hex::decode;
use gdb_rsp::target::Arch;

/// Where a GDB register's value comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot
{
    /// A field of the register file: its byte offset, and how many of its
    /// low bytes the register holds. `writable` is false for a field the
    /// stub keeps (the x86-64 segment selectors).
    Field
    {
        offset: usize,
        bytes: usize,
        writable: bool,
    },
    /// A register that always reads zero (riscv64 `x0`).
    Zero,
    /// A register the kernel's register file does not hold (the floating
    /// point and vector registers, the x86-64 data segment selectors): sent
    /// as unavailable, and a write to it is ignored.
    Unavailable,
}

/// The x86-64 register file's field offsets, in its order (`TrapFrame`):
/// `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `rbp`, `r8`..`r15`, `rip`,
/// `rflags`, `rsp`, `cs`, `ss`, `fs_base`.
mod x86_64
{
    pub const RAX: usize = 0;
    pub const RBX: usize = 8;
    pub const RCX: usize = 16;
    pub const RDX: usize = 24;
    pub const RSI: usize = 32;
    pub const RDI: usize = 40;
    pub const RBP: usize = 48;
    pub const R8: usize = 56;
    pub const RIP: usize = syscall_abi::REGS_X86_64_IP_OFFSET;
    pub const RFLAGS: usize = syscall_abi::REGS_X86_64_FLAGS_OFFSET;
    pub const RSP: usize = syscall_abi::REGS_X86_64_SP_OFFSET;
    pub const CS: usize = 144;
    pub const SS: usize = 152;
}

/// The slot of GDB register `regnum`; `None` past the description's last
/// register.
#[must_use]
pub fn slot(arch: Arch, regnum: usize) -> Option<Slot>
{
    if regnum >= arch.registers().len()
    {
        return None;
    }
    let field = |offset, bytes| Slot::Field {
        offset,
        bytes,
        writable: true,
    };
    Some(match arch
    {
        Arch::X86_64 => match regnum
        {
            0 => field(x86_64::RAX, 8),
            1 => field(x86_64::RBX, 8),
            2 => field(x86_64::RCX, 8),
            3 => field(x86_64::RDX, 8),
            4 => field(x86_64::RSI, 8),
            5 => field(x86_64::RDI, 8),
            6 => field(x86_64::RBP, 8),
            7 => field(x86_64::RSP, 8),
            8..=15 => field(x86_64::R8 + (regnum - 8) * 8, 8),
            16 => field(x86_64::RIP, 8),
            17 => field(x86_64::RFLAGS, 4),
            18 | 19 => Slot::Field {
                offset: if regnum == 18 { x86_64::CS } else { x86_64::SS },
                bytes: 4,
                writable: false,
            },
            _ => Slot::Unavailable,
        },
        Arch::Riscv64 => match regnum
        {
            0 => Slot::Zero,
            1..=31 => field(syscall_abi::REGS_RISCV64_X1_OFFSET + (regnum - 1) * 8, 8),
            32 => field(syscall_abi::REGS_RISCV64_IP_OFFSET, 8),
            _ => Slot::Unavailable,
        },
    })
}

/// The register file's size, in bytes, on `arch`.
#[must_use]
pub fn file_size(arch: Arch) -> usize
{
    match arch
    {
        Arch::X86_64 => syscall_abi::REGS_X86_64_SIZE,
        Arch::Riscv64 => syscall_abi::REGS_RISCV64_SIZE,
    }
}

/// Write register `regnum`'s value from the register file `file` to `w`, in
/// hex, the bytes the description gives it: a field's bytes, zero-extended
/// to the register's size; zeros; or unavailable.
pub fn encode_register(arch: Arch, file: &[u8], regnum: usize, w: &mut PacketWriter<'_>)
{
    let size = arch.registers().get(regnum).map_or(0, |r| r.bytes);
    match slot(arch, regnum)
    {
        Some(Slot::Field { offset, bytes, .. }) =>
        {
            let mut value = [0u8; 16];
            let n = bytes.min(size);
            if let Some(src) = file.get(offset..offset + n)
            {
                value[..n].copy_from_slice(src);
            }
            w.hex(&value[..size]);
        }
        Some(Slot::Zero) =>
        {
            w.hex(&[0u8; 16][..size]);
        }
        Some(Slot::Unavailable) | None =>
        {
            w.unavailable(size);
        }
    }
}

/// Write every register, in description order: the body of a `g` reply.
pub fn encode_registers(arch: Arch, file: &[u8], w: &mut PacketWriter<'_>)
{
    for regnum in 0..arch.registers().len()
    {
        encode_register(arch, file, regnum, w);
    }
}

/// Why a register write was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError
{
    /// The register number is past the description's last register.
    NoSuchRegister,
    /// The value is not the register's size in hex digits.
    BadValue,
}

/// Apply GDB's hex `value` for register `regnum` to the register file
/// `file`. A read-only or unavailable register, or one reading zero, keeps
/// its value: GDB writes every register of a `G` block back, changed or
/// not.
///
/// # Errors
/// [`WriteError::NoSuchRegister`] past the last register;
/// [`WriteError::BadValue`] for a value that is not the register's size.
pub fn write_register(
    arch: Arch,
    regnum: usize,
    value: &[u8],
    file: &mut [u8],
) -> Result<(), WriteError>
{
    let size = arch
        .registers()
        .get(regnum)
        .ok_or(WriteError::NoSuchRegister)?
        .bytes;
    let mut bytes = [0u8; 16];
    if value.len() != size * 2 || value.contains(&b'x')
    {
        // `xx` marks bytes GDB does not know; such a value changes nothing.
        return if value.len() == size * 2
        {
            Ok(())
        }
        else
        {
            Err(WriteError::BadValue)
        };
    }
    decode(value, &mut bytes).map_err(|_| WriteError::BadValue)?;
    if let Some(Slot::Field {
        offset,
        bytes: n,
        writable: true,
    }) = slot(arch, regnum)
        && let Some(dst) = file.get_mut(offset..offset + n)
    {
        dst.copy_from_slice(&bytes[..n]);
    }
    Ok(())
}

/// Apply a `G` packet's hex register block to `file`, register by register.
///
/// # Errors
/// [`WriteError::BadValue`] when the block is not the description's whole
/// register block in hex.
pub fn write_registers(arch: Arch, block: &[u8], file: &mut [u8]) -> Result<(), WriteError>
{
    if block.len() != arch.register_block_len() * 2
    {
        return Err(WriteError::BadValue);
    }
    let mut at = 0;
    for (regnum, reg) in arch.registers().iter().enumerate()
    {
        write_register(arch, regnum, &block[at..at + reg.bytes * 2], file)?;
        at += reg.bytes * 2;
    }
    Ok(())
}

/// The program counter's value in `file`.
#[must_use]
pub fn pc(arch: Arch, file: &[u8]) -> u64
{
    let offset = match arch
    {
        Arch::X86_64 => x86_64::RIP,
        Arch::Riscv64 => syscall_abi::REGS_RISCV64_IP_OFFSET,
    };
    file.get(offset..offset + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

#[cfg(test)]
mod tests
{
    use super::*;

    extern crate std;
    use std::vec::Vec;

    fn body(f: impl FnOnce(&mut PacketWriter<'_>)) -> Vec<u8>
    {
        let mut buf = [0u8; 4096];
        let mut w = PacketWriter::new(&mut buf);
        f(&mut w);
        let n = w.finish().unwrap();
        buf[1..n - 3].to_vec()
    }

    /// A register file whose every u64 field holds its own byte offset.
    fn numbered_file(arch: Arch) -> Vec<u8>
    {
        let mut file = std::vec![0u8; file_size(arch)];
        for (i, word) in file.chunks_mut(8).enumerate()
        {
            word.copy_from_slice(&((i * 8) as u64).to_le_bytes());
        }
        file
    }

    #[test]
    fn x86_64_registers_come_from_the_register_file_in_gdb_order()
    {
        let file = numbered_file(Arch::X86_64);
        let block = body(|w| encode_registers(Arch::X86_64, &file, w));
        assert_eq!(block.len(), Arch::X86_64.register_block_len() * 2);
        let hex_of = |regnum: usize| {
            let span = Arch::X86_64.register_span(regnum).unwrap();
            std::string::String::from_utf8(block[span.start * 2..span.end * 2].to_vec()).unwrap()
        };
        // rsp sits apart from the other general registers in the file.
        assert_eq!(hex_of(7), "8800000000000000");
        assert_eq!(hex_of(8), "3800000000000000");
        assert_eq!(hex_of(16), "7800000000000000");
        // eflags is the low four bytes of rflags.
        assert_eq!(hex_of(17), "80000000");
        assert_eq!(hex_of(18), "90000000");
        // The data segment selectors and the x87 and SSE state are not held.
        assert_eq!(hex_of(20), "xxxxxxxx");
        assert_eq!(hex_of(24), "xxxxxxxxxxxxxxxxxxxx");
    }

    #[test]
    fn riscv64_registers_read_x0_as_zero_and_the_rest_from_the_file()
    {
        let file = numbered_file(Arch::Riscv64);
        let block = body(|w| encode_registers(Arch::Riscv64, &file, w));
        let hex_of = |regnum: usize| {
            let span = Arch::Riscv64.register_span(regnum).unwrap();
            std::string::String::from_utf8(block[span.start * 2..span.end * 2].to_vec()).unwrap()
        };
        assert_eq!(hex_of(0), "0000000000000000");
        assert_eq!(hex_of(1), "0000000000000000");
        assert_eq!(hex_of(2), "0800000000000000");
        assert_eq!(hex_of(31), "f000000000000000");
        assert_eq!(hex_of(32), "f800000000000000");
        assert_eq!(hex_of(33), "xxxxxxxxxxxxxxxx");
        assert_eq!(pc(Arch::Riscv64, &file), 0xf8);
    }

    #[test]
    fn a_register_block_written_back_unchanged_leaves_the_file_unchanged()
    {
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            let file = numbered_file(arch);
            let block = body(|w| encode_registers(arch, &file, w));
            let mut copy = file.clone();
            write_registers(arch, &block, &mut copy).unwrap();
            assert_eq!(copy, file, "{arch:?}");
        }
    }

    #[test]
    fn a_register_write_changes_its_field_alone()
    {
        let mut file = numbered_file(Arch::X86_64);
        let before = file.clone();
        write_register(Arch::X86_64, 16, b"efbeadde00000000", &mut file).unwrap();
        assert_eq!(pc(Arch::X86_64, &file), 0xdead_beef);
        assert_eq!(file[..x86_64::RIP], before[..x86_64::RIP]);
        assert_eq!(file[x86_64::RIP + 8..], before[x86_64::RIP + 8..]);
        // eflags writes the low half of rflags only.
        write_register(Arch::X86_64, 17, b"46020000", &mut file).unwrap();
        assert_eq!(
            &file[x86_64::RFLAGS..x86_64::RFLAGS + 8],
            &[0x46, 0x02, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn writes_to_kept_unavailable_and_zero_registers_change_nothing()
    {
        let mut file = numbered_file(Arch::X86_64);
        let before = file.clone();
        write_register(Arch::X86_64, 18, b"33000000", &mut file).unwrap();
        write_register(Arch::X86_64, 24, b"00000000000000000000", &mut file).unwrap();
        write_register(Arch::X86_64, 0, b"xxxxxxxxxxxxxxxx", &mut file).unwrap();
        assert_eq!(file, before);
        let mut rv = numbered_file(Arch::Riscv64);
        let rv_before = rv.clone();
        write_register(Arch::Riscv64, 0, b"0100000000000000", &mut rv).unwrap();
        assert_eq!(rv, rv_before);
    }

    #[test]
    fn a_write_of_the_wrong_size_or_register_is_refused()
    {
        let mut file = numbered_file(Arch::Riscv64);
        assert_eq!(
            write_register(Arch::Riscv64, 1, b"00", &mut file),
            Err(WriteError::BadValue)
        );
        assert_eq!(
            write_register(Arch::Riscv64, 1000, b"00", &mut file),
            Err(WriteError::NoSuchRegister)
        );
        assert_eq!(
            write_registers(Arch::Riscv64, b"0011", &mut file),
            Err(WriteError::BadValue)
        );
    }
}
