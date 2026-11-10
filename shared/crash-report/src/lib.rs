// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crash-report/src/lib.rs

//! The crash-report block: crashd's emitter and the host tools' parser of one
//! format (services/crashd/docs/block-format.md).
//!
//! crashd fills a [`Report`] for a faulting thread and [`Report::emit`]s it as
//! the lines of one block, each logged to logd; a host tool reads a boot's log
//! back with [`parse`], which yields one [`Block`] per begin marker, and
//! [`Block::check`] tells whether a block holds every field its kind requires.
//! [`walk::scan`] is the stack walk crashd runs for the block's frames.
//!
//! `no_std` with `alloc`: the parser builds owned blocks; the emitter
//! allocates nothing.

#![no_std]

extern crate alloc;

mod parse;
pub mod walk;

use core::fmt;

pub use parse::{Block, Defect, parse};

/// The block format's version, carried on the begin marker. A change that
/// renames or removes a field, or changes a value's encoding, bumps it; a new
/// field does not, since a parser ignores keys it does not know.
pub const VERSION: u32 = 1;

/// The begin marker's tag.
pub const BEGIN_TAG: &str = "CRASH-BEGIN";
/// The tag of every field line.
pub const FIELD_TAG: &str = "CRASH";
/// The end marker's tag.
pub const END_TAG: &str = "CRASH-END";

/// Most instruction bytes a report carries, from the instruction pointer on.
pub const MAX_CODE_BYTES: usize = 16;

/// Most frames a report carries, the instruction pointer included.
pub const MAX_FRAMES: usize = 32;

/// The architecture of the faulting process, which names its registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch
{
    /// x86-64.
    X86_64,
    /// riscv64.
    Riscv64,
}

/// x86-64 register names, in the order of the register file
/// `SYS_THREAD_READ_REGS` fills (the kernel's `TrapFrame`).
const X86_64_REGISTERS: [&str; 21] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
    "r15", "rip", "rflags", "rsp", "cs", "ss", "fs_base",
];

/// riscv64 register names, in the order of the register file
/// `SYS_THREAD_READ_REGS` fills: `x1` to `x31` by their ABI names, then the
/// trap CSRs.
const RISCV64_REGISTERS: [&str; 35] = [
    "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6",
    "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
    "sepc", "scause", "stval", "sstatus",
];

// ABI contract: one name per `u64` of each architecture's register file, whose
// size `abi/syscall` publishes and the kernel asserts its `TrapFrame` against.
const _: () = assert!(X86_64_REGISTERS.len() * 8 == syscall_abi::REGS_X86_64_SIZE);
const _: () = assert!(RISCV64_REGISTERS.len() * 8 == syscall_abi::REGS_RISCV64_SIZE);

impl Arch
{
    /// The value of the report's `arch` field.
    #[must_use]
    pub fn name(self) -> &'static str
    {
        match self
        {
            Arch::X86_64 => "x86_64",
            Arch::Riscv64 => "riscv64",
        }
    }

    /// The names of the register file's words, in its order; the report's
    /// `reg.<name>` fields use them.
    #[must_use]
    pub fn register_names(self) -> &'static [&'static str]
    {
        match self
        {
            Arch::X86_64 => &X86_64_REGISTERS,
            Arch::Riscv64 => &RISCV64_REGISTERS,
        }
    }

    fn from_name(name: &str) -> Option<Arch>
    {
        match name
        {
            "x86_64" => Some(Arch::X86_64),
            "riscv64" => Some(Arch::Riscv64),
            _ => None,
        }
    }
}

/// Which thread of the process faulted, as far as the reporter can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Thread
{
    /// The process's main thread, whose registers the report carries.
    Main,
    /// A thread the runtime spawned and registered with procmgr, whose
    /// registers the report carries.
    Spawned,
    /// A thread the reporter could not identify (one that never registered):
    /// the report carries the fault and the image, but no registers and no
    /// frames.
    Unidentified,
}

impl Thread
{
    fn name(self) -> &'static str
    {
        match self
        {
            Thread::Main => "main",
            Thread::Spawned => "spawned",
            Thread::Unidentified => "unidentified",
        }
    }

    /// Whether a report of this thread carries its registers and stack walk
    /// when complete.
    #[must_use]
    pub fn carries_registers(self) -> bool
    {
        matches!(self, Thread::Main | Thread::Spawned)
    }
}

/// How far the reporter got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status
{
    /// Every field the thread's identification allows.
    Complete,
    /// The reporter could not attach to the process (it had exited, or was
    /// refused): the report carries the fault message alone.
    Unattached,
    /// The reporter's bound on one fault elapsed before it finished: the
    /// report carries what it had read by then.
    Timeout,
}

impl Status
{
    fn name(self) -> &'static str
    {
        match self
        {
            Status::Complete => "complete",
            Status::Unattached => "unattached",
            Status::Timeout => "timeout",
        }
    }
}

/// The access a virtual-memory fault made, from the fault message's access
/// bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access
{
    /// A data read.
    Read,
    /// A data write.
    Write,
    /// An instruction fetch.
    Fetch,
}

impl Access
{
    /// The access the fault message's access word (`FAULT_ACCESS_*` bits)
    /// names: a fetch when its fetch bit is set, else a write when its write
    /// bit is, else a read.
    #[must_use]
    pub fn from_flags(flags: u64) -> Access
    {
        if flags & syscall_abi::FAULT_ACCESS_EXEC != 0
        {
            Access::Fetch
        }
        else if flags & syscall_abi::FAULT_ACCESS_WRITE != 0
        {
            Access::Write
        }
        else
        {
            Access::Read
        }
    }

    fn name(self) -> &'static str
    {
        match self
        {
            Access::Read => "read",
            Access::Write => "write",
            Access::Fetch => "fetch",
        }
    }
}

/// The fault the kernel delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault
{
    /// A virtual-memory fault (`FAULT_KIND_VM`), which the pager declined
    /// and forwarded.
    Vm
    {
        /// The access that faulted.
        access: Access,
        /// The faulting address.
        addr: u64,
        /// The pager's decline reason, when it forwarded one.
        pager_reason: Option<u64>,
    },
    /// A CPU exception (`FAULT_KIND_EXCEPTION`).
    Exception
    {
        /// The normalized exception code (`FAULT_EXC_*`).
        code: u64,
        /// The architecture's auxiliary code: the x86-64 error code, or the
        /// riscv64 `stval`.
        aux: u64,
    },
}

/// The normalized exception code's name, the report's `exception` field; an
/// unrecognized code is the unknown class, as the fault-message contract
/// requires of every handler.
#[must_use]
pub fn exception_name(code: u64) -> &'static str
{
    match code
    {
        syscall_abi::FAULT_EXC_ILLEGAL_INSTRUCTION => "illegal-instruction",
        syscall_abi::FAULT_EXC_BREAKPOINT => "breakpoint",
        syscall_abi::FAULT_EXC_DEBUG => "debug",
        syscall_abi::FAULT_EXC_DIVIDE => "divide",
        syscall_abi::FAULT_EXC_OVERFLOW => "overflow",
        syscall_abi::FAULT_EXC_BOUND_RANGE => "bound-range",
        syscall_abi::FAULT_EXC_ALIGNMENT => "alignment",
        syscall_abi::FAULT_EXC_ACCESS => "access",
        syscall_abi::FAULT_EXC_PROTECTION => "protection",
        syscall_abi::FAULT_EXC_FP => "fp",
        _ => "unknown",
    }
}

/// Where the process's image lies: its load bias and its text range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image
{
    /// The bias the loader added to every ELF address of the image.
    pub load_bias: u64,
    /// Lowest byte of the image's executable segments, biased.
    pub text_start: u64,
    /// One past the highest byte of the image's executable segments, biased.
    pub text_end: u64,
}

/// One crash report, as crashd fills it.
pub struct Report<'a>
{
    /// The block's id, on both markers and every field line; crashd also
    /// gives it as its decline reason, which the kernel prints.
    pub id: u64,
    /// The process badge, the identity logd's reclaim line also prints.
    pub badge: u64,
    /// The process's architecture.
    pub arch: Arch,
    /// Which thread faulted.
    pub thread: Thread,
    /// How far the reporter got.
    pub status: Status,
    /// The fault.
    pub fault: Fault,
    /// The faulting instruction pointer from the fault message.
    pub ip: u64,
    /// The image's placement, when the reporter attached.
    pub image: Option<Image>,
    /// The register file, one word per [`Arch::register_names`] entry; empty
    /// when the reporter read none.
    pub regs: &'a [u64],
    /// The bytes at the instruction pointer, at most [`MAX_CODE_BYTES`];
    /// empty when unread.
    pub code: &'a [u8],
    /// The stack walk: the instruction pointer, then the candidate return
    /// addresses, at most [`MAX_FRAMES`]; empty when no walk ran.
    pub frames: &'a [u64],
}

/// A field value and its encoding.
#[derive(Clone, Copy)]
enum Value<'a>
{
    Hex(u64),
    Dec(u64),
    Text(&'a str),
    Range(u64, u64),
    Bytes(&'a [u8]),
}

impl fmt::Display for Value<'_>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match *self
        {
            Value::Hex(v) => write!(f, "0x{v:016x}"),
            Value::Dec(v) => write!(f, "{v}"),
            Value::Text(s) => f.write_str(s),
            Value::Range(a, b) => write!(f, "0x{a:016x}-0x{b:016x}"),
            Value::Bytes(bytes) =>
            {
                for b in bytes
                {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }
    }
}

/// The key of a field line: a plain name, or a name with an index or a
/// register suffix.
#[derive(Clone, Copy)]
enum Key
{
    Plain(&'static str),
    Reg(&'static str),
    Frame(usize),
}

impl fmt::Display for Key
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match *self
        {
            Key::Plain(name) => f.write_str(name),
            Key::Reg(name) => write!(f, "reg.{name}"),
            Key::Frame(n) => write!(f, "frame.{n}"),
        }
    }
}

/// One line of a block.
enum Line<'a>
{
    Begin(u64),
    Field(u64, Key, Value<'a>),
    End(u64, usize),
}

impl fmt::Display for Line<'_>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Line::Begin(id) => write!(f, "{BEGIN_TAG} id={id:016x} version={VERSION}"),
            Line::Field(id, key, value) => write!(f, "{FIELD_TAG} id={id:016x} {key}={value}"),
            Line::End(id, count) => write!(f, "{END_TAG} id={id:016x} lines={count}"),
        }
    }
}

impl Report<'_>
{
    /// Hand each line of the block to `out`, in order: the begin marker, the
    /// field lines, the end marker, which counts the field lines. Returns the
    /// number of lines handed over, markers included.
    ///
    /// Registers are emitted only when `regs` holds one word per register of
    /// the architecture; code bytes past [`MAX_CODE_BYTES`] and frames past
    /// [`MAX_FRAMES`] are not emitted.
    pub fn emit(&self, mut out: impl FnMut(&dyn fmt::Display)) -> usize
    {
        let id = self.id;
        out(&Line::Begin(id));
        let mut fields = 0usize;
        self.emit_fields(&mut |key, value| {
            out(&Line::Field(id, key, value));
            fields += 1;
        });
        out(&Line::End(id, fields));
        fields + 2
    }

    fn emit_fields(&self, field: &mut dyn FnMut(Key, Value<'_>))
    {
        field(Key::Plain("badge"), Value::Dec(self.badge));
        field(Key::Plain("arch"), Value::Text(self.arch.name()));
        field(Key::Plain("thread"), Value::Text(self.thread.name()));
        field(Key::Plain("status"), Value::Text(self.status.name()));
        match self.fault
        {
            Fault::Vm {
                access,
                addr,
                pager_reason,
            } =>
            {
                field(Key::Plain("kind"), Value::Text("vm"));
                field(Key::Plain("access"), Value::Text(access.name()));
                field(Key::Plain("addr"), Value::Hex(addr));
                if let Some(reason) = pager_reason
                {
                    field(Key::Plain("pager_reason"), Value::Hex(reason));
                }
            }
            Fault::Exception { code, aux } =>
            {
                field(Key::Plain("kind"), Value::Text("exception"));
                field(Key::Plain("exception"), Value::Text(exception_name(code)));
                field(Key::Plain("aux"), Value::Hex(aux));
            }
        }
        field(Key::Plain("ip"), Value::Hex(self.ip));
        if let Some(image) = self.image
        {
            field(Key::Plain("load_bias"), Value::Hex(image.load_bias));
            field(
                Key::Plain("text"),
                Value::Range(image.text_start, image.text_end),
            );
        }
        let names = self.arch.register_names();
        if self.regs.len() == names.len()
        {
            for (name, value) in names.iter().zip(self.regs)
            {
                field(Key::Reg(name), Value::Hex(*value));
            }
        }
        if !self.code.is_empty()
        {
            let len = self.code.len().min(MAX_CODE_BYTES);
            field(Key::Plain("code"), Value::Bytes(&self.code[..len]));
        }
        if !self.frames.is_empty()
        {
            field(Key::Plain("walk"), Value::Text("scan"));
            for (n, frame) in self.frames.iter().take(MAX_FRAMES).enumerate()
            {
                field(Key::Frame(n), Value::Hex(*frame));
            }
        }
    }
}

#[cfg(test)]
mod tests;
