// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/breakpoint_kill.rs

//! The kill of a guest process from outside the guest at a hardware
//! breakpoint, through QEMU's gdbstub: the CPU that runs a function of the
//! process's binary is moved to program counter 0, an address no process
//! maps, so the process takes a fault no handler resolves. The `shutdown`
//! case's death boots kill memmgr and procmgr so, and the `debug-port` case's
//! boots the debug port's driver, which declares itself undebuggable and so is
//! out of every in-guest debugger's reach.

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SymbolKind};

use crate::arch::Arch;
use crate::context::Context;
use crate::debug_stub;
use crate::error::{Context as _, Result, bail};
use crate::qemu_gdb::{Stub, field_hex, function_path, le_hex, stop_thread};
use crate::symbolize::store::Store;

/// Budget for one reply of QEMU's gdbstub, and for the breakpoint's hit.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(20);
const HIT_TIMEOUT: Duration = Duration::from_mins(1);

/// Stops at the breakpoint's address whose code is not the target's (another
/// process running at the same address) before the kill gives up.
const FOREIGN_HITS_MAX: u32 = 8;

/// Stops in the target's code by a thread the kill does not take ([`Take`])
/// before the kill gives up.
const PASSED_HITS_MAX: u32 = 256;

/// The gdbstub thread of the CPU of index 0: QEMU numbers its threads by CPU
/// index from 1.
const FIRST_CPU_THREAD: u64 = 1;

/// The stops in the target's code that are the kill's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Take
{
    /// Every stop.
    Any,
    /// A stop whose stack pointer lies in `[start, end)`: one of the threads
    /// whose stacks the target keeps there (memmgr's receive threads but its
    /// main one). Any other stop is passed over, the breakpoint kept for the
    /// next.
    StackIn
    {
        start: u64, end: u64
    },
}

impl Take
{
    /// Whether a stop with stack pointer `sp` is the kill's.
    #[must_use]
    pub fn take(self, sp: u64) -> bool
    {
        match self
        {
            Self::Any => true,
            Self::StackIn { start, end } => (start..end).contains(&sp),
        }
    }
}

/// The register number of the stack pointer in `arch`'s register block.
fn sp_regnum(arch: Arch) -> Result<usize>
{
    let name = match arch
    {
        Arch::X86_64 => "rsp",
        Arch::Riscv64 => "sp",
    };
    debug_stub::rsp_arch(arch)
        .registers()
        .iter()
        .position(|r| r.name == name)
        .with_context(|| format!("no {name} register in the {arch:?} register block"))
}

/// Bytes of code compared at the stop.
pub const CODE_CHECK_BYTES: usize = 16;

/// The start of procmgr's line naming a process's image bias, which ends
/// with the process's name in parentheses. Kept in sync with
/// `services/procmgr/src/main.rs`.
const SPAWN_BIAS: &str = "spawn image bias=";

/// A breakpoint's function, resolved in its binary.
#[derive(Debug)]
pub struct Function
{
    /// The function's link address.
    pub address: u64,
    /// Its first [`CODE_CHECK_BYTES`] bytes.
    pub code: Vec<u8>,
}

/// What [`kill_at_breakpoint`] did: the program counter it moved, the CPU
/// whose it was (QEMU's index, from 0), the moment the VM resumed, and the
/// trigger's result.
pub struct Killed<T>
{
    pub pc: u64,
    pub cpu: u64,
    pub resumed: Instant,
    pub triggered: T,
}

/// The function whose demangled path is `path` in the binary installed at
/// `installed` under the sysroot. The installed image is stripped: its
/// symbols, and its code, are read from the symbols store's file of its build
/// id.
pub fn resolve_installed(ctx: &Context, installed: &str, path: &str) -> Result<Function>
{
    let file = Store::at(ctx.symbols_dir()).symbols_path(&ctx.sysroot.join(installed))?;
    let data = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
    resolve(&data, path).with_context(|| format!("finding {path} in {}", file.display()))
}

/// The image bias of the process named `name` from procmgr's
/// `spawn image bias=0x… (<name>)` lines among `lines`, the first such line.
pub fn spawn_bias<S: AsRef<str>>(lines: &[S], name: &str) -> Option<u64>
{
    let suffix = format!(" ({name})");
    lines
        .iter()
        .map(AsRef::as_ref)
        .filter(|l| l.trim_end().ends_with(&suffix))
        .find_map(|l| field_hex(l, SPAWN_BIAS))
}

/// Over QEMU's gdbstub at `sock`, break on `function` at `bias`, run
/// `trigger` on a thread of its own once the VM runs again, and move the
/// CPU stopped in the function's code, by a stop `take` takes, to program
/// counter 0.
/// The trigger is joined after the detach that resumes the VM; a function the
/// target runs unasked needs none.
pub fn kill_at_breakpoint<T: Send + 'static>(
    arch: Arch,
    sock: &Path,
    bias: u64,
    function: &Function,
    take: Take,
    trigger: impl FnOnce() -> T + Send + 'static,
) -> Result<Killed<T>>
{
    let pc_reg = debug_stub::rsp_arch(arch).pc_regnum();
    let sp_reg = sp_regnum(arch)?;
    let at = bias.wrapping_add(function.address);
    let kind = breakpoint_kind(arch);
    // Connecting stops the VM.
    let mut stub = Stub::connect(sock, ANSWER_TIMEOUT)?;
    stub.request(b"?")?;
    stub.expect_ok(format!("Z1,{at:x},{kind:x}").as_bytes())?;
    // Run once the VM runs again, while the continue below waits.
    let trigger = thread::spawn(trigger);
    let mut foreign: u32 = 0;
    let mut passed: u32 = 0;
    let (moved, cpu) = loop
    {
        stub.set_answer_timeout(HIT_TIMEOUT)?;
        let reply = stub.request(b"c")?;
        stub.set_answer_timeout(ANSWER_TIMEOUT)?;
        let thread = stop_thread(&reply).with_context(|| {
            format!(
                "a stop reply naming no CPU: {}",
                String::from_utf8_lossy(&reply)
            )
        })?;
        stub.expect_ok(format!("Hg{thread:x}").as_bytes())?;
        // Reading the whole register block has QEMU fetch the CPU's state
        // from the accelerator and write it back on resume (the `wedge` case).
        stub.request(b"g")?;
        let pc = stub.read_register(pc_reg)?;
        let code = stub.read_memory(pc, CODE_CHECK_BYTES)?;
        if pc == at && code == function.code
        {
            if take.take(stub.read_register(sp_reg)?)
            {
                stub.expect_ok(format!("P{pc_reg:x}={}", le_hex(0)).as_bytes())?;
                break (pc, thread.saturating_sub(FIRST_CPU_THREAD));
            }
            passed = passed.saturating_add(1);
            if passed >= PASSED_HITS_MAX
            {
                bail!(
                    "{PASSED_HITS_MAX} stops in the target's code were by threads the kill passes over"
                );
            }
        }
        else
        {
            foreign = foreign.saturating_add(1);
            if foreign >= FOREIGN_HITS_MAX
            {
                bail!("{FOREIGN_HITS_MAX} stops at {at:#x} ran other code than the target's");
            }
        }
        step_over(&mut stub, thread, at, kind)?;
    };
    stub.expect_ok(format!("z1,{at:x},{kind:x}").as_bytes())?;
    stub.expect_ok(b"D")?;
    let resumed = Instant::now();
    let triggered = trigger
        .join()
        .map_err(|_| crate::error::Error::msg("the trigger's thread panicked"))?;
    Ok(Killed {
        pc: moved,
        cpu,
        resumed,
        triggered,
    })
}

/// Resume the CPU of gdbstub thread `thread`, stopped at the breakpoint at
/// `at`, past it: remove the breakpoint, step that CPU one instruction, and
/// set the breakpoint again, so the next continue does not stop at once on
/// the same instruction.
fn step_over(stub: &mut Stub, thread: u64, at: u64, kind: u32) -> Result<()>
{
    stub.expect_ok(format!("z1,{at:x},{kind:x}").as_bytes())?;
    stub.expect_ok(format!("Hc{thread:x}").as_bytes())?;
    let reply = stub.request(b"s")?;
    if stop_thread(&reply).is_none()
    {
        bail!(
            "a step answered with no stop: {}",
            String::from_utf8_lossy(&reply)
        );
    }
    stub.expect_ok(format!("Z1,{at:x},{kind:x}").as_bytes())
}

/// The `kind` of a hardware breakpoint: the instruction's length, which
/// QEMU does not need for a hardware breakpoint but GDB sends.
fn breakpoint_kind(arch: Arch) -> u32
{
    match arch
    {
        Arch::X86_64 => 1,
        Arch::Riscv64 => 4,
    }
}

/// Find the function whose demangled path is `path` in the ELF `data`: its
/// link address and its first code bytes.
pub fn resolve(data: &[u8], path: &str) -> Result<Function>
{
    let file = object::File::parse(data).context("parsing the ELF")?;
    let mut found = None;
    for sym in file.symbols()
    {
        if sym.kind() != SymbolKind::Text || !sym.is_definition() || sym.size() == 0
        {
            continue;
        }
        let Ok(raw) = sym.name()
        else
        {
            continue;
        };
        if function_path(&crate::symbolize::demangle(raw)) != path
        {
            continue;
        }
        if found
            .replace(sym.address())
            .is_some_and(|a| a != sym.address())
        {
            bail!("two symbols named {path}");
        }
    }
    let address = found.with_context(|| format!("no symbol {path} (is it inlined?)"))?;
    let code = file
        .sections()
        .find_map(|s| {
            s.data_range(address, CODE_CHECK_BYTES as u64)
                .ok()
                .flatten()
        })
        .with_context(|| format!("no section holds {path}'s code"))?
        .to_vec();
    Ok(Function { address, code })
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a kill that must miss memmgr's main thread taking a
    // stop whose stack lies outside the receive threads' zone, or missing
    // one inside it.
    #[test]
    fn only_a_stop_on_a_stack_in_the_range_is_taken_when_it_must_be()
    {
        let take = Take::StackIn {
            start: 0x1000,
            end: 0x2000,
        };
        assert!(Take::Any.take(0));
        assert!(!take.take(0xfff));
        assert!(take.take(0x1000));
        assert!(take.take(0x1fff));
        assert!(!take.take(0x2000));
    }

    // Defect caught: the stack pointer read from another register than
    // `rsp` or `sp`, so the kill judges a stop by an unrelated value.
    #[test]
    fn the_stack_pointer_is_found_in_each_register_block()
    {
        assert_eq!(sp_regnum(Arch::X86_64).unwrap(), 7);
        assert_eq!(sp_regnum(Arch::Riscv64).unwrap(), 2);
    }

    // Defect caught: a breakpoint set on another function than the one
    // named, or on a symbol the host's own binary resolves.
    #[test]
    fn a_function_is_resolved_by_its_path_with_its_code()
    {
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let f = resolve(&exe, "xtask::breakpoint_kill::resolve").unwrap();
        assert_eq!(f.code.len(), CODE_CHECK_BYTES);
        resolve(&exe, "xtask::breakpoint_kill::no_such_function").unwrap_err();
    }

    // Defect caught: another process's bias taken for the named one's, or
    // a name that only starts the process's name matched.
    #[test]
    fn a_spawn_bias_is_read_from_the_line_naming_its_process()
    {
        let lines = [
            "[1.0] [procmgr] spawn image bias=0x1000 (/services/drivers/virtio-input)",
            "[1.1] [procmgr] spawn image bias=0x2000 (/services/drivers/virtio-console)",
            "[1.2] [procmgr] spawn image bias=0x3000 (/services/drivers/virtio-console)",
        ];
        assert_eq!(
            spawn_bias(&lines, "/services/drivers/virtio-console"),
            Some(0x2000)
        );
        assert_eq!(spawn_bias(&lines, "virtio-console"), None);
        assert_eq!(spawn_bias(&lines, "/services/drivers/virtio-rng"), None);
    }
}
