// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/debug_stub.rs

//! Staging the GDB stub for one boot, the GDB command line that connects to
//! it, and the kill of the process it holds that the host tests make.
//!
//! The stub's recipe template lives at `config/svcmgr/debug/gdbstub.svc`,
//! which svcmgr does not scan. Staging writes it into
//! `config/svcmgr/services/` with the target's name appended to its `argv`
//! and repacks the disk images in the layout they already had (the block
//! size of `disk.img`, and the data partition on `disk-data.img` when one
//! is there), so a 4Kn or split boot stays one; unstaging removes it and
//! repacks again in that layout.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Context as _, Result, bail};

use crate::arch::Arch;
use crate::context::Context;
use crate::disk::DiskLayout;
use crate::qemu_gdb::{Stub, le_hex, le_u64};

/// The stub's line once it holds its target, followed by ` (<target>)`. Kept
/// in sync with `services/gdbstub/src/main.rs`.
pub const ATTACHED_MARKER: &str = "[gdbstub] attached; serving the debug port";

/// The stub's answer to a register write of a thread held in a call, whose
/// registers the call's return still writes, so the kernel writes them only
/// once the call returns. Kept in sync with `IN_CALL_CODE` in
/// `services/gdbstub/src/session.rs`.
const HELD_IN_CALL: &[u8] = b"E06";

/// How long a kill reads and writes again the program counter of a main
/// thread held in a call: a server can answer late, as a file-system read stalled 43 s on a
/// loaded riscv64 host (#1382).
const IN_CALL_WAIT: Duration = Duration::from_secs(60);

/// The pause between two tries of a thread held in a call.
const IN_CALL_PAUSE: Duration = Duration::from_millis(100);

/// The stub's recipe file name, in the template directory and once staged.
const RECIPE: &str = "gdbstub.svc";

/// The longest target name: procmgr records a process's name truncated to
/// `svcmgr_labels::NAME_MAX` (64) bytes, so a longer one never matches.
const NAME_MAX: usize = 64;

/// Where the stub's recipe template is installed in the sysroot.
fn template(ctx: &Context) -> PathBuf
{
    ctx.sysroot.join("config/svcmgr/debug").join(RECIPE)
}

/// Where the staged recipe goes.
fn staged(ctx: &Context) -> PathBuf
{
    ctx.sysroot.join("config/svcmgr/services").join(RECIPE)
}

/// The template's recipe with `target` appended to its `argv` line.
fn recipe_for(template: &str, target: &str) -> Result<String>
{
    if target.is_empty() || target.contains(char::is_whitespace)
    {
        bail!("debug target name {target:?} must be one word");
    }
    if target.len() > NAME_MAX
    {
        bail!("debug target name {target:?} is longer than procmgr's {NAME_MAX}-byte names");
    }
    let mut found = false;
    let lines: Vec<String> = template
        .lines()
        .map(|line| {
            if line.starts_with("argv") && line.contains('=')
            {
                found = true;
                format!("{line} {target}")
            }
            else
            {
                line.to_string()
            }
        })
        .collect();
    if !found
    {
        bail!("the gdbstub recipe template has no argv line");
    }
    Ok(lines.join("\n") + "\n")
}

/// Stage the stub for `target` and repack the disk images in the layout
/// they have; returns that layout, for [`unstage`]. A failed repack removes
/// the staged recipe again and leaves the images to a rebuild.
pub fn stage(ctx: &Context, arch: Arch, target: &str) -> Result<DiskLayout>
{
    let layout = crate::disk::current_layout(ctx)?;
    let template_path = template(ctx);
    let text = std::fs::read_to_string(&template_path)
        .with_context(|| format!("reading {}", template_path.display()))?;
    let recipe = recipe_for(&text, target)?;
    let dst = staged(ctx);
    std::fs::write(&dst, recipe).with_context(|| format!("writing {}", dst.display()))?;
    if let Err(e) = crate::disk::create_disk_image(ctx, arch, layout)
    {
        // The recipe goes again, so a later repack does not pick it up.
        let _ = std::fs::remove_file(&dst);
        return Err(e.context("repacking the disk images with the gdbstub staged"));
    }
    Ok(layout)
}

/// Remove the staged stub and repack the disk images in `layout`, the one
/// [`stage`] returned.
pub fn unstage(ctx: &Context, arch: Arch, layout: DiskLayout) -> Result<()>
{
    let dst = staged(ctx);
    match std::fs::remove_file(&dst)
    {
        Ok(()) =>
        {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound =>
        {}
        Err(e) => return Err(e).with_context(|| format!("removing {}", dst.display())),
    }
    crate::disk::create_disk_image(ctx, arch, layout)
        .context("repacking the disk images without the gdbstub")
}

/// The ELF that holds the symbols of the sysroot binary a process named
/// `target` runs, best effort: the symbols store's file of the binary's build
/// id, the binary being the `binary` of a staged recipe whose `argv` begins
/// with the name, or else `/programs/<target>` or `/services/<target>` when
/// one exists.
pub fn binary_for(ctx: &Context, target: &str) -> Option<PathBuf>
{
    let installed = installed_binary_for(ctx, target)?;
    match crate::symbolize::store::Store::at(ctx.symbols_dir()).symbols_path(&installed)
    {
        Ok(symbols) => Some(symbols),
        Err(err) =>
        {
            crate::util::step(&format!("no symbols for the GDB command: {err:#}"));
            None
        }
    }
}

/// The sysroot binary a process named `target` runs, as [`binary_for`]
/// finds it.
fn installed_binary_for(ctx: &Context, target: &str) -> Option<PathBuf>
{
    if let Some(binary) = recipe_binary_in(&ctx.sysroot.join("config/svcmgr/services"), target)
    {
        return Some(ctx.sysroot.join(binary.trim_start_matches('/')));
    }
    ["programs", "services"]
        .iter()
        .map(|d| ctx.sysroot.join(d).join(target))
        .find(|p| p.is_file())
}

/// The `binary` of the first recipe in `dir` whose `argv` begins with
/// `target`. A recipe the last pack signed carries a trailer, so its text is
/// its body (docs/signing.md § Configuration); a file that is not a recipe is
/// passed over.
fn recipe_binary_in(dir: &Path, target: &str) -> Option<String>
{
    std::fs::read_dir(dir).ok()?.flatten().find_map(|entry| {
        let object = std::fs::read(entry.path()).ok()?;
        let text = std::str::from_utf8(crate::signing::body_of(&object).ok()?).ok()?;
        recipe_binary_named(text, target).map(str::to_owned)
    })
}

/// The `binary` of `recipe` when its `argv` begins with `name`.
fn recipe_binary_named<'a>(recipe: &'a str, name: &str) -> Option<&'a str>
{
    let value = |key: &str| {
        recipe.lines().find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim())
        })
    };
    let argv0 = value("argv")?.split_whitespace().next()?;
    (argv0 == name).then(|| value("binary")).flatten()
}

/// The GDB architecture name of `arch`.
pub fn gdb_architecture(arch: Arch) -> &'static str
{
    match arch
    {
        Arch::X86_64 => "i386:x86-64",
        Arch::Riscv64 => "riscv:rv64",
    }
}

/// The GDB command line that connects to the stub on `port` with `binary`'s
/// symbols; the stub reports the load offset (`qOffsets`), so GDB relocates
/// them itself.
pub fn gdb_command(arch: Arch, port: u16, binary: Option<&Path>) -> String
{
    let file = binary.map_or_else(|| "<binary>".to_string(), |b| b.display().to_string());
    format!(
        "gdb -ex 'set architecture {}' -ex 'set remotetimeout 30' -ex 'target remote \
         localhost:{port}' {file}",
        gdb_architecture(arch)
    )
}

/// The GDB remote protocol's description of `arch`.
pub fn rsp_arch(arch: Arch) -> gdb_rsp::target::Arch
{
    match arch
    {
        Arch::X86_64 => gdb_rsp::target::Arch::X86_64,
        Arch::Riscv64 => gdb_rsp::target::Arch::Riscv64,
    }
}

/// Kill `name`, the process the stub on `stub` holds, by a terminal fault
/// made from outside the guest: move its main thread, the first of the
/// stub's list, to program counter 0, an address no process maps, and
/// detach, which resumes it there. Returns the program counter it moved the
/// thread from. A stub that holds no process (it exited, or the stub's walk
/// found none) answers `?` as exited, which fails the kill. A main thread
/// held in a call is read and written again until the call returns
/// ([`move_held_register`]).
pub fn kill_held(stub: &mut Stub, arch: Arch, name: &str) -> Result<u64>
{
    let pc_reg = rsp_arch(arch).pc_regnum();
    let halt = stub.request(b"?")?;
    if !halt.starts_with(b"T") && !halt.starts_with(b"S")
    {
        bail!(
            "the stub holds no {name}: {}",
            String::from_utf8_lossy(&halt)
        );
    }
    stub.expect_ok(b"Hg1")?;
    let pc = move_held_register(stub, pc_reg, 0, IN_CALL_WAIT, IN_CALL_PAUSE)?;
    stub.expect_ok(b"D")?;
    Ok(pc)
}
/// Set register `regnum` of the selected thread to `value` and return the
/// value it held: read it, then write it, both again every `pause` for up to
/// `wait` while the stub refuses the write because the thread is held in a
/// call ([`HELD_IN_CALL`]). The stub counts such a thread stopped and reads
/// its registers, but writes them only once its call returns and the stub
/// holds it, by when the register can hold another value.
fn move_held_register(
    stub: &mut Stub,
    regnum: usize,
    value: u64,
    wait: Duration,
    pause: Duration,
) -> Result<u64>
{
    let start = Instant::now();
    let read = format!("p{regnum:x}");
    let write = format!("P{regnum:x}={}", le_hex(value));
    loop
    {
        let reply = stub.exchange(read.as_bytes())?;
        if reply.first() == Some(&b'E') && reply.len() == 3
        {
            bail!(
                "the gdbstub refused `{read}`: {}",
                String::from_utf8_lossy(&reply)
            );
        }
        let held = le_u64(&reply).with_context(|| format!("register {regnum}"))?;
        let reply = stub.exchange(write.as_bytes())?;
        if reply == HELD_IN_CALL && start.elapsed() < wait
        {
            std::thread::sleep(pause);
            continue;
        }
        if reply != b"OK"
        {
            bail!(
                "the gdbstub refused `{write}`: {}",
                String::from_utf8_lossy(&reply)
            );
        }
        return Ok(held);
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Serve `replies` over the far end of a socket pair, one per request,
    /// as a stub in the acknowledged mode does.
    fn fake_stub(replies: Vec<&'static [u8]>) -> Stub
    {
        use std::io::{Read as _, Write as _};

        use gdb_rsp::frame::{Event, PacketReader, PacketWriter};

        let (near, mut far) = std::os::unix::net::UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut reader = PacketReader::<{ gdb_rsp::PACKET_SIZE }>::new();
            let mut replies = replies.into_iter();
            let mut byte = [0u8; 1];
            while far.read(&mut byte).is_ok_and(|n| n == 1)
            {
                if let Some(Event::Packet(_)) = reader.push(byte[0])
                {
                    let Some(body) = replies.next()
                    else
                    {
                        return;
                    };
                    let mut buf = vec![0u8; 2 * gdb_rsp::PACKET_SIZE];
                    let mut w = PacketWriter::new(&mut buf);
                    w.bytes(body);
                    let len = w.finish().unwrap();
                    far.write_all(b"+").unwrap();
                    far.write_all(&buf[..len]).unwrap();
                }
            }
        });
        Stub::over_unix(near, Duration::from_secs(5)).unwrap()
    }

    // Defect caught: a kill whose target's main thread was held in a call
    // failed on the stub's first `E06` instead of trying again once the call
    // returned; and a kill that, the call returned, kept the program counter
    // it read in the call instead of the one it moved the thread from.
    #[test]
    fn a_register_move_waits_out_a_thread_held_in_a_call()
    {
        let in_call: &'static [u8] = le_hex(0x1234).leak().as_bytes();
        let returned: &'static [u8] = le_hex(0x5678).leak().as_bytes();
        let mut stub = fake_stub(vec![in_call, HELD_IN_CALL, returned, b"OK"]);
        let pc = move_held_register(&mut stub, 16, 0, Duration::from_secs(5), Duration::ZERO);
        assert_eq!(pc.unwrap(), 0x5678);

        // Past the wait, the refusal stands; any other refusal at once.
        let mut stub = fake_stub(vec![in_call, HELD_IN_CALL]);
        let err = move_held_register(&mut stub, 16, 0, Duration::ZERO, Duration::ZERO).unwrap_err();
        assert!(err.to_string().contains("E06"), "{err}");
        let mut stub = fake_stub(vec![b"E01"]);
        let err = move_held_register(&mut stub, 16, 0, Duration::from_secs(5), Duration::ZERO)
            .unwrap_err();
        assert!(err.to_string().contains("E01"), "{err}");
        let mut stub = fake_stub(vec![in_call, b"E01"]);
        let err = move_held_register(&mut stub, 16, 0, Duration::from_secs(5), Duration::ZERO)
            .unwrap_err();
        assert!(err.to_string().contains("E01"), "{err}");
    }

    #[test]
    fn staging_appends_the_target_to_the_argv_line_alone()
    {
        let template = "# stub\nbinary = /services/gdbstub\nargv   = gdbstub\nseed = x\n";
        let recipe = recipe_for(template, "gdb-target").unwrap();
        assert!(recipe.contains("argv   = gdbstub gdb-target\n"));
        assert!(recipe.contains("binary = /services/gdbstub\n"));
        recipe_for(template, "two words").unwrap_err();
        recipe_for("binary = /x\n", "t").unwrap_err();
        // A name procmgr would truncate can never match.
        recipe_for(template, &"n".repeat(NAME_MAX)).unwrap();
        recipe_for(template, &"n".repeat(NAME_MAX + 1)).unwrap_err();
    }

    #[test]
    fn a_recipe_names_its_binary_by_its_first_argv_word()
    {
        let recipe = "binary = /programs/debugger\nargv = gdb-target --gdb-target\n";
        assert_eq!(
            recipe_binary_named(recipe, "gdb-target"),
            Some("/programs/debugger")
        );
        assert_eq!(recipe_binary_named(recipe, "debugger"), None);
    }

    // Defect caught: a recipe the pack signed, whose trailer is not UTF-8,
    // passed over, so the GDB command names no symbols for a target whose
    // binary is not its argv[0].
    #[test]
    fn a_signed_recipe_names_its_binary()
    {
        use crate::signing::testing::{scratch, signer};
        let dir = scratch("debug-stub-recipe");
        let signer = signer(&dir.join("keys"), crate::arch::Arch::Riscv64);
        let services = dir.join("services");
        std::fs::create_dir_all(&services).unwrap();
        let body = b"binary = /programs/debugger\nargv = gdb-target\n";
        let recipe = signer
            .sign(
                body,
                objsig::RoleSet::of(&[objsig::Role::Configuration]),
                "/config/svcmgr/services/gdb-target.svc",
            )
            .unwrap();
        std::fs::write(services.join("gdb-target.svc"), &recipe).unwrap();
        assert_eq!(
            recipe_binary_in(&services, "gdb-target").as_deref(),
            Some("/programs/debugger")
        );
        assert_eq!(recipe_binary_in(&services, "debugger"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
