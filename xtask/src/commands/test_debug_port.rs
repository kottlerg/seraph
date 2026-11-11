// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_debug_port.rs

//! Debug-port transport test: GDB remote serial protocol packets reach a
//! guest service over the debug port and its answers come back.
//!
//! Stages the `debug-echo` fixture's recipe into the boot set, repacks
//! `disk.img`, and boots the current sysroot once with the debug port
//! attached (a `virtio-console` device whose host end QEMU serves on a TCP
//! port). Once the fixture logs [`READY_MARKER`] on the serial stream, the
//! host connects and drives one exchange ([`exchange`]), framing and checking
//! every packet with the same `gdb-rsp` crate the fixture links. The fixture's
//! recipe is always removed and `disk.img` repacked afterwards. The verdict
//! is computed here and the host kills QEMU, as `test-terminal` does.
//!
//! A pure runner: requires a populated sysroot from `cargo xtask build`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use gdb_rsp::PACKET_SIZE;
use gdb_rsp::frame::{Event, PacketReader, PacketWriter, unescape};

use crate::arch::Arch;
use crate::cli::TestDebugPortArgs;
use crate::context::Context;
use crate::firmware::find_ovmf_code;
use crate::qemu::{
    GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, X86Paging, build_qemu_argv,
    prepare_riscv_firmware, validate_sysroot_for_launch,
};
use crate::util::{require_tool, step};

/// The fixture's recipe, as `cargo xtask build` installs it under
/// `config/svcmgr/tests/`, staged into `config/svcmgr/services/` for the boot.
const RECIPE: &str = "debug-echo.svc";

/// The fixture's line once it holds the debug port. Kept in sync with
/// `services/debug-echo/src/main.rs`.
const READY_MARKER: &str = "[debug-echo] READY on the debug port";

/// Budget for the boot to reach [`READY_MARKER`].
const BOOT_TIMEOUT: Duration = Duration::from_mins(5);

/// Budget for each answer of the exchange.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(20);

pub fn run(ctx: &Context, args: &TestDebugPortArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    // Held until the command returns, after its last QEMU has exited.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
    let staged = ctx
        .sysroot
        .join("config")
        .join("svcmgr")
        .join("services")
        .join(RECIPE);
    let source = ctx
        .sysroot
        .join("config")
        .join("svcmgr")
        .join("tests")
        .join(RECIPE);
    std::fs::copy(&source, &staged)
        .with_context(|| format!("staging {} as {}", source.display(), staged.display()))?;
    let booted = repack(ctx, args.arch).and_then(|()| boot(ctx, args));
    // Restore first, and surface its failure ahead of the boot's: a recipe
    // left staged would start the fixture on every later boot.
    std::fs::remove_file(&staged)
        .with_context(|| format!("removing {}", staged.display()))
        .and_then(|()| repack(ctx, args.arch))
        .context("restoring disk.img without the fixture")?;
    booted?;
    step("debug port test: PASS (packets reached the fixture and its answers came back)");
    Ok(())
}

/// Repack `disk.img` from the sysroot as it stands (`mkdisk --repack-only`).
fn repack(ctx: &Context, arch: Arch) -> Result<()>
{
    crate::disk::create_disk_image(ctx, arch, crate::disk::DiskLayout::default())
}

/// Boot with the debug port, wait for the fixture, drive the exchange, and
/// kill QEMU.
fn boot(ctx: &Context, args: &TestDebugPortArgs) -> Result<()>
{
    let (firmware_code, firmware_vars) = match args.arch
    {
        Arch::X86_64 => (find_ovmf_code()?, None),
        Arch::Riscv64 =>
        {
            let (code, vars) = prepare_riscv_firmware(ctx)?;
            (code, Some(vars))
        }
    };
    let disk_path = ctx.disk_image();
    let spec = QemuLaunchSpec {
        arch: args.arch,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: None,
        firmware_code_path: &firmware_code,
        firmware_vars_path: firmware_vars.as_deref(),
        cpus: args.cpus,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb: GdbMode::Off,
        qmp_socket: None,
        vmgenid_guid: Some("auto"),
        incoming: None,
        riscv_mmu: RiscvMmu::Sv48,
        x86_paging: X86Paging::Four,
        iommu: Iommu::Attached,
        debug_port: Some(args.port),
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;

    step(&format!(
        "debug port test: booting with the debug port on 127.0.0.1:{}",
        args.port
    ));
    let mut child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))?;
    let stdout = child.stdout.take().context("QEMU stdout unavailable")?;

    // Serial lines on a worker thread, so the wait for the marker has a
    // deadline; the thread keeps echoing the guest's log through the
    // exchange.
    let (tx, rx) = mpsc::channel::<()>();
    let reader = thread::spawn(move || {
        let mut signalled = false;
        for line in BufReader::new(stdout).lines()
        {
            let Ok(l) = line
            else
            {
                break;
            };
            println!("{l}");
            if !signalled && l.contains(READY_MARKER)
            {
                signalled = true;
                let _ = tx.send(());
            }
        }
    });

    let result = rx
        .recv_timeout(BOOT_TIMEOUT)
        .map_err(|_| {
            anyhow::anyhow!(
                "the fixture's {READY_MARKER:?} line did not appear within {}s",
                BOOT_TIMEOUT.as_secs()
            )
        })
        .and_then(|()| {
            let stream = TcpStream::connect(("127.0.0.1", args.port))
                .with_context(|| format!("connecting to 127.0.0.1:{}", args.port))?;
            stream.set_read_timeout(Some(ANSWER_TIMEOUT))?;
            exchange(&mut Link::new(stream))
        });
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    result
}

/// The host's end of the debug port: the stream and the reader that frames
/// its bytes.
struct Link
{
    stream: TcpStream,
    reader: PacketReader<PACKET_SIZE>,
}

/// What the host waits for next on the link.
#[derive(Debug, PartialEq, Eq)]
enum Expect
{
    Ack,
    Nack,
    /// A packet, its body returned.
    Packet,
}

impl Link
{
    fn new(stream: TcpStream) -> Self
    {
        Self {
            stream,
            reader: PacketReader::new(),
        }
    }

    /// Send raw bytes.
    fn send(&mut self, bytes: &[u8]) -> Result<()>
    {
        self.stream.write_all(bytes)?;
        Ok(())
    }

    /// Send one packet whose body `body` fills.
    fn send_packet(&mut self, body: impl FnOnce(&mut PacketWriter<'_>)) -> Result<()>
    {
        let mut buf = vec![0u8; 2 * PACKET_SIZE];
        let mut w = PacketWriter::new(&mut buf);
        body(&mut w);
        let len = w
            .finish()
            .map_err(|e| anyhow::anyhow!("packet past the buffer: {e:?}"))?;
        self.send(&buf[..len])
    }

    /// Read until the next event; fail on any other than `want`. Returns a
    /// packet's body.
    fn expect(&mut self, want: &Expect, what: &str) -> Result<Vec<u8>>
    {
        let deadline = Instant::now() + ANSWER_TIMEOUT;
        let mut byte = [0u8; 1];
        while Instant::now() < deadline
        {
            let n = self
                .stream
                .read(&mut byte)
                .with_context(|| format!("reading {what}"))?;
            if n == 0
            {
                bail!("the debug port closed while waiting for {what}");
            }
            let Some(event) = self.reader.push(byte[0])
            else
            {
                continue;
            };
            return match (want, event)
            {
                (Expect::Ack, Event::Ack) | (Expect::Nack, Event::Nack) => Ok(Vec::new()),
                (Expect::Packet, Event::Packet(body)) => Ok(body.to_vec()),
                (_, other) => bail!("{what}: expected {want:?}, got {other:?}"),
            };
        }
        bail!("{what}: nothing within {}s", ANSWER_TIMEOUT.as_secs())
    }
}

/// The exchange the fixture answers (services/debug-echo/README.md):
/// acknowledged mode first, a refused checksum, the interrupt byte, then
/// no-ack mode, a binary echo through the escapes, and a packet past the
/// fixture's buffer.
fn exchange(link: &mut Link) -> Result<()>
{
    link.send_packet(|w| {
        w.bytes(b"qSupported:multiprocess+;swbreak+");
    })?;
    link.expect(&Expect::Ack, "the ack of qSupported")?;
    let supported = link.expect(&Expect::Packet, "the qSupported reply")?;
    if !supported.starts_with(b"PacketSize=") || !contains(&supported, b"QStartNoAckMode+")
    {
        bail!(
            "qSupported reply {:?} lacks PacketSize or QStartNoAckMode+",
            String::from_utf8_lossy(&supported)
        );
    }
    link.send(b"+")?;

    link.send(b"$?#00")?;
    link.expect(&Expect::Nack, "the refusal of a bad checksum")?;

    link.send_packet(|w| {
        w.bytes(b"?");
    })?;
    link.expect(&Expect::Ack, "the ack of ?")?;
    expect_body(link, b"S05", "the halt reason")?;
    link.send(b"+")?;

    link.send(&[0x03])?;
    expect_body(link, b"S02", "the answer to the interrupt byte")?;
    link.send(b"+")?;

    link.send_packet(|w| {
        w.bytes(b"QStartNoAckMode");
    })?;
    link.expect(&Expect::Ack, "the ack of QStartNoAckMode")?;
    expect_body(link, b"OK", "the QStartNoAckMode reply")?;
    link.send(b"+")?;

    // No-ack mode from here: every byte value, through the escapes both
    // ways.
    let data: Vec<u8> = (0..=u8::MAX).collect();
    link.send_packet(|w| {
        w.bytes(b"qSeraph.Echo:").bytes(&data);
    })?;
    let echoed = link.expect(&Expect::Packet, "the echo")?;
    let mut out = vec![0u8; echoed.len()];
    let n = unescape(&echoed, &mut out).map_err(|e| anyhow::anyhow!("echo: {e:?}"))?;
    if out[..n] != data[..]
    {
        bail!("the echo differs from the {} bytes sent", data.len());
    }

    let long = vec![b'0'; PACKET_SIZE + 64];
    link.send_packet(|w| {
        w.bytes(b"G").bytes(&long);
    })?;
    expect_body(link, b"E02", "the refusal of a packet past the buffer")?;
    Ok(())
}

/// Expect a packet whose body is `want`.
fn expect_body(link: &mut Link, want: &[u8], what: &str) -> Result<()>
{
    let body = link.expect(&Expect::Packet, what)?;
    if body != want
    {
        bail!(
            "{what}: expected {:?}, got {:?}",
            String::from_utf8_lossy(want),
            String::from_utf8_lossy(&body)
        );
    }
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool
{
    haystack.windows(needle.len()).any(|w| w == needle)
}
