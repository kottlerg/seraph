// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/debug_port/echo.rs

//! Debug-port transport test: GDB remote serial protocol packets reach a
//! guest service over the debug port and its answers come back.
//!
//! Stages the `debug-echo` fixture's recipe into the boot set, repacks the
//! disk images in the layout they have, and boots the current sysroot once with the debug port
//! attached (a `virtio-console` device whose host end QEMU serves on a TCP
//! port). Once the fixture logs [`READY_MARKER`] on the serial stream, the
//! host connects and drives one exchange ([`exchange`]), framing and checking
//! every packet with the same `gdb-rsp` crate the fixture links. A restart
//! round follows on the same connection ([`restart_round`]): the host kills
//! the port's driver through QEMU's gdbstub at a hardware breakpoint in its
//! code (`breakpoint_kill`; the driver declares itself undebuggable, so no
//! guest debugger reaches it), waits for the fixture's [`FOLLOWED_MARKER`]
//! once devmgr has restarted the driver at the class's next ordinal, and
//! drives an echo through the restarted driver. The fixture's
//! recipe is always removed and the images repacked in that layout afterwards. The verdict
//! is computed here and the host kills QEMU, as the `terminal` case does.
//!
//! A pure runner: requires a populated sysroot from `cargo xtask build`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{Context as _, Result, bail};
use gdb_rsp::PACKET_SIZE;
use gdb_rsp::frame::{Event, PacketReader, PacketWriter, unescape};

use crate::arch::Arch;
use crate::breakpoint_kill;
use crate::commands::test::cases::CaseArgs;
use crate::context::Context;
use crate::disk::DiskLayout;
use crate::guest::Guest;
use crate::qemu::{
    Firmware, GdbMode, InterruptRemapping, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr,
    SecondDisk, X86Paging, X86ShadowStack, build_qemu_argv, validate_sysroot_for_launch,
};
use crate::socket_dir::SocketDir;
use crate::util::{require_tool, step};

/// The fixture's recipe, as `cargo xtask build` installs it under
/// `config/svcmgr/tests/`, staged into `config/svcmgr/services/` for the boot.
const RECIPE: &str = "debug-echo.svc";

/// The fixture's line once it holds the debug port. Kept in sync with
/// `services/fixtures/debug-echo/src/main.rs`.
const READY_MARKER: &str = "[debug-echo] READY on the debug port";

/// The fixture's line once it holds the driver devmgr restarted at the
/// class's next ordinal. Kept in sync with `shared/device-tracker`.
const FOLLOWED_MARKER: &str = "[debug-echo] debug port driver at ordinal 1";

/// The debug port's driver: its process name (its install path, which devmgr
/// creates it with as its `argv[0]`), its binary under the sysroot, and the
/// function the kill breaks on, which the driver runs on every
/// `SERIAL_READ_BYTES` and out of line in both profiles. Kept in sync with
/// `services/drivers/virtio/console/src/main.rs`.
const PORT_DRIVER_NAME: &str = "/services/drivers/virtio-console";
const PORT_DRIVER_BINARY: &str = "services/drivers/virtio-console";
const PORT_DRIVER_FUNCTION: &str = "<virtio_console::Console>::drain_rx";

/// Budget for the restart, from the kill to [`FOLLOWED_MARKER`].
const RESTART_TIMEOUT: Duration = Duration::from_mins(1);

/// Budget for the boot to reach [`READY_MARKER`].
const BOOT_TIMEOUT: Duration = Duration::from_mins(5);

/// Budget for each answer of the exchange.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(20);

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    // Held until the case returns, after its last QEMU has exited.
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
    // Read before staging, so a failed staging repack cannot change the
    // layout the restore writes.
    let layout = crate::disk::current_layout(ctx)?;
    std::fs::copy(&source, &staged)
        .with_context(|| format!("staging {} as {}", source.display(), staged.display()))?;
    let booted = crate::disk::create_disk_image(ctx, args.arch, layout)
        .and_then(|()| boot(ctx, args, layout));
    // Restore first, and surface its failure ahead of the boot's: a recipe
    // left staged would start the fixture on every later boot.
    std::fs::remove_file(&staged)
        .with_context(|| format!("removing {}", staged.display()))
        .and_then(|()| crate::disk::create_disk_image(ctx, args.arch, layout))
        .context("restoring the disk images without the fixture")?;
    booted?;
    step(
        "debug port test: PASS (packets reached the fixture and its answers came back, across a \
         restart of the port's driver)",
    );
    Ok(())
}

/// Boot the images of `layout` with the debug port, wait for the fixture,
/// drive the exchange, and kill QEMU.
fn boot(ctx: &Context, args: &CaseArgs, layout: DiskLayout) -> Result<()>
{
    // Picked here, right before QEMU binds it, to keep the window in which
    // another process could take it short.
    let port = crate::util::debug_port_or_free(args.port)?;
    let driver = breakpoint_kill::resolve_installed(ctx, PORT_DRIVER_BINARY, PORT_DRIVER_FUNCTION)?;
    // Declared before the guest, so it is removed after QEMU is reaped.
    let sockets = SocketDir::create()?;
    let gdb_sock = sockets.socket("debug-port.gdb")?;
    let firmware = Firmware::prepare(ctx, args.arch)?;
    let vars = firmware.launch_vars()?;
    let disk_path = ctx.disk_image();
    let data_image = layout.second_image(ctx);
    let spec = QemuLaunchSpec {
        arch: args.arch,
        disk_path: &disk_path,
        disk_block_size: crate::disk::logical_block_size(&disk_path)?,
        second_disk: data_image
            .as_deref()
            .map(SecondDisk::of_image)
            .transpose()?,
        firmware_code_path: &firmware.code,
        firmware_vars_path: vars.path(),
        smm: firmware.smm,
        cpus: args.cpus,
        threads_per_core: 1,
        mem_mib: args.mem,
        display: QemuDisplay::Headless,
        gdb: GdbMode::Unix(&gdb_sock),
        qmp_socket: None,
        vmgenid_guid: Some("auto"),
        incoming: None,
        riscv_mmu: RiscvMmu::Sv48,
        riscv_zkr: RiscvZkr::On,
        idle_wait: crate::qemu::IdleWait::Off,
        x86_paging: X86Paging::Four,
        x86_shadow_stack: X86ShadowStack::Off,
        iommu: Iommu::Attached,
        interrupt_remapping: InterruptRemapping::for_sysroot(ctx),
        debug_port: Some(port),
        test_devices: false,
        hotplug_port: None,
    };
    let qemu_args = build_qemu_argv(&spec)?;
    let qemu_binary = require_tool(args.arch.qemu_binary())?;

    step(&format!(
        "debug port test: booting with the debug port on 127.0.0.1:{port}"
    ));
    let child = Command::new(&qemu_binary)
        .args(&qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {}", args.arch.qemu_binary()))?;
    // Dropping the guest on any return kills and reaps QEMU.
    let mut guest = Guest::from_child(child)?.holding(vars);
    let booted = guest.collect_until(READY_MARKER, BOOT_TIMEOUT)?;
    let stream = TcpStream::connect(("127.0.0.1", port))
        .with_context(|| format!("connecting to 127.0.0.1:{port}"))?;
    stream.set_read_timeout(Some(ANSWER_TIMEOUT))?;
    let mut link = Link::new(stream);
    exchange(&mut link)?;
    restart_round(
        args.arch, &gdb_sock, &driver, &mut link, &booted, &mut guest,
    )
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
            .map_err(|e| crate::error::err!("packet past the buffer: {e:?}"))?;
        self.send(buf.get(..len).context("packet length past the buffer")?)
    }

    /// Read until the next event; fail on any other than `want`. Returns a
    /// packet's body.
    fn expect(&mut self, want: &Expect, what: &str) -> Result<Vec<u8>>
    {
        let start = Instant::now();
        let mut byte = [0u8; 1];
        while start.elapsed() < ANSWER_TIMEOUT
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

/// The exchange the fixture answers (services/fixtures/debug-echo/README.md):
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
    let n = unescape(&echoed, &mut out).map_err(|e| crate::error::err!("echo: {e:?}"))?;
    if out.get(..n) != Some(data.as_slice())
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

/// The restart round, in no-ack mode after [`exchange`]: kill the port's
/// driver at [`PORT_DRIVER_FUNCTION`], which it runs on each of the
/// fixture's reads, so no trigger is needed; wait for the fixture to hold the
/// driver devmgr restarted, and echo through that driver. `booted` is the
/// serial output through the fixture's [`READY_MARKER`].
fn restart_round(
    arch: Arch,
    gdb_sock: &Path,
    driver: &breakpoint_kill::Function,
    link: &mut Link,
    booted: &[String],
    guest: &mut Guest,
) -> Result<()>
{
    let bias = breakpoint_kill::spawn_bias(booted, PORT_DRIVER_NAME).with_context(|| {
        format!("no procmgr bias line for {PORT_DRIVER_NAME} before the fixture's READY")
    })?;
    let killed = breakpoint_kill::kill_at_breakpoint(
        arch,
        gdb_sock,
        bias,
        driver,
        breakpoint_kill::Take::Any,
        || (),
    )?;
    step(&format!(
        "debug port test: moved the port's driver at {:#x} to 0",
        killed.pc
    ));
    guest.wait_for_markers(&[FOLLOWED_MARKER], RESTART_TIMEOUT)?;
    let data = b"after the restart";
    link.send_packet(|w| {
        w.bytes(b"qSeraph.Echo:").bytes(data);
    })?;
    let echoed = link.expect(&Expect::Packet, "the echo after the restart")?;
    if echoed != data
    {
        bail!(
            "the echo after the restart differs: {:?}",
            String::from_utf8_lossy(&echoed)
        );
    }
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
