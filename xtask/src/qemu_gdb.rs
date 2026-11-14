// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/qemu_gdb.rs

//! A client of QEMU's own gdbstub (`-gdb unix:...`), which the host-driven
//! tests use to act on a running guest at the hardware boundary, so the
//! kernel carries no test code: `test-wedge` moves a CPU's program counter,
//! and `test-cet` corrupts a kernel return address. It also holds the helpers
//! those tests share: kernel symbol spans and the serial lines' hex fields.
//!
//! Distinct from the GDB stub service (`services/gdbstub`), which debugs a
//! userspace process over the debug port.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use gdb_rsp::PACKET_SIZE;
use gdb_rsp::frame::{Event, PacketReader, PacketWriter};

/// A half-open address range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span
{
    pub start: u64,
    pub end: u64,
}

impl Span
{
    pub fn contains(self, addr: u64) -> bool
    {
        (self.start..self.end).contains(&addr)
    }

    pub fn slid(self, slide: u64) -> Self
    {
        Self {
            start: self.start.wrapping_add(slide),
            end: self.end.wrapping_add(slide),
        }
    }
}

/// A demangled symbol name without the legacy mangling's `::h<16 hex>` hash.
pub fn function_path(name: &str) -> &str
{
    match name.rsplit_once("::h")
    {
        Some((path, hash)) if hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            path
        }
        _ => name,
    }
}

/// The hexadecimal number after `key` in `line` (`0x` prefix optional), up
/// to whitespace or a closing parenthesis.
pub fn field_hex(line: &str, key: &str) -> Option<u64>
{
    let (_, rest) = line.split_once(key)?;
    let digits = rest.split(|c: char| c.is_whitespace() || c == ')').next()?;
    let digits = digits.strip_prefix("0x").unwrap_or(digits);
    u64::from_str_radix(digits, 16).ok()
}

/// `value` as GDB register or memory bytes: little-endian, two hex digits a
/// byte.
pub fn le_hex(value: u64) -> String
{
    let mut hex = String::with_capacity(16);
    for b in value.to_le_bytes()
    {
        // Writing to a String cannot fail.
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Bytes from GDB hex digits.
pub fn from_hex(hex: &[u8]) -> Result<Vec<u8>>
{
    if hex.len() % 2 != 0
    {
        bail!("odd hex length {}", hex.len());
    }
    hex.chunks(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).context("non-ASCII hex")?;
            u8::from_str_radix(digits, 16).with_context(|| format!("bad hex `{digits}`"))
        })
        .collect()
}

/// A little-endian 64-bit value from a register or memory reply.
pub fn le_u64(hex: &[u8]) -> Result<u64>
{
    let bytes = from_hex(hex)?;
    let array: [u8; 8] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("a {}-byte value, not 8", bytes.len()))?;
    Ok(u64::from_le_bytes(array))
}

/// The thread a stop reply (`T<signal>thread:<id>;...`) names, if any.
pub fn stop_thread(reply: &[u8]) -> Option<u64>
{
    let text = std::str::from_utf8(reply).ok()?;
    if !text.starts_with('T')
    {
        return None;
    }
    text.split(';')
        .find_map(|field| field.split_once("thread:").map(|(_, id)| id))
        .and_then(|id| u64::from_str_radix(id, 16).ok())
}

/// QEMU's gdbstub over its unix socket, in the protocol's acknowledged mode.
/// Connecting stops the VM; detaching (`D`) resumes it.
pub struct Stub
{
    stream: UnixStream,
    reader: PacketReader<PACKET_SIZE>,
}

impl Stub
{
    /// Connect, waiting at most `answer_timeout` for each later reply.
    pub fn connect(path: &Path, answer_timeout: Duration) -> Result<Self>
    {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("connecting to the gdbstub at {}", path.display()))?;
        stream.set_read_timeout(Some(answer_timeout))?;
        Ok(Self {
            stream,
            reader: PacketReader::new(),
        })
    }

    /// Send `body` and return the reply's body, acknowledging it.
    pub fn request(&mut self, body: &[u8]) -> Result<Vec<u8>>
    {
        let mut buf = vec![0u8; 2 * PACKET_SIZE];
        let mut w = PacketWriter::new(&mut buf);
        w.bytes(body);
        let len = w
            .finish()
            .map_err(|e| anyhow::anyhow!("packet past the buffer: {e:?}"))?;
        let packet = buf.get(..len).context("packet length past the buffer")?;
        let what = String::from_utf8_lossy(body).into_owned();
        self.stream
            .write_all(packet)
            .with_context(|| format!("sending `{what}`"))?;
        let mut byte = [0u8; 1];
        loop
        {
            let n = self
                .stream
                .read(&mut byte)
                .with_context(|| format!("reading the reply to `{what}`"))?;
            if n == 0
            {
                bail!("the gdbstub closed the connection before replying to `{what}`");
            }
            match self.reader.push(byte[0])
            {
                None | Some(Event::Ack) =>
                {}
                Some(Event::Nack) => self.stream.write_all(packet)?,
                Some(Event::Packet(reply)) =>
                {
                    let reply = reply.to_vec();
                    self.stream.write_all(b"+")?;
                    if reply.first() == Some(&b'E') && reply.len() == 3
                    {
                        bail!(
                            "the gdbstub refused `{what}`: {}",
                            String::from_utf8_lossy(&reply)
                        );
                    }
                    return Ok(reply);
                }
                Some(other) => bail!("unexpected {other:?} replying to `{what}`"),
            }
        }
    }

    pub fn expect_ok(&mut self, body: &[u8]) -> Result<()>
    {
        let reply = self.request(body)?;
        if reply != b"OK"
        {
            bail!(
                "`{}` answered {:?}, not OK",
                String::from_utf8_lossy(body),
                String::from_utf8_lossy(&reply)
            );
        }
        Ok(())
    }

    pub fn read_register(&mut self, regnum: usize) -> Result<u64>
    {
        let reply = self.request(format!("p{regnum:x}").as_bytes())?;
        le_u64(&reply).with_context(|| format!("register {regnum}"))
    }

    pub fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>>
    {
        let reply = self.request(format!("m{addr:x},{len:x}").as_bytes())?;
        from_hex(&reply).with_context(|| format!("memory at {addr:#x}"))
    }

    /// The 64-bit value at the guest virtual address `addr`.
    pub fn read_u64(&mut self, addr: u64) -> Result<u64>
    {
        let reply = self.request(format!("m{addr:x},8").as_bytes())?;
        le_u64(&reply).with_context(|| format!("memory at {addr:#x}"))
    }

    /// Write the 64-bit `value` at the guest virtual address `addr`.
    pub fn write_u64(&mut self, addr: u64, value: u64) -> Result<()>
    {
        self.expect_ok(format!("M{addr:x},8:{}", le_hex(value)).as_bytes())
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn register_values_round_trip_little_endian()
    {
        let v = 0xffff_ffff_8012_3456;
        assert_eq!(le_hex(v), "56341280ffffffff");
        assert_eq!(le_u64(le_hex(v).as_bytes()).unwrap(), v);
        le_u64(b"5634").unwrap_err();
        le_u64(b"zz34128000000000").unwrap_err();
        assert_eq!(from_hex(b"f4").unwrap(), [0xF4]);
        from_hex(b"f").unwrap_err();
    }

    #[test]
    fn the_legacy_hash_is_stripped_from_a_symbol()
    {
        assert_eq!(
            function_path("kernel::arch::x86_64::cpu::halt_loop::h0123456789abcdef"),
            "kernel::arch::x86_64::cpu::halt_loop"
        );
        assert_eq!(
            function_path("kernel::sched::helper"),
            "kernel::sched::helper"
        );
        assert_eq!(function_path("a::hxyz"), "a::hxyz");
    }

    #[test]
    fn a_mangled_symbol_is_matched_by_its_path()
    {
        let name =
            crate::symbolize::demangle("_ZN6kernel4arch6x86_643cpu9halt_loop17h0123456789abcdefE");
        assert!(function_path(&name).ends_with("::cpu::halt_loop"), "{name}");
    }

    // The defect caught: a stop reply whose thread is misread, so the test
    // reads another CPU's registers.
    #[test]
    fn a_stop_reply_names_its_thread()
    {
        assert_eq!(stop_thread(b"T05thread:03;"), Some(3));
        assert_eq!(stop_thread(b"T05hwbreak:;thread:0a;"), Some(10));
        assert_eq!(stop_thread(b"S05"), None);
        assert_eq!(stop_thread(b"T05"), None);
    }

    #[test]
    fn a_hex_field_ends_at_whitespace_or_a_parenthesis()
    {
        assert_eq!(
            field_hex("kaslr: slide=0x1f200000 image", "slide="),
            Some(0x1f20_0000)
        );
        assert_eq!(field_hex("(hardware id 0x2)", "hardware id "), Some(2));
        assert_eq!(field_hex("rip=ffff", "rip="), Some(0xffff));
        assert_eq!(field_hex("nothing", "rip="), None);
    }
}
