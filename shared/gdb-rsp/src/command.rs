// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/gdb-rsp/src/command.rs

//! The commands GDB sends a stub, parsed from a packet body.
//!
//! [`Command::parse`] recognises the packet set `target remote` needs for one
//! process: the halt reason, registers, memory, continue and step (plain and
//! `vCont`), breakpoints and watchpoints, thread selection and listing, the
//! queries of the connection's start (`qSupported`, `qAttached`, `qOffsets`,
//! `QStartNoAckMode`, the target description), attach, detach, and kill.
//! Every other body is [`Command::Unknown`], which a stub answers with an
//! empty reply: GDB's sign that a packet is not supported.

use crate::Error;
use crate::frame::unescaped_len;
use crate::hex::{nibble, parse_u64};

/// A thread named by a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadId
{
    /// `-1`: every thread.
    All,
    /// `0`: any thread, the stub's choice.
    Any,
    /// One thread, by the id the stub gave it in its thread list.
    Id(u64),
}

/// The thread operation an `H` packet selects a thread for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadOp
{
    /// `Hg`: the thread later register and memory commands act on.
    General,
    /// `Hc`: the thread a later `c` or `s` resumes.
    Resume,
}

/// The kind of a `Z` or `z` packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakpointType
{
    /// `0`: a breakpoint the stub plants in memory.
    Software,
    /// `1`: a breakpoint in a debug register.
    Hardware,
    /// `2`: a watchpoint on writes.
    WriteWatch,
    /// `3`: a watchpoint on reads.
    ReadWatch,
    /// `4`: a watchpoint on any access.
    AccessWatch,
}

/// What a `vCont` action does to the threads it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resume
{
    /// `c`, or `C<signal>`: run.
    Continue,
    /// `s`, or `S<signal>`: run one instruction.
    Step,
    /// `t`: stop.
    Stop,
}

/// One action of a `vCont` packet: what to do, and to which thread (every
/// thread no earlier action named, when `None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VContAction
{
    pub resume: Resume,
    pub thread: Option<ThreadId>,
}

/// The actions of a `vCont` packet, in the order GDB sent them; the first one
/// that names a thread applies to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VContActions<'a>
{
    /// The actions after `vCont;`, each checked by [`Command::parse`].
    raw: &'a [u8],
}

impl<'a> VContActions<'a>
{
    /// The actions, in packet order.
    pub fn iter(&self) -> impl Iterator<Item = VContAction> + 'a
    {
        // parse checked every action, so none is dropped here.
        self.raw
            .split(|&b| b == b';')
            .filter_map(|a| parse_action(a).ok())
    }
}

/// A command parsed from a packet body. Slices borrow the body: register and
/// memory data stay hex digits, and `X` data stays escaped, until the stub
/// decodes them into its own buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command<'a>
{
    /// `?`: why the target stopped.
    HaltReason,
    /// `g`: read every register.
    ReadRegisters,
    /// `G<hex>`: write every register, as [`crate::target::Arch`]'s register
    /// block in hex.
    WriteRegisters(&'a [u8]),
    /// `p<n>`: read register `n`.
    ReadRegister(u64),
    /// `P<n>=<hex>`: write register `n`.
    WriteRegister
    {
        regnum: u64, value: &'a [u8]
    },
    /// `m<addr>,<len>`: read `len` bytes of memory.
    ReadMemory
    {
        addr: u64, len: u64
    },
    /// `M<addr>,<len>:<hex>`: write memory, `len` bytes in hex.
    WriteMemory
    {
        addr: u64, data: &'a [u8]
    },
    /// `X<addr>,<len>:<data>`: write memory, `len` bytes of escaped binary
    /// data ([`crate::frame::unescape`]).
    WriteMemoryBinary
    {
        addr: u64, data: &'a [u8]
    },
    /// `c[addr]` or `C<signal>[;addr]`: resume, at `addr` when given. A
    /// stub delivers no signal, so `C` resumes as `c` does.
    Continue(Option<u64>),
    /// `s[addr]` or `S<signal>[;addr]`: step one instruction, from `addr`
    /// when given; `S` steps as `s` does.
    Step(Option<u64>),
    /// `vCont?`: which `vCont` actions the stub takes.
    VContQuery,
    /// `vCont;<action>[:thread]...`: resume or stop threads.
    VCont(VContActions<'a>),
    /// `Z<type>,<addr>,<kind>`: insert a breakpoint or watchpoint; `kind` is
    /// the breakpoint's length in bytes, or the watched length.
    InsertBreakpoint
    {
        ty: BreakpointType,
        addr: u64,
        kind: u64,
    },
    /// `z<type>,<addr>,<kind>`: remove one.
    RemoveBreakpoint
    {
        ty: BreakpointType,
        addr: u64,
        kind: u64,
    },
    /// `H<op><thread>`: select the thread for later commands.
    SetThread
    {
        op: ThreadOp, thread: ThreadId
    },
    /// `T<thread>`: whether the thread is alive.
    ThreadAlive(ThreadId),
    /// `qfThreadInfo`: the start of the thread list.
    ThreadInfoFirst,
    /// `qsThreadInfo`: the rest of the thread list.
    ThreadInfoNext,
    /// `qC`: the current thread.
    CurrentThread,
    /// `qSupported[:features]`: GDB's features, `;`-separated, and a request
    /// for the stub's.
    Supported(&'a [u8]),
    /// `qAttached[:pid]`: whether the stub attached to an existing process.
    Attached,
    /// `qOffsets`: the load offsets of the image.
    Offsets,
    /// `QStartNoAckMode`: stop acknowledging packets.
    StartNoAckMode,
    /// `qXfer:features:read:<annex>:<offset>,<len>`: read the target
    /// description document `annex`.
    FeaturesRead
    {
        annex: &'a [u8],
        offset: u64,
        len: u64,
    },
    /// `vAttach;<pid>`: attach to process `pid`.
    Attach(u64),
    /// `D[;pid]`: detach, leaving the process running.
    Detach,
    /// `k`: kill the process.
    Kill,
    /// Any other body, which the stub answers with an empty reply.
    Unknown(&'a [u8]),
}

impl<'a> Command<'a>
{
    /// Parse a packet body, as [`crate::frame::Event::Packet`] gives it.
    ///
    /// # Errors
    /// - `Malformed`: the body starts as a recognised command but does not
    ///   have its form: a missing field or separator, a number that is not
    ///   hex or overflows 64 bits, data whose length disagrees with the
    ///   length the packet states, or an unknown thread, breakpoint type, or
    ///   `vCont` action.
    pub fn parse(body: &'a [u8]) -> Result<Self, Error>
    {
        let Some((&head, rest)) = body.split_first()
        else
        {
            return Ok(Self::Unknown(body));
        };
        match head
        {
            b'?' if rest.is_empty() => Ok(Self::HaltReason),
            b'g' if rest.is_empty() => Ok(Self::ReadRegisters),
            b'G' => Ok(Self::WriteRegisters(hex_data(rest)?)),
            b'p' => Ok(Self::ReadRegister(parse_u64(rest)?)),
            b'P' =>
            {
                let (n, value) = split_once(rest, b'=')?;
                Ok(Self::WriteRegister {
                    regnum: parse_u64(n)?,
                    value: hex_data(value)?,
                })
            }
            b'm' =>
            {
                let (addr, len) = addr_len(rest)?;
                Ok(Self::ReadMemory { addr, len })
            }
            b'M' => parse_write_memory(rest),
            b'X' => parse_write_binary(rest),
            b'c' => Ok(Self::Continue(optional_addr(rest)?)),
            b's' => Ok(Self::Step(optional_addr(rest)?)),
            b'C' => Ok(Self::Continue(signal_then_addr(rest)?)),
            b'S' => Ok(Self::Step(signal_then_addr(rest)?)),
            b'Z' | b'z' =>
            {
                let (ty, addr, kind) = parse_breakpoint(rest)?;
                Ok(
                    if head == b'Z'
                    {
                        Self::InsertBreakpoint { ty, addr, kind }
                    }
                    else
                    {
                        Self::RemoveBreakpoint { ty, addr, kind }
                    },
                )
            }
            b'H' => parse_set_thread(rest),
            b'T' => Ok(Self::ThreadAlive(parse_thread(rest)?)),
            b'D' if rest.is_empty() || rest.starts_with(b";") => Ok(Self::Detach),
            b'k' if rest.is_empty() => Ok(Self::Kill),
            b'q' | b'Q' => parse_query(body),
            b'v' => parse_v(body),
            _ => Ok(Self::Unknown(body)),
        }
    }
}

/// The general and setting queries, `q` and `Q` bodies.
fn parse_query(body: &[u8]) -> Result<Command<'_>, Error>
{
    const FEATURES_READ: &[u8] = b"qXfer:features:read:";
    Ok(match body
    {
        b"qfThreadInfo" => Command::ThreadInfoFirst,
        b"qsThreadInfo" => Command::ThreadInfoNext,
        b"qC" => Command::CurrentThread,
        b"qOffsets" => Command::Offsets,
        b"QStartNoAckMode" => Command::StartNoAckMode,
        b"qSupported" => Command::Supported(b""),
        _ if body.starts_with(b"qSupported:") => Command::Supported(&body[b"qSupported:".len()..]),
        b"qAttached" => Command::Attached,
        _ if body.starts_with(b"qAttached:") => Command::Attached,
        _ if body.starts_with(FEATURES_READ) =>
        {
            let (annex, range) = split_once(&body[FEATURES_READ.len()..], b':')?;
            let (offset, len) = addr_len(range)?;
            Command::FeaturesRead { annex, offset, len }
        }
        _ => Command::Unknown(body),
    })
}

/// The `v` packets: `vCont?`, `vCont;...`, and `vAttach;<pid>`.
fn parse_v(body: &[u8]) -> Result<Command<'_>, Error>
{
    if body == b"vCont?"
    {
        return Ok(Command::VContQuery);
    }
    if let Some(raw) = body.strip_prefix(b"vCont;")
    {
        for action in raw.split(|&b| b == b';')
        {
            parse_action(action)?;
        }
        return Ok(Command::VCont(VContActions { raw }));
    }
    if let Some(pid) = body.strip_prefix(b"vAttach;")
    {
        return Ok(Command::Attach(parse_u64(pid)?));
    }
    Ok(Command::Unknown(body))
}

/// One `vCont` action: `c`, `C<sig>`, `s`, `S<sig>` or `t`, then optionally
/// `:<thread>`.
fn parse_action(action: &[u8]) -> Result<VContAction, Error>
{
    let (verb, thread) = match action.iter().position(|&b| b == b':')
    {
        Some(i) => (&action[..i], Some(parse_thread(&action[i + 1..])?)),
        None => (action, None),
    };
    let resume = match verb
    {
        b"c" => Resume::Continue,
        b"s" => Resume::Step,
        b"t" => Resume::Stop,
        [b'C', sig @ ..] =>
        {
            parse_signal(sig)?;
            Resume::Continue
        }
        [b'S', sig @ ..] =>
        {
            parse_signal(sig)?;
            Resume::Step
        }
        _ => return Err(Error::Malformed),
    };
    Ok(VContAction { resume, thread })
}

/// `M<addr>,<len>:<hex>`, after the `M`.
fn parse_write_memory(rest: &[u8]) -> Result<Command<'_>, Error>
{
    let (header, data) = split_once(rest, b':')?;
    let (addr, len) = addr_len(header)?;
    let data = hex_data(data)?;
    if data.len() as u64 != len.checked_mul(2).ok_or(Error::Malformed)?
    {
        return Err(Error::Malformed);
    }
    Ok(Command::WriteMemory { addr, data })
}

/// `X<addr>,<len>:<data>`, after the `X`. The data is binary, so it may hold
/// `:`; the header ends at the first one.
fn parse_write_binary(rest: &[u8]) -> Result<Command<'_>, Error>
{
    let (header, data) = split_once(rest, b':')?;
    let (addr, len) = addr_len(header)?;
    if unescaped_len(data)? as u64 != len
    {
        return Err(Error::Malformed);
    }
    Ok(Command::WriteMemoryBinary { addr, data })
}

/// `<type>,<addr>,<kind>`, after the `Z` or `z`. A condition or command list
/// (`;...`) is refused: a stub using this crate advertises neither.
fn parse_breakpoint(rest: &[u8]) -> Result<(BreakpointType, u64, u64), Error>
{
    let (ty, rest) = split_once(rest, b',')?;
    let ty = match ty
    {
        b"0" => BreakpointType::Software,
        b"1" => BreakpointType::Hardware,
        b"2" => BreakpointType::WriteWatch,
        b"3" => BreakpointType::ReadWatch,
        b"4" => BreakpointType::AccessWatch,
        _ => return Err(Error::Malformed),
    };
    let (addr, kind) = addr_len(rest)?;
    Ok((ty, addr, kind))
}

/// `H<op><thread>`, after the `H`.
fn parse_set_thread(rest: &[u8]) -> Result<Command<'_>, Error>
{
    let (&op, thread) = rest.split_first().ok_or(Error::Malformed)?;
    let op = match op
    {
        b'g' => ThreadOp::General,
        b'c' => ThreadOp::Resume,
        _ => return Err(Error::Malformed),
    };
    Ok(Command::SetThread {
        op,
        thread: parse_thread(thread)?,
    })
}

/// A thread id: `-1`, `0`, or a positive id in hex. The multiprocess form
/// (`p<pid>.<tid>`) is refused: a stub using this crate does not advertise
/// it.
fn parse_thread(digits: &[u8]) -> Result<ThreadId, Error>
{
    if digits == b"-1"
    {
        return Ok(ThreadId::All);
    }
    match parse_u64(digits)?
    {
        0 => Ok(ThreadId::Any),
        id => Ok(ThreadId::Id(id)),
    }
}

/// A signal number: two hex digits.
fn parse_signal(digits: &[u8]) -> Result<u8, Error>
{
    match digits
    {
        [hi, lo] =>
        {
            Ok(nibble(*hi).ok_or(Error::Malformed)? << 4 | nibble(*lo).ok_or(Error::Malformed)?)
        }
        _ => Err(Error::Malformed),
    }
}

/// `<signal>[;addr]`, after the `C` or `S`.
fn signal_then_addr(rest: &[u8]) -> Result<Option<u64>, Error>
{
    let (signal, addr) = match rest.iter().position(|&b| b == b';')
    {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };
    parse_signal(signal)?;
    addr.map(parse_u64).transpose()
}

/// An address that may be absent (`c`, `s`).
fn optional_addr(digits: &[u8]) -> Result<Option<u64>, Error>
{
    if digits.is_empty()
    {
        Ok(None)
    }
    else
    {
        parse_u64(digits).map(Some)
    }
}

/// `<addr>,<len>`, both hex.
fn addr_len(field: &[u8]) -> Result<(u64, u64), Error>
{
    let (addr, len) = split_once(field, b',')?;
    Ok((parse_u64(addr)?, parse_u64(len)?))
}

/// Hex data: an even count of hex digits.
fn hex_data(data: &[u8]) -> Result<&[u8], Error>
{
    if !data.len().is_multiple_of(2) || data.iter().any(|&b| nibble(b).is_none())
    {
        return Err(Error::Malformed);
    }
    Ok(data)
}

/// Split `field` at the first `sep`.
fn split_once(field: &[u8], sep: u8) -> Result<(&[u8], &[u8]), Error>
{
    let i = field
        .iter()
        .position(|&b| b == sep)
        .ok_or(Error::Malformed)?;
    Ok((&field[..i], &field[i + 1..]))
}

#[cfg(test)]
mod tests
{
    use super::*;

    extern crate std;
    use std::vec::Vec;

    fn parse(body: &[u8]) -> Result<Command<'_>, Error>
    {
        Command::parse(body)
    }

    #[test]
    fn register_commands_parse_with_their_numbers_and_data()
    {
        assert_eq!(parse(b"g"), Ok(Command::ReadRegisters));
        assert_eq!(parse(b"G00ff"), Ok(Command::WriteRegisters(b"00ff")));
        assert_eq!(parse(b"p20"), Ok(Command::ReadRegister(0x20)));
        assert_eq!(
            parse(b"P10=efbeadde"),
            Ok(Command::WriteRegister {
                regnum: 0x10,
                value: b"efbeadde"
            })
        );
    }

    #[test]
    fn register_data_that_is_not_whole_hex_bytes_is_malformed()
    {
        assert_eq!(parse(b"G0"), Err(Error::Malformed));
        assert_eq!(parse(b"P1=zz"), Err(Error::Malformed));
        assert_eq!(parse(b"P1"), Err(Error::Malformed));
        assert_eq!(parse(b"p"), Err(Error::Malformed));
    }

    #[test]
    fn memory_commands_parse_their_address_length_and_data()
    {
        assert_eq!(
            parse(b"m7fff0010,40"),
            Ok(Command::ReadMemory {
                addr: 0x7fff_0010,
                len: 0x40
            })
        );
        assert_eq!(
            parse(b"M1000,2:cc90"),
            Ok(Command::WriteMemory {
                addr: 0x1000,
                data: b"cc90"
            })
        );
        // Binary data may hold `:`, and the escape of `#`.
        assert_eq!(
            parse(b"X1000,3::}\x03a"),
            Ok(Command::WriteMemoryBinary {
                addr: 0x1000,
                data: b":}\x03a"
            })
        );
        // GDB probes for `X` with an empty write.
        assert_eq!(
            parse(b"X0,0:"),
            Ok(Command::WriteMemoryBinary { addr: 0, data: b"" })
        );
    }

    #[test]
    fn memory_data_whose_length_disagrees_with_the_stated_length_is_malformed()
    {
        assert_eq!(parse(b"M1000,2:cc"), Err(Error::Malformed));
        assert_eq!(parse(b"X1000,2:}\x03"), Err(Error::Malformed));
        assert_eq!(parse(b"X1000,1:}"), Err(Error::Malformed));
        assert_eq!(
            parse(b"Mffffffffffffffff,ffffffffffffffff:"),
            Err(Error::Malformed)
        );
        assert_eq!(parse(b"m1000"), Err(Error::Malformed));
        assert_eq!(parse(b"M1000,2"), Err(Error::Malformed));
    }

    #[test]
    fn resume_commands_take_an_optional_address_and_ignore_a_signal()
    {
        assert_eq!(parse(b"c"), Ok(Command::Continue(None)));
        assert_eq!(parse(b"c4000"), Ok(Command::Continue(Some(0x4000))));
        assert_eq!(parse(b"s"), Ok(Command::Step(None)));
        assert_eq!(parse(b"C05"), Ok(Command::Continue(None)));
        assert_eq!(parse(b"S0b;4000"), Ok(Command::Step(Some(0x4000))));
        assert_eq!(parse(b"C5"), Err(Error::Malformed));
        assert_eq!(parse(b"cxyz"), Err(Error::Malformed));
    }

    #[test]
    fn vcont_actions_parse_in_order_with_their_threads()
    {
        assert_eq!(parse(b"vCont?"), Ok(Command::VContQuery));
        let Ok(Command::VCont(actions)) = parse(b"vCont;s:2;C05:-1;t:0;c")
        else
        {
            panic!("vCont did not parse");
        };
        let got: Vec<VContAction> = actions.iter().collect();
        assert_eq!(
            got,
            [
                VContAction {
                    resume: Resume::Step,
                    thread: Some(ThreadId::Id(2))
                },
                VContAction {
                    resume: Resume::Continue,
                    thread: Some(ThreadId::All)
                },
                VContAction {
                    resume: Resume::Stop,
                    thread: Some(ThreadId::Any)
                },
                VContAction {
                    resume: Resume::Continue,
                    thread: None
                },
            ]
        );
    }

    #[test]
    fn a_vcont_with_an_unknown_action_or_bad_thread_is_malformed()
    {
        assert_eq!(parse(b"vCont;r1000,2000"), Err(Error::Malformed));
        assert_eq!(parse(b"vCont;c:p1.2"), Err(Error::Malformed));
        assert_eq!(parse(b"vCont;"), Err(Error::Malformed));
    }

    #[test]
    fn breakpoints_parse_their_type_address_and_kind()
    {
        assert_eq!(
            parse(b"Z0,401000,1"),
            Ok(Command::InsertBreakpoint {
                ty: BreakpointType::Software,
                addr: 0x40_1000,
                kind: 1
            })
        );
        assert_eq!(
            parse(b"z4,2000,8"),
            Ok(Command::RemoveBreakpoint {
                ty: BreakpointType::AccessWatch,
                addr: 0x2000,
                kind: 8
            })
        );
        assert_eq!(parse(b"Z5,2000,8"), Err(Error::Malformed));
        assert_eq!(parse(b"Z0,2000,1;X2,0a"), Err(Error::Malformed));
    }

    #[test]
    fn thread_selection_parses_all_any_and_one_thread()
    {
        assert_eq!(
            parse(b"Hg0"),
            Ok(Command::SetThread {
                op: ThreadOp::General,
                thread: ThreadId::Any
            })
        );
        assert_eq!(
            parse(b"Hc-1"),
            Ok(Command::SetThread {
                op: ThreadOp::Resume,
                thread: ThreadId::All
            })
        );
        assert_eq!(parse(b"T1f"), Ok(Command::ThreadAlive(ThreadId::Id(0x1f))));
        assert_eq!(parse(b"Hx1"), Err(Error::Malformed));
        assert_eq!(parse(b"H"), Err(Error::Malformed));
    }

    #[test]
    fn connection_queries_parse()
    {
        assert_eq!(
            parse(b"qSupported:multiprocess+;swbreak+"),
            Ok(Command::Supported(b"multiprocess+;swbreak+"))
        );
        assert_eq!(parse(b"qSupported"), Ok(Command::Supported(b"")));
        assert_eq!(parse(b"qAttached:1"), Ok(Command::Attached));
        assert_eq!(parse(b"qAttached"), Ok(Command::Attached));
        assert_eq!(parse(b"qOffsets"), Ok(Command::Offsets));
        assert_eq!(parse(b"QStartNoAckMode"), Ok(Command::StartNoAckMode));
        assert_eq!(parse(b"qfThreadInfo"), Ok(Command::ThreadInfoFirst));
        assert_eq!(parse(b"qsThreadInfo"), Ok(Command::ThreadInfoNext));
        assert_eq!(parse(b"qC"), Ok(Command::CurrentThread));
        assert_eq!(parse(b"?"), Ok(Command::HaltReason));
    }

    #[test]
    fn a_target_description_read_names_its_annex_and_range()
    {
        assert_eq!(
            parse(b"qXfer:features:read:target.xml:0,ffb"),
            Ok(Command::FeaturesRead {
                annex: b"target.xml",
                offset: 0,
                len: 0xffb
            })
        );
        assert_eq!(
            parse(b"qXfer:features:read:target.xml"),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn attach_detach_and_kill_parse()
    {
        assert_eq!(parse(b"vAttach;2a"), Ok(Command::Attach(0x2a)));
        assert_eq!(parse(b"vAttach;"), Err(Error::Malformed));
        assert_eq!(parse(b"D"), Ok(Command::Detach));
        assert_eq!(parse(b"D;2a"), Ok(Command::Detach));
        assert_eq!(parse(b"k"), Ok(Command::Kill));
    }

    #[test]
    fn bodies_outside_the_packet_set_are_unknown()
    {
        for body in [
            &b""[..],
            b"vMustReplyEmpty",
            b"qTStatus",
            b"qSymbol::",
            b"QThreadEvents:1",
            b"qXfer:auxv:read::0,100",
            b"gg",
            b"Dx",
            b"!",
        ]
        {
            assert_eq!(parse(body), Ok(Command::Unknown(body)));
        }
    }
}
