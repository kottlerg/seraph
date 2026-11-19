// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/tpm/src/sim.rs

//! Simulated TPMs for the host tests: a TPM 2.0 command processor
//! ([`Tpm`]) behind a FIFO register window ([`FifoSim`]) or a CRB one
//! ([`CrbSim`]), and a wait that allows a fixed number of pauses
//! ([`Polls`]).

use std::cell::RefCell;
use std::collections::VecDeque;

use crate::command::{HEADER_LEN, rc, response_size};
use crate::regs::{Registers, Wait};
use crate::{crb, fifo};

/// A wait that allows `.0` pauses.
pub struct Polls(pub u32);

impl Wait for Polls
{
    fn pause(&mut self) -> bool
    {
        if self.0 == 0
        {
            return false;
        }
        self.0 -= 1;
        true
    }
}

/// The most bytes the simulated TPM returns per `TPM2_GetRandom`, as a TPM
/// whose largest digest is SHA-256's.
const DIGEST_MAX: usize = 32;

/// How a simulated TPM answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Behaviour
{
    /// Serves every command.
    Serve,
    /// Never completes a command.
    Stall,
    /// Answers every `TPM2_GetRandom` with `TPM_RC_FAILURE`.
    Fail,
    /// Answers `TPM_RC_INITIALIZE` to every command.
    NeverStarts,
}

/// A TPM 2.0 command processor: `TPM2_Startup` and `TPM2_GetRandom`.
pub struct Tpm
{
    behaviour: Behaviour,
    started: bool,
    /// `TPM2_GetRandom` calls answered `TPM_RC_RETRY` before one is served.
    busy: u32,
    /// `TPM2_GetRandom` calls served before every later one is answered
    /// `TPM_RC_RETRY`.
    busy_after: Option<u32>,
    /// Random bytes handed out so far: the next byte is this count.
    handed: usize,
    received: Vec<Vec<u8>>,
}

impl Tpm
{
    /// A started TPM that answers as `behaviour` says.
    fn with(behaviour: Behaviour) -> Self
    {
        Self {
            behaviour,
            started: true,
            busy: 0,
            busy_after: None,
            handed: 0,
            received: Vec::new(),
        }
    }

    /// A TPM firmware started.
    pub fn started() -> Self
    {
        Self::with(Behaviour::Serve)
    }

    /// A TPM no one has sent `TPM2_Startup`.
    pub fn unstarted() -> Self
    {
        Self {
            started: false,
            ..Self::started()
        }
    }

    /// A TPM that answers `TPM_RC_INITIALIZE` whatever it is sent.
    pub fn unstartable() -> Self
    {
        Self {
            started: false,
            ..Self::with(Behaviour::NeverStarts)
        }
    }

    /// A started TPM that never completes a command.
    pub fn stalled() -> Self
    {
        Self::with(Behaviour::Stall)
    }

    /// A started TPM in failure mode.
    pub fn failed() -> Self
    {
        Self::with(Behaviour::Fail)
    }

    /// A started TPM busy for its first `calls` reads.
    pub fn busy(calls: u32) -> Self
    {
        Self {
            busy: calls,
            ..Self::started()
        }
    }

    /// A started TPM busy for every read after its first `calls`.
    pub fn busy_after(calls: u32) -> Self
    {
        Self {
            busy_after: Some(calls),
            ..Self::started()
        }
    }

    /// The `n` random bytes a simulated TPM hands out from its `start`th.
    pub fn bytes(start: usize, n: usize) -> Vec<u8>
    {
        (0..=250u8).cycle().skip(start).take(n).collect()
    }

    /// The response to the whole command `cmd`, `None` while it executes.
    fn respond(&mut self, cmd: &[u8]) -> Option<Vec<u8>>
    {
        self.received.push(cmd.to_vec());
        let code = u32::from_be_bytes(cmd[6..10].try_into().unwrap());
        let param = u16::from_be_bytes(cmd[10..12].try_into().unwrap());
        let answer = |code: u32, params: &[u8]| {
            let size = u32::try_from(HEADER_LEN + params.len()).unwrap();
            let mut out = vec![0x80, 0x01];
            out.extend(size.to_be_bytes());
            out.extend(code.to_be_bytes());
            out.extend(params);
            out
        };
        match (self.behaviour, code)
        {
            (Behaviour::Stall, _) => None,
            (Behaviour::NeverStarts, _) => Some(answer(rc::INITIALIZE, &[])),
            (_, 0x144) if self.started => Some(answer(rc::INITIALIZE, &[])),
            (_, 0x144) =>
            {
                self.started = true;
                Some(answer(rc::SUCCESS, &[]))
            }
            (_, 0x17B) if !self.started => Some(answer(rc::INITIALIZE, &[])),
            (Behaviour::Fail, 0x17B) => Some(answer(rc::FAILURE, &[])),
            (_, 0x17B) if self.busy > 0 =>
            {
                self.busy -= 1;
                Some(answer(rc::RETRY, &[]))
            }
            (_, 0x17B) if self.busy_after == Some(0) => Some(answer(rc::RETRY, &[])),
            (_, 0x17B) =>
            {
                self.busy_after = self.busy_after.map(|n| n - 1);
                let n = usize::from(param).min(DIGEST_MAX);
                let bytes = Self::bytes(self.handed, n);
                self.handed += n;
                let mut params = u16::try_from(n).unwrap().to_be_bytes().to_vec();
                params.extend(bytes);
                Some(answer(rc::SUCCESS, &params))
            }
            _ => Some(answer(0x143, &[])),
        }
    }
}

/// Where a FIFO command is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase
{
    Idle,
    Ready,
    Reception,
    Execution,
    Completion,
}

/// The state behind [`FifoSim`].
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is one independent flag of the simulated device's state"
)]
struct FifoState
{
    tpm: Tpm,
    burst: usize,
    absent: bool,
    expect_stuck: bool,
    active: bool,
    requests: u32,
    aborted: bool,
    phase: Phase,
    input: Vec<u8>,
    output: VecDeque<u8>,
}

impl FifoState
{
    /// Whether the TPM expects more command bytes.
    fn expects(&self) -> bool
    {
        self.expect_stuck || response_size(&self.input).is_none_or(|size| self.input.len() < size)
    }

    fn status(&self) -> u8
    {
        match self.phase
        {
            Phase::Ready => fifo::STS_VALID | fifo::STS_COMMAND_READY,
            Phase::Reception if self.expects() => fifo::STS_VALID | fifo::STS_EXPECT,
            Phase::Completion if !self.output.is_empty() => fifo::STS_VALID | fifo::STS_DATA_AVAIL,
            Phase::Idle | Phase::Execution | Phase::Reception | Phase::Completion =>
            {
                fifo::STS_VALID
            }
        }
    }

    fn burst(&self) -> usize
    {
        match self.phase
        {
            Phase::Ready | Phase::Reception => self.burst,
            Phase::Completion => self.burst.min(self.output.len()),
            Phase::Idle | Phase::Execution => 0,
        }
    }
}

/// A TPM behind the FIFO interface whose `burstCount` is at most a set
/// number of bytes.
pub struct FifoSim(RefCell<FifoState>);

impl FifoSim
{
    /// `tpm` behind a FIFO that moves at most `burst` bytes without a wait.
    pub fn new(tpm: Tpm, burst: usize) -> Self
    {
        Self(RefCell::new(FifoState {
            tpm,
            burst,
            absent: false,
            expect_stuck: false,
            active: false,
            requests: 0,
            aborted: false,
            phase: Phase::Idle,
            input: Vec::new(),
            output: VecDeque::new(),
        }))
    }

    /// A window with no TPM behind it: every read is all-ones.
    pub fn absent() -> Self
    {
        let sim = Self::new(Tpm::started(), 64);
        sim.0.borrow_mut().absent = true;
        sim
    }

    /// Make the TPM expect more bytes whatever it receives.
    pub fn set_expect_stuck(&self)
    {
        self.0.borrow_mut().expect_stuck = true;
    }

    /// The commands the TPM received, in order.
    pub fn received(&self) -> Vec<Vec<u8>>
    {
        self.0.borrow().tpm.received.clone()
    }

    pub fn locality_active(&self) -> bool
    {
        self.0.borrow().active
    }

    pub fn locality_requests(&self) -> u32
    {
        self.0.borrow().requests
    }

    /// Whether a command in execution was aborted.
    pub fn aborted(&self) -> bool
    {
        self.0.borrow().aborted
    }
}

impl Registers for &FifoSim
{
    fn read8(&self, offset: usize) -> u8
    {
        let mut s = self.0.borrow_mut();
        if s.absent
        {
            return 0xFF;
        }
        match offset
        {
            fifo::ACCESS if s.active => fifo::ACCESS_VALID | fifo::ACCESS_ACTIVE,
            fifo::ACCESS => fifo::ACCESS_VALID,
            fifo::STS => s.status(),
            fifo::DATA_FIFO if s.phase == Phase::Completion => s.output.pop_front().unwrap_or(0xFF),
            _ => 0xFF,
        }
    }

    fn read32(&self, offset: usize) -> u32
    {
        let s = self.0.borrow();
        if s.absent
        {
            return u32::MAX;
        }
        match offset
        {
            fifo::STS => u32::from(s.status()) | (u32::try_from(s.burst()).unwrap() << 8),
            crate::INTERFACE_ID => 0x0000_2100,
            _ => u32::MAX,
        }
    }

    fn write8(&self, offset: usize, value: u8)
    {
        let mut s = self.0.borrow_mut();
        if s.absent
        {
            return;
        }
        match offset
        {
            fifo::ACCESS if value & fifo::ACCESS_REQUEST_USE != 0 =>
            {
                s.active = true;
                s.requests += 1;
            }
            fifo::ACCESS if value & fifo::ACCESS_ACTIVE != 0 => s.active = false,
            _ if !s.active =>
            {}
            fifo::STS if value & fifo::STS_COMMAND_READY != 0 =>
            {
                if s.phase == Phase::Execution
                {
                    s.aborted = true;
                }
                s.phase = Phase::Ready;
                s.input.clear();
                s.output.clear();
            }
            fifo::STS
                if value & fifo::STS_GO != 0 && s.phase == Phase::Reception && !s.expects() =>
            {
                let cmd = std::mem::take(&mut s.input);
                match s.tpm.respond(&cmd)
                {
                    Some(rsp) =>
                    {
                        s.output = rsp.into();
                        s.phase = Phase::Completion;
                    }
                    None => s.phase = Phase::Execution,
                }
            }
            fifo::DATA_FIFO if matches!(s.phase, Phase::Ready | Phase::Reception) =>
            {
                s.input.push(value);
                s.phase = Phase::Reception;
            }
            _ =>
            {}
        }
    }

    fn write32(&self, offset: usize, value: u32)
    {
        let [low, ..] = value.to_le_bytes();
        self.write8(offset, low);
    }
}

/// The low 32 bits of `value`.
fn low(value: u64) -> u32
{
    u32::try_from(value & u64::from(u32::MAX)).unwrap()
}

/// The physical address of a simulated CRB window.
pub const WINDOW_PHYS: u64 = 0xFED4_0000;

/// The state behind [`CrbSim`].
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is one independent flag of the simulated device's state"
)]
struct CrbState
{
    tpm: Tpm,
    absent: bool,
    fatal: bool,
    granted: bool,
    cancelled: bool,
    start: bool,
    cmd: (u64, u32),
    rsp: (u64, u32),
    /// The window's bytes from the start of the data buffer.
    memory: Vec<u8>,
}

/// A TPM behind the CRB interface, its command and response buffers both at
/// offset 0x80 of a one-page window unless a test moves them.
pub struct CrbSim(RefCell<CrbState>);

/// Where the shared data buffer starts in the window.
const DATA_BUFFER: usize = 0x80;

impl CrbSim
{
    pub fn new(tpm: Tpm) -> Self
    {
        let at = WINDOW_PHYS + DATA_BUFFER as u64;
        Self(RefCell::new(CrbState {
            tpm,
            absent: false,
            fatal: false,
            granted: false,
            cancelled: false,
            start: false,
            cmd: (at, 0xF80),
            rsp: (at, 0xF80),
            memory: vec![0; 0x1000],
        }))
    }

    /// A window with no TPM behind it.
    pub fn absent() -> Self
    {
        let sim = Self::new(Tpm::started());
        sim.set_absent();
        sim
    }

    pub fn set_absent(&self)
    {
        self.0.borrow_mut().absent = true;
    }

    pub fn set_fatal(&self)
    {
        self.0.borrow_mut().fatal = true;
    }

    pub fn set_cmd_buffer(&self, addr: u64, len: u32)
    {
        self.0.borrow_mut().cmd = (addr, len);
    }

    pub fn set_rsp_buffer(&self, addr: u64, len: u32)
    {
        self.0.borrow_mut().rsp = (addr, len);
    }

    pub fn received(&self) -> Vec<Vec<u8>>
    {
        self.0.borrow().tpm.received.clone()
    }

    pub fn locality_granted(&self) -> bool
    {
        self.0.borrow().granted
    }

    pub fn cancelled(&self) -> bool
    {
        self.0.borrow().cancelled
    }
}

impl Registers for &CrbSim
{
    fn read8(&self, offset: usize) -> u8
    {
        let s = self.0.borrow();
        if s.absent
        {
            return 0xFF;
        }
        s.memory.get(offset).copied().unwrap_or(0xFF)
    }

    fn read32(&self, offset: usize) -> u32
    {
        let s = self.0.borrow();
        if s.absent
        {
            return u32::MAX;
        }
        match offset
        {
            crb::LOC_STATE if s.granted => crb::LOC_STATE_VALID | crb::LOC_STATE_ASSIGNED,
            crb::LOC_STATE => crb::LOC_STATE_VALID,
            crb::LOC_STS => u32::from(s.granted),
            crb::CTRL_REQ => 0,
            crb::CTRL_STS => u32::from(s.fatal),
            crb::CTRL_START => u32::from(s.start),
            crb::CMD_SIZE => s.cmd.1,
            crb::CMD_LADDR => low(s.cmd.0),
            crb::CMD_HADDR => (s.cmd.0 >> 32) as u32,
            crb::RSP_SIZE => s.rsp.1,
            crb::RSP_ADDR => low(s.rsp.0),
            0x6C => (s.rsp.0 >> 32) as u32,
            crate::INTERFACE_ID => 0x0000_4011,
            _ => 0,
        }
    }

    fn write8(&self, offset: usize, value: u8)
    {
        let mut s = self.0.borrow_mut();
        if let Some(byte) = s.memory.get_mut(offset)
        {
            *byte = value;
        }
    }

    fn write32(&self, offset: usize, value: u32)
    {
        let mut s = self.0.borrow_mut();
        if s.absent
        {
            return;
        }
        match offset
        {
            crb::LOC_CTRL if value & crb::LOC_CTRL_REQUEST != 0 => s.granted = true,
            crb::LOC_CTRL if value & crb::LOC_CTRL_RELINQUISH != 0 => s.granted = false,
            crb::CTRL_CANCEL if value == crb::INVOKE => s.cancelled = true,
            crb::CTRL_START if value == crb::INVOKE && s.granted && !s.start =>
            {
                let at = usize::try_from(s.cmd.0 - WINDOW_PHYS).unwrap();
                let size = response_size(&s.memory[at..at + HEADER_LEN]).unwrap_or(HEADER_LEN);
                let cmd = s.memory[at..at + size].to_vec();
                match s.tpm.respond(&cmd)
                {
                    Some(rsp) =>
                    {
                        let at = usize::try_from(s.rsp.0 - WINDOW_PHYS).unwrap();
                        let end = (at + rsp.len()).min(s.memory.len());
                        let n = end - at;
                        s.memory[at..end].copy_from_slice(&rsp[..n]);
                    }
                    None => s.start = true,
                }
            }
            _ =>
            {}
        }
    }
}
