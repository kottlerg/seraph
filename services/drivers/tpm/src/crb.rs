// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/tpm/src/crb.rs

//! The Command Response Buffer interface (TCG PC Client Platform TPM
//! Profile, § 6.4 and § 6.5.3), started by a write of `TPM_CRB_CTRL_START`
//! (the `TPM2` table's start method 7): a command is written into the
//! command buffer the control area names, started, and its response read
//! from the response buffer once the TPM clears the start bit. Locality 0
//! only. Both buffers must lie in the register window the driver maps;
//! [`Crb::new`] refuses a TPM whose buffers do not.

use crate::Transport;
use crate::command::{HEADER_LEN, response_size};
use crate::regs::{Fault, Registers, Step, Wait, poll};

/// `TPM_LOC_STATE_0`.
pub const LOC_STATE: usize = 0x00;
/// `TPM_LOC_CTRL_0`.
pub const LOC_CTRL: usize = 0x08;
/// `TPM_LOC_STS_0`.
pub const LOC_STS: usize = 0x0C;
/// `TPM_CRB_CTRL_REQ_0`.
pub const CTRL_REQ: usize = 0x40;
/// `TPM_CRB_CTRL_STS_0`.
pub const CTRL_STS: usize = 0x44;
/// `TPM_CRB_CTRL_CANCEL_0`.
pub const CTRL_CANCEL: usize = 0x48;
/// `TPM_CRB_CTRL_START_0`.
pub const CTRL_START: usize = 0x4C;
/// `TPM_CRB_CTRL_CMD_SIZE_0`.
pub const CMD_SIZE: usize = 0x58;
/// `TPM_CRB_CTRL_CMD_LADDR_0`.
pub const CMD_LADDR: usize = 0x5C;
/// `TPM_CRB_CTRL_CMD_HADDR_0`.
pub const CMD_HADDR: usize = 0x60;
/// `TPM_CRB_CTRL_RSP_SIZE_0`.
pub const RSP_SIZE: usize = 0x64;
/// `TPM_CRB_CTRL_RSP_ADDR_0`, low half; the high half follows.
pub const RSP_ADDR: usize = 0x68;

/// `TPM_LOC_STATE` `tpmRegValidSts`.
pub const LOC_STATE_VALID: u32 = 1 << 7;
/// `TPM_LOC_STATE` `locAssigned`.
pub const LOC_STATE_ASSIGNED: u32 = 1 << 1;
/// `TPM_LOC_CTRL` `requestAccess`.
pub const LOC_CTRL_REQUEST: u32 = 1 << 0;
/// `TPM_LOC_CTRL` `relinquish`.
pub const LOC_CTRL_RELINQUISH: u32 = 1 << 1;
/// `TPM_LOC_STS` `Granted`.
pub const LOC_STS_GRANTED: u32 = 1 << 0;
/// `TPM_CRB_CTRL_REQ` `cmdReady`: the TPM clears it once ready.
pub const REQ_CMD_READY: u32 = 1 << 0;
/// `TPM_CRB_CTRL_REQ` `goIdle`: the TPM clears it once idle.
pub const REQ_GO_IDLE: u32 = 1 << 1;
/// `TPM_CRB_CTRL_STS` `tpmSts`: the TPM is in a fatal error state.
pub const STS_FATAL: u32 = 1 << 0;
/// `TPM_CRB_CTRL_START` and `TPM_CRB_CTRL_CANCEL`: invoke.
pub const INVOKE: u32 = 1;

/// One of the two buffers, as an offset into the register window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Buffer
{
    offset: usize,
    len: usize,
}

impl Buffer
{
    /// The buffer of `len` bytes at physical address `addr`, inside the
    /// window of `window_len` bytes at `window_phys`; `None` when it does
    /// not lie wholly inside it or cannot hold a response header.
    fn within(addr: u64, len: u32, window_phys: u64, window_len: usize) -> Option<Self>
    {
        let offset = usize::try_from(addr.checked_sub(window_phys)?).ok()?;
        let len = usize::try_from(len).ok()?;
        (len >= HEADER_LEN && offset.checked_add(len)? <= window_len)
            .then_some(Self { offset, len })
    }
}

/// The CRB interface over `R`.
pub struct Crb<R>
{
    regs: R,
    cmd: Buffer,
    rsp: Buffer,
}

impl<R: Registers> Crb<R>
{
    /// The CRB interface of the TPM whose locality-0 window `regs` reaches,
    /// `window_len` bytes at physical address `window_phys`. `None` when the
    /// command or the response buffer the control area names does not lie
    /// in the window: the driver reaches the TPM through that window alone.
    pub fn new(regs: R, window_phys: u64, window_len: usize) -> Option<Self>
    {
        let cmd_addr =
            u64::from(regs.read32(CMD_LADDR)) | (u64::from(regs.read32(CMD_HADDR)) << 32);
        let rsp_addr = u64::from(regs.read32(RSP_ADDR))
            | (u64::from(regs.read32(RSP_ADDR.checked_add(4)?)) << 32);
        let cmd = Buffer::within(cmd_addr, regs.read32(CMD_SIZE), window_phys, window_len)?;
        let rsp = Buffer::within(rsp_addr, regs.read32(RSP_SIZE), window_phys, window_len)?;
        Some(Self { regs, cmd, rsp })
    }

    /// Take locality 0, unless it is already assigned.
    fn request_locality(&self, wait: &mut dyn Wait) -> Result<(), Fault>
    {
        let state = self.regs.read32(LOC_STATE);
        if state == u32::MAX
        {
            return Err(Fault::Protocol(Step::Locality));
        }
        let held = LOC_STATE_VALID | LOC_STATE_ASSIGNED;
        if state & held == held && self.regs.read32(LOC_STS) & LOC_STS_GRANTED != 0
        {
            return Ok(());
        }
        self.regs.write32(LOC_CTRL, LOC_CTRL_REQUEST);
        poll(wait, Step::Locality, || {
            self.regs.read32(LOC_STS) & LOC_STS_GRANTED != 0
        })
    }

    /// Move the TPM to its command-ready state.
    fn command_ready(&self, wait: &mut dyn Wait) -> Result<(), Fault>
    {
        // A cancel left by an earlier command that timed out is withdrawn.
        self.regs.write32(CTRL_CANCEL, 0);
        self.regs.write32(CTRL_REQ, REQ_CMD_READY);
        poll(wait, Step::CommandReady, || {
            self.regs.read32(CTRL_REQ) & REQ_CMD_READY == 0
        })?;
        if self.regs.read32(CTRL_STS) & STS_FATAL != 0
        {
            return Err(Fault::Protocol(Step::CommandReady));
        }
        Ok(())
    }

    /// Copy `bytes` into the window from `offset`.
    fn write_bytes(&self, offset: usize, bytes: &[u8])
    {
        for (at, &byte) in (offset..).zip(bytes)
        {
            self.regs.write8(at, byte);
        }
    }

    /// Copy the window's bytes from `offset` into `out`.
    fn read_bytes(&self, offset: usize, out: &mut [u8])
    {
        for (at, byte) in (offset..).zip(out)
        {
            *byte = self.regs.read8(at);
        }
    }

    /// One command, from a held locality: command-ready, write, start, wait
    /// for the TPM to clear the start bit, read the response.
    fn transact(&self, cmd: &[u8], rsp: &mut [u8], wait: &mut dyn Wait) -> Result<usize, Fault>
    {
        if cmd.len() > self.cmd.len
        {
            return Err(Fault::Protocol(Step::Send));
        }
        self.command_ready(wait)?;
        self.write_bytes(self.cmd.offset, cmd);
        self.regs.write32(CTRL_START, INVOKE);
        let done = poll(wait, Step::Execute, || {
            self.regs.read32(CTRL_START) & INVOKE == 0
        });
        if let Err(fault) = done
        {
            self.regs.write32(CTRL_CANCEL, INVOKE);
            return Err(fault);
        }
        if self.regs.read32(CTRL_STS) & STS_FATAL != 0
        {
            return Err(Fault::Protocol(Step::Execute));
        }
        let header = rsp.get_mut(..HEADER_LEN).ok_or(Fault::Malformed)?;
        self.read_bytes(self.rsp.offset, header);
        let size = response_size(header).ok_or(Fault::Malformed)?;
        if size > self.rsp.len
        {
            return Err(Fault::Malformed);
        }
        let body = rsp.get_mut(HEADER_LEN..size).ok_or(Fault::Malformed)?;
        let body_offset = self
            .rsp
            .offset
            .checked_add(HEADER_LEN)
            .ok_or(Fault::Malformed)?;
        self.read_bytes(body_offset, body);
        Ok(size)
    }
}

impl<R: Registers> Transport for Crb<R>
{
    fn execute(&mut self, cmd: &[u8], rsp: &mut [u8], wait: &mut dyn Wait) -> Result<usize, Fault>
    {
        self.request_locality(wait)?;
        let out = self.transact(cmd, rsp, wait);
        // Back to idle and give the locality up, whatever the outcome.
        self.regs.write32(CTRL_REQ, REQ_GO_IDLE);
        self.regs.write32(LOC_CTRL, LOC_CTRL_RELINQUISH);
        out
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::command::{self, Response, parse_response};
    use crate::sim::{CrbSim, Polls, Tpm, WINDOW_PHYS};

    #[test]
    fn a_command_crosses_the_buffers_and_the_locality_is_given_up()
    {
        let sim = CrbSim::new(Tpm::started());
        let mut crb = Crb::new(&sim, WINDOW_PHYS, 0x1000).unwrap();
        let mut rsp = [0u8; 128];
        let len = crb
            .execute(&command::get_random(12), &mut rsp, &mut Polls(50))
            .unwrap();
        let Some(Response::Success(params)) = parse_response(&rsp[..len])
        else
        {
            panic!("no success");
        };
        assert_eq!(
            command::random_bytes(params, 12).unwrap(),
            Tpm::bytes(0, 12)
        );
        assert_eq!(sim.received(), vec![command::get_random(12).to_vec()]);
        assert!(!sim.locality_granted());
    }

    #[test]
    fn buffers_outside_the_window_are_refused()
    {
        // The command buffer past the window's end, then below its start.
        let sim = CrbSim::new(Tpm::started());
        sim.set_cmd_buffer(WINDOW_PHYS + 0xF80, 0x100);
        assert!(Crb::new(&sim, WINDOW_PHYS, 0x1000).is_none());
        sim.set_cmd_buffer(WINDOW_PHYS - 0x1000, 0x100);
        assert!(Crb::new(&sim, WINDOW_PHYS, 0x1000).is_none());
        // A response buffer too small for a header.
        let sim = CrbSim::new(Tpm::started());
        sim.set_rsp_buffer(WINDOW_PHYS + 0x80, 4);
        assert!(Crb::new(&sim, WINDOW_PHYS, 0x1000).is_none());
    }

    #[test]
    fn a_tpm_that_never_completes_is_cancelled_at_the_bound()
    {
        let sim = CrbSim::new(Tpm::stalled());
        let mut crb = Crb::new(&sim, WINDOW_PHYS, 0x1000).unwrap();
        let mut rsp = [0u8; 128];
        let out = crb.execute(&command::get_random(8), &mut rsp, &mut Polls(20));
        assert_eq!(out, Err(Fault::Timeout(Step::Execute)));
        assert!(sim.cancelled());
        assert!(!sim.locality_granted());
    }

    #[test]
    fn a_fatal_status_breaks_the_protocol()
    {
        let sim = CrbSim::new(Tpm::started());
        sim.set_fatal();
        let mut crb = Crb::new(&sim, WINDOW_PHYS, 0x1000).unwrap();
        let mut rsp = [0u8; 128];
        let out = crb.execute(&command::get_random(8), &mut rsp, &mut Polls(20));
        assert_eq!(out, Err(Fault::Protocol(Step::CommandReady)));
    }

    #[test]
    fn a_response_size_past_the_response_buffer_is_malformed()
    {
        let sim = CrbSim::new(Tpm::started());
        sim.set_rsp_buffer(WINDOW_PHYS + 0x80, 16);
        let mut crb = Crb::new(&sim, WINDOW_PHYS, 0x1000).unwrap();
        let mut rsp = [0u8; 128];
        let out = crb.execute(&command::get_random(32), &mut rsp, &mut Polls(20));
        assert_eq!(out, Err(Fault::Malformed));
    }

    #[test]
    fn an_absent_device_is_refused()
    {
        let sim = CrbSim::absent();
        let mut crb = Crb::new(&sim, WINDOW_PHYS, 0x1000);
        // All-ones buffer addresses lie outside the window.
        assert!(crb.is_none());
        let sim = CrbSim::new(Tpm::started());
        crb = Crb::new(&sim, WINDOW_PHYS, 0x1000);
        sim.set_absent();
        let mut rsp = [0u8; 128];
        let out = crb
            .unwrap()
            .execute(&command::get_random(8), &mut rsp, &mut Polls(20));
        assert_eq!(out, Err(Fault::Protocol(Step::Locality)));
    }
}
