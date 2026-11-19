// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/tpm/src/fifo.rs

//! The FIFO interface (TCG PC Client Platform TPM Profile, § 6.5.2 and
//! § 6.5.3; the TIS of TPM 1.2 platforms): a command is written byte by byte
//! into `TPM_DATA_FIFO` as `burstCount` allows, started with `tpmGo`,
//! and its response read back from the same register once `dataAvail` is
//! set. Locality 0 only.

use crate::Transport;
use crate::command::{HEADER_LEN, response_size};
use crate::regs::{Fault, Registers, Step, Wait, poll};

/// `TPM_ACCESS_0`.
pub const ACCESS: usize = 0x00;
/// `TPM_STS_0`: the status byte, then `burstCount` in bytes 1 and 2.
pub const STS: usize = 0x18;
/// `TPM_DATA_FIFO_0`.
pub const DATA_FIFO: usize = 0x24;

/// `TPM_ACCESS` `tpmRegValidSts`: the other bits are valid.
pub const ACCESS_VALID: u8 = 0x80;
/// `TPM_ACCESS` `activeLocality`: this locality holds the TPM; written,
/// it relinquishes it.
pub const ACCESS_ACTIVE: u8 = 0x20;
/// `TPM_ACCESS` `requestUse`: ask for the locality.
pub const ACCESS_REQUEST_USE: u8 = 0x02;

/// `TPM_STS` `stsValid`: `dataAvail` and `Expect` are valid.
pub const STS_VALID: u8 = 0x80;
/// `TPM_STS` `commandReady`: read, the TPM is ready for a command;
/// written, it moves there, aborting any command in progress.
pub const STS_COMMAND_READY: u8 = 0x40;
/// `TPM_STS` `tpmGo`: written, the TPM executes the command received.
pub const STS_GO: u8 = 0x20;
/// `TPM_STS` `dataAvail`: response bytes wait in the FIFO.
pub const STS_DATA_AVAIL: u8 = 0x10;
/// `TPM_STS` `Expect`: the TPM expects more command bytes.
pub const STS_EXPECT: u8 = 0x08;

/// The FIFO interface over `R`.
pub struct Fifo<R>
{
    regs: R,
}

impl<R: Registers> Fifo<R>
{
    /// The FIFO interface of the TPM whose locality-0 window `regs` reaches.
    pub const fn new(regs: R) -> Self
    {
        Self { regs }
    }

    /// The status byte.
    fn status(&self) -> u8
    {
        self.regs.read8(STS)
    }

    /// `burstCount`: how many bytes the FIFO takes or holds without a wait.
    fn burst(&self) -> usize
    {
        usize::try_from((self.regs.read32(STS) >> 8) & 0xFFFF).unwrap_or(0)
    }

    /// Take locality 0, unless it is already active.
    fn request_locality(&self, wait: &mut dyn Wait) -> Result<(), Fault>
    {
        let access = self.regs.read8(ACCESS);
        // All-ones is what an absent locality, or no device, reads.
        if access == 0xFF
        {
            return Err(Fault::Protocol(Step::Locality));
        }
        let held = ACCESS_VALID | ACCESS_ACTIVE;
        if access & held == held
        {
            return Ok(());
        }
        self.regs.write8(ACCESS, ACCESS_REQUEST_USE);
        poll(wait, Step::Locality, || {
            self.regs.read8(ACCESS) & held == held
        })
    }

    /// Move the TPM to its command-ready state, aborting whatever it held.
    fn command_ready(&self, wait: &mut dyn Wait) -> Result<(), Fault>
    {
        self.regs.write8(STS, STS_COMMAND_READY);
        poll(wait, Step::CommandReady, || {
            self.status() & STS_COMMAND_READY != 0
        })
    }

    /// Write `cmd` into the FIFO, each burst no longer than `burstCount`,
    /// and check that the TPM expects no more.
    fn send(&self, cmd: &[u8], wait: &mut dyn Wait) -> Result<(), Fault>
    {
        let mut rest = cmd;
        while !rest.is_empty()
        {
            let mut burst = 0;
            poll(wait, Step::Send, || {
                burst = self.burst();
                burst != 0
            })?;
            let (now, later) = rest.split_at(burst.min(rest.len()));
            for &byte in now
            {
                self.regs.write8(DATA_FIFO, byte);
            }
            rest = later;
            // Before the last byte the TPM must still expect more; after it,
            // it must not.
            poll(wait, Step::Send, || self.status() & STS_VALID != 0)?;
            let expects = self.status() & STS_EXPECT != 0;
            if expects == rest.is_empty()
            {
                return Err(Fault::Protocol(Step::Send));
            }
        }
        Ok(())
    }

    /// Read `out.len()` bytes from the FIFO, each burst no longer than
    /// `burstCount`.
    fn read_bytes(&self, out: &mut [u8], wait: &mut dyn Wait) -> Result<(), Fault>
    {
        let mut rest = out;
        while !rest.is_empty()
        {
            let mut burst = 0;
            poll(wait, Step::Receive, || {
                let status = self.status();
                if status & (STS_VALID | STS_DATA_AVAIL) != (STS_VALID | STS_DATA_AVAIL)
                {
                    return false;
                }
                burst = self.burst();
                burst != 0
            })?;
            let n = burst.min(rest.len());
            let (now, later) = core::mem::take(&mut rest).split_at_mut(n);
            for byte in now
            {
                *byte = self.regs.read8(DATA_FIFO);
            }
            rest = later;
        }
        Ok(())
    }

    /// Read the response into `rsp`: its header, then the rest its size
    /// gives, then check that the FIFO holds nothing past it.
    fn receive(&self, rsp: &mut [u8], wait: &mut dyn Wait) -> Result<usize, Fault>
    {
        let header = rsp.get_mut(..HEADER_LEN).ok_or(Fault::Malformed)?;
        self.read_bytes(header, wait)?;
        let size = response_size(header).ok_or(Fault::Malformed)?;
        let body = rsp.get_mut(HEADER_LEN..size).ok_or(Fault::Malformed)?;
        self.read_bytes(body, wait)?;
        poll(wait, Step::Receive, || self.status() & STS_VALID != 0)?;
        if self.status() & STS_DATA_AVAIL != 0
        {
            return Err(Fault::Malformed);
        }
        Ok(size)
    }

    /// One command, from a held locality: command-ready, send, go, receive.
    fn transact(&self, cmd: &[u8], rsp: &mut [u8], wait: &mut dyn Wait) -> Result<usize, Fault>
    {
        self.command_ready(wait)?;
        self.send(cmd, wait)?;
        self.regs.write8(STS, STS_GO);
        poll(wait, Step::Execute, || {
            self.status() & (STS_VALID | STS_DATA_AVAIL) == (STS_VALID | STS_DATA_AVAIL)
        })?;
        self.receive(rsp, wait)
    }
}

impl<R: Registers> Transport for Fifo<R>
{
    fn execute(&mut self, cmd: &[u8], rsp: &mut [u8], wait: &mut dyn Wait) -> Result<usize, Fault>
    {
        self.request_locality(wait)?;
        let out = self.transact(cmd, rsp, wait);
        // Back to idle, aborting a command that failed part way, and give the
        // locality up, whatever the command's outcome.
        self.regs.write8(STS, STS_COMMAND_READY);
        self.regs.write8(ACCESS, ACCESS_ACTIVE);
        out
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::command::{self, Response, parse_response};
    use crate::sim::{FifoSim, Polls, Tpm};

    fn get_random(sim: &FifoSim, asked: u16) -> Result<Vec<u8>, Fault>
    {
        let mut fifo = Fifo::new(sim);
        let mut rsp = [0u8; 128];
        let len = fifo.execute(&command::get_random(asked), &mut rsp, &mut Polls(50))?;
        match parse_response(&rsp[..len])
        {
            Some(Response::Success(params)) =>
            {
                Ok(command::random_bytes(params, usize::from(asked))
                    .unwrap()
                    .to_vec())
            }
            other => panic!("unexpected response {other:?}"),
        }
    }

    #[test]
    fn a_command_crosses_the_fifo_in_bursts()
    {
        // A burst shorter than the command and the response makes each
        // cross in several.
        let sim = FifoSim::new(Tpm::started(), 5);
        assert_eq!(get_random(&sim, 16).unwrap(), Tpm::bytes(0, 16));
        assert_eq!(sim.received(), vec![command::get_random(16).to_vec()]);
    }

    #[test]
    fn the_locality_is_given_up_after_each_command()
    {
        let sim = FifoSim::new(Tpm::started(), 64);
        get_random(&sim, 4).unwrap();
        assert!(!sim.locality_active());
        get_random(&sim, 4).unwrap();
        assert_eq!(sim.locality_requests(), 2);
    }

    #[test]
    fn a_tpm_that_never_completes_ends_at_the_bound_and_is_reset()
    {
        let sim = FifoSim::new(Tpm::stalled(), 64);
        assert_eq!(get_random(&sim, 4), Err(Fault::Timeout(Step::Execute)));
        // commandReady written after the failure aborts the command, and the
        // locality is given up.
        assert!(sim.aborted());
        assert!(!sim.locality_active());
    }

    #[test]
    fn an_absent_locality_is_refused_without_a_write()
    {
        let sim = FifoSim::absent();
        assert_eq!(get_random(&sim, 4), Err(Fault::Protocol(Step::Locality)));
    }

    #[test]
    fn a_response_larger_than_the_buffer_is_malformed()
    {
        let sim = FifoSim::new(Tpm::started(), 64);
        let mut fifo = Fifo::new(&sim);
        // Room for the header alone.
        let mut rsp = [0u8; HEADER_LEN];
        let out = fifo.execute(&command::get_random(8), &mut rsp, &mut Polls(50));
        assert_eq!(out, Err(Fault::Malformed));
    }

    #[test]
    fn a_tpm_that_expects_more_than_the_command_breaks_the_protocol()
    {
        let sim = FifoSim::new(Tpm::started(), 64);
        sim.set_expect_stuck();
        let mut fifo = Fifo::new(&sim);
        let mut rsp = [0u8; 64];
        let out = fifo.execute(&command::get_random(8), &mut rsp, &mut Polls(50));
        assert_eq!(out, Err(Fault::Protocol(Step::Send)));
    }
}
