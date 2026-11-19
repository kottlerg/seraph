// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/tpm/src/lib.rs

//! Host-testable logic of the TPM 2.0 driver.
//!
//! The driver binary (`main.rs`) maps the TPM's register window and serves
//! the `hwrng` class protocol. This library holds everything it does with
//! the window: which interface the TPM presents ([`interface`]), the FIFO
//! and CRB interfaces ([`fifo::Fifo`], [`crb::Crb`]) as state machines
//! whose every wait is bounded ([`regs::Wait`]), the two commands the
//! driver sends ([`command`]), the `TPM2_GetRandom` loop that fills a read
//! within the TPM's per-call limit ([`Session::get_random`]), and the
//! service endpoint's verb-bit gate ([`authorized`]). The design is in
//! `services/drivers/docs/tpm.md`.

pub mod command;
pub mod crb;
pub mod fifo;
pub mod regs;
#[cfg(test)]
mod sim;

use hwrng_protocol::{MAX_READ_BYTES, READ, READ_AUTHORITY};

use crate::command::{COMMAND_LEN, HEADER_LEN, Response, parse_response, random_bytes, rc};
use crate::regs::{Fault, Wait};

/// `TPM_INTERFACE_ID_0`, the same offset on both interfaces; its low nibble
/// is `InterfaceType`.
pub const INTERFACE_ID: usize = 0x30;

/// The interface a TPM presents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interface
{
    /// The FIFO interface: `InterfaceType` 0, or 0xF, the TIS 1.3 FIFO,
    /// whose `TPM_INTERFACE_ID` register is reserved and reads all-ones.
    Fifo,
    /// The CRB interface: `InterfaceType` 1.
    Crb,
}

/// The interface `TPM_INTERFACE_ID` value `id` names; `None` for an
/// `InterfaceType` the driver does not speak.
#[must_use]
pub const fn interface(id: u32) -> Option<Interface>
{
    match id & 0xF
    {
        0x0 | 0xF => Some(Interface::Fifo),
        0x1 => Some(Interface::Crb),
        _ => None,
    }
}

/// An interface that carries one command to the TPM and its response back.
pub trait Transport
{
    /// Send `cmd` and read the response into `rsp`, every wait bounded by
    /// `wait`. Returns the response's length.
    ///
    /// # Errors
    /// The [`Fault`] that ended the command. The interface is left idle and
    /// the locality given up either way.
    fn execute(&mut self, cmd: &[u8], rsp: &mut [u8], wait: &mut dyn Wait) -> Result<usize, Fault>;
}

/// The most bytes one `TPM2_GetRandom` asks for: the most one `READ`
/// reply carries. A TPM returns at most its largest digest's size per call
/// whatever is asked.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the assert in the initializer bounds the value to u16"
)]
const REQUEST_MAX: u16 = {
    assert!(MAX_READ_BYTES <= u16::MAX as usize);
    MAX_READ_BYTES as u16
};

/// Bytes of the largest `TPM2_GetRandom` response: its header, the
/// `TPM2B_DIGEST` count, and [`REQUEST_MAX`] bytes.
const RESPONSE_MAX: usize = HEADER_LEN + 2 + REQUEST_MAX as usize;

/// The driver's session with one TPM over its interface `T`.
pub struct Session<T>
{
    transport: T,
}

impl<T: Transport> Session<T>
{
    /// A session over `transport`.
    pub const fn new(transport: T) -> Self
    {
        Self { transport }
    }

    /// Send `cmd`, read the response, and return what it says.
    fn call(
        &mut self,
        cmd: &[u8; COMMAND_LEN],
        rsp: &mut [u8; RESPONSE_MAX],
        wait: &mut dyn Wait,
    ) -> Result<(), Fault>
    {
        let len = self.transport.execute(cmd, rsp, wait)?;
        match parse_response(rsp.get(..len).ok_or(Fault::Malformed)?).ok_or(Fault::Malformed)?
        {
            Response::Success(_) => Ok(()),
            Response::Code(code) => Err(Fault::Code(code)),
        }
    }

    /// Fill `out` from the TPM's random number generator, one
    /// `TPM2_GetRandom` after another, each asking for what is left and
    /// answered with at most the TPM's per-call limit. A TPM not yet started
    /// (`TPM_RC_INITIALIZE`) is sent `TPM2_Startup(TPM_SU_CLEAR)` once; a busy
    /// TPM (`TPM_RC_RETRY`, `TPM_RC_TESTING`, `TPM_RC_YIELDED`) is asked
    /// again after a pause on `wait`, as is one that returns no bytes. Returns
    /// the bytes filled, fewer than `out.len()` when `wait` ended first or a
    /// command failed after some arrived.
    ///
    /// # Errors
    /// The [`Fault`] that ended the read before any byte arrived: a
    /// response code the driver does not retry ([`Fault::Code`]), a bound
    /// passed, or a broken interface or response.
    pub fn get_random(&mut self, out: &mut [u8], wait: &mut dyn Wait) -> Result<usize, Fault>
    {
        let mut filled = 0usize;
        let mut started = false;
        let mut rsp = [0u8; RESPONSE_MAX];
        let mut last = Fault::Timeout(regs::Step::Execute);
        while let Some(rest) = out.get_mut(filled..).filter(|rest| !rest.is_empty())
        {
            let asked = u16::try_from(rest.len())
                .unwrap_or(REQUEST_MAX)
                .min(REQUEST_MAX);
            // `None`: ask again after a pause; `Some`: the read ends.
            let end = match self.random(asked, &mut rsp, wait)
            {
                Ok(bytes) if !bytes.is_empty() =>
                {
                    for (dst, &src) in rest.iter_mut().zip(bytes)
                    {
                        *dst = src;
                    }
                    // At most `rest.len()` bytes, since a response never
                    // carries more than was asked.
                    filled = filled.saturating_add(bytes.len().min(rest.len()));
                    continue;
                }
                Ok(_) => None,
                Err(Fault::Code(rc::INITIALIZE)) if !started =>
                {
                    started = true;
                    match self.call(&command::startup_clear(), &mut rsp, wait)
                    {
                        // A TPM another party started meanwhile answers
                        // INITIALIZE to the start-up; it is started either way.
                        Ok(()) | Err(Fault::Code(rc::INITIALIZE)) => continue,
                        Err(fault) => Some(fault),
                    }
                }
                Err(Fault::Code(code)) if command::retryable(code) =>
                {
                    last = Fault::Code(code);
                    None
                }
                Err(fault) => Some(fault),
            };
            if let Some(fault) = end
            {
                last = fault;
                break;
            }
            if !wait.pause()
            {
                break;
            }
        }
        if filled == 0 && !out.is_empty()
        {
            return Err(last);
        }
        Ok(filled)
    }

    /// One `TPM2_GetRandom` of `asked` bytes; the bytes it returned.
    fn random<'r>(
        &mut self,
        asked: u16,
        rsp: &'r mut [u8; RESPONSE_MAX],
        wait: &mut dyn Wait,
    ) -> Result<&'r [u8], Fault>
    {
        let len = self
            .transport
            .execute(&command::get_random(asked), rsp, wait)?;
        match parse_response(rsp.get(..len).ok_or(Fault::Malformed)?).ok_or(Fault::Malformed)?
        {
            Response::Success(params) =>
            {
                random_bytes(params, usize::from(asked)).ok_or(Fault::Malformed)
            }
            Response::Code(code) => Err(Fault::Code(code)),
        }
    }
}

/// Whether a request with label `label` from a caller badged `badge` may be
/// served: `false` when `label` is [`READ`] and `badge` lacks
/// [`READ_AUTHORITY`]. Unknown labels carry no gate and are answered
/// `UNKNOWN_OPCODE`.
#[must_use]
pub const fn authorized(label: u64, badge: u64) -> bool
{
    label != READ || badge & READ_AUTHORITY != 0
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::fifo::Fifo;
    use crate::sim::{FifoSim, Polls, Tpm};

    fn session(sim: &FifoSim) -> Session<Fifo<&FifoSim>>
    {
        Session::new(Fifo::new(sim))
    }

    #[test]
    fn a_read_past_the_per_call_limit_takes_several_commands()
    {
        // The simulated TPM answers at most 32 bytes per call.
        let sim = FifoSim::new(Tpm::started(), 64);
        let mut out = [0u8; 100];
        assert_eq!(session(&sim).get_random(&mut out, &mut Polls(200)), Ok(100));
        assert_eq!(out.to_vec(), Tpm::bytes(0, 100));
        let asks: Vec<Vec<u8>> = [100, 68, 36, 4]
            .into_iter()
            .map(|n| command::get_random(n).to_vec())
            .collect();
        assert_eq!(sim.received(), asks);
    }

    #[test]
    fn an_unstarted_tpm_is_started_once_and_read()
    {
        let sim = FifoSim::new(Tpm::unstarted(), 64);
        let mut out = [0u8; 8];
        assert_eq!(session(&sim).get_random(&mut out, &mut Polls(200)), Ok(8));
        assert_eq!(
            sim.received(),
            vec![
                command::get_random(8).to_vec(),
                command::startup_clear().to_vec(),
                command::get_random(8).to_vec(),
            ]
        );
    }

    #[test]
    fn a_tpm_that_stays_uninitialized_is_not_started_twice()
    {
        let sim = FifoSim::new(Tpm::unstartable(), 64);
        let mut out = [0u8; 8];
        assert_eq!(
            session(&sim).get_random(&mut out, &mut Polls(200)),
            Err(Fault::Code(rc::INITIALIZE))
        );
        assert_eq!(sim.received().len(), 3);
    }

    #[test]
    fn a_busy_tpm_is_asked_again()
    {
        let sim = FifoSim::new(Tpm::busy(2), 64);
        let mut out = [0u8; 8];
        assert_eq!(session(&sim).get_random(&mut out, &mut Polls(200)), Ok(8));
        assert_eq!(sim.received().len(), 3);
    }

    #[test]
    fn a_failed_tpm_ends_the_read_at_once()
    {
        let sim = FifoSim::new(Tpm::failed(), 64);
        let mut out = [0u8; 8];
        assert_eq!(
            session(&sim).get_random(&mut out, &mut Polls(200)),
            Err(Fault::Code(rc::FAILURE))
        );
        assert_eq!(sim.received().len(), 1);
    }

    #[test]
    fn a_read_the_bound_cuts_short_returns_what_arrived()
    {
        // Busy after its first answer: 32 bytes arrive, then every call
        // retries until the bound.
        let sim = FifoSim::new(Tpm::busy_after(1), 64);
        let mut out = [0u8; 64];
        assert_eq!(session(&sim).get_random(&mut out, &mut Polls(400)), Ok(32));
        assert_eq!(out[..32].to_vec(), Tpm::bytes(0, 32));
    }

    #[test]
    fn a_stalled_tpm_fails_the_read_at_the_bound()
    {
        let sim = FifoSim::new(Tpm::stalled(), 64);
        let mut out = [0u8; 8];
        assert_eq!(
            session(&sim).get_random(&mut out, &mut Polls(30)),
            Err(Fault::Timeout(regs::Step::Execute))
        );
    }

    #[test]
    fn an_empty_read_sends_nothing()
    {
        let sim = FifoSim::new(Tpm::started(), 64);
        assert_eq!(session(&sim).get_random(&mut [], &mut Polls(10)), Ok(0));
        assert_eq!(sim.received(), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn interface_type_selects_the_interface()
    {
        assert_eq!(interface(0x0000_2100), Some(Interface::Fifo));
        assert_eq!(interface(u32::MAX), Some(Interface::Fifo));
        assert_eq!(interface(0x0000_4011), Some(Interface::Crb));
        assert_eq!(interface(0x0000_0002), None);
    }

    #[test]
    fn read_is_refused_without_read_authority()
    {
        assert!(!authorized(READ, 0));
        assert!(!authorized(READ, 1u64 << 62));
        assert!(authorized(READ, READ_AUTHORITY));
        assert!(authorized(0xFFFF, 0));
    }
}
