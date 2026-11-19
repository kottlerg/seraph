// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/tpm/src/regs.rs

//! What the interface state machines run on: register access to the TPM's
//! locality-0 window ([`Registers`]), the bound on a command's waits
//! ([`Wait`]), and how a command fails ([`Fault`]).

/// Access to the TPM's register window, by byte offset from the start of
/// locality 0. The driver binary implements it over the mapped `Mmio` range
/// with volatile accesses; the host tests over a simulated TPM. An offset past
/// the window reads all-ones and drops a write, so no value the device
/// reports can move an access out of the window.
pub trait Registers
{
    /// Read the byte at `offset`.
    fn read8(&self, offset: usize) -> u8;
    /// Read the little-endian 32-bit register at `offset`.
    fn read32(&self, offset: usize) -> u32;
    /// Write the byte at `offset`.
    fn write8(&self, offset: usize, value: u8);
    /// Write the little-endian 32-bit register at `offset`.
    fn write32(&self, offset: usize, value: u32);
}

/// The bound on one command's waits. Every poll of a register a step waits
/// on calls [`Self::pause`] between reads, so a device that never answers
/// ends the command at the bound rather than holding the driver.
pub trait Wait
{
    /// Pause before the next poll. `false` once the bound has passed, which
    /// ends the wait.
    fn pause(&mut self) -> bool;
}

/// The step of a command a [`Fault`] names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step
{
    /// Requesting or holding locality 0.
    Locality,
    /// Moving the TPM to its command-ready state.
    CommandReady,
    /// Writing the command.
    Send,
    /// Waiting for the TPM to execute it.
    Execute,
    /// Reading the response.
    Receive,
}

/// Why a command failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault
{
    /// A wait of the step passed its bound.
    Timeout(Step),
    /// The device broke its interface's protocol at the step: an absent
    /// locality, a status no conforming TPM reports, or a fatal-error
    /// status.
    Protocol(Step),
    /// The response was malformed: a size past the buffer or below a
    /// header, bytes past its size, or fields that do not parse.
    Malformed,
    /// The TPM answered with a response code the driver does not retry.
    Code(u32),
}

/// Poll `ready` until it holds, pausing on `wait` between reads.
///
/// # Errors
/// [`Fault::Timeout`] of `step` when `wait` ends first.
pub(crate) fn poll(
    wait: &mut dyn Wait,
    step: Step,
    mut ready: impl FnMut() -> bool,
) -> Result<(), Fault>
{
    loop
    {
        if ready()
        {
            return Ok(());
        }
        if !wait.pause()
        {
            return Err(Fault::Timeout(step));
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::sim::Polls;

    #[test]
    fn poll_ends_at_the_bound_when_the_condition_never_holds()
    {
        let mut wait = Polls(3);
        let mut reads = 0u32;
        let out = poll(&mut wait, Step::Execute, || {
            reads += 1;
            false
        });
        assert_eq!(out, Err(Fault::Timeout(Step::Execute)));
        // One read before each of the three pauses, and one after the last.
        assert_eq!(reads, 4);
    }

    #[test]
    fn poll_returns_once_the_condition_holds()
    {
        let mut wait = Polls(10);
        let mut reads = 0u32;
        let out = poll(&mut wait, Step::Send, || {
            reads += 1;
            reads == 2
        });
        assert_eq!(out, Ok(()));
        assert_eq!(wait.0, 9);
    }
}
