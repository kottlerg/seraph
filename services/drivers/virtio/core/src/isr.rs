// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/core/src/isr.rs

//! Interrupt-service loop shared by the `VirtIO` drivers.
//!
//! A driver on a line devmgr may share MUST acknowledge each delivery
//! promptly, whether or not it has a request in flight
//! (services/drivers/docs/driver-model.md rule 5). Each `VirtIO` driver runs
//! [`serve_interrupts`] on a thread of its own, as the only waiter on the
//! notification bound to its line, and its request or read path waits on a
//! second notification the loop signals. A thread of its own, rather than the
//! service loop, acknowledges, because the service loop blocks in `ipc_recv`,
//! which has no timeout: a wait set over the service endpoint and the
//! notification can report a sender that has since left, and the receive
//! then blocks with the binding owing.

use ipc::recv_guard::{RecvFailureStage, RecvGuard};

use crate::pci::PciTransport;

/// How long, in milliseconds, [`serve_interrupts`] waits for a delivery
/// before it reads the device's interrupt status anyway.
///
/// On a line whose x86-64 I/O APIC entry is programmed edge-triggered (a
/// line the firmware describes as edge), a device that asserts the shared
/// line while it is masked raises no edge, and stays asserted until its ISR
/// is read. The timed read clears that assertion, so the device's next one
/// raises an edge again, and a lost interrupt costs the waiter at most this
/// long. A level-triggered entry delivers such an assertion at the unmask,
/// so there the read only bounds a lost wake. A tuning value that bounds no
/// capacity: it decides only how soon a lost edge is recovered, against one
/// ISR read per period while the device is idle.
pub const ISR_POLL_MS: u64 = 50;

/// What [`serve_interrupts`] does after one bounded wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsrStep
{
    /// Acknowledge the binding: a delivery made it owe one.
    pub ack: bool,
    /// Signal the waiting path: a delivery arrived, or the device had an
    /// interrupt pending that no delivery reported.
    pub signal: bool,
}

/// The step after a wait that returned a delivery (`delivered`) or timed
/// out, given the ISR value the loop then read.
///
/// A delivery is acknowledged and signalled whatever the ISR holds, since it
/// may be another device's on the line and the binding owes either way. A
/// timeout owes no acknowledgement; it signals only when the ISR was set,
/// which is an interrupt no delivery reported: a lost edge on a line programmed
/// edge-triggered, a lost wake on a level-triggered one.
#[must_use]
pub const fn isr_step(delivered: bool, isr: u8) -> IsrStep
{
    IsrStep {
        ack: delivered,
        signal: delivered || isr != 0,
    }
}

/// Serve the device's line forever: wait on `irq_notification` for at most
/// [`ISR_POLL_MS`], read the ISR (which clears this device's assertion),
/// then act on [`isr_step`]: acknowledge `irq_cap` and signal `signal`.
///
/// A failed wait goes through a [`RecvGuard`] with `diag` as its hook: the
/// backoff, the log at the start of a failure streak, and the exit once a
/// streak proves the notification unusable, so a broken cap fails the
/// driver rather than spinning or leaving the line masked.
pub fn serve_interrupts(
    transport: &PciTransport,
    irq_notification: u32,
    irq_cap: u32,
    signal: u32,
    diag: fn(RecvFailureStage, i64),
) -> !
{
    let mut guard = RecvGuard::new(diag);
    loop
    {
        let delivered = match syscall::notification_wait_timeout(irq_notification, ISR_POLL_MS)
        {
            // Ok(0) is a timeout: notification_send rejects zero-bit sends.
            Ok(bits) =>
            {
                guard.on_success();
                bits != 0
            }
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        let step = isr_step(delivered, transport.read_isr());
        if step.ack
        {
            let _ = syscall::irq_ack(irq_cap);
        }
        if step.signal
        {
            let _ = syscall::notification_send(signal, 1);
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // With the ISR clear, so the delivery alone signals: it may be another
    // device's on the line.
    #[test]
    fn a_delivery_is_acknowledged_and_signalled_even_with_the_isr_clear()
    {
        assert_eq!(
            isr_step(true, 0),
            IsrStep {
                ack: true,
                signal: true
            }
        );
    }

    #[test]
    fn a_timeout_with_the_isr_set_signals_without_acknowledging()
    {
        // The lost-edge case: the device asserted while the line was masked.
        assert_eq!(
            isr_step(false, 1),
            IsrStep {
                ack: false,
                signal: true
            }
        );
    }

    #[test]
    fn a_quiet_timeout_does_nothing()
    {
        assert_eq!(
            isr_step(false, 0),
            IsrStep {
                ack: false,
                signal: false
            }
        );
    }
}
