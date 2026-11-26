// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/serial/src/uart.rs

//! The 16550 register file as the driver uses it: register offsets, the
//! bits it reads and writes, and the decoding of the interrupt
//! identification register (IIR).
//!
//! The driver assumes a 16550-compatible UART that an earlier boot stage
//! programmed (baud rate, line control, FIFO control) and leaves those
//! registers as they are. It writes only THR and IER, and never FCR: a write
//! to FCR clears the FIFOs, which can hold an earlier stage's last bytes.

/// Receive buffer register (read) and transmit holding register (write).
pub const DATA: u8 = 0;
/// Interrupt enable register.
pub const IER: u8 = 1;
/// Interrupt identification register (read).
pub const IIR: u8 = 2;
/// Line status register.
pub const LSR: u8 = 5;
/// Modem status register.
pub const MSR: u8 = 6;
/// Registers a 16550's register file spans.
pub const REGISTERS: u8 = 8;

/// IER: received-data-available interrupt (with the character timeout).
pub const IER_RX: u8 = 0x01;
/// IER: transmit-holding-register-empty interrupt.
pub const IER_TX: u8 = 0x02;

/// LSR: a received byte is ready in RBR.
pub const LSR_DATA_READY: u8 = 0x01;
/// LSR: the transmit holding register, the whole transmit FIFO in FIFO mode,
/// is empty.
pub const LSR_THR_EMPTY: u8 = 0x20;
/// LSR: the transmitter is empty: THR (or the FIFO) and the shift register.
pub const LSR_TX_EMPTY: u8 = 0x40;

/// Bytes one load of the transmit FIFO takes once THR reports empty, with
/// the FIFOs enabled: a 16550A's FIFO depth. A UART with a deeper FIFO takes
/// the same loads.
pub const FIFO_LOAD: usize = 16;

/// What the IIR names as the UART's highest-priority pending interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause
{
    /// No interrupt is pending.
    None,
    /// A line status error (overrun, parity, framing, break); cleared by
    /// reading LSR.
    LineStatus,
    /// Received data reached the FIFO trigger level, or one byte without
    /// FIFOs; cleared by reading RBR below it.
    ReceivedData,
    /// Received bytes sat in the FIFO for four character times; cleared by
    /// reading RBR.
    ReceiveTimeout,
    /// THR (the transmit FIFO) is empty; cleared by reading IIR naming it,
    /// or by writing THR.
    TransmitEmpty,
    /// A modem status change; cleared by reading MSR.
    ModemStatus,
    /// An identification a 16550 does not define.
    Other,
}

/// The cause the IIR value `iir` names: bit 0 clear means one is pending,
/// and bits 3:1 identify it.
#[must_use]
pub const fn cause(iir: u8) -> Cause
{
    if iir & 0x01 != 0
    {
        return Cause::None;
    }
    match (iir >> 1) & 0x07
    {
        0b011 => Cause::LineStatus,
        0b010 => Cause::ReceivedData,
        0b110 => Cause::ReceiveTimeout,
        0b001 => Cause::TransmitEmpty,
        0b000 => Cause::ModemStatus,
        _ => Cause::Other,
    }
}

/// Bytes one load of THR may write once LSR reports it empty, read from the
/// IIR value `iir`: [`FIFO_LOAD`] when bits 7:6 report the FIFOs enabled,
/// else one, the holding register alone.
#[must_use]
pub const fn transmit_load(iir: u8) -> usize
{
    if iir & 0xC0 == 0xC0 { FIFO_LOAD } else { 1 }
}

/// The IER value for the transmitter's state: the receive interrupt unless
/// the receive ring is full (`rx_paused`), and the transmit interrupt
/// while bytes wait to be loaded or a write waits for the transmitter to
/// empty (`tx_wanted`).
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`rx_paused` and `tx_wanted` are the transmitter's state, data the IER value is \
              computed from"
)]
pub const fn interrupt_enable(rx_paused: bool, tx_wanted: bool) -> u8
{
    let rx = if rx_paused { 0 } else { IER_RX };
    let tx = if tx_wanted { IER_TX } else { 0 };
    rx | tx
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a pending interrupt read as none (the transmitter would
    // sleep with the line raised) or an idle IIR read as a cause.
    #[test]
    fn iir_causes_decode_as_the_16550_defines_them()
    {
        assert_eq!(cause(0x01), Cause::None);
        assert_eq!(cause(0xC1), Cause::None);
        assert_eq!(cause(0x06), Cause::LineStatus);
        assert_eq!(cause(0xC4), Cause::ReceivedData);
        assert_eq!(cause(0xCC), Cause::ReceiveTimeout);
        assert_eq!(cause(0xC2), Cause::TransmitEmpty);
        assert_eq!(cause(0x00), Cause::ModemStatus);
        assert_eq!(cause(0x08), Cause::Other);
    }

    // Defect caught: a FIFO load written to a UART whose FIFOs are off, which
    // would overrun its one-byte holding register.
    #[test]
    fn a_load_is_the_fifo_only_with_fifos_enabled()
    {
        assert_eq!(transmit_load(0xC1), FIFO_LOAD);
        assert_eq!(transmit_load(0x01), 1);
        assert_eq!(transmit_load(0x81), 1);
    }

    // Defect caught: the receive interrupt left on with a full receive ring
    // (a level line would fire without end) or the transmit interrupt left
    // off while bytes wait (the ring would drain only on the watchdog).
    #[test]
    fn interrupt_enable_follows_the_rings()
    {
        assert_eq!(interrupt_enable(false, false), IER_RX);
        assert_eq!(interrupt_enable(false, true), IER_RX | IER_TX);
        assert_eq!(interrupt_enable(true, true), IER_TX);
        assert_eq!(interrupt_enable(true, false), 0);
    }
}
