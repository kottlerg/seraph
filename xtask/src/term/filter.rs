// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! term/filter.rs
//!
//! Byte-stream control-sequence filter for QEMU output.
//!
//! `FilterWriter` is a `Write` adapter that strips terminal-control
//! sequences known to corrupt the host tty when emitted unsolicited.
//! The primary offender is OVMF (x86-64) and EDK2 (RISC-V), which emit
//! xterm window-manipulation and DEC private-mode sequences over the
//! serial console during firmware init. A misbehaving Seraph print
//! site can hit the same failure mode by accident; filtering both
//! paths makes that fail loudly rather than corrupt the user's shell.
//!
//! What is dropped (rationale, blocklist):
//!
//! - `CSI ... t` — xterm window manipulation. OVMF emits
//!   `ESC[8;rows;colst` which resizes (or asks the emulator to resize)
//!   the host terminal. No legitimate kernel/userspace use.
//! - `CSI ? ... h` / `l` for modes 47, 1047, 1049 — alternate-screen
//!   buffer toggles. Leaving the alt buffer active hides subsequent
//!   output from scrollback.
//! - `CSI ? 5 h` / `l` — DECSCNM (full-screen reverse video).
//! - `CSI ? 9 h` / `l` and `CSI ? 1000`–`1006 h` / `l` — mouse-tracking
//!   modes. Leaving these enabled feeds mouse-move bytes into the next
//!   program's stdin.
//! - `OSC 0;…`, `OSC 1;…`, `OSC 2;…` (terminated by BEL or ST) —
//!   window/icon title set. Persists after the run.
//! - `ESC c` — RIS (full reset). Clears scrollback in many emulators.
//!
//! What is passed through:
//!
//! - SGR (`CSI ... m`) — colors and text attributes.
//! - Cursor positioning, line/screen clear within current screen, and
//!   any other CSI sequence not in the drop list.
//! - DEC private modes outside the blocklist (notably `?25` cursor
//!   visibility).
//! - All plain bytes including `\r`, `\n`, `\t`, `\b`.
//! - `ESC X` for `X` other than `[`, `]`, `c` (charset selection,
//!   etc.).
//!
//! Conservative composition rule: when one CSI private-mode sequence
//! mixes blocklisted and non-blocklisted modes (e.g. `CSI ? 25;1049 h`),
//! the whole sequence is dropped. Combining safe and unsafe modes in
//! one sequence is not idiomatic and is safer to discard wholesale than
//! to attempt to rewrite.
//!
//! The filter is a pure byte-stream parser — no I/O beyond the wrapped
//! writer, no platform code, no allocation beyond a small reusable
//! scratch buffer that holds at most one in-flight sequence. It is
//! unit-tested in isolation against the full CSI/OSC grammar and
//! split-across-write boundaries.

use std::io::{self, Write};

/// CSI / OSC parser state. Bytes that arrive mid-sequence are buffered
/// in `FilterWriter::pending` until the sequence completes; at that
/// point the buffered bytes are either emitted to the inner writer or
/// dropped as a unit.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State
{
    /// Outside any escape sequence. Bytes pass through directly.
    Ground,
    /// Saw `ESC`. The next byte selects the sequence type
    /// (`[` = CSI, `]` = OSC, `c` = RIS, anything else = pass through).
    Esc,
    /// Saw `ESC [`, collecting params / intermediates until a final
    /// byte in `0x40..=0x7e` ends the CSI sequence.
    Csi,
    /// Saw `ESC ]`, collecting OSC body until BEL (`0x07`) or the
    /// start of an ST terminator (`ESC \`).
    Osc,
    /// Saw `ESC ] ... ESC`, waiting for the trailing `\` that
    /// completes the ST terminator.
    OscEsc,
}

/// `Write` adapter that drops dangerous terminal-control sequences
/// from the byte stream and passes everything else through unchanged.
///
/// See the module docs for the full drop / pass-through rules.
pub struct FilterWriter<W: Write>
{
    inner: W,
    state: State,
    /// Bytes consumed since the start of an in-progress sequence,
    /// including the leading `ESC`. Empty in `State::Ground`.
    pending: Vec<u8>,
}

impl<W: Write> FilterWriter<W>
{
    /// Wrap `inner` in a filter. Bytes written to the returned writer
    /// are screened against the blocklist and the remainder forwarded
    /// to `inner`.
    pub fn new(inner: W) -> Self
    {
        FilterWriter {
            inner,
            state: State::Ground,
            pending: Vec::new(),
        }
    }

    /// Resolve a completed escape sequence: emit it to `inner` if
    /// permitted, or drop the buffered bytes otherwise. Always clears
    /// `pending`.
    fn flush_pending(&mut self) -> io::Result<()>
    {
        if should_drop(&self.pending)
        {
            self.pending.clear();
            return Ok(());
        }
        let result = self.inner.write_all(&self.pending);
        self.pending.clear();
        result
    }
}

impl<W: Write> Write for FilterWriter<W>
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>
    {
        // Batch contiguous Ground bytes into a single inner.write_all to
        // avoid per-byte syscalls on the common no-escape path.
        let mut ground_start: Option<usize> = None;

        for (i, &b) in buf.iter().enumerate()
        {
            match self.state
            {
                State::Ground =>
                {
                    if b == 0x1b
                    {
                        if let Some(start) = ground_start.take()
                        {
                            self.inner.write_all(&buf[start..i])?;
                        }
                        self.state = State::Esc;
                        self.pending.push(b);
                    }
                    else
                    {
                        ground_start.get_or_insert(i);
                    }
                }
                State::Esc =>
                {
                    self.pending.push(b);
                    match b
                    {
                        b'[' => self.state = State::Csi,
                        b']' => self.state = State::Osc,
                        b'c' =>
                        {
                            // RIS — full terminal reset. Drop.
                            self.pending.clear();
                            self.state = State::Ground;
                        }
                        _ =>
                        {
                            // Other ESC X — pass through (charset switches, etc.).
                            self.flush_pending()?;
                            self.state = State::Ground;
                        }
                    }
                }
                State::Csi =>
                {
                    self.pending.push(b);
                    // Final byte (0x40..=0x7e) ends the CSI sequence.
                    if (0x40..=0x7e).contains(&b)
                    {
                        self.flush_pending()?;
                        self.state = State::Ground;
                    }
                }
                State::Osc =>
                {
                    self.pending.push(b);
                    if b == 0x07
                    {
                        self.flush_pending()?;
                        self.state = State::Ground;
                    }
                    else if b == 0x1b
                    {
                        self.state = State::OscEsc;
                    }
                }
                State::OscEsc =>
                {
                    self.pending.push(b);
                    // Whether the next byte is `\` (proper ST) or anything
                    // else (malformed input — treat as end-of-sequence),
                    // we resolve `pending` and return to Ground.
                    self.flush_pending()?;
                    self.state = State::Ground;
                }
            }
        }

        if let Some(start) = ground_start
        {
            self.inner.write_all(&buf[start..])?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()>
    {
        // Mid-sequence pending bytes stay buffered across flush; only
        // the inner writer is flushed. CSI/OSC bytes that have not yet
        // reached a final byte have ambiguous emit/drop status and must
        // not leak.
        self.inner.flush()
    }
}

/// Decide whether a completed escape sequence should be dropped.
/// `seq` always begins with `ESC` (`0x1b`).
fn should_drop(seq: &[u8]) -> bool
{
    if seq.len() < 2
    {
        return false;
    }
    match seq[1]
    {
        b'c' => true,
        b'[' => csi_should_drop(&seq[2..]),
        b']' => osc_should_drop(&seq[2..]),
        _ => false,
    }
}

/// Drop-decision for a CSI body (everything after `ESC [`).
/// Body ends with the final byte (`0x40..=0x7e`).
fn csi_should_drop(body: &[u8]) -> bool
{
    let Some((&final_byte, params)) = body.split_last()
    else
    {
        return false;
    };

    match final_byte
    {
        b't' => true,
        b'h' | b'l' if params.first() == Some(&b'?') => any_blocklisted_dec_mode(&params[1..]),
        _ => false,
    }
}

/// Returns true if any semicolon-separated decimal in `params`
/// matches a blocklisted DEC private mode.
fn any_blocklisted_dec_mode(params: &[u8]) -> bool
{
    for chunk in params.split(|&b| b == b';')
    {
        let Ok(s) = std::str::from_utf8(chunk)
        else
        {
            continue;
        };
        let Ok(n) = s.parse::<u32>()
        else
        {
            continue;
        };
        if is_blocklisted_dec_mode(n)
        {
            return true;
        }
    }
    false
}

/// DEC private modes that must not be left enabled in the host tty.
/// Strictly enumerated rather than ranged-with-exceptions so the
/// blocklist is self-documenting in the failure case.
fn is_blocklisted_dec_mode(n: u32) -> bool
{
    matches!(
        n,
        47       // legacy alternate screen
      | 1047    // alternate screen (DECRPM-style)
      | 1049    // alternate screen + save cursor
      | 5       // DECSCNM (reverse video, entire screen)
      | 9       // X10 mouse reporting
      | 1000..=1006 // xterm mouse modes (button, any-event, focus, utf8, sgr, urxvt)
    )
}

/// Drop-decision for an OSC body (everything after `ESC ]`).
/// `body` includes the terminator (BEL or `ESC \`) at the end.
fn osc_should_drop(body: &[u8]) -> bool
{
    let trim_end = body
        .iter()
        .position(|&b| b == 0x07 || b == 0x1b)
        .unwrap_or(body.len());
    let trimmed = &body[..trim_end];
    let semi = trimmed
        .iter()
        .position(|&b| b == b';')
        .unwrap_or(trimmed.len());
    let prefix = &trimmed[..semi];
    // OSC 0 = icon + window title, 1 = icon title, 2 = window title.
    matches!(prefix, b"0" | b"1" | b"2")
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Run `input` through a fresh `FilterWriter` and return the bytes
    /// that reached the inner writer.
    fn run(input: &[u8]) -> Vec<u8>
    {
        let mut out = Vec::new();
        {
            let mut w = FilterWriter::new(&mut out);
            w.write_all(input).unwrap();
        }
        out
    }

    /// Like `run`, but writes one byte at a time. Exercises mid-sequence
    /// state preservation across `write` boundaries.
    fn run_one_byte_at_a_time(input: &[u8]) -> Vec<u8>
    {
        let mut out = Vec::new();
        {
            let mut w = FilterWriter::new(&mut out);
            for &b in input
            {
                w.write_all(&[b]).unwrap();
            }
        }
        out
    }

    #[test]
    fn plain_ascii_passes_through_unchanged()
    {
        assert_eq!(run(b"hello world\n"), b"hello world\n");
    }

    #[test]
    fn empty_input_produces_empty_output()
    {
        assert_eq!(run(b""), b"");
    }

    #[test]
    fn sgr_color_passes_through()
    {
        let input = b"\x1b[31mred\x1b[0m";
        assert_eq!(run(input), input);
    }

    #[test]
    fn cursor_positioning_passes_through()
    {
        let input = b"\x1b[10;20H";
        assert_eq!(run(input), input);
    }

    #[test]
    fn clear_to_end_of_line_passes_through()
    {
        let input = b"\x1b[K";
        assert_eq!(run(input), input);
    }

    #[test]
    fn cursor_visibility_is_preserved()
    {
        // DEC ?25 — show / hide cursor — is NOT in the blocklist.
        assert_eq!(run(b"\x1b[?25h"), b"\x1b[?25h");
        assert_eq!(run(b"\x1b[?25l"), b"\x1b[?25l");
    }

    #[test]
    fn window_manipulation_is_stripped()
    {
        let input = b"before\x1b[8;24;80tafter";
        assert_eq!(run(input), b"beforeafter");
    }

    #[test]
    fn window_manipulation_without_params_is_stripped()
    {
        // CSI t with no params still has 't' as the final byte; drop.
        assert_eq!(run(b"\x1b[t"), b"");
    }

    #[test]
    fn alternate_screen_1049_is_stripped()
    {
        assert_eq!(run(b"\x1b[?1049h"), b"");
        assert_eq!(run(b"\x1b[?1049l"), b"");
    }

    #[test]
    fn alternate_screen_legacy_47_is_stripped()
    {
        assert_eq!(run(b"\x1b[?47h"), b"");
        assert_eq!(run(b"\x1b[?47l"), b"");
    }

    #[test]
    fn alternate_screen_1047_is_stripped()
    {
        assert_eq!(run(b"\x1b[?1047h"), b"");
        assert_eq!(run(b"\x1b[?1047l"), b"");
    }

    #[test]
    fn reverse_video_decscnm_is_stripped()
    {
        assert_eq!(run(b"\x1b[?5h"), b"");
        assert_eq!(run(b"\x1b[?5l"), b"");
    }

    #[test]
    fn x10_mouse_mode_is_stripped()
    {
        assert_eq!(run(b"\x1b[?9h"), b"");
    }

    #[test]
    fn xterm_mouse_modes_are_stripped()
    {
        for n in 1000_u32..=1006
        {
            let seq = format!("\x1b[?{n}h");
            assert!(
                run(seq.as_bytes()).is_empty(),
                "failed to strip mouse mode {n}"
            );
        }
    }

    #[test]
    fn mixed_safe_and_blocklisted_dec_modes_drop_whole_sequence()
    {
        // ?25 is safe (cursor visibility), ?1049 is blocked (alt screen).
        // Conservative rule: drop the whole sequence.
        assert_eq!(run(b"\x1b[?25;1049h"), b"");
        assert_eq!(run(b"\x1b[?1049;25h"), b"");
    }

    #[test]
    fn ris_full_reset_is_stripped()
    {
        let input = b"before\x1bcafter";
        assert_eq!(run(input), b"beforeafter");
    }

    #[test]
    fn osc_window_title_bel_terminated_is_stripped()
    {
        let input = b"hi\x1b]0;some title\x07bye";
        assert_eq!(run(input), b"hibye");
    }

    #[test]
    fn osc_icon_title_bel_terminated_is_stripped()
    {
        let input = b"\x1b]1;icon\x07";
        assert_eq!(run(input), b"");
    }

    #[test]
    fn osc_window_title_st_terminated_is_stripped()
    {
        // ST = ESC \. ECMA-48 canonical OSC terminator.
        let input = b"\x1b]2;title\x1b\\";
        assert_eq!(run(input), b"");
    }

    #[test]
    fn osc_outside_blocklist_passes_through()
    {
        // OSC 4 is the xterm palette query/response — not in the blocklist.
        let input = b"\x1b]4;0;rgb:00/00/00\x07";
        assert_eq!(run(input), input);
    }

    #[test]
    fn esc_followed_by_unknown_byte_passes_through()
    {
        // ESC ( B — switch G0 to ASCII. Uncommon but legitimate.
        let input = b"\x1b(B";
        assert_eq!(run(input), input);
    }

    #[test]
    fn split_window_resize_across_writes_is_stripped()
    {
        let input = b"foo\x1b[8;30;100tbar";
        assert_eq!(run_one_byte_at_a_time(input), b"foobar");
    }

    #[test]
    fn split_alternate_screen_across_writes_is_stripped()
    {
        assert_eq!(run_one_byte_at_a_time(b"\x1b[?1049h"), b"");
    }

    #[test]
    fn split_sgr_across_writes_passes_through()
    {
        let input = b"\x1b[31;1mred\x1b[0m";
        assert_eq!(run_one_byte_at_a_time(input), input);
    }

    #[test]
    fn split_osc_title_across_writes_is_stripped()
    {
        let input = b"\x1b]0;split title\x07";
        assert_eq!(run_one_byte_at_a_time(input), b"");
    }

    #[test]
    fn write_returns_full_input_length_on_drop()
    {
        let mut out = Vec::new();
        let mut w = FilterWriter::new(&mut out);
        let n = w.write(b"\x1b[?1049h").unwrap();
        assert_eq!(n, 8);
    }

    #[test]
    fn write_returns_full_input_length_on_passthrough()
    {
        let mut out = Vec::new();
        let mut w = FilterWriter::new(&mut out);
        let n = w.write(b"hello").unwrap();
        assert_eq!(n, 5);
    }

    #[test]
    fn multiple_sequences_in_one_write_are_handled()
    {
        // SGR + window-resize + plain text + alt-screen + SGR-reset.
        let input = b"\x1b[31mhi\x1b[8;1;1tworld\x1b[?1049h\x1b[0m";
        assert_eq!(run(input), b"\x1b[31mhiworld\x1b[0m");
    }

    #[test]
    fn realistic_ovmf_resize_burst_is_stripped()
    {
        // Approximate one of the bursts OVMF emits during init:
        // request 80×25 terminal, set cursor pos, clear screen, SGR
        // reset. Only the window-manipulation should be removed.
        let input = b"\x1b[8;25;80t\x1b[1;1H\x1b[2J\x1b[0m";
        assert_eq!(run(input), b"\x1b[1;1H\x1b[2J\x1b[0m");
    }
}
