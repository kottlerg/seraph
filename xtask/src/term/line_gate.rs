// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! term/line_gate.rs
//!
//! Line-level marker gate for QEMU output.
//!
//! `LineGate` is a `Write` adapter that buffers incoming bytes line by
//! line and suppresses all output until the first line containing a
//! configured marker is seen. From that line onward — the marker line
//! included — every byte is forwarded to the inner writer unchanged.
//!
//! The default Seraph launch flow points this at `"[--------] boot:"`,
//! which is the first line the bootloader emits after firmware exits.
//! Without the gate, the user sees thousands of lines of EDK2 / OVMF
//! initialization spam before anything Seraph-related; with the gate,
//! they see Seraph's own output and nothing else. Verbose mode skips
//! installing the gate altogether.
//!
//! The gate is intentionally line-granular rather than byte-granular:
//! a partial line cannot be classified, and EDK2 / OVMF lines that
//! contain `[--------] boot:` as a substring after garbage on the same
//! byte-line would be rare to nonexistent. Once the marker is seen,
//! the gate becomes a transparent pass-through forever.
//!
//! Composition with `FilterWriter`: the gate sits **after** the filter
//! (i.e. filter wraps inner; gate wraps filter). This ordering matters
//! because the filter never modifies a Seraph-style ASCII marker line,
//! so the gate's substring match remains correct, and bytes pre-gate
//! are also screened for control sequences before being either dropped
//! by the gate or passed through. A debug assertion in `LineGate::new`
//! enforces the marker is plain ASCII with no `ESC` byte, locking in
//! this invariant.

use std::io::{self, Write};

/// `Write` adapter that drops bytes until the first complete line
/// containing `marker` is seen, then passes everything through.
///
/// See the module docs for the line-vs-byte rationale and ordering
/// rule relative to `FilterWriter`.
pub struct LineGate<W: Write>
{
    inner: W,
    marker: Vec<u8>,
    /// Bytes of the current (in-progress) line. Empty after each `\n`.
    line: Vec<u8>,
    /// Once true, the gate is a transparent pass-through.
    opened: bool,
}

// LineGate is wired into the QEMU stdout pipeline in a separate commit
// on this branch; until then it has no caller in the binary.
#[allow(dead_code)]
impl<W: Write> LineGate<W>
{
    /// Wrap `inner` in a gate keyed on `marker`. Bytes are dropped
    /// until the first complete line whose content (terminated by `\n`)
    /// contains `marker`.
    ///
    /// `marker` must be plain ASCII with no `ESC` byte; combining the
    /// gate with a CSI/OSC-bearing marker would interact badly with
    /// `FilterWriter` upstream. Violations panic in debug builds and
    /// are silently honored (i.e. the gate may never open) in release
    /// builds.
    pub fn new(inner: W, marker: &[u8]) -> Self
    {
        debug_assert!(
            !marker.is_empty(),
            "LineGate marker must be non-empty",
        );
        debug_assert!(
            marker.iter().all(|&b| b.is_ascii() && b != 0x1b),
            "LineGate marker must be plain ASCII with no ESC byte",
        );
        LineGate {
            inner,
            marker: marker.to_vec(),
            line: Vec::new(),
            opened: false,
        }
    }

    /// Recover the inner writer. Any bytes still buffered in the
    /// in-progress line are discarded.
    pub fn into_inner(self) -> W
    {
        self.inner
    }
}

impl<W: Write> Write for LineGate<W>
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>
    {
        if self.opened
        {
            return self.inner.write_all(buf).map(|()| buf.len());
        }

        for (i, &b) in buf.iter().enumerate()
        {
            self.line.push(b);
            if b == b'\n'
            {
                if contains_subsequence(&self.line, &self.marker)
                {
                    // Emit the marker line in full, then drain any
                    // remaining bytes from this write batch directly
                    // into the inner writer.
                    self.inner.write_all(&self.line)?;
                    self.line.clear();
                    self.opened = true;
                    let rest = &buf[i + 1..];
                    if !rest.is_empty()
                    {
                        self.inner.write_all(rest)?;
                    }
                    return Ok(buf.len());
                }
                // No marker on this line — discard and continue.
                self.line.clear();
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()>
    {
        // In-progress (no `\n` yet) bytes stay buffered: a marker may
        // still appear before the line terminates. Only the inner
        // writer is flushed.
        self.inner.flush()
    }
}

/// Returns true if `needle` appears as a contiguous subsequence of `haystack`.
fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool
{
    if needle.is_empty() || needle.len() > haystack.len()
    {
        return needle.is_empty();
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests
{
    use super::*;

    const MARKER: &[u8] = b"[--------] boot:";

    fn run(input: &[u8]) -> Vec<u8>
    {
        let mut g = LineGate::new(Vec::new(), MARKER);
        g.write_all(input).unwrap();
        g.into_inner()
    }

    fn run_one_byte_at_a_time(input: &[u8]) -> Vec<u8>
    {
        let mut g = LineGate::new(Vec::new(), MARKER);
        for &b in input
        {
            g.write_all(&[b]).unwrap();
        }
        g.into_inner()
    }

    #[test]
    fn drops_all_lines_before_marker()
    {
        let input = b"firmware spam\nmore spam\nstill no marker\n";
        assert_eq!(run(input), b"");
    }

    #[test]
    fn emits_marker_line_in_full()
    {
        let input = b"junk\n[--------] boot: hello\n";
        assert_eq!(run(input), b"[--------] boot: hello\n");
    }

    #[test]
    fn passes_through_all_lines_after_marker()
    {
        let input = b"junk\n[--------] boot: hi\nafter1\nafter2\n";
        assert_eq!(
            run(input),
            b"[--------] boot: hi\nafter1\nafter2\n",
        );
    }

    #[test]
    fn marker_in_first_line_emits_immediately()
    {
        let input = b"[--------] boot: starting\n";
        assert_eq!(run(input), b"[--------] boot: starting\n");
    }

    #[test]
    fn marker_with_prefix_on_same_line_emits_whole_line()
    {
        // The byte-line that contains the marker may have leading
        // garbage if firmware output ran together with the bootloader
        // line; gate emits the full line, not just from the marker on.
        let input = b"firmware garbage [--------] boot: hi\n";
        assert_eq!(run(input), b"firmware garbage [--------] boot: hi\n");
    }

    #[test]
    fn marker_split_across_writes_is_detected()
    {
        let input = b"junk\n[--------] boot: split\n";
        assert_eq!(
            run_one_byte_at_a_time(input),
            b"[--------] boot: split\n",
        );
    }

    #[test]
    fn marker_without_newline_does_not_open_gate()
    {
        // Marker present but the line never terminates: gate must not
        // open. (Caller's responsibility to ensure newlines arrive.)
        let input = b"[--------] boot: no newline yet";
        assert_eq!(run(input), b"");
    }

    #[test]
    fn missing_marker_drops_everything()
    {
        let input = b"line one\nline two\nline three\n";
        assert_eq!(run(input), b"");
    }

    #[test]
    fn empty_input_produces_empty_output()
    {
        assert_eq!(run(b""), b"");
    }

    #[test]
    fn write_returns_full_input_length_before_marker()
    {
        let mut g = LineGate::new(Vec::new(), MARKER);
        let n = g.write(b"pre-marker garbage\n").unwrap();
        assert_eq!(n, 19);
    }

    #[test]
    fn write_returns_full_input_length_after_marker()
    {
        let mut g = LineGate::new(Vec::new(), MARKER);
        g.write_all(b"[--------] boot: x\n").unwrap();
        let n = g.write(b"hello\n").unwrap();
        assert_eq!(n, 6);
    }

    #[test]
    fn bytes_after_marker_line_in_same_write_are_forwarded()
    {
        // Marker line and a subsequent line arrive in the same write.
        let input = b"[--------] boot: hi\nimmediate next line\n";
        assert_eq!(
            run(input),
            b"[--------] boot: hi\nimmediate next line\n",
        );
    }

    #[test]
    fn marker_appears_on_second_attempt_after_close_call()
    {
        // A near-miss line that contains a substring of the marker but
        // not the full marker must not open the gate.
        let input = b"[--------] boo\n[--------] boot: real\n";
        assert_eq!(run(input), b"[--------] boot: real\n");
    }

    #[test]
    fn subsequence_helper_handles_edge_cases()
    {
        assert!(contains_subsequence(b"abcdef", b"cd"));
        assert!(contains_subsequence(b"abcdef", b"abcdef"));
        assert!(!contains_subsequence(b"abcdef", b"xy"));
        assert!(!contains_subsequence(b"ab", b"abc"));
        assert!(contains_subsequence(b"abc", b""));
    }

    #[test]
    #[should_panic(expected = "LineGate marker must be non-empty")]
    fn empty_marker_panics_in_debug()
    {
        let _ = LineGate::new(Vec::new(), b"");
    }

    #[test]
    #[should_panic(expected = "plain ASCII with no ESC byte")]
    fn marker_containing_esc_panics_in_debug()
    {
        let _ = LineGate::new(Vec::new(), b"\x1b[boot");
    }
}
