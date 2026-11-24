// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/leader/src/main.rs

//! The session leader of svctest's operator sessions: the leader sessiond's
//! svctest recipe names (`rootfs/config/svcmgr/tests/sessiond.svc`), so the
//! services layer's sessions run no program
//! (services/fixtures/leader/README.md).
//!
//! It reads `\n`-terminated lines from stdin and prints the prompt
//! [`PROMPT`] before each command. `echo <args...>` prints its arguments
//! separated by single spaces, `exit` ends it with status 0, and a command
//! holding a `/` starts the image at that path as a job, with the rest of
//! the line as its arguments: the job's stdout and stderr are copied to the
//! leader's, and each later line is forwarded to the job's stdin until the
//! job ends, after which the leader prompts again. Any other command prints
//! `leader: command not found: <cmd>` to stderr. End of input ends it.
//!
//! The stdin lock is owned by a reader thread that feeds the main loop over
//! a channel, and a waiter thread posts a job's end onto the same channel,
//! so a job that never reads its stdin does not leave the leader blocked in
//! a read when the job ends.

use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;

/// The prompt printed before each command.
const PROMPT: &[u8] = b"$ ";

/// An input line (its newline included), the end of input, or the end of
/// the running job.
enum Event
{
    Line(String),
    Eof,
    JobEnded,
}

fn main()
{
    let (tx, rx) = channel::<Event>();
    let reader_tx = tx.clone();
    thread::spawn(move || read_lines(&reader_tx));
    serve(&rx, &tx);
}

/// Send each stdin line to the main loop, then the end of input.
fn read_lines(tx: &Sender<Event>)
{
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    loop
    {
        let mut line = String::new();
        match reader.read_line(&mut line)
        {
            Ok(0) | Err(_) =>
            {
                let _ = tx.send(Event::Eof);
                return;
            }
            Ok(_) =>
            {
                if tx.send(Event::Line(line)).is_err()
                {
                    return;
                }
            }
        }
    }
}

/// Prompt, read a command, run it; return on `exit` or the end of input.
fn serve(rx: &Receiver<Event>, tx: &Sender<Event>)
{
    let mut out = std::io::stdout();
    loop
    {
        if out.write_all(PROMPT).is_err() || out.flush().is_err()
        {
            return;
        }
        let line = match rx.recv()
        {
            Ok(Event::Line(line)) => line,
            Ok(Event::Eof | Event::JobEnded) | Err(_) => return,
        };
        let mut words = line.split_whitespace();
        let Some(command) = words.next()
        else
        {
            continue;
        };
        let args: Vec<&str> = words.collect();
        match command
        {
            "exit" => return,
            "echo" =>
            {
                let _ = writeln!(out, "{}", args.join(" "));
                let _ = out.flush();
            }
            path if path.contains('/') =>
            {
                if run_job(path, &args, rx, tx)
                {
                    return;
                }
            }
            other => eprint_line(&format!("leader: command not found: {other}")),
        }
    }
}

/// Write `msg` and a newline to stderr; a failed write is dropped.
fn eprint_line(msg: &str)
{
    let mut err = std::io::stderr();
    let _ = err.write_all(msg.as_bytes());
    let _ = err.write_all(b"\n");
    let _ = err.flush();
}

/// Start the image at `path` as a job, copy its output to the leader's, and
/// forward each later line to its stdin until it ends. Returns `true` when
/// the input ended while the job ran.
fn run_job(path: &str, args: &[&str], rx: &Receiver<Event>, tx: &Sender<Event>) -> bool
{
    let mut child = match Command::new(path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) =>
        {
            eprint_line(&format!("leader: {path}: {e}"));
            return false;
        }
    };
    let mut stdin = child.stdin.take();
    let out_pump = child
        .stdout
        .take()
        .map(|src| thread::spawn(move || pump(src, std::io::stdout())));
    let err_pump = child
        .stderr
        .take()
        .map(|src| thread::spawn(move || pump(src, std::io::stderr())));
    let waiter_tx = tx.clone();
    let waiter = thread::spawn(move || {
        let _ = child.wait();
        let _ = waiter_tx.send(Event::JobEnded);
    });

    let mut eof = false;
    loop
    {
        match rx.recv()
        {
            Ok(Event::Line(line)) =>
            {
                let broken = stdin.as_mut().is_some_and(|sink| {
                    sink.write_all(line.as_bytes()).is_err() || sink.flush().is_err()
                });
                if broken
                {
                    drop(stdin.take());
                }
            }
            Ok(Event::Eof) =>
            {
                eof = true;
                drop(stdin.take());
            }
            Ok(Event::JobEnded) | Err(_) => break,
        }
    }
    drop(stdin.take());
    let _ = waiter.join();
    for pump in [out_pump, err_pump].into_iter().flatten()
    {
        let _ = pump.join();
    }
    eof
}

/// Copy `from` to `to` until the end or an error, flushing each chunk.
fn pump<R: Read, W: Write>(mut from: R, mut to: W)
{
    let mut buf = [0u8; 512];
    loop
    {
        match from.read(&mut buf)
        {
            Ok(0) | Err(_) => return,
            Ok(n) =>
            {
                let Some(chunk) = buf.get(..n)
                else
                {
                    return;
                };
                if to.write_all(chunk).is_err() || to.flush().is_err()
                {
                    return;
                }
            }
        }
    }
}
