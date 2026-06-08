// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/shell/src/main.rs

//! Minimal interactive shell (#112). The child of `programs/terminal`.
//!
//! Reads `\n`-terminated lines from stdin, runs a small set of built-ins
//! (`help`, `exit`, `echo`, `pwd`, `cd`, `ls`, `cat`), and otherwise spawns
//! `/programs/<name>` as an external command. Pure `std`: no Seraph cap
//! awareness — stdin/stdout/stderr are the terminal's stdio pipes, and
//! children are spawned through `std::process::Command`. The terminal renders
//! no prompt; the shell owns the `$ ` prompt.
//!
//! I/O structure. A dedicated reader thread owns the process stdin lock and
//! feeds lines to the main loop over an `mpsc` channel; the main loop never
//! reads stdin directly. When an external child runs, a per-child waiter
//! thread posts the child's exit onto the same channel and two pump threads
//! relay the child's stdout/stderr to the shell's own stdout/stderr. The main
//! loop then forwards subsequent input lines to the child's stdin until it
//! exits. The reader/waiter split is what lets the shell forward stdin without
//! wedging: a blocked stdin read cannot be cancelled, so a child that never
//! reads stdin (e.g. `/programs/hello`) would otherwise hang the shell until
//! the next input line. This is the interim stand-in for a shared-tty /
//! foreground-process-group model; real job control is #29.
//!
//! Paths are resolved lexically against an absolute working directory the shell
//! owns (`resolve_path`): absolute and cwd-relative inputs both work, including
//! `.`/`..`, and `cd` keeps the process cwd cap in lockstep. Limitations
//! (v0.0.1): no pipes/redirection, quoting/escaping, variable expansion,
//! globbing, or job control.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;

use shell_path::resolve_path;

/// The prompt. The terminal renders none, so the shell prints its own.
const PROMPT: &[u8] = b"$ ";

/// Directory holding spawnable external programs — Seraph's `/bin`.
const PROGRAMS_DIR: &str = "/programs";

/// An input line (newline included), end-of-input, or an external child's
/// exit, delivered to the main loop from the reader / per-child waiter threads.
enum Event
{
    Line(String),
    Eof,
    ChildExited,
}

fn main()
{
    std::os::seraph::log::register_name(b"shell");

    // The shell tracks its own absolute cwd string (see `repl`) and resolves
    // every path to absolute before calling `std`. Seed the process cwd cap at
    // the namespace root so external children inherit it.
    if let Err(e) = std::env::set_current_dir("/")
    {
        std::os::seraph::log!("shell: set_current_dir(\"/\") failed: {e}");
    }

    let (tx, rx) = channel::<Event>();
    let reader_tx = tx.clone();
    thread::spawn(move || stdin_reader(&reader_tx));

    repl(&rx, &tx);
}

/// Own the process stdin lock and forward each line (newline included) to the
/// main loop, then signal end-of-input. Never reads on behalf of a child
/// directly — the main loop decides whether a line is a command or child input.
fn stdin_reader(tx: &Sender<Event>)
{
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
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

/// Prompt, read a command, dispatch. Returns when stdin closes or on `exit`.
fn repl(rx: &Receiver<Event>, tx: &Sender<Event>)
{
    let mut out = std::io::stdout();
    // Authoritative absolute working directory. Built-ins resolve relative
    // inputs against it; `cd` keeps the process cwd cap in lockstep.
    let mut cwd = String::from("/");
    loop
    {
        if out.write_all(PROMPT).is_err() || out.flush().is_err()
        {
            return;
        }
        let raw = match rx.recv()
        {
            Ok(Event::Line(line)) => line,
            Ok(Event::Eof | Event::ChildExited) | Err(_) => return,
        };
        let trimmed = raw.trim();
        if trimmed.is_empty()
        {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(cmd) = parts.next()
        else
        {
            continue;
        };
        let args: Vec<&str> = parts.collect();

        match cmd
        {
            "exit" => return,
            "help" => help(&mut out),
            "echo" => echo(&mut out, &args),
            "pwd" => pwd(&mut out, &cwd),
            "cd" => cd(&mut cwd, &args),
            "ls" => ls(&mut out, &cwd, &args),
            "cat" => cat(&mut out, &cwd, &args),
            _ =>
            {
                if run_external(cmd, &args, rx, tx)
                {
                    return; // stdin reached EOF while the child ran
                }
            }
        }
    }
}

/// Write an error line to stderr. Write failures are unrecoverable here and
/// dropped — the REPL continues regardless of a command's outcome.
fn eprint_line(msg: &str)
{
    let mut err = std::io::stderr();
    let _ = err.write_all(msg.as_bytes());
    let _ = err.write_all(b"\n");
    let _ = err.flush();
}

/// `help` — list the built-ins. The first line is a stable marker the terminal
/// interactive test (`xtask/src/commands/test_terminal.rs`) asserts on.
fn help(out: &mut std::io::Stdout)
{
    let text = "shell built-ins:\n\
                help            show this help\n\
                exit            exit the shell\n\
                echo <args...>  print arguments\n\
                pwd             print the working directory\n\
                cd <path>       change directory\n\
                ls [path]       list a directory\n\
                cat <path>      print a file\n\
                <name> [args]   run /programs/<name>\n";
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
}

/// `echo` — print the arguments separated by single spaces.
fn echo(out: &mut std::io::Stdout, args: &[&str])
{
    let _ = writeln!(out, "{}", args.join(" "));
    let _ = out.flush();
}

/// `pwd` — print the working directory.
fn pwd(out: &mut std::io::Stdout, cwd: &str)
{
    let _ = writeln!(out, "{cwd}");
    let _ = out.flush();
}

/// `cd <path>` — change directory. Resolves `path` against `cwd` to an absolute
/// path, validates it via `set_current_dir` (which also updates the process cwd
/// cap that children inherit), and on success records it as the new `cwd`.
fn cd(cwd: &mut String, args: &[&str])
{
    if args.len() != 1
    {
        eprint_line("cd: usage: cd <path>");
        return;
    }
    let Some(&arg) = args.first()
    else
    {
        return;
    };
    let target = resolve_path(cwd, arg);
    match std::env::set_current_dir(&target)
    {
        Ok(()) => *cwd = target,
        Err(e) => eprint_line(&format!("cd: {arg}: {e}")),
    }
}

/// `ls [path]` — list a directory; with no argument, the working directory.
fn ls(out: &mut std::io::Stdout, cwd: &str, args: &[&str])
{
    let dir = if args.is_empty()
    {
        cwd.to_string()
    }
    else if args.len() == 1
    {
        match args.first()
        {
            Some(&path) => resolve_path(cwd, path),
            None => return,
        }
    }
    else
    {
        eprint_line("ls: usage: ls [path]");
        return;
    };

    match std::fs::read_dir(&dir)
    {
        Ok(entries) =>
        {
            for entry in entries
            {
                match entry
                {
                    Ok(ent) =>
                    {
                        let _ = writeln!(out, "{}", ent.file_name().to_string_lossy());
                    }
                    Err(e) => eprint_line(&format!("ls: {e}")),
                }
            }
            let _ = out.flush();
        }
        Err(e) => eprint_line(&format!("ls: {dir}: {e}")),
    }
}

/// `cat <path>` — print a file's bytes. Byte-oriented so non-UTF-8 files do
/// not error.
fn cat(out: &mut std::io::Stdout, cwd: &str, args: &[&str])
{
    if args.len() != 1
    {
        eprint_line("cat: usage: cat <path>");
        return;
    }
    let Some(&arg) = args.first()
    else
    {
        return;
    };
    let path = resolve_path(cwd, arg);
    match std::fs::read(&path)
    {
        Ok(bytes) =>
        {
            let _ = out.write_all(&bytes);
            let _ = out.flush();
        }
        Err(e) => eprint_line(&format!("cat: {arg}: {e}")),
    }
}

/// Spawn `/programs/<cmd>`, relay its stdout/stderr to the shell's, and
/// forward subsequent input lines to its stdin until it exits. Returns `true`
/// if stdin reached EOF while the child ran (the caller ends the session).
fn run_external(cmd: &str, args: &[&str], rx: &Receiver<Event>, tx: &Sender<Event>) -> bool
{
    if cmd.contains('/')
    {
        eprint_line(&format!(
            "shell: {cmd}: only bare /programs names are runnable"
        ));
        return false;
    }
    let path = format!("{PROGRAMS_DIR}/{cmd}");
    let mut child = match Command::new(&path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) =>
        {
            if e.kind() == std::io::ErrorKind::NotFound
            {
                eprint_line(&format!("shell: command not found: {cmd}"));
            }
            else
            {
                eprint_line(&format!("shell: {cmd}: {e}"));
            }
            return false;
        }
    };

    let mut child_stdin = child.stdin.take();
    let out_pump = child
        .stdout
        .take()
        .map(|src| thread::spawn(move || pump(src, std::io::stdout())));
    let err_pump = child
        .stderr
        .take()
        .map(|src| thread::spawn(move || pump(src, std::io::stderr())));

    // Reap the child on its own thread and post the exit edge onto the shared
    // channel, so the main loop can wake on either an input line or the exit.
    let waiter_tx = tx.clone();
    let waiter = thread::spawn(move || {
        let _ = child.wait();
        let _ = waiter_tx.send(Event::ChildExited);
    });

    let mut eof = false;
    loop
    {
        match rx.recv()
        {
            Ok(Event::Line(line)) =>
            {
                let mut broken = false;
                if let Some(sink) = child_stdin.as_mut()
                {
                    broken = sink.write_all(line.as_bytes()).is_err() || sink.flush().is_err();
                }
                if broken
                {
                    drop(child_stdin.take()); // child closed its stdin
                }
            }
            Ok(Event::Eof) =>
            {
                eof = true;
                drop(child_stdin.take()); // deliver EOF to the child
            }
            Ok(Event::ChildExited) | Err(_) => break,
        }
    }

    drop(child_stdin.take());
    let _ = waiter.join();
    if let Some(handle) = out_pump
    {
        let _ = handle.join();
    }
    if let Some(handle) = err_pump
    {
        let _ = handle.join();
    }
    eof
}

/// Copy `from` to `to` until EOF or error, flushing each chunk so output
/// reaches the display promptly.
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
                let chunk = &buf[..n];
                if to.write_all(chunk).is_err() || to.flush().is_err()
                {
                    return;
                }
            }
        }
    }
}
