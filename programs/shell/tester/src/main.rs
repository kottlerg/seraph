// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/shell/tester/src/main.rs

//! Per-program tester for `/programs/shell` (#112). Drives the shell over piped
//! stdin/stdout and asserts its built-ins, an external spawn, and stdin
//! forwarding to a child. See [docs/testing.md](../../../../docs/testing.md).
//!
//! Two invocations are used because the shell forwards subsequent input lines
//! to a running external child: any command after an external one would be
//! consumed by that child's stdin. Each invocation therefore puts its external
//! command last, before EOF — (A) the built-ins plus `/programs/hello`, and
//! (B) `/tests/fixtures/programs/stdiotest`, a command given as a path, fed one
//! line to prove stdin forwarding. (C) runs no program: a missing path, a
//! missing bare name and a file that is no program each fail with an error
//! line, and the shell reads on.
//!
//! There is no terminal here, so nothing echoes the typed commands; the shell's
//! own `$ ` prompt and command output are the only bytes on its stdout. The
//! prompt is written without a trailing newline, so it prefixes the next output
//! line — [`strip_prompts`] removes it for exact-line checks.

#![expect(
    clippy::expect_used,
    reason = "a per-program tester is test code, where unwrap and expect are permitted \
              (docs/coding-standards.md § Error Handling): a failed spawn, read, or wait must \
              abort the tester, and the panic's non-zero exit is its FAIL verdict"
)]

use std::io::{Read, Write};
use std::process::{Command, Stdio};

/// Drive a fresh `/programs/shell` with `script` on stdin (closed afterwards,
/// so the shell exits on EOF). Returns its captured stdout and stderr and its
/// clean-exit flag.
fn run_shell(script: &str) -> (String, String, bool)
{
    let mut child = Command::new("/programs/shell")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn /programs/shell");

    // Drained on its own thread, so a full stderr pipe cannot stall the
    // shell while stdout is read.
    let mut stderr = child.stderr.take().expect("piped stderr");
    let errors = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).expect("read shell stderr");
        String::from_utf8_lossy(&bytes).into_owned()
    });

    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(script.as_bytes()).expect("write script");
    } // drop stdin → EOF → shell exits

    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut bytes = Vec::new();
    stdout.read_to_end(&mut bytes).expect("read shell stdout");
    let status = child.wait().expect("wait /programs/shell");
    let errors = errors.join().expect("join the stderr reader");

    (
        String::from_utf8_lossy(&bytes).into_owned(),
        errors,
        status.success(),
    )
}

/// Strip leading `$ ` prompts (the prompt has no trailing newline, so it
/// prefixes the next output line) and surrounding whitespace.
fn strip_prompts(line: &str) -> &str
{
    let mut s = line.trim_start();
    while let Some(rest) = s.strip_prefix("$ ")
    {
        s = rest.trim_start();
    }
    s.trim_end()
}

fn fail(msg: &str, out: &str) -> !
{
    println!("[shell-tester] FAIL {msg}");
    println!("[shell-tester] captured stdout: {out:?}");
    std::process::exit(1);
}

fn main()
{
    // Invocation A: built-ins exercising absolute and relative paths (incl.
    // `..` and no-arg `ls`), then one external command (hello) last.
    let script_a = "echo hello-shell\n\
                    pwd\n\
                    ls /\n\
                    cd programs\n\
                    pwd\n\
                    cd ..\n\
                    ls programs\n\
                    cd /data\n\
                    ls\n\
                    cat test.txt\n\
                    hello\n";
    let (out_a, _, ok_a) = run_shell(script_a);

    if !out_a.contains("$ ")
    {
        fail("prompt ($ ) missing", &out_a);
    }
    if !out_a.lines().any(|l| strip_prompts(l) == "hello-shell")
    {
        fail("echo output missing", &out_a);
    }
    // Initial `pwd` is `/`. Exercises the ruststd root-walk fix (a path with no
    // components resolving to the anchor directory).
    if !out_a.lines().any(|l| strip_prompts(l) == "/")
    {
        fail("initial pwd is not the root `/`", &out_a);
    }
    // `ls /` exercises vfsd's root-readdir fall-through: root-fs entries
    // (`programs`, `data`) enumerate alongside the synthetic `esp` mount.
    if !out_a.lines().any(|l| strip_prompts(l) == "programs")
    {
        fail(
            "ls / did not list `programs` (root readdir fall-through)",
            &out_a,
        );
    }
    if !out_a.lines().any(|l| strip_prompts(l) == "data")
    {
        fail(
            "ls / did not list `data` (root readdir fall-through)",
            &out_a,
        );
    }
    // Relative `cd programs` (from `/`) then `pwd` proves cwd-relative cd.
    if !out_a.lines().any(|l| strip_prompts(l) == "/programs")
    {
        fail("pwd after relative `cd programs` missing", &out_a);
    }
    // After `cd ..`, `ls programs` (relative arg, from `/`) must list the
    // /programs entries — proves `..` returned to `/` and relative `ls`.
    if !out_a.lines().any(|l| strip_prompts(l) == "shell")
    {
        fail(
            "relative `ls programs` after `cd ..` did not list `shell`",
            &out_a,
        );
    }
    if !out_a.lines().any(|l| strip_prompts(l) == "hello")
    {
        fail(
            "relative `ls programs` after `cd ..` did not list `hello`",
            &out_a,
        );
    }
    // No-arg `ls` after `cd /data` lists the cwd — the case that previously
    // failed (round-tripping a relative cwd string through read_dir).
    if !out_a.lines().any(|l| strip_prompts(l) == "test.txt")
    {
        fail(
            "no-arg `ls` after `cd /data` did not list `test.txt`",
            &out_a,
        );
    }
    // Relative `cat test.txt` from `/data`.
    if !out_a.lines().any(|l| strip_prompts(l) == "srv-test-marker")
    {
        fail("relative `cat test.txt` content missing", &out_a);
    }
    if !out_a.contains("hello from seraph userspace")
    {
        fail("external /programs/hello output missing", &out_a);
    }
    if !ok_a
    {
        fail("shell (invocation A) exited non-zero", &out_a);
    }

    // Invocation B: an external child that reads stdin, last, to prove the
    // shell forwards stdin to it, named by its path, which proves a command
    // given as a path runs. stdiotest uppercases the line it reads.
    let script_b = "/tests/fixtures/programs/stdiotest\nhello-stdio\n";
    let (out_b, _, ok_b) = run_shell(script_b);

    if !out_b.contains("shouted: HELLO-STDIO")
    {
        fail(
            "stdin not forwarded to child (uppercased echo missing)",
            &out_b,
        );
    }
    if !out_b.contains("PASS")
    {
        fail("stdiotest PASS marker missing", &out_b);
    }
    if !ok_b
    {
        fail("shell (invocation B) exited non-zero", &out_b);
    }

    commands_that_name_no_program();

    println!("[shell-tester] PASS");
}

/// Invocation C: a command given as a path that names no file fails as a
/// bare name naming no program does, with `command not found`; one that
/// names a file that is no program fails with an error line naming it. After
/// each the shell reads its next command, which the `echo` lines prove.
fn commands_that_name_no_program()
{
    let script_c = "/tests/fixtures/programs/absent\n\
                    echo after-missing-path\n\
                    absent\n\
                    echo after-missing-name\n\
                    /data/test.txt\n\
                    echo after-not-a-program\n";
    let (out_c, err_c, ok_c) = run_shell(script_c);
    let both = format!("stdout {out_c:?} stderr {err_c:?}");

    for line in [
        "after-missing-path",
        "after-missing-name",
        "after-not-a-program",
    ]
    {
        if !out_c.lines().any(|l| strip_prompts(l) == line)
        {
            fail(
                &format!("the shell did not read on to `echo {line}`"),
                &both,
            );
        }
    }
    for line in [
        "shell: command not found: absent",
        "shell: command not found: /tests/fixtures/programs/absent",
    ]
    {
        if !err_c.lines().any(|l| l.trim_end() == line)
        {
            fail(&format!("error line {line:?} missing"), &both);
        }
    }
    if !err_c
        .lines()
        .any(|l| l.starts_with("shell: ") && l.contains("/data/test.txt"))
    {
        fail("no error line for a file that is no program", &both);
    }
    if !ok_c
    {
        fail("shell (invocation C) exited non-zero", &both);
    }
}
