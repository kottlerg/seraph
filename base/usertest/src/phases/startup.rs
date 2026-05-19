// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Process-startup surface (procmgr/kernel `_start`).
//!
//! Covers what every process inherits at entry: argv, env, stack
//! envelope, native thread-local statics. Also hosts `env_cwd_unset`,
//! which asserts the path-string surface of `std::env::current_dir`
//! is `Unsupported` until something records it.

use std::cell::Cell;
use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

// Native TLS probe statics. `TLS_INIT` is const-initialised (lives in
// `.tdata` of the PT_TLS template) so readback of the initial value
// exercises the template-copy path in procmgr/alloc_thread_tls. `TLS_BSS`
// has no initialiser on the RHS (lives in `.tbss`) so readback exercises
// the zero-fill tail past filesz up to memsz. `TLS_COUNTER` is a Cell so
// we can exercise writes through `%fs:TPOFF`.
#[thread_local]
static TLS_INIT: u64 = 0xDEAD_BEEF_CAFE_BABE;
#[thread_local]
static TLS_BSS: u64 = 0;
#[thread_local]
static TLS_COUNTER: Cell<u32> = Cell::new(0);

/// Phases that run at the very start of the sequence.
pub fn main_startup() -> &'static [Phase]
{
    &[
        Phase {
            name: "args",
            run: args_phase,
        },
        Phase {
            name: "env",
            run: env_phase,
        },
        Phase {
            name: "stack_envelope",
            run: stack_envelope_phase,
        },
        Phase {
            name: "tls_main",
            run: tls_main_phase,
        },
    ]
}

/// Phases that must run late (after the `std::fs` surface but before
/// `fs_open_relative_phase` installs a path-string cwd).
pub fn late() -> &'static [Phase]
{
    &[Phase {
        name: "env_cwd_unset",
        run: env_cwd_unset_phase,
    }]
}

pub fn args_phase(_: &Caps)
{
    let collected: Vec<String> = std::env::args().collect();
    for (i, a) in collected.iter().enumerate()
    {
        std::os::seraph::log!("argv[{i}]={a:?}");
    }
    assert_eq!(
        collected.len(),
        2,
        "expected 2 args, got {}",
        collected.len()
    );
    assert_eq!(collected[0], "usertest", "argv[0] mismatch");
    assert_eq!(collected[1], "run", "argv[1] mismatch");
    std::os::seraph::log!("args phase passed");
}

pub fn env_phase(_: &Caps)
{
    use std::env;

    assert_eq!(
        env::var("SERAPH_TEST").unwrap_or_default(),
        "1",
        "init-seeded SERAPH_TEST missing"
    );
    assert_eq!(
        env::var("SERAPH_MODE").unwrap_or_default(),
        "boot",
        "init-seeded SERAPH_MODE missing"
    );
    assert!(
        env::var("SERAPH_NOPE").is_err(),
        "unset key must return Err"
    );
    assert_eq!(env::vars().count(), 2, "expected 2 seeded entries");

    // SAFETY: usertest is single-threaded at this point in main.
    unsafe {
        env::set_var("FOO", "bar");
        env::set_var("BAZ", "qux");
    }
    assert_eq!(env::var("FOO").unwrap_or_default(), "bar");
    assert_eq!(env::var("BAZ").unwrap_or_default(), "qux");

    // SAFETY: still single-threaded.
    unsafe {
        env::set_var("SERAPH_MODE", "test");
    }
    assert_eq!(env::var("SERAPH_MODE").unwrap_or_default(), "test");

    let all: Vec<(String, String)> = env::vars().collect();
    assert_eq!(all.len(), 4, "expected 4 entries, got {}", all.len());

    // SAFETY: single-threaded.
    unsafe {
        env::remove_var("FOO");
    }
    assert!(env::var("FOO").is_err(), "removed key must return Err");
    assert_eq!(env::vars().count(), 3, "three entries must remain");

    std::os::seraph::log!("env phase passed");
}

pub fn stack_envelope_phase(_: &Caps)
{
    let info = startup_info();
    assert_eq!(
        info.stack_pages, 8,
        "usertest declares no stack note; expected default of 8 pages, got {}",
        info.stack_pages
    );
    assert_eq!(
        info.stack_top_vaddr, 0x0000_7FFF_FFFF_E000,
        "stack_top_vaddr {:#x} does not match PROCESS_STACK_TOP",
        info.stack_top_vaddr
    );

    let sp_probe = 0u64;
    let sp = core::ptr::addr_of!(sp_probe) as u64;
    let stack_base = info.stack_top_vaddr - u64::from(info.stack_pages) * 4096;
    assert!(
        (stack_base..info.stack_top_vaddr).contains(&sp),
        "SP {sp:#x} outside reported stack range \
         [{stack_base:#x}, {top:#x})",
        top = info.stack_top_vaddr
    );

    std::os::seraph::log!(
        "stack envelope phase passed (pages={}, top={:#x})",
        info.stack_pages,
        info.stack_top_vaddr
    );
}

pub fn tls_main_phase(_: &Caps)
{
    let init = TLS_INIT;
    let bss = TLS_BSS;
    std::os::seraph::log!("TLS_INIT ={init:#018x}");
    std::os::seraph::log!("TLS_BSS  ={bss:#018x}");
    assert_eq!(init, 0xDEAD_BEEF_CAFE_BABE, "TLS_INIT tdata readback");
    assert_eq!(bss, 0, "TLS_BSS tbss readback");
    for i in 1..=4u32
    {
        TLS_COUNTER.set(i);
        assert_eq!(TLS_COUNTER.get(), i, "TLS_COUNTER set/get");
    }
    std::os::seraph::log!("TLS main-thread phase passed");
}

pub fn env_cwd_unset_phase(_: &Caps)
{
    assert_ne!(
        std::os::seraph::current_dir_cap(),
        0,
        "env_cwd_unset_phase pre-condition: init's CONFIGURE_NAMESPACE \
         must have installed a startup cwd cap",
    );
    let err = std::env::current_dir()
        .expect_err("std::env::current_dir() with no recorded path must fail");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::Unsupported,
        "std::env::current_dir() pre-set should be Unsupported, got {err:?}",
    );
    std::os::seraph::log!("env_cwd_unset phase passed");
}
