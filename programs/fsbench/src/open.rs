// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/fsbench/src/open.rs

//! The `open` case: the cycles `File::open` takes on a three-component path
//! the root filesystem owns, and the check that its walk makes one
//! `NS_LOOKUP` call.
//!
//! `/services/fs/fatfs` is reached through vfsd's synthetic root, which
//! forwards the whole path to the root filesystem; that walks all three
//! components in the one request (shared/namespace-protocol/README.md
//! § `NS_LOOKUP`). The open then makes its `FS_OPEN` on the file's cap.

use std::fs::File;

use bench::{Report, Unit, Value};

use crate::{Bench, WARMUP_ITERS};

/// The path the case opens: three components, every one on the root
/// filesystem.
const OPEN_PATH: &str = "/services/fs/fatfs";
/// The number of components of [`OPEN_PATH`], the `depth=` of the result line.
const OPEN_DEPTH: u64 = 3;

/// Time `run.read_iters` opens of [`OPEN_PATH`], after [`WARMUP_ITERS`] untimed
/// ones, each file closed outside its sample, and log their result line.
/// Panics when an open's walk makes other than one `NS_LOOKUP` call.
pub(crate) fn measure(run: &Bench)
{
    for _ in 0..WARMUP_ITERS
    {
        drop(open());
    }

    let mut samples = Vec::with_capacity(run.read_iters as usize);
    for _ in 0..run.read_iters
    {
        let lookups = std::os::seraph::fs::ns_lookup_calls();
        let start = run.counters.read();
        let file = open();
        let elapsed = run.counters.read().since(&start).cycles;
        let made = std::os::seraph::fs::ns_lookup_calls().wrapping_sub(lookups);
        drop(file);
        assert_eq!(
            made, 1,
            "fsbench: open of {OPEN_PATH} made {made} NS_LOOKUP calls, expected one"
        );
        samples.push(elapsed);
    }
    let summary = bench::summarize(&mut samples).expect("measure_iters returns a positive count");

    let report = Report {
        suite: "fsbench",
        name: "open",
        variant: &[("depth", Value::Num(OPEN_DEPTH))],
        cpus: run.cpus,
        unit: Unit::Cycles,
        summary,
        extras: &[],
    };
    let mut line = String::new();
    report
        .write(&mut line)
        .unwrap_or_else(|e| panic!("fsbench: result line of open: {e}"));
    std::os::seraph::log!("{line}");
}

fn open() -> File
{
    File::open(OPEN_PATH).unwrap_or_else(|e| panic!("fsbench: open {OPEN_PATH}: {e}"))
}
