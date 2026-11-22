// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/stopsrc_labels.rs

//! The `stopsrc` fixture's service labels (services/stopsrc/README.md): a
//! supervised stop source of the program class, staged only with svctest,
//! that runs one job child holding memory on request and lists it as its
//! candidate, so svctest's phases drive svcmgr's list of sources and oomd's
//! program class end to end.
//!
//! The fixture serves them on the endpoint of the name its recipe provides,
//! [`NAME`], on any badge, and serves [`crate::stop_labels`] there as well on
//! a badge carrying [`crate::stop_labels::STOP_AUTHORITY`]; its labels avoid
//! the stop labels' values.

/// The name the fixture's recipe provides, badged `:deny`
/// (`rootfs/config/svcmgr/tests/stopsrc.svc`).
pub const NAME: &[u8] = b"stopsrc.ctl";
/// The name the fixture lists its job under.
pub const JOB_NAME: &[u8] = b"stopsrc-job";
/// Reply [`SUCCESS`] with data word 0 the instance's nonce, a random
/// value the process draws once at startup, data word 1 the job's state
/// ([`JOB_NONE`], [`JOB_RUNNING`] or [`JOB_STOPPED`]), and data word 2
/// the key the job is listed under, 0 with none.
pub const PROBE: u64 = 1;
/// Start a job: a child process of the fixture that touches `data[0]`
/// pages of heap and waits. Reply [`SUCCESS`] with data word 0 the job's
/// key once the fixture's subtree holds the pages, [`JOB_FAILED`] when
/// the child is not created or does not hold them within 10 s (it is
/// destroyed), and [`BUSY`] while a job runs.
pub const START_JOB: u64 = 2;
/// Reply [`SUCCESS`], then exit with status 0, which the recipe's
/// `restart = always` restarts: a new instance of the source starts. A
/// running job is left to procmgr, which destroys it with the fixture,
/// since svcmgr creates a stop source contained.
pub const EXIT: u64 = 3;
/// [`PROBE`]: no job has run in this instance.
pub const JOB_NONE: u64 = 0;
/// [`PROBE`]: the job runs, and the fixture lists it.
pub const JOB_RUNNING: u64 = 1;
/// [`PROBE`]: a `STOP_CANDIDATE` of the job's key destroyed it.
pub const JOB_STOPPED: u64 = 2;
/// The reply label of a handled request.
pub const SUCCESS: u64 = 0;
/// The reply label of a request with an unknown label.
pub const UNKNOWN_OPCODE: u64 = 1;
/// [`START_JOB`]: the job was not started.
pub const JOB_FAILED: u64 = 2;
/// [`START_JOB`]: a job runs already.
pub const BUSY: u64 = 3;
const _: () = core::assert!(
    PROBE != crate::stop_labels::STOP_CANDIDATE
        && PROBE != crate::stop_labels::LIST_CANDIDATES
        && START_JOB != crate::stop_labels::STOP_CANDIDATE
        && START_JOB != crate::stop_labels::LIST_CANDIDATES
        && EXIT != crate::stop_labels::STOP_CANDIDATE
        && EXIT != crate::stop_labels::LIST_CANDIDATES
);
