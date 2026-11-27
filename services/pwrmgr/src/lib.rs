// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/lib.rs

//! Host-testable parts of pwrmgr's power-off on the death of a core service
//! (docs/supervision.md § Core Set and System Death): the allocation guard
//! the power-off runs under ([`guard`]), the reading of the core-death
//! queue's entries ([`core_death`]), and the reading of the register the
//! x86-64 power-off writes ([`power_off`]); and the steps of the wait for
//! logd's flush barrier before every power-off and reset ([`log_flush`]).
//!
//! The binary (`main.rs`) installs the guard as its global allocator and
//! drains the queue svcmgr serves it into a [`core_death::Deaths`].

#![cfg_attr(not(test), no_std)]

pub mod core_death;
pub mod guard;
pub mod log_flush;
pub mod power_off;
