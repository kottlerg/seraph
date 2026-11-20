// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/lib.rs

//! Host-testable parts of pwrmgr's power-off on the death of a core service
//! (docs/supervision.md § Core Set and System Death): the allocation guard
//! the power-off runs under ([`guard`]), and the reading of the core-death
//! queue's entries ([`core_death`]).
//!
//! The binary (`main.rs`) installs the guard as its global allocator and
//! drains the queue svcmgr serves it with [`core_death::first`].

#![cfg_attr(not(test), no_std)]

pub mod core_death;
pub mod guard;
