// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/cap_batches.rs

//! Interrupts taken between the derivation-lock batches of the capability
//! syscalls whose length the caller chooses.
//!
//! A revoke, a delete's reparent, a move, a range split and a dying
//! `CSpace`'s drain each edit a child list the caller built, one bounded
//! batch per hold of the derivation lock, and the kernel takes interrupts
//! between the batches (core/kernel/docs/capability-internals.md § Global
//! Derivation Lock). Each case gives one capability [`CHILDREN`] children,
//! 64 batches' worth, and makes the call on the `crate::latency` rig: a
//! TLB shootdown of the calling CPU, issued from another CPU while the call
//! runs, is acknowledged before the call returns and within the rig's bound.
//! No object reaches a reference count of zero in the measured call apart
//! from the drain case's `CSpace`, so the call opens no other window
//! (the drain case's late one, the dead `CSpace`'s pool return, is
//! answered by [`Measured::judged_by_first_half`]).

use syscall::{
    cap_copy, cap_create_cspace, cap_create_notification, cap_delete, cap_derive, cap_info,
    cap_move,
};
use syscall_abi::{CAP_INFO_CSPACE_USED, RIGHTS_ALL};

use crate::latency::{self, Call, Measured};
use crate::{TestContext, TestResult};

/// Children each case gives the capability its call edits: 64 batches of the
/// kernel's `MAX_REVOKE_EDITS`, `MAX_REPARENT_EDITS` and `MAX_DRAIN_EDITS`
/// (256 each).
const CHILDREN: u32 = 16_384;
/// The level the split case splits its band at: the lower child takes the
/// levels below it, the upper the rest.
const SPLIT_AT: u8 = 21;
/// Pages of the drain case's dying `CSpace`: one slot page and its pool's
/// spare.
const DYING_PAGES: u64 = 2;

/// A `CSpace` that holds `CHILDREN` copies of one capability, each a child
/// of it; deleted on drop.
struct Children
{
    cspace: u64,
    /// The slots the `CSpace` held before the copies.
    empty: u64,
}

impl Children
{
    /// Copy `parent` `CHILDREN` times into a fresh `CSpace`, whose pool holds
    /// the slot pages that cover them and a spare page.
    fn of(ctx: &TestContext, parent: u64) -> Result<Self, &'static str>
    {
        let pages = crate::cspace_geometry::pages_to_cover(u64::from(CHILDREN)).saturating_add(1);
        let mut children = Self {
            cspace: cap_create_cspace(ctx.memory_base, 0, pages)
                .map_err(|_| "cap_batches: create the children's CSpace failed")?,
            empty: 0,
        };
        children.empty = children.used()?;
        for copied in 0..CHILDREN
        {
            if let Err(e) = cap_copy(parent, children.cspace, RIGHTS_ALL)
            {
                crate::log_u64("ktest: cap_batches copies_made=", u64::from(copied));
                crate::log_u64("ktest: cap_batches copy_error=", e.unsigned_abs());
                return Err("cap_batches: copy a child failed");
            }
        }
        Ok(children)
    }

    /// The slots the children's `CSpace` holds.
    fn used(&self) -> Result<u64, &'static str>
    {
        cap_info(self.cspace, CAP_INFO_CSPACE_USED)
            .map_err(|_| "cap_batches: cap_info(CSPACE_USED) failed")
    }

    /// Whether every child is gone from the `CSpace`.
    fn all_gone(&self) -> Result<bool, &'static str>
    {
        Ok(self.used()? == self.empty)
    }
}

impl Drop for Children
{
    fn drop(&mut self)
    {
        cap_delete(self.cspace).ok();
    }
}

/// A capability of ktest's own `CSpace`, deleted on drop unless taken.
struct Owned(u64);

impl Owned
{
    /// Give the capability up to a call that consumed it.
    fn take(&mut self)
    {
        self.0 = 0;
    }
}

impl Drop for Owned
{
    fn drop(&mut self)
    {
        if self.0 != 0
        {
            cap_delete(self.0).ok();
        }
    }
}

/// A fresh notification in ktest's own `CSpace`.
fn notification(ctx: &TestContext) -> Result<Owned, &'static str>
{
    cap_create_notification(ctx.memory_base)
        .map(Owned)
        .map_err(|_| "cap_batches: cap_create_notification failed")
}

/// Measure `call`, failing when the worker's call itself failed.
fn measure_ok(ctx: &TestContext, call: Call, what: &'static str) -> Result<Measured, &'static str>
{
    let m = latency::measure_call(ctx, call)?;
    if m.result == u64::MAX
    {
        return Err(what);
    }
    Ok(m)
}

/// Run `once` on a fresh fixture per call until the rig's attempts end,
/// then check the measure, logged as `line`.
fn run(line: &'static str, once: impl FnMut() -> Result<Measured, &'static str>) -> TestResult
{
    if !latency::cpus_present()
    {
        return Ok(());
    }
    let m = latency::attempt_until_acked(once)?;
    latency::check_measured(line, &m)
}

/// `SYS_CAP_REVOKE` of a notification with `CHILDREN` children deletes them
/// all, taking interrupts between its batches.
pub fn revoke_takes_interrupts(ctx: &TestContext) -> TestResult
{
    run("ktest: cap_batches call=cap_revoke", || {
        let root = notification(ctx)?;
        let children = Children::of(ctx, root.0)?;
        let m = measure_ok(
            ctx,
            Call::Revoke(root.0),
            "cap_batches::revoke: the worker's revoke failed",
        )?;
        if !children.all_gone()?
        {
            return Err("cap_batches::revoke: a child outlived the revoke");
        }
        Ok(m)
    })
}

/// `SYS_CAP_DELETE` of a copy with `CHILDREN` children re-links them under
/// the copy's parent, taking interrupts between its batches.
pub fn delete_reparent_takes_interrupts(ctx: &TestContext) -> TestResult
{
    run("ktest: cap_batches call=cap_delete_reparent", || {
        let root = notification(ctx)?;
        let mut copy = Owned(
            cap_copy(root.0, ctx.cspace_cap, RIGHTS_ALL)
                .map_err(|_| "cap_batches::delete: copy the root failed")?,
        );
        let children = Children::of(ctx, copy.0)?;
        let m = latency::measure_call(ctx, Call::Delete(copy.0));
        if latency::worker_results().map(|r| r.0) == Some(0)
        {
            copy.take();
        }
        let m = m?;
        if m.result == u64::MAX
        {
            return Err("cap_batches::delete: the worker's delete failed");
        }
        // The children now hang under the root: its revoke reaches them all.
        syscall::cap_revoke(root.0).map_err(|_| "cap_batches::delete: revoke the root failed")?;
        if !children.all_gone()?
        {
            return Err("cap_batches::delete: a child was not re-linked under the root");
        }
        Ok(m)
    })
}

/// `SYS_CAP_MOVE` of a notification with `CHILDREN` children rewrites each
/// child's parent link, taking interrupts between its batches.
pub fn move_takes_interrupts(ctx: &TestContext) -> TestResult
{
    run("ktest: cap_batches call=cap_move", || {
        let mut source = notification(ctx)?;
        let children = Children::of(ctx, source.0)?;
        let m = latency::measure_call(
            ctx,
            Call::Move {
                cap: source.0,
                cspace: ctx.cspace_cap,
            },
        );
        let moved = latency::worker_results()
            .map(|r| r.0)
            .filter(|&r| r != u64::MAX)
            .map(|handle| {
                source.take();
                Owned(handle)
            });
        let m = m?;
        let moved = moved.ok_or("cap_batches::move: the worker's move failed")?;
        // The children follow the moved capability: its revoke reaches them.
        syscall::cap_revoke(moved.0)
            .map_err(|_| "cap_batches::move: revoke the moved cap failed")?;
        if !children.all_gone()?
        {
            return Err("cap_batches::move: a child did not follow the move");
        }
        Ok(m)
    })
}

/// `SYS_SCHED_SPLIT` of a band with `CHILDREN` children re-links them under
/// the band's parent, taking interrupts between its batches.
pub fn sched_split_takes_interrupts(ctx: &TestContext) -> TestResult
{
    run("ktest: cap_batches call=sched_split", || {
        // The band's parent, of ktest's own, so that its revoke below reaches
        // no capability of ktest's other cases.
        let parent = Owned(
            cap_derive(ctx.sched_control_cap, RIGHTS_ALL)
                .map_err(|_| "cap_batches::sched_split: cap_derive(sched_control) failed")?,
        );
        let mut band = Owned(
            cap_derive(parent.0, RIGHTS_ALL)
                .map_err(|_| "cap_batches::sched_split: cap_derive(parent) failed")?,
        );
        let children = Children::of(ctx, band.0)?;
        let m = latency::measure_call(
            ctx,
            Call::SchedSplit {
                cap: band.0,
                at: SPLIT_AT,
            },
        );
        let halves = latency::worker_results()
            .filter(|r| r.0 != u64::MAX)
            .map(|(lower, upper)| {
                band.take();
                (Owned(lower), Owned(upper))
            });
        let m = m?;
        let _halves = halves.ok_or("cap_batches::sched_split: the worker's split failed")?;
        // The band's children now hang under its parent.
        syscall::cap_revoke(parent.0)
            .map_err(|_| "cap_batches::sched_split: revoke the band's parent failed")?;
        if !children.all_gone()?
        {
            return Err("cap_batches::sched_split: a child was not re-linked under the split");
        }
        Ok(m)
    })
}

/// `SYS_CAP_DELETE` of the last capability to a small `CSpace` holding one
/// copy with `CHILDREN` children drains it, re-linking the children under
/// the copy's parent and taking interrupts between the drain's batches.
pub fn cspace_drain_takes_interrupts(ctx: &TestContext) -> TestResult
{
    run("ktest: cap_batches call=cspace_drain", || {
        let root = notification(ctx)?;
        let mut copy = Owned(
            cap_copy(root.0, ctx.cspace_cap, RIGHTS_ALL)
                .map_err(|_| "cap_batches::drain: copy the root failed")?,
        );
        let children = Children::of(ctx, copy.0)?;
        let mut dying = Owned(
            cap_create_cspace(ctx.memory_base, 0, DYING_PAGES)
                .map_err(|_| "cap_batches::drain: create the dying CSpace failed")?,
        );
        // The copy and its children move into the dying CSpace together.
        cap_move(copy.0, dying.0, 0).map_err(|_| "cap_batches::drain: move the copy failed")?;
        copy.take();
        let m = latency::measure_call(ctx, Call::Delete(dying.0));
        if latency::worker_results().map(|r| r.0) == Some(0)
        {
            dying.take();
        }
        let m = m?;
        if m.result == u64::MAX
        {
            return Err("cap_batches::drain: the worker's delete failed");
        }
        syscall::cap_revoke(root.0).map_err(|_| "cap_batches::drain: revoke the root failed")?;
        if !children.all_gone()?
        {
            return Err("cap_batches::drain: a child was not re-linked under the root");
        }
        Ok(m.judged_by_first_half())
    })
}
