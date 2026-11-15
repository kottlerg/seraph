// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/eval/sync.rs

//! Mutexes, events, the global lock, delays and `Notify`.
//!
//! The evaluator runs one thread of AML, so a mutex is never held by
//! another: `Acquire` succeeds at once unless it breaks the ordering rule
//! of ACPI 6.5 § 19.6.2, which fails with [`FaultKind::MutexOrder`]. The
//! current sync level is the highest among the mutexes held, a serialized
//! method's implicit mutex among them; `Acquire` of a mutex below it
//! fails, and `Release` must name a mutex at it. A mutex acquired again
//! nests. `\_GL_` and a field whose lock rule says so also hold the
//! firmware global lock, which the [`crate::Host`] gives. Every mutex an
//! evaluation leaves held is released when it ends.
//!
//! An event counts its signals. `Wait` on an event with none pending would
//! block forever with no other thread to signal it: a finite timeout waits
//! it out and times out, and no timeout (0xFFFF) fails with
//! [`FaultKind::Deadlock`]. Every wait, for an event or for the global
//! lock, counts against [`MAX_EVAL_DELAY_MS`].

use super::place::Place;
use super::{Evaluator, at, by, imm_int, kid};
use crate::host::HostError;
use crate::namespace::{NodeId, Object};
use crate::term::{Op, Term};
use crate::value::{Base, Data, Ref};
use crate::{Fault, FaultKind, MAX_EVAL_DELAY_MS, MAX_STALL_US};

/// A timeout that never expires.
const FOREVER: u64 = 0xFFFF;

/// What a held mutex is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind
{
    /// A `Mutex` object.
    Mutex,
    /// A serialized method's implicit mutex.
    Method,
}

/// A mutex the evaluation holds.
#[derive(Clone, Copy, Debug)]
pub(super) struct Held
{
    /// The `Mutex` object, or the serialized method whose implicit mutex
    /// this is.
    node: NodeId,
    /// The node's generation when it was acquired: an entry whose node has
    /// since been removed no longer sets the sync level.
    generation: Option<u32>,
    /// Whether this is a `Mutex` or a serialized method's implicit mutex.
    kind: Kind,
    /// The sync level.
    sync: u8,
    /// The acquisitions not yet released.
    depth: u32,
}

impl Evaluator<'_>
{
    // ── Mutexes ───────────────────────────────────────────────────────

    /// The current sync level: the highest among the mutexes held.
    fn sync_level(&self) -> u8
    {
        self.held
            .iter()
            .filter(|h| self.ns.generation(h.node) == h.generation)
            .map(|h| h.sync)
            .max()
            .unwrap_or(0)
    }

    /// The position in [`Evaluator::held`] of the entry of `node`, made
    /// for the object the node holds now: an entry left by an object since
    /// removed is not the entry of one that reuses its node.
    fn held_at(&self, node: NodeId, kind: Kind) -> Option<usize>
    {
        let generation = self.ns.generation(node);
        self.held
            .iter()
            .position(|h| h.node == node && h.kind == kind && h.generation == generation)
    }

    /// Acquire the mutex `node` of sync level `sync`, or nest it again.
    fn acquire(&mut self, node: NodeId, sync: u8, kind: Kind) -> Result<(), FaultKind>
    {
        if self.sync_level() > sync
        {
            return Err(FaultKind::MutexOrder);
        }
        if let Some(i) = self.held_at(node, kind)
            && let Some(h) = self.held.get_mut(i)
        {
            h.depth = h.depth.checked_add(1).ok_or(FaultKind::Bound)?;
            return Ok(());
        }
        let held = Held {
            node,
            generation: self.ns.generation(node),
            kind,
            sync,
            depth: 1,
        };
        crate::push(&mut self.held, held)
    }

    /// Release one acquisition of the mutex `node`; whether it is now free.
    fn release(&mut self, node: NodeId, kind: Kind) -> Result<bool, FaultKind>
    {
        let i = self.held_at(node, kind).ok_or(FaultKind::MutexOrder)?;
        let h = self.held.get_mut(i).ok_or(FaultKind::MutexOrder)?;
        h.depth = h.depth.saturating_sub(1);
        if h.depth > 0
        {
            return Ok(false);
        }
        self.held.remove(i);
        Ok(true)
    }

    /// Take the implicit mutex of the serialized method `node`, of sync
    /// level `sync`.
    pub(super) fn acquire_method(&mut self, node: NodeId, sync: u8) -> Result<(), FaultKind>
    {
        self.acquire(node, sync & 0xF, Kind::Method)
    }

    /// Release the implicit mutex of the serialized method `node` as it
    /// returns. Its own acquisition was checked, so no order check applies.
    pub(super) fn release_method(&mut self, node: NodeId)
    {
        // The entry exists: `acquire_method` made it and nothing else
        // removes a method's entry before the method returns.
        let _ = self.release(node, Kind::Method);
    }

    /// Release every mutex and the global lock, as an evaluation ends.
    pub(super) fn release_all(&mut self)
    {
        self.held.clear();
        if self.global > 0
        {
            self.global = 0;
            // The evaluation has ended; a host that fails the release has
            // nothing the evaluation could do about it.
            let _ = self.host.release_global_lock();
        }
    }

    /// Take the firmware global lock, waiting up to `timeout_ms` (0xFFFF:
    /// no limit), or nest it again; whether it is held.
    ///
    /// The wait counts against [`MAX_EVAL_DELAY_MS`]: the host is asked to
    /// wait no longer than the budget has left, and a wait that ends without
    /// the lock counts in full. One the budget cut short (no limit, or a
    /// timeout past what is left) fails with [`FaultKind::Bound`].
    pub(super) fn global_acquire(&mut self, timeout_ms: u16) -> Result<bool, FaultKind>
    {
        if self.global == 0
        {
            let left = MAX_EVAL_DELAY_MS.saturating_sub(self.budget.delay_us / 1000);
            let asked = u64::from(timeout_ms);
            let cut = asked >= FOREVER || asked > left;
            // At most 0xFFFE, the longest finite timeout.
            let wait = if cut { left } else { asked }.min(0xFFFE);
            let wait_ms = u16::try_from(wait).unwrap_or(0xFFFE);
            if !self
                .host
                .acquire_global_lock(wait_ms)
                .map_err(FaultKind::Host)?
            {
                self.budget.delay_us = self
                    .budget
                    .delay_us
                    .saturating_add(u64::from(wait_ms).saturating_mul(1000));
                return if cut
                {
                    Err(FaultKind::Bound)
                }
                else
                {
                    Ok(false)
                };
            }
        }
        self.global = self.global.checked_add(1).ok_or(FaultKind::Bound)?;
        Ok(true)
    }

    /// Release one hold of the firmware global lock.
    pub(super) fn global_release(&mut self) -> Result<(), FaultKind>
    {
        self.global = self.global.checked_sub(1).ok_or(FaultKind::MutexOrder)?;
        if self.global == 0
        {
            self.host.release_global_lock().map_err(FaultKind::Host)?;
        }
        Ok(())
    }

    /// The object node the super name `t` names: a name, or a reference to
    /// a whole named object held by a local, an argument or an expression.
    fn object_node(&mut self, t: &Term) -> Result<NodeId, Fault>
    {
        let place = self.place(t)?;
        let v = match place
        {
            Place::Node(n) => return Ok(n),
            Place::Local(i) => self
                .frame()
                .map_err(by(t))?
                .locals
                .get(i)
                .and_then(held_node),
            Place::Arg(i) => self.frame().map_err(by(t))?.args.get(i).and_then(held_node),
            Place::Ref(r) => whole_node(&r),
            Place::Discard => None,
        };
        match v
        {
            Some((node, generation)) if self.ns.generation(node) == Some(generation) =>
            {
                self.ns.follow(node).ok_or(at(t, FaultKind::NotFound))
            }
            Some(_) | None => Err(at(t, FaultKind::Type)),
        }
    }

    /// The sync level of the mutex `node`.
    fn mutex_sync(&self, t: &Term, node: NodeId) -> Result<u8, Fault>
    {
        match self.ns.object(node)
        {
            Some(Object::Mutex { sync }) => Ok(*sync),
            Some(_) | None => Err(at(t, FaultKind::Type)),
        }
    }

    // ── Operators ─────────────────────────────────────────────────────

    /// `Acquire` and `Wait`, which return whether they timed out.
    pub(super) fn sync_expr(&mut self, t: &Term) -> Result<Data, Fault>
    {
        let node = self.object_node(kid(t, 0)?)?;
        let ones = Data::Integer(self.width().mask());
        if t.op == Op::Acquire
        {
            let sync = self.mutex_sync(t, node)?;
            let timeout = u16::try_from(imm_int(kid(t, 1)?)? & 0xFFFF).unwrap_or(u16::MAX);
            if self.sync_level() > sync
            {
                return Err(at(t, FaultKind::MutexOrder));
            }
            if self.gl == Some(node)
                && self.held_at(node, Kind::Mutex).is_none()
                && !self.global_acquire(timeout).map_err(by(t))?
            {
                return Ok(ones);
            }
            self.acquire(node, sync, Kind::Mutex).map_err(by(t))?;
            return Ok(Data::Integer(0));
        }
        let timeout = self.int(kid(t, 1)?)?;
        let Some(Object::Event { pending }) = self.ns.object_mut(node)
        else
        {
            return Err(at(t, FaultKind::Type));
        };
        if *pending > 0
        {
            *pending = pending.saturating_sub(1);
            return Ok(Data::Integer(0));
        }
        if timeout >= FOREVER
        {
            return Err(at(t, FaultKind::Deadlock));
        }
        self.delay(t, timeout.saturating_mul(1000))?;
        self.host.sleep(timeout);
        Ok(ones)
    }

    /// Count `us` microseconds of delay against [`MAX_EVAL_DELAY_MS`].
    fn delay(&mut self, t: &Term, us: u64) -> Result<(), Fault>
    {
        let total = self.budget.delay_us.saturating_add(us);
        if total > MAX_EVAL_DELAY_MS.saturating_mul(1000)
        {
            return Err(at(t, FaultKind::Bound));
        }
        self.budget.delay_us = total;
        Ok(())
    }

    /// `Release`, `Reset`, `Signal`, `Sleep`, `Stall`.
    pub(super) fn sync_statement(&mut self, t: &Term) -> Result<(), Fault>
    {
        if t.op == Op::Sleep
        {
            let ms = self.int(kid(t, 0)?)?;
            self.delay(t, ms.saturating_mul(1000))?;
            self.host.sleep(ms);
            return Ok(());
        }
        if t.op == Op::Stall
        {
            let us = self.int(kid(t, 0)?)?;
            if us > MAX_STALL_US
            {
                return Err(at(t, FaultKind::Range));
            }
            self.delay(t, us)?;
            self.host.stall(us);
            return Ok(());
        }
        let node = self.object_node(kid(t, 0)?)?;
        if t.op == Op::Release
        {
            let sync = self.mutex_sync(t, node)?;
            if self.held_at(node, Kind::Mutex).is_none() || sync != self.sync_level()
            {
                return Err(at(t, FaultKind::MutexOrder));
            }
            if self.release(node, Kind::Mutex).map_err(by(t))? && self.gl == Some(node)
            {
                self.global_release().map_err(by(t))?;
            }
            return Ok(());
        }
        let Some(Object::Event { pending }) = self.ns.object_mut(node)
        else
        {
            return Err(at(t, FaultKind::Type));
        };
        *pending = if t.op == Op::Reset
        {
            0
        }
        else
        {
            pending.saturating_add(1)
        };
        Ok(())
    }

    /// `Notify` of a device, processor or thermal zone, passed to the host
    /// with the object's absolute path.
    pub(super) fn notify(&mut self, t: &Term) -> Result<(), Fault>
    {
        let node = self.object_node(kid(t, 0)?)?;
        let value = self.int(kid(t, 1)?)?;
        match self.ns.object(node)
        {
            Some(Object::Device | Object::Processor { .. } | Object::ThermalZone) =>
            {}
            Some(_) | None => return Err(at(t, FaultKind::Type)),
        }
        let path = self.ns.path(node).map_err(by(t))?;
        self.host
            .notify(&path, value)
            .map_err(|e: HostError| at(t, FaultKind::Host(e)))
    }
}

/// The node and generation of the whole named object `r` refers to.
fn whole_node(r: &Ref) -> Option<(NodeId, u32)>
{
    if !r.path.is_empty()
    {
        return None;
    }
    match r.base
    {
        Base::Node { node, generation } => Some((node, generation)),
        Base::Local { .. } | Base::Arg { .. } | Base::Value(_) => None,
    }
}

/// The node and generation of the whole named object the reference `d`
/// holds refers to.
fn held_node(d: &Data) -> Option<(NodeId, u32)>
{
    match d
    {
        Data::Ref(r) => whole_node(r),
        Data::Uninitialized
        | Data::Integer(_)
        | Data::String(_)
        | Data::Buffer(_)
        | Data::Package(_)
        | Data::Name(_) => None,
    }
}
