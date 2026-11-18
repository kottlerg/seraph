// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/lib.rs

//! Host-testable start-up evaluation of acpid: the device initialization walk
//! ([`walk`]) and the PCI host bridges' `_OSC`, `_CRS` windows and `_PRT`
//! routes ([`bridge`]), run by the [`aml`] evaluator over any [`aml::Host`], and
//! where a served table sits in its region's mapping ([`table`]); the
//! decoding and evaluation of the power requests acpid serves ([`power`]);
//! the fixed and general-purpose events it dispatches ([`events`]); and the
//! PCI hotplug events of the firmware's `Notify` ([`hotplug`]).
//!
//! The binary (`main.rs`) gives the evaluator a host that reaches the
//! hardware through the grants devmgr makes, logs the failures this library
//! returns, and pushes its results to devmgr.

pub mod bridge;
pub mod events;
pub mod hotplug;
pub mod power;
pub mod table;
pub mod walk;

#[cfg(test)]
mod sim;

use aml::Fault;
use aml::encoding::Seg;
use aml::namespace::NodeId;

/// One evaluation that did not give a usable value: the object whose child
/// was evaluated, the child's name, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure
{
    /// The device (or other object) the evaluated name is a child of.
    pub node: NodeId,
    /// The name evaluated (`_STA`, `_INI`, `_OSC`, ...).
    pub name: Seg,
    /// Why its value could not be used.
    pub why: Why,
}

/// Why an evaluation's value could not be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why
{
    /// The evaluation faulted.
    Fault(Fault),
    /// It returned a value of a type or shape the object's definition in the
    /// ACPI specification does not allow.
    Shape,
    /// It returned more than devmgr's interface carries
    /// (`ipc::devmgr_labels::MAX_BRIDGE_WINDOWS` windows).
    Bound,
}

/// The child of `node` named `name`, followed through aliases.
fn child(ns: &aml::Namespace, node: NodeId, name: Seg) -> Option<NodeId>
{
    ns.child(node, name).and_then(|id| ns.follow(id))
}
