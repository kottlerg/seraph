// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/walk.rs

//! The device initialization walk of ACPI 6.5 § 6.5.1: `\_SB._INI`
//! first, then, depth-first from the root, each device's `_STA` and, when it
//! reports the device present, its `_INI`.
//!
//! A device absent but functioning has its children walked and no `_INI`
//! run; a device absent and not functioning is skipped with its children. A
//! device whose `_STA` faults, or returns no integer, is treated as absent
//! and not functioning, and the failure is returned. A faulting `_INI` is
//! returned too, and the walk goes on.

use aml::namespace::{NodeId, Object};
use aml::{Data, Evaluator};

use crate::{Failure, Why, child};

/// `_STA` bit 0: the device is present.
const STA_PRESENT: u64 = 1;
/// `_STA` bit 3: the device is functioning properly.
const STA_FUNCTIONING: u64 = 1 << 3;
/// The status of a device with no `_STA`: present, enabled, shown in the
/// user interface, and functioning (ACPI 6.5 § 6.3.7).
const STA_DEFAULT: u64 = 0x0F;

/// What the walk found and ran.
#[derive(Debug, Default)]
pub struct Walk
{
    /// The devices whose status reports them present, in walk order (a
    /// parent before its children).
    pub present: Vec<NodeId>,
    /// The `_INI` methods that ran without a fault.
    pub initialized: usize,
    /// The `_STA` and `_INI` evaluations that failed.
    pub failures: Vec<Failure>,
}

/// Run the initialization walk over the namespace of `ev`.
pub fn initialize(ev: &mut Evaluator<'_>) -> Walk
{
    let mut walk = Walk::default();
    let sb = ev.namespace().find("\\_SB");
    // The root's children, `\_SB` last so that it is visited first. The
    // namespace lists a node's children most recently added first, so the
    // stack pops them in the order the tables define them.
    let mut stack: Vec<NodeId> = ev
        .namespace()
        .children(NodeId::ROOT)
        .filter(|&n| Some(n) != sb)
        .collect();
    stack.extend(sb);
    while let Some(node) = stack.pop()
    {
        let descend = match ev.namespace().object(node)
        {
            Some(Object::Device | Object::Processor { .. } | Object::ThermalZone) =>
            {
                device(ev, node, &mut walk)
            }
            _ => true,
        };
        if descend
        {
            stack.extend(ev.namespace().children(node));
        }
    }
    walk
}

/// Evaluate the status of `device`, run its `_INI` when it is present, and
/// return whether its children are walked.
fn device(ev: &mut Evaluator<'_>, device: NodeId, walk: &mut Walk) -> bool
{
    let sta = match child(ev.namespace(), device, *b"_STA")
    {
        None => STA_DEFAULT,
        Some(id) => match ev.evaluate(id, Vec::new())
        {
            Ok(Data::Integer(v)) => v,
            Ok(_) => return fail(walk, device, *b"_STA", Why::Shape),
            Err(f) => return fail(walk, device, *b"_STA", Why::Fault(f)),
        },
    };
    if sta & STA_PRESENT == 0
    {
        return sta & STA_FUNCTIONING != 0;
    }
    walk.present.push(device);
    if let Some(ini) = child(ev.namespace(), device, *b"_INI")
    {
        match ev.evaluate(ini, Vec::new())
        {
            Ok(_) => walk.initialized = walk.initialized.saturating_add(1),
            Err(f) =>
            {
                fail(walk, device, *b"_INI", Why::Fault(f));
            }
        }
    }
    true
}

/// Record the failure of `name` of `node`; false, the device then being
/// skipped with its children.
fn fail(walk: &mut Walk, node: NodeId, name: aml::encoding::Seg, why: Why) -> bool
{
    walk.failures.push(Failure { node, name, why });
    false
}

#[cfg(test)]
mod tests
{
    use aml::encoding::Seg;
    use aml::{Evaluator, FaultKind};

    use super::*;
    use crate::sim::{self, Sim, device, method, name};

    /// `\_SB.` then the one-segment name `seg`, as a `NameString`.
    fn sb(seg: [u8; 4]) -> Vec<u8>
    {
        [&b"\\\x2E_SB_"[..], &seg].concat()
    }

    fn names(ns: &aml::Namespace, nodes: &[NodeId]) -> Vec<String>
    {
        nodes
            .iter()
            .map(|&n| String::from_utf8_lossy(&ns.name(n).unwrap()).into_owned())
            .collect()
    }

    #[test]
    fn the_walk_runs_ini_of_present_devices_and_walks_only_functioning_absent_ones()
    {
        let ini = method(b"_INI", &[]);
        let body = [
            // Present: its _INI and its child's run.
            device(
                &sb(*b"P___"),
                &[
                    name(b"_STA", &[0x0A, 0x0F]),
                    ini.clone(),
                    device(b"Q___", &ini),
                ]
                .concat(),
            ),
            // Absent but functioning: no _INI, its child's runs.
            device(
                &sb(*b"F___"),
                &[
                    name(b"_STA", &[0x0A, 0x08]),
                    ini.clone(),
                    device(b"G___", &ini),
                ]
                .concat(),
            ),
            // Absent and not functioning: skipped with its child.
            device(
                &sb(*b"N___"),
                &[name(b"_STA", &[0x00]), device(b"M___", &ini)].concat(),
            ),
            // A _STA that is no integer: a failure, skipped with its child.
            device(
                &sb(*b"S___"),
                &[name(b"_STA", &[0x0D, b'x', 0]), device(b"T___", &ini)].concat(),
            ),
            // An _INI that faults (1 / 0): a failure, the device present.
            device(
                &sb(*b"E___"),
                &method(b"_INI", &[0x78, 0x01, 0x00, 0x00, 0x60]),
            ),
        ]
        .concat();
        let mut ns = sim::namespace(&[sim::table(&body)]);
        let mut host = Sim::new();
        let mut ev = Evaluator::new(&mut ns, &mut host);
        let walk = initialize(&mut ev);
        let ns = ev.namespace();
        assert_eq!(
            names(ns, &walk.present),
            ["_SB_", "P___", "Q___", "G___", "E___"]
        );
        assert_eq!(walk.initialized, 3);
        let failures: Vec<(String, Seg, Why)> = walk
            .failures
            .iter()
            .map(|f| (names(ns, &[f.node])[0].clone(), f.name, f.why))
            .collect();
        assert_eq!(failures.len(), 2, "{failures:?}");
        assert_eq!(failures[0], ("S___".into(), *b"_STA", Why::Shape));
        assert!(
            matches!(failures[1], (ref n, s, Why::Fault(f)) if n == "E___" && s == *b"_INI" && f.kind == FaultKind::DivideByZero),
            "{failures:?}"
        );
    }

    #[test]
    fn the_q35_hpet_reads_absent_when_the_global_lock_is_refused()
    {
        let mut ns = sim::fixture("x86-default");
        let mut host = Sim::new();
        sim::run_module_code(&mut ns, &mut host);
        let mut ev = Evaluator::new(&mut ns, &mut host);
        let walk = initialize(&mut ev);
        let ns = ev.namespace();
        let present = names(ns, &walk.present);
        assert!(present.contains(&"PCI0".to_string()), "{present:?}");
        assert!(!present.contains(&"HPET".to_string()), "{present:?}");
        let hpet: Vec<&Failure> = walk
            .failures
            .iter()
            .filter(|f| ns.name(f.node) == Some(*b"HPET"))
            .collect();
        assert_eq!(hpet.len(), 1, "{:?}", walk.failures);
        assert_eq!(hpet[0].name, *b"_STA");
        assert!(
            matches!(hpet[0].why, Why::Fault(f) if f.kind == FaultKind::Host(aml::HostError::Refused)),
            "{:?}",
            hpet[0]
        );
    }
}
