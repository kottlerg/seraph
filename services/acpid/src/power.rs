// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/power.rs

//! acpid's power requests (`ipc::acpid_labels`): their decoding, and the
//! evaluation the sleep sequence needs (ACPI 6.5 § 7.4.2 and § 16.1.6): the
//! state's `SLP_TYPa` from its `\_Sx_` package and `\_PTS`. The binary
//! performs the register writes, whose values
//! `ipc::acpid_labels::pm1_control_writes` gives.
//!
//! Only `PM1a_CNT` is written: devmgr serves no `PM1b` block, and no
//! platform acpid runs on declares one.

use aml::{Data, Evaluator, Fault};
use ipc::{acpid_errors, acpid_labels};

use crate::Why;

/// A request acpid serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request
{
    /// `SLEEP` of the state, which is S5.
    Sleep(u8),
    /// `QUERY_SLEEP` of the state, which is S5.
    QuerySleep(u8),
    /// `RESET`.
    Reset,
    /// `WAIT_EVENT`.
    WaitEvent,
}

/// Decode a request of `label` sent with `badge`, whose words are
/// `version` (`data[0]`) and `arg` (`data[1]`): the opcode first, then
/// the authority, then the version, then the argument.
///
/// # Errors
///
/// The `acpid_errors` code to reply: `UNKNOWN_OPCODE`, `UNAUTHORIZED` for
/// a badge without `POWER_AUTHORITY`, `LABEL_VERSION_MISMATCH`, or
/// `INVALID_REQUEST` for a sleep state other than S5 (`SLEEP` and
/// `QUERY_SLEEP`).
pub fn decode(label: u64, badge: u64, version: u64, arg: u64) -> Result<Request, u64>
{
    if label != acpid_labels::SLEEP
        && label != acpid_labels::QUERY_SLEEP
        && label != acpid_labels::RESET
        && label != acpid_labels::WAIT_EVENT
    {
        return Err(acpid_errors::UNKNOWN_OPCODE);
    }
    if badge & acpid_labels::POWER_AUTHORITY == 0
    {
        return Err(acpid_errors::UNAUTHORIZED);
    }
    if version != u64::from(ipc::ACPID_LABELS_VERSION)
    {
        return Err(acpid_errors::LABEL_VERSION_MISMATCH);
    }
    if label == acpid_labels::RESET
    {
        return Ok(Request::Reset);
    }
    if label == acpid_labels::WAIT_EVENT
    {
        return Ok(Request::WaitEvent);
    }
    if arg != acpid_labels::STATE_S5
    {
        return Err(acpid_errors::INVALID_REQUEST);
    }
    if label == acpid_labels::QUERY_SLEEP
    {
        return Ok(Request::QuerySleep(5));
    }
    Ok(Request::Sleep(5))
}

/// The ASL path of sleep state `state`'s package, `\_S5_` for S5.
fn package_path(state: u8) -> String
{
    format!("\\_S{state}_")
}

/// The `SLP_TYPa` of sleep state `state`: element 0 of its `\_Sx_`
/// package; `Ok(None)` when the tables define no such package.
///
/// # Errors
///
/// [`Why::Fault`] when evaluating the package faults, and [`Why::Shape`]
/// when it is no package, or its first element is no integer of at most
/// [`acpid_labels::SLP_TYP_MAX`].
pub fn sleep_type(ev: &mut Evaluator<'_>, state: u8) -> Result<Option<u16>, Why>
{
    let Some(node) = ev.namespace().find(&package_path(state))
    else
    {
        return Ok(None);
    };
    let elements = match ev.evaluate(node, Vec::new())
    {
        Ok(Data::Package(elements)) => elements,
        Ok(_) => return Err(Why::Shape),
        Err(fault) => return Err(Why::Fault(fault)),
    };
    match elements.first()
    {
        Some(&Data::Integer(v)) if v <= acpid_labels::SLP_TYP_MAX =>
        {
            u16::try_from(v).map(Some).map_err(|_| Why::Shape)
        }
        _ => Err(Why::Shape),
    }
}

/// Run `\_PTS(state)`, the "prepare to sleep" method, when the tables
/// define it; the fault when it faults. The sleep goes on either way.
pub fn prepare(ev: &mut Evaluator<'_>, state: u8) -> Option<Fault>
{
    let node = ev.namespace().find("\\_PTS")?;
    ev.evaluate(node, vec![Data::Integer(u64::from(state))])
        .err()
}

#[cfg(test)]
mod tests
{
    use aml::{Evaluator, FaultKind};

    use super::*;
    use crate::sim::{self, Sim, name, package};

    /// `ZeroOp`, an integer element.
    const ZERO: u8 = 0x00;
    /// `OneOp`.
    const ONE: u8 = 0x01;

    /// A `BytePrefix` constant.
    fn byte(v: u8) -> Vec<u8>
    {
        vec![0x0A, v]
    }

    /// `Method (\_PTS, 1) { body }`.
    fn pts(body: &[u8]) -> Vec<u8>
    {
        let mut out = vec![0x14];
        out.extend(sim::pkg(&[&b"\\_PTS"[..], &[1], body].concat()));
        out
    }

    fn s5_of(body: &[u8]) -> Result<Option<u16>, Why>
    {
        let mut ns = sim::namespace(&[sim::table(body)]);
        let mut host = Sim::new();
        sleep_type(&mut Evaluator::new(&mut ns, &mut host), 5)
    }

    #[test]
    fn decode_checks_the_opcode_then_the_authority_then_the_version_then_the_state()
    {
        let auth = acpid_labels::POWER_AUTHORITY;
        let v = u64::from(ipc::ACPID_LABELS_VERSION);
        let s5 = acpid_labels::STATE_S5;
        assert_eq!(
            decode(acpid_labels::SLEEP, auth, v, s5),
            Ok(Request::Sleep(5))
        );
        assert_eq!(
            decode(acpid_labels::QUERY_SLEEP, auth, v, s5),
            Ok(Request::QuerySleep(5))
        );
        assert_eq!(decode(acpid_labels::RESET, auth, v, 0), Ok(Request::Reset));
        assert_eq!(
            decode(acpid_labels::WAIT_EVENT, auth, v, 9),
            Ok(Request::WaitEvent)
        );
        assert_eq!(
            decode(acpid_labels::WAIT_EVENT, 1, v, 0),
            Err(acpid_errors::UNAUTHORIZED)
        );
        assert_eq!(
            decode(acpid_labels::WAIT_EVENT, auth, v + 1, 0),
            Err(acpid_errors::LABEL_VERSION_MISMATCH)
        );
        // The deny twin's badge, 1, carries no verb bit.
        assert_eq!(
            decode(acpid_labels::SLEEP, 1, v + 1, 3),
            Err(acpid_errors::UNAUTHORIZED)
        );
        assert_eq!(
            decode(acpid_labels::RESET, 1, v, 0),
            Err(acpid_errors::UNAUTHORIZED)
        );
        assert_eq!(decode(0x77, 1, v, 0), Err(acpid_errors::UNKNOWN_OPCODE));
        assert_eq!(
            decode(acpid_labels::SLEEP, auth, v + 1, 3),
            Err(acpid_errors::LABEL_VERSION_MISMATCH)
        );
        // S3, and a state past S5.
        assert_eq!(
            decode(acpid_labels::SLEEP, auth, v, 3),
            Err(acpid_errors::INVALID_REQUEST)
        );
        assert_eq!(
            decode(acpid_labels::SLEEP, auth, v, 6),
            Err(acpid_errors::INVALID_REQUEST)
        );
        // QUERY_SLEEP is gated and checked as SLEEP is: the deny twin's
        // badge, a stale version, and a state other than S5.
        assert_eq!(
            decode(acpid_labels::QUERY_SLEEP, 1, v, s5),
            Err(acpid_errors::UNAUTHORIZED)
        );
        assert_eq!(
            decode(acpid_labels::QUERY_SLEEP, auth, v + 1, s5),
            Err(acpid_errors::LABEL_VERSION_MISMATCH)
        );
        assert_eq!(
            decode(acpid_labels::QUERY_SLEEP, auth, v, 3),
            Err(acpid_errors::INVALID_REQUEST)
        );
    }

    #[test]
    fn every_captured_q35_configuration_gives_s5_type_zero_and_riscv_virt_none()
    {
        for config in ["x86-default", "x86-rootport", "x86-rootport-native"]
        {
            let mut ns = sim::fixture(config);
            let mut host = Sim::new();
            sim::run_module_code(&mut ns, &mut host);
            let mut ev = Evaluator::new(&mut ns, &mut host);
            assert_eq!(sleep_type(&mut ev, 5), Ok(Some(0)), "{config}");
            // q35 defines no _PTS.
            assert_eq!(prepare(&mut ev, 5), None, "{config}");
        }
        let mut ns = sim::fixture("riscv64-rootport");
        let mut host = Sim::new();
        assert_eq!(
            sleep_type(&mut Evaluator::new(&mut ns, &mut host), 5),
            Ok(None)
        );
    }

    #[test]
    fn s5_type_is_element_zero_of_at_most_seven()
    {
        let pkg = |a: Vec<u8>| name(b"\\_S5_", &package(&[a, vec![ZERO]]));
        assert_eq!(s5_of(&pkg(byte(7))), Ok(Some(7)));
        assert_eq!(s5_of(&pkg(vec![ONE])), Ok(Some(1)));
        assert_eq!(s5_of(&pkg(byte(8))), Err(Why::Shape));
        // No package, an empty one, a first element that is no integer.
        assert_eq!(s5_of(&name(b"\\_S5_", &byte(5))), Err(Why::Shape));
        assert_eq!(s5_of(&name(b"\\_S5_", &package(&[]))), Err(Why::Shape));
        assert_eq!(
            s5_of(&name(b"\\_S5_", &package(&[sim::buffer(&[5])]))),
            Err(Why::Shape)
        );
        // Another state's package is not S5's.
        assert_eq!(s5_of(&name(b"\\_S4_", &package(&[vec![ZERO]]))), Ok(None));
    }

    #[test]
    fn prepare_runs_pts_with_the_state_and_reports_its_fault()
    {
        // _PTS stores its argument in \PTSA: Store (Arg0, \PTSA).
        let body = [
            name(b"\\PTSA", &byte(0)),
            pts(&[&[0x70, 0x68][..], b"\\PTSA"].concat()),
        ]
        .concat();
        let mut ns = sim::namespace(&[sim::table(&body)]);
        let mut host = Sim::new();
        let mut ev = Evaluator::new(&mut ns, &mut host);
        assert_eq!(prepare(&mut ev, 5), None);
        assert_eq!(ev.evaluate_path("\\PTSA", Vec::new()), Ok(Data::Integer(5)));

        // Divide (1, 0): the fault is reported.
        let mut ns = sim::namespace(&[sim::table(&pts(&[0x78, 0x01, 0x00, 0x00, 0x60]))]);
        let mut ev = Evaluator::new(&mut ns, &mut host);
        assert!(matches!(prepare(&mut ev, 5), Some(f) if f.kind == FaultKind::DivideByZero));
    }
}
