// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/stop.rs

//! The eligibility rule of svcmgr's stop of a service
//! (`stop_labels::STOP_CANDIDATE` on svcmgr's endpoint): which supervised
//! services svcmgr stops for a stop-authority holder; and the classes a
//! `stop_source` recipe names.
//!
//! One decision table, [`stop_refusal`], read from the facts svcmgr holds on
//! a service ([`StopFacts`]). svcmgr applies it to each request, and the
//! `.svc` parser applies it to a recipe that sets `oom_stop = yes`, so a
//! recipe the rule would refuse is rejected when it is read. The rule is
//! specified in `services/svcmgr/docs/service-definitions.md` § `oom_stop`.

/// What svcmgr knows of a supervised service when it decides a stop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each field is one independent input of the eligibility table, which the table \
              names by row"
)]
pub struct StopFacts
{
    /// svcmgr launched the service from its recipe. A service init started
    /// (memmgr, procmgr, devmgr, vfsd) is supervised but was not launched by
    /// svcmgr.
    pub launched: bool,
    /// The recipe's `restart = never`.
    pub restart_never: bool,
    /// The recipe's `critical = yes`.
    pub critical: bool,
    /// The recipe gives the service a core role: `log_sink`,
    /// `debug_authority`, `stop_authority`, `reserve`, `shutdown_actuator`,
    /// or `stop_source` (see [`core_role`]).
    pub core_role: bool,
    /// The recipe's `oom_stop = yes`.
    pub oom_stop: bool,
}

/// Why svcmgr refuses to stop a service, most informative first: the order
/// of the variants is the order [`stop_refusal`] tests them in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopRefusal
{
    /// init started the service; svcmgr only binds it.
    NotLaunched,
    /// `restart = never`: a one-shot service svcmgr does not supervise.
    RestartNever,
    /// `critical = yes`: the system is not viable without it.
    Critical,
    /// The service holds a core role ([`core_role`]).
    CoreRole,
    /// The recipe does not set `oom_stop = yes`.
    NotOptedIn,
}

impl StopRefusal
{
    /// The reason as svcmgr logs it, and as the parser reports a recipe the
    /// rule refuses.
    #[must_use]
    pub const fn reason(self) -> &'static str
    {
        match self
        {
            Self::NotLaunched => "not launched by svcmgr",
            Self::RestartNever => "restart = never",
            Self::Critical => "critical = yes",
            Self::CoreRole =>
            {
                "holds a core role (log_sink, debug_authority, stop_authority, reserve, \
                 shutdown_actuator or stop_source)"
            }
            Self::NotOptedIn => "oom_stop is not yes",
        }
    }
}

/// Whether a recipe's keys give its service a core role, which the
/// eligibility rule never stops: the system log sink, the holders of
/// procmgr's debug authority and of the stop authority, a service in the
/// system reserve, the shutdown actuator, and a stop source, which holds kill
/// authority over processes of its own.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "each argument is one recipe key the rule reads"
)]
pub const fn core_role(
    log_sink: bool,
    debug_authority: bool,
    stop_authority: bool,
    reserve: bool,
    shutdown_actuator: bool,
    stop_source: bool,
) -> bool
{
    log_sink || debug_authority || stop_authority || reserve || shutdown_actuator || stop_source
}

/// The class a `stop_source = <class>` recipe names: the class svcmgr gives
/// the source in `svcmgr_labels::LIST_STOP_SOURCES`, read from the recipe and
/// never from the source. Specified in
/// `services/svcmgr/docs/service-definitions.md` § `stop_source`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopClass
{
    /// `program`: the programs of sessions.
    Program,
}

impl StopClass
{
    /// The class a recipe value names; `None` for any other value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self>
    {
        match value
        {
            "program" => Some(Self::Program),
            _ => None,
        }
    }

    /// The class's code on the wire (`ipc::stop_labels`).
    #[must_use]
    pub const fn code(self) -> u64
    {
        match self
        {
            Self::Program => ipc::stop_labels::CLASS_PROGRAM,
        }
    }
}

/// The eligibility rule: `None` when svcmgr may stop the service `facts`
/// describe, else the first reason, in [`StopRefusal`]'s order, that refuses
/// it.
///
/// | launched | restart | critical | core role | `oom_stop` | result |
/// |---|---|---|---|---|---|
/// | no | any | any | any | any | [`StopRefusal::NotLaunched`] |
/// | yes | never | any | any | any | [`StopRefusal::RestartNever`] |
/// | yes | other | yes | any | any | [`StopRefusal::Critical`] |
/// | yes | other | no | yes | any | [`StopRefusal::CoreRole`] |
/// | yes | other | no | no | no | [`StopRefusal::NotOptedIn`] |
/// | yes | other | no | no | yes | eligible |
#[must_use]
pub const fn stop_refusal(facts: &StopFacts) -> Option<StopRefusal>
{
    if !facts.launched
    {
        Some(StopRefusal::NotLaunched)
    }
    else if facts.restart_never
    {
        Some(StopRefusal::RestartNever)
    }
    else if facts.critical
    {
        Some(StopRefusal::Critical)
    }
    else if facts.core_role
    {
        Some(StopRefusal::CoreRole)
    }
    else if !facts.oom_stop
    {
        Some(StopRefusal::NotOptedIn)
    }
    else
    {
        None
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const ELIGIBLE: StopFacts = StopFacts {
        launched: true,
        restart_never: false,
        critical: false,
        core_role: false,
        oom_stop: true,
    };

    #[test]
    fn a_launched_restartable_non_critical_opted_in_service_is_eligible()
    {
        assert_eq!(stop_refusal(&ELIGIBLE), None);
    }

    #[test]
    fn each_input_alone_refuses_with_its_own_reason()
    {
        let rows = [
            (
                StopFacts {
                    launched: false,
                    ..ELIGIBLE
                },
                StopRefusal::NotLaunched,
            ),
            (
                StopFacts {
                    restart_never: true,
                    ..ELIGIBLE
                },
                StopRefusal::RestartNever,
            ),
            (
                StopFacts {
                    critical: true,
                    ..ELIGIBLE
                },
                StopRefusal::Critical,
            ),
            (
                StopFacts {
                    core_role: true,
                    ..ELIGIBLE
                },
                StopRefusal::CoreRole,
            ),
            (
                StopFacts {
                    oom_stop: false,
                    ..ELIGIBLE
                },
                StopRefusal::NotOptedIn,
            ),
        ];
        for (facts, refusal) in rows
        {
            assert_eq!(stop_refusal(&facts), Some(refusal), "{facts:?}");
        }
    }

    #[test]
    fn a_service_failing_several_inputs_is_refused_for_the_first_in_table_order()
    {
        // memmgr: started by init, restart = never, critical = yes.
        let memmgr = StopFacts {
            launched: false,
            restart_never: true,
            critical: true,
            core_role: false,
            oom_stop: false,
        };
        // logd: launched, on_failure, critical = yes, the log sink.
        let logd = StopFacts {
            launched: true,
            restart_never: false,
            critical: true,
            core_role: true,
            oom_stop: false,
        };
        // pwrmgr: launched, on_failure, critical = no, the shutdown actuator.
        let pwrmgr = StopFacts {
            critical: false,
            ..logd
        };
        // timed: launched, on_failure, critical = no, no core role.
        let timed = StopFacts {
            core_role: false,
            ..pwrmgr
        };
        assert_eq!(stop_refusal(&memmgr), Some(StopRefusal::NotLaunched));
        assert_eq!(stop_refusal(&logd), Some(StopRefusal::Critical));
        assert_eq!(stop_refusal(&pwrmgr), Some(StopRefusal::CoreRole));
        assert_eq!(stop_refusal(&timed), Some(StopRefusal::NotOptedIn));
        // Opting in changes none of them.
        for facts in [memmgr, logd, pwrmgr]
        {
            assert!(
                stop_refusal(&StopFacts {
                    oom_stop: true,
                    ..facts
                })
                .is_some()
            );
        }
    }

    #[test]
    fn each_core_role_key_alone_is_a_core_role()
    {
        assert!(!core_role(false, false, false, false, false, false));
        assert!(core_role(true, false, false, false, false, false));
        assert!(core_role(false, true, false, false, false, false));
        assert!(core_role(false, false, true, false, false, false));
        assert!(core_role(false, false, false, true, false, false));
        assert!(core_role(false, false, false, false, true, false));
        assert!(core_role(false, false, false, false, false, true));
    }

    #[test]
    fn program_is_the_one_class_a_recipe_names()
    {
        assert_eq!(StopClass::parse("program"), Some(StopClass::Program));
        assert_eq!(StopClass::Program.code(), ipc::stop_labels::CLASS_PROGRAM);
        for other in ["service", "Program", "", "program "]
        {
            assert_eq!(StopClass::parse(other), None, "{other:?}");
        }
    }
}
