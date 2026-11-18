// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/oomd/policy/src/lib.rs

//! What oomd decides: its configuration, when it acts, and which candidate
//! it stops first (services/oomd/docs/operation.md).
//!
//! [`Config`] holds the recipe's `OOMD_GRACE_MS`, `OOMD_COOLDOWN_MS` and
//! `OOMD_STOP` ([`parse_ms`], [`parse_stop`]). [`Ladder`] follows memmgr's
//! pressure level: it reports each change oomd logs, and asks for an act once
//! the level has read `CRITICAL` for the grace and the cooldown has passed
//! since the last act. [`Best`] keeps, of the candidates a walk of the stop
//! sources offers, the one stopped first: the earliest class, then the lowest
//! rank within it, then the most pages, a tie going to the candidate offered
//! first, so to the earlier source and then its earlier entry
//! (docs/session-supervision.md § Stop Sources); the program class goes
//! before the service class. The state takes the time and
//! the level as arguments and holds no capability, so it is host-tested.

#![cfg_attr(not(test), no_std)]

/// `OOMD_GRACE_MS` when the recipe gives none: how long the level reads
/// `CRITICAL` before oomd acts.
pub const GRACE_DEFAULT_MS: u64 = 2000;

/// `OOMD_COOLDOWN_MS` when the recipe gives none: how long after an act oomd
/// waits before the next.
pub const COOLDOWN_DEFAULT_MS: u64 = 5000;

/// The longest grace or cooldown oomd takes, in milliseconds: ten minutes. A
/// longer value is clamped to it.
pub const DURATION_MAX_MS: u64 = 600_000;

/// How a setting was read from the environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read
{
    /// The recipe gave a valid value.
    Given,
    /// The recipe gave none; the default holds.
    Absent,
    /// The value asked more than [`DURATION_MAX_MS`] and was clamped to it.
    Clamped,
    /// The value does not parse; the default holds, or for `OOMD_STOP`,
    /// advice.
    Invalid,
}

/// A setting's value and how it was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setting<T>
{
    pub value: T,
    pub read: Read,
}

/// Whether oomd stops the candidate it picks (`OOMD_STOP`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode
{
    /// `OOMD_STOP=yes`, the default: stop the candidate.
    Stop,
    /// `OOMD_STOP=no`: name the candidate it would stop, and stop nothing.
    Advise,
}

/// A duration from the environment value `value`: no entry gives `default`,
/// decimal digits give their milliseconds, clamped to [`DURATION_MAX_MS`],
/// and anything else gives `default`, marked [`Read::Invalid`].
#[must_use]
pub fn parse_ms(value: Option<&str>, default: u64) -> Setting<u64>
{
    let Some(text) = value
    else
    {
        return Setting {
            value: default,
            read: Read::Absent,
        };
    };
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Setting {
            value: default,
            read: Read::Invalid,
        };
    }
    // Digits alone: the parse fails only past u64::MAX, which is past the max.
    let ms = text.parse::<u64>().unwrap_or(u64::MAX);
    if ms > DURATION_MAX_MS
    {
        return Setting {
            value: DURATION_MAX_MS,
            read: Read::Clamped,
        };
    }
    Setting {
        value: ms,
        read: Read::Given,
    }
}

/// `OOMD_STOP` from the environment value `value`: `yes` or no entry stops,
/// `no` advises, and anything else advises, marked [`Read::Invalid`], so a
/// misspelt setting stops nothing.
#[must_use]
pub fn parse_stop(value: Option<&str>) -> Setting<Mode>
{
    match value
    {
        None => Setting {
            value: Mode::Stop,
            read: Read::Absent,
        },
        Some("yes") => Setting {
            value: Mode::Stop,
            read: Read::Given,
        },
        Some("no") => Setting {
            value: Mode::Advise,
            read: Read::Given,
        },
        Some(_) => Setting {
            value: Mode::Advise,
            read: Read::Invalid,
        },
    }
}

/// oomd's configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config
{
    /// Milliseconds the level reads `CRITICAL` before oomd acts.
    pub grace_ms: u64,
    /// Milliseconds after an act before the next.
    pub cooldown_ms: u64,
    /// Whether an act stops its candidate or only names it.
    pub mode: Mode,
}

/// memmgr's pressure level as oomd reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level
{
    Normal,
    Low,
    Critical,
    /// The level could not be read: memmgr did not answer.
    Unknown,
}

/// A change of the level that oomd logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition
{
    /// An episode of pressure began: the level left `NORMAL`, for the level
    /// named.
    Began(Level),
    /// The level rose to `CRITICAL` within an episode.
    Critical,
    /// The level fell from `CRITICAL` to `LOW` within the episode, having
    /// read `CRITICAL` for `critical_ms` milliseconds.
    Eased
    {
        critical_ms: u64
    },
    /// The episode ended: the level reads `NORMAL` again, `episode_ms`
    /// milliseconds after it left it.
    Ended
    {
        episode_ms: u64
    },
}

/// An act the ladder asks for: walk the stop sources and stop, or name, the
/// candidate stopped first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Act
{
    pub mode: Mode,
    /// How long the level has read `CRITICAL`, in milliseconds.
    pub critical_ms: u64,
    /// Whether this is the first act since the level last rose to
    /// `CRITICAL`.
    pub first: bool,
}

/// What one reading of the level gives.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Step
{
    pub transition: Option<Transition>,
    pub act: Option<Act>,
}

/// oomd's ladder over memmgr's pressure level.
#[derive(Clone, Copy, Debug)]
pub struct Ladder
{
    config: Config,
    /// The last level read; `NORMAL` before the first.
    level: Level,
    /// When the level last left `NORMAL`, while it does not read `NORMAL`.
    episode_since: Option<u64>,
    /// When the level last rose to `CRITICAL`, while it reads `CRITICAL`.
    critical_since: Option<u64>,
    /// When the last act was asked for.
    last_act: Option<u64>,
    /// Whether an act was asked for since the level last rose to `CRITICAL`.
    acted_this_critical: bool,
}

impl Ladder
{
    #[must_use]
    pub const fn new(config: Config) -> Self
    {
        Self {
            config,
            level: Level::Normal,
            episode_since: None,
            critical_since: None,
            last_act: None,
            acted_this_critical: false,
        }
    }

    /// Take the level `level` read at `now` (milliseconds): the change it
    /// makes, and an act when the level has read `CRITICAL` for the grace and
    /// the cooldown has passed since the last act. An unreadable level changes
    /// nothing and asks for no act: oomd acts on no level it did not read.
    pub fn observe(&mut self, now: u64, level: Level) -> Step
    {
        if level == Level::Unknown
        {
            return Step::default();
        }
        let transition = self.transition_to(now, level);
        self.level = level;
        Step {
            transition,
            act: self.act(now),
        }
    }

    /// The change from the last level to `level`, starting or ending the
    /// episode and the `CRITICAL` state it makes. The last level is never
    /// `Unknown`: [`Ladder::observe`] keeps the last level it read.
    fn transition_to(&mut self, now: u64, level: Level) -> Option<Transition>
    {
        match (self.level, level)
        {
            (Level::Normal, Level::Low) =>
            {
                self.episode_since = Some(now);
                Some(Transition::Began(Level::Low))
            }
            (Level::Normal, Level::Critical) =>
            {
                self.episode_since = Some(now);
                self.enter_critical(now);
                Some(Transition::Began(Level::Critical))
            }
            (Level::Low, Level::Critical) =>
            {
                self.enter_critical(now);
                Some(Transition::Critical)
            }
            (Level::Critical, Level::Low) => Some(Transition::Eased {
                critical_ms: since(self.critical_since.take(), now),
            }),
            (Level::Low | Level::Critical, Level::Normal) =>
            {
                self.critical_since = None;
                Some(Transition::Ended {
                    episode_ms: since(self.episode_since.take(), now),
                })
            }
            (Level::Normal, Level::Normal)
            | (Level::Low, Level::Low)
            | (Level::Critical, Level::Critical)
            | (Level::Unknown, _)
            | (_, Level::Unknown) => None,
        }
    }

    fn enter_critical(&mut self, now: u64)
    {
        self.critical_since = Some(now);
        self.acted_this_critical = false;
    }

    /// An act, recorded as the last, when one is due at `now`.
    fn act(&mut self, now: u64) -> Option<Act>
    {
        let since = self.critical_since?;
        if now < self.next_deadline()?
        {
            return None;
        }
        let first = !self.acted_this_critical;
        self.acted_this_critical = true;
        self.last_act = Some(now);
        Some(Act {
            mode: self.config.mode,
            critical_ms: now.saturating_sub(since),
            first,
        })
    }

    /// When the next act falls due, so when oomd reads the level next even
    /// if memmgr signals no change: the grace after the rise to `CRITICAL` or
    /// the cooldown after the last act, whichever is later. `None` while the
    /// level does not read `CRITICAL`, when only a change can make an act due.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64>
    {
        let grace_end = self.critical_since?.saturating_add(self.config.grace_ms);
        Some(match self.last_act
        {
            Some(at) => grace_end.max(at.saturating_add(self.config.cooldown_ms)),
            None => grace_end,
        })
    }
}

/// Milliseconds from `at` to `now`; 0 with no `at`.
fn since(at: Option<u64>, now: u64) -> u64
{
    at.map_or(0, |at| now.saturating_sub(at))
}

/// A stop source's class. Classes are stopped in their declaration order:
/// every candidate of an earlier class before any of a later one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class
{
    /// The programs of sessions: the sources whose recipes set
    /// `stop_source = program`.
    Program,
    /// svcmgr's services whose recipes set `oom_stop = yes`.
    Service,
}

impl Class
{
    /// The class of a source svcmgr lists with class code `code`
    /// (`svcmgr_labels::LIST_STOP_SOURCES`); `None` for a code oomd does not
    /// know. svcmgr itself, the service class's source, is never listed.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Self>
    {
        match code
        {
            ipc::stop_labels::CLASS_PROGRAM => Some(Self::Program),
            _ => None,
        }
    }
}

/// Where a candidate falls in the order oomd stops in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Order
{
    /// Its source's class.
    pub class: Class,
    /// Its rank within its class, the lower first; one a source gives.
    pub rank: u64,
    /// The pages its memory budget node and that node's subtree hold.
    pub pages: u64,
}

impl Order
{
    /// Whether `self` is stopped strictly before `other`: an earlier class,
    /// else a lower rank, else more pages.
    #[must_use]
    pub fn precedes(&self, other: &Self) -> bool
    {
        (self.class, self.rank, core::cmp::Reverse(self.pages))
            < (other.class, other.rank, core::cmp::Reverse(other.pages))
    }
}

/// The candidate a walk stops first. A walk offers each candidate in its
/// order, the sources in theirs and each source's entries in the order it
/// lists them; the one kept is stopped first, a tie going to the one offered
/// first.
#[derive(Clone, Copy, Debug)]
pub struct Best<T>
{
    best: Option<(Order, T)>,
}

impl<T> Default for Best<T>
{
    fn default() -> Self
    {
        Self { best: None }
    }
}

impl<T> Best<T>
{
    /// Keep `item`, at `order`, when it is stopped before the one kept.
    /// Returns the item not kept: the one `item` displaced, or `item`
    /// itself; `None` when nothing was kept before.
    #[must_use]
    pub fn offer(&mut self, order: Order, item: T) -> Option<T>
    {
        let first = match &self.best
        {
            Some((kept, _)) => order.precedes(kept),
            None => true,
        };
        if first
        {
            self.best.replace((order, item)).map(|(_, old)| old)
        }
        else
        {
            Some(item)
        }
    }

    /// The candidate kept so far, if any was offered.
    #[must_use]
    pub const fn kept(&self) -> Option<&(Order, T)>
    {
        self.best.as_ref()
    }

    /// The candidate kept, if any was offered.
    #[must_use]
    pub fn take(self) -> Option<(Order, T)>
    {
        self.best
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const CONFIG: Config = Config {
        grace_ms: 2000,
        cooldown_ms: 5000,
        mode: Mode::Stop,
    };

    #[test]
    fn a_duration_reads_digits_and_falls_back_to_its_default()
    {
        assert_eq!(
            parse_ms(None, 7),
            Setting {
                value: 7,
                read: Read::Absent
            }
        );
        assert_eq!(
            parse_ms(Some("1500"), 7),
            Setting {
                value: 1500,
                read: Read::Given
            }
        );
        assert_eq!(parse_ms(Some("0"), 7).value, 0);
        for bad in ["", "-1", "2s", " 5", "1e3"]
        {
            assert_eq!(
                parse_ms(Some(bad), 7),
                Setting {
                    value: 7,
                    read: Read::Invalid
                },
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_duration_past_the_max_is_clamped_to_it()
    {
        assert_eq!(parse_ms(Some("600000"), 7).read, Read::Given);
        for long in ["600001", "99999999999999999999999"]
        {
            assert_eq!(
                parse_ms(Some(long), 7),
                Setting {
                    value: DURATION_MAX_MS,
                    read: Read::Clamped
                },
                "{long}"
            );
        }
    }

    #[test]
    fn only_yes_or_no_entry_stops_and_anything_else_advises()
    {
        assert_eq!(parse_stop(None).value, Mode::Stop);
        assert_eq!(parse_stop(Some("yes")).value, Mode::Stop);
        assert_eq!(parse_stop(Some("no")).value, Mode::Advise);
        assert_eq!(
            parse_stop(Some("YES")),
            Setting {
                value: Mode::Advise,
                read: Read::Invalid
            }
        );
    }

    #[test]
    fn low_begins_and_normal_ends_an_episode_with_no_act()
    {
        let mut ladder = Ladder::new(CONFIG);
        let low = ladder.observe(1, Level::Low);
        assert_eq!(low.transition, Some(Transition::Began(Level::Low)));
        assert_eq!(ladder.observe(100_000, Level::Low), Step::default());
        assert_eq!(ladder.next_deadline(), None);
        assert_eq!(
            ladder.observe(100_001, Level::Normal),
            Step {
                transition: Some(Transition::Ended {
                    episode_ms: 100_000
                }),
                act: None
            }
        );
    }

    #[test]
    fn critical_acts_once_the_grace_has_passed_and_not_before()
    {
        let mut ladder = Ladder::new(CONFIG);
        assert_eq!(ladder.observe(1000, Level::Low).act, None);
        let rise = ladder.observe(1500, Level::Critical);
        assert_eq!(rise.transition, Some(Transition::Critical));
        assert_eq!(rise.act, None);
        assert_eq!(ladder.next_deadline(), Some(3500));
        assert_eq!(ladder.observe(3499, Level::Critical).act, None);
        assert_eq!(
            ladder.observe(3500, Level::Critical).act,
            Some(Act {
                mode: Mode::Stop,
                critical_ms: 2000,
                first: true
            })
        );
    }

    #[test]
    fn a_second_act_waits_for_the_cooldown()
    {
        let mut ladder = Ladder::new(CONFIG);
        let _ = ladder.observe(0, Level::Critical);
        assert!(ladder.observe(2000, Level::Critical).act.is_some());
        assert_eq!(ladder.next_deadline(), Some(7000));
        assert_eq!(ladder.observe(6999, Level::Critical).act, None);
        assert_eq!(
            ladder.observe(7000, Level::Critical).act,
            Some(Act {
                mode: Mode::Stop,
                critical_ms: 7000,
                first: false
            })
        );
    }

    #[test]
    fn a_fall_below_critical_restarts_the_grace_and_keeps_the_cooldown()
    {
        let mut ladder = Ladder::new(CONFIG);
        let _ = ladder.observe(0, Level::Critical);
        assert!(ladder.observe(2000, Level::Critical).act.is_some());
        let eased = ladder.observe(2100, Level::Low);
        assert_eq!(
            eased.transition,
            Some(Transition::Eased { critical_ms: 2100 })
        );
        assert_eq!(ladder.next_deadline(), None);
        // Back to CRITICAL: the grace runs again from 3000, and the cooldown
        // from the act at 2000 holds the next act to 7000.
        let _ = ladder.observe(3000, Level::Critical);
        assert_eq!(ladder.observe(5000, Level::Critical).act, None);
        assert_eq!(ladder.next_deadline(), Some(7000));
        let act = ladder.observe(7000, Level::Critical).act;
        assert_eq!(act.map(|a| (a.critical_ms, a.first)), Some((4000, true)));
    }

    #[test]
    fn an_unreadable_level_changes_nothing_and_asks_for_no_act()
    {
        let mut ladder = Ladder::new(CONFIG);
        let _ = ladder.observe(0, Level::Critical);
        assert_eq!(ladder.observe(5000, Level::Unknown), Step::default());
        // The rise at 0 stands once the level is read again.
        let again = ladder.observe(5001, Level::Critical);
        assert_eq!(again.transition, None);
        assert_eq!(again.act.map(|a| a.critical_ms), Some(5001));
        let ended = ladder.observe(5002, Level::Normal).transition;
        assert_eq!(ended, Some(Transition::Ended { episode_ms: 5002 }));
    }

    #[test]
    fn oomd_stop_no_asks_only_for_advice()
    {
        let mut ladder = Ladder::new(Config {
            mode: Mode::Advise,
            ..CONFIG
        });
        let _ = ladder.observe(0, Level::Critical);
        for now in [2000, 7000, 12_000]
        {
            let act = ladder.observe(now, Level::Critical).act;
            assert_eq!(act.map(|a| a.mode), Some(Mode::Advise), "at {now}");
        }
    }

    #[test]
    fn a_zero_grace_acts_on_the_rise_itself()
    {
        let mut ladder = Ladder::new(Config {
            grace_ms: 0,
            ..CONFIG
        });
        let rise = ladder.observe(10, Level::Critical);
        assert_eq!(rise.transition, Some(Transition::Began(Level::Critical)));
        assert_eq!(rise.act.map(|a| a.critical_ms), Some(0));
    }

    fn service(rank: u64, pages: u64) -> Order
    {
        Order {
            class: Class::Service,
            rank,
            pages,
        }
    }

    fn program(rank: u64, pages: u64) -> Order
    {
        Order {
            class: Class::Program,
            rank,
            pages,
        }
    }

    /// Offer each of `offers` in turn, returning what the walk keeps and the
    /// items it handed back, in the order it handed them back.
    fn walk<'a>(offers: &[(Order, &'a str)]) -> (Option<(Order, &'a str)>, Vec<&'a str>)
    {
        let mut best = Best::default();
        let mut returned = Vec::new();
        for &(order, item) in offers
        {
            returned.extend(best.offer(order, item));
        }
        (best.take(), returned)
    }

    #[test]
    fn the_most_pages_go_first_and_a_tie_goes_to_the_earlier_offer()
    {
        let (kept, returned) = walk(&[
            (service(0, 10), "a"),
            (service(0, 30), "b"),
            (service(0, 30), "c"),
            (service(0, 20), "d"),
        ]);
        assert_eq!(kept, Some((service(0, 30), "b")));
        let mut best = Best::default();
        assert!(best.kept().is_none());
        assert_eq!(best.offer(service(0, 1), "x"), None);
        assert_eq!(best.kept(), Some(&(service(0, 1), "x")));
        // Every item not kept comes back once: the displaced "a", then the
        // refused "c" and "d".
        assert_eq!(returned, ["a", "c", "d"]);
    }

    #[test]
    fn a_lower_rank_goes_first_whatever_its_pages()
    {
        let (kept, returned) = walk(&[(service(1, 1000), "big"), (service(0, 1), "small")]);
        assert_eq!(kept.map(|(_, name)| name), Some("small"));
        assert_eq!(returned, ["big"]);
    }

    #[test]
    fn programs_go_before_services_whatever_their_pages()
    {
        // svcmgr's services offered first, as from an earlier source, still
        // yield to a program of a later one.
        let (kept, _) = walk(&[
            (service(0, 100_000), "memhog"),
            (program(ipc::stop_labels::RANK_SESSION, 2), "session"),
            (program(ipc::stop_labels::RANK_JOB, 1), "job"),
            (service(0, 1), "small service"),
        ]);
        assert_eq!(kept.map(|(_, name)| name), Some("job"));
    }

    #[test]
    fn jobs_go_before_sessions_and_the_largest_job_first()
    {
        let job = ipc::stop_labels::RANK_JOB;
        let session = ipc::stop_labels::RANK_SESSION;
        let (kept, _) = walk(&[
            (program(session, 5000), "session"),
            (program(job, 10), "small job"),
            (program(job, 300), "large job"),
            (program(job, 300), "tied job"),
        ]);
        assert_eq!(kept, Some((program(job, 300), "large job")));
        // With no job, the session goes before any service.
        let (kept, _) = walk(&[(service(0, 9000), "svc"), (program(session, 1), "session")]);
        assert_eq!(kept.map(|(_, name)| name), Some("session"));
    }

    #[test]
    fn the_program_class_code_names_the_program_class_and_no_other_code_a_class()
    {
        assert_eq!(
            Class::from_code(ipc::stop_labels::CLASS_PROGRAM),
            Some(Class::Program)
        );
        for code in [0, 2, u64::MAX]
        {
            assert_eq!(Class::from_code(code), None, "{code}");
        }
    }

    #[test]
    fn a_walk_that_offers_nothing_picks_nothing()
    {
        assert_eq!(walk(&[]), (None, Vec::new()));
    }
}
