// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/logd_follow.rs

//! Following logd's journal and steering its sinks
//! (`services/logd/docs/ipc-interface.md` § Queries, § Subscriptions and
//! § Sink control).
//!
//! `logd_follow` subscribes on `logd.query` with a signal, takes the token the
//! reply carries, logs
//! an informational and a warning line, waits for the signal, and reads both
//! lines oldest first from the subscription's next `seq`, then only the
//! warning through the severity filter. A walk on another instance's epoch is
//! refused `QUERY_STALE`. It fills the `logd.follow` pool beside the
//! `logd.query` subscription, requires the next subscription refused
//! `QUERY_FULL`, and requires one freed once its token is deleted. A refused
//! subscription, a signal without the notify right or a request with a
//! capability more among them, leaves logd holding none of the capabilities
//! it moved, and a badge with neither authority is refused `QUERY_DENIED`.
//!
//! `logd_control` requires `SINK_LIST` and `SINK_SET` refused on
//! `logd.query`, lists the serial and framebuffer sinks through
//! `logd.control`, sets the framebuffer sink's level, which logd's own
//! notice line records, and sets its settings back. It turns the framebuffer
//! sink `off`, logs a line, and turns it on again, which starts its cursor
//! past that line whether or not a driver serves the sink. It steers the framebuffer
//! sink, whose output no boot check reads, so the serial lines the boot is
//! judged on keep their level.

use std::time::{Duration, Instant};

use ipc::IpcMessage;
use ipc::log_control::{SINK_SERVED, SINK_STALLED, SetRequest, decode_list_reply, list_request};
use ipc::log_query::{
    HistoryEntries, HistoryRequest, QUERY_DENIED, QUERY_FULL, QUERY_INVALID, QUERY_NO_SINK,
    QUERY_OK, QUERY_STALE, Subscribed, Walk, reply_more, reply_status, subscribe_request,
};
use ipc::stream_labels::LEVEL_WARN;

use super::procmgr::logd_query_call;
use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "logd_follow",
            run: logd_follow_phase,
        },
        Phase {
            name: "logd_control",
            run: logd_control_phase,
        },
    ]
}

/// The `logd.query` pool's size (`SUBSCRIBERS_MAX` in logd).
const SUBSCRIBERS_MAX: u64 = 8;
/// The `logd.follow` pool's size (`SINK_SUBSCRIBERS_MAX` in logd).
const SINK_SUBSCRIBERS_MAX: u64 = 4;

/// The informational line the subscriber reads back.
const INFO_LINE: &str = "logd_follow: an informational line to follow";
/// The warning line the subscriber reads back, alone through the filter.
const WARN_LINE: &str = "logd_follow: a warning line to follow";

/// How long the phase waits for logd: a signal, or the end of a subscription
/// whose token it deleted, which logd's main thread sees within a timer tick
/// of the deletion and its own wake.
const LOGD_WAIT: Duration = Duration::from_secs(30);

/// The pause between polls for an ended subscription.
const POLL: Duration = Duration::from_millis(10);

/// A subscriber's end: its Notification, which logd signals, and the token
/// an accepted subscription's reply carries, whose deletion ends it; 0 before.
struct Subscriber
{
    signal: u64,
    token: u64,
}

impl Subscriber
{
    /// A new Notification, and no token.
    fn new() -> Self
    {
        Self {
            signal: notification(),
            token: 0,
        }
    }

    /// A copy of the signal with `rights`, to move to logd.
    fn signal_copy(&self, rights: u64) -> u64
    {
        syscall::cap_derive(self.signal, rights)
            .unwrap_or_else(|e| panic!("logd_follow: signal derive failed ({e})"))
    }

    /// `LOG_SUBSCRIBE` on `cap`, moving a copy of the signal with only the
    /// notify right (`signal_rights`), and keeping the reply's token.
    fn subscribe_with(&mut self, cap: u64, signal_rights: u64) -> Result<Subscribed, u64>
    {
        let request = subscribe_request(self.signal_copy(signal_rights));
        let sub = Subscribed::decode(&logd_query_call(cap, &request))?;
        assert!(
            sub.token != 0 && self.token == 0,
            "logd_follow: subscription reply {sub:?} for a subscriber with token {}",
            self.token
        );
        self.token = sub.token;
        Ok(sub)
    }

    /// `LOG_SUBSCRIBE` on `cap`.
    fn subscribe(&mut self, cap: u64) -> Result<Subscribed, u64>
    {
        self.subscribe_with(cap, syscall::RIGHTS_NTF_NOTIFY)
    }

    /// Whether the signal is at this one reference: logd holds no copy of it.
    fn signal_sole(&self) -> bool
    {
        syscall::cap_info(self.signal, syscall::CAP_INFO_SOLE_REFERENCE) == Ok(1)
    }

    /// Delete the token, which ends the subscription, and the signal.
    fn end(self)
    {
        if self.token != 0
        {
            let _ = syscall::cap_delete(self.token);
        }
        let _ = syscall::cap_delete(self.signal);
    }
}

/// A new Notification; a failure panics.
fn notification() -> u64
{
    std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
        syscall::cap_create_notification(slab).ok()
    })
    .expect("logd_follow: notification create failed")
}

/// The entries from `from` on, oldest first, at `least` or more severe, as
/// (`seq`, level, bytes), read across every `QUERY_HISTORY` page on `epoch`;
/// `Err` with the status of a refused page.
fn read_up(
    query: u64,
    from: u64,
    epoch: u64,
    least: Option<u8>,
) -> Result<Vec<(u64, u8, Vec<u8>)>, u64>
{
    let mut found = Vec::new();
    let mut req = HistoryRequest {
        badge: None,
        walk: Walk::Up { from, epoch },
        least,
    };
    loop
    {
        let reply = logd_query_call(query, &req.message());
        match reply_status(reply.label)
        {
            QUERY_OK => (),
            status => return Err(status),
        }
        for entry in HistoryEntries::new(&reply)
        {
            let next = entry
                .seq
                .checked_add(1)
                .expect("logd_follow: seq overflowed");
            req.walk = Walk::Up { from: next, epoch };
            found.push((entry.seq, entry.level, entry.bytes.to_vec()));
        }
        if !reply_more(reply.label)
        {
            return Ok(found);
        }
    }
}

/// The `seq` of the entry whose bytes are `line`.
fn seq_of(entries: &[(u64, u8, Vec<u8>)], line: &str) -> Option<u64>
{
    entries
        .iter()
        .find(|(_, _, bytes)| bytes == line.as_bytes())
        .map(|&(seq, _, _)| seq)
}

/// Whether `cap` carries `GRANT`.
fn grants(cap: u64) -> bool
{
    syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS)
        .is_ok_and(|info| info & syscall::RIGHTS_EP_GRANT != 0)
}

/// Subscriptions on both pools, the signal, the ascending walk with and
/// without the filter, the stale epoch, the full pool and the end of a
/// subscription by its token's deletion (module documentation).
fn logd_follow_phase(caps: &Caps)
{
    assert_ne!(caps.logd_query, 0, "logd_follow: no logd.query seed");
    assert_ne!(caps.logd_follow, 0, "logd_follow: no logd.follow seed");
    assert_ne!(caps.logd_control, 0, "logd_follow: no logd.control seed");
    assert!(
        grants(caps.logd_query) && grants(caps.logd_follow),
        "logd_follow: logd.query and logd.follow must carry GRANT"
    );
    assert!(
        !grants(caps.logd_control),
        "logd_follow: logd.control must not carry GRANT"
    );

    // Neither authority: refused before the request's capabilities are read.
    let denied = logd_query_call(
        caps.logd_control,
        &IpcMessage::builder(ipc::log_labels::LOG_SUBSCRIBE)
            .word(0, u64::from(ipc::LOG_LABELS_VERSION))
            .build(),
    );
    assert_eq!(
        reply_status(denied.label),
        QUERY_DENIED,
        "logd_follow: LOG_SUBSCRIBE without an authority not refused ({:#x})",
        denied.label
    );

    // A signal without the notify right: refused, and logd keeps no copy.
    let mut invalid = Subscriber::new();
    assert_eq!(
        invalid
            .subscribe_with(caps.logd_query, syscall::RIGHTS_NTF_WAIT)
            .err(),
        Some(QUERY_INVALID),
        "logd_follow: a signal without the notify right not refused"
    );
    assert!(
        invalid.signal_sole(),
        "logd_follow: logd kept the signal of a refused subscription"
    );
    // A request with a capability more than the signal: refused, and logd
    // keeps neither.
    let other = notification();
    let two = IpcMessage::builder(ipc::log_labels::LOG_SUBSCRIBE)
        .word(0, u64::from(ipc::LOG_LABELS_VERSION))
        .cap(invalid.signal_copy(syscall::RIGHTS_NTF_NOTIFY))
        .cap(
            syscall::cap_derive(other, syscall::RIGHTS_NTF_NOTIFY)
                .unwrap_or_else(|e| panic!("logd_follow: derive failed ({e})")),
        )
        .build();
    assert_eq!(
        Subscribed::decode(&logd_query_call(caps.logd_query, &two)).err(),
        Some(QUERY_INVALID),
        "logd_follow: a request with two capabilities not refused"
    );
    assert!(
        invalid.signal_sole()
            && syscall::cap_info(other, syscall::CAP_INFO_SOLE_REFERENCE) == Ok(1),
        "logd_follow: logd kept a capability of a refused subscription"
    );
    let _ = syscall::cap_delete(other);
    invalid.end();

    let mut follower = Subscriber::new();
    let sub = follower
        .subscribe(caps.logd_query)
        .unwrap_or_else(|s| panic!("logd_follow: LOG_SUBSCRIBE on logd.query refused ({s})"));
    assert!(
        sub.index < SUBSCRIBERS_MAX && sub.epoch != 0 && sub.oldest <= sub.next,
        "logd_follow: subscription reply {sub:?}"
    );
    check_follow(caps.logd_query, &follower, sub);
    check_pools(caps);
    follower.end();
    std::os::seraph::log!("logd_follow: subscribers signalled, read ascending, and ended");
}

/// Log the two lines, wait for the signal, and read them back from the
/// subscription's next `seq`, with and without the filter, and refused on
/// another epoch.
fn check_follow(query: u64, follower: &Subscriber, sub: Subscribed)
{
    std::os::seraph::log!("{INFO_LINE}");
    std::os::seraph::log!(warn: "{WARN_LINE}");
    let deadline = Instant::now()
        .checked_add(LOGD_WAIT)
        .expect("logd_follow: deadline overflowed");
    let entries = loop
    {
        let left = deadline.saturating_duration_since(Instant::now());
        let left_ms = u64::try_from(left.as_millis()).unwrap_or(u64::MAX).max(1);
        let waited = syscall::notification_wait_timeout(follower.signal, left_ms);
        assert!(
            waited.is_ok_and(|bits| bits & 1 != 0),
            "logd_follow: no signal within {LOGD_WAIT:?} ({waited:?})"
        );
        let entries = read_up(query, sub.next, sub.epoch, None)
            .unwrap_or_else(|s| panic!("logd_follow: ascending walk refused ({s})"));
        if seq_of(&entries, WARN_LINE).is_some()
        {
            break entries;
        }
    };
    assert!(
        entries
            .windows(2)
            .all(|pair| matches!(pair, [a, b] if a.0 < b.0)),
        "logd_follow: the ascending walk is not in seq order"
    );
    let info = seq_of(&entries, INFO_LINE).expect("logd_follow: informational line not read");
    let warn = seq_of(&entries, WARN_LINE).expect("logd_follow: warning line not read");
    assert!(
        sub.next <= info && info < warn,
        "logd_follow: lines at {info} and {warn}, subscribed at {}",
        sub.next
    );

    let warn_level = u8::try_from(LEVEL_WARN).expect("level fits a byte");
    let filtered = read_up(query, sub.next, sub.epoch, Some(warn_level))
        .unwrap_or_else(|s| panic!("logd_follow: filtered walk refused ({s})"));
    assert!(
        seq_of(&filtered, WARN_LINE) == Some(warn) && seq_of(&filtered, INFO_LINE).is_none(),
        "logd_follow: the filter at warning kept the informational line or lost the warning"
    );
    assert!(
        filtered.iter().all(|&(_, level, _)| level <= warn_level),
        "logd_follow: the filter at warning passed a less severe entry"
    );

    assert_eq!(
        read_up(query, sub.next, sub.epoch.wrapping_add(1), None).err(),
        Some(QUERY_STALE),
        "logd_follow: a walk on another epoch not refused"
    );
}

/// Fill the `logd.follow` pool beside the `logd.query` subscription, require
/// the next refused `QUERY_FULL` with its capabilities deleted, and require a
/// subscription again once one token is deleted.
fn check_pools(caps: &Caps)
{
    let mut sinks: Vec<Subscriber> = (0..SINK_SUBSCRIBERS_MAX)
        .map(|_| {
            let mut sink = Subscriber::new();
            let sub = sink.subscribe(caps.logd_follow).unwrap_or_else(|s| {
                panic!("logd_follow: LOG_SUBSCRIBE on logd.follow refused ({s})")
            });
            assert!(
                (SUBSCRIBERS_MAX..SUBSCRIBERS_MAX + SINK_SUBSCRIBERS_MAX).contains(&sub.index),
                "logd_follow: logd.follow subscription at index {}",
                sub.index
            );
            sink
        })
        .collect();
    let mut extra = Subscriber::new();
    assert_eq!(
        extra.subscribe(caps.logd_follow).err(),
        Some(QUERY_FULL),
        "logd_follow: a subscription past the logd.follow pool not refused"
    );
    assert!(
        extra.signal_sole(),
        "logd_follow: logd kept the signal of a refused subscription"
    );

    sinks
        .pop()
        .expect("logd_follow: the pool's subscribers")
        .end();
    let deadline = Instant::now()
        .checked_add(LOGD_WAIT)
        .expect("logd_follow: deadline overflowed");
    loop
    {
        match extra.subscribe(caps.logd_follow)
        {
            Ok(_) => break,
            Err(QUERY_FULL) if Instant::now() < deadline => std::thread::sleep(POLL),
            Err(status) => panic!(
                "logd_follow: no logd.follow subscription within {LOGD_WAIT:?} of a token's \
                 deletion ({status})"
            ),
        }
    }
    sinks.push(extra);
    for sink in sinks
    {
        sink.end();
    }
}

/// One `SINK_LIST` walk on `cap`: each sink's (name, settings, state, cursor).
fn sink_list(cap: u64) -> Result<Vec<(String, String, u8, u64)>, u64>
{
    let mut sinks = Vec::new();
    for index in 0u64..
    {
        let reply = logd_query_call(cap, &list_request(index));
        let Some((view, more)) = decode_list_reply(&reply)?
        else
        {
            break;
        };
        sinks.push((
            String::from_utf8_lossy(view.name).into_owned(),
            String::from_utf8_lossy(view.settings).into_owned(),
            view.state,
            view.cursor,
        ));
        if !more
        {
            break;
        }
    }
    Ok(sinks)
}

/// The settings and the cursor `SINK_LIST` reports for the sink `name`.
fn listed(cap: u64, name: &str) -> (String, u64)
{
    sink_list(cap)
        .unwrap_or_else(|s| panic!("logd_control: SINK_LIST refused ({s})"))
        .into_iter()
        .find(|(n, _, _, _)| n == name)
        .map_or_else(
            || panic!("logd_control: no {name} sink listed"),
            |(_, settings, _, cursor)| (settings, cursor),
        )
}

/// The settings `SINK_LIST` reports for the sink `name`.
fn settings_of(cap: u64, name: &str) -> String
{
    listed(cap, name).0
}

/// The line the phase logs while the framebuffer sink is `off`.
const OFF_LINE: &str = "logd_control: a line while the framebuffer sink is off";

/// Turn `sink` `off`, log [`OFF_LINE`], and set it back to `on`, its
/// settings before: the cursor `SINK_LIST` reports must be past the line.
fn check_turned_on(caps: &Caps, sink: &str, on: &str)
{
    assert!(
        !on.starts_with("level=off"),
        "logd_control: {sink} is off before the phase: {on}"
    );
    assert_eq!(
        sink_set(caps.logd_control, sink, "level=off"),
        QUERY_OK,
        "logd_control: SINK_SET {sink} level=off refused"
    );
    std::os::seraph::log!("{OFF_LINE}");
    let mut off_seq = None;
    super::procmgr::logd_history_each(caps.logd_query, None, |entry| {
        if entry.bytes == OFF_LINE.as_bytes()
        {
            off_seq = Some(entry.seq);
        }
        off_seq.is_none()
    });
    let off_seq = off_seq.expect("logd_control: the line logged while off not read");
    assert_eq!(
        sink_set(caps.logd_control, sink, on),
        QUERY_OK,
        "logd_control: SINK_SET {sink} back to {on} refused"
    );
    let (settings, cursor) = listed(caps.logd_control, sink);
    assert!(
        settings == on && cursor > off_seq,
        "logd_control: {sink} turned on at {settings} with its cursor at {cursor}, not past the \
         line logged while off at {off_seq}"
    );
}

/// `SINK_SET` on `cap`: its status.
fn sink_set(cap: u64, name: &str, settings: &str) -> u64
{
    let msg = SetRequest {
        name: name.as_bytes(),
        settings: settings.as_bytes(),
    }
    .message()
    .expect("logd_control: SINK_SET request within its limits");
    reply_status(logd_query_call(cap, &msg).label)
}

/// The sink control labels' authority, listing, refusals, and a level set and
/// set back (module documentation).
fn logd_control_phase(caps: &Caps)
{
    const SINK: &str = "framebuffer";
    const LEVEL: &str = "level=error";

    assert_ne!(caps.logd_control, 0, "logd_control: no logd.control seed");
    assert_ne!(caps.logd_query, 0, "logd_control: no logd.query seed");
    assert_eq!(
        sink_list(caps.logd_query).err(),
        Some(QUERY_DENIED),
        "logd_control: SINK_LIST on logd.query not refused"
    );
    assert_eq!(
        sink_set(caps.logd_query, SINK, LEVEL),
        QUERY_DENIED,
        "logd_control: SINK_SET on logd.query not refused"
    );

    let sinks = sink_list(caps.logd_control)
        .unwrap_or_else(|s| panic!("logd_control: SINK_LIST refused ({s})"));
    let names: Vec<&str> = sinks.iter().map(|(name, _, _, _)| name.as_str()).collect();
    assert_eq!(names, ["serial", SINK], "logd_control: sinks listed");
    assert!(
        sinks
            .iter()
            .all(|(_, settings, _, _)| settings.starts_with("level=")),
        "logd_control: settings not in the recipe's syntax: {sinks:?}"
    );
    assert!(
        matches!(sinks.first(), Some((_, _, SINK_SERVED | SINK_STALLED, _))),
        "logd_control: the serial sink is not served: {sinks:?}"
    );

    let before = settings_of(caps.logd_control, SINK);
    assert_eq!(
        sink_set(caps.logd_control, "no-such-sink", LEVEL),
        QUERY_NO_SINK,
        "logd_control: SINK_SET on an unknown sink not refused"
    );
    assert_eq!(
        sink_set(caps.logd_control, SINK, "level=loudest"),
        QUERY_INVALID,
        "logd_control: SINK_SET with a value its key does not take not refused"
    );
    assert_eq!(
        settings_of(caps.logd_control, SINK),
        before,
        "logd_control: a refused SINK_SET changed the settings"
    );

    assert_eq!(
        sink_set(caps.logd_control, SINK, LEVEL),
        QUERY_OK,
        "logd_control: SINK_SET {SINK} {LEVEL} refused"
    );
    let set = settings_of(caps.logd_control, SINK);
    let recorded = format!("{SINK}: settings set to {LEVEL}");
    let mut noticed = false;
    super::procmgr::logd_history_each(
        caps.logd_query,
        Some(ipc::log_badges::LOG_BADGE_LOGD),
        |entry| {
            noticed = entry.bytes == recorded.as_bytes();
            !noticed
        },
    );
    assert_eq!(
        sink_set(caps.logd_control, SINK, &before),
        QUERY_OK,
        "logd_control: SINK_SET {SINK} back to {before} refused"
    );
    assert!(
        set.starts_with(&format!("{LEVEL},")),
        "logd_control: {SINK} settings after the set: {set}"
    );
    assert!(noticed, "logd_control: logd recorded no line of the set");
    assert_eq!(
        settings_of(caps.logd_control, SINK),
        before,
        "logd_control: {SINK} settings not set back"
    );
    check_turned_on(caps, SINK, &before);
    std::os::seraph::log!("logd_control: sinks listed, steered and set back");
}
