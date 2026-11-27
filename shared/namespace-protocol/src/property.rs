// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/namespace-protocol/src/property.rs

//! The contract of this crate's parsers of hostile input as one property over
//! any input, [`namespace_protocol_holds`], which the fuzz target
//! `namespace-protocol` (`xtask/fuzz/targets`) drives, the replay test of the
//! checked-in inputs under `fuzz/namespace-protocol/` runs on every
//! `cargo xtask test`, and the proofs of `badge.rs`, `gate.rs`, `name.rs`,
//! `lib.rs` and `client.rs` check on every input up to their bounds
//! (docs/testing.md § Fuzzing, § Bounded verification).
//!
//! A server decodes a client's request: the label and the kernel-delivered
//! badge through [`gate`] and [`gate_open`], an `NS_LOOKUP`'s rights word
//! through [`compose_forward_lookup_rights`] when it forwards the lookup, and
//! its path through `lookup_path`, which checks each component with
//! [`validate_name`]. A client decodes a server's `NS_LOOKUP` reply through
//! [`PathWalk::advance`]. Each check states the contract from `README.md`
//! (§ Badge shape, § `NS_LOOKUP`, § Names, § Rights) by its own reading of
//! the bits and bytes, never through the code it checks, save that a check
//! of a walk runs the walk's step, which a check of its own holds to its
//! contract.

use ipc::IpcMessage;
use syscall_abi::MSG_DATA_WORDS_MAX;

use crate::badge::{
    NodeId, OpenRef, is_kind_flagged, is_open_instance, open_ref, pack, pack_open, pack_session,
    session_id, unpack,
};
use crate::client::{PathWalk, StepError, consumed_in_range};
use crate::gate::{GateError, compose_forward_lookup_rights, gate, gate_open};
use crate::name::{NameError, NameScan, name_char, validate_name};
use crate::rights::{self, NamespaceRights};
use crate::{
    MAX_LOOKUP_PATH_LEN, NodeKind, NsError, PathScan, WalkError, lookup_path, path_components,
    request_path,
};

/// The most words an input is read as: a label, a badge, and the data words
/// a message carries.
pub(crate) const MAX_WORDS: usize = 2 + MSG_DATA_WORDS_MAX;

/// Badge bits 0..40: a node cap's `NodeId`, and the low bits of a
/// kind-flagged badge's identifier (README § Badge shape).
const LOW_ID_MASK: u64 = (1 << 40) - 1;

/// The defined rights bits, rights-field bits 0..8 (README § Rights).
const DEFINED_RIGHTS: u64 = 0xFF;

/// The longest name README § Names allows.
const NAME_MAX: usize = 255;

/// Check the parsers' contract on `input`, read as up to [`MAX_WORDS`]
/// little-endian words, a last partial word zero-padded: a label, a badge,
/// then the data words of a request; and as a name and a client's path.
///
/// # Panics
///
/// When a parser breaks its contract on `input`: a defect of the parser.
pub fn namespace_protocol_holds(input: &[u8])
{
    let mut words = [0u64; MAX_WORDS];
    for (word, chunk) in words.iter_mut().zip(input.chunks(8))
    {
        let mut le = [0u8; 8];
        le.iter_mut().zip(chunk).for_each(|(dst, &src)| *dst = src);
        *word = u64::from_le_bytes(le);
    }
    let words = words
        .get(..input.len().div_ceil(8).min(MAX_WORDS))
        .unwrap_or_default();
    let label = words.first().copied().unwrap_or(0);
    let badge = words.get(1).copied().unwrap_or(0);
    let data = words.get(2..).unwrap_or_default();
    let first = data.first().copied().unwrap_or(0);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a rights mask is any u32: the label's low 32 bits"
    )]
    let rights = label as u32;
    gate_holds(label, badge);
    forward_rights_holds(badge, first);
    badge_holds(first, label, rights);
    let scan = NameScan {
        len: usize::try_from(label >> 1).unwrap_or(usize::MAX),
        dots_only: label & 1 == 1,
    };
    let path_scan = PathScan {
        component: badge,
        name: scan,
    };
    name_finish_holds(scan);
    path_finish_holds(path_scan);
    for start in 0..input.len()
    {
        let rest = input.get(start..).unwrap_or_default();
        name_char_holds(rest);
        name_step_holds(scan, rest);
        path_step_holds(path_scan, rest);
    }
    lookup_path_holds(label, data);
    name_holds(input);
    walk_holds(input, words);
}

/// The width of the UTF-8 character `bytes` starts with, by core's UTF-8
/// check (`core::str::from_utf8`) of its first four bytes, the most one
/// character holds; `None` when `bytes` starts with none.
fn utf8_width(bytes: &[u8]) -> Option<usize>
{
    let window = bytes.get(..4).unwrap_or(bytes);
    let valid = match core::str::from_utf8(window)
    {
        Ok(text) => text,
        Err(error) => window
            .get(..error.valid_up_to())
            .and_then(|prefix| core::str::from_utf8(prefix).ok())
            .unwrap_or_default(),
    };
    valid.chars().next().map(char::len_utf8)
}

/// Whether `bytes` is UTF-8 throughout, by core's UTF-8 check.
fn is_utf8(bytes: &[u8]) -> bool
{
    core::str::from_utf8(bytes).is_ok()
}

/// Which of the rules of README § Names `name` breaks, each read alone.
#[derive(Copy, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one flag a rule, read together by the check of the result"
)]
struct NameRules
{
    empty: bool,
    too_long: bool,
    dots: bool,
    slash: bool,
    nul: bool,
    not_utf8: bool,
}

impl NameRules
{
    fn of(name: &[u8]) -> Self
    {
        Self {
            empty: name.is_empty(),
            too_long: name.len() > NAME_MAX,
            dots: name == b"." || name == b"..",
            slash: name.contains(&b'/'),
            nul: name.contains(&0),
            not_utf8: !is_utf8(name),
        }
    }

    fn all_kept(self) -> bool
    {
        !(self.empty || self.too_long || self.dots || self.slash || self.nul || self.not_utf8)
    }

    /// Whether `error` names a rule `name` breaks.
    fn names(self, error: NameError) -> bool
    {
        match error
        {
            NameError::Empty => self.empty,
            NameError::TooLong => self.too_long,
            NameError::DotOrDotDot => self.dots,
            NameError::ContainsSlash => self.slash,
            NameError::ContainsNul => self.nul,
            NameError::NotUtf8 => self.not_utf8,
        }
    }
}

/// [`validate_name`] of `name` keeps its contract (its doc, README
/// § Names): it accepts a name exactly when the name keeps every rule, and
/// refuses one with an error that names a rule the name breaks.
pub(crate) fn name_holds(name: &[u8])
{
    let rules = NameRules::of(name);
    match validate_name(name)
    {
        Ok(()) => assert!(rules.all_kept(), "a name that breaks a rule was accepted"),
        Err(error) =>
        {
            assert!(
                !rules.all_kept(),
                "a name that keeps every rule was refused"
            );
            assert!(rules.names(error), "a name was refused for a rule it keeps");
        }
    }
}

/// [`NameScan::step`] from `scan`, the scan of some bytes, over the
/// character `rest` starts with answers [`name_char`]'s judgement of it, and
/// on a character of width `w` the scan of those bytes and the `w` after
/// them: `w` more bytes, all dots when the bytes were and the character is
/// a `.`.
pub(crate) fn name_step_holds(scan: NameScan, rest: &[u8])
{
    let expected = name_char(rest).map(|width| {
        let character = rest.get(..width).unwrap_or_default();
        let after = NameScan {
            len: scan.len.saturating_add(width),
            dots_only: scan.dots_only && character.iter().all(|&byte| byte == b'.'),
        };
        (after, width)
    });
    assert_eq!(scan.step(rest), expected, "a name's scan stepped wrong");
}

/// [`NameScan::finish`] of the scan of a name refuses an empty name, then
/// one longer than `NAME_MAX`, then `.` and `..` (one or two bytes, all
/// dots), and accepts every other name.
pub(crate) fn name_finish_holds(scan: NameScan)
{
    let expected = if scan.len == 0
    {
        Err(NameError::Empty)
    }
    else if scan.len > NAME_MAX
    {
        Err(NameError::TooLong)
    }
    else if scan.dots_only && matches!(scan.len, 1 | 2)
    {
        Err(NameError::DotOrDotDot)
    }
    else
    {
        Ok(())
    };
    assert_eq!(scan.finish(), expected, "a name's end was misjudged");
}

/// [`name_char`] of `rest` answers the width of the UTF-8 character `rest`
/// starts with, by core's UTF-8 check, when that character is neither
/// `/` nor NUL; refuses `/` and NUL as such; and refuses a start that is
/// no UTF-8 character, an empty `rest` included.
pub(crate) fn name_char_holds(rest: &[u8])
{
    let expected = match (utf8_width(rest), rest.first())
    {
        (None, _) => Err(NameError::NotUtf8),
        (Some(_), Some(&b'/')) => Err(NameError::ContainsSlash),
        (Some(_), Some(&0)) => Err(NameError::ContainsNul),
        (Some(width), _) => Ok(width),
    };
    assert_eq!(name_char(rest), expected, "a character was misjudged");
}

/// The rights requirement README § Rights and § Rights gate give `opcode`:
/// the bits a badge must hold, `Some(0)` for a non-empty mask alone, and
/// `None` for an opcode no badged label has.
fn requirement(opcode: u64) -> Option<u32>
{
    use ipc::fs_labels::{
        FS_CLOSE, FS_CREATE, FS_MKDIR, FS_OPEN, FS_READ, FS_READ_MEMORY, FS_RELEASE_MEMORY,
        FS_REMOVE, FS_RENAME, FS_SESSION, FS_TRUNCATE, FS_WRITE, FS_WRITE_MEMORY,
    };
    use ipc::ns_labels::{NS_LOOKUP, NS_READDIR, NS_STAT};
    match opcode
    {
        NS_LOOKUP => Some(rights::LOOKUP),
        NS_READDIR => Some(rights::READDIR),
        NS_STAT => Some(rights::STAT),
        FS_READ | FS_READ_MEMORY => Some(rights::READ),
        FS_WRITE | FS_WRITE_MEMORY | FS_TRUNCATE => Some(rights::WRITE),
        FS_CREATE | FS_REMOVE | FS_MKDIR | FS_RENAME => Some(rights::MUTATE_DIR),
        FS_RELEASE_MEMORY | FS_CLOSE | FS_OPEN | FS_SESSION => Some(0),
        _ => None,
    }
}

/// A badge's fields as README § Badge shape lays them out.
#[derive(Copy, Clone)]
struct BadgeFields
{
    /// Bits 0..40.
    node: u64,
    /// The defined bits of the rights field, bits 40..48.
    rights: u32,
    /// Bit 48.
    open: bool,
    /// Bit 49.
    session: bool,
    /// Bits 0..40, then bits 50..64 as its bits 40..54.
    id: u64,
}

impl BadgeFields
{
    fn of(badge: u64) -> Self
    {
        // Masked to the eight defined bits, so the cast keeps every bit.
        let rights = ((badge >> 40) & DEFINED_RIGHTS) as u32;
        Self {
            node: badge & LOW_ID_MASK,
            rights,
            open: (badge >> 48) & 1 == 1,
            session: (badge >> 49) & 1 == 1,
            id: (badge & LOW_ID_MASK) | ((badge >> 50) << 40),
        }
    }
}

/// [`gate`] and [`gate_open`] of `label` and `badge` keep their contract
/// (their docs, README § Rights gate): each refuses a badge of another kind
/// first, then an opcode (the label's bits 0..16) no badged label has, then
/// rights that lack the opcode's requirement, and otherwise answers what the
/// badge names and its rights. The badge's kind tests agree with its flags.
pub(crate) fn gate_holds(label: u64, badge: u64)
{
    let fields = BadgeFields::of(badge);
    let granted = requirement(label & 0xFFFF).map(|need| {
        if need == 0
        {
            fields.rights != 0
        }
        else
        {
            fields.rights & need == need
        }
    });
    let checked = |kind_ok: bool| match granted
    {
        _ if !kind_ok => Err(GateError::WrongKind),
        None => Err(GateError::UnknownLabel),
        Some(false) => Err(GateError::PermissionDenied),
        Some(true) => Ok(()),
    };
    let node_kind = !fields.open && !fields.session;
    let open_kind = fields.open && !fields.session;
    assert_eq!(
        gate(label, badge).map(|(node, rights)| (node.raw(), rights.raw())),
        checked(node_kind).map(|()| (fields.node, fields.rights)),
        "a node badge's request was gated against its label and rights"
    );
    assert_eq!(
        gate_open(label, badge).map(|(open, rights)| (open, rights.raw())),
        checked(open_kind).map(|()| (OpenRef(fields.id), fields.rights)),
        "an open badge's request was gated against its label and rights"
    );
    assert_eq!(
        session_id(badge),
        (fields.session && !fields.open).then_some(fields.id),
        "a session badge was read against its flags"
    );
    assert_eq!(is_kind_flagged(badge), !node_kind);
    assert_eq!(is_open_instance(badge), fields.open);
}

/// [`compose_forward_lookup_rights`] of `badge` and the rights word `word`
/// is the badge's rights and the word's requested rights in common: the
/// word's defined bits, or every defined bit for the `0xFFFF` sentinel
/// (README § `NS_LOOKUP`). So a forwarded lookup asks for no right the
/// badge lacks.
pub(crate) fn forward_rights_holds(badge: u64, word: u64)
{
    let requested = if word == 0xFFFF
    {
        DEFINED_RIGHTS
    }
    else
    {
        word & DEFINED_RIGHTS
    };
    let held = u64::from(BadgeFields::of(badge).rights);
    assert_eq!(
        u64::from(compose_forward_lookup_rights(badge, word)),
        held & requested,
        "a forwarded lookup asked for other rights than the caller's request within its badge"
    );
}

/// The badge encoders keep their contract with the decoders (their docs,
/// README § Badge shape): [`pack`] of a node and rights decodes to the node's
/// low 40 bits and the rights' defined bits, with no kind flag; [`pack_open`]
/// and [`pack_session`] take exactly the non-zero identifiers of up to 54
/// bits, and their badges decode to the identifier and, for an open, its
/// rights, with their own kind flag alone.
pub(crate) fn badge_holds(node: u64, id: u64, rights_raw: u32)
{
    let rights = NamespaceRights::from_raw(rights_raw);
    let defined = rights_raw & 0xFF;
    assert_eq!(
        rights.raw(),
        defined,
        "a rights mask kept a bit no right has"
    );
    let node_badge = pack(NodeId::from_raw_truncated(node), rights);
    let (decoded_node, decoded_rights) = unpack(node_badge);
    assert_eq!(
        (decoded_node.raw(), decoded_rights.raw()),
        (node & LOW_ID_MASK, defined),
        "a node badge decoded to another node or rights"
    );
    assert!(
        !is_kind_flagged(node_badge),
        "a node badge carries a kind flag"
    );
    let fits = id != 0 && id >> 54 == 0;
    let open = pack_open(id, rights);
    assert_eq!(
        open.is_some(),
        fits,
        "an open id was packed against its range"
    );
    if let Some(open) = open
    {
        assert_eq!(
            open_ref(open),
            Some(OpenRef(id)),
            "an open badge lost its id"
        );
        assert_eq!(
            unpack(open).1.raw(),
            defined,
            "an open badge lost its rights"
        );
        assert_eq!(session_id(open), None, "an open badge read as a session");
    }
    let session = pack_session(id);
    assert_eq!(
        session.is_some(),
        fits,
        "a session id was packed against its range"
    );
    if let Some(session) = session
    {
        assert_eq!(session_id(session), Some(id), "a session badge lost its id");
        assert_eq!(open_ref(session), None, "a session badge read as an open");
        assert!(
            unpack(session).1.is_empty(),
            "a session badge carries rights"
        );
    }
}

/// [`request_path`] of `label` and the data bytes `data` is the
/// `path_len` bytes after the 8-byte rights word, `path_len` the label's
/// bits 16..32, exactly when `path_len` is 1 to [`MAX_LOOKUP_PATH_LEN`] and
/// the data hold that many bytes after the rights word (README
/// § `NS_LOOKUP`).
pub(crate) fn request_path_holds(label: u64, data: &[u8])
{
    let len = usize::try_from((label >> 16) & 0xFFFF).unwrap_or(usize::MAX);
    let fits = (1..=MAX_LOOKUP_PATH_LEN).contains(&len) && data.len() >= len.saturating_add(8);
    match request_path(label, data)
    {
        Some(path) =>
        {
            assert!(fits, "a path past its bounds was taken");
            assert!(
                path.len() == len
                    && data
                        .get(8..)
                        .is_some_and(|rest| rest.as_ptr() == path.as_ptr()),
                "a path was cut from other bytes"
            );
        }
        None => assert!(!fits, "a path inside its bounds was refused"),
    }
}

/// `lookup_path` of an `NS_LOOKUP` request with `label` and the data words
/// `data` keeps its contract (its doc, README § `NS_LOOKUP`): it refuses
/// at component 0 a request whose path [`request_path`] refuses, and
/// otherwise answers the path when [`path_components`] takes it and that
/// check's error when it does not.
pub(crate) fn lookup_path_holds(label: u64, data: &[u64])
{
    let data = data.get(..MSG_DATA_WORDS_MAX).unwrap_or(data);
    let message = IpcMessage::builder(label).words(0, data).build();
    let bytes = message.data_bytes();
    request_path_holds(label, bytes);
    let expected = request_path(label, bytes).map_or(
        Err(WalkError {
            error: NsError::InvalidName,
            component: 0,
        }),
        |path| {
            components_holds(path);
            path_components(path).map(|()| path)
        },
    );
    let decoded = lookup_path(&message);
    assert_eq!(
        decoded.map(<[u8]>::as_ptr),
        expected.map(<[u8]>::as_ptr),
        "a lookup's path was misjudged"
    );
}

/// [`path_components`] of `path` refuses, at its index, the first component
/// (split at each `/`) that [`validate_name`], its step, refuses, and takes
/// the path when every component passes. [`name_holds`] holds the step to
/// its own contract.
pub(crate) fn components_holds(path: &[u8])
{
    let mut expected = Ok(());
    let mut component = 0u64;
    let mut start = 0;
    // The components are the runs between the path's ends and its `/`s.
    for end in 0..=path.len()
    {
        if end < path.len() && path.get(end) != Some(&b'/')
        {
            continue;
        }
        let name = path.get(start..end).unwrap_or_default();
        if validate_name(name).is_err()
        {
            expected = Err(WalkError {
                error: NsError::InvalidName,
                component,
            });
            break;
        }
        component = component.saturating_add(1);
        start = end.saturating_add(1);
    }
    assert_eq!(
        path_components(path),
        expected,
        "a lookup's components were misjudged"
    );
}

/// [`PathScan::step`] from `scan` over the character `rest` starts with:
/// a `/` ends the component, whose name [`NameScan::finish`] judges, and
/// starts the next one's name; any other character steps the component's
/// name as [`NameScan::step`] does. A refusal is `InvalidName` at the
/// component.
pub(crate) fn path_step_holds(scan: PathScan, rest: &[u8])
{
    let at = |_| WalkError {
        error: NsError::InvalidName,
        component: scan.component,
    };
    let expected = if rest.first() == Some(&b'/')
    {
        scan.name.finish().map_err(at).map(|()| {
            let next = PathScan {
                component: scan.component.saturating_add(1),
                name: NameScan::START,
            };
            (next, 1)
        })
    }
    else
    {
        scan.name.step(rest).map_err(at).map(|(name, width)| {
            let next = PathScan {
                component: scan.component,
                name,
            };
            (next, width)
        })
    };
    assert_eq!(scan.step(rest), expected, "a path's scan stepped wrong");
}

/// [`PathScan::finish`] judges the last component's name as
/// [`NameScan::finish`] does, a refusal being `InvalidName` at the
/// component.
pub(crate) fn path_finish_holds(scan: PathScan)
{
    let expected = scan.name.finish().map_err(|_| WalkError {
        error: NsError::InvalidName,
        component: scan.component,
    });
    assert_eq!(scan.finish(), expected, "a path's end was misjudged");
}

/// The components of `path` a client walks, the empty ones skipped.
fn components(path: &[u8]) -> impl Iterator<Item = &[u8]>
{
    path.split(|&byte| byte == b'/')
        .filter(|component| !component.is_empty())
}

/// A client's walk of `path` keeps its contract (README § `NS_LOOKUP`, The
/// client's walk; [`PathWalk`]'s docs) against the replies `replies`, read
/// in pairs of a consumed count and a kind, each the reply to the walk's next
/// request: each request carries the next components joined by single `/`,
/// as many whole ones as fit [`MAX_LOOKUP_PATH_LEN`] bytes; a reply whose
/// count is zero or more than its request carried is refused and leaves the
/// walk where it was; any other advances the walk past exactly that many
/// components, and is refused when components remain after an entry that is
/// not a directory.
pub(crate) fn walk_holds(path: &[u8], replies: &[u64])
{
    let mut walk = PathWalk::new(path);
    let mut consumed = 0usize;
    for &[count, kind] in replies.as_chunks::<2>().0
    {
        assert!(
            walk.components().eq(components(path).skip(consumed)),
            "the walk holds other components than the path's unconsumed ones"
        );
        let Some(request) = walk.request()
        else
        {
            let next = components(path).nth(consumed);
            assert!(
                next.is_none_or(|name| name.len() > MAX_LOOKUP_PATH_LEN),
                "a walk with a component that fits a request made none"
            );
            return;
        };
        request_holds(path, consumed, &request);
        let carried = request.components();
        consumed_holds(count, carried);
        let before = walk;
        let result = walk.advance(&request, count, kind);
        if count == 0 || count > carried
        {
            assert_eq!(result, Err(StepError::ConsumedOutOfRange));
            assert!(
                walk.components().eq(before.components()),
                "a refused reply moved the walk"
            );
            continue;
        }
        consumed = consumed.saturating_add(usize::try_from(count).unwrap_or(usize::MAX));
        let remains = components(path).nth(consumed).is_some();
        let expected = if remains && kind != NodeKind::Dir as u64
        {
            Err(StepError::NotADirectory)
        }
        else
        {
            Ok(())
        };
        assert_eq!(result, expected, "a reply's kind was misjudged");
        stop_holds(&walk, kind);
    }
}

/// [`consumed_in_range`] takes a reply's count `consumed` exactly when it
/// is 1 to `carried`, the request's component count.
pub(crate) fn consumed_holds(consumed: u64, carried: u64)
{
    let expected = if (1..=carried).contains(&consumed)
    {
        Ok(())
    }
    else
    {
        Err(StepError::ConsumedOutOfRange)
    };
    assert_eq!(
        consumed_in_range(consumed, carried),
        expected,
        "a reply's count was misjudged"
    );
}

/// [`PathWalk::may_stop_at`] refuses an entry of `kind` other than a
/// directory when the walk has components left, and takes every other.
pub(crate) fn stop_holds(walk: &PathWalk<'_>, kind: u64)
{
    let remains = walk.components().next().is_some();
    let expected = if remains && kind != NodeKind::Dir as u64
    {
        Err(StepError::NotADirectory)
    }
    else
    {
        Ok(())
    };
    assert_eq!(
        walk.may_stop_at(kind),
        expected,
        "a reply's kind was misjudged"
    );
}

/// The request a walk of `path` makes after `consumed` components carries
/// the next ones joined by single `/`, as many as fit
/// [`MAX_LOOKUP_PATH_LEN`] bytes, and at least one, and its label is
/// `NS_LOOKUP` with its path's length in bits 16..32.
fn request_holds(path: &[u8], consumed: usize, request: &crate::client::LookupRequest)
{
    let sent = request.path();
    let carried = usize::try_from(request.components()).unwrap_or(usize::MAX);
    assert!(carried >= 1, "a request carries no component");
    assert!(
        sent.len() <= MAX_LOOKUP_PATH_LEN,
        "a request's path is too long"
    );
    assert!(
        sent.split(|&byte| byte == b'/')
            .eq(components(path).skip(consumed).take(carried)),
        "a request carries other components than the walk's next ones"
    );
    if let Some(next) = components(path).nth(consumed.saturating_add(carried))
    {
        assert!(
            sent.len().saturating_add(1).saturating_add(next.len()) > MAX_LOOKUP_PATH_LEN,
            "a request left out a component that fits"
        );
    }
    let len = u64::try_from(sent.len()).unwrap_or(u64::MAX);
    assert_eq!(
        request.label(),
        ipc::ns_labels::NS_LOOKUP | (len << 16),
        "a request's label names another length"
    );
}
