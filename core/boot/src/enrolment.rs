// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/enrolment.rs

//! The trust store enrolled in firmware storage, and the change requests
//! that alter it without a rebuild of the bootloader
//! ([docs/signing.md](../../../docs/signing.md) § Trust Store).
//!
//! The enrolled store (`objsig::enrol::EnrolledStore`) is one UEFI
//! variable, [`STORE_VARIABLE`] under [`SERAPH_VENDOR_GUID`], non-volatile and
//! reachable by boot services alone. [`read_enrolled`] reads it before any
//! object is loaded, and refuses the boot when it is malformed: a boot past
//! it would drop the revocations it holds. The boot verifies with, and hands
//! procmgr, the built-in store merged with it (`objsig::enrol::merge`), and
//! [`log_store`] logs every anchor of that store with its source.
//!
//! A change request on the ESP, `\EFI\seraph\trust-request`, is decided by
//! [`decide`] once the kernel and the bundle are read and before either is
//! verified for loading. A request that would change nothing is skipped; one
//! that would pass the enrolled store's bound, or under whose resulting store
//! the kernel or a bundle entry does not verify, is refused. Otherwise it is
//! applied when the current store verifies it in the enrolment role under
//! `trust-request`, or when someone at the console confirms it after seeing
//! each change. The new store is written through [`VariableServices`] before
//! the security floor, so no variable call follows the memory-map reads
//! ([core/boot/docs/uefi-environment.md](../docs/uefi-environment.md)
//! § Variable Services).

use objsig::enrol::{
    Applied, ApplyError, EnrolError, EnrolledStore, MAX_ANCHORS, MAX_REVOKED, REQUEST_NAME,
    TrustRequest, apply, merge,
};
use objsig::{
    EncodeError, Expectation, KeyId, ParseError, Refusal, Role, RoleSet, TrustStore, split, verify,
};

use crate::bprintln;
use crate::error::BootError;
use crate::signing::{ARCH, KeyIdHex};
use crate::uefi::{
    ConsoleInput, EFI_VARIABLE_BOOTSERVICE_ACCESS, EFI_VARIABLE_NON_VOLATILE, EfiStatus, LineRead,
    SERAPH_VENDOR_GUID, VariableInfo, VariableRead, VariableServices,
};

/// `TrustStore` as a NUL-terminated UTF-16 variable name.
// rustfmt::skip keeps the UTF-16 code units in rows of five, which rustfmt would
// spread one per line.
#[rustfmt::skip]
pub static STORE_VARIABLE: [u16; 11] = [
    b'T' as u16, b'r' as u16, b'u' as u16, b's' as u16, b't' as u16,
    b'S' as u16, b't' as u16, b'o' as u16, b'r' as u16, b'e' as u16,
    0u16,
];

/// The enrolled store variable's attributes, exactly: kept across resets,
/// reachable before `ExitBootServices` alone. A variable that carries any
/// other set was not written by a bootloader, and is malformed.
pub const STORE_ATTRIBUTES: u32 = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS;

/// The seconds the console waits for a confirmation; the timeout is a no.
pub const CONFIRM_SECONDS: u64 = 60;

/// The answer that confirms a request, typed and followed by Enter.
pub const CONFIRMATION: &[u8] = b"yes";

/// The longest request file the bootloader reads, 64 KiB: a request the
/// bound admits, with a trailer of the most records a signed object holds,
/// fits many times over.
pub const REQUEST_MAX_LEN: usize = 64 * 1024;

/// How the enrolled store variable is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed
{
    /// It carries these attributes, not [`STORE_ATTRIBUTES`].
    Attributes(u32),
    /// It holds this many bytes, more than the longest enrolled store.
    Length(usize),
    /// Its bytes are no enrolled store.
    Format(EnrolError),
    /// It does not merge with the built-in store into a trust store.
    Merge,
}

impl core::fmt::Display for Malformed
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self
        {
            Malformed::Attributes(attributes) => write!(
                f,
                "attributes {attributes:#x}, not {STORE_ATTRIBUTES:#x} (non-volatile, boot services alone)"
            ),
            Malformed::Length(len) => write!(
                f,
                "{len} bytes, more than the {} of the longest enrolled store",
                objsig::enrol::MAX_STORE_LEN
            ),
            Malformed::Format(err) => write!(f, "{err:?}"),
            Malformed::Merge => f.write_str("it does not merge with the built-in trust store"),
        }
    }
}

/// The enrolled store, as the variable gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enrolled<'a>
{
    /// The variable holds this store; an absent one is the empty store.
    Store(EnrolledStore<'a>),
    /// The firmware failed the read with this status: the boot runs on the
    /// built-in store and applies no request.
    Unavailable(EfiStatus),
}

impl<'a> Enrolled<'a>
{
    /// The store the boot merges: an unreadable one is the empty store.
    #[must_use]
    pub const fn store(&self) -> EnrolledStore<'a>
    {
        match self
        {
            Enrolled::Store(store) => *store,
            Enrolled::Unavailable(_) => EnrolledStore::EMPTY,
        }
    }
}

/// The enrolled store from what `GetVariable` returned into `buffer`.
///
/// # Errors
/// [`Malformed`] when the variable carries other attributes than
/// [`STORE_ATTRIBUTES`], is longer than `buffer`, or does not parse.
pub fn decode(read: VariableRead, buffer: &[u8]) -> Result<Enrolled<'_>, Malformed>
{
    match read
    {
        VariableRead::NotFound => Ok(Enrolled::Store(EnrolledStore::EMPTY)),
        VariableRead::Failed(status) => Ok(Enrolled::Unavailable(status)),
        VariableRead::TooLarge { len } => Err(Malformed::Length(len)),
        VariableRead::Found { attributes, .. } if attributes != STORE_ATTRIBUTES =>
        {
            Err(Malformed::Attributes(attributes))
        }
        VariableRead::Found { len, .. } =>
        {
            let bytes = buffer.get(..len).ok_or(Malformed::Length(len))?;
            EnrolledStore::parse(bytes)
                .map(Enrolled::Store)
                .map_err(Malformed::Format)
        }
    }
}

/// The length of the longest trust store `builtin` merged with an enrolled
/// store gives: the buffer [`merge_current`] and [`Scratch::effective`]
/// each need. Counts past a trust store's fields saturate the length, which
/// no allocation then meets.
#[must_use]
pub fn merged_capacity(builtin: &TrustStore<'_>) -> usize
{
    TrustStore::encoded_len(
        builtin.anchors().count().saturating_add(MAX_ANCHORS),
        builtin.revoked().len().saturating_add(MAX_REVOKED),
    )
    .unwrap_or(usize::MAX)
}

/// Merge `builtin` with `enrolled` into `out`, [`merged_capacity`] bytes:
/// the store the boot runs on unless a request is applied.
///
/// # Errors
/// [`BootError::EnrolledMalformed`] when the two do not merge into a trust
/// store.
pub fn merge_current<'o>(
    builtin: &TrustStore<'_>,
    enrolled: &EnrolledStore<'_>,
    out: &'o mut [u8],
) -> Result<(TrustStore<'o>, &'o [u8]), BootError>
{
    let malformed = BootError::EnrolledMalformed(Malformed::Merge);
    let len = merge(builtin, enrolled, out).map_err(|_| malformed)?;
    let out: &'o [u8] = out;
    let bytes = out
        .get(..len)
        .ok_or(BootError::EnrolledMalformed(Malformed::Merge))?;
    let store =
        TrustStore::parse(bytes).map_err(|_| BootError::EnrolledMalformed(Malformed::Merge))?;
    Ok((store, bytes))
}

/// Read the enrolled store from `vars` into `buffer`, [`MAX_STORE_LEN`] bytes,
/// and log what was read, or the one warning of a read the firmware failed.
///
/// [`MAX_STORE_LEN`]: objsig::enrol::MAX_STORE_LEN
///
/// # Errors
/// [`BootError::EnrolledMalformed`] for a malformed variable.
pub fn read_enrolled<'b>(
    vars: &mut impl VariableServices,
    buffer: &'b mut [u8],
) -> Result<Enrolled<'b>, BootError>
{
    let read = vars.get(&STORE_VARIABLE, &SERAPH_VENDOR_GUID, buffer);
    let enrolled = decode(read, buffer).map_err(BootError::EnrolledMalformed)?;
    match enrolled
    {
        Enrolled::Store(store) => bprintln!(
            "[--------] boot: enrolled trust store: {} anchors, {} revoked key ids",
            store.anchors().count(),
            store.revoked().len()
        ),
        Enrolled::Unavailable(status) => bprintln!(
            "[--------] boot: WARNING: the firmware did not read the enrolled trust store \
             (status={status:#018x}); this boot runs on the built-in trust store and applies \
             no trust request"
        ),
    }
    Ok(enrolled)
}

/// Log every anchor of `effective`, the store the boot verifies with, with
/// its source (built in, when `builtin` holds its key id, else enrolled), and
/// mark one generated on the build machine and one whose key id is revoked;
/// then the store's counts and floor.
pub fn log_store(effective: &TrustStore<'_>, builtin: &TrustStore<'_>)
{
    let mut enrolled = 0usize;
    for anchor in effective.anchors()
    {
        let source = if builtin.anchor(&anchor.key_id).is_some()
        {
            "built in"
        }
        else
        {
            enrolled = enrolled.saturating_add(1);
            "enrolled"
        };
        let local = if anchor.local
        {
            ", locally generated"
        }
        else
        {
            ""
        };
        let revoked = if effective.is_revoked(&anchor.key_id)
        {
            ", revoked"
        }
        else
        {
            ""
        };
        bprintln!(
            "[--------] boot: trust anchor \"{}\" key id {}: {source}{local}{revoked}",
            anchor.label,
            KeyIdHex(&anchor.key_id),
        );
    }
    bprintln!(
        "[--------] boot: trust store: {} anchors ({enrolled} enrolled), {} revoked key ids, \
         security floor {}",
        effective.anchors().count(),
        effective.revoked().len(),
        effective.security_floor()
    );
}

/// The stores a request is decided against.
#[derive(Clone, Copy)]
pub struct Stores<'a>
{
    /// The store built into this bootloader.
    pub builtin: TrustStore<'a>,
    /// The enrolled store.
    pub enrolled: EnrolledStore<'a>,
    /// The two merged: the store the boot runs on unless a request is
    /// applied.
    pub current: TrustStore<'a>,
}

/// Where [`decide`] builds the new stores.
pub struct Scratch<'b>
{
    /// The new enrolled store: [`objsig::enrol::MAX_STORE_LEN`] bytes.
    pub enrolled: &'b mut [u8],
    /// The new effective store: `objsig::enrol::merged_len` of the built-in
    /// store and the longest enrolled one.
    pub effective: &'b mut [u8],
}

/// How a request was authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authorized
{
    /// The current store verified it in the enrolment role through the
    /// anchor of this key id.
    Signed(KeyId),
    /// Someone at the console typed the confirmation.
    Confirmed,
}

/// Why a request was not applied.
#[derive(Debug)]
pub enum Refused
{
    /// The file ends in a trailer that does not parse.
    Trailer(ParseError),
    /// The request does not parse.
    Request(EnrolError),
    /// The enrolled store would hold these counts, past its bound.
    Bound
    {
        anchors: usize, revoked: usize
    },
    /// A new store could not be built in its buffer.
    Build(EncodeError),
    /// The kernel or a bundle entry does not verify under the store the
    /// request would give.
    Commit(BootError),
    /// The answer at the console was not the confirmation.
    NotConfirmed,
    /// No answer came within [`CONFIRM_SECONDS`].
    Timeout,
    /// The console could not be read: the status of the failed call.
    NoConsole(EfiStatus),
    /// The firmware's largest variable is smaller than the new store's
    /// variable, its name and data: `needed` bytes.
    TooLarge
    {
        needed: usize, max_variable: u64
    },
    /// The firmware refused the write with `status`; `info` is what it
    /// reported of its store before the write, when it reported it.
    Write
    {
        status: EfiStatus,
        info: Option<VariableInfo>,
    },
}

impl core::fmt::Display for Refused
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self
        {
            Refused::Trailer(err) => write!(f, "its signature trailer does not parse ({err:?})"),
            Refused::Request(err) => write!(f, "it does not parse ({err:?})"),
            Refused::Bound { anchors, revoked } => write!(
                f,
                "the enrolled store would hold {anchors} anchors and {revoked} revoked key ids, \
                 past its bound of {MAX_ANCHORS} anchors and {MAX_REVOKED} revoked key ids"
            ),
            Refused::Build(err) => write!(f, "the new trust store could not be built ({err:?})"),
            Refused::Commit(err) => write!(
                f,
                "the boot set does not verify under the trust store it would give: {err}"
            ),
            Refused::NotConfirmed => f.write_str("it was not confirmed at the console"),
            Refused::Timeout => write!(f, "no confirmation came within {CONFIRM_SECONDS} seconds"),
            Refused::NoConsole(status) => write!(
                f,
                "it is not signed for enrolment and the console cannot be read \
                 (status={status:#018x})"
            ),
            Refused::TooLarge {
                needed,
                max_variable,
            } => write!(
                f,
                "the firmware's largest variable is {max_variable} bytes, and the enrolled store \
                 needs {needed}"
            ),
            Refused::Write { status, info } =>
            {
                write!(f, "the firmware refused the write (status={status:#018x})")?;
                if let Some(info) = info
                {
                    write!(
                        f,
                        "; its store reported {} of {} bytes free, largest variable {}",
                        info.remaining, info.max_storage, info.max_variable
                    )?;
                }
                Ok(())
            }
        }
    }
}

/// What [`decide`] did with a request.
#[derive(Debug)]
pub enum Outcome
{
    /// The request would change nothing (a replay): skipped, no prompt.
    Unchanged,
    /// The request was applied: the new enrolled store is written, and the
    /// boot runs on the new effective store, the first `len` bytes of
    /// [`Scratch::effective`].
    Applied
    {
        /// The new effective store's length.
        len: usize,
        /// What the request changed.
        change: Applied,
        /// How it was authorized.
        by: Authorized,
    },
    /// The request was refused: nothing was written, and the boot runs on
    /// the current store.
    Refused(Refused),
}

/// Decide the request `file` against `stores`, and apply it when it passes:
/// parse it, skip it when it would change nothing, refuse it past the bound,
/// build the new enrolled and effective stores in `scratch`, refuse it when
/// `commit` (the kernel and every bundle entry verifying) fails under the new
/// effective store, then take its authorization (a signature the current
/// store verifies in the enrolment role, else a confirmation at `console`),
/// and write the new enrolled store through `vars`. Log the outcome.
pub fn decide(
    file: &[u8],
    stores: Stores<'_>,
    scratch: Scratch<'_>,
    vars: &mut impl VariableServices,
    console: &mut impl ConsoleInput,
    commit: impl FnOnce(&TrustStore<'_>) -> Result<(), BootError>,
) -> Outcome
{
    let outcome = decide_quietly(file, stores, scratch, vars, console, commit);
    match &outcome
    {
        Outcome::Unchanged =>
        {
            bprintln!("[--------] boot: trust request: changes nothing (already applied); skipped");
        }
        Outcome::Applied { change, by, .. } =>
        {
            let (added, removed, revoked) = match change
            {
                Applied::Changed {
                    added,
                    removed,
                    revoked,
                    ..
                } => (*added, *removed, *revoked),
                Applied::Unchanged => (0, 0, 0),
            };
            match by
            {
                Authorized::Signed(id) => bprintln!(
                    "[--------] boot: trust request: applied, signed for enrolment by key id {}: \
                     {added} anchors added, {removed} removed, {revoked} key ids revoked",
                    KeyIdHex(id)
                ),
                Authorized::Confirmed => bprintln!(
                    "[--------] boot: trust request: applied, confirmed at the console: \
                     {added} anchors added, {removed} removed, {revoked} key ids revoked"
                ),
            }
        }
        Outcome::Refused(why) => bprintln!(
            "[--------] boot: trust request: refused: {why}; this boot runs on the current trust \
             store"
        ),
    }
    outcome
}

/// [`decide`] without its log line.
fn decide_quietly(
    file: &[u8],
    stores: Stores<'_>,
    scratch: Scratch<'_>,
    vars: &mut impl VariableServices,
    console: &mut impl ConsoleInput,
    commit: impl FnOnce(&TrustStore<'_>) -> Result<(), BootError>,
) -> Outcome
{
    let Scratch {
        enrolled: enrolled_buf,
        effective: effective_buf,
    } = scratch;
    // A file with no trailer is an unsigned request, its whole file the
    // request; one shorter than a footer has none either.
    let (body, signed) = match split(file)
    {
        Ok(object) => (object.body(), true),
        Err(ParseError::Magic | ParseError::TooShort) => (file, false),
        Err(err) => return Outcome::Refused(Refused::Trailer(err)),
    };
    let request = match TrustRequest::parse(body)
    {
        Ok(request) => request,
        Err(err) => return Outcome::Refused(Refused::Request(err)),
    };
    let change = match apply(&stores.builtin, &stores.enrolled, &request, enrolled_buf)
    {
        Ok(Applied::Unchanged) => return Outcome::Unchanged,
        Ok(change @ Applied::Changed { .. }) => change,
        Err(ApplyError::Bound { anchors, revoked }) =>
        {
            return Outcome::Refused(Refused::Bound { anchors, revoked });
        }
        Err(ApplyError::Encode(err)) => return Outcome::Refused(Refused::Build(err)),
    };
    let Applied::Changed { len: new_len, .. } = change
    else
    {
        return Outcome::Unchanged;
    };
    let new_bytes: &[u8] = enrolled_buf.get(..new_len).unwrap_or_default();
    let effective_len = match EnrolledStore::parse(new_bytes)
        .map_err(|_| EncodeError::Store)
        .and_then(|new| merge(&stores.builtin, &new, effective_buf))
    {
        Ok(len) => len,
        Err(err) => return Outcome::Refused(Refused::Build(err)),
    };
    let effective_bytes: &[u8] = effective_buf.get(..effective_len).unwrap_or_default();
    let Ok(effective) = TrustStore::parse(effective_bytes)
    else
    {
        return Outcome::Refused(Refused::Build(EncodeError::Store));
    };
    if let Err(err) = commit(&effective)
    {
        return Outcome::Refused(Refused::Commit(err));
    }

    let expect = Expectation {
        roles: RoleSet::of(&[Role::Enrolment]),
        name: REQUEST_NAME,
        arch: ARCH,
    };
    let by = match signed.then(|| verify(file, &stores.current, &expect))
    {
        Some(Ok(verified)) => Authorized::Signed(verified.anchor.key_id),
        refused =>
        {
            show(&request, refused.and_then(Result::err));
            match confirm(console)
            {
                Ok(()) => Authorized::Confirmed,
                Err(why) => return Outcome::Refused(why),
            }
        }
    };

    let info = vars.query(STORE_ATTRIBUTES).ok();
    // The variable the firmware stores is its name and its data.
    let needed = new_len.saturating_add(core::mem::size_of_val(&STORE_VARIABLE));
    if let Some(info) = info
        && u64::try_from(needed).is_ok_and(|needed| needed > info.max_variable)
    {
        return Outcome::Refused(Refused::TooLarge {
            needed,
            max_variable: info.max_variable,
        });
    }
    if let Err(status) = vars.set(
        &STORE_VARIABLE,
        &SERAPH_VENDOR_GUID,
        STORE_ATTRIBUTES,
        new_bytes,
    )
    {
        return Outcome::Refused(Refused::Write { status, info });
    }
    Outcome::Applied {
        len: effective_len,
        change,
        by,
    }
}

/// Show a request no signature authorizes at the console: why, each anchor
/// it adds with its roles, each key id it revokes, and what a confirmation
/// does.
fn show(request: &TrustRequest<'_>, refusal: Option<Refusal>)
{
    match refusal
    {
        None =>
        {
            bprintln!("[--------] boot: trust request: \\EFI\\seraph\\trust-request is unsigned");
        }
        Some(refusal) => bprintln!(
            "[--------] boot: trust request: \\EFI\\seraph\\trust-request is not signed for \
             enrolment by a key the trust store accepts ({refusal:?})"
        ),
    }
    for anchor in request.additions()
    {
        let certify = if anchor.usage.certify
        {
            " and certify"
        }
        else
        {
            ""
        };
        bprintln!(
            "[--------] boot: trust request: add root \"{}\" key id {}, roles {:#x}{certify}",
            anchor.label,
            KeyIdHex(&anchor.key_id),
            anchor.usage.roles.bits()
        );
    }
    for id in request.revocations()
    {
        bprintln!(
            "[--------] boot: trust request: revoke key id {}",
            KeyIdHex(id)
        );
    }
    bprintln!(
        "[--------] boot: trust request: confirming it trusts each added root, for the roles \
         shown, on every later boot, and refuses every object signed under a revoked key id \
         from then on"
    );
}

/// Ask the console for the confirmation.
///
/// # Errors
/// The [`Refused`] of an answer other than the confirmation, of no answer in
/// time, or of a console that cannot be read.
fn confirm(console: &mut impl ConsoleInput) -> Result<(), Refused>
{
    let mut answer = [0u8; 8];
    let prompt = "[--------] boot: trust request: type yes and Enter within 60 seconds to apply \
                  it; anything else, or no answer, refuses it";
    match console.read_line(prompt, &mut answer, CONFIRM_SECONDS)
    {
        LineRead::Line { len } if answer.get(..len) == Some(CONFIRMATION) => Ok(()),
        LineRead::Line { .. } => Err(Refused::NotConfirmed),
        LineRead::Timeout => Err(Refused::Timeout),
        LineRead::Unavailable(status) => Err(Refused::NoConsole(status)),
    }
}

#[cfg(test)]
mod tests
{
    use objsig::composite::{self, SEED_LEN};
    use objsig::enrol::{MAX_STORE_LEN, encoded_len};
    use objsig::{AnchorSpec, KeyId, PublicKey, Refusal, Role, RoleSet, TrustStore, Usage, key_id};

    use super::{
        Authorized, CONFIRM_SECONDS, ConsoleInput, Enrolled, EnrolledStore, LineRead, Malformed,
        Outcome, REQUEST_NAME, Refused, STORE_ATTRIBUTES, STORE_VARIABLE, Scratch, Stores,
        TrustRequest, VariableInfo, VariableRead, VariableServices, decide, decode, merge_current,
        merged_capacity, read_enrolled,
    };
    use crate::error::{BootError, ObjectName};
    use crate::signing::testing::{ROOT_SEED, STRANGER_SEED, signed, store_of};
    use crate::uefi::{EFI_UNSUPPORTED, EfiGuid, EfiStatus, SERAPH_VENDOR_GUID};

    /// `EFI_WRITE_PROTECTED`, a store that refuses the write.
    const WRITE_PROTECTED: EfiStatus = 0x8000_0000_0000_0008;

    /// A variable store in memory, holding at most the enrolled store.
    #[derive(Default)]
    struct Vars
    {
        /// The variable's attributes and bytes, when it exists.
        store: Option<(u32, Vec<u8>)>,
        /// The status every read fails with, when set.
        read_fails: Option<EfiStatus>,
        /// The status every write is refused with, when set.
        refuses: Option<EfiStatus>,
        /// What `QueryVariableInfo` reports; unsupported when unset.
        info: Option<VariableInfo>,
        /// The writes asked of the store, refused ones included.
        writes: usize,
    }

    impl VariableServices for Vars
    {
        fn get(&mut self, name: &[u16], vendor: &EfiGuid, buffer: &mut [u8]) -> VariableRead
        {
            assert!(
                name == STORE_VARIABLE.as_slice()
                    && core::ptr::eq(vendor, &raw const SERAPH_VENDOR_GUID)
            );
            if let Some(status) = self.read_fails
            {
                return VariableRead::Failed(status);
            }
            match &self.store
            {
                None => VariableRead::NotFound,
                Some((_, data)) if data.len() > buffer.len() =>
                {
                    VariableRead::TooLarge { len: data.len() }
                }
                Some((attributes, data)) =>
                {
                    buffer[..data.len()].copy_from_slice(data);
                    VariableRead::Found {
                        len: data.len(),
                        attributes: *attributes,
                    }
                }
            }
        }

        fn set(
            &mut self,
            name: &[u16],
            vendor: &EfiGuid,
            attributes: u32,
            data: &[u8],
        ) -> Result<(), EfiStatus>
        {
            assert!(
                name == STORE_VARIABLE.as_slice()
                    && core::ptr::eq(vendor, &raw const SERAPH_VENDOR_GUID)
            );
            self.writes += 1;
            if let Some(status) = self.refuses
            {
                return Err(status);
            }
            self.store = Some((attributes, data.to_vec()));
            Ok(())
        }

        fn query(&mut self, attributes: u32) -> Result<VariableInfo, EfiStatus>
        {
            assert_eq!(attributes, STORE_ATTRIBUTES);
            self.info.ok_or(EFI_UNSUPPORTED)
        }
    }

    /// The console's one answer.
    #[derive(Clone, Copy)]
    enum Answer
    {
        /// This text, then Enter.
        Typed(&'static str),
        /// No answer in time.
        Timeout,
        /// No console.
        Unavailable,
    }

    /// A console that gives one answer, and counts the questions.
    struct Console
    {
        answer: Answer,
        asked: usize,
    }

    impl Console
    {
        fn answering(answer: Answer) -> Self
        {
            Self { answer, asked: 0 }
        }
    }

    impl ConsoleInput for Console
    {
        fn read_line(&mut self, prompt: &str, buffer: &mut [u8], seconds: u64) -> LineRead
        {
            self.asked += 1;
            assert!(prompt.contains("type yes and Enter within 60 seconds"));
            assert_eq!(seconds, CONFIRM_SECONDS);
            match self.answer
            {
                Answer::Typed(text) =>
                {
                    for (out, byte) in buffer.iter_mut().zip(text.bytes())
                    {
                        *out = byte;
                    }
                    LineRead::Line { len: text.len() }
                }
                Answer::Timeout => LineRead::Timeout,
                Answer::Unavailable => LineRead::Unavailable(EFI_UNSUPPORTED),
            }
        }
    }

    /// The seeds of keys the tests enrol.
    const SEEDS: [[u8; SEED_LEN]; 4] = [[1; SEED_LEN], [2; SEED_LEN], [3; SEED_LEN], [4; SEED_LEN]];

    fn spec<'k>(key: &'k PublicKey, label: &'k str) -> AnchorSpec<'k>
    {
        AnchorSpec {
            key,
            usage: Usage {
                roles: RoleSet::of(&[Role::Kernel, Role::Init, Role::BootModule]),
                certify: true,
            },
            local: false,
            label,
        }
    }

    /// A request body adding the keys of `seeds` and revoking `revoked`.
    fn request(seeds: &[[u8; SEED_LEN]], revoked: &[KeyId]) -> Vec<u8>
    {
        let keys: Vec<PublicKey> = seeds.iter().map(composite::public_key).collect();
        let mut specs: Vec<AnchorSpec<'_>> = keys.iter().map(|key| spec(key, "enrolled")).collect();
        specs.sort_by_key(|anchor| key_id(anchor.key));
        let mut revoked = revoked.to_vec();
        revoked.sort_unstable();
        let mut out = vec![0u8; encoded_len(specs.len(), revoked.len()).unwrap()];
        TrustRequest::encode(&specs, &revoked, &mut out).unwrap();
        out
    }

    /// An enrolled store of the keys of `seeds` and `revoked`.
    fn enrolled_of(seeds: &[[u8; SEED_LEN]], revoked: &[KeyId]) -> Vec<u8>
    {
        let keys: Vec<PublicKey> = seeds.iter().map(composite::public_key).collect();
        let mut specs: Vec<AnchorSpec<'_>> = keys.iter().map(|key| spec(key, "enrolled")).collect();
        specs.sort_by_key(|anchor| key_id(anchor.key));
        let mut revoked = revoked.to_vec();
        revoked.sort_unstable();
        let mut out = vec![0u8; encoded_len(specs.len(), revoked.len()).unwrap()];
        EnrolledStore::encode(&specs, &revoked, &mut out).unwrap();
        out
    }

    fn id_of(seed: &[u8; SEED_LEN]) -> KeyId
    {
        key_id(&composite::public_key(seed))
    }

    /// What one decision did: the outcome, the new effective store when it
    /// was applied, and the questions asked.
    struct Run
    {
        outcome: Outcome,
        effective: Option<Vec<u8>>,
        asked: usize,
    }

    /// Decide `file` on a machine whose built-in store trusts the root and
    /// whose enrolled store is `enrolled`, the commit rule giving `commit`.
    fn decide_on(
        file: &[u8],
        enrolled: &[u8],
        vars: &mut Vars,
        answer: Answer,
        commit: fn(&TrustStore<'_>) -> Result<(), BootError>,
    ) -> Run
    {
        let builtin_bytes = store_of(&ROOT_SEED);
        let builtin = TrustStore::parse(&builtin_bytes).unwrap();
        let enrolled = EnrolledStore::parse(enrolled).unwrap();
        let mut current_buf = vec![0u8; merged_capacity(&builtin)];
        let (current, _) = merge_current(&builtin, &enrolled, &mut current_buf).unwrap();
        let mut new_buf = vec![0u8; MAX_STORE_LEN];
        let mut effective_buf = vec![0u8; merged_capacity(&builtin)];
        let mut console = Console::answering(answer);
        let outcome = decide(
            file,
            Stores {
                builtin,
                enrolled,
                current,
            },
            Scratch {
                enrolled: &mut new_buf,
                effective: &mut effective_buf,
            },
            vars,
            &mut console,
            commit,
        );
        let effective = match outcome
        {
            Outcome::Applied { len, .. } => Some(effective_buf[..len].to_vec()),
            Outcome::Unchanged | Outcome::Refused(_) => None,
        };
        Run {
            outcome,
            effective,
            asked: console.asked,
        }
    }

    fn refuses_the_kernel(_: &TrustStore<'_>) -> Result<(), BootError>
    {
        Err(BootError::SignatureRefused {
            object: ObjectName::new(b"kernel"),
            refusal: Refusal::Untrusted,
        })
    }

    fn empty() -> Vec<u8>
    {
        enrolled_of(&[], &[])
    }

    // Defect caught: a variable read as an enrolled store that the bootloader
    // never wrote (other attributes, longer than any store, bytes that do not
    // parse), or a missing or unreadable one read as malformed, which would
    // halt a machine that never enrolled anything.
    #[test]
    fn every_read_of_the_variable_is_classified()
    {
        let good = enrolled_of(&[SEEDS[0]], &[]);
        assert_eq!(
            decode(VariableRead::NotFound, &[]),
            Ok(Enrolled::Store(EnrolledStore::EMPTY))
        );
        assert_eq!(
            decode(VariableRead::Failed(EFI_UNSUPPORTED), &[]),
            Ok(Enrolled::Unavailable(EFI_UNSUPPORTED))
        );
        assert_eq!(
            decode(VariableRead::TooLarge { len: 9000 }, &[]),
            Err(Malformed::Length(9000))
        );
        assert_eq!(
            decode(
                VariableRead::Found {
                    len: good.len(),
                    attributes: STORE_ATTRIBUTES | 0x4
                },
                &good
            ),
            Err(Malformed::Attributes(STORE_ATTRIBUTES | 0x4))
        );
        assert!(matches!(
            decode(
                VariableRead::Found {
                    len: 4,
                    attributes: STORE_ATTRIBUTES
                },
                &good
            ),
            Err(Malformed::Format(_))
        ));
        assert_eq!(
            decode(
                VariableRead::Found {
                    len: good.len(),
                    attributes: STORE_ATTRIBUTES
                },
                &good
            ),
            Ok(Enrolled::Store(EnrolledStore::parse(&good).unwrap()))
        );
    }

    // Defect caught: the store read from another variable or GUID, or a
    // malformed one let through, so the boot drops the revocations it holds.
    #[test]
    fn read_enrolled_reads_the_variable_and_refuses_a_malformed_one()
    {
        let good = enrolled_of(&[SEEDS[0]], &[id_of(&SEEDS[1])]);
        let mut buffer = vec![0u8; MAX_STORE_LEN];
        let mut vars = Vars {
            store: Some((STORE_ATTRIBUTES, good.clone())),
            ..Vars::default()
        };
        let read = read_enrolled(&mut vars, &mut buffer).unwrap();
        assert_eq!(read.store(), EnrolledStore::parse(&good).unwrap());
        let mut bad = Vars {
            store: Some((STORE_ATTRIBUTES, b"SRPHENRL junk".to_vec())),
            ..Vars::default()
        };
        assert!(matches!(
            read_enrolled(&mut bad, &mut buffer),
            Err(BootError::EnrolledMalformed(Malformed::Format(_)))
        ));
        let mut failed = Vars {
            read_fails: Some(EFI_UNSUPPORTED),
            ..Vars::default()
        };
        let read = read_enrolled(&mut failed, &mut buffer).unwrap();
        assert_eq!(read, Enrolled::Unavailable(EFI_UNSUPPORTED));
        assert_eq!(read.store(), EnrolledStore::EMPTY);
    }

    // Defect caught: a workspace too short for the built-in store merged with
    // a full enrolled store, so a machine at the bound cannot boot.
    #[test]
    fn the_merged_capacity_holds_a_full_enrolled_store()
    {
        let builtin_bytes = store_of(&ROOT_SEED);
        let builtin = TrustStore::parse(&builtin_bytes).unwrap();
        let revoked: Vec<KeyId> = (0..super::MAX_REVOKED)
            .map(|i| {
                let mut id = [0u8; objsig::KEY_ID_LEN];
                id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                id
            })
            .collect();
        let full = enrolled_of(&SEEDS[..super::MAX_ANCHORS], &revoked);
        assert!(full.len() <= MAX_STORE_LEN);
        let full = EnrolledStore::parse(&full).unwrap();
        let capacity = merged_capacity(&builtin);
        let mut out = vec![0u8; capacity];
        let (merged, bytes) = merge_current(&builtin, &full, &mut out).unwrap();
        assert_eq!(bytes.len(), capacity);
        assert_eq!(merged.anchors().count(), 1 + super::MAX_ANCHORS);
        assert_eq!(merged.revoked().len(), super::MAX_REVOKED);
    }

    // Defect caught: an unsigned request applied with no one at the console
    // asked, or applied on an answer other than yes, on a timeout, or with
    // no console.
    #[test]
    fn an_unsigned_request_is_applied_only_on_yes()
    {
        let file = request(&[SEEDS[0]], &[]);
        for (answer, refused) in [
            (Answer::Typed("no"), "NotConfirmed"),
            (Answer::Typed("yes please"), "NotConfirmed"),
            (Answer::Typed("YES"), "NotConfirmed"),
            (Answer::Typed(""), "NotConfirmed"),
            (Answer::Timeout, "Timeout"),
            (Answer::Unavailable, "NoConsole"),
        ]
        {
            let mut vars = Vars::default();
            let run = decide_on(&file, &empty(), &mut vars, answer, |_| Ok(()));
            assert!(
                matches!(&run.outcome, Outcome::Refused(why) if format!("{why:?}").starts_with(refused)),
                "{:?}",
                run.outcome
            );
            assert_eq!(run.asked, 1);
            assert_eq!(vars.writes, 0);
        }
        let mut vars = Vars::default();
        let run = decide_on(&file, &empty(), &mut vars, Answer::Typed("yes"), |_| Ok(()));
        assert!(matches!(
            run.outcome,
            Outcome::Applied {
                by: Authorized::Confirmed,
                ..
            }
        ));
        let (attributes, written) = vars.store.unwrap();
        assert_eq!(attributes, STORE_ATTRIBUTES);
        let written = EnrolledStore::parse(&written).unwrap();
        assert!(written.anchor(&id_of(&SEEDS[0])).is_some());
        let effective = run.effective.unwrap();
        let effective = TrustStore::parse(&effective).unwrap();
        assert!(effective.anchor(&id_of(&SEEDS[0])).is_some());
        assert!(effective.anchor(&id_of(&ROOT_SEED)).is_some());
    }

    // Defect caught: a request signed for enrolment by a trusted root still
    // asking the console, or one signed in another role, or by a key the
    // store does not trust, or under another name, applied without asking.
    #[test]
    fn a_request_signed_for_enrolment_is_applied_without_asking()
    {
        let body = request(&[SEEDS[0]], &[]);
        let file = signed(&ROOT_SEED, &body, &[Role::Enrolment], REQUEST_NAME);
        let mut vars = Vars::default();
        let run = decide_on(&file, &empty(), &mut vars, Answer::Unavailable, |_| Ok(()));
        assert!(
            matches!(run.outcome, Outcome::Applied { by: Authorized::Signed(id), .. } if id == id_of(&ROOT_SEED)),
            "{:?}",
            run.outcome
        );
        assert_eq!(run.asked, 0);
        assert_eq!(vars.writes, 1);

        for file in [
            signed(&ROOT_SEED, &body, &[Role::BootModule], REQUEST_NAME),
            signed(&STRANGER_SEED, &body, &[Role::Enrolment], REQUEST_NAME),
            signed(&ROOT_SEED, &body, &[Role::Enrolment], b"kernel"),
        ]
        {
            let mut vars = Vars::default();
            let run = decide_on(&file, &empty(), &mut vars, Answer::Timeout, |_| Ok(()));
            assert!(
                matches!(run.outcome, Outcome::Refused(Refused::Timeout)),
                "{:?}",
                run.outcome
            );
            assert_eq!(run.asked, 1);
            assert_eq!(vars.writes, 0);
        }
    }

    // Defect caught: a replayed request prompting or writing on every boot,
    // or one past the bound written in part.
    #[test]
    fn a_replay_is_skipped_and_a_request_past_the_bound_is_refused_whole()
    {
        let enrolled = enrolled_of(&[SEEDS[0]], &[]);
        let mut vars = Vars::default();
        let run = decide_on(
            &request(&[SEEDS[0]], &[]),
            &enrolled,
            &mut vars,
            Answer::Typed("yes"),
            |_| Ok(()),
        );
        assert!(
            matches!(run.outcome, Outcome::Unchanged),
            "{:?}",
            run.outcome
        );
        assert_eq!((run.asked, vars.writes), (0, 0));

        let mut vars = Vars::default();
        let run = decide_on(
            &request(&SEEDS, &[]),
            &empty(),
            &mut vars,
            Answer::Typed("yes"),
            |_| Ok(()),
        );
        assert!(
            matches!(
                run.outcome,
                Outcome::Refused(Refused::Bound {
                    anchors: 4,
                    revoked: 0
                })
            ),
            "{:?}",
            run.outcome
        );
        assert_eq!((run.asked, vars.writes), (0, 0));
        let Outcome::Refused(why) = run.outcome
        else
        {
            unreachable!()
        };
        let line = format!("{why}");
        assert!(
            line.contains("3 anchors") && line.contains("120 revoked"),
            "{line}"
        );
    }

    // Defect caught: a request applied although the kernel or a bundle entry
    // does not verify under the store it gives, which bricks the next boot,
    // or the console asked before that is known.
    #[test]
    fn a_request_the_boot_set_does_not_verify_under_is_refused_before_asking()
    {
        let mut vars = Vars::default();
        let run = decide_on(
            &request(&[], &[id_of(&ROOT_SEED)]),
            &empty(),
            &mut vars,
            Answer::Typed("yes"),
            refuses_the_kernel,
        );
        assert!(
            matches!(run.outcome, Outcome::Refused(Refused::Commit(_))),
            "{:?}",
            run.outcome
        );
        assert_eq!((run.asked, vars.writes), (0, 0));
    }

    // Defect caught: a request reported as applied although the firmware
    // refused the write, or one larger than the firmware's largest variable
    // sent to it anyway; or the refusal's line without the figures.
    #[test]
    fn a_write_the_firmware_refuses_or_cannot_hold_is_refused()
    {
        let file = request(&[SEEDS[0]], &[]);
        let info = VariableInfo {
            max_storage: 65536,
            remaining: 100,
            max_variable: 8132,
        };
        let mut vars = Vars {
            refuses: Some(WRITE_PROTECTED),
            info: Some(info),
            ..Vars::default()
        };
        let run = decide_on(&file, &empty(), &mut vars, Answer::Typed("yes"), |_| Ok(()));
        let Outcome::Refused(why) = run.outcome
        else
        {
            panic!("{:?}", run.outcome)
        };
        assert!(matches!(
            why,
            Refused::Write {
                status: WRITE_PROTECTED,
                info: Some(_)
            }
        ));
        let line = format!("{why}");
        assert!(
            line.contains("100 of 65536 bytes free") && line.contains("8132"),
            "{line}"
        );
        assert!(vars.store.is_none());

        let mut vars = Vars {
            info: Some(VariableInfo {
                max_variable: 64,
                ..info
            }),
            ..Vars::default()
        };
        let run = decide_on(&file, &empty(), &mut vars, Answer::Typed("yes"), |_| Ok(()));
        assert!(
            matches!(
                run.outcome,
                Outcome::Refused(Refused::TooLarge {
                    max_variable: 64,
                    ..
                })
            ),
            "{:?}",
            run.outcome
        );
        assert_eq!(vars.writes, 0);
    }

    // Defect caught: a revocation that leaves the revoked enrolled anchor
    // trusted, or forgets the id so a replay enrols it again.
    #[test]
    fn a_revoked_enrolled_anchor_leaves_and_stays_revoked()
    {
        let enrolled = enrolled_of(&[SEEDS[0], SEEDS[1]], &[]);
        let gone = id_of(&SEEDS[0]);
        let mut vars = Vars::default();
        let run = decide_on(
            &request(&[], &[gone]),
            &enrolled,
            &mut vars,
            Answer::Typed("yes"),
            |_| Ok(()),
        );
        assert!(
            matches!(run.outcome, Outcome::Applied { .. }),
            "{:?}",
            run.outcome
        );
        let (_, written) = vars.store.clone().unwrap();
        let written = EnrolledStore::parse(&written).unwrap();
        assert!(written.anchor(&gone).is_none() && written.is_revoked(&gone));
        let effective = run.effective.unwrap();
        let effective = TrustStore::parse(&effective).unwrap();
        assert!(effective.anchor(&gone).is_none() && effective.is_revoked(&gone));
        assert!(effective.anchor(&id_of(&SEEDS[1])).is_some());

        let now = enrolled_of(&[SEEDS[1]], &[gone]);
        let mut vars = Vars::default();
        let run = decide_on(
            &request(&[SEEDS[0]], &[]),
            &now,
            &mut vars,
            Answer::Typed("yes"),
            |_| Ok(()),
        );
        assert!(
            matches!(run.outcome, Outcome::Unchanged),
            "{:?}",
            run.outcome
        );
    }

    // Defect caught: a malformed request or trailer applied or prompted for.
    #[test]
    fn a_malformed_request_is_refused_without_asking()
    {
        let mut vars = Vars::default();
        let run = decide_on(
            b"not a request",
            &empty(),
            &mut vars,
            Answer::Typed("yes"),
            |_| Ok(()),
        );
        assert!(
            matches!(run.outcome, Outcome::Refused(Refused::Request(_))),
            "{:?}",
            run.outcome
        );
        let mut file = signed(
            &ROOT_SEED,
            &request(&[SEEDS[0]], &[]),
            &[Role::Enrolment],
            REQUEST_NAME,
        );
        let len = file.len();
        // The footer's version, before its magic.
        file[len - 10] ^= 0xff;
        let run = decide_on(&file, &empty(), &mut vars, Answer::Typed("yes"), |_| Ok(()));
        assert!(
            matches!(
                run.outcome,
                Outcome::Refused(Refused::Trailer(objsig::ParseError::Version))
            ),
            "{:?}",
            run.outcome
        );
        assert_eq!(vars.writes, 0);
    }
}
