// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/generate/ml_dsa.rs

//! The generator of `vectors/reference/ml_dsa_65.json`: signing inputs with
//! the key and deterministic signature OpenSSL derives, and edits of each
//! with the verdict they reach.
//!
//! A verdict names the first FIPS 204 Algorithm 8 check that fails: the hint
//! section's encoding (`HintBitUnpack`, Algorithm 21), then the norm bound of
//! z, then OpenSSL's verification. OpenSSL reports only accept or refuse, so
//! the generator makes the first two checks itself on the signature's bytes,
//! with the layout of FIPS 204 Algorithm 26 (sigEncode); it fails when
//! OpenSSL accepts a signature either check refuses, when OpenSSL refuses a
//! signature it made, and when a crafted edit does not reach the verdict it
//! is built for.

use json::{Value, json};

use super::Error;
use super::openssl::OpenSsl;
use crate::hex;
use crate::ml_dsa::{self, Edit, Field, SignInput, Verdict};
use crate::rng::Rng;

/// The seed of the generated signing inputs and edits.
pub const ML_DSA_SEED: u64 = 0x5e4a_d5a6;
/// The number of generated signing inputs.
pub const ML_DSA_ROUNDS: usize = 24;

/// The parameters of ML-DSA-65 the encoding checks read (FIPS 204 Table 1).
const OMEGA: usize = 55;
const K: usize = 6;
const GAMMA1: i64 = 1 << 19;
const BETA: i64 = 196;
/// The bytes of c-tilde (lambda / 4), of z (L = 5 polynomials of 256
/// 20-bit coefficients), and the offset of the hint section after both.
const CTILDE_LEN: usize = 48;
const Z_LEN: usize = 5 * 640;
const HINT_OFFSET: usize = CTILDE_LEN + Z_LEN;

/// The hint section's position bytes and its K row ends.
fn hint_section(signature: &[u8]) -> (&[u8], &[u8])
{
    let hints = signature.get(HINT_OFFSET..).unwrap_or_default();
    hints.split_at_checked(OMEGA).unwrap_or_default()
}

/// Whether the hint section passes `HintBitUnpack` (FIPS 204 Algorithm 21):
/// row ends non-decreasing and at most OMEGA, positions strictly increasing
/// within a row, and every slot past the last row's end zero.
pub fn hints_valid(signature: &[u8]) -> bool
{
    let (positions, ends) = hint_section(signature);
    if ends.len() != K
    {
        return false;
    }
    let mut index = 0;
    for &end in ends
    {
        let end = usize::from(end);
        if end < index || end > OMEGA
        {
            return false;
        }
        let row = positions.get(index..end).unwrap_or_default();
        if !row.is_sorted_by(|a, b| a < b)
        {
            return false;
        }
        index = end;
    }
    positions
        .get(index..)
        .is_some_and(|rest| rest.iter().all(|&p| p == 0))
}

/// The coefficients of z: GAMMA1 minus each little-endian 20-bit field
/// (`BitUnpack`, FIPS 204 Algorithm 19, with a = GAMMA1 - 1 and b = GAMMA1).
fn z_coefficients(signature: &[u8]) -> impl Iterator<Item = i64> + '_
{
    let z = signature.get(CTILDE_LEN..HINT_OFFSET).unwrap_or_default();
    z.as_chunks::<5>().0.iter().flat_map(|pair| {
        let mut word = [0u8; 8];
        for (w, b) in word.iter_mut().zip(pair)
        {
            *w = *b;
        }
        let both = i64::from_le_bytes(word);
        [both & 0xf_ffff, both >> 20].map(|field| GAMMA1 - field)
    })
}

/// Whether every coefficient of z is below GAMMA1 - BETA in magnitude (FIPS
/// 204 Algorithm 8, line 13).
pub fn z_in_range(signature: &[u8]) -> bool
{
    let bound = GAMMA1 - BETA;
    z_coefficients(signature).all(|z| z > -bound && z < bound)
}

/// The verdict on `input`: the generator's encoding checks, then OpenSSL's
/// verification.
fn classify(openssl: &OpenSsl, input: &SignInput) -> Result<Verdict, Error>
{
    let accepted = openssl.ml_dsa_verifies(
        &input.public_key,
        &input.message,
        &input.context,
        &input.signature,
    )?;
    let verdict = if !hints_valid(&input.signature)
    {
        Verdict::MalformedHint
    }
    else if !z_in_range(&input.signature)
    {
        Verdict::ZOutOfRange
    }
    else if accepted
    {
        Verdict::Accept
    }
    else
    {
        Verdict::Mismatch
    };
    if accepted && verdict != Verdict::Accept
    {
        return Err(Error(format!(
            "OpenSSL accepts a signature FIPS 204 refuses ({})",
            verdict.name()
        )));
    }
    Ok(verdict)
}

/// The verification section as it is built.
struct Cases<'a>
{
    openssl: &'a OpenSsl,
    cases: Vec<Value>,
}

impl Cases<'_>
{
    /// Add signing input `index` (`base`) with `edit`, and its verdict;
    /// an error when `built_for` names another verdict.
    fn add(
        &mut self,
        index: usize,
        base: &SignInput,
        comment: &str,
        edit: Option<Edit>,
        built_for: Option<Verdict>,
    ) -> Result<(), Error>
    {
        let input = match &edit
        {
            Some(edit) => edit
                .apply(base)
                .map_err(|e| Error(format!("signing input {index}, {comment}: {e}")))?,
            None => base.clone(),
        };
        let verdict = classify(self.openssl, &input)?;
        if built_for.is_some_and(|expected| expected != verdict)
        {
            return Err(Error(format!(
                "signing input {index}, {comment}: reached {} instead of {:?}",
                verdict.name(),
                built_for
            )));
        }
        let mut case = json!({
            "signing": index,
            "comment": comment,
            "verdict": verdict.name(),
        });
        if let (Some(edit), Value::Object(members)) = (edit, &mut case)
        {
            members.insert(
                "edit".into(),
                json!({
                    "field": edit.field.name(),
                    "offset": edit.offset,
                    "bytes": hex::encode(&edit.bytes),
                }),
            );
        }
        self.cases.push(case);
        Ok(())
    }
}

/// An edit flipping one random bit of `field`, with its comment; `None` for
/// an empty field.
fn flip(rng: &mut Rng, input: &SignInput, field: Field) -> Option<(String, Edit)>
{
    let data = input.field(field);
    let bit = rng.below(data.len().checked_mul(8).filter(|&bits| bits > 0)?);
    let offset = bit / 8;
    let byte = data.get(offset)? ^ (1u8 << (bit % 8));
    Some((
        format!("{} bit {bit} flipped", field.name()),
        Edit {
            field,
            offset,
            bytes: vec![byte],
        },
    ))
}

/// An edit setting coefficient `index` of z, which is even so the field
/// starts on a byte, to `z`; the high half of its third byte, the next
/// coefficient's, is kept.
fn set_z(signature: &[u8], index: usize, z: i64) -> Edit
{
    let offset = CTILDE_LEN + index / 2 * 5;
    let [b0, b1, b2, ..] = (GAMMA1 - z).to_le_bytes();
    let kept = signature.get(offset + 2).map_or(0, |b| b & 0xf0);
    Edit {
        field: Field::Signature,
        offset,
        bytes: vec![b0, b1, kept | (b2 & 0x0f)],
    }
}

/// The edits of a signature's hint section that `HintBitUnpack` refuses, each
/// with its comment: a row end past OMEGA, a row ending before the previous
/// one, a non-zero slot past the last row's end, and a row's positions out
/// of order and repeated. An edit the signature's hints leave no room for
/// (no row before a non-empty one, no free slot, no row of two positions) is
/// left out.
fn hint_edits(signature: &[u8]) -> Vec<(String, Edit)>
{
    let edit = |offset: usize, bytes: Vec<u8>| Edit {
        field: Field::Signature,
        offset,
        bytes,
    };
    let (positions, ends) = hint_section(signature);
    let ends_at = HINT_OFFSET + OMEGA;
    let past_omega = u8::try_from(OMEGA + 1).unwrap_or(u8::MAX);
    let mut edits = vec![(
        "the last row end past OMEGA".to_owned(),
        edit(ends_at + K - 1, vec![past_omega]),
    )];
    if let Some(row) = (1..K).find(|&row| ends.get(row - 1).is_some_and(|&end| end > 0))
        && let Some(&previous) = ends.get(row - 1)
    {
        edits.push((
            format!("row {row} ending before row {}", row - 1),
            edit(ends_at + row, vec![previous - 1]),
        ));
    }
    if ends.last().is_some_and(|&last| usize::from(last) < OMEGA)
    {
        edits.push((
            "a non-zero position slot past the last row end".to_owned(),
            edit(ends_at - 1, vec![1]),
        ));
    }
    let starts = std::iter::once(0).chain(ends.iter().map(|&end| usize::from(end)));
    let row = starts
        .zip(ends)
        .enumerate()
        .find(|(_, (start, end))| usize::from(**end) >= start + 2);
    if let Some((row, (start, _))) = row
        && let Some(&[first, second]) = positions
            .get(start..start + 2)
            .and_then(|p| p.first_chunk())
    {
        edits.push((
            format!("row {row}'s first two positions swapped"),
            edit(HINT_OFFSET + start, vec![second, first]),
        ));
        edits.push((
            format!("row {row}'s second position repeating its first"),
            edit(HINT_OFFSET + start + 1, vec![first]),
        ));
    }
    edits
}

/// Generate the file with OpenSSL: `ML_DSA_ROUNDS` signing inputs from
/// seed `ML_DSA_SEED` (the first with an empty message and context, the
/// second with the longest context, every eighth with a message of up to
/// 4 KiB), each verified as signed, with four one-bit flips of the
/// signature, one of the public key, the message and the context, z's
/// coefficients at and inside the norm bound, and the hint edits of
/// [`hint_edits`].
#[expect(
    clippy::large_stack_frames,
    reason = "the `json!` expansions' temporaries, on the generator binary's main thread, \
              which has 8 MiB"
)]
pub(super) fn file(openssl: &OpenSsl) -> Result<String, Error>
{
    let mut rng = Rng::new(ML_DSA_SEED);
    let mut signing = Vec::new();
    let mut inputs = Vec::new();
    for round in 0..ML_DSA_ROUNDS
    {
        let seed: [u8; 32] = rng.array();
        let message_len = match round
        {
            0 => 0,
            _ if round % 8 == 7 => rng.below(4096),
            _ => rng.below(600),
        };
        let context_len = match round
        {
            0 => 0,
            1 => ml_dsa::MAX_CONTEXT_LEN,
            _ if rng.below(3) == 0 => 0,
            _ => rng.below(ml_dsa::MAX_CONTEXT_LEN + 1),
        };
        let message = rng.bytes(message_len);
        let context = rng.bytes(context_len);
        let (public_key, signature) = openssl.ml_dsa_sign(&seed, &message, &context)?;
        signing.push(json!({
            "seed": hex::encode(&seed),
            "message": hex::encode(&message),
            "context": hex::encode(&context),
            "publicKey": hex::encode(&public_key),
            "signature": hex::encode(&signature),
        }));
        inputs.push(SignInput {
            seed,
            message,
            context,
            public_key,
            signature,
        });
    }

    let mut cases = Cases {
        openssl,
        cases: Vec::new(),
    };
    let bound = GAMMA1 - BETA;
    for (index, base) in inputs.iter().enumerate()
    {
        cases.add(
            index,
            base,
            "the signature as signed",
            None,
            Some(Verdict::Accept),
        )?;
        let flips = [Field::Signature; 4].into_iter().chain([
            Field::PublicKey,
            Field::Message,
            Field::Context,
        ]);
        for field in flips
        {
            if let Some((comment, edit)) = flip(&mut rng, base, field)
            {
                cases.add(index, base, &comment, Some(edit), None)?;
            }
        }
        let coefficient = rng.below(5 * 128) * 2;
        for (z, built_for) in [
            (bound, Verdict::ZOutOfRange),
            (-bound, Verdict::ZOutOfRange),
            (GAMMA1, Verdict::ZOutOfRange),
            (bound - 1, Verdict::Mismatch),
        ]
        {
            let comment = format!("z coefficient {coefficient} set to {z}");
            let edit = set_z(&base.signature, coefficient, z);
            cases.add(index, base, &comment, Some(edit), Some(built_for))?;
        }
        for (comment, edit) in hint_edits(&base.signature)
        {
            cases.add(
                index,
                base,
                &comment,
                Some(edit),
                Some(Verdict::MalformedHint),
            )?;
        }
    }

    let verification = cases.cases;
    Ok(super::vector_file(
        &[
            ("schema", json!(ml_dsa::SCHEMA)),
            ("seed", json!(ML_DSA_SEED)),
            ("rounds", json!(ML_DSA_ROUNDS)),
            ("numberOfTests", json!(signing.len() + verification.len())),
        ],
        &[("signing", signing), ("verification", verification)],
    ))
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A signature of zero bytes but for `edits`: every z field 0 (z =
    /// GAMMA1), no hints.
    fn signature(edits: &[(usize, u8)]) -> Vec<u8>
    {
        let mut signature = vec![0u8; ml_dsa::SIGNATURE_LEN];
        for &(offset, byte) in edits
        {
            signature[offset] = byte;
        }
        signature
    }

    #[test]
    fn the_hint_check_takes_canonical_hints_and_refuses_each_malformed_form()
    {
        let ends = HINT_OFFSET + OMEGA;
        // Row 0 holds positions 3 and 9; every later row ends there too.
        let mut canonical = vec![(HINT_OFFSET, 3), (HINT_OFFSET + 1, 9)];
        canonical.extend((0..K).map(|row| (ends + row, 2)));
        assert!(hints_valid(&signature(&canonical)));
        assert!(hints_valid(&signature(&[])));
        for (what, change) in [
            ("an end past OMEGA", (ends + K - 1, 56)),
            ("a decreasing end", (ends + 1, 1)),
            ("a trailing slot", (HINT_OFFSET + 2, 1)),
            ("positions out of order", (HINT_OFFSET + 1, 2)),
            ("a repeated position", (HINT_OFFSET + 1, 3)),
        ]
        {
            let mut edits = canonical.clone();
            edits.push(change);
            assert!(!hints_valid(&signature(&edits)), "{what}");
        }
    }

    #[test]
    fn the_norm_check_refuses_z_at_the_bound_and_takes_it_inside()
    {
        // Every pair of 20-bit fields GAMMA1 (0x80000), so every z is 0.
        let mut inside = signature(&[]);
        for pair in inside[CTILDE_LEN..HINT_OFFSET].as_chunks_mut::<5>().0
        {
            pair.copy_from_slice(&[0x00, 0x00, 0x08, 0x00, 0x80]);
        }
        assert!(z_coefficients(&inside).all(|z| z == 0));
        assert_eq!(z_coefficients(&inside).count(), 5 * 256);
        assert!(z_in_range(&inside));
        let bound = GAMMA1 - BETA;
        for (z, in_range) in [
            (bound, false),
            (-bound, false),
            (GAMMA1, false),
            (bound - 1, true),
            (1 - bound, true),
        ]
        {
            let edit = set_z(&inside, 6, z);
            let mut changed = inside.clone();
            changed[edit.offset..edit.offset + 3].copy_from_slice(&edit.bytes);
            assert_eq!(z_coefficients(&changed).nth(6), Some(z));
            assert_eq!(
                z_coefficients(&changed).nth(7),
                Some(0),
                "the next coefficient is kept"
            );
            assert_eq!(z_in_range(&changed), in_range, "{z}");
        }
    }

    #[test]
    fn the_hint_edits_each_break_the_canonical_encoding()
    {
        let ends = HINT_OFFSET + OMEGA;
        let mut canonical = vec![(HINT_OFFSET, 3), (HINT_OFFSET + 1, 9)];
        canonical.extend((0..K).map(|row| (ends + row, 2)));
        let base = signature(&canonical);
        let edits = hint_edits(&base);
        assert_eq!(edits.len(), 5);
        for (comment, edit) in edits
        {
            let mut changed = base.clone();
            changed[edit.offset..edit.offset + edit.bytes.len()].copy_from_slice(&edit.bytes);
            assert!(!hints_valid(&changed), "{comment}");
        }
    }
}
