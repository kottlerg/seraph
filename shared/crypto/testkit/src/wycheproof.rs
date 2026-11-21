// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/wycheproof.rs

//! The Wycheproof loader: read a Wycheproof test file into typed groups and
//! cases, and run every case against an implementation.
//!
//! A test file is JSON: a header (`algorithm`, `schema`, `numberOfTests`) and
//! `testGroups`, each of one group type (`EddsaVerify`, ...) holding its key
//! material and its `tests`. Each case has an id (`tcId`), a comment, flags
//! and an expected `result`: `valid`, `invalid`, or `acceptable` (an input
//! the standard lets an implementation take either way). [`load`] checks the
//! file is what its [`Source`] says (schema, group type), that it holds as
//! many cases as `numberOfTests` declares, and that every `tcId` is unique, so
//! a loader that drops cases fails rather than passing on fewer. [`run`]
//! compares the implementation's verdict on every case with the expected one;
//! an `acceptable` case is judged by the caller's stated policy, never skipped.
//!
//! A schema for another algorithm is one more group type here, and a vector
//! file one more [`Source`]; the files live under `vectors/wycheproof/` (see
//! the crate's README for their provenance).

use std::collections::HashSet;
use std::fmt;

use json::Value;

use crate::differential::{self, Report};
use crate::vectors;
pub use crate::vectors::LoadError;

/// One vendored Wycheproof test file.
#[derive(Debug, Clone, Copy)]
pub struct Source
{
    /// The upstream file name, under `testvectors_v1/`.
    pub file: &'static str,
    /// The schema the file declares, which [`load`] checks.
    pub schema: &'static str,
    json: &'static str,
}

/// `ed25519_test.json`: Ed25519 signature verification (`EddsaVerify`).
pub const ED25519: Source = Source {
    file: "ed25519_test.json",
    schema: "eddsa_verify_schema_v1.json",
    json: include_str!("../vectors/wycheproof/ed25519_test.json"),
};

/// `chacha20_poly1305_test.json`: ChaCha20-Poly1305 authenticated encryption
/// (`AeadTest`).
pub const CHACHA20_POLY1305: Source = Source {
    file: "chacha20_poly1305_test.json",
    schema: "aead_test_schema_v1.json",
    json: include_str!("../vectors/wycheproof/chacha20_poly1305_test.json"),
};

/// `mldsa_65_verify_test.json`: ML-DSA-65 signature verification
/// (`MlDsaVerify`).
pub const MLDSA_65_VERIFY: Source = Source {
    file: "mldsa_65_verify_test.json",
    schema: "mldsa_verify_schema.json",
    json: include_str!("../vectors/wycheproof/mldsa_65_verify_test.json"),
};

/// `mldsa_65_sign_seed_test.json`: ML-DSA-65 signing from a key-generation
/// seed (`MlDsaSign`).
pub const MLDSA_65_SIGN_SEED: Source = Source {
    file: "mldsa_65_sign_seed_test.json",
    schema: "mldsa_sign_seed_schema.json",
    json: include_str!("../vectors/wycheproof/mldsa_65_sign_seed_test.json"),
};

/// A case's expected result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected
{
    /// The implementation must accept the input.
    Valid,
    /// The implementation must reject the input.
    Invalid,
    /// The standard allows either; the caller's policy decides.
    Acceptable,
}

/// A loaded test file.
#[derive(Debug, Clone)]
pub struct TestFile<G>
{
    /// The algorithm the file tests.
    pub algorithm: String,
    /// The schema the file declares.
    pub schema: String,
    /// The number of cases the file declares, which [`load`] checked.
    pub number_of_tests: usize,
    /// The test groups.
    pub groups: Vec<G>,
}

impl Expected
{
    /// The case's `result` member.
    fn from_json(case: &Value) -> Result<Self, LoadError>
    {
        match vectors::string(case, "result")?
        {
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            "acceptable" => Ok(Self::Acceptable),
            other => Err(LoadError::Parse(format!("unknown result {other:?}"))),
        }
    }
}

/// What every case carries, whatever its schema.
pub trait Case
{
    /// The case id (`tcId`).
    fn id(&self) -> u64;
    /// The expected result.
    fn expected(&self) -> Expected;
    /// The case's comment.
    fn comment(&self) -> &str;
    /// The case's flags.
    fn flags(&self) -> &[String];
}

/// A test group of one schema.
pub trait Group: Sized
{
    /// The `type` every group of the schema carries.
    const TYPE: &'static str;
    /// The schema's case.
    type Case: Case;
    /// Read a group of the schema, whatever its `type`, which [`load`]
    /// checks.
    ///
    /// # Errors
    ///
    /// [`LoadError::Parse`] for a missing field, a field of another type, an
    /// unknown result, or bad hex.
    fn from_json(group: &Value) -> Result<Self, LoadError>;
    /// This group's `type`.
    fn group_type(&self) -> &str;
    /// This group's cases.
    fn cases(&self) -> &[Self::Case];
}

/// Load `source` as a file of `G` groups.
///
/// # Errors
///
/// A [`LoadError`] when the file does not parse, declares another schema,
/// holds a group of another type, holds another number of cases than it
/// declares, or repeats a `tcId`.
pub fn load<G: Group>(source: &Source) -> Result<TestFile<G>, LoadError>
{
    parse(source.json, source.schema)
}

fn parse<G: Group>(json: &str, schema: &str) -> Result<TestFile<G>, LoadError>
{
    let document = vectors::document(json)?;
    let algorithm = vectors::string(&document, "algorithm")?.to_owned();
    let declared_schema = vectors::string(&document, "schema")?.to_owned();
    let number_of_tests = vectors::count(&document, "numberOfTests")?;
    let groups = vectors::array(&document, "testGroups")?
        .iter()
        .map(G::from_json)
        .collect::<Result<Vec<G>, LoadError>>()?;
    if declared_schema != schema
    {
        return Err(LoadError::Schema(declared_schema));
    }
    let mut ids = HashSet::new();
    for group in &groups
    {
        if group.group_type() != G::TYPE
        {
            return Err(LoadError::GroupType(group.group_type().to_owned()));
        }
        for case in group.cases()
        {
            if !ids.insert(case.id())
            {
                return Err(LoadError::DuplicateId(case.id()));
            }
        }
    }
    if ids.len() != number_of_tests
    {
        return Err(LoadError::Count {
            declared: number_of_tests,
            found: ids.len(),
        });
    }
    Ok(TestFile {
        algorithm,
        schema: declared_schema,
        number_of_tests,
        groups,
    })
}

/// One case as a run reports it.
struct Labelled<'a, G: Group>
{
    group: &'a G,
    case: &'a G::Case,
}

impl<G: Group> fmt::Debug for Labelled<'_, G>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(
            f,
            "tcId {} ({:?}, {:?}, flags {:?})",
            self.case.id(),
            self.case.expected(),
            self.case.comment(),
            self.case.flags()
        )
    }
}

/// Run every case of `file`: `accepts` is the implementation's verdict (true
/// for accepted), and `acceptable` the caller's policy for an `acceptable`
/// case (true when the implementation is required to accept it).
///
/// The report holds every case whose verdict differs from the expected one.
pub fn run<G: Group>(
    file: &TestFile<G>,
    name: &str,
    mut accepts: impl FnMut(&G, &G::Case) -> bool,
    mut acceptable: impl FnMut(&G, &G::Case) -> bool,
) -> Report
{
    let cases = file.groups.iter().flat_map(|group| {
        group
            .cases()
            .iter()
            .map(move |case| Labelled { group, case })
    });
    differential::compare(
        name,
        cases,
        |c| accepts(c.group, c.case),
        |c| match c.case.expected()
        {
            Expected::Valid => true,
            Expected::Invalid => false,
            Expected::Acceptable => acceptable(c.group, c.case),
        },
    )
}

/// The `EddsaVerify` schema (`eddsa_verify_schema_v1.json`): a public key per
/// group, and a message and signature per case.
pub mod eddsa
{
    use super::{Case as _, Expected, LoadError, Value, vectors};

    /// An `EddsaVerify` group.
    #[derive(Debug, Clone)]
    pub struct Group
    {
        kind: String,
        /// The group's public key.
        pub public_key: PublicKey,
        /// The group's cases.
        pub tests: Vec<Case>,
    }

    /// An `EddsaVerify` group's public key.
    #[derive(Debug, Clone)]
    pub struct PublicKey
    {
        /// The curve (`edwards25519`).
        pub curve: String,
        /// The raw public key.
        pub pk: Vec<u8>,
    }

    /// An `EddsaVerify` case.
    #[derive(Debug, Clone)]
    pub struct Case
    {
        tc_id: u64,
        comment: String,
        flags: Vec<String>,
        /// The signed message.
        pub msg: Vec<u8>,
        /// The signature, of any length: a case may carry a truncated or
        /// extended one.
        pub sig: Vec<u8>,
        result: Expected,
    }

    impl Case
    {
        fn from_json(case: &Value) -> Result<Self, LoadError>
        {
            Ok(Self {
                tc_id: vectors::integer(case, "tcId")?,
                comment: vectors::string(case, "comment")?.to_owned(),
                flags: vectors::strings(case, "flags")?,
                msg: vectors::bytes(case, "msg")?,
                sig: vectors::bytes(case, "sig")?,
                result: Expected::from_json(case)?,
            })
        }

        /// Whether the case carries `flag`.
        #[must_use]
        pub fn has_flag(&self, flag: &str) -> bool
        {
            self.flags().iter().any(|f| f == flag)
        }
    }

    impl super::Case for Case
    {
        fn id(&self) -> u64
        {
            self.tc_id
        }

        fn expected(&self) -> Expected
        {
            self.result
        }

        fn comment(&self) -> &str
        {
            &self.comment
        }

        fn flags(&self) -> &[String]
        {
            &self.flags
        }
    }

    impl super::Group for Group
    {
        const TYPE: &'static str = "EddsaVerify";
        type Case = Case;

        fn from_json(group: &Value) -> Result<Self, LoadError>
        {
            let key = vectors::field(group, "publicKey")?;
            Ok(Self {
                kind: vectors::string(group, "type")?.to_owned(),
                public_key: PublicKey {
                    curve: vectors::string(key, "curve")?.to_owned(),
                    pk: vectors::bytes(key, "pk")?,
                },
                tests: vectors::array(group, "tests")?
                    .iter()
                    .map(Case::from_json)
                    .collect::<Result<_, _>>()?,
            })
        }

        fn group_type(&self) -> &str
        {
            &self.kind
        }

        fn cases(&self) -> &[Case]
        {
            &self.tests
        }
    }
}

/// The `AeadTest` schema (`aead_test_schema_v1.json`): the key, nonce (`iv`),
/// AAD, plaintext (`msg`), ciphertext and tag per case. A `valid` case is a
/// correct encryption; an `invalid` one carries a modified tag or a nonce of
/// another size than the algorithm's.
pub mod aead
{
    use super::{Expected, LoadError, Value, vectors};

    /// An `AeadTest` group.
    #[derive(Debug, Clone)]
    pub struct Group
    {
        kind: String,
        /// The key size of every case, in bits.
        pub key_size: usize,
        /// The nonce size of every case, in bits.
        pub iv_size: usize,
        /// The tag size of every case, in bits.
        pub tag_size: usize,
        /// The group's cases.
        pub tests: Vec<Case>,
    }

    /// An `AeadTest` case.
    #[derive(Debug, Clone)]
    pub struct Case
    {
        tc_id: u64,
        comment: String,
        flags: Vec<String>,
        /// The key.
        pub key: Vec<u8>,
        /// The nonce, of any length: a case may carry one of another size.
        pub iv: Vec<u8>,
        /// The associated data.
        pub aad: Vec<u8>,
        /// The plaintext.
        pub msg: Vec<u8>,
        /// The ciphertext, as long as the plaintext.
        pub ct: Vec<u8>,
        /// The tag.
        pub tag: Vec<u8>,
        result: Expected,
    }

    impl Case
    {
        fn from_json(case: &Value) -> Result<Self, LoadError>
        {
            Ok(Self {
                tc_id: vectors::integer(case, "tcId")?,
                comment: vectors::string(case, "comment")?.to_owned(),
                flags: vectors::strings(case, "flags")?,
                key: vectors::bytes(case, "key")?,
                iv: vectors::bytes(case, "iv")?,
                aad: vectors::bytes(case, "aad")?,
                msg: vectors::bytes(case, "msg")?,
                ct: vectors::bytes(case, "ct")?,
                tag: vectors::bytes(case, "tag")?,
                result: Expected::from_json(case)?,
            })
        }
    }

    impl super::Case for Case
    {
        fn id(&self) -> u64
        {
            self.tc_id
        }

        fn expected(&self) -> Expected
        {
            self.result
        }

        fn comment(&self) -> &str
        {
            &self.comment
        }

        fn flags(&self) -> &[String]
        {
            &self.flags
        }
    }

    impl super::Group for Group
    {
        const TYPE: &'static str = "AeadTest";
        type Case = Case;

        fn from_json(group: &Value) -> Result<Self, LoadError>
        {
            Ok(Self {
                kind: vectors::string(group, "type")?.to_owned(),
                key_size: vectors::count(group, "keySize")?,
                iv_size: vectors::count(group, "ivSize")?,
                tag_size: vectors::count(group, "tagSize")?,
                tests: vectors::array(group, "tests")?
                    .iter()
                    .map(Case::from_json)
                    .collect::<Result<_, _>>()?,
            })
        }

        fn group_type(&self) -> &str
        {
            &self.kind
        }

        fn cases(&self) -> &[Case]
        {
            &self.tests
        }
    }
}

/// The ML-DSA schemas: `MlDsaVerify` (`mldsa_verify_schema.json`), a public
/// key per group and a message, an optional context and a signature per case;
/// and `MlDsaSign` (`mldsa_sign_seed_schema.json`), a private seed and its
/// public key per group, and per case a message or a message representative
/// mu, an optional context and randomness, and the expected signature.
pub mod mldsa
{
    use super::{Expected, LoadError, Value, vectors};

    /// The members every case of both schemas carries.
    #[derive(Debug, Clone)]
    struct Common
    {
        tc_id: u64,
        comment: String,
        flags: Vec<String>,
        result: Expected,
    }

    impl Common
    {
        fn from_json(case: &Value) -> Result<Self, LoadError>
        {
            Ok(Self {
                tc_id: vectors::integer(case, "tcId")?,
                comment: vectors::string(case, "comment")?.to_owned(),
                flags: vectors::strings(case, "flags")?,
                result: Expected::from_json(case)?,
            })
        }
    }

    /// An `MlDsaVerify` group.
    #[derive(Debug, Clone)]
    pub struct VerifyGroup
    {
        kind: String,
        /// The raw public key, of any length: a group may carry one of
        /// another size.
        pub public_key: Vec<u8>,
        /// The group's cases.
        pub tests: Vec<VerifyCase>,
    }

    /// An `MlDsaVerify` case.
    #[derive(Debug, Clone)]
    pub struct VerifyCase
    {
        common: Common,
        /// The signed message.
        pub msg: Vec<u8>,
        /// The context string; empty when the case has none.
        pub ctx: Vec<u8>,
        /// The signature, of any length.
        pub sig: Vec<u8>,
    }

    /// An `MlDsaSign` group.
    #[derive(Debug, Clone)]
    pub struct SignGroup
    {
        kind: String,
        /// The key-generation seed, of any length: a group may carry one of
        /// another size.
        pub private_seed: Vec<u8>,
        /// The public key the seed derives; `None` for a group whose seed has
        /// no key, being of another size (the file gives null).
        pub public_key: Option<Vec<u8>>,
        /// The group's cases.
        pub tests: Vec<SignCase>,
    }

    /// An `MlDsaSign` case: it signs `msg` with context `ctx`, or, when
    /// `msg` is absent, the message representative `mu` through the
    /// internal interface.
    #[derive(Debug, Clone)]
    pub struct SignCase
    {
        common: Common,
        /// The message, when the case signs one.
        pub msg: Option<Vec<u8>>,
        /// The message representative, which a case without `msg` signs.
        pub mu: Option<Vec<u8>>,
        /// The context string; empty when the case has none.
        pub ctx: Vec<u8>,
        /// The randomness of a hedged signature; `None` for a deterministic
        /// one.
        pub rnd: Option<Vec<u8>>,
        /// The expected signature.
        pub sig: Vec<u8>,
    }

    impl VerifyCase
    {
        fn from_json(case: &Value) -> Result<Self, LoadError>
        {
            Ok(Self {
                common: Common::from_json(case)?,
                msg: vectors::bytes(case, "msg")?,
                ctx: vectors::optional_bytes(case, "ctx")?.unwrap_or_default(),
                sig: vectors::bytes(case, "sig")?,
            })
        }
    }

    impl SignCase
    {
        fn from_json(case: &Value) -> Result<Self, LoadError>
        {
            let case = Self {
                common: Common::from_json(case)?,
                msg: vectors::optional_bytes(case, "msg")?,
                mu: vectors::optional_bytes(case, "mu")?,
                ctx: vectors::optional_bytes(case, "ctx")?.unwrap_or_default(),
                rnd: vectors::optional_bytes(case, "rnd")?,
                sig: vectors::bytes(case, "sig")?,
            };
            if case.msg.is_none() && case.mu.is_none()
            {
                return Err(LoadError::Parse(format!(
                    "tcId {} has neither msg nor mu",
                    case.common.tc_id
                )));
            }
            Ok(case)
        }
    }

    macro_rules! case_members {
        ($case:ty) => {
            impl super::Case for $case
            {
                fn id(&self) -> u64
                {
                    self.common.tc_id
                }

                fn expected(&self) -> Expected
                {
                    self.common.result
                }

                fn comment(&self) -> &str
                {
                    &self.common.comment
                }

                fn flags(&self) -> &[String]
                {
                    &self.common.flags
                }
            }
        };
    }

    case_members!(VerifyCase);
    case_members!(SignCase);

    impl super::Group for VerifyGroup
    {
        const TYPE: &'static str = "MlDsaVerify";
        type Case = VerifyCase;

        fn from_json(group: &Value) -> Result<Self, LoadError>
        {
            Ok(Self {
                kind: vectors::string(group, "type")?.to_owned(),
                public_key: vectors::bytes(group, "publicKey")?,
                tests: vectors::array(group, "tests")?
                    .iter()
                    .map(VerifyCase::from_json)
                    .collect::<Result<_, _>>()?,
            })
        }

        fn group_type(&self) -> &str
        {
            &self.kind
        }

        fn cases(&self) -> &[VerifyCase]
        {
            &self.tests
        }
    }

    impl super::Group for SignGroup
    {
        const TYPE: &'static str = "MlDsaSign";
        type Case = SignCase;

        fn from_json(group: &Value) -> Result<Self, LoadError>
        {
            Ok(Self {
                kind: vectors::string(group, "type")?.to_owned(),
                private_seed: vectors::bytes(group, "privateSeed")?,
                public_key: vectors::optional_bytes(group, "publicKey")?,
                tests: vectors::array(group, "tests")?
                    .iter()
                    .map(SignCase::from_json)
                    .collect::<Result<_, _>>()?,
            })
        }

        fn group_type(&self) -> &str
        {
            &self.kind
        }

        fn cases(&self) -> &[SignCase]
        {
            &self.tests
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const SCHEMA: &str = "eddsa_verify_schema_v1.json";

    /// A file of one group whose cases have the given ids and results, and
    /// which declares `declared` cases.
    fn file(declared: usize, cases: &[(u64, &str)], group_type: &str) -> String
    {
        let tests: Vec<String> = cases
            .iter()
            .map(|(id, result)| {
                format!(
                    r#"{{"tcId":{id},"comment":"","flags":[],"msg":"","sig":"00","result":"{result}"}}"#
                )
            })
            .collect();
        format!(
            r#"{{"algorithm":"EDDSA","schema":"{SCHEMA}","numberOfTests":{declared},
            "testGroups":[{{"type":"{group_type}","publicKey":{{"curve":"edwards25519","pk":"ab"}},
            "tests":[{}]}}]}}"#,
            tests.join(",")
        )
    }

    #[test]
    fn load_reads_every_case_of_a_well_formed_file()
    {
        let text = file(2, &[(1, "valid"), (2, "acceptable")], "EddsaVerify");
        let loaded = parse::<eddsa::Group>(&text, SCHEMA).unwrap();
        let group = &loaded.groups[0];
        assert_eq!(group.public_key.pk, [0xab]);
        let got: Vec<(u64, Expected)> =
            group.tests.iter().map(|c| (c.id(), c.expected())).collect();
        assert_eq!(got, [(1, Expected::Valid), (2, Expected::Acceptable)]);
    }

    #[test]
    fn load_refuses_a_file_that_holds_fewer_or_more_cases_than_it_declares()
    {
        let short = file(3, &[(1, "valid"), (2, "invalid")], "EddsaVerify");
        assert_eq!(
            parse::<eddsa::Group>(&short, SCHEMA).unwrap_err(),
            LoadError::Count {
                declared: 3,
                found: 2
            }
        );
        let long = file(1, &[(1, "valid"), (2, "invalid")], "EddsaVerify");
        assert!(matches!(
            parse::<eddsa::Group>(&long, SCHEMA),
            Err(LoadError::Count { .. })
        ));
    }

    #[test]
    fn load_refuses_a_repeated_case_id()
    {
        let text = file(2, &[(7, "valid"), (7, "invalid")], "EddsaVerify");
        assert_eq!(
            parse::<eddsa::Group>(&text, SCHEMA).unwrap_err(),
            LoadError::DuplicateId(7)
        );
    }

    #[test]
    fn load_refuses_another_schema_group_type_or_result()
    {
        let text = file(1, &[(1, "valid")], "EddsaVerify");
        assert!(matches!(
            parse::<eddsa::Group>(&text, "other_schema.json"),
            Err(LoadError::Schema(_))
        ));
        let text = file(1, &[(1, "valid")], "EcdsaVerify");
        assert!(matches!(
            parse::<eddsa::Group>(&text, SCHEMA),
            Err(LoadError::GroupType(_))
        ));
        let text = file(1, &[(1, "maybe")], "EddsaVerify");
        assert!(matches!(
            parse::<eddsa::Group>(&text, SCHEMA),
            Err(LoadError::Parse(_))
        ));
    }

    #[test]
    fn an_mldsa_sign_case_needs_a_message_or_mu_and_reads_its_optional_members()
    {
        use json::parse as json;
        let full = json(r#"{"tcId":1,"comment":"","flags":[],"msg":"01","ctx":"02","rnd":"03","sig":"04","result":"valid"}"#).unwrap();
        let case = <mldsa::SignGroup as Group>::from_json(
            &json(&format!(
                r#"{{"type":"MlDsaSign","privateSeed":"00","publicKey":"00","tests":[{full}]}}"#
            ))
            .unwrap(),
        )
        .unwrap();
        let case = &case.tests[0];
        assert_eq!(
            (
                case.msg.as_deref(),
                case.mu.as_deref(),
                case.ctx.as_slice(),
                case.rnd.as_deref()
            ),
            (Some(&[1u8][..]), None, &[2u8][..], Some(&[3u8][..]))
        );
        let bare = json(r#"{"type":"MlDsaSign","privateSeed":"00","publicKey":"00","tests":[{"tcId":1,"comment":"","flags":[],"sig":"04","result":"valid"}]}"#).unwrap();
        assert!(matches!(
            <mldsa::SignGroup as Group>::from_json(&bare),
            Err(LoadError::Parse(_))
        ));
    }

    #[test]
    fn run_holds_valid_and_invalid_cases_to_their_result_and_acceptable_ones_to_the_policy()
    {
        let text = file(
            4,
            &[
                (1, "valid"),
                (2, "invalid"),
                (3, "acceptable"),
                (4, "acceptable"),
            ],
            "EddsaVerify",
        );
        let loaded = parse::<eddsa::Group>(&text, SCHEMA).unwrap();
        // The implementation accepts 1 and 3; the policy requires 3 accepted
        // and 4 rejected: every case agrees.
        let accepts = |_: &eddsa::Group, c: &eddsa::Case| c.id() % 2 == 1;
        let policy = |_: &eddsa::Group, c: &eddsa::Case| c.id() == 3;
        assert!(run(&loaded, "agree", accepts, policy).agrees());
        // An implementation that accepts everything fails cases 2 and 4.
        let report = run(&loaded, "lenient", |_, _| true, policy);
        let failed: Vec<bool> = report
            .disagreements
            .iter()
            .map(|d| d.case.starts_with("tcId 2 ") || d.case.starts_with("tcId 4 "))
            .collect();
        assert_eq!(failed, [true, true]);
    }
}
