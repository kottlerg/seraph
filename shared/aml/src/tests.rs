// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/tests.rs

//! Tests of the parser and the loader: the checked-in QEMU tables, the
//! no-panic properties over prefixes and arbitrary bytes, and one
//! hand-assembled case per grammar piece.

use std::path::{Path, PathBuf};
use std::{fs, thread};

use crate::encoding::Seg;
use crate::namespace::{
    AccessAs, Body, Data, FieldKind, FieldUnit, Namespace, NodeId, Object, Owner,
};
use crate::parse::Parser;
use crate::resource::{self, Resource};
use crate::term::{FieldElem, Imm, Name, Op, Term};
use crate::{FaultKind, LoadReport, MAX_PARSE_DEPTH};

// ── Builders ──────────────────────────────────────────────────────────

/// `PkgLength` of a package of `payload` bytes after it, in its shortest
/// form.
fn pkg(payload: usize) -> Vec<u8>
{
    for n in 1..=4usize
    {
        let len = payload + n;
        if n == 1 && len <= 63
        {
            return vec![u8::try_from(len).unwrap()];
        }
        if n > 1 && len < 1 << (4 + 8 * (n - 1))
        {
            let mut out =
                vec![(u8::try_from(n - 1).unwrap() << 6) | u8::try_from(len & 0xF).unwrap()];
            for i in 0..n - 1
            {
                out.push(u8::try_from((len >> (4 + 8 * i)) & 0xFF).unwrap());
            }
            return out;
        }
    }
    panic!("package too long");
}

/// A name string from ASL-style text: `\`, `^`s, then dot-separated
/// segments padded with `_`.
fn name(text: &str) -> Vec<u8>
{
    let mut out = Vec::new();
    let mut rest = text;
    if let Some(r) = rest.strip_prefix('\\')
    {
        out.push(b'\\');
        rest = r;
    }
    while let Some(r) = rest.strip_prefix('^')
    {
        out.push(b'^');
        rest = r;
    }
    if rest.is_empty()
    {
        out.push(0);
        return out;
    }
    let segs: Vec<Vec<u8>> = rest
        .split('.')
        .map(|s| {
            let mut v = s.as_bytes().to_vec();
            v.resize(4, b'_');
            v
        })
        .collect();
    match segs.len()
    {
        1 =>
        {}
        2 => out.push(0x2E),
        n =>
        {
            out.push(0x2F);
            out.push(u8::try_from(n).unwrap());
        }
    }
    for s in segs
    {
        out.extend(s);
    }
    out
}

/// A package-length object: `op`, `PkgLength`, then `body`.
fn pkg_obj(op: &[u8], body: &[u8]) -> Vec<u8>
{
    let mut out = op.to_vec();
    out.extend(pkg(body.len()));
    out.extend_from_slice(body);
    out
}

fn cat(parts: &[&[u8]]) -> Vec<u8>
{
    parts.concat()
}

fn scope(n: &str, body: &[u8]) -> Vec<u8>
{
    pkg_obj(&[0x10], &cat(&[&name(n), body]))
}

fn device(n: &str, body: &[u8]) -> Vec<u8>
{
    pkg_obj(&[0x5B, 0x82], &cat(&[&name(n), body]))
}

fn method(n: &str, args: u8, body: &[u8]) -> Vec<u8>
{
    pkg_obj(&[0x14], &cat(&[&name(n), &[args], body]))
}

fn name_obj(n: &str, data: &[u8]) -> Vec<u8>
{
    cat(&[&[0x08], &name(n), data])
}

fn byte(v: u8) -> Vec<u8>
{
    vec![0x0A, v]
}

fn dword(v: u32) -> Vec<u8>
{
    let mut out = vec![0x0C];
    out.extend(v.to_le_bytes());
    out
}

fn string(s: &str) -> Vec<u8>
{
    let mut out = vec![0x0D];
    out.extend(s.as_bytes());
    out.push(0);
    out
}

fn buffer(size: &[u8], init: &[u8]) -> Vec<u8>
{
    pkg_obj(&[0x11], &cat(&[size, init]))
}

fn package(count: u8, elems: &[Vec<u8>]) -> Vec<u8>
{
    pkg_obj(&[0x12], &cat(&[&[count], &elems.concat()]))
}

fn if_(pred: &[u8], body: &[u8]) -> Vec<u8>
{
    pkg_obj(&[0xA0], &cat(&[pred, body]))
}

fn else_(body: &[u8]) -> Vec<u8>
{
    pkg_obj(&[0xA1], body)
}

fn ret(v: &[u8]) -> Vec<u8>
{
    cat(&[&[0xA4], v])
}

fn store(src: &[u8], dst: &[u8]) -> Vec<u8>
{
    cat(&[&[0x70], src, dst])
}

const LOCAL0: u8 = 0x60;
const ARG0: u8 = 0x68;

/// A DSDT of revision `rev` holding `aml`.
fn table_rev(aml: &[u8], rev: u8) -> Vec<u8>
{
    let mut t = b"DSDT".to_vec();
    t.extend(u32::try_from(36 + aml.len()).unwrap().to_le_bytes());
    t.push(rev);
    t.resize(36, 0);
    t.extend_from_slice(aml);
    t
}

fn table(aml: &[u8]) -> Vec<u8>
{
    table_rev(aml, 2)
}

/// A namespace with `aml` loaded; the load must meet no fault.
fn load(aml: &[u8]) -> Namespace
{
    let mut ns = Namespace::new().unwrap();
    let r = ns.load_table(&table(aml)).unwrap();
    assert_eq!(r.faults, 0, "{r:?}");
    ns
}

/// The parsed code of the method at `path`.
fn code(ns: &mut Namespace, path: &str) -> Vec<Term>
{
    let id = ns.find(path).unwrap_or_else(|| panic!("{path} not found"));
    let code = ns.method_code(id).unwrap();
    ns.code(code).unwrap().to_vec()
}

fn seg(s: &str) -> Seg
{
    let mut out = *b"____";
    out[..s.len()].copy_from_slice(s.as_bytes());
    out
}

fn data(ns: &Namespace, path: &str) -> Data
{
    match ns.object(ns.find(path).unwrap())
    {
        Some(Object::Data(d)) => d.clone(),
        other => panic!("{path}: {other:?}"),
    }
}

// ── Fixtures ──────────────────────────────────────────────────────────

/// The captured configurations, each a directory of tables.
fn fixture_dirs() -> Vec<PathBuf>
{
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let mut dirs: Vec<PathBuf> = fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

/// Whether the file name `n` has the `.aml` extension.
fn is_aml(n: &str) -> bool
{
    Path::new(n)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("aml"))
}

/// The AML tables of one configuration: the DSDT, then the SSDTs in the
/// order of their numbers (`SSDT1.aml`, `SSDT2.aml`, ...), the order the
/// capture found them in the XSDT.
fn aml_tables(dir: &Path) -> Vec<(String, Vec<u8>)>
{
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("SSDT") && is_aml(n))
        .collect();
    names.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
    let dsdt = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .find(|n| n.starts_with("DSDT") && is_aml(n))
        .unwrap_or_else(|| panic!("no DSDT in {}", dir.display()));
    names.insert(0, dsdt);
    names
        .into_iter()
        .map(|n| {
            let bytes = fs::read(dir.join(&n)).unwrap();
            (n, bytes)
        })
        .collect()
}

/// Load one configuration; every load and every method parse must meet no
/// fault.
fn load_fixture(dir: &Path) -> Namespace
{
    let mut ns = Namespace::new().unwrap();
    for (n, bytes) in aml_tables(dir)
    {
        let r: LoadReport = ns.load_table(&bytes).unwrap();
        assert_eq!(r.faults, 0, "{}/{n}: {r:?}", dir.display());
        assert!(r.objects > 0, "{}/{n}", dir.display());
    }
    let (parsed, faults, first) = ns.parse_methods();
    assert_eq!(faults, 0, "{}: first {first:?}", dir.display());
    assert!(parsed > 0);
    ns
}

#[test]
fn every_fixture_loads_and_parses_without_fault()
{
    let dirs = fixture_dirs();
    assert_eq!(dirs.len(), 4, "{dirs:?}");
    for dir in dirs
    {
        let ns = load_fixture(&dir);
        assert!(ns.find("\\_SB.PCI0").is_some(), "{}", dir.display());
        // Every call in every method names a method of the namespace.
        for id in ns.nodes()
        {
            if let Some(Object::Method(m)) = ns.object(id)
                && let Some(c) = m.code
            {
                for t in ns.code(c).unwrap()
                {
                    check_calls(&ns, id, t);
                }
            }
        }
    }
}

/// Every [`Op::Call`] under `t` resolves from `scope` to a method taking as
/// many arguments as it has kids.
fn check_calls(ns: &Namespace, scope: NodeId, t: &Term)
{
    if t.op == Op::Call
    {
        let n = ns
            .follow(ns.resolve(scope, t.name().unwrap()).unwrap())
            .unwrap();
        let args = match ns.object(n)
        {
            Some(Object::Method(m)) => m.args,
            Some(Object::External { args, .. }) => *args,
            other => panic!("{other:?}"),
        };
        assert_eq!(usize::from(args), t.kids.len());
    }
    for k in &t.kids
    {
        check_calls(ns, scope, k);
    }
}

#[test]
fn x86_fixture_objects()
{
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/x86-default");
    let mut ns = load_fixture(&dir);
    // `_S5_` is a package of two zeros on q35.
    let Data::Package(s5) = data(&ns, "\\_S5")
    else
    {
        panic!();
    };
    assert_eq!(s5[0], Data::Integer(0));
    // The host bridge's static `_CRS` decodes to the bus range first.
    let Data::Buffer(crs) = data(&ns, "\\_SB.PCI0._CRS")
    else
    {
        panic!("PCI0._CRS is not a buffer");
    };
    let first = resource::descriptors(&crs).next().unwrap().unwrap();
    let Resource::Address(a) = first
    else
    {
        panic!("{first:?}");
    };
    assert_eq!((a.space, a.min, a.max), (resource::SPACE_BUS, 0, 0xFF));
    assert!(resource::descriptors(&crs).all(|r| r.is_ok()));
    // `_PRT` is a method choosing between the PIC and APIC tables.
    assert!(matches!(
        ns.object(ns.find("\\_SB.PCI0._PRT").unwrap()),
        Some(Object::Method(_))
    ));
    // The GPE block's `_E01` is an empty method in this configuration.
    let e01 = code(&mut ns, "\\_GPE._E01");
    assert_eq!(e01, Vec::new());
    // A field unit of the PCI hotplug region.
    let pciu = ns.find("\\_SB.PCI0.PCIU").unwrap();
    let Some(Object::Field(f)) = ns.object(pciu)
    else
    {
        panic!();
    };
    assert!(matches!(f.kind, FieldKind::Region(_)));
    assert_eq!(f.bit_len, 32);
}

// ── No panic ──────────────────────────────────────────────────────────

/// Load `t` and parse every method; the result is irrelevant.
fn churn(t: &[u8])
{
    let mut ns = Namespace::new().unwrap();
    let _ = ns.load_table(t);
    let _ = ns.parse_methods();
    for m in ns.module_terms()
    {
        let _ = m.term.count();
    }
}

/// A table whose AML is `aml`, cut to `k` bytes with its length field
/// matching.
fn cut(t: &[u8], k: usize) -> Vec<u8>
{
    let mut v = t[..k].to_vec();
    if v.len() >= 8
    {
        let len = u32::try_from(k).unwrap();
        v[4..8].copy_from_slice(&len.to_le_bytes());
    }
    v
}

/// A hand-assembled table that uses every construct the builders make.
fn sample() -> Vec<u8>
{
    let body = cat(&[
        &name_obj(
            "PKG0",
            &package(3, &[byte(1), string("A"), name("\\_SB.DEV0")]),
        ),
        &method(
            "MTH0",
            2,
            &cat(&[
                &if_(&[0x93, ARG0, 0x01], &ret(&[0x01])),
                &else_(&store(&[0x72, ARG0, ARG0 + 1, 0x00], &[LOCAL0])),
                &ret(&[LOCAL0]),
            ]),
        ),
        &device(
            "DEV0",
            &cat(&[
                &name_obj("_HID", &dword(0x0105_D041)),
                &name_obj("_CRS", &buffer(&byte(4), &[0x4B, 0x60, 0, 5, 0x79, 0])),
                &method("_STA", 0, &ret(&cat(&[&[0x0A, 0x0F]]))),
            ]),
        ),
        &cat(&[&[0x5B, 0x80], &name("REG0"), &[1], &dword(0x400), &byte(8)]),
        &pkg_obj(
            &[0x5B, 0x81],
            &cat(&[&name("REG0"), &[1], b"FLD0", &[8], &[0, 8], b"FLD1", &[8]]),
        ),
        &cat(&[&[0x70], &name("MTH0"), &byte(1), &byte(2), &name("FLD0")]),
    ]);
    table(&scope("\\_SB", &body))
}

#[test]
fn sample_loads_without_fault()
{
    let mut ns = Namespace::new().unwrap();
    let r = ns.load_table(&sample()).unwrap();
    assert_eq!(r.faults, 0, "{r:?}");
    assert_eq!(r.module_terms, 1);
    let (parsed, faults, _) = ns.parse_methods();
    assert_eq!((parsed, faults), (2, 0));
}

#[test]
fn every_prefix_of_hand_assembled_aml_terminates()
{
    let t = sample();
    for k in 0..=t.len()
    {
        churn(&cut(&t, k));
        // The same bytes with the full length field: a table shorter than
        // its header says is refused.
        churn(&t[..k]);
    }
}

#[test]
fn every_prefix_of_every_method_body_terminates()
{
    for dir in fixture_dirs()
    {
        let ns = load_fixture(&dir);
        for id in ns.nodes()
        {
            let Some(Object::Method(m)) = ns.object(id)
            else
            {
                continue;
            };
            let Body::Aml { table, start, end } = m.body
            else
            {
                continue;
            };
            let bytes = ns.table_bytes(table).unwrap();
            let (start, end) = (start as usize, end as usize);
            for k in start..=end
            {
                let _ = Parser::new(&ns, bytes, start, k, id).term_list();
            }
        }
    }
}

#[test]
fn fixture_prefixes_and_mutations_terminate()
{
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut rand = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for dir in fixture_dirs()
    {
        for (_, t) in aml_tables(&dir)
        {
            for k in (0..=t.len()).step_by(61)
            {
                churn(&cut(&t, k));
            }
            for _ in 0..64
            {
                let mut m = t.clone();
                for _ in 0..=rand() % 8
                {
                    let i = 36 + usize::try_from(rand()).unwrap() % (m.len() - 36);
                    m[i] = u8::try_from(rand() & 0xFF).unwrap();
                }
                churn(&m);
            }
        }
    }
}

#[test]
fn arbitrary_byte_strings_terminate()
{
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    let mut rand = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..4000
    {
        let len = usize::try_from(rand() % 96).unwrap();
        let aml: Vec<u8> = (0..len)
            .map(|_| u8::try_from(rand() & 0xFF).unwrap())
            .collect();
        churn(&table(&aml));
    }
    // Every two-byte string after each opcode-like lead.
    for a in 0..=255u8
    {
        for b in 0..=255u8
        {
            churn(&table(&[a, b, 0x0A, 0x01]));
        }
    }
}

// ── Grammar ───────────────────────────────────────────────────────────

#[test]
fn method_call_takes_its_argument_count_from_the_namespace()
{
    // `MTH1` is defined after `MTH0` calls it: method bodies parse after the
    // load, so the forward call has its arguments.
    let aml = cat(&[
        &method("MTH0", 0, &ret(&cat(&[&name("MTH1"), &byte(1), &byte(2)]))),
        &method("MTH1", 2, &ret(&[ARG0])),
        &method("MTH2", 0, &ret(&name("UNKN"))),
    ]);
    let mut ns = load(&aml);
    let c = code(&mut ns, "\\MTH0");
    let call = &c[0].kids[0];
    assert_eq!(call.op, Op::Call);
    assert_eq!(call.kids.len(), 2);
    assert_eq!(call.kids[1].int(), Some(2));
    let c = code(&mut ns, "\\MTH2");
    assert_eq!(c[0].kids[0].op, Op::NameRef);
}

#[test]
fn external_and_alias_give_arity()
{
    let aml = cat(&[
        &cat(&[&[0x15], &name("\\EXTM"), &[8, 1]]),
        &method("REAL", 1, &ret(&[ARG0])),
        &cat(&[&[0x06], &name("REAL"), &name("ALI0")]),
        &method(
            "CALL",
            0,
            &cat(&[
                &store(&cat(&[&name("EXTM"), &byte(3)]), &[LOCAL0]),
                &store(&cat(&[&name("ALI0"), &byte(4)]), &[LOCAL0]),
            ]),
        ),
    ]);
    let mut ns = load(&aml);
    let c = code(&mut ns, "\\CALL");
    for t in &c
    {
        assert_eq!(t.kids[0].op, Op::Call);
        assert_eq!(t.kids[0].kids.len(), 1);
    }
}

#[test]
fn reference_operands_never_invoke()
{
    // RefOf, CondRefOf and ObjectType of a method name are references.
    let aml = cat(&[
        &method("MTH1", 1, &ret(&[ARG0])),
        &method(
            "MTH0",
            0,
            &cat(&[
                &store(&cat(&[&[0x71], &name("MTH1")]), &[LOCAL0]),
                &cat(&[&[0x5B, 0x12], &name("MTH1"), &[LOCAL0 + 1]]),
                &store(&cat(&[&[0x8E], &name("MTH1")]), &[LOCAL0]),
                &cat(&[&[0x9D], &byte(1), &name("ZZZZ")]),
            ]),
        ),
    ]);
    let mut ns = load(&aml);
    let c = code(&mut ns, "\\MTH0");
    assert_eq!(c[0].kids[0].op, Op::RefOf);
    assert_eq!(c[0].kids[0].kids[0].op, Op::NameRef);
    assert_eq!(c[1].op, Op::CondRefOf);
    assert_eq!(c[1].kids[0].op, Op::NameRef);
    assert_eq!(c[1].kids[1].op, Op::Local);
    assert_eq!(c[2].kids[0].kids[0].op, Op::NameRef);
    assert_eq!(c[3].op, Op::CopyObject);
    assert_eq!(c[3].kids[1].op, Op::NameRef);
}

#[test]
fn targets_and_super_names()
{
    let aml = method(
        "MTH0",
        1,
        &cat(&[
            // Add (Arg0, 1, ) -- NullName target.
            &[0x72, ARG0, 0x01, 0x00],
            // Divide (Arg0, 3, Local1, Local2)
            &[0x78, ARG0, 0x0A, 3, LOCAL0 + 1, LOCAL0 + 2],
            // Store (1, Debug)
            &[0x70, 0x01, 0x5B, 0x31],
            // Store (2, Index (Arg0, 0))
            &[0x70, 0x0A, 2, 0x88, ARG0, 0x00, 0x00],
            // Increment (DerefOf (Local0))
            &[0x75, 0x83, LOCAL0],
        ]),
    );
    let mut ns = load(&aml);
    let c = code(&mut ns, "\\MTH0");
    assert_eq!(c[0].kids[2].op, Op::Null);
    assert_eq!(c[1].kids.len(), 4);
    assert_eq!(c[2].kids[1].op, Op::Debug);
    assert_eq!(c[3].kids[1].op, Op::Index);
    assert_eq!(c[3].kids[1].kids[2].op, Op::Null);
    assert_eq!(c[4].kids[0].op, Op::DerefOf);
}

#[test]
fn compound_comparisons_parse_as_lnot()
{
    // LNotEqual (Arg0, 1), LLessEqual, LGreaterEqual.
    let aml = method(
        "MTH0",
        1,
        &cat(&[
            &if_(&[0x92, 0x93, ARG0, 0x01], &[0xA3]),
            &if_(&[0x92, 0x94, ARG0, 0x01], &[0xA3]),
            &if_(&[0x92, 0x95, ARG0, 0x01], &[0xA3]),
        ]),
    );
    let mut ns = load(&aml);
    let c = code(&mut ns, "\\MTH0");
    for (t, inner) in c.iter().zip([Op::LEqual, Op::LGreater, Op::LLess])
    {
        assert_eq!(t.op, Op::If);
        assert_eq!(t.kids[0].op, Op::LNot);
        assert_eq!(t.kids[0].kids[0].op, inner);
    }
}

#[test]
fn else_attaches_to_its_if_and_a_stray_else_faults()
{
    let aml = method(
        "MTH0",
        1,
        &cat(&[
            &if_(&[ARG0], &ret(&[0x01])),
            &else_(&if_(&[ARG0], &ret(&[0x00]))),
            &[0xA3],
        ]),
    );
    let mut ns = load(&aml);
    let c = code(&mut ns, "\\MTH0");
    assert_eq!(c.len(), 2);
    assert_eq!(c[0].kids.len(), 3);
    // The Else's body is one If: it is an ElseIf of the first.
    assert_eq!(c[0].kids[2].op, Op::ElseIf);
    assert_eq!(c[0].kids[2].kids[1].op, Op::List);
    assert_eq!(c[1].op, Op::Noop);

    // An Else whose body is more than one If stays an Else.
    let aml = method(
        "MTH0",
        1,
        &cat(&[
            &if_(&[ARG0], &ret(&[0x01])),
            &else_(&cat(&[&if_(&[ARG0], &ret(&[0x00])), &[0xA3]])),
        ]),
    );
    let mut ns = load(&aml);
    let c = code(&mut ns, "\\MTH0");
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].kids[2].op, Op::Else);
    assert_eq!(c[0].kids[2].kids[0].kids.len(), 2);

    let stray = method("MTH0", 0, &cat(&[&[0xA3], &else_(&[0xA3])]));
    let mut ns = load(&stray);
    let id = ns.find("\\MTH0").unwrap();
    assert_eq!(ns.method_code(id).unwrap_err().kind, FaultKind::StrayElse);
}

#[test]
fn an_else_if_chain_of_any_length_nests_no_deeper()
{
    // A compiled Switch of CASES cases: If (LEqual (Arg0, k)) { Return (k) }
    // Else { If ... Else { Return (0xFF) } }, far past the depth bound.
    const CASES: u8 = 200;
    let case = |k: u8| if_(&cat(&[&[0x93, ARG0], &byte(k)]), &ret(&byte(k)));
    let mut chain = cat(&[&case(CASES - 1), &else_(&ret(&byte(0xFF)))]);
    for k in (0..CASES - 1).rev()
    {
        chain = cat(&[&case(k), &else_(&chain)]);
    }
    let mut ns = load(&method("SWCH", 1, &chain));
    let c = code(&mut ns, "\\SWCH");
    assert_eq!(c.len(), 1);
    let kids = &c[0].kids;
    assert_eq!(c[0].op, Op::If);
    assert_eq!(kids.len(), 2 + usize::from(CASES - 1) + 1);
    for (k, t) in kids[2..kids.len() - 1].iter().enumerate()
    {
        assert_eq!(t.op, Op::ElseIf);
        assert_eq!(t.kids[0].kids[1].int(), Some(u64::try_from(k + 1).unwrap()));
    }
    assert_eq!(kids.last().unwrap().op, Op::Else);

    // A chain that ends in an If ends in an ElseIf.
    let aml = method(
        "MTH0",
        1,
        &cat(&[&case(0), &else_(&cat(&[&case(1), &else_(&case(2))]))]),
    );
    let mut ns = load(&aml);
    let c = code(&mut ns, "\\MTH0");
    let ops: Vec<Op> = c[0].kids.iter().map(|t| t.op).collect();
    assert_eq!(ops, [Op::LEqual, Op::List, Op::ElseIf, Op::ElseIf]);
}

#[test]
fn statements_are_not_operands()
{
    let aml = method("MTH0", 0, &store(&[0xA3], &[LOCAL0]));
    let mut ns = load(&aml);
    let id = ns.find("\\MTH0").unwrap();
    assert_eq!(ns.method_code(id).unwrap_err().kind, FaultKind::NotOperand);
}

#[test]
fn while_and_nested_lists()
{
    let aml = method(
        "MTH0",
        1,
        &pkg_obj(
            &[0xA2],
            &cat(&[
                &[0x95, LOCAL0, ARG0],
                &[0x75, LOCAL0],
                &if_(&[0x01], &[0xA5]),
                &[0x9F],
            ]),
        ),
    );
    let mut ns = load(&aml);
    let c = code(&mut ns, "\\MTH0");
    assert_eq!(c[0].op, Op::While);
    assert_eq!(c[0].kids[0].op, Op::LLess);
    let body = &c[0].kids[1];
    assert_eq!(body.op, Op::List);
    assert_eq!(body.kids.len(), 3);
    assert_eq!(body.kids[1].kids[1].kids[0].op, Op::Break);
    assert_eq!(body.kids[2].op, Op::Continue);
}

#[test]
fn search_rules()
{
    // \_SB.DEV0.MTH0 refers to FOO (found in \_SB by search), to ^^BAR.FOO
    // (\_SB.BAR.FOO), to ^FOO (the parent's: undefined), and to BAR.FOO (a
    // two-segment path, which is not searched: undefined).
    let aml = scope(
        "\\_SB",
        &cat(&[
            &method("FOO_", 0, &ret(&[0x01])),
            &device("BAR_", &cat(&[&method("FOO_", 1, &ret(&[ARG0]))])),
            &device(
                "DEV0",
                &method(
                    "MTH0",
                    0,
                    &cat(&[
                        &store(&name("FOO"), &[LOCAL0]),
                        &store(&cat(&[&name("^^BAR.FOO"), &byte(9)]), &[LOCAL0]),
                        &store(&name("^FOO"), &[LOCAL0]),
                        &store(&name("BAR.FOO"), &[LOCAL0]),
                    ]),
                ),
            ),
        ]),
    );
    let mut ns = load(&aml);
    let c = code(&mut ns, "\\_SB.DEV0.MTH0");
    assert_eq!(c[0].kids[0].op, Op::Call);
    assert_eq!(c[0].kids[0].kids.len(), 0);
    assert_eq!(c[1].kids[0].op, Op::Call);
    assert_eq!(c[1].kids[0].kids.len(), 1);
    // ^FOO from the method's scope is \_SB.DEV0.FOO: undefined, a reference.
    assert_eq!(c[2].kids[0].op, Op::NameRef);
    assert_eq!(c[3].kids[0].op, Op::NameRef);
    assert_eq!(c.len(), 4);
    let dev = ns.find("\\_SB.DEV0").unwrap();
    let mth = ns.find("\\_SB.DEV0.MTH0").unwrap();
    assert_eq!(ns.parent(mth), Some(dev));
    let foo = ns.find("\\_SB.FOO").unwrap();
    let n = Name {
        root: false,
        up: 0,
        segs: vec![seg("FOO")],
    };
    assert_eq!(ns.resolve(mth, &n), Some(foo));
    let n = Name {
        root: false,
        up: 0,
        segs: vec![seg("BAR"), seg("FOO")],
    };
    assert_eq!(ns.resolve(mth, &n), None);
    assert_eq!(
        ns.resolve(ns.find("\\_SB").unwrap(), &n),
        ns.find("\\_SB.BAR.FOO")
    );
    assert_eq!(
        ns.resolve(
            mth,
            &Name {
                root: false,
                up: 2,
                segs: vec![seg("BAR"), seg("FOO")]
            }
        ),
        ns.find("\\_SB.BAR.FOO")
    );
    assert_eq!(
        ns.resolve(
            mth,
            &Name {
                root: false,
                up: 9,
                segs: vec![seg("FOO")]
            }
        ),
        None
    );
}

#[test]
fn name_data_folds_to_constants()
{
    let aml = cat(&[
        &name_obj("INT0", &dword(0x1234_5678)),
        &name_obj("STR0", &string("hello")),
        &name_obj("BUF0", &buffer(&byte(4), &[1, 2])),
        &name_obj("BUF1", &buffer(&[0x01], &[7, 8, 9])),
        &name_obj(
            "PKG0",
            &package(4, &[byte(1), name("\\INT0"), package(1, &[string("x")])]),
        ),
        &name_obj("VPK0", &pkg_obj(&[0x13], &cat(&[&byte(2), &[0xFF]]))),
        &name_obj("REV0", &[0x5B, 0x30]),
        &name_obj("ONES", &[0xFF]),
    ]);
    let ns = load(&aml);
    assert_eq!(data(&ns, "\\INT0"), Data::Integer(0x1234_5678));
    assert_eq!(data(&ns, "\\STR0"), Data::String(b"hello".to_vec()));
    assert_eq!(data(&ns, "\\BUF0"), Data::Buffer(vec![1, 2, 0, 0]));
    assert_eq!(data(&ns, "\\BUF1"), Data::Buffer(vec![7, 8, 9]));
    let Data::Package(p) = data(&ns, "\\PKG0")
    else
    {
        panic!();
    };
    assert_eq!(p.len(), 4);
    assert_eq!(p[0], Data::Integer(1));
    assert!(matches!(&p[1], Data::Reference(n) if n.root && n.segs == vec![seg("INT0")]));
    assert_eq!(p[2], Data::Package(vec![Data::String(b"x".to_vec())]));
    assert_eq!(p[3], Data::Uninitialized);
    assert_eq!(
        data(&ns, "\\VPK0"),
        Data::Package(vec![Data::Integer(u64::MAX), Data::Uninitialized])
    );
    assert_eq!(data(&ns, "\\REV0"), Data::Integer(crate::REVISION));
    assert_eq!(data(&ns, "\\ONES"), Data::Integer(u64::MAX));

    // A revision-1 table has 32-bit integers.
    let mut ns = Namespace::new().unwrap();
    ns.load_table(&table_rev(&name_obj("ONES", &[0xFF]), 1))
        .unwrap();
    assert_eq!(data(&ns, "\\ONES"), Data::Integer(0xFFFF_FFFF));

    // A buffer whose size is not constant is a fault.
    let mut ns = Namespace::new().unwrap();
    let r = ns
        .load_table(&table(&name_obj("BUF2", &buffer(&[LOCAL0], &[]))))
        .unwrap();
    assert_eq!(r.first_fault.unwrap().kind, FaultKind::NotConstant);
}

/// A namespace with a `Field`, an `IndexField` and a `BankField` over two
/// regions.
fn field_namespace() -> Namespace
{
    let field =
        |flags: u8, elems: &[u8]| pkg_obj(&[0x5B, 0x81], &cat(&[&name("REG0"), &[flags], elems]));
    let aml = cat(&[
        &cat(&[&[0x5B, 0x80], &name("REG0"), &[1], &dword(0xAE00), &byte(8)]),
        &field(
            0x01,
            &cat(&[
                b"AAAA",
                &[4],
                &[0x00, 4],          // Offset: 4 reserved bits
                &[0x01, 0x03, 0x00], // AccessAs (DWordAcc)
                b"BBBB",
                &[0x41, 0x01],             // 17 bits (two-byte PkgLength 0x11)
                &[0x03, 0x02, 0x0B, 0x04], // extended AccessAs
                &[0x02],
                &name("REG0"), // Connection (name)
                b"CCCC",
                &[1],
            ]),
        ),
        &cat(&[&[0x5B, 0x80], &name("IDXR"), &[1], &dword(0x70), &byte(2)]),
        &pkg_obj(
            &[0x5B, 0x81],
            &cat(&[&name("IDXR"), &[0x01], b"INDX", &[8], b"DATA", &[8]]),
        ),
        &pkg_obj(
            &[0x5B, 0x86],
            &cat(&[&name("INDX"), &name("DATA"), &[0x01], b"CMOS", &[8]]),
        ),
        &pkg_obj(
            &[0x5B, 0x87],
            &cat(&[
                &name("REG0"),
                &name("AAAA"),
                &byte(3),
                &[0x01],
                b"BNK0",
                &[8],
            ]),
        ),
    ]);
    load(&aml)
}

/// The field unit at `path`.
fn unit(ns: &Namespace, path: &str) -> FieldUnit
{
    match ns.object(ns.find(path).unwrap())
    {
        Some(Object::Field(f)) => *f,
        other => panic!("{other:?}"),
    }
}

#[test]
fn fields_create_units_at_their_bit_offsets()
{
    let ns = field_namespace();
    let unit = |p: &str| unit(&ns, p);
    let reg = ns.find("\\REG0").unwrap();
    let a = unit("\\AAAA");
    assert_eq!(
        (a.kind, a.flags, a.bit_offset, a.bit_len, a.access_as),
        (FieldKind::Region(reg), 1, 0, 4, None)
    );
    let b = unit("\\BBBB");
    assert_eq!((b.bit_offset, b.bit_len), (8, 0x11));
    assert_eq!(
        b.access_as,
        Some(AccessAs {
            kind: 3,
            attrib: 0,
            len: 0
        })
    );
    assert!(b.connection.is_none());
    let c = unit("\\CCCC");
    assert_eq!(c.bit_offset, 25);
    assert_eq!(
        c.access_as,
        Some(AccessAs {
            kind: 2,
            attrib: 0x0B,
            len: 4
        })
    );
    let conn = ns.expr(c.connection.unwrap()).unwrap();
    assert_eq!(conn.op, Op::NameRef);
}

#[test]
fn index_and_bank_fields_name_their_registers()
{
    let ns = field_namespace();
    let unit = |p: &str| unit(&ns, p);
    let reg = ns.find("\\REG0").unwrap();
    let cmos = unit("\\CMOS");
    assert_eq!(
        cmos.kind,
        FieldKind::Index {
            index: ns.find("\\INDX").unwrap(),
            data: ns.find("\\DATA").unwrap()
        }
    );
    let bnk = unit("\\BNK0");
    let FieldKind::Bank {
        region,
        bank,
        value,
    } = bnk.kind
    else
    {
        panic!();
    };
    assert_eq!((region, bank), (reg, ns.find("\\AAAA").unwrap()));
    assert_eq!(ns.expr(value).unwrap().int(), Some(3));
    let Some(Object::Region(r)) = ns.object(reg)
    else
    {
        panic!();
    };
    assert_eq!(r.space, 1);
    assert_eq!(ns.expr(r.offset).unwrap().int(), Some(0xAE00));
}

#[test]
fn field_list_parse_forms()
{
    // The field list of a Field inside a method, with a buffer connection.
    let elems = cat(&[&[0x02], &buffer(&byte(2), &[0x79, 0]), b"FLD0", &[8]]);
    let aml = method(
        "MTH0",
        0,
        &pkg_obj(&[0x5B, 0x81], &cat(&[&name("REG0"), &[0], &elems])),
    );
    let mut ns = load(&aml);
    let c = code(&mut ns, "\\MTH0");
    assert_eq!(c[0].op, Op::Field);
    let Imm::Fields(list) = &c[0].imm
    else
    {
        panic!();
    };
    assert!(matches!(&list.elems[0], FieldElem::Connect(t) if t.op == Op::Buffer));
    assert_eq!(
        list.elems[1],
        FieldElem::Named {
            name: *b"FLD0",
            bits: 8
        }
    );
}

#[test]
fn object_kinds()
{
    let aml = cat(&[
        &cat(&[&[0x5B, 0x01], &name("MTX0"), &[0x13]]),
        &cat(&[&[0x5B, 0x02], &name("EVT0")]),
        &pkg_obj(
            &[0x5B, 0x83],
            &cat(&[
                &name("CPU0"),
                &[1],
                &0x410u32.to_le_bytes(),
                &[6],
                &name_obj("XX00", &[0]),
            ]),
        ),
        &pkg_obj(&[0x5B, 0x84], &cat(&[&name("PWR0"), &[3], &[2, 0]])),
        &pkg_obj(
            &[0x5B, 0x85],
            &cat(&[&name("TZ00"), &method("_TMP", 0, &ret(&[0]))]),
        ),
        &cat(&[
            &[0x5B, 0x88],
            &name("DREG"),
            &string("FACP"),
            &string(""),
            &string(""),
        ]),
    ]);
    let ns = load(&aml);
    let obj = |p: &str| ns.object(ns.find(p).unwrap()).unwrap().clone();
    assert_eq!(obj("\\MTX0"), Object::Mutex { sync: 3 });
    assert_eq!(obj("\\EVT0"), Object::Event);
    assert_eq!(
        obj("\\CPU0"),
        Object::Processor {
            id: 1,
            pblk: 0x410,
            pblk_len: 6
        }
    );
    assert!(ns.find("\\CPU0.XX00").is_some());
    assert_eq!(obj("\\PWR0"), Object::PowerResource { level: 3, order: 2 });
    assert_eq!(obj("\\TZ00"), Object::ThermalZone);
    assert!(matches!(obj("\\TZ00._TMP"), Object::Method(_)));
    assert!(matches!(obj("\\DREG"), Object::DataRegion(_)));
    // The predefined objects.
    assert!(matches!(obj("\\_OSI"), Object::Method(m) if m.args == 1));
    assert_eq!(obj("\\_GL"), Object::Mutex { sync: 0 });
    assert_eq!(obj("\\_SB"), Object::Device);
    assert_eq!(obj("\\_REV"), Object::Data(Data::Integer(2)));
}

#[test]
fn module_level_code_is_kept_in_order()
{
    let aml = cat(&[
        &name_obj("FLAG", &[0x01]),
        &if_(&name("FLAG"), &name_obj("COND", &[0])),
        &cat(&[&[0x8A], &name("\\BUF0"), &[0x00], &name("DW00")]),
        &name_obj("BUF0", &buffer(&byte(4), &[])),
    ]);
    let ns = load(&aml);
    let m = ns.module_terms();
    assert_eq!(m.len(), 2);
    assert_eq!(m[0].term.op, Op::If);
    assert_eq!(m[0].scope, NodeId::ROOT);
    assert_eq!(m[1].term.op, Op::CreateDWordField);
    // The If's Name is the evaluator's to create.
    assert!(ns.find("\\COND").is_none());
}

#[test]
fn a_call_to_a_method_defined_later_in_the_table_parses_at_load()
{
    // If (One) { MTHA (1) } and OperationRegion (REG0, SystemMemory,
    // MTHB (1), 0x10), both before the methods they call.
    let aml = cat(&[
        &if_(&[0x01], &cat(&[&name("MTHA"), &byte(1)])),
        &cat(&[
            &[0x5B, 0x80],
            &name("REG0"),
            &[0x00],
            &name("MTHB"),
            &byte(1),
            &byte(0x10),
        ]),
        &device("DEV0", &method("MTHA", 1, &ret(&[ARG0]))),
        &method("MTHB", 1, &ret(&[ARG0])),
        &scope("\\", &method("MTHA", 1, &ret(&[ARG0]))),
    ]);
    let ns = load(&aml);
    let m = ns.module_terms();
    assert_eq!(m.len(), 1, "{m:?}");
    let call = &m[0].term.kids[1].kids[0];
    assert_eq!((call.op, call.kids.len()), (Op::Call, 1));
    let Some(Object::Region(r)) = ns.object(ns.find("\\REG0").unwrap())
    else
    {
        panic!("REG0 is not a region");
    };
    let offset = ns.expr(r.offset).unwrap();
    assert_eq!((offset.op, offset.kids.len()), (Op::Call, 1));
    assert_eq!(ns.expr(r.length).unwrap().int(), Some(0x10));
}

#[test]
fn a_load_counts_each_object_once()
{
    // Two walks, one count: the device, its method, the External and the
    // method defined over it.
    let aml = cat(&[
        &cat(&[&[0x15], &name("\\MTHX"), &[8, 1]]),
        &device("DEV0", &method("MTH0", 0, &[0xA3])),
        &method("MTHX", 1, &[0xA3]),
    ]);
    let mut ns = Namespace::new().unwrap();
    let r = ns.load_table(&table(&aml)).unwrap();
    assert_eq!((r.objects, r.faults), (4, 0), "{r:?}");
    // An External of a defined name creates nothing.
    let ssdt = cat(&[&[0x15], &name("\\DEV0"), &[6, 0]]);
    let r = ns.load_table(&table(&ssdt)).unwrap();
    assert_eq!((r.objects, r.faults), (0, 0), "{r:?}");
}

#[test]
fn a_fault_ends_only_its_enclosing_list()
{
    // DEV0's body holds a bad opcode after its first Name: the rest of DEV0
    // is lost, DEV1 loads.
    let aml = cat(&[
        &device(
            "DEV0",
            &cat(&[
                &name_obj("AAAA", &[0x01]),
                &[0xEE],
                &name_obj("BBBB", &[0x01]),
            ]),
        ),
        &device("DEV1", &name_obj("CCCC", &[0x01])),
        // An If whose body faults is skipped by its PkgLength.
        &if_(&[0x01], &[0xEE]),
        &name_obj("DDDD", &[0x01]),
        // A duplicate definition is a fault; the list continues.
        &name_obj("DDDD", &[0x00]),
        &name_obj("EEEE", &[0x01]),
    ]);
    let mut ns = Namespace::new().unwrap();
    let r = ns.load_table(&table(&aml)).unwrap();
    assert_eq!(r.faults, 3, "{r:?}");
    assert_eq!(r.first_fault.unwrap().kind, FaultKind::BadOpcode);
    assert!(ns.find("\\DEV0.AAAA").is_some());
    assert!(ns.find("\\DEV0.BBBB").is_none());
    assert!(ns.find("\\DEV1.CCCC").is_some());
    assert_eq!(data(&ns, "\\DDDD"), Data::Integer(1));
    assert!(ns.find("\\EEEE").is_some());
}

#[test]
fn scope_of_an_undefined_name_faults_and_external_defines_it()
{
    let aml = cat(&[&scope("\\NOPE", &name_obj("AAAA", &[0]))]);
    let mut ns = Namespace::new().unwrap();
    let r = ns.load_table(&table(&aml)).unwrap();
    assert_eq!(r.first_fault.unwrap().kind, FaultKind::NotFound);

    // An External is replaced by the definition; a Scope of it enters the
    // defined object.
    let ssdt = cat(&[
        &cat(&[&[0x15], &name("\\DEV0"), &[6, 0]]),
        &scope("\\DEV0", &name_obj("AAAA", &[0])),
    ]);
    let dsdt = device("DEV0", &[]);
    let mut ns = Namespace::new().unwrap();
    assert_eq!(ns.load_table(&table(&ssdt)).unwrap().faults, 0);
    assert!(matches!(
        ns.object(ns.find("\\DEV0").unwrap()),
        Some(Object::External { kind: 6, .. })
    ));
    assert_eq!(ns.load_table(&table(&dsdt)).unwrap().faults, 0);
    assert_eq!(ns.object(ns.find("\\DEV0").unwrap()), Some(&Object::Device));
    assert!(ns.find("\\DEV0.AAAA").is_some());
    // An External after the definition changes nothing; one whose parent is
    // undefined declares nothing and is no fault.
    let late = cat(&[
        &[0x15],
        &name("\\DEV0"),
        &[6, 0],
        &[0x15],
        &name("\\XXXX.YYYY"),
        &[8, 2],
    ]);
    assert_eq!(ns.load_table(&table(&late)).unwrap().faults, 0);
    assert_eq!(ns.object(ns.find("\\DEV0").unwrap()), Some(&Object::Device));
}

#[test]
fn depth_bound()
{
    // Nested LNot: depth-many terms in one If predicate.
    let nest = |n: usize| {
        let mut pred = vec![0x92; n];
        pred.push(0x01);
        method("MTH0", 0, &if_(&pred, &[0xA3]))
    };
    // The method body is one level, its If another, its predicate the rest.
    let mut ns = load(&nest(MAX_PARSE_DEPTH - 2));
    assert_eq!(ns.method_code(ns.find("\\MTH0").unwrap()).err(), None);
    let mut ns = load(&nest(MAX_PARSE_DEPTH));
    assert_eq!(
        ns.method_code(ns.find("\\MTH0").unwrap()).unwrap_err().kind,
        FaultKind::Depth
    );
    let mut ns = load(&nest(100_000));
    assert_eq!(
        ns.method_code(ns.find("\\MTH0").unwrap()).unwrap_err().kind,
        FaultKind::Depth
    );

    // Nested scopes in the loader.
    let mut body = name_obj("LEAF", &[0]);
    for _ in 0..MAX_PARSE_DEPTH + 4
    {
        body = device("D000", &body);
    }
    let mut ns = Namespace::new().unwrap();
    let r = ns.load_table(&table(&body)).unwrap();
    assert_eq!(r.first_fault.unwrap().kind, FaultKind::Depth);
}

#[test]
fn a_load_and_parse_fit_the_stack_budget_at_the_depth_bounds()
{
    // Each recursion the bound limits, at the bound: an operand chain, a
    // package chain, a statement chain (an If in an If), both as method code
    // and as module-level code, inside object bodies nested to the loader's
    // bound.
    let mut lnots = vec![0x92; MAX_PARSE_DEPTH - 2];
    lnots.push(0x01);
    let mut pkgs = byte(1);
    for _ in 0..MAX_PARSE_DEPTH - 2
    {
        pkgs = package(1, &[pkgs]);
    }
    let mut ifs = if_(&[0x01], &[0xA3]);
    for _ in 0..MAX_PARSE_DEPTH - 2
    {
        ifs = if_(&[0x01], &ifs);
    }
    let mut body = cat(&[
        &name_obj("PKGS", &pkgs),
        &ifs,
        &method("MTH0", 0, &if_(&lnots, &[0xA3])),
        &method("MTH1", 0, &ret(&pkgs)),
        &method("MTH2", 0, &ifs),
    ]);
    for _ in 0..MAX_PARSE_DEPTH - 1
    {
        body = device("D000", &body);
    }
    let t = table(&body);
    thread::Builder::new()
        .stack_size(crate::PARSE_STACK_BYTES)
        .spawn(move || {
            let mut ns = Namespace::new().unwrap();
            let r = ns.load_table(&t).unwrap();
            assert_eq!((r.faults, r.module_terms), (0, 1), "{r:?}");
            let (parsed, faults, first) = ns.parse_methods();
            assert_eq!((parsed, faults), (3, 0), "{first:?}");
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn frame_objects_are_removed_with_their_frame()
{
    let mut ns = load(&method("MTH0", 0, &[]));
    let mth = ns.find("\\MTH0").unwrap();
    let before = ns.len();
    let n = |s: &str| Name {
        root: false,
        up: 0,
        segs: vec![seg(s)],
    };
    let a = ns
        .create(
            mth,
            &n("LOC0"),
            Object::Data(Data::Integer(1)),
            Owner::Frame(7),
        )
        .unwrap();
    ns.create(a, &n("SUB0"), Object::Event, Owner::Frame(7))
        .unwrap();
    ns.create(mth, &n("LOC1"), Object::Event, Owner::Frame(8))
        .unwrap();
    assert_eq!(ns.len(), before + 3);
    ns.remove_owned(Owner::Frame(7)).unwrap();
    assert_eq!(ns.len(), before + 1);
    assert!(ns.find("\\MTH0.LOC0").is_none());
    assert!(ns.find("\\MTH0.LOC1").is_some());
    // The freed slots are reused.
    let c = ns
        .create(mth, &n("LOC2"), Object::Event, Owner::Frame(9))
        .unwrap();
    assert!(c == a || ns.len() == before + 2);
    assert_eq!(ns.path(c).unwrap(), vec![seg("MTH0"), seg("LOC2")]);
    assert_eq!(
        ns.create(mth, &n("LOC1"), Object::Event, Owner::Frame(9)),
        Err(FaultKind::Exists)
    );
}

#[test]
fn bad_tables_are_refused()
{
    let mut ns = Namespace::new().unwrap();
    assert_eq!(
        ns.load_table(&[0; 10]).unwrap_err().kind,
        FaultKind::BadTable
    );
    let mut t = table(&[0xA3]);
    t[4..8].copy_from_slice(&20u32.to_le_bytes());
    assert_eq!(ns.load_table(&t).unwrap_err().kind, FaultKind::BadTable);
    t[4..8].copy_from_slice(&100u32.to_le_bytes());
    assert_eq!(ns.load_table(&t).unwrap_err().kind, FaultKind::BadTable);
}
