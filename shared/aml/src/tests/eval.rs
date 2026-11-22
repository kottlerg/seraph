// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/aml/src/tests/eval.rs

//! Hand-assembled evaluator tests: each operator and implicit conversion,
//! the store rules, fields and buffer fields, synchronization, every bound
//! with the fault past it, the stack an evaluation needs, and the no-panic
//! property over arbitrary method bodies.

use std::cell::Cell;

use super::sim::{Sim, Space};
use super::*;
use crate::eval::Evaluator;
use crate::host::{Host, HostError, Width};
use crate::value::Data;
use crate::{
    EVAL_STACK_BYTES, Fault, MAX_BUFFER_BYTES, MAX_CALL_DEPTH, MAX_EVAL_ALLOC, MAX_EVAL_DEPTH,
    MAX_EVAL_OBJECTS, MAX_EVAL_STEPS, MAX_VALUE_DEPTH, PARSE_STACK_BYTES,
};

// ── Assembler ─────────────────────────────────────────────────────────

/// An integer constant in its shortest encoding.
fn i(v: u64) -> Vec<u8>
{
    match v
    {
        0 => vec![0x00],
        1 => vec![0x01],
        2..=0xFF => vec![0x0A, u8::try_from(v).unwrap()],
        0x100..=0xFFFF => cat(&[&[0x0B], &u16::try_from(v).unwrap().to_le_bytes()]),
        0x1_0000..=0xFFFF_FFFF => cat(&[&[0x0C], &u32::try_from(v).unwrap().to_le_bytes()]),
        _ => cat(&[&[0x0E], &v.to_le_bytes()]),
    }
}

/// A buffer of `bytes`.
fn b(bytes: &[u8]) -> Vec<u8>
{
    buffer(&i(bytes.len() as u64), bytes)
}

fn l(n: u8) -> Vec<u8>
{
    vec![0x60 + n]
}

fn a(n: u8) -> Vec<u8>
{
    vec![0x68 + n]
}

fn n(text: &str) -> Vec<u8>
{
    name(text)
}

/// An operator `code` with `operands`.
fn op(code: &[u8], operands: &[&[u8]]) -> Vec<u8>
{
    let mut out = code.to_vec();
    for o in operands
    {
        out.extend_from_slice(o);
    }
    out
}

/// A two-operand operator whose result goes to no target.
fn bin(code: u8, x: &[u8], y: &[u8]) -> Vec<u8>
{
    op(&[code], &[x, y, &[0]])
}

/// A one-operand operator whose result goes to no target.
fn un(code: &[u8], x: &[u8]) -> Vec<u8>
{
    op(code, &[x, &[0]])
}

fn while_(pred: &[u8], body: &[u8]) -> Vec<u8>
{
    pkg_obj(&[0xA2], &cat(&[pred, body]))
}

fn index(src: &[u8], at: &[u8]) -> Vec<u8>
{
    op(&[0x88], &[src, at, &[0]])
}

fn deref(x: &[u8]) -> Vec<u8>
{
    op(&[0x83], &[x])
}

fn ext(code: u8) -> [u8; 2]
{
    [0x5B, code]
}

fn region(name_: &str, space: u8, offset: &[u8], len: &[u8]) -> Vec<u8>
{
    op(&ext(0x80), &[&n(name_), &[space], offset, len])
}

/// A field list element: a named unit of `bits` (or reserved bits, for
/// the empty name).
fn unit(name_: &str, bits: u32) -> Vec<u8>
{
    let mut out = if name_.is_empty()
    {
        vec![0]
    }
    else
    {
        seg(name_).to_vec()
    };
    if bits < 0x40
    {
        out.push(u8::try_from(bits).unwrap());
    }
    else if bits < 0x1000
    {
        out.extend([
            0x40 | u8::try_from(bits & 0xF).unwrap(),
            u8::try_from(bits >> 4).unwrap(),
        ]);
    }
    else
    {
        out.extend([
            0x80 | u8::try_from(bits & 0xF).unwrap(),
            u8::try_from((bits >> 4) & 0xFF).unwrap(),
            u8::try_from(bits >> 12).unwrap(),
        ]);
    }
    out
}

fn field(region_: &str, flags: u8, units: &[Vec<u8>]) -> Vec<u8>
{
    pkg_obj(&ext(0x81), &cat(&[&n(region_), &[flags], &units.concat()]))
}

fn mutex(name_: &str, sync: u8) -> Vec<u8>
{
    op(&ext(0x01), &[&n(name_), &[sync]])
}

fn acquire(name_: &str, timeout: u16) -> Vec<u8>
{
    op(&ext(0x23), &[&n(name_), &timeout.to_le_bytes()])
}

fn release(name_: &str) -> Vec<u8>
{
    op(&ext(0x27), &[&n(name_)])
}

// ── Running ───────────────────────────────────────────────────────────

/// The table of `defs` and a method `TEST` of `args` arguments whose body
/// is `body`, of table revision `rev`.
fn table_of(rev: u8, defs: &[u8], args: u8, body: &[u8]) -> Namespace
{
    let mut ns = Namespace::new().unwrap();
    let aml = cat(&[defs, &method("TEST", args, body)]);
    let r = ns.load_table(&table_rev(&aml, rev)).unwrap();
    assert_eq!(r.faults, 0, "{r:?}");
    ns
}

fn run_on(ns: &mut Namespace, sim: &mut Sim, path: &str, args: Vec<Data>) -> Result<Data, Fault>
{
    Evaluator::new(ns, sim).evaluate_path(path, args)
}

/// Evaluate `TEST` of `body` after `defs`.
fn test(defs: &[u8], body: &[u8]) -> Result<Data, Fault>
{
    let mut ns = table_of(2, defs, 0, body);
    run_on(&mut ns, &mut Sim::new(), "\\TEST", vec![])
}

/// The value `TEST` returns.
fn ok(defs: &[u8], body: &[u8]) -> Data
{
    test(defs, body).unwrap_or_else(|f| panic!("{f:?}"))
}

/// The integer `TEST` returns.
fn int_of(body: &[u8]) -> u64
{
    let d = ok(&[], body);
    let Data::Integer(v) = d
    else
    {
        panic!("{d:?}");
    };
    v
}

/// The fault that ends `TEST`.
fn fault(defs: &[u8], body: &[u8]) -> FaultKind
{
    test(defs, body).unwrap_err().kind
}

fn s_(text: &str) -> Data
{
    Data::String(text.as_bytes().to_vec())
}

const ONES: u64 = u64::MAX;

// ── Operators ─────────────────────────────────────────────────────────

#[test]
fn integer_arithmetic()
{
    assert_eq!(int_of(&ret(&bin(0x72, &i(5), &i(7)))), 12);
    assert_eq!(int_of(&ret(&bin(0x74, &i(5), &i(7)))), ONES - 1);
    assert_eq!(int_of(&ret(&bin(0x77, &i(6), &i(7)))), 42);
    assert_eq!(int_of(&ret(&bin(0x85, &i(17), &i(5)))), 2);
    // Divide: the remainder to its first target, the quotient to the second.
    let divide = op(&[0x78], &[&i(17), &i(5), &l(1), &l(2)]);
    let both = ret(&bin(0x72, &bin(0x77, &l(2), &i(100)), &l(1)));
    assert_eq!(int_of(&cat(&[&divide, &both])), 302);
    assert_eq!(
        fault(&[], &ret(&bin(0x85, &i(1), &i(0)))),
        FaultKind::DivideByZero
    );
    assert_eq!(
        fault(&[], &op(&[0x78], &[&i(1), &i(0), &[0], &[0]])),
        FaultKind::DivideByZero
    );
    assert_eq!(int_of(&ret(&bin(0x79, &i(1), &i(4)))), 16);
    assert_eq!(int_of(&ret(&bin(0x79, &i(1), &i(64)))), 0);
    assert_eq!(int_of(&ret(&bin(0x7A, &i(0x100), &i(4)))), 0x10);
    assert_eq!(int_of(&ret(&bin(0x7B, &i(0xC), &i(0xA)))), 8);
    assert_eq!(int_of(&ret(&bin(0x7D, &i(0xC), &i(0xA)))), 0xE);
    assert_eq!(int_of(&ret(&bin(0x7F, &i(0xC), &i(0xA)))), 6);
    assert_eq!(int_of(&ret(&bin(0x7C, &i(0xC), &i(0xA)))), !8);
    assert_eq!(int_of(&ret(&bin(0x7E, &i(0xC), &i(0xA)))), !0xE);
    assert_eq!(int_of(&ret(&un(&[0x80], &i(0)))), ONES);
    assert_eq!(int_of(&ret(&un(&[0x81], &i(0x10)))), 5);
    assert_eq!(int_of(&ret(&un(&[0x82], &i(0x10)))), 5);
    assert_eq!(int_of(&ret(&un(&[0x81], &i(0)))), 0);
    assert_eq!(int_of(&ret(&un(&ext(0x28), &i(0x1234)))), 1234);
    assert_eq!(int_of(&ret(&un(&ext(0x29), &i(1234)))), 0x1234);
    // Increment and Decrement wrap.
    let inc = cat(&[&store(&[0xFF], &l(0)), &[0x75], &l(0), &ret(&l(0))]);
    assert_eq!(int_of(&inc), 0);
    let dec = cat(&[&store(&i(0), &l(0)), &[0x76], &l(0), &ret(&l(0))]);
    assert_eq!(int_of(&dec), ONES);
    // A result stored to its target and returned.
    let add = cat(&[&op(&[0x72], &[&i(2), &i(3), &l(4)]), &ret(&l(4))]);
    assert_eq!(int_of(&add), 5);
}

#[test]
fn integers_are_32_bits_in_a_revision_1_table()
{
    let mut ns = table_of(1, &[], 0, &ret(&bin(0x72, &i(0xFFFF_FFFF), &i(1))));
    assert_eq!(
        run_on(&mut ns, &mut Sim::new(), "\\TEST", vec![]),
        Ok(Data::Integer(0))
    );
    let mut ns = table_of(1, &[], 0, &ret(&[0xFF]));
    assert_eq!(
        run_on(&mut ns, &mut Sim::new(), "\\TEST", vec![]),
        Ok(Data::Integer(0xFFFF_FFFF))
    );
    let mut ns = table_of(1, &[], 0, &ret(&bin(0x73, &i(1), &i(2))));
    assert_eq!(
        run_on(&mut ns, &mut Sim::new(), "\\TEST", vec![]),
        Ok(Data::Buffer(vec![1, 0, 0, 0, 2, 0, 0, 0]))
    );
}

#[test]
fn logical_operators_compare_each_type()
{
    assert_eq!(int_of(&ret(&op(&[0x90], &[&i(1), &i(2)]))), ONES);
    assert_eq!(int_of(&ret(&op(&[0x90], &[&i(1), &i(0)]))), 0);
    assert_eq!(int_of(&ret(&op(&[0x91], &[&i(0), &i(2)]))), ONES);
    assert_eq!(int_of(&ret(&op(&[0x92], &[&i(0)]))), ONES);
    assert_eq!(int_of(&ret(&op(&[0x93], &[&i(3), &i(3)]))), ONES);
    assert_eq!(
        int_of(&ret(&op(&[0x95], &[&string("abc"), &string("abd")]))),
        ONES
    );
    assert_eq!(
        int_of(&ret(&op(&[0x94], &[&string("abc"), &string("ab")]))),
        ONES
    );
    assert_eq!(
        int_of(&ret(&op(&[0x93], &[&b(&[1, 2]), &b(&[1, 2])]))),
        ONES
    );
    // The second operand converted to the first's type.
    assert_eq!(int_of(&ret(&op(&[0x93], &[&i(0x1F), &string("1F")]))), ONES);
    assert_eq!(int_of(&ret(&op(&[0x93], &[&string("1F"), &i(0x1F)]))), 0);
    // LNotEqual and LLessEqual are LNot of the comparison.
    assert_eq!(int_of(&ret(&op(&[0x92, 0x93], &[&i(1), &i(2)]))), ONES);
}

#[test]
fn explicit_conversions()
{
    let conv = |code: u8, x: &[u8]| ok(&[], &ret(&un(&[code], x)));
    assert_eq!(conv(0x99, &string("0x1F")), Data::Integer(0x1F));
    assert_eq!(conv(0x99, &string("31")), Data::Integer(31));
    assert_eq!(conv(0x99, &b(&[1, 2])), Data::Integer(0x0201));
    assert_eq!(
        conv(0x96, &i(0x0102)),
        Data::Buffer(vec![2, 1, 0, 0, 0, 0, 0, 0])
    );
    assert_eq!(conv(0x96, &string("ab")), Data::Buffer(b"ab\0".to_vec()));
    assert_eq!(conv(0x98, &i(0xAB)), s_("0xAB"));
    assert_eq!(conv(0x98, &b(&[1, 0xAB])), s_("0x01,0xAB"));
    assert_eq!(conv(0x97, &i(123)), s_("123"));
    assert_eq!(conv(0x97, &b(&[1, 200])), s_("1,200"));
    let to_string = |x: &[u8], len: &[u8]| ok(&[], &ret(&op(&[0x9C], &[x, len, &[0]])));
    assert_eq!(to_string(&b(b"ab\0c"), &[0xFF]), s_("ab"));
    assert_eq!(to_string(&b(b"abcd"), &i(3)), s_("abc"));
    let mid =
        |x: &[u8], at: u64, len: u64| ok(&[], &ret(&op(&[0x9E], &[x, &i(at), &i(len), &[0]])));
    assert_eq!(mid(&string("abcdef"), 2, 3), s_("cde"));
    assert_eq!(mid(&string("abcdef"), 4, 9), s_("ef"));
    assert_eq!(mid(&b(&[1, 2, 3]), 9, 1), Data::Buffer(vec![]));
    assert_eq!(
        fault(
            &[],
            &ret(&op(&[0x99], &[&string("99999999999999999999"), &[0]]))
        ),
        FaultKind::Range
    );
}

#[test]
fn concatenation_converts_the_second_operand_to_the_first_type()
{
    let concat = |x: &[u8], y: &[u8]| ok(&[], &ret(&bin(0x73, x, y)));
    assert_eq!(concat(&string("ab"), &i(0x10)), s_("ab0000000000000010"));
    assert_eq!(concat(&string("ab"), &string("cd")), s_("abcd"));
    assert_eq!(
        concat(&b(&[1]), &i(2)),
        Data::Buffer(vec![1, 2, 0, 0, 0, 0, 0, 0, 0])
    );
    assert_eq!(
        concat(&i(1), &i(2)),
        Data::Buffer([1u64.to_le_bytes(), 2u64.to_le_bytes()].concat())
    );
    // ConcatenateResTemplate: the descriptors of both, one end tag.
    let irq = [0x22, 0x01, 0x00];
    let io = [0x47, 0x01, 0x60, 0x00, 0x60, 0x00, 0x01, 0x01];
    let x = b(&cat(&[&irq, &[0x79, 0]]));
    let y = b(&cat(&[&io, &[0x79, 0]]));
    assert_eq!(
        ok(&[], &ret(&bin(0x84, &x, &y))),
        Data::Buffer(cat(&[&irq, &io, &[0x79, 0]]))
    );
    assert_eq!(
        fault(&[], &ret(&bin(0x84, &b(&[1, 2]), &y))),
        FaultKind::Type
    );
}

#[test]
fn size_and_type_of_each_object()
{
    let defs = cat(&[
        &name_obj("INT0", &i(5)),
        &name_obj("STR0", &string("abc")),
        &name_obj("BUF0", &b(&[1, 2, 3, 4])),
        &name_obj("PKG0", &package(2, &[i(1), i(2)])),
        &device("DEV0", &[]),
        &mutex("MTX0", 0),
        &method("MTH0", 0, &[]),
        &op(&ext(0x02), &[&n("EVT0")]),
        &region("REG0", 1, &i(0x100), &i(4)),
        &pkg_obj(&ext(0x84), &cat(&[&n("PWR0"), &[0], &[0, 0]])),
        &pkg_obj(&ext(0x83), &cat(&[&n("CPU0"), &[0], &[0; 4], &[0]])),
        &pkg_obj(&ext(0x85), &n("TZ00")),
    ]);
    let size = |obj: &str| ok(&defs, &ret(&op(&[0x87], &[&n(obj)])));
    assert_eq!(size("STR0"), Data::Integer(3));
    assert_eq!(size("BUF0"), Data::Integer(4));
    assert_eq!(size("PKG0"), Data::Integer(2));
    assert_eq!(
        test(&defs, &ret(&op(&[0x87], &[&n("INT0")])))
            .unwrap_err()
            .kind,
        FaultKind::Type
    );
    let kind = |obj: &str| ok(&defs, &ret(&op(&[0x8E], &[&n(obj)])));
    for (obj, t) in [
        ("INT0", 1),
        ("STR0", 2),
        ("BUF0", 3),
        ("PKG0", 4),
        ("DEV0", 6),
        ("EVT0", 7),
        ("MTH0", 8),
        ("MTX0", 9),
        ("REG0", 10),
        ("PWR0", 11),
        ("CPU0", 12),
        ("TZ00", 13),
    ]
    {
        assert_eq!(kind(obj), Data::Integer(t), "{obj}");
    }
    // A buffer field, made by CreateQWordField, and the debug object.
    let body = cat(&[
        &op(&[0x8F], &[&b(&[0; 8]), &i(0), &n("QW00")]),
        &ret(&op(&[0x8E], &[&n("QW00")])),
    ]);
    assert_eq!(ok(&defs, &body), Data::Integer(14));
    assert_eq!(
        ok(&defs, &ret(&op(&[0x8E], &[&ext(0x31)]))),
        Data::Integer(16)
    );
    assert_eq!(ok(&defs, &ret(&op(&[0x8E], &[&l(0)]))), Data::Integer(0));
}

#[test]
fn constants_timer_revision_and_osi()
{
    assert_eq!(int_of(&ret(&ext(0x30))), crate::REVISION);
    assert_ne!(int_of(&ret(&ext(0x33))), 0);
    assert_eq!(
        int_of(&ret(&op(&n("\\_OSI"), &[&string("Windows 2015")]))),
        ONES
    );
    assert_eq!(int_of(&ret(&op(&n("\\_OSI"), &[&string("Linux")]))), 0);
    assert_eq!(ok(&[], &ret(&n("\\_REV"))), Data::Integer(2));
}

// ── References and the store rules ────────────────────────────────────

#[test]
fn references_read_and_write_in_place()
{
    let defs = cat(&[
        &name_obj("INT0", &i(5)),
        &name_obj("BUF0", &b(&[1, 2, 3, 4])),
        &name_obj("STR0", &string("abc")),
        &name_obj("PKG0", &package(3, &[i(1), i(2), package(1, &[i(3)])])),
        &method("SET_", 1, &store(&i(7), &a(0))),
    ]);
    let mut ns = table_of(
        2,
        &defs,
        0,
        &cat(&[
            // RefOf and DerefOf.
            &store(&op(&[0x71], &[&n("INT0")]), &l(0)),
            &store(&deref(&l(0)), &l(1)),
            // A store through an index of a package, a buffer and a string.
            &store(&i(9), &index(&n("PKG0"), &i(1))),
            &store(&i(0x41), &index(&n("BUF0"), &i(0))),
            &store(&i(0x5A), &index(&n("STR0"), &i(2))),
            // A nested element.
            &store(&i(8), &index(&deref(&index(&n("PKG0"), &i(2))), &i(0))),
            // A method storing to an argument that holds a reference.
            &op(&n("SET_"), &[&op(&[0x71], &[&n("INT0")])]),
            &ret(&l(1)),
        ]),
    );
    let mut sim = Sim::new();
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![]),
        Ok(Data::Integer(5))
    );
    assert_eq!(data(&ns, "\\INT0"), Data::Integer(7));
    assert_eq!(data(&ns, "\\BUF0"), Data::Buffer(vec![0x41, 2, 3, 4]));
    assert_eq!(data(&ns, "\\STR0"), s_("abZ"));
    assert_eq!(
        data(&ns, "\\PKG0"),
        Data::Package(vec![
            Data::Integer(1),
            Data::Integer(9),
            Data::Package(vec![Data::Integer(8)])
        ])
    );
    // An index past the end.
    assert_eq!(
        fault(&defs, &ret(&deref(&index(&n("PKG0"), &i(3))))),
        FaultKind::Range
    );
    assert_eq!(
        fault(&defs, &store(&i(1), &index(&n("BUF0"), &i(4)))),
        FaultKind::Range
    );
    // An element read through the index, without DerefOf, as an operand.
    assert_eq!(
        ok(&defs, &ret(&bin(0x72, &index(&n("BUF0"), &i(1)), &i(0)))),
        Data::Integer(2)
    );
    // CondRefOf: whether the name resolves, storing its reference.
    let cond = |obj: &str| ok(&defs, &ret(&op(&ext(0x12), &[&n(obj), &l(0)])));
    assert_eq!(cond("INT0"), Data::Integer(ONES));
    assert_eq!(cond("NONE"), Data::Integer(0));
    // A reference returned to the caller of a local's reference is the
    // value it referred to.
    let r = ok(
        &[],
        &cat(&[&store(&i(4), &l(0)), &ret(&op(&[0x71], &[&l(0)]))]),
    );
    assert_eq!(r, Data::Integer(4));
}

#[test]
fn deref_of_an_element_that_names_an_object_is_that_object()
{
    let defs = cat(&[
        &device("DEV0", &[]),
        &mutex("MTX1", 1),
        &name_obj("INT0", &i(5)),
        &name_obj("PKG1", &package(2, &[i(1), i(2)])),
        &name_obj(
            "REFS",
            &package(4, &[n("DEV0"), n("MTX1"), n("INT0"), n("PKG1")]),
        ),
    ]);
    let el = |k: u64| deref(&index(&n("REFS"), &i(k)));
    let body = cat(&[
        &op(&[0x86], &[&el(0), &i(0x80)]),
        &op(&ext(0x23), &[&el(1), &0xFFFFu16.to_le_bytes()]),
        &op(&ext(0x27), &[&el(1)]),
        &store(&i(7), &el(2)),
        &store(&i(9), &index(&el(3), &i(1))),
        &ret(&deref(&index(&el(3), &i(0)))),
    ]);
    let mut ns = table_of(2, &defs, 0, &body);
    let mut sim = Sim::new();
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![]),
        Ok(Data::Integer(1))
    );
    assert_eq!(sim.notes, vec![("\\DEV0".to_string(), 0x80)]);
    assert_eq!(data(&ns, "\\INT0"), Data::Integer(7));
    assert_eq!(
        data(&ns, "\\PKG1"),
        Data::Package(vec![Data::Integer(1), Data::Integer(9)])
    );
    // A package a method builds holds references; a local holds it.
    let body = cat(&[
        &store(&package(1, &[n("INT0")]), &l(0)),
        &store(&i(3), &deref(&index(&l(0), &i(0)))),
        &ret(&n("INT0")),
    ]);
    assert_eq!(ok(&defs, &body), Data::Integer(3));
    // An element that is not a reference is written in place.
    let body = cat(&[
        &store(&package(1, &[i(4)]), &l(0)),
        &store(&i(6), &deref(&index(&l(0), &i(0)))),
        &ret(&deref(&index(&l(0), &i(0)))),
    ]);
    assert_eq!(ok(&defs, &body), Data::Integer(6));
}

#[test]
fn store_converts_to_a_named_objects_type_and_copy_object_replaces()
{
    let defs = cat(&[
        &name_obj("INT0", &i(5)),
        &name_obj("BUF0", &buffer(&i(4), &[])),
        &name_obj("STR0", &string("x")),
        &name_obj("PKG0", &package(1, &[i(1)])),
    ]);
    let mut ns = table_of(
        2,
        &defs,
        0,
        &cat(&[
            &store(&string("1F"), &n("INT0")),
            &store(&i(0x01_0203_0405), &n("BUF0")),
            &store(&i(0x1F), &n("STR0")),
            &store(&i(3), &n("PKG0")),
        ]),
    );
    run_on(&mut ns, &mut Sim::new(), "\\TEST", vec![]).unwrap();
    assert_eq!(data(&ns, "\\INT0"), Data::Integer(0x1F));
    // A buffer keeps its length.
    assert_eq!(data(&ns, "\\BUF0"), Data::Buffer(vec![5, 4, 3, 2]));
    assert_eq!(data(&ns, "\\STR0"), s_("000000000000001F"));
    // A store to a package replaces it.
    assert_eq!(data(&ns, "\\PKG0"), Data::Integer(3));
    let mut ns = table_of(2, &defs, 0, &op(&[0x9D], &[&b(&[9]), &n("INT0")]));
    run_on(&mut ns, &mut Sim::new(), "\\TEST", vec![]).unwrap();
    assert_eq!(data(&ns, "\\INT0"), Data::Buffer(vec![9]));
    // A local takes any value as it is.
    assert_eq!(
        ok(&[], &cat(&[&store(&string("q"), &l(0)), &ret(&l(0))])),
        s_("q")
    );
    // An uninitialized local read is a fault.
    assert_eq!(
        fault(&[], &ret(&bin(0x72, &l(3), &i(1)))),
        FaultKind::Uninitialized
    );
}

#[test]
fn match_finds_the_first_element_meeting_both_conditions()
{
    let defs = name_obj("PKG0", &package(4, &[i(1), i(5), i(9), string("x")]));
    // MEQ 5, MTR.
    let m = |op1: u8, x: u64, op2: u8, y: u64, start: u64| {
        ok(
            &defs,
            &ret(&op(
                &[0x89],
                &[&n("PKG0"), &[op1], &i(x), &[op2], &i(y), &i(start)],
            )),
        )
    };
    assert_eq!(m(1, 5, 0, 0, 0), Data::Integer(1));
    // MGT 4 and MLT 9.
    assert_eq!(m(5, 4, 3, 9, 0), Data::Integer(1));
    assert_eq!(m(1, 5, 0, 0, 2), Data::Integer(ONES));
    assert_eq!(m(1, 7, 0, 0, 0), Data::Integer(ONES));
}

// ── Control flow and calls ────────────────────────────────────────────

#[test]
fn loops_branches_and_calls()
{
    // While with Continue and Break: the sum of the odd numbers below 10.
    let body = cat(&[
        &store(&i(0), &l(0)),
        &store(&i(0), &l(1)),
        &while_(
            &[0x01],
            &cat(&[
                &[0x75],
                &l(0),
                &if_(&op(&[0x92, 0x95], &[&l(0), &i(10)]), &[0xA5]),
                &if_(&op(&[0x93], &[&bin(0x7B, &l(0), &i(1)), &i(0)]), &[0x9F]),
                &op(&[0x72], &[&l(1), &l(0), &l(1)]),
            ]),
        ),
        &ret(&l(1)),
    ]);
    assert_eq!(int_of(&body), 1 + 3 + 5 + 7 + 9);
    // If, Else.
    let pick = |x: u64| {
        int_of(&cat(&[
            &if_(&op(&[0x93], &[&i(x), &i(1)]), &ret(&i(10))),
            &else_(&ret(&i(20))),
        ]))
    };
    assert_eq!((pick(1), pick(2)), (10, 20));
    // A recursive call with an argument: 5!.
    let fact = method(
        "FACT",
        1,
        &cat(&[
            &if_(&op(&[0x95], &[&a(0), &i(2)]), &ret(&i(1))),
            &ret(&bin(
                0x77,
                &a(0),
                &op(&n("FACT"), &[&bin(0x74, &a(0), &i(1))]),
            )),
        ]),
    );
    assert_eq!(
        ok(&fact, &ret(&op(&n("FACT"), &[&i(5)]))),
        Data::Integer(120)
    );
    // A method with no Return returns no value.
    assert_eq!(ok(&[], &[0xA3]), Data::Uninitialized);
    // Arguments and locals are each frame's own.
    let set = method("SETL", 0, &store(&i(1), &l(0)));
    assert_eq!(
        ok(&set, &cat(&[&store(&i(7), &l(0)), &n("SETL"), &ret(&l(0))])),
        Data::Integer(7)
    );
    // Too many arguments.
    let mut ns = table_of(2, &[], 1, &ret(&a(0)));
    let args = vec![Data::Integer(1); 8];
    assert_eq!(
        run_on(&mut ns, &mut Sim::new(), "\\TEST", args)
            .unwrap_err()
            .kind,
        FaultKind::Args
    );
}

#[test]
fn objects_a_method_creates_are_removed_when_it_returns()
{
    let mut ns = table_of(
        2,
        &[],
        0,
        &cat(&[
            &name_obj("LOC0", &i(3)),
            &device("DEV0", &name_obj("_ADR", &i(0))),
            &method("INNR", 0, &ret(&i(4))),
            &ret(&bin(0x72, &n("LOC0"), &n("INNR"))),
        ]),
    );
    let before = ns.len();
    let mut sim = Sim::new();
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![]),
        Ok(Data::Integer(7))
    );
    assert_eq!(ns.len(), before);
    assert!(ns.find("\\TEST.LOC0").is_none());
    // And again: the names are free to create.
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![]),
        Ok(Data::Integer(7))
    );
    // A fault removes them too.
    let mut ns = table_of(
        2,
        &[],
        0,
        &cat(&[&name_obj("LOC0", &i(3)), &ext(0x32), &[1], &[0; 4], &i(0)]),
    );
    let before = ns.len();
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![])
            .unwrap_err()
            .kind,
        FaultKind::Fatal
    );
    assert_eq!(ns.len(), before);
}

#[test]
fn a_method_defining_an_external_name_gives_the_table_node_back()
{
    // A table declares \_SB.XDEV External and loads TBL0 under it; MAKE
    // defines the device, with an object of its own, and reads TBL0.
    let defs = cat(&[
        &[0x15],
        &n("\\_SB.XDEV"),
        &[6, 0],
        &scope("\\_SB.XDEV", &name_obj("TBL0", &i(5))),
        &method(
            "MAKE",
            0,
            &cat(&[
                &device("\\_SB.XDEV", &name_obj("LOC0", &i(1))),
                &ret(&n("\\_SB.XDEV.TBL0")),
            ]),
        ),
    ]);
    // TEST calls MAKE more times than an evaluation may create objects.
    const { assert!(MAX_EVAL_OBJECTS < 5000) };
    let body = cat(&[
        &store(&i(0), &l(0)),
        &while_(
            &op(&[0x95], &[&l(0), &i(5000)]),
            &cat(&[&op(&n("MAKE"), &[]), &op(&[0x75], &[&l(0)])]),
        ),
        &ret(&l(0)),
    ]);
    let mut ns = table_of(2, &defs, 0, &body);
    let before = ns.len();
    let xdev = ns.find("\\_SB.XDEV").unwrap();
    let generation = ns.generation(xdev).unwrap();
    let mut sim = Sim::new();
    for _ in 0..2
    {
        assert_eq!(
            run_on(&mut ns, &mut sim, "\\MAKE", vec![]),
            Ok(Data::Integer(5))
        );
        assert_eq!(ns.len(), before);
        assert_eq!(ns.find("\\_SB.XDEV"), Some(xdev));
        assert!(matches!(
            ns.object(xdev),
            Some(Object::External { kind: 6, .. })
        ));
        assert!(matches!(ns.owner(xdev), Some(Owner::Table(_))));
        assert_eq!(data(&ns, "\\_SB.XDEV.TBL0"), Data::Integer(5));
        assert!(ns.find("\\_SB.XDEV.LOC0").is_none());
    }
    // Each return gave the External back with a new generation, so a
    // reference to the method's device fails.
    assert_ne!(ns.generation(xdev), Some(generation));
    // Each return also gave back the object count the definition took.
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![]),
        Ok(Data::Integer(5000))
    );
    assert_eq!(ns.len(), before);
    assert_eq!(data(&ns, "\\_SB.XDEV.TBL0"), Data::Integer(5));
}

#[test]
fn module_level_code_runs_once_and_keeps_its_objects()
{
    let aml = cat(&[
        &name_obj("FLAG", &i(0)),
        &if_(
            &[0x01],
            &cat(&[&store(&i(1), &n("FLAG")), &name_obj("MADE", &i(2))]),
        ),
        &store(&i(1), &n("NONE")),
    ]);
    let mut ns = Namespace::new().unwrap();
    let r = ns.load_table(&table(&aml)).unwrap();
    assert_eq!(r.module_terms, 2, "{r:?}");
    let mut sim = Sim::new();
    let report = Evaluator::new(&mut ns, &mut sim).run_module_code();
    assert_eq!((report.terms, report.faults), (2, 1));
    assert_eq!(report.first_fault.unwrap().kind, FaultKind::NotFound);
    assert_eq!(data(&ns, "\\FLAG"), Data::Integer(1));
    assert_eq!(data(&ns, "\\MADE"), Data::Integer(2));
}

#[test]
fn unsupported_operators_fail_closed()
{
    let load = op(&ext(0x20), &[&n("BUF0"), &l(0)]);
    assert_eq!(
        fault(&name_obj("BUF0", &b(&[0])), &load),
        FaultKind::Unsupported
    );
    let region_ = region("REG0", 0x0A, &i(0), &i(4));
    let body = cat(&[
        &region_,
        &field("REG0", 1, &[unit("FLD0", 8)]),
        &ret(&n("FLD0")),
    ]);
    assert_eq!(fault(&[], &body), FaultKind::Unsupported);
    // A Connection in a field list a method defines.
    let region_ = region("REG0", 1, &i(0x100), &i(4));
    let connect = cat(&[&[0x02], &n("REG0")]);
    let body = cat(&[
        &region_,
        &field("REG0", 1, &[connect, unit("FLD0", 8)]),
        &ret(&n("FLD0")),
    ]);
    assert_eq!(fault(&[], &body), FaultKind::Unsupported);
    assert_eq!(
        fault(&[], &cat(&[&ext(0x32), &[1], &[0; 4], &i(0)])),
        FaultKind::Fatal
    );
    // LoadTable, Unload and DataTableRegion: no table is loaded or mapped
    // after the namespace's load.
    let strings: Vec<Vec<u8>> = (0..5).map(|_| string("")).collect();
    let load_table = op(
        &ext(0x1F),
        &[
            &strings[0],
            &strings[1],
            &strings[2],
            &strings[3],
            &strings[4],
            &i(0),
        ],
    );
    assert_eq!(fault(&[], &load_table), FaultKind::Unsupported);
    assert_eq!(
        fault(&[], &op(&ext(0x2A), &[&l(0)])),
        FaultKind::Unsupported
    );
    let data_region = op(
        &ext(0x88),
        &[&n("DRG0"), &string("DSDT"), &string(""), &string("")],
    );
    assert_eq!(fault(&[], &data_region), FaultKind::Unsupported);
}

// ── Fields ────────────────────────────────────────────────────────────

/// A `SystemIO` region at 0x100, 8 bytes, with a field of `flags` holding
/// `units`, and a method `TEST` of `body`.
fn io_field(flags: u8, units: &[Vec<u8>], body: &[u8]) -> (Namespace, Sim)
{
    let defs = cat(&[
        &region("REG0", 1, &i(0x100), &i(8)),
        &field("REG0", flags, units),
    ]);
    (table_of(2, &defs, 0, body), Sim::new())
}

#[test]
fn field_units_read_and_write_their_bits_under_each_update_rule()
{
    let units = [unit("", 4), unit("FLD0", 8), unit("FLD1", 4)];
    // ByteAcc, Preserve: the bytes the unit covers in part are read first.
    let (mut ns, mut sim) = io_field(0x01, &units, &store(&i(0xAB), &n("FLD0")));
    for (port, v) in [(0x100, 0x5Au8), (0x101, 0xC3)]
    {
        Host::io_write(
            &mut sim,
            crate::host::Span {
                base: 0x100,
                len: 8,
            },
            port,
            Width::Byte,
            u64::from(v),
        )
        .unwrap();
    }
    sim.log.clear();
    run_on(&mut ns, &mut sim, "\\TEST", vec![]).unwrap();
    assert_eq!((sim.io_byte(0x100), sim.io_byte(0x101)), (0xBA, 0xCA));
    assert_eq!(sim.io_writes(), vec![(0x100, 0xBA), (0x101, 0xCA)]);
    // Reading it back.
    let (mut ns, _) = io_field(0x01, &units, &ret(&n("FLD0")));
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![]),
        Ok(Data::Integer(0xAB))
    );
    // WriteAsOnes and WriteAsZeros: no read, the other bits set or clear.
    let (mut ns, mut ones) = io_field(0x21, &units, &store(&i(0), &n("FLD1")));
    run_on(&mut ns, &mut ones, "\\TEST", vec![]).unwrap();
    assert_eq!(ones.log.iter().filter(|a| a.write.is_none()).count(), 0);
    assert_eq!(ones.io_writes(), vec![(0x101, 0x0F)]);
    let (mut ns, mut zeros) = io_field(0x41, &units, &store(&i(0xF), &n("FLD1")));
    run_on(&mut ns, &mut zeros, "\\TEST", vec![]).unwrap();
    assert_eq!(zeros.io_writes(), vec![(0x101, 0xF0)]);
    // A WordAcc unit that crosses a word: two aligned words.
    let crossing = [unit("", 12), unit("FLD2", 16)];
    let (mut ns, mut sim) = io_field(0x42, &crossing, &store(&i(0xFFFF), &n("FLD2")));
    run_on(&mut ns, &mut sim, "\\TEST", vec![]).unwrap();
    assert_eq!(sim.io_writes(), vec![(0x100, 0xF000), (0x102, 0x0FFF)]);
    assert!(sim.log.iter().all(|a| a.width == Width::Word));
}

#[test]
fn a_field_unit_wider_than_a_buffer_is_neither_read_nor_written()
{
    let units = [unit("FLDW", 0x1_0000 * 8 + 8)];
    for body in [store(&i(0), &n("FLDW")), ret(&n("FLDW"))]
    {
        let (mut ns, mut sim) = io_field(0x01, &units, &body);
        assert_eq!(
            run_on(&mut ns, &mut sim, "\\TEST", vec![])
                .unwrap_err()
                .kind,
            FaultKind::Bound
        );
        assert_eq!(sim.log.len(), 0);
    }
}

#[test]
fn a_field_wider_than_an_integer_reads_as_a_buffer()
{
    let defs = cat(&[
        &region("REG0", 0, &i(0x1000), &i(16)),
        &pkg_obj(
            &ext(0x81),
            &cat(&[&n("REG0"), &[0x03], &unit("WIDE", 0x48)]),
        ),
    ]);
    let mut ns = table_of(
        2,
        &defs,
        0,
        &cat(&[
            &store(&b(&[1, 2, 3, 4, 5, 6, 7, 8, 9]), &n("WIDE")),
            &ret(&n("WIDE")),
        ]),
    );
    let mut sim = Sim::new();
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![]),
        Ok(Data::Buffer(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]))
    );
    assert_eq!(sim.mem_byte(0x1008), 9);
    assert!(
        sim.log
            .iter()
            .all(|a| a.space == Space::Mem && a.width == Width::DWord)
    );
}

#[test]
fn index_and_bank_fields_select_their_register_first()
{
    let defs = cat(&[
        &region("REG0", 1, &i(0x100), &i(4)),
        &field(
            "REG0",
            0x01,
            &[unit("IDX0", 8), unit("DAT0", 8), unit("BNK0", 8)],
        ),
        &pkg_obj(
            &ext(0x86),
            &cat(&[
                &n("IDX0"),
                &n("DAT0"),
                &[0x01],
                &unit("", 16),
                &unit("IFL0", 8),
            ]),
        ),
        &pkg_obj(
            &ext(0x87),
            &cat(&[
                &n("REG0"),
                &n("BNK0"),
                &i(3),
                &[0x01],
                &unit("", 24),
                &unit("BFL0", 8),
            ]),
        ),
    ]);
    let mut ns = table_of(
        2,
        &defs,
        0,
        &cat(&[&store(&i(0x77), &n("IFL0")), &store(&i(0x66), &n("BFL0"))]),
    );
    let mut sim = Sim::new();
    run_on(&mut ns, &mut sim, "\\TEST", vec![]).unwrap();
    // The index field's unit at byte 2: index 2, then the data; the bank
    // field's: bank 3, then the register.
    assert_eq!(
        sim.io_writes(),
        vec![(0x100, 2), (0x101, 0x77), (0x102, 3), (0x103, 0x66)]
    );
}

#[test]
fn a_region_offset_from_an_expression_is_evaluated_at_first_access()
{
    let defs = cat(&[
        &name_obj("BASE", &i(0x200)),
        &region("REG0", 1, &bin(0x72, &n("BASE"), &i(0x10)), &i(2)),
        &field("REG0", 0x01, &[unit("FLD0", 8)]),
    ]);
    let mut ns = table_of(2, &defs, 0, &store(&i(5), &n("FLD0")));
    let mut sim = Sim::new();
    run_on(&mut ns, &mut sim, "\\TEST", vec![]).unwrap();
    assert_eq!(sim.io_writes(), vec![(0x210, 5)]);
    // An access the host refuses ends the evaluation.
    sim.refuse = Some(1);
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![])
            .unwrap_err()
            .kind,
        FaultKind::Host(HostError::Refused)
    );
}

#[test]
fn buffer_fields_read_and_write_their_bits()
{
    let defs = name_obj("BUF0", &buffer(&i(8), &[]));
    // CreateQWordField over the whole buffer.
    let body = cat(&[
        &op(&[0x8F], &[&n("BUF0"), &i(0), &n("QW00")]),
        &store(&i(0x0102_0304_0506_0708), &n("QW00")),
        &ret(&n("BUF0")),
    ]);
    assert_eq!(ok(&defs, &body), Data::Buffer(vec![8, 7, 6, 5, 4, 3, 2, 1]));
    let mut ns = table_of(
        2,
        &defs,
        0,
        &cat(&[
            &op(&[0x8A], &[&n("BUF0"), &i(0), &n("DW00")]),
            &op(&[0x8D], &[&n("BUF0"), &i(32), &n("BIT0")]),
            &op(&ext(0x13), &[&n("BUF0"), &i(36), &i(12), &n("FL12")]),
            &store(&i(0x1234_5678), &n("DW00")),
            &store(&i(1), &n("BIT0")),
            &store(&i(0xABC), &n("FL12")),
            &ret(&bin(0x72, &n("DW00"), &n("FL12"))),
        ]),
    );
    let mut sim = Sim::new();
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![]),
        Ok(Data::Integer(0x1234_5678 + 0xABC))
    );
    assert_eq!(
        data(&ns, "\\BUF0"),
        Data::Buffer(vec![0x78, 0x56, 0x34, 0x12, 0xC1, 0xAB, 0, 0])
    );
    // A field past the end of its buffer.
    assert_eq!(
        fault(&defs, &op(&[0x8A], &[&n("BUF0"), &i(5), &n("DW00")])),
        FaultKind::Range
    );
    // A field over an argument writes the caller's buffer (as _OSC does).
    let body = cat(&[
        &op(&[0x8B], &[&a(0), &i(1), &n("WD00")]),
        &store(&i(0xBEEF), &n("WD00")),
        &ret(&a(0)),
    ]);
    let mut ns = table_of(2, &[], 1, &body);
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![Data::Buffer(vec![0; 4])]),
        Ok(Data::Buffer(vec![0, 0xEF, 0xBE, 0]))
    );
    // A field over a temporary.
    let body = cat(&[
        &op(&[0x8C], &[&b(&[1, 2]), &i(1), &n("BY00")]),
        &ret(&n("BY00")),
    ]);
    assert_eq!(ok(&[], &body), Data::Integer(2));
}

// ── Synchronization ───────────────────────────────────────────────────

#[test]
fn mutexes_follow_the_ordering_rule()
{
    let defs = cat(&[&mutex("MTX1", 1), &mutex("MTX2", 2)]);
    // Ascending, released in reverse: fine, and nests.
    let good = cat(&[
        &acquire("MTX1", 0xFFFF),
        &acquire("MTX1", 0xFFFF),
        &acquire("MTX2", 0xFFFF),
        &release("MTX2"),
        &release("MTX1"),
        &release("MTX1"),
        &ret(&acquire("MTX2", 0)),
    ]);
    assert_eq!(ok(&defs, &good), Data::Integer(0));
    // Descending.
    assert_eq!(
        fault(
            &defs,
            &cat(&[&acquire("MTX2", 0xFFFF), &acquire("MTX1", 0xFFFF)])
        ),
        FaultKind::MutexOrder
    );
    // A release below the current level.
    let wrong = cat(&[
        &acquire("MTX1", 0xFFFF),
        &acquire("MTX2", 0xFFFF),
        &release("MTX1"),
    ]);
    assert_eq!(fault(&defs, &wrong), FaultKind::MutexOrder);
    // A release of a mutex not held.
    assert_eq!(fault(&defs, &release("MTX1")), FaultKind::MutexOrder);
    // A mutex left held is released when the evaluation ends.
    let hold = cat(&[&defs, &method("HOLD", 0, &acquire("MTX2", 0xFFFF))]);
    let mut ns = table_of(2, &hold, 0, &acquire("MTX1", 0xFFFF));
    let mut sim = Sim::new();
    run_on(&mut ns, &mut sim, "\\HOLD", vec![]).unwrap();
    run_on(&mut ns, &mut sim, "\\TEST", vec![]).unwrap();
    // A serialized method of sync level 3 holds level 3 while it runs.
    let serialized = pkg_obj(
        &[0x14],
        &cat(&[&n("SER3"), &[0x38], &acquire("MTX1", 0xFFFF)]),
    );
    let defs3 = cat(&[&defs, &serialized]);
    assert_eq!(fault(&defs3, &n("SER3")), FaultKind::MutexOrder);
    // The global lock mutex takes the firmware lock.
    let mut ns = table_of(
        2,
        &[],
        0,
        &cat(&[
            &acquire("\\_GL_", 0xFFFF),
            &acquire("\\_GL_", 0xFFFF),
            &release("\\_GL_"),
        ]),
    );
    let mut sim = Sim::new();
    run_on(&mut ns, &mut sim, "\\TEST", vec![]).unwrap();
    assert_eq!(
        (sim.gl_acquires, sim.gl_releases, sim.gl_held),
        (1, 1, false)
    );
    sim.gl_refuse = true;
    let mut ns = table_of(2, &[], 0, &ret(&acquire("\\_GL_", 5)));
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![]),
        Ok(Data::Integer(ONES))
    );
    // The wait with no limit asked for the whole delay budget.
    assert_eq!(sim.gl_waits, vec![10_000, 5]);
}

#[test]
fn a_mutex_a_returned_method_left_held_does_not_hold_its_successor()
{
    // LEAK defines a mutex of level 3 and acquires it; with Arg0 1 it
    // releases it, with Arg0 2 it then acquires MTX1, of level 1. Called a
    // second time, its mutex is a new object whose acquisition sets level
    // 3: the release is in order, and the acquisition of MTX1 is not.
    let when = |v: u64, then: &[u8]| pkg_obj(&[0xA0], &cat(&[&op(&[0x93], &[&a(0), &i(v)]), then]));
    let leak = method(
        "LEAK",
        1,
        &cat(&[
            &mutex("MTXL", 3),
            &acquire("MTXL", 0xFFFF),
            &when(1, &release("MTXL")),
            &when(2, &acquire("\\MTX1", 0xFFFF)),
        ]),
    );
    let defs = cat(&[&mutex("MTX1", 1), &leak]);
    let call = |arg: u64| op(&n("LEAK"), &[&i(arg)]);
    assert_eq!(
        ok(&defs, &cat(&[&call(0), &call(1), &ret(&i(1))])),
        Data::Integer(1)
    );
    assert_eq!(
        fault(&defs, &cat(&[&call(0), &call(2)])),
        FaultKind::MutexOrder
    );
    // Fifty calls, each leaving its mutex held: the entries of the removed
    // ones are dropped, so one is held at most.
    let lt50 = op(&[0x95], &[&l(0), &i(50)]);
    let body = cat(&[
        &store(&i(0), &l(0)),
        &while_(&lt50, &cat(&[&call(0), &[0x75], &l(0)])),
    ]);
    let mut ns = table_of(2, &defs, 0, &body);
    let mut sim = Sim::new();
    let mut ev = Evaluator::new(&mut ns, &mut sim);
    ev.evaluate_path("\\TEST", vec![]).unwrap();
    assert_eq!(ev.held_peak(), 1);
}

#[test]
fn events_count_their_signals()
{
    let defs = op(&ext(0x02), &[&n("EVT0")]);
    let signal = op(&ext(0x24), &[&n("EVT0")]);
    let reset = op(&ext(0x26), &[&n("EVT0")]);
    let wait = |t: u64| op(&ext(0x25), &[&n("EVT0"), &i(t)]);
    let body = cat(&[
        &signal,
        &signal,
        &store(&wait(0), &l(0)),
        &store(&wait(0), &l(1)),
        &store(&wait(5), &l(2)),
        &signal,
        &reset,
        &store(&wait(0), &l(3)),
        &ret(&bin(
            0x72,
            &bin(0x72, &l(0), &l(1)),
            &bin(0x7B, &l(2), &l(3)),
        )),
    ]);
    let mut ns = table_of(2, &defs, 0, &body);
    let mut sim = Sim::new();
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![]),
        Ok(Data::Integer(ONES))
    );
    assert_eq!(sim.slept_ms, 5);
    // No timeout, nothing to signal: a deadlock.
    assert_eq!(fault(&defs, &wait(0xFFFF)), FaultKind::Deadlock);
}

#[test]
fn delays_and_notifications_reach_the_host()
{
    let defs = cat(&[
        &device("DEV0", &[]),
        &pkg_obj(&ext(0x83), &cat(&[&n("CPU0"), &[0], &[0; 4], &[0]])),
        &pkg_obj(&ext(0x85), &n("TZ00")),
    ]);
    let body = cat(&[
        &op(&ext(0x22), &[&i(100)]),
        &op(&ext(0x21), &[&i(255)]),
        &[0xCC],
        &op(&[0x86], &[&n("DEV0"), &i(0x80)]),
        &op(&[0x86], &[&n("CPU0"), &i(0x81)]),
        &op(&[0x86], &[&n("TZ00"), &i(0x82)]),
        &store(&i(1), &ext(0x31)),
    ]);
    let mut ns = table_of(2, &defs, 0, &body);
    let mut sim = Sim::new();
    run_on(&mut ns, &mut sim, "\\TEST", vec![]).unwrap();
    assert_eq!((sim.slept_ms, sim.stalled_us), (100, 255));
    assert_eq!(
        sim.notes,
        vec![
            ("\\DEV0".to_string(), 0x80),
            ("\\CPU0".to_string(), 0x81),
            ("\\TZ00".to_string(), 0x82)
        ]
    );
    assert_eq!(fault(&[], &op(&ext(0x21), &[&i(256)])), FaultKind::Range);
    let defs = name_obj("INT0", &i(0));
    assert_eq!(
        fault(&defs, &op(&[0x86], &[&n("INT0"), &i(1)])),
        FaultKind::Type
    );
}

// ── Bounds ────────────────────────────────────────────────────────────

/// A method whose body counts its loop's passes in `CNT_` and runs `pass`
/// in each, forever; the fault that ends it and the passes it made.
fn count_passes(pass: &[u8]) -> (FaultKind, u64)
{
    count_passes_on(&[], pass, &mut Sim::new())
}

/// As [`count_passes`], after `defs`, on `sim`.
fn count_passes_on(defs: &[u8], pass: &[u8], sim: &mut Sim) -> (FaultKind, u64)
{
    let defs = cat(&[&name_obj("CNT_", &i(0)), defs]);
    let body = while_(&[0x01], &cat(&[&[0x75], &n("CNT_"), pass]));
    let mut ns = table_of(2, &defs, 0, &body);
    let kind = run_on(&mut ns, sim, "\\TEST", vec![]).unwrap_err().kind;
    let Data::Integer(passes) = data(&ns, "\\CNT_")
    else
    {
        panic!();
    };
    (kind, passes)
}

#[test]
fn every_loop_ends_at_the_step_bound()
{
    let (kind, passes) = count_passes(&[0xA3]);
    assert_eq!(kind, FaultKind::Bound);
    // Each pass: the predicate, the Increment and its operand, the Noop.
    assert!(
        passes > (MAX_EVAL_STEPS / 8) as u64 && passes < MAX_EVAL_STEPS as u64,
        "{passes}"
    );
}

#[test]
fn the_values_an_evaluation_makes_are_bounded()
{
    // Each value counted once, as it is made: a 4 KiB buffer made, read
    // from a name, returned by a method, held in a package, converted, or
    // copied from one package element to another through two references.
    let slot = size_of::<Data>();
    let buf = 0x1000 + slot;
    let defs = cat(&[
        &name_obj("BUF0", &buffer(&i(0x1000), &[])),
        &method("MKBF", 0, &ret(&buffer(&i(0x1000), &[]))),
        &name_obj("SRC_", &package(1, &[buffer(&i(0x1000), &[])])),
        &name_obj("DST_", &package(1, &[i(0)])),
    ]);
    // A reference to an element: its own slot and one index.
    let element_ref = slot + 4;
    let cases: [(Vec<u8>, usize); 6] = [
        (store(&buffer(&i(0x1000), &[]), &l(0)), buf),
        (store(&n("BUF0"), &l(0)), buf),
        (store(&n("MKBF"), &l(0)), buf),
        (
            store(&package(1, &[buffer(&i(0x1000), &[])]), &l(0)),
            buf + slot,
        ),
        (op(&[0x96], &[&n("BUF0"), &l(0)]), 2 * buf),
        (
            store(&index(&n("SRC_"), &i(0)), &index(&n("DST_"), &i(0))),
            buf + 2 * element_ref,
        ),
    ];
    for (pass, each) in cases
    {
        let (kind, passes) = count_passes_on(&defs, &pass, &mut Sim::new());
        assert_eq!(kind, FaultKind::Bound);
        let most = u64::try_from(MAX_EVAL_ALLOC / each).unwrap();
        assert!(passes.abs_diff(most) <= 2, "{passes} against {most}");
    }
    // One buffer or package past its own bound.
    assert_eq!(
        fault(&[], &store(&buffer(&i(0x1_0001), &[]), &l(0))),
        FaultKind::Bound
    );
    assert_eq!(
        fault(&[], &store(&pkg_obj(&[0x13], &i(5000)), &l(0))),
        FaultKind::Bound
    );
    // A string doubled by Concatenate: 16 bytes doubled 12 times reaches
    // MAX_BUFFER_BYTES, which it may, and a 13th passes it, long before
    // MAX_EVAL_ALLOC or MAX_EVAL_STEPS ends the evaluation.
    let doubled = |times: usize| {
        cat(&[
            &store(&string("0123456789abcdef"), &l(0)),
            &op(&[0x73], &[&l(0), &l(0), &l(0)]).repeat(times),
            &ret(&op(&[0x87], &[&l(0)])),
        ])
    };
    assert_eq!(16 << 12, MAX_BUFFER_BYTES);
    assert_eq!(int_of(&doubled(12)), 65_536);
    assert_eq!(fault(&[], &doubled(13)), FaultKind::Bound);
}

#[test]
fn a_scope_over_an_alias_in_a_method_calls_the_targets_methods()
{
    // Scope (ALS0) { Local0 = MTH1 (5) }, ALS0 an Alias of DEV0, which holds
    // MTH1: the call is parsed in DEV0, as it runs, so 5 is its argument.
    let defs = cat(&[
        &device("DEV0", &method("MTH1", 1, &ret(&bin(0x72, &a(0), &i(1))))),
        &cat(&[&[0x06], &name("DEV0"), &name("ALS0")]),
    ]);
    let body = cat(&[
        &scope("ALS0", &store(&cat(&[&n("MTH1"), &i(5)]), &l(0))),
        &ret(&l(0)),
    ]);
    assert_eq!(ok(&defs, &body), Data::Integer(6));
}

#[test]
fn a_definition_by_a_path_resolves_its_names_from_where_it_is_written()
{
    // In DEV0: OperationRegion (\XREG, SystemMemory, OFS0, 4) and
    // Name (\PRT0, Package () { LNKA }), with OFS0 and LNKA DEV0's own: each
    // name resolves from DEV0, where the definition is written, not from the
    // root the path places it under.
    let defs = device(
        "DEV0",
        &cat(&[
            &name_obj("OFS0", &i(0x2000)),
            &device("LNKA", &[]),
            &region("\\XREG", 0, &n("OFS0"), &i(4)),
            &field("\\XREG", 0x01, &[unit("XB00", 8)]),
            &name_obj("\\PRT0", &package(1, &[n("LNKA")])),
        ]),
    );
    let mut ns = table_of(2, &defs, 0, &store(&i(0x5A), &n("\\DEV0.XB00")));
    let mut sim = Sim::new();
    run_on(&mut ns, &mut sim, "\\TEST", vec![]).unwrap();
    assert_eq!(sim.mem_byte(0x2000), 0x5A);
    let prt = run_on(&mut ns, &mut sim, "\\PRT0", vec![]).unwrap();
    let Data::Package(p) = prt
    else
    {
        panic!("{prt:?}");
    };
    assert!(matches!(p[0], Data::Ref(_)), "{:?}", p[0]);
}

#[test]
fn package_nesting_is_bounded()
{
    // Local0 = Package { Local0 }, again and again.
    let nest = cat(&[
        &store(&pkg_obj(&[0x13], &i(1)), &l(1)),
        &store(&l(0), &index(&l(1), &i(0))),
        &store(&l(1), &l(0)),
    ]);
    let defs = name_obj("CNT_", &i(0));
    let body = cat(&[
        &store(&i(0), &l(0)),
        &while_(&[0x01], &cat(&[&[0x75], &n("CNT_"), &nest])),
    ]);
    let mut ns = table_of(2, &defs, 0, &body);
    assert_eq!(
        run_on(&mut ns, &mut Sim::new(), "\\TEST", vec![])
            .unwrap_err()
            .kind,
        FaultKind::Bound
    );
    let Data::Integer(passes) = data(&ns, "\\CNT_")
    else
    {
        panic!();
    };
    assert!(
        (MAX_VALUE_DEPTH as u64..=MAX_VALUE_DEPTH as u64 + 1).contains(&passes),
        "{passes}"
    );
}

#[test]
fn call_depth_is_bounded()
{
    let defs = method(
        "RECR",
        1,
        &ret(&op(&n("RECR"), &[&bin(0x72, &a(0), &i(1))])),
    );
    let mut ns = table_of(2, &defs, 0, &ret(&op(&n("RECR"), &[&i(0)])));
    let f = run_on(&mut ns, &mut Sim::new(), "\\TEST", vec![]).unwrap_err();
    assert_eq!(f.kind, FaultKind::Depth);
    // TEST and RECR(0) to RECR(n): n + 2 nested calls, the most
    // MAX_CALL_DEPTH, and one more.
    let recr = |last: u64| {
        let body = cat(&[
            &if_(&op(&[0x93], &[&a(0), &i(last)]), &ret(&a(0))),
            &ret(&op(&n("RECR"), &[&bin(0x72, &a(0), &i(1))])),
        ]);
        let mut ns = table_of(
            2,
            &method("RECR", 1, &body),
            0,
            &ret(&op(&n("RECR"), &[&i(0)])),
        );
        run_on(&mut ns, &mut Sim::new(), "\\TEST", vec![])
    };
    let last = MAX_CALL_DEPTH as u64 - 2;
    assert_eq!(recr(last), Ok(Data::Integer(last)));
    assert_eq!(recr(last + 1).unwrap_err().kind, FaultKind::Depth);
}

#[test]
fn the_objects_an_evaluation_creates_are_bounded()
{
    // A chain of methods M0 to M<last>, each creating 600 objects in its
    // own scope and calling the next: six make 3600 objects, seven 4200.
    const { assert!(600 * 6 < MAX_EVAL_OBJECTS && 600 * 7 > MAX_EVAL_OBJECTS) };
    let names: Vec<u8> = (0..600)
        .flat_map(|k| name_obj(&format!("N{k:03}"), &i(0)))
        .collect();
    let chain = |last: usize| {
        let defs: Vec<u8> = (0..=last)
            .flat_map(|k| {
                let next = if k < last
                {
                    op(&n(&format!("M{}", k + 1)), &[])
                }
                else
                {
                    vec![]
                };
                method(&format!("M{k}"), 0, &cat(&[&names, &next]))
            })
            .collect();
        let mut ns = table_of(2, &defs, 0, &op(&n("M0"), &[]));
        let before = ns.len();
        let r = run_on(&mut ns, &mut Sim::new(), "\\TEST", vec![]);
        // Whatever the outcome, the objects are gone when it returns.
        assert_eq!(ns.len(), before);
        r
    };
    assert_eq!(chain(5), Ok(Data::Uninitialized));
    assert_eq!(chain(6).unwrap_err().kind, FaultKind::Bound);
    // A method that recurses creates its objects again in the same scope.
    let body = cat(&[
        &name_obj("N000", &i(0)),
        &if_(&a(0), &op(&n("RECR"), &[&i(0)])),
    ]);
    let defs = method("RECR", 1, &body);
    assert_eq!(fault(&defs, &op(&n("RECR"), &[&i(1)])), FaultKind::Exists);
}

#[test]
fn delays_are_bounded()
{
    let (kind, passes) = count_passes(&op(&ext(0x22), &[&i(1000)]));
    assert_eq!((kind, passes), (FaultKind::Bound, 11));
    assert_eq!(fault(&[], &op(&ext(0x22), &[&i(10_001)])), FaultKind::Bound);
    // Waits for the global lock count too: each refused wait in full, and
    // a wait with no limit asks for what the budget has left.
    let mut sim = Sim::new();
    sim.gl_refuse = true;
    let (kind, passes) = count_passes_on(&[], &acquire("\\_GL_", 1000), &mut sim);
    assert_eq!((kind, passes), (FaultKind::Bound, 11));
    assert_eq!(sim.gl_waits.last(), Some(&0));
    let mut sim = Sim::new();
    sim.gl_refuse = true;
    let mut ns = table_of(
        2,
        &[],
        0,
        &cat(&[&op(&ext(0x22), &[&i(4000)]), &acquire("\\_GL_", 0xFFFF)]),
    );
    assert_eq!(
        run_on(&mut ns, &mut sim, "\\TEST", vec![])
            .unwrap_err()
            .kind,
        FaultKind::Bound
    );
    assert_eq!(sim.gl_waits, vec![6000]);
    // A granted wait counts the time it took: 1000 ms per pass, and 1 ms of
    // Sleep, end the budget in the tenth pass.
    let mut sim = Sim::new();
    sim.gl_grant_ms = 1000;
    let pass = cat(&[
        &acquire("\\_GL_", 1000),
        &release("\\_GL_"),
        &op(&ext(0x22), &[&i(1)]),
    ]);
    let (kind, passes) = count_passes_on(&[], &pass, &mut sim);
    assert_eq!((kind, passes), (FaultKind::Bound, 10));
}

// The lowest stack address the host saw, through its callbacks.
thread_local! {
    static LOWEST: Cell<usize> = const { Cell::new(usize::MAX) };
}

/// A host recording the stack depth of its callbacks.
struct Probe(Sim);

impl Host for Probe
{
    fn io_read(
        &mut self,
        region: crate::host::Span,
        port: u64,
        width: Width,
    ) -> Result<u64, HostError>
    {
        let mark = 0u8;
        LOWEST.with(|l| l.set(l.get().min(std::ptr::addr_of!(mark) as usize)));
        self.0.io_read(region, port, width)
    }
    fn io_write(
        &mut self,
        region: crate::host::Span,
        port: u64,
        width: Width,
        value: u64,
    ) -> Result<(), HostError>
    {
        self.0.io_write(region, port, width, value)
    }
    fn mem_read(
        &mut self,
        region: crate::host::Span,
        addr: u64,
        width: Width,
    ) -> Result<u64, HostError>
    {
        self.0.mem_read(region, addr, width)
    }
    fn mem_write(
        &mut self,
        region: crate::host::Span,
        addr: u64,
        width: Width,
        value: u64,
    ) -> Result<(), HostError>
    {
        self.0.mem_write(region, addr, width, value)
    }
    fn pci_read(
        &mut self,
        function: crate::host::PciAddress,
        offset: u64,
        width: Width,
    ) -> Result<u64, HostError>
    {
        self.0.pci_read(function, offset, width)
    }
    fn pci_write(
        &mut self,
        function: crate::host::PciAddress,
        offset: u64,
        width: Width,
        value: u64,
    ) -> Result<(), HostError>
    {
        self.0.pci_write(function, offset, width, value)
    }
    fn notify(&mut self, path: &[Seg], value: u64) -> Result<(), HostError>
    {
        self.0.notify(path, value)
    }
    fn sleep(&mut self, ms: u64)
    {
        self.0.sleep(ms);
    }
    fn stall(&mut self, us: u64)
    {
        self.0.stall(us);
    }
    fn timer(&mut self) -> u64
    {
        self.0.timer()
    }
    fn acquire_global_lock(&mut self, timeout_ms: u16) -> Result<bool, HostError>
    {
        self.0.acquire_global_lock(timeout_ms)
    }
    fn release_global_lock(&mut self) -> Result<(), HostError>
    {
        self.0.release_global_lock()
    }
    fn osi(&mut self, name: &[u8]) -> bool
    {
        self.0.osi(name)
    }
}

#[test]
fn an_evaluation_fits_the_stack_budget_at_the_depth_bound()
{
    thread::Builder::new()
        .stack_size(EVAL_STACK_BYTES)
        .spawn(|| {
            let top = 0u8;
            let top = std::ptr::addr_of!(top) as usize;
            // RECR(n) nests k operators around a call of RECR(n - 1), and
            // RECR(0) reads a field: every depth up to the bound, reached
            // through calls and operands both.
            let mut deepest = 0usize;
            let mut reached = 0usize;
            for k in [1usize, 4, 16, 58]
            {
                let mut call = op(&n("RECR"), &[&bin(0x74, &a(0), &i(1))]);
                for _ in 0..k
                {
                    call = op(&[0x80], &[&call, &[0]]);
                }
                let body = cat(&[
                    &if_(&op(&[0x93], &[&a(0), &i(0)]), &ret(&n("FLD0"))),
                    &ret(&call),
                ]);
                let defs = cat(&[
                    &region("REG0", 1, &i(0x100), &i(1)),
                    &field("REG0", 1, &[unit("FLD0", 8)]),
                    &method("RECR", 1, &body),
                ]);
                for depth in 0..=MAX_CALL_DEPTH as u64
                {
                    let mut ns = table_of(2, &defs, 0, &ret(&op(&n("RECR"), &[&i(depth)])));
                    let mut probe = Probe(Sim::new());
                    LOWEST.with(|l| l.set(usize::MAX));
                    let r = Evaluator::new(&mut ns, &mut probe).evaluate_path("\\TEST", vec![]);
                    if let Err(f) = r
                    {
                        assert_eq!(f.kind, FaultKind::Depth);
                        break;
                    }
                    reached = reached.max(usize::try_from(depth).unwrap() * (k + 3));
                    deepest = deepest.max(top - LOWEST.with(Cell::get));
                }
            }
            // The levels reached come within one call's of the bound.
            assert!(reached + 64 > MAX_EVAL_DEPTH, "{reached}");
            // A parse nested to its bound may run at that depth, on the
            // same stack.
            assert!(
                2 * deepest + PARSE_STACK_BYTES < EVAL_STACK_BYTES,
                "{deepest}"
            );
            eprintln!("evaluation stack at the depth bound: {deepest} bytes");
        })
        .unwrap()
        .join()
        .unwrap();
}

// ── No panic ──────────────────────────────────────────────────────────

#[test]
fn arbitrary_method_bodies_evaluate_to_a_result_or_a_fault()
{
    let mut seed = 0x0123_4567_89AB_CDEFu64;
    let mut rand = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    // Objects for the bodies to reach: data, a field, a mutex, an event, a
    // device and a method.
    let defs = cat(&[
        &name_obj("INT0", &i(5)),
        &name_obj("BUF0", &b(&[1, 2, 3, 4])),
        &name_obj("PKG0", &package(2, &[i(1), string("x")])),
        &region("REG0", 1, &i(0x100), &i(8)),
        &field("REG0", 1, &[unit("FLD0", 8), unit("FLD1", 16)]),
        &mutex("MTX0", 0),
        &op(&ext(0x02), &[&n("EVT0")]),
        &device("DEV0", &[]),
        &method("MTH0", 1, &ret(&a(0))),
    ]);
    // Operator bytes, to make the bodies more than noise.
    let lead = [
        0x70, 0x72, 0x73, 0x74, 0x75, 0x77, 0x78, 0x79, 0x7B, 0x83, 0x86, 0x87, 0x88, 0x8A, 0x8E,
        0x93, 0x96, 0x98, 0x9D, 0xA0, 0xA2, 0xA4, 0x60, 0x61, 0x68, 0x0A, 0x0D, 0x11, 0x12, 0x5B,
    ];
    let tails = [
        b"INT0".as_slice(),
        b"BUF0",
        b"PKG0",
        b"FLD0",
        b"MTX0",
        b"EVT0",
        b"DEV0",
        b"MTH0",
    ];
    let mut faults = 0;
    for _ in 0..3000
    {
        let len = usize::try_from(rand() % 48).unwrap();
        let mut body = Vec::new();
        while body.len() < len
        {
            match rand() % 4
            {
                0 => body.push(lead[usize::try_from(rand() % lead.len() as u64).unwrap()]),
                1 => body.extend_from_slice(
                    tails[usize::try_from(rand() % tails.len() as u64).unwrap()],
                ),
                _ => body.push(u8::try_from(rand() & 0xFF).unwrap()),
            }
        }
        let mut ns = Namespace::new().unwrap();
        let aml = cat(&[&defs, &method("TEST", 2, &body)]);
        let _ = ns.load_table(&table(&aml));
        let mut sim = Sim::new();
        let failed = {
            let mut ev = Evaluator::new(&mut ns, &mut sim);
            let _ = ev.run_module_code();
            ev.evaluate_path("\\TEST", vec![Data::Integer(1), Data::Buffer(vec![0; 4])])
                .is_err()
        };
        faults += usize::from(failed);
        assert!(!sim.gl_held);
    }
    assert!(faults > 0);
}
