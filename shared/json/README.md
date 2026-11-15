# shared/json

A strict JSON value (RFC 8259): the parser of untrusted text, the value it yields, and its compact
and indented printers.

---

## Source Layout

```
json/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs              # Value, Number, Map, ToJson, json!, the accessors
    ├── parse.rs            # parse, Error, ErrorKind, MAX_DEPTH, MAX_LEN
    └── print.rs            # Display (compact), Value::to_string_pretty (indented)
```

`no_std` with `alloc`, no dependency. Host-tested (`cargo xtask test`). In-tree code replaces a
registry crate here ([docs/coding-standards.md](../../docs/coding-standards.md) § Dependencies).

---

## Parsing

`parse` reads exactly one JSON value under the grammar of RFC 8259, with whitespace around it,
and refuses every other text with an `Error` that names what is wrong and the line and character
column where it is. It refuses:

- a text longer than `MAX_LEN` (16 MiB), before reading it, and arrays and objects nested deeper
  than `MAX_DEPTH` (128), which bounds the parser's recursion;
- whitespace other than space, tab, line feed and carriage return, a byte order mark among it;
- a trailing comma, a missing separator, a non-string key, and text after the value;
- in a string, an unescaped character below U+0020, an escape other than the eight short ones and
  `\uXXXX`, and a `\u` escape of a UTF-16 surrogate that is not half of a pair;
- in a number, a leading zero, a sign other than a leading `-`, a fraction or an exponent with
  no digit, and a magnitude no finite `f64` holds;
- an object that names a key twice, the keys compared after their escapes are read. RFC 8259
  leaves a repeated key's meaning to the reader, and two readers that resolve it differently read
  two documents from one text.

A number is held as the first of `u64`, a negative `i64`, and a finite `f64` that holds it:
an integer neither integer form holds, and every number written with a fraction or an exponent,
is a float, so `Value::as_u64` of `1.0` is `None`.

---

## Values and Printing

A `Value` is `Null`, `Bool`, `Number`, `String`, `Array`, or `Object`; an object's
members are a `Map`, a `BTreeMap` in name order. Indexing by a key or an element index yields
`null` for a member or an element the value does not hold, and assigning through a key index
makes the value an object that holds the member. `json!` builds a value from JSON text with Rust
expressions in it, each converted through a reference by `ToJson`.

`Display` prints a value compactly; `Value::to_string_pretty` indents it two spaces a level,
with `": "` after a key and `[]` and `{}` for an empty array and object. Both print members
in name order, escape in a string only what RFC 8259 requires (`"`, `\`, and the characters
below U+0020), and print a float with a fraction or an exponent, so that every printed value
reads back as itself.

---

## Consumers

| Consumer | Reads |
|---|---|
| [`xtask`](../../xtask/README.md) | The GitHub CLI's answers, the review run records and ledgers, the orchestration state, the host lock's records, and the assistant's hook events; it writes the records and the state with the printers |
| [`shared/crypto/testkit`](../crypto/testkit/README.md) | The vendored Wycheproof files and its reference vectors; its generator writes the vectors with the compact printer |

No component of the OS depends on the crate.

---

## Relevant Design Documents

| Document | Relevance |
|---|---|
| [docs/coding-standards.md](../../docs/coding-standards.md) | § Dependencies: no registry crate, the reason the crate exists |

---

## Summarized By

None
