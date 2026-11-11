# shared/svc-grammar

The line grammar of the `.svc` files, shared by every parser of a file written in it.

---

## Source Layout

```
svc-grammar/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs              # Entry, MissingEquals, entries
```

`no_std`, no allocation, no dependency. Host-tested (`cargo xtask test`).

---

## Grammar

A file is a sequence of lines. Each line is trimmed of surrounding whitespace; a blank line,
and one whose first character is `#`, is skipped. Every other line is `key = value`, split at
its first `=`, the key and the value each trimmed; a line with no `=` is an error that carries
its 1-based line number. `entries(contents)` yields one `Entry { line, key, value }` per
`key = value` line, in file order, each borrowing the caller's text.

The keys a file kind has, which of them repeat, and how a value is read belong to that kind's
parser, which keeps its own error type over this one.

---

## Consumers

| Consumer | Files |
|---|---|
| [`services/svcmgr/svc-defs`](../../services/svcmgr/README.md) | The `.svc` service definitions and the device class files (`/config/devmgr/classes/<class>.class`) |
| [`services/devmgr/firmware`](../../services/devmgr/README.md) | The platform description tables of the boot bundle (`firmware::platform::parse_table`) |

---

## Summarized By

[Driver Binding](../../docs/driver-binding.md),
[`.svc` Service Definitions](../../services/svcmgr/docs/service-definitions.md)
