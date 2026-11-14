# shared/aml

The ACPI Machine Language (AML) of ACPI 6.5 § 20: its encodings, the resource-template decoder,
the term parser, and the namespace a DSDT and its SSDTs load into.

---

## Source Layout

```
aml/
├── Cargo.toml
├── README.md
├── fixtures/                   # QEMU's tables, one directory per configuration (§ Fixtures)
│   ├── riscv64-rootport/
│   ├── x86-default/
│   ├── x86-rootport/
│   └── x86-rootport-native/
└── src/
    ├── lib.rs                  # Bounds, Fault, FaultKind
    ├── encoding.rs             # Opcodes, PkgLength, NameString, integer and string data, EISA ID
    ├── resource.rs             # Resource-template decoder (descriptors, Resource)
    ├── term.rs                 # Parsed form of AML code (Term, Op, Imm, Name)
    ├── parse.rs                # Term parser
    ├── namespace.rs            # Object tree, search rules, predefined objects, code store
    ├── load.rs                 # Table load (Namespace::load_table, LoadReport)
    └── tests.rs                # Host tests over hand-assembled AML and the fixtures
```

`no_std` with `alloc`, no dependency. Host-tested (`cargo xtask test`).

---

## Modules

| Module | Contents | Allocates |
|---|---|---|
| `encoding` | The opcodes, `PkgLength`, `NameString` (a borrowed `NameStr`), integer and string data, the length of a data object, and the EISA ID | No |
| `resource` | `descriptors`, an iterator over the descriptors of a resource template (§ 6.4), address windows included | No |
| `term`, `parse` | `Term`, one per opcode, name reference or data object, with its operands in encoding order; the parser that produces it | Yes |
| `namespace` | `Namespace`: the object tree, name resolution, the objects a load creates, and the code store | Yes |

The alloc-free modules serve a caller with no heap: devmgr's static walk of the namespace and its
`_CRS` adapter (`services/devmgr/firmware/src/aml.rs`) are built on them.

---

## Parsing

The grammar is context-free but for one point: a name in an operand position is a method call
when it names a method, and the operands that follow it are as many as the method takes. The
parser takes that count from the namespace, resolving the name from the scope of the code it
parses; an alias is followed, and an `External` of a method gives its count. Each operand
position takes the operand kind its opcode's grammar names (`TermArg`, `SuperName`, `Target`, a
name that is never invoked, or `SimpleName`).

An `Else` whose body is one `If` (alone or with its own `Else`) is an `ElseIf` of the `If` it
follows, parsed at that `If`'s depth, so a chain of them, as a compiled `Switch` makes one per
`Case`, nests no deeper however long it is.

Every read is bounded by the end of the package being parsed, nesting is bounded by
`MAX_PARSE_DEPTH`, every term consumes at least one byte, and every allocation is fallible, so
any byte string parses to terms or a `Fault`, never a panic.

---

## Namespace

Nodes live in an arena and link to their parent, first child and next sibling. Every node has
an owner: the predefined objects, the table whose load created it, or a method frame of an
evaluator, whose objects `remove_owned` deletes when the method returns. A removed node's slot
and id are reused.

`Namespace::new` creates the predefined objects: `\`, `\_GPE`, `\_PR_`, `\_SB_`, `\_SI_`,
`\_TZ_`, the Global Lock mutex `\_GL_`, the native method `\_OSI`, and the data objects `\_OS_`
and `\_REV`.

Names resolve as ACPI 6.5 § 5.3 says: a name with a root or parent prefix, or of more than one
segment, is a path from the scope it starts at; a relative name of one segment is looked up in
that scope and then in each enclosing scope up to the root.

`load_table` walks a DSDT or SSDT's term list in order, twice. Both walks enter the bodies of
`Scope`, `Device`, `Processor`, `PowerResource` and `ThermalZone`. The first declares: it creates
the `Device`, `Processor`, `PowerResource` and `ThermalZone` objects, each `Method` with the span
of its body, which `method_code` parses on first use, and each `External`, and parses every
other term only to find its end. The second defines: it parses every other term again, now that
the table's methods have their argument counts in the namespace, so a call to a method defined
later in the same table parses as a call; it creates the objects that `Name` (its data folded to
a constant), `Alias`, `Mutex`, `Event`, `OperationRegion`, `DataRegion` and the field
definitions declare; and it keeps every other term as module-level code, in order, for an
evaluator to run. The namespace keeps a copy of each table.

A fault ends only the term list it is found in: a term whose end its `PkgLength` gives is
skipped and the list continues after it, and any other fault ends the list, whose enclosing
list continues. The `LoadReport` counts the objects created, the module-level terms kept and the
faults the second walk met, and keeps the first fault. `method_code` parses a method's whole
body or none of it: a fault anywhere in the body is the method's fault, and the method has no
code. `parse_methods` parses every method and counts the methods that fault.

---

## Bounds

The bounds are constants of `src/lib.rs`, stated in [docs/limits.md](../../docs/limits.md)
§ devmgr: the nesting depth (`MAX_PARSE_DEPTH`), and the size of a buffer and of a package a
table's `Name` declares (`MAX_BUFFER_BYTES`, `MAX_PACKAGE_ELEMENTS`). The namespace has no node
bound: its arena grows with the nodes created, and a table's load creates at most one node for
each four bytes of its AML, since every object a table declares takes at least its name segment.
A thread that loads or parses AML MUST have `PARSE_STACK_BYTES` of stack, which a host test
checks by a load and a parse nested to the depth bound on a thread of that size.

---

## Fixtures

`fixtures/<configuration>/` holds the AML tables of one QEMU configuration, as QEMU's firmware
installed them: `DSDT.aml`, and `SSDT1.aml`, `SSDT2.aml`, ... in the order of the XSDT, which is
the order they load in. `capture.txt` beside them records the command that wrote them, the QEMU
version, the firmware image and the QEMU arguments, with host paths replaced by placeholders.

| Configuration | Machine |
|---|---|
| `x86-default` | q35 as the tree boots it |
| `x86-rootport` | q35 with an empty PCI Express root port |
| `x86-rootport-native` | `x86-rootport` with ACPI PCI hotplug off (`-global ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off`) |
| `riscv64-rootport` | riscv64 `virt` with an empty PCI Express root port |

Each is the tree's launch of its architecture with the test devices attached, 4 vCPUs and
512 MiB. `cargo xtask capture-acpi --config <configuration>`
([xtask/README.md](../../xtask/README.md) § `cargo xtask capture-acpi`) writes a configuration's
tables again, for a new QEMU version. The host tests load every table of every configuration and
parse every method with no fault, and run every prefix of each table through the loader.

Firmware tables captured from real hardware are not tracked
([docs/testing.md](../../docs/testing.md)).

---

## Consumers

| Consumer | Uses |
|---|---|
| [`services/devmgr/firmware`](../../services/devmgr/README.md) | `encoding` for the static walk of the namespace, `resource` for the `_CRS` adapter |

---

## Relevant Design Documents

| Document | Relevance |
|---|---|
| [docs/driver-binding.md](../../docs/driver-binding.md) | The ACPI namespace source of devmgr's device records |
| [docs/limits.md](../../docs/limits.md) | The parser's and the namespace's bounds |
| [docs/testing.md](../../docs/testing.md) | Host tests, and the rule on real-hardware firmware tables |

---

## Summarized By

[Testing](../../docs/testing.md), [xtask/README.md](../../xtask/README.md)
