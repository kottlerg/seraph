# shared/aml

The ACPI Machine Language (AML) of ACPI 6.5 § 20: its encodings, the resource-template decoder,
the term parser, the namespace a DSDT and its SSDTs load into, and the evaluator that runs their
code, reaching hardware through a host trait.

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
    ├── value.rs                # Values (Data), object references, data conversions
    ├── host.rs                 # The Host trait the evaluator reaches hardware through
    ├── eval/
    │   ├── mod.rs              # Evaluator: frames, calls, control flow, module-level code
    │   ├── expr.rs             # Operand terms and the operators that compute a value
    │   ├── place.rs            # Targets, references, the store rules
    │   ├── field.rs            # Operation regions, field units, buffer fields
    │   └── sync.rs             # Mutexes, events, the global lock, delays, Notify
    └── tests/
        ├── mod.rs              # Parser and loader tests over hand-assembled AML and the fixtures
        ├── eval.rs             # Evaluator tests over hand-assembled AML
        ├── sim.rs              # The simulated QEMU machine behind the Host trait
        └── qemu.rs             # The fixtures' methods run on the simulated machine
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
| `value` | `Data`, the value of a data object or an expression; `Ref`, an object reference; the conversions of ACPI 6.5 § 19.3.5 | Yes |
| `host` | `Host`, the trait through which the evaluator reaches operation regions, notifications, delays, the timer, the global lock and `_OSI` | No |
| `eval` | `Evaluator`: runs control methods and module-level code over a `Namespace` and a `Host` | Yes |

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

Nodes live in an arena and link to their parent, first child and next sibling, and record the
scope their definition is written in, from which the names of a region's offset and length, a bank
field's value and a package's elements resolve: the parent, but for a definition by a path, which
is placed under the path's node. Every node has an owner: the predefined objects, the table whose load created it, or a method frame of an
evaluator, whose objects `remove_owned` deletes when the method returns. A removed node's slot
and id are reused. A node a table created is never removed: a method frame that defines a name a
table declared `External` holds that node until the method returns, when `remove_owned` gives
the `External` back to the table, with a new generation.

`Namespace::new` creates the predefined objects: `\`, `\_GPE`, `\_PR_`, `\_SB_`, `\_SI_`,
`\_TZ_`, the Global Lock mutex `\_GL_`, the native method `\_OSI`, and the data objects `\_OS_`
and `\_REV`.

Names resolve as ACPI 6.5 § 5.3 says: a name with a root or parent prefix, or of more than one
segment, is a path from the scope it starts at; a relative name of one segment is looked up in
that scope and then in each enclosing scope up to the root.

`load_table` walks a DSDT or SSDT's term list in order, twice. Both walks enter the bodies of
`Scope`, `Device`, `Processor`, `PowerResource` and `ThermalZone`. The first declares the names
the table defines at load: it creates the `Device`, `Processor`, `PowerResource` and
`ThermalZone` objects, each `Method` with the span of its body, which `method_code` parses on
first use, each `External`, and a placeholder holding an uninitialized data object for each name
that `Name`, `Alias`, `Mutex`, `Event`, `OperationRegion`, `DataRegion` and the field
definitions declare. The second defines: it parses every term but those bodies again, now that
the table's names are in the namespace, so a call to a method defined later in the table parses
as a call, and a data object the first walk declared hides a method of the same name in an
enclosing scope; it gives each of the table's placeholders that a definition names its object
(a `Name`'s data folded to a constant); and it keeps every other term as module-level code, in
order, for an evaluator to run. The namespace keeps a copy of each table.

Where a method call may stand, each walk reads a name as a call when the name, resolved from the
term's scope and through any alias, is a method or a method's `External`, and as a reference
otherwise. A walk resolves it in the namespace as it stands when that walk reaches the term: in
the first walk it holds the earlier tables' names and what the walk has declared so far in table
order, and in the second every name the first walk declared. So a reference the first walk
meets before the definition of the data object it names can read, in that walk, as a call of a
method of that name defined earlier in an enclosing scope. The second walk reads it as a
reference when the data object is declared by then in a scope the search reaches before the
method's, as it is when the first walk declared it there, and as the same call when the search
still finds the method. A fault that ends the term list holding the definition, before the
definition is reached, keeps the first walk from declaring it; a definition in a list no fault
ends, an enclosing list or a later `Scope` among them, is reached. Where the two walks read a
term differently, the first may declare a name the second never defines. A load never removes a
node: a placeholder the second walk does not define, by a fault or by such a reading, stays an
uninitialized data object, so every reference resolved to it stays valid.

A fault ends only the term list it is found in: a term whose end its `PkgLength` gives is
skipped and the list continues after it, and any other fault ends the list, whose enclosing
list continues. The `LoadReport` counts the objects created, the module-level terms kept and the
faults the second walk met, and keeps the first fault. `method_code` parses a method's whole
body or none of it: a fault anywhere in the body is the method's fault, and the method has no
code. `parse_methods` parses every method and counts the methods that fault.

---

## Evaluation

`Evaluator::new` borrows a `Namespace` and a `Host`. `evaluate` (or `evaluate_path`, from an
absolute path) calls a method with its arguments or reads any other object's value, and
`run_module_code` runs the module-level terms the loads kept, in load order, each as its own
evaluation, the objects it creates owned by its table. Each evaluation starts with the full
budget of every bound (§ Bounds) and ends with a value or a `Fault`, never a panic; at its end
every mutex it left held, the global lock among them, is released.

The evaluator walks the parsed terms of each method's code, which the namespace parses on first
use. A call pushes a frame holding the method's seven arguments and eight locals; the objects
the method creates belong to the frame and are removed when it returns, normally or by a fault,
so a fault leaves the namespace as the code changed it up to the fault, without the frames'
objects. A table of revision below 2 runs with 32-bit integers.

Values own their data: a package holds its elements and a buffer its bytes. An object reference
(`RefOf`, `Index`, `CondRefOf`) names where the object lives (a namespace node with its
generation, a frame's local or argument, or a temporary it owns) and an index path into it, so a
store through it changes the object in place, and a reference to a removed node or to a returned
frame's local resolves to nothing. A package element that is an unresolved name is resolved from
the scope the package's `Name` is written in when it is read, whole or through `Index`.

The store rules are those of ACPI 6.5 § 19.3.5: a store to a named integer, string or buffer
converts the value to that type, a buffer keeping its length; a store to a named object of any
other data type, or to a local, replaces it; a store to an argument holding a reference stores
through it; a store to a field unit or buffer field writes it. `CopyObject` replaces without
converting.

A field unit is accessed in datums of its access width, each aligned to that width from the
start of its region, a datum it covers in part written under its update rule (preserve, write as
ones, write as zeros). A `BankField` unit writes its bank value first; an `IndexField` unit
writes each datum's byte offset to its index field and moves the datum through its data field.
A unit whose lock rule says so holds the firmware global lock across the access, waiting for it
no longer than the delay budget allows. A unit wider than an integer reads as a buffer; one wider
than `MAX_BUFFER_BYTES` is neither read nor written and fails with `FaultKind::Bound`. A region
is `SystemMemory`, `SystemIO` or `PCI_Config`; its offset and length are evaluated when a method
defines it, or at its first access when a table does, and every access lies inside that span.
An I/O or memory access carries the span to the host; a `PCI_Config` access carries the
function and the offset in its configuration space. A `PCI_Config` region's function is found
at its first access: the segment and bus are the enclosing host bridge's `_SEG` and `_BBN` (0
when absent), replaced at each PCI-to-PCI or CardBus bridge on the way down by the secondary bus
number its header holds, and the device and function are the region's device's `_ADR`. To find
the bus the evaluator reads, outside any region, the header type of each device with an `_ADR`
on the way down and the secondary bus of each that is a bridge.

The evaluator runs one thread of AML, so no other thread holds a mutex: `Acquire` succeeds unless
it breaks the ordering rule of ACPI 6.5 § 19.6.2 (the current sync level is the highest among
the mutexes held, a serialized method's own among them), and `Release` must name a mutex at the
current level. `\_GL_` also holds the firmware global lock, which the host gives; a wait for it
counts against the delay budget, and one with no timeout fails when the budget ends. An event
counts its signals; `Wait` with none pending times out after its timeout, and fails with no
timeout, since nothing could signal it. `Notify` passes the object's absolute path and the value
to the host; `Sleep` and `Stall` go to the host's delays, and `\_OSI` asks the host.

`Load`, `LoadTable`, `Unload`, `DataTableRegion`, a field `Connection`, and the region spaces
other than the three above fail with `FaultKind::Unsupported`; `Fatal` ends the evaluation with
`FaultKind::Fatal`.

---

## Bounds

The bounds are constants of `src/lib.rs`, stated in [docs/limits.md](../../docs/limits.md)
§ devmgr: the parser's nesting depth (`MAX_PARSE_DEPTH`), and the size of a buffer, a string and
a package, whether a table's `Name` declares it or an evaluation makes it (`MAX_BUFFER_BYTES`,
`MAX_PACKAGE_ELEMENTS`). The namespace has no node bound: its arena grows with the nodes created,
and a table's load creates at most one node for each four bytes of its AML, since every object a
table declares takes at least its name segment. A thread that loads or parses AML MUST have
`PARSE_STACK_BYTES` of stack, which a host test checks by a load and a parse nested to the depth
bound on a thread of that size.

Each evaluation is bounded in its call depth (`MAX_CALL_DEPTH`), its nesting of terms, calls and
field accesses on the stack (`MAX_EVAL_DEPTH`), the terms it runs (`MAX_EVAL_STEPS`), which ends
every loop, the bytes of the values it makes (`MAX_EVAL_ALLOC`), the nesting of packages in a
value (`MAX_VALUE_DEPTH`), the objects it creates (`MAX_EVAL_OBJECTS`), one `Stall`
(`MAX_STALL_US`) and its delays in all, waits for the global lock among them
(`MAX_EVAL_DELAY_MS`). Past a bound it ends with a fault.
A thread that evaluates MUST have `EVAL_STACK_BYTES` of stack, which a host test checks by an
evaluation nested to the depth bound on a thread of that size.

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
parse every method with no fault, and run every prefix of each table through the loader. They
also run every method of every configuration on a simulated machine (`src/tests/sim.rs`) that
models the registers the methods reach as QEMU's devices implement them: ACPI PCI hotplug, CPU
hotplug, the HPET, the LPC bridge's PIRQ routing and the root port's configuration header.

Firmware tables captured from real hardware are not tracked
([docs/testing.md](../../docs/testing.md)).

---

## Consumers

| Consumer | Uses |
|---|---|
| [`services/devmgr/firmware`](../../services/devmgr/README.md) | `encoding` for the static walk of the namespace, `resource` for the `_CRS` adapter |
| [`services/acpid`](../../services/acpid/README.md) | Evaluates with it at run time, over a `Host` that reaches hardware through devmgr's grants |

---

## Relevant Design Documents

| Document | Relevance |
|---|---|
| [docs/driver-binding.md](../../docs/driver-binding.md) | The ACPI namespace source of devmgr's device records |
| [docs/limits.md](../../docs/limits.md) | The parser's, the namespace's and the evaluator's bounds |
| [docs/testing.md](../../docs/testing.md) | Host tests, and the rule on real-hardware firmware tables |

---

## Summarized By

[Testing](../../docs/testing.md), [xtask/README.md](../../xtask/README.md)
