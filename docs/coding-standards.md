# Coding Standards

This document specifies the coding conventions and safety rules that apply to all
source code in the Seraph project.

---

## A. Tooling Invariants

### Formatters

The following tools are mandatory and authoritative. Each is configured at the repo root.

| Language | Tool | Config |
|---|---|---|
| Rust | `cargo fmt` | `rustfmt.toml` |
| C | `clang-format -i <file>` | `.clang-format` |

Formatters MUST be run before committing. Rules enforced by these tools are not
restated in this document. Developers MUST NOT disable or bypass these tools.

`.editorconfig` is authoritative for editor-level settings (indentation, line endings,
trailing whitespace). Editors MUST respect it.

### Clippy

Clippy defines the baseline for correct Rust code. The following lint groups are mandatory:

- `clippy::all`
- `clippy::pedantic`
- `clippy::cargo`

The following individual lints are additionally mandatory:

- `clippy::unwrap_used`
- `clippy::expect_used`
- `clippy::undocumented_unsafe_blocks`
- From `clippy::restriction`: `arithmetic_side_effects`, `as_pointer_underscore`, `as_underscore`,
  `assertions_on_result_states`, `dbg_macro`, `default_union_representation`,
  `empty_enum_variants_with_brackets`, `empty_structs_with_brackets`, `fn_to_numeric_cast_any`,
  `get_unwrap`, `indexing_slicing`, `infinite_loop`, `iter_over_hash_type`, `mem_forget`,
  `mixed_read_write_in_expression`, `pointer_format`, `precedence_bits`, `pub_without_shorthand`,
  `renamed_function_params`, `rest_pat_in_fully_bound_structs`, `self_named_module_files`,
  `separated_literal_suffix`, `suspicious_xor_used_as_pow`, `tests_outside_test_module`, `todo`,
  `try_err`, `unimplemented`, `unnecessary_rest_pattern`, `unnecessary_safety_comment`,
  `unnecessary_safety_doc`, `unnecessary_self_imports`, and `unneeded_field_pattern`.
- From `clippy::nursery`: `as_ptr_cast_mut`, `collection_is_never_read`,
  `debug_assert_with_mut_call`, `fallible_impl_from`, `literal_string_with_formatting_args`,
  `non_send_fields_in_send_ty`, `read_zero_byte_vec`, `significant_drop_in_scrutinee`,
  `trailing_empty_array`, `transmute_undefined_repr`, and `uninhabited_references`.

`pub_without_shorthand` keeps the `pub(crate)` form, `self_named_module_files` the
`mod.rs` form of a module with children, `separated_literal_suffix` the unseparated
literal suffix (`0u8`), and `tests_outside_test_module` every test in the `#[cfg(test)]` module of
§ D Form.

Each of the lints below, those listed above and those the staged roll-out below is making
mandatory, checks a rule this document states, and a site the rule permits carries an item-level
`#[expect(<lint>, reason = "...")]` (§ E) whose reason gives what the rule asks of it. The rules of
`panic`, `unreachable`, `unwrap_in_result` and `panic_in_result_fn` are in § Error Handling, of
`fn_params_excessive_bools` in § Function Design, of `non_send_fields_in_send_ty` in
§ Concurrency, and of `pointer_format` in § Cross-Boundary Data Hygiene. The others:

- `wildcard_enum_match_arm`: a match on an enum the tree defines names every variant it handles,
  the variants of a shared arm included, so that adding a variant fails the build at every match
  that must decide what to do with it. A wildcard arm remains only over an enum defined outside
  the tree, and its `#[expect]` says so.
- `volatile_composites`: a volatile access reads or writes one primitive at a time (a field, an
  element or a register) at the width the device, the protocol or the memory defines. An array or
  a struct is accessed field by field or element by element, a scrub included.
- `string_slice`: a `str` is split by a pattern method (`strip_prefix`, `split_once`,
  `char_indices`) or by `str::get` with a path for `None`, not by a byte index. An index no such
  form expresses carries an `#[expect]` that says why it lies on a character boundary.
- `significant_drop_tightening`: a lock guard is dropped at its last use, by `drop` or by a
  narrower scope. A guard held past it carries an `#[expect]` naming what the longer hold
  serialises.
- `large_stack_frames`: Clippy estimates a frame as the sum of the function's locals, an upper
  bound on the compiled frame. A function whose estimate exceeds its crate's threshold (below)
  moves its large local off the stack or is split; a frame that stays large carries an
  `#[expect]` naming the large local, its size, and the stack that holds it.

`cargo xtask build` runs Clippy with all warnings treated as errors. Code that does not pass this
configuration is non-compliant. Configuration lives in `[workspace.lints]` in the root
`Cargo.toml`; all member crates opt in via `[lints] workspace = true`. A crate-root or module-root
lint level MUST NOT enable a Clippy lint, except as a staged roll-out below permits: a Clippy lint
the project enforces is enforced in `[workspace.lints]`, for every crate.

`clippy::multiple_unsafe_ops_per_block` is being made mandatory by a staged roll-out. A crate whose
sites are fixed enables it at its crate root, `#![warn(clippy::multiple_unsafe_ops_per_block)]`,
which the build's warnings-as-errors makes binding for that crate. `core/kernel` is taken by
subsystem: the same inner attribute at the root module of a subsystem
(`core/kernel/src/<subsystem>/mod.rs`) binds that subsystem until every subsystem is fixed and the
line moves to the kernel's crate root. The crates are taken in this order: `core/boot`,
`core/kernel` by subsystem, the `abi/`, `shared/` and `runtime/` crates, the userspace services,
drivers and programs, and the harness and host crates. The roll-out ends by moving the lint to
`[workspace.lints]` and removing every crate-root and module-root level for it; a crate-root or
module-root level that enables it is permitted only until then. A site is fixed as § Unsafe Code
says.

`fn_params_excessive_bools`, `large_stack_frames`, `panic`, `panic_in_result_fn`,
`significant_drop_tightening`, `string_slice`, `unreachable`, `unwrap_in_result`,
`volatile_composites` and `wildcard_enum_match_arm` are being made mandatory by a staged roll-out
taken the same way: a crate whose sites are fixed enables them at its crate root, and `core/kernel`
at the root module of each subsystem whose sites are fixed, until the roll-out moves them to
`[workspace.lints]` and removes every crate-root and module-root level for them. A site is fixed
as the rule above that the lint checks says. Test code is exempt from `panic`,
`panic_in_result_fn`, `string_slice`, `unreachable` and `unwrap_in_result`, so their level is
`#![cfg_attr(not(test), warn(...))]`: a source-level level would override the test
configuration's relaxation, to which the roll-out ends by adding them. Two of the lints take a
setting from Clippy's configuration file, `clippy.toml`: `max-fn-params-bools = 0`, so that
`fn_params_excessive_bools` reports every function with a `bool` parameter, and
`stack-size-threshold`, the frame above which `large_stack_frames` reports. For `core/boot` and
`core/kernel` the threshold is a quarter of the smallest stack any of the crate's code runs on, and
every other crate keeps Clippy's default of 512,000 bytes. `core/boot` and `core/kernel` each add
a `clippy.toml` with both settings, and the stack the threshold derives from, when their sites are
fixed, and the roll-out ends with the root `clippy.toml`. Until then a site added in a crate or
subsystem whose sites are fixed follows the same rule.

`clippy::allow_attributes` and `clippy::allow_attributes_without_reason`, which check the
suppression form of § E, are being made mandatory by a staged roll-out. A crate whose suppressions
are in that form enables both at its crate root,
`#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]`. The crates are taken
in this order: the `abi/`, `shared/` and `runtime/` crates, the userspace services, drivers and
programs, the harness and host crates, `core/boot`, and `core/kernel`. The roll-out ends by moving
both lints to `[workspace.lints]` and removing every crate-root level for them. Until then a crate
without the line still carries `#[allow]` suppressions, and a suppression added or changed in it
takes the § E form.

`cargo xtask test` runs Clippy over test code before it runs the tests: the test configuration
(`cargo clippy --tests`) of every package it tests, once for each architecture's Linux target
(`x86_64-unknown-linux-gnu` and `riscv64gc-unknown-linux-gnu`), so test code gated on either
architecture is linted on any host, with all warnings treated as errors. Test code is held to the
configuration above except for four lints, which that pass allows: `unwrap_used`, `expect_used`,
`indexing_slicing` and `arithmetic_side_effects`. In a test, an unwrapped error, an out-of-range
index and an overflow each fail the test, which is how a test reports a defect; the lints exist to
keep those outcomes out of production code (§ Error Handling). The list `TEST_RELAXED_LINTS` in
`xtask/src/commands/test.rs` is the one place the relaxation is stated, and a test does not
suppress these lints at its own site. The pass sees the code outside the test modules too, as
the test configuration compiles it; the build's pass lints that code without the relaxation.

A site that `indexing_slicing` or `arithmetic_side_effects` reports is fixed by a checked, wrapping
or saturating operation chosen for the meaning the code already has, a `get` with an error path
the function already returns, or a restructuring that removes the index; a fix that sends an
out-of-range input down a different path carries a host test of that input (§ D). A site none of
these can express is a suppression under § E.

### Markdown

Markdown source MUST be soft-wrapped to the project column limit (100 characters). Exempt, since
the syntax cannot break them: a Markdown table row; a line consisting of one link, image, badge,
or bare URL construct, optionally preceded by a list-item marker and followed by sentence
punctuation or closing parentheses; and a leading YAML front-matter block, which is metadata
rather than Markdown source. Cells and link text SHOULD stay short. `cargo xtask lint-docs`
([xtask/README.md](../xtask/README.md)) checks the limit.
Paragraphs are separated by exactly one blank line.
Hard line breaks MUST NOT be used for visual layout only.

---

## B. Safety and Correctness Invariants

### File Headers

Every source file MUST open with a license block, a path line, and a brief description.
Author names and dates MUST NOT appear in file headers — version control handles that.

#### Structure

Elements appear in this order, each separated by a blank line:

1. **License block** — SPDX identifier, then copyright line(s)
2. **Path** — repository-relative path to this file
3. **Description** — brief summary of the file's purpose

For shell scripts with a shebang, the shebang MUST precede the license block on line 1.

#### License Block

```
SPDX-License-Identifier: GPL-2.0-only
Copyright (C) <year> <name> <email>
```

Comment syntax follows the file type: `//` for Rust and assembly, `#` for shell and YAML. Files
using block comments use the `/* * ... */` style throughout, headers included.

#### Description in Rust Files

Rust files MUST use `//!` inner doc comments for the description rather than plain
comments. These are the module's rustdoc entry. The first `//!` line is the short
summary shown in module index views; additional paragraphs, separated by a blank `//!`
line, appear only on the module's own page. Crate-level attributes (`#![no_std]`,
`#![cfg_attr(...)]`) follow the `//!` block.

#### Third-Party Attribution

Files derived from third-party sources list the original copyright first, with a note
identifying the source. Add your own copyright only for meaningful original contributions.

---

### Naming

#### General Rules (All Languages)

- `snake_case` for variables, functions, and modules
- `SCREAMING_SNAKE_CASE` for constants and macros
- Names SHOULD be self-describing. If a name requires a comment to explain what it refers
  to, rename it instead.
- Abbreviations SHOULD be used only when universally understood in context (`addr`, `buf`,
  `len`, `idx`). Avoid novel abbreviations.

#### Rust

| Item | Convention | Example |
|---|---|---|
| Variables, functions, methods | `snake_case` | `frame_count` |
| Modules | `snake_case` | `memory::paging` |
| Types (structs, enums, unions) | `PascalCase` | `PageTable` |
| Traits | `PascalCase` | `FrameAllocator` |
| Constants and statics | `SCREAMING_SNAKE_CASE` | `MAX_ORDER` |
| Enum variants | `PascalCase` | `Error::OutOfMemory` |

#### C

| Item | Convention | Example |
|---|---|---|
| Variables and functions | `snake_case` | `map_region` |
| Typedef'd structs and enums | `snake_case_t` | `process_t` |
| Macros and constants | `SCREAMING_SNAKE_CASE` | `PAGE_SIZE` |

Struct and enum tags use plain `snake_case` without `_t`:

```c
typedef struct process
{
    pid_t pid;
    char* name;
} process_t;
```

#### Assembly

Follow the target architecture's register naming conventions. Labels use `snake_case`.
Global symbols are prefixed with the component name to avoid collisions
(e.g. `kernel_entry`, `boot_gdt`).

---

### Function Design

- Functions SHOULD do one thing. If a function needs a comment to separate phases, split it.
- Functions SHOULD be under 50 lines. Functions over 100 lines require strong justification.
- A `bool` parameter that chooses what the function does MUST NOT be used: the choice is an
  enum whose variants name the behaviours, or separate functions where every caller fixes the
  choice. A `bool` parameter that is data, a value the function stores, encodes, compares or
  reports (a bit of a register or of a message word, a field of a record, an outcome it
  records), is permitted and carries `#[expect(clippy::fn_params_excessive_bools, reason =
  "...")]` naming the value, since the lint reports every `bool` parameter (§ Clippy) and cannot
  tell the two apart.

---

### Error Handling

#### Rust

- All fallible operations MUST return `Result`. Callers MUST handle errors explicitly.
- `unwrap()` and `expect()` MUST NOT be used in production code paths. Permitted in tests
  and in `const` contexts where the value is statically guaranteed.
- `panic!` and `unreachable!` MUST NOT be used in production code. A failure the caller can act
  on is an error the function returns, and a condition whose failure means the code is wrong is
  an assertion (§ Assertions). In a function that returns `Result` or `Option`, a check whose
  failure the function can report is that error, not an assertion or an `expect`. A panic is the
  last resort for an unrecoverable state neither form expresses, such as a match arm the code's
  invariants exclude; the site carries `#[expect(clippy::panic, reason = "...")]` (or
  `clippy::unreachable`) whose reason names that state. `clippy::panic`, `clippy::unreachable`,
  `clippy::panic_in_result_fn` and `clippy::unwrap_in_result` check this (§ Clippy); test code
  reports a defect by panicking and is exempt as § Clippy and § E state.
- Error types are defined per-subsystem and carry enough context for the caller to decide
  without inspecting internal state.

#### C

- Functions that can fail MUST return a status code or a sentinel error value. Error paths
  MUST be documented in the function comment.
- Return values from fallible functions MUST NOT be silently discarded. If intentionally
  ignored, document why.

---

### Assertions

Assertions communicate invariants — conditions that must hold for the program to be
correct. They are not error handling.

- `debug_assert!` / `assert()` in debug builds: use liberally for internal invariants.
  Removed in release builds.
- `assert!` / unconditional `assert()`: use only for invariants whose violation indicates
  an unrecoverable correctness failure. Remain in release builds; use sparingly.
- External values (user input, hardware registers, boot info) MUST NOT be asserted on.
  Return an error instead.

---

### Unsafe Code

- Unsafe blocks MUST be as small as possible — wrap only the lines that require it.
- An unsafe block MUST hold one unsafe operation (a raw-pointer dereference, a call of an unsafe
  function or method, an access to a mutable static, an inline-assembly invocation, or a read of
  a union field), so that each operation has a SAFETY comment of its own;
  `clippy::multiple_unsafe_ops_per_block` checks this (§ Clippy). A block that holds several is
  split, and each new block carries its own SAFETY comment.
- Several operations MAY share one block when one invariant is the whole justification of each,
  so that the SAFETY comment any one of them would carry alone states that invariant and nothing
  else, and when each is an access to memory or registers the invariant names, at a place it
  fixes, or the offset of a pointer by a constant to such a place: a run of field accesses through
  pointers to the objects one held lock serialises, or of accesses at constant offsets to the
  registers of one device under one mapping. An operation that needs a fact of its own takes a
  block of its own: a pointer offset by a computed value, whose bound is that fact; a call whose
  `# Safety` contract asks more than the invariant, the call of a function pointer loaded through
  a raw pointer among them; and an operation that relies on an earlier one of the block, such as
  a slice formed over memory the block has just zeroed. The shared block carries
  `#[expect(clippy::multiple_unsafe_ops_per_block, reason = "...")]` on the statement or
  expression that holds it, above its `// SAFETY:` comment, since
  `clippy::undocumented_unsafe_blocks` reads the comment only directly above the block. The
  `reason` names the shared invariant and is the rationale § E requires; the SAFETY comment shows
  that the invariant holds.
- Every unsafe block MUST be preceded by a `// SAFETY:` comment explaining why the
  operation is sound: what invariants hold, what has been checked, and why safe Rust
  cannot express it.
- Unsafe SHOULD NOT be used to work around a design problem — reconsider the design
  first. No lint checks this rule, and the pre-merge review reports it only where the
  workaround is a defect ([conventions.md](conventions.md) § Findings): a safety contract
  the code does not uphold, or one its callers cannot.
- `unsafe fn` MUST document their safety contract under a `# Safety` rustdoc heading.

```rust
// SAFETY: `ptr` is non-null and correctly aligned, and we hold the exclusive
// lock on this region for the duration of this call.
let value = unsafe { ptr.read() };

#[expect(
    clippy::multiple_unsafe_ops_per_block,
    reason = "every write is to a COM1 register, which the caller's contract gives this function"
)]
// SAFETY: the caller runs in ring 0 and calls this once, before any other COM1 access.
unsafe {
    outb(COM1 + 1, 0x00); // disable all interrupts
    outb(COM1 + 3, 0x80); // DLAB = 1 (access divisor latch)
}
```

---

### Memory Allocation

- All allocation paths MUST handle failure explicitly — no silent OOM.
- In the kernel, prefer static or pool allocation on hot paths. Document why dynamic
  allocation is acceptable at each site where it appears.
- Allocation MUST NOT occur inside interrupt handlers.

---

### Concurrency

- Shared mutable state MUST be protected by an explicit synchronisation primitive. Use
  `Mutex<T>` rather than a bare `T` with a separate lock — the type system should enforce
  the invariant. The exception is a kernel field whose owner a design document records:
  - a thread-control-block field whose owner
    [scheduling-internals.md § Cross-CPU TCB Ownership](../core/kernel/docs/scheduling-internals.md#cross-cpu-tcb-ownership)
    names (the TCB's own `sched_lock`, a CPU's `scheduler.lock`, the all-locks hold of a lifecycle
    commit, `THREAD_REGISTRY_LOCK`, the lock of the source or wait set the thread is parked on,
    `SLEEP_LIST_LOCK` for the thread's sleep-list node, the timer pop's batch for the expiry
    snapshot that batch takes, or, for a field that table assigns to it, the claim on the thread's
    park episode);
  - a field of an IPC object, a source or a wait set, that the object's own `lock` serialises, as
    the object's § Object Structure in [ipc-internals.md](../core/kernel/docs/ipc-internals.md)
    records;
  - a death-observer node's link and correlator, which the lock of the list holding the node
    serialises (its queue's `lock` on the free list, the owner thread's `sched_lock` or the owner
    address space's `death_lock` on an owner chain), as
    [ipc-internals.md § Event Queue](../core/kernel/docs/ipc-internals.md#event-queue-corekernelsrcipcevent_queuers)
    records;
  - a field of a per-CPU scheduler that its `lock` serialises, as
    [scheduling-internals.md § Lock Hierarchy](../core/kernel/docs/scheduling-internals.md#lock-hierarchy)
    records;
  - a field of a `CSpace` that its spinlock serialises, as
    [capability-internals.md § Storage: Hybrid Radix Directory](../core/kernel/docs/capability-internals.md#storage-hybrid-radix-directory)
    records;
  - an address space's terminal-fault observer state, which its `death_lock` serialises, as
    [memory-internals.md § Address Space Objects](../core/kernel/docs/memory-internals.md#address-space-objects-mmaddress_spacers)
    records.

  Such a field MAY be a bare `T` when a rustdoc names that owner: the field's own for a
  thread-control-block field, whose owners differ field by field; for any other object, the
  object's rustdoc, or the field's own, names the lock that owns it.
- An `unsafe impl Send` for a type with fields that are not `Send` carries
  `#[expect(clippy::non_send_fields_in_send_ty, reason = "...")]` naming the lock, or the owner
  rule above, that serialises those fields; its SAFETY comment shows that the rule holds.
- Prefer message passing over shared memory; shared memory is a deliberate optimisation,
  not the default.
- Lock ordering MUST be documented and consistent. When acquiring multiple locks, always
  take them in the documented order.
- A lock SHOULD NOT be held across an IPC call or any operation that may block.

---

### CPU-Count Width

These rules bind the kernel and the bootloader (`core/kernel/`, `core/boot/`) and every in-tree
crate either one depends on. They keep the CPU count a single definition, the boot's `cpu_count`,
bounded by the sanity ceiling `MAX_CPUS`, so a width defect is visible in review rather than only
in a boot at the boundary CPU counts ([testing.md](testing.md#coverage-tiers) § Coverage tiers).

- A structure with one entry or one bit per CPU MUST take its width from the boot's CPU count: a
  per-CPU slab the kernel's `alloc_per_cpu_slab` sizes at the boot CPU count, or a CPU set
  (`AtomicCpuMask`, `cpu_count.div_ceil(64)` words held with its object). `MAX_CPUS` MUST NOT
  size one. A literal (`64`, `256`, or any other) MUST NOT stand in for the CPU count or a
  CPU-set width, and a fixed-width integer (`u64`, `u128`) MUST NOT hold a set of CPUs.
- A CPU index or CPU count MUST NOT be converted with `as` to an integer type that cannot
  represent `MAX_CPUS` (an `as u8` truncates at 256 CPUs).
- A fixed-width window an external interface defines (the SBI `hart_mask` and `hart_mask_base`
  pair) is not a set of CPUs the kernel holds; the code filling it MUST reject or split an index
  the window cannot hold.

---

### Cross-Boundary Data Hygiene

Kernel virtual addresses, kernel pointers, and any value derived from one — a
pointer cast to an integer, a fixed kernel VA, a kernel return address, a saved
kernel stack pointer — MUST NOT cross into userspace. This covers every
cross-boundary output: syscall return registers, IPC label/badge/data/cap-slot
fields, fault and exception messages, exit and death reasons, `SYS_CAP_INFO` /
`SYS_SYSTEM_INFO` selectors, and `SYS_ASPACE_QUERY` results.

- Kernel-minted identifiers observed across the boundary MUST be opaque and
  unguessable — drawn from the entropy root (`entropy::next_u32` /
  `entropy::fill_bytes`), never a monotonic counter that leaks creation counts or
  rates.
- A value that must cross and cannot be made opaque MUST be fixed by ABI contract
  (an enum discriminant, a constant, or a count) and documented as such.
- A physical address MAY cross only where an ABI contract requires it and the caller
  already holds the capability the address describes; the kernel virtual mapping of
  that physical address MUST NOT be exposed.
- Kernel-pointer values MAY appear only in kernel-owned console diagnostics that
  userspace cannot read back: the serial-only class
  [docs/console-model.md](console-model.md) § Ownership across the boot lifecycle
  defines, with the known sites listed in
  [core/kernel/docs/cross-boundary-disclosure.md](../core/kernel/docs/cross-boundary-disclosure.md)
  § Kernel console diagnostics. They MUST NOT reach a userspace IPC or log channel. Each format
  of a kernel pointer (`{:p}`, or `{:?}` of a raw pointer) carries
  `#[expect(clippy::pointer_format, reason = "...")]` naming the serial-only sink it prints
  through, such as a panic or assertion message, which the panic handler prints through
  `console::panic_write_fmt`.

New or changed cross-boundary outputs MUST be classified in the kernel
cross-boundary disclosure inventory (`core/kernel/docs/cross-boundary-disclosure.md`)
in the same change.

---

### Documentation

- All public APIs MUST have rustdoc comments covering behaviour, arguments, return value,
  and all error variants.
- Comments explain *why*, not *what*. Self-evident code needs no comment; non-obvious
  logic must explain its reasoning.
- TODO comments follow [documentation-standards.md](documentation-standards.md) § Incomplete
  Work Markers and MUST additionally state why the work was deferred.
- Architecture decisions not obvious from the code belong in the relevant `docs/` file,
  not only in inline comments.
- Comments and rustdoc MUST reference code by stable identifier (symbol, function, const,
  type, or behaviour), never by line number. A `path:line` reference rots silently as files
  shift; reserve it for review and chat. A bare file path (no line) is acceptable for
  cross-file navigation.

---

## C. Architecture Invariants

- All architecture-specific behaviour MUST be behind a trait or module boundary.
  No `#[cfg(target_arch)]` blocks in architecture-neutral code.
- Arch-specific code in a crate MUST live under an `arch/<target>/` submodule
  (for example `arch/x86_64/`, `arch/riscv64/`). A sibling `arch/mod.rs` (or
  equivalent parent module) MUST expose the arch-dispatch surface — traits,
  type aliases, or re-exports — so that arch-neutral callers reach arch
  behaviour through a single anchor module.
- Each function in the arch-dispatch surface MUST be defined on every
  supported architecture. A function present on one architecture and
  absent on another is not permitted; the dispatch surface is the contract.
- Where a surface function has no meaningful behaviour on an architecture
  because the underlying hardware concept does not apply (for example,
  x86-64 GDT/IDT setup on RISC-V), the implementation MAY be a no-op stub.
  The stub's rustdoc MUST state that it is a no-op and briefly explain why
  the concept does not apply on that architecture. Silent no-op stubs
  without a documented reason are not permitted.
- `#[cfg(target_arch = ...)]` MUST appear only at arch-module declaration
  sites (for example, on `mod x86_64;` in `arch/mod.rs`). Items inside
  `arch/<target>/` inherit the parent's cfg gate and MUST NOT carry their
  own `cfg(target_arch)` attribute. The one exception is a lint suppression
  whose lint fires on one architecture only,
  `#[cfg_attr(target_arch = "...", expect(...))]` (§ E): it changes no
  compiled code and is permitted at any site outside `arch/<target>/`.
- Inline assembly MUST be isolated to dedicated functions or modules; never inlined
  alongside logic.
- Every inline assembly block MUST comment what it does, what registers it clobbers,
  and what constraints it assumes.
- When adding a new architecture, do not diverge from the interface contract without
  updating every implementation.

---

## D. Testing Invariants

For how to run host tests and the build/test mechanism, see
[build-system.md](build-system.md#testing). For the booted harnesses (`ktest`, `svctest`,
`usertest`), see [testing.md](testing.md).

### Scope

These invariants govern host-side `#[cfg(test)]` unit tests in every crate — kernel,
services, programs, and runtime alike, not the kernel alone. Host unit tests cover **pure,
host-reachable logic**: parsers, encoders, allocators, table walkers, state machines,
arithmetic, and validation. Logic reachable only through a syscall, IPC, real hardware, or a
booted runtime is exercised by the harnesses in [testing.md](testing.md), not by host unit
tests. Mocking the kernel ABI to manufacture a host test is forbidden — such a test exercises
the mock, not the system.

Where a component's pure logic is non-trivial — a parser of external input, a codec, an
allocator, a state machine — it SHOULD be factored so that logic is host-reachable: a
`no_std` library crate, or a trait boundary that injects the platform, rather than logic
entangled with IPC, syscall, or `std::os::seraph` calls. The goal is keeping the algorithmic
core separable from mechanism, as the kernel already does for its allocators and capability
tree ([build-system.md](build-system.md#kernel-testing-strategy)); host-testability is the
symptom of that separation, not the goal. This is a SHOULD that applies to non-trivial logic —
it is not a mandate to extract trivial glue into crates.

### Tests assert behaviour, not surface area

Coverage is the set of behaviours and failure modes that can no longer regress silently. It
is never the count of functions or fields that carry a test. Test count is not a quality
metric. Removing a test that guards nothing, adding none in its place, is a valid and
expected outcome of a test-touching change.

A test MUST be able to fail for a real reason: at least one of its failure modes must
correspond to a genuine defect in the code under test. A test whose only red path is a
constant edited in two places, or the standard library, a `derive` macro, or the compiler's
layout rules changing, guards nothing and MUST NOT exist. Before adding a test, state in one
sentence the defect it would catch; if that sentence is "someone changed the literal," do not
add it.

### Form

Unit tests live in a `#[cfg(test)]` module at the bottom of each source file:

```rust
#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn alloc_fails_when_no_regions_added()
    {
        let mut alloc = BuddyAllocator::new();
        assert_eq!(alloc.alloc(0), None);
    }
}
```

- Each test MUST cover one logical behaviour — one invariant, one transition, or one round
  trip. A behaviour whose correctness spans several fields or several assertions (a round
  trip, a multi-field constructor, a state-machine step) is one test, not one test per field
  or per assertion. Unrelated behaviours MUST NOT be bundled into one test.
- Test names read as a sentence describing the behaviour, and stay accurate after
  consolidation — name the behaviour, not the function.
- Tests MUST be independent, order-independent, and deterministic — no randomness, no timing,
  no external or shared mutable state.
- In test code, `assert!`, `assert_eq!`, `assert_ne!`, `unwrap()`, and `expect()` are all
  permitted, and indexing and arithmetic need no checked form (§ Clippy names the lints relaxed
  for test code).

### What Must Be Tested

- Non-trivial logic: every function containing a branch, loop, arithmetic, or state
  transition MUST have a success-path test for each materially distinct outcome.
- Every `Result::Err` variant, or `None`-as-failure, a function can return MUST be exercised
  by an input that provokes it.
- Boundary conditions: empty input, maximum-size input, and off-by-one cases where behaviour
  changes at the boundary.
- Modules containing `unsafe` blocks MUST have tests confirming the safe wrapper upholds its
  documented invariants under normal use.
- Serialization and wire round trips (`to_bytes`/`from_bytes`, encode/decode, cross-boundary
  marshalling) MUST have a round-trip test on a populated value.

A function with no branch and no failure mode — a plain constructor, a getter, a derived
`Default` — does not require a dedicated test. Exercising it incidentally as setup for a
behaviour test is sufficient.

### What Must Not Be Tested

These cannot fail for a real reason. They MUST NOT be added, and existing instances are
removed or consolidated:

- Tautologies and constant mirrors: asserting a constant equals its own literal, or that one
  constant bounds another by definition.
- Language- or library-guaranteed behaviour: `derive` output, `bitflags!`-generated
  operators, standard operator overloads, enum-discriminant values already pinned by
  `#[repr]`, or the compiler-guaranteed layout of an internal struct.
- Per-field fragmentation of a single behaviour.
- Duplicate-input redundancy: several tests driving one code path with inputs that exercise
  no new branch or boundary.
- Private implementation details not visible through the public interface, and trivial getters
  and setters with no logic.

### Layout and ABI Assertions

A `size_of`, `offset_of`, or alignment assertion is legitimate only when it guards an external
stability contract — a layout some consumer outside the Rust struct definition depends on:

- An ABI or wire format shared across the boot boundary or with userspace.
- A layout read from assembly or via raw-pointer cast (a per-CPU field offset; a header
  required at offset zero for a concrete-to-header pointer cast).
- A hard size budget asserted elsewhere (a structure that must fit one page or chunk).

Such an assertion is forbidden when the layout is purely internal and no external consumer
depends on it; that is a constant mirror that breaks on any benign field reorder. When
legitimate, layout assertions MUST be consolidated into one test per struct family or module,
named for the contract, with a comment naming the consumer that depends on the layout. A hard
size budget is the one exception: it MAY instead be a build-time `const` assertion beside its
type, with a comment naming the consumer that depends on the budget, so that an overflow fails
the build. That assertion is the one assertion for that budget, and the consolidated test does
not repeat it:

```rust
// Hard size budget: the bootloader writes BootInfo into one page, and the kernel
// validates and reads it there.
const _: () = assert!(size_of::<BootInfo>() <= 4096);

// ABI contract: the bootloader writes these structures into the BootInfo page and the
// kernel reads them back by offset; their sizes are part of BOOT_PROTOCOL_VERSION.
#[test]
fn boot_protocol_struct_sizes_are_stable()
{
    assert_eq!(size_of::<ReclaimRange>(), 16);
    assert_eq!(size_of::<MmioAperture>(), 16);
}
```

The same rule extends to **enum-discriminant values that form a cross-boundary contract** — a
kernel enum whose discriminants are mirrored by a userspace or ABI enum or constant. Such an
assertion is legitimate, but it MUST be anchored to the authoritative ABI definition (assert the
two sides agree), never a re-stated literal, so that drift on either side trips the test. A bare
`assert_eq!(MyEnum::Variant as u8, 3)` that mirrors the enum's own definition is a constant
mirror and is forbidden; `assert_eq!(KernelTag::X as u8, abi::Tag::X as u8)` is the legitimate
form.

---

## E. Exception Policy

Any suppression of compiler warnings, Clippy lints, static analysis checks, or
formatter behavior MUST:

- Be as narrowly scoped as possible (prefer item-level `#[expect(...)]` over
  module-level `#![expect(...)]`).
- Carry a rationale explaining why the rule is inapplicable at this site.

Blanket or module-wide suppressions are forbidden without explicit justification.

A crate that exists only to test reports a defect by panicking: a booted harness (`svctest`,
`usertest`), a per-program tester, and a test fixture or benchmark program under `programs/`. Its
crate root MAY suppress, of `unwrap_used`, `expect_used`, `panic`, `unreachable`,
`unwrap_in_result` and `panic_in_result_fn`, those that fire in it, with one
`#![expect(.., reason = "...")]` whose reason names the crate's role and how it reports a
failure. That is the justified module-wide suppression the rule above admits; any other
suppression in such a crate is item-level.

A lint is suppressed with `#[expect(<lint>, reason = "<rationale>")]`, MUST NOT be suppressed
with `#[allow(...)]`, and its `reason` carries the rationale; a comment immediately preceding the
attribute MAY extend it. An `#[expect]` whose lint no longer fires at the site fails the build,
so a suppression that is no longer needed is removed. A suppression with no `reason` field (a
formatter skip such as `#[rustfmt::skip]`) carries its rationale in a comment immediately
preceding it. Clippy's `allow_attributes` and `allow_attributes_without_reason` check this form
(§ Clippy).

Test code is linted (§ Clippy), and a suppression in it follows this section like one in
production code. A suppression whose lint fires only in some build configurations (a feature, one
architecture, the test configuration where an item's only callers are compiled out) is
permitted; its rationale MUST name the configuration in which the lint fires, and it MUST be
gated on that configuration's predicate, either with `#[cfg_attr(<predicate>, expect(...))]` or
by sitting on an item that is itself gated on the predicate, since an `#[expect]` fails a linted
build in which its lint does not fire. A lint that fires on one architecture only takes
`#[cfg_attr(target_arch = "<arch>", expect(<lint>, reason = "..."))]`, which § C permits at any
site; inside `arch/<target>/` the module's own gate suffices and the attribute is unconditional.

A suppression in code that is compiled with no lint check takes the same form: the `std` overlay
under `runtime/ruststd/src/`, and the code a workspace crate compiles only under its
`rustc-dep-of-std` feature, which only the `std` build enables, with lints capped. No build checks
that its lint still fires there, so the review of a change to that code does.

```rust
#[cfg_attr(
    target_arch = "riscv64",
    expect(
        dead_code,
        reason = "`capacity` is part of the public contract on every architecture; \
                  no riscv64 code reads it, and it MUST NOT be removed"
    )
)]
capacity: usize,
```

---

## Build and CI

`cargo xtask build` is the single mandatory build command; it runs Clippy with the
mandated lint groups and treats all warnings as errors. The command's options are listed
in [xtask/README.md](../xtask/README.md) § `cargo xtask build`. `cargo xtask test` runs Clippy
over test code the same way (§ Clippy) before it runs the unit tests.

---

## Summarized By

[core/boot/README.md](../core/boot/README.md),
[Architecture Abstraction Layer](../core/kernel/docs/arch-interface.md),
[Kernel Cross-Boundary Disclosure Inventory](../core/kernel/docs/cross-boundary-disclosure.md),
[xtask/README.md](../xtask/README.md)
