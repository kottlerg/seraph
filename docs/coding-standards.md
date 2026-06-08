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

`cargo xtask build` runs Clippy with all warnings treated as errors. Code that does
not pass this configuration is non-compliant. Configuration lives in `[workspace.lints]`
in the root `Cargo.toml`; all member crates opt in via `[lints] workspace = true`.

### Markdown

Markdown source MUST be soft-wrapped to the project column limit (100 characters).
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

Comment syntax follows the file type: `//` for Rust and assembly, `#` for shell. Files
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
- Boolean parameters that alter behaviour MUST NOT be used — prefer separate functions or
  an explicit enum.

---

### Error Handling

#### Rust

- All fallible operations MUST return `Result`. Callers MUST handle errors explicitly.
- `unwrap()` and `expect()` MUST NOT be used in production code paths. Permitted in tests
  and in `const` contexts where the value is statically guaranteed.
- `panic!` MUST NOT be used in production code. A kernel panic is a last resort for
  unrecoverable states only, not a substitute for error handling.
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
- Every unsafe block MUST be preceded by a `// SAFETY:` comment explaining why the
  operation is sound: what invariants hold, what has been checked, and why safe Rust
  cannot express it.
- Unsafe SHOULD NOT be used to work around a design problem — reconsider the design
  first. This is a review gate, not a lint-checkable rule; violations are design-smell
  and should surface in code review.
- `unsafe fn` MUST document their safety contract under a `# Safety` rustdoc heading.

```rust
// SAFETY: `ptr` is non-null and correctly aligned, and we hold the exclusive
// lock on this region for the duration of this call.
let value = unsafe { ptr.read() };
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
  the invariant.
- Prefer message passing over shared memory; shared memory is a deliberate optimisation,
  not the default.
- Lock ordering MUST be documented and consistent. When acquiring multiple locks, always
  take them in the documented order.
- A lock SHOULD NOT be held across an IPC call or any operation that may block.

---

### Documentation

- All public APIs MUST have rustdoc comments covering behaviour, arguments, return value,
  and all error variants.
- Comments explain *why*, not *what*. Self-evident code needs no comment; non-obvious
  logic must explain its reasoning.
- TODO comments MUST state what needs doing and why it was deferred.
- Architecture decisions not obvious from the code belong in the relevant `docs/` file,
  not only in inline comments.

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
  own `cfg(target_arch)` attribute.
- Inline assembly MUST be isolated to dedicated functions or modules; never inlined
  alongside logic.
- Every inline assembly block MUST comment what it does, what registers it clobbers,
  and what constraints it assumes.
- When adding a new architecture, do not diverge from the interface contract without
  updating both implementations.

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
tree; host-testability is the symptom of that separation, not the goal. This is a SHOULD that
applies to non-trivial logic — it is not a mandate to extract trivial glue into crates.

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
        let mut alloc = BuddyAllocator::new(10);
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
  permitted.

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
- A hard size budget asserted elsewhere (a structure that must fit one page).

Such an assertion is forbidden when the layout is purely internal and no external consumer
depends on it; that is a constant mirror that breaks on any benign field reorder. When
legitimate, layout assertions MUST be consolidated into one test per struct family or module,
named for the contract, with a comment naming the consumer that depends on the layout:

```rust
// ABI contract: the bootloader writes these structures into the BootInfo page and the
// kernel reads them back by offset; their sizes are part of BOOT_PROTOCOL_VERSION.
#[test]
fn boot_protocol_struct_sizes_are_stable()
{
    assert_eq!(size_of::<ReclaimRange>(), 16);
    assert_eq!(size_of::<MmioAperture>(), 16);
    assert!(size_of::<BootInfo>() <= 4096);
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

- Be as narrowly scoped as possible (prefer item-level `#[allow(...)]` over
  module-level `#![allow(...)]`).
- Include a rationale comment immediately preceding the attribute, explaining why the
  rule is inapplicable at this site.

Blanket or module-wide suppressions are forbidden without explicit justification.

```rust
// `capacity` is part of the public contract on all target architectures; the
// field is unused on x86_64 but MUST NOT be removed.
#[allow(dead_code)]
capacity: usize,
```

---

## Build and CI

`cargo xtask build` is the single mandatory build command; it runs Clippy with the
mandated lint groups and treats all warnings as errors. Invocation details are in
[build-system.md](build-system.md).

---

## Summarized By

[Build System](build-system.md)

