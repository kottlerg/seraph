# Seraph — AI Project Context

@../README.md

## Authority
- System-wide design and architectural invariants are defined exclusively in `docs/`.
- Each component’s `README.md` defines that component’s scope, role, and links to any authoritative
  design documents.
- Detailed behavior is defined only in component-specific `docs/` where present.
- `docs/coding-standards.md` is a system-wide, non-negotiable authority.
  - All code changes MUST comply with its rules.
  - Any deviation MUST be minimal, local, and explicitly justified at the point of use.
- `docs/documentation-standards.md` is a system-wide, non-negotiable authority.
  - All documentation changes MUST comply with its rules.

## Coding invariants
See [docs/coding-standards.md](../docs/coding-standards.md) — non-negotiable authority.

## Documentation invariants
See [docs/documentation-standards.md](../docs/documentation-standards.md) — non-negotiable authority.

## Operating procedure
- Documentation MUST be consumed by scope:
  1. System scope (`docs/`)
  2. Component scope (`<component>/README.md`)
  3. Component design scope (`<component>/docs/*.md`)
- Additional documentation MUST NOT be loaded unless required by the task.

## Tooling constraints
- All build, run, clean, and test actions MUST be performed via `cargo xtask` commands.
- Direct invocation of `cargo build`, `cargo run`, `cargo test`, or `cargo clippy` is forbidden.
- When switching architectures or targets, `cargo xtask clean` MUST be run first.

## Validation
- Changes MUST be validated beyond successful compilation.
- At minimum: the relevant build MUST succeed, and functional tests MUST
  execute against the running OS on both `x86_64` and `riscv64` (`cargo xtask
  run` booting ktest or userspace services under QEMU). Host-side compilation,
  unit tests, and `cargo check` alone do not satisfy this requirement.

## Conflicts
- If any instruction, plan, or change conflicts with documented invariants or these constraints,
  the assistant MUST stop and surface the conflict explicitly.
