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

## Project conventions
See [docs/conventions.md](../docs/conventions.md) for versioning, backlog tracking (GitHub Issues),
branch/PR workflow, CI gating, and release production. Treat its rules as the source of
truth for "how work is tracked and shipped" on this project.

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

## PR workflow operations
- All non-tag-driven work lands via a feature-branch PR per
  [docs/conventions.md](../docs/conventions.md); the assistant MUST NOT push directly
  to `master`.
- After pushing a PR, the assistant MUST start watching its CI run via
  `gh pr checks <N> --watch` (or `gh run watch <run-id>`) as a backgrounded
  `Bash` invocation (`run_in_background: true`). Do not poll, do not sleep —
  the harness notifies on completion.
- On green: confirm the pass in one line, then run the pre-merge audit
  before prompting for merge:
  1. `gh pr view <N> --json body`. Every `- [ ]` in the PR body MUST be
     `- [x]` or removed with rationale. List any unticked items to the
     user and resolve them (`gh pr edit`) before continuing.
  2. For each `Closes #N` / `Fixes #N` in the PR body, `gh issue view <N>
     --json body`. Every `- [ ]` under `## Acceptance` MUST be `- [x]` or
     dropped with rationale. Resolve via `gh issue edit`.
  3. Only after the audit clears, prompt the user for the merge decision.
     Merge via `gh pr merge <N> --merge --delete-branch`.
- On red: surface the failing job's tail (`gh run view <run-id> --log-failed`
  or equivalent) so the user can see the actual error without asking.
- The assistant MUST NOT merge a PR while its CI run is pending or failing.
  Merge is the user's call; the assistant prepares the merge but does not
  execute it without explicit instruction.

## Validation
- Changes MUST be validated beyond successful compilation.
- At minimum, on both `x86_64` and `riscv64`:
  1. `cargo xtask build` MUST succeed.
  2. `cargo xtask run` (a pure runner; it does not build) MUST then boot
     ktest or userspace services under QEMU and the chosen mode's
     terminal pass marker MUST appear.
- Host-side compilation, unit tests, and `cargo check` alone do not
  satisfy this requirement.

## Completeness
- Drift or defects discovered on the surface under audit MUST be fixed in
  the same pass; they are the scope, surfaced incidentally.
- "Out of scope", "follow-up", and similar deferrals MUST NOT be used to
  avoid mechanically reachable work consistent with the task's intent.
- Material scope expansions MUST be stated in one line and continued, not
  paused for permission.
- Genuine deferrals (different review surface, or expansion too large to
  absorb) MUST be filed as GitHub Issues per
  [docs/conventions.md](../docs/conventions.md), with user approval,
  before the task closes.

## Conflicts
- If any instruction, plan, or change conflicts with documented invariants or these constraints,
  the assistant MUST stop and surface the conflict explicitly.
