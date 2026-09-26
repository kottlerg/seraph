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
- Existing history or code that violates a written rule is not a convention;
  the rule governs new work.

## Coding invariants
See [docs/coding-standards.md](../docs/coding-standards.md) — non-negotiable authority.

## Documentation invariants
See [docs/documentation-standards.md](../docs/documentation-standards.md) — non-negotiable
authority.

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
- On green: confirm the pass in one line, then run the pre-merge review
  before prompting for merge. The review is the saved `pr-review`
  workflow; this bullet is the maintainer's standing request to run it:
  `Workflow({name: "pr-review", args: {pr: <N>, mode: "full"}})` for the
  first run on a PR, then `mode: "delta"` with `since` set to the head
  the previous run reviewed. It shards the diff across parallel
  `@pr-reviewer` agents, adversarially verifies each Critical or Should
  finding and each MUST violation, runs `@pr-auditor` alongside, and
  returns one report with a reviewer verdict (`READY TO MERGE`,
  `BLOCKING ISSUES`, `NON-BLOCKING ISSUES ONLY`) and an audit verdict
  (`AUDIT PASS`, `AUDIT FAIL`). Save the report as
  `target/xtask/review/pr<N>/<mode>-<head>.md` and the returned
  findings, recorded, dropped, and audit fields as `<mode>-<head>.json`
  beside it, and surface both verdict lines to the user verbatim. If the
  Workflow tool is unavailable, invoke `@pr-reviewer` and `@pr-auditor`
  directly in parallel (single message, two `Agent` tool calls) with the
  PR number as scope and the open Issue list (`gh issue list --state
  open --json number,title`), and the same verdict handling.

  Findings on the review surface are fixed as one batch per run, whatever
  their severity, and findings off it are recorded in the same pass:
  reviewer findings on the surface via commits, reviewer findings off it
  via `gh issue edit` on the open Issue that already names the work, else
  on the audit Issue (or `gh issue create` with the user's approval), and
  `AUDIT FAIL` items via `gh pr edit`, `gh issue edit`, or commits. A
  finding the verifiers contested is put to the user. On the surface it
  resolves in the same PR as a fix, as a clarification of the rule it
  misread, or, when the user finds it false on the facts, as a
  clarification of the code or document it misread, so the next run reads
  what the user knows. Off the surface it is recorded, with the user's
  answer, on the Issue named above (the one that already names the work,
  else the audit Issue), or, when it misread a rule, resolved by the
  clarification of that rule alone, which is its record. Nothing else
  carries the decision forward. A finding no verifier could judge is
  treated as confirmed. No finding is waived, ruled, or exempted anywhere
  but in the standards themselves. A genuine deferral is an Issue filed
  with the user's approval, per "Completeness" below.

  After the fixes are pushed and CI is green again, run the workflow in
  `delta` mode. Prompt for the merge decision only when a run completes
  with no failed agent, `READY TO MERGE`, and `AUDIT PASS` (the reviewer
  verdict counts findings on the surface; recorded off-surface findings do
  not block). Merge via `gh pr merge <N> --merge --delete-branch`.
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
- Changes matching the trigger paths in
  [docs/testing.md](../docs/testing.md) "Coverage tiers" MUST additionally
  run the local host runs defined there.
- Host-side compilation, unit tests, and `cargo check` alone do not
  satisfy this requirement.
- A documentation-only or comment-only change, as
  [docs/testing.md](../docs/testing.md) "Coverage tiers" defines it,
  requires none of the runs above (the CI gate builds and boots both
  architectures); the pre-merge review still applies, and the PR body MUST
  state the validated head and the documentation-only delta.

## Completeness
- Drift or defects found on the review surface, as
  [docs/conventions.md](../docs/conventions.md) § Branch and PR Workflow
  defines it, MUST be fixed in the same pass; they are the scope, surfaced
  incidentally. Findings off the surface MUST be recorded in the same pass,
  never dropped: on the open Issue that already names the work, else on the
  open audit Issue (or a new one filed with the user's approval).
- "Out of scope", "follow-up", and similar deferrals MUST NOT be used to
  avoid mechanically reachable work on the surface.
- Material scope expansions MUST be stated in one line and continued, not
  paused for permission.
- Genuine deferrals (different review surface, or expansion too large to
  absorb) MUST be filed as GitHub Issues per
  [docs/conventions.md](../docs/conventions.md), with user approval,
  before the task closes.

## Conflicts
- If any instruction, plan, or change conflicts with documented invariants or these constraints,
  the assistant MUST stop and surface the conflict explicitly.
