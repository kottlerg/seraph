# Seraph — AI Project Context

@../README.md

## Authority
Per [docs/documentation-standards.md](../docs/documentation-standards.md) § Document Hierarchy:
- System-wide design and architectural invariants are defined exclusively in `docs/`.
- Each component’s `README.md` defines that component’s scope, role, and links to any authoritative
  design documents.
- Detailed behavior is defined only in component-specific `docs/` where present.

- `docs/coding-standards.md` governs all source code; all code changes MUST comply with its
  rules (per its preamble), and a suppression MUST be narrowly scoped and carry a rationale
  comment at the point of use (per [docs/coding-standards.md](../docs/coding-standards.md)
  § E. Exception Policy).
- `docs/documentation-standards.md` is the authoritative standard for all documentation; all
  documentation changes MUST comply with its rules (per its preamble).
- For the assistant: existing history or code that violates a written rule is not a
  convention; the rule governs new work.

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
- Documentation MUST be consumed in the order of the authoritative scopes
  [docs/documentation-standards.md](../docs/documentation-standards.md) § Document Hierarchy
  defines (grouping READMEs only index components; the root README routes to and may
  summarize the authoritative documents):
  1. System scope (`docs/`)
  2. Component scope (`<component>/README.md`)
  3. Design-authority scope (`<component>/docs/*.md`)
- Additional documentation MUST NOT be loaded unless required by the task.

## Tooling constraints
- All build, run, clean, and test actions MUST be performed via `cargo xtask` commands
  (per [docs/build-system.md](../docs/build-system.md) § Convenience Commands).
- Direct invocation of `cargo build`, `cargo run`, `cargo test`, or `cargo clippy` is forbidden
  (per [docs/build-system.md](../docs/build-system.md) § Workspace Structure and § Convenience
  Commands, and [docs/coding-standards.md](../docs/coding-standards.md) § Clippy).
- When switching architectures, `cargo xtask clean` MUST be run first
  (per [docs/build-system.md](../docs/build-system.md) § Build Output: the Sysroot).

## PR workflow operations
- All non-tag-driven work lands via a feature-branch PR per
  [docs/conventions.md](../docs/conventions.md); the assistant MUST NOT push directly
  to `master`.
- After pushing a PR, the assistant MUST start watching its CI run via
  `gh pr checks <N> --watch` (or `gh run watch <run-id>`) as a backgrounded
  `Bash` invocation (`run_in_background: true`). Do not poll, do not sleep —
  the harness notifies on completion.
- On green: confirm the pass in one line, then run the pre-merge review
  before prompting for merge. The gate, the review surface, the two
  tracks, the recording of findings, and the merge-prompt condition are
  owned by [docs/conventions.md](../docs/conventions.md) § Branch and PR
  Workflow; this section gives only the assistant's mechanics. The review
  is the saved `pr-review` workflow; this bullet is the maintainer's
  standing request to run it:
  `Workflow({name: "pr-review", args: {pr: <N>, mode: "full"}})` for the
  first run on a PR, then `mode: "delta"` with `since` set to the head
  the previous run reviewed and `ledger` set to the ledger file built
  below. The workflow's header comment describes what it does. Save the
  report as `target/xtask/review/pr<N>/<mode>-<head>.md` and the whole
  returned object as `<mode>-<head>.json` beside it (the ledger command
  below reads its `verdict`, `stats`, `findings`, `recorded`, and
  `dropped`), and surface both verdict lines to the user verbatim. If the Workflow tool is
  unavailable (the directly invoked agents are then the review, per that
  section), invoke `@pr-reviewer` and
  `@pr-auditor` directly in parallel (single message, two `Agent` tool
  calls) with the PR number as scope, the open Issue list (`gh issue list
  --state open --limit 500 --json number,title`), and, for a re-review,
  the `since` head and the ledger path, and apply the same verdict
  handling.

  Before each `delta` run, build the ledger that section names from every
  saved run record of the PR:

  ```sh
  jq -s '[.[] | .stats.head[0:8] as $run
          | ((.recorded + .dropped
              + [.findings[] | select(.status == "contested")]
              + (if .verdict == "NON-BLOCKING ISSUES ONLY" then .findings else [] end))[]
             | {run: $run, file, line, class, bucket, must_violation, status, issue,
                claim, fix})]
         | unique_by([.run, .file, .line, .class, .bucket, .must_violation])' \
      target/xtask/review/pr<N>/*-*.json > target/xtask/review/pr<N>/ledger.json
  ```

  The surface findings of a `NON-BLOCKING ISSUES ONLY` run enter the ledger
  because the pass below records them after every such run, whatever its
  audit verdict and failed-agent list.

  Handle the run's findings as that section says, in one pass: fixes via
  commits; recorded findings via `gh issue edit` on the Issue the section
  names, or `gh issue create` with the user's approval; after a
  `NON-BLOCKING ISSUES ONLY` run, the run's surface findings recorded the
  same way on the follow-up Issues the section defines; `AUDIT FAIL`
  items via `gh pr edit`, `gh issue edit`, or commits; a contested
  finding put to the user and resolved as the section says. Before
  pushing a fix, for every fact it changes (a symbol, a constant, a rule
  sentence, a state or section name) walk the `## Summarized By` lists
  ([docs/documentation-standards.md](../docs/documentation-standards.md)
  § Change propagation procedure owns that rule) and, as the assistant's
  mechanics, `git grep -n` the tracked tree for every other statement of
  it, and update each copy in the same push.

  After the fixes are pushed and CI is green again, run the workflow in
  `delta` mode. Prompt for the merge decision only under that section's
  merge-prompt condition; when a `NON-BLOCKING ISSUES ONLY` run meets it,
  offer one more fix round beside the merge. Merge
  via `gh pr merge <N> --merge --delete-branch` (per
  [docs/conventions.md](../docs/conventions.md) § Merge method).
- On red: surface the failing job's tail (`gh run view <run-id> --log-failed`
  or equivalent) so the user can see the actual error without asking.
- The assistant MUST NOT merge a PR while its CI run is pending or failing (CI gates
  merge, per [docs/conventions.md](../docs/conventions.md) § Branch and PR Workflow).
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
- `cargo xtask lint-docs` MUST pass on every change, documentation-only
  ones included (per [docs/conventions.md](../docs/conventions.md) § CI
  Gating; CI's `host-tests` job runs it, per
  [docs/build-system.md](../docs/build-system.md) § Continuous Integration).

## Completeness
- Findings on the review surface, as
  [docs/conventions.md](../docs/conventions.md) § Branch and PR Workflow
  defines it, are the scope, surfaced incidentally: blocking ones MUST be
  fixed in the same pass, and non-blocking ones MUST be fixed in that batch
  or recorded as that section says. Findings off the surface MUST be
  recorded in the same pass, never dropped: on the open Issue that already
  names the work, else on the PR's follow-up Issue that section defines
  (filed with the user's approval).
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
