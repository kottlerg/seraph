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
  standing request to run it, each run preceded by `git fetch origin` (the
  auditor reads the PR's own diff against `origin/master` and does not
  fetch):
  `Workflow({name: "pr-review", args: {pr: <N>, mode: "full"}})` for the
  first run on a PR (a later full run adds `ledger` once one exists), then
  `mode: "delta"` with `since` set to the head the previous run reviewed
  and `ledger` set to the ledger file built below. The named workflow is
  the copy the session loaded at its start: when the script changed since,
  pass `scriptPath` with the file's path instead of `name`. The workflow's
  header comment describes what it does. Save the report as
  `target/xtask/review/pr<N>/<mode>-<head>.md` and the whole returned
  object as `<mode>-<head>.json` beside it (the ledger command below reads
  its `verdict`, `stats`, `findings`, `recorded`, and `dropped`), and
  surface both verdict lines to the user verbatim. If the
  Workflow tool is unavailable (the directly invoked agents are then the
  review, per that section), invoke `@pr-reviewer` and `@pr-auditor`
  directly in parallel (single message, two `Agent` tool calls) with the
  PR number as scope, the open Issue list (`gh issue list --state open
  --limit 500 --json number,title`), the ledger path once one exists, and,
  for a delta run, the `since` head and the merge bases at `since` and at
  the head (`git merge-base <sha> origin/master` for each); save the
  reviewer's findings
  (status `unverified`, since no refuter judged them, or `nit` for a nit
  that cannot block), the recorded and dropped ones, the ledger-flagged
  ones its `Ledger (not re-raised)` heading lists as `ledgered`, the
  `verdict`, and the head as `stats.head`, as `<mode>-<head>.json` in the
  workflow's shape, so the ledger command reads a fallback run too, and
  apply the same verdict handling.

  Before each run after the first (every `delta` run, and a `full` run
  once a record exists), build the ledger that section names from every
  saved run record of the PR:

  ```sh
  jq -s '[.[] | .stats.head[0:8] as $run
          | ((.recorded + .dropped
              + [.findings[] | select(.status == "contested")]
              + (if .verdict == "NON-BLOCKING ISSUES ONLY" then .findings else [] end))[]
             | {run: $run, file, line, class, bucket, must_violation, status, issue,
                claim, fix})]
         | unique' \
      target/xtask/review/pr<N>/*-*.json > target/xtask/review/pr<N>/ledger.json
  ```

  The surface findings of a `NON-BLOCKING ISSUES ONLY` run enter the ledger
  because the pass below records them after every such run, whatever its
  audit verdict and failed-agent list.

  Handle the run's findings as that section says, in one pass: fixes via
  commits; recorded findings via `gh issue edit` on the Issue the section
  names; after a `NON-BLOCKING ISSUES ONLY` run, the run's surface
  findings recorded the same way on the follow-up Issue of each finding's
  scope, as the section defines it: the Issue the PR drains in that scope
  when it drains one (the lowest-numbered when it drains several; its
  body carries `Refs #N` for each), else the scope's rolling Issue, found
  with `gh issue list --state open --limit 500 --search '"defects found
  by review" in:title' --json number,title` and, when the scope has none,
  filed with the user's approval as `gh issue create --milestone
  <current> --label <subsystem> --label <class>`, the current milestone
  being the one [docs/conventions.md](../docs/conventions.md) § Milestones
  defines and the labels the ones its § Labels requires. Before recording a
  finding, and after fixing one, search every open follow-up Issue of its
  scope, rolling and earlier-pattern (`gh issue list --state open --limit 500
  --search '"defects found by" in:title' --json number,title`, then the
  titles beginning `<scope>:`), for an item stating it: a finding one holds
  is recorded nowhere, and its fix ticks that item. A PR that fixes items on
  a follow-up Issue ticks each there with `(fixed by PR #<M>)`, copies those
  items, ticked, into its body's `## Acceptance`, and carries `Refs #N` in
  its body, and `Fixes #N` only under that section's closing condition.
  Before each run, an Issue the PR closes (by its body or a commit) whose
  milestone is missing or not the current one gets the current one (`gh issue
  edit <N> --milestone <current>`), which the audit checks. `AUDIT FAIL`
  items via `gh pr edit`, `gh issue edit`, or commits; a contested finding
  put to the user and resolved as the section says.
  Before pushing a fix, for every fact it changes (a symbol, a constant, a
  rule sentence, a state or section name) walk the `## Summarized By` lists
  ([docs/documentation-standards.md](../docs/documentation-standards.md)
  § Change propagation procedure owns that rule) and, as the assistant's
  mechanics, `git grep -n` the tracked tree for every other statement of
  it, and update each copy in the same push.

  After the fixes are pushed and CI is green again, run the workflow in
  `delta` mode. Prompt for the merge decision only under that section's
  merge-prompt condition; when a `NON-BLOCKING ISSUES ONLY` run meets it,
  offer one more fix round beside the merge. Merge via
  `gh pr merge <N> --merge --delete-branch` (per
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
- A change whose own diff makes a non-inert change to the CPU-count or
  memory surface [docs/testing.md](../docs/testing.md) "Coverage tiers"
  names, or whose PR states a concurrency-fix purpose as that section's
  Repeat count defines it, MUST additionally run the local host runs that section owes
  for it, at the heads and repeat counts it sets; any other change owes
  none, whatever directory it touches.
- Host-side compilation, unit tests, and `cargo check` alone do not
  satisfy this requirement.
- A documentation-only or comment-only change, as
  [docs/testing.md](../docs/testing.md) "Coverage tiers" defines it,
  requires none of the runs above (the CI gate builds and boots both
  architectures); the pre-merge review still applies, and the PR body MUST
  carry what [docs/conventions.md](../docs/conventions.md) § PR-body
  checklist discipline requires (the validated head, the documentation-only
  delta, and the local host-run report).
- `cargo xtask lint-docs` MUST pass on every change, documentation-only
  ones included (per [docs/conventions.md](../docs/conventions.md) § CI
  Gating; CI's `host-tests` job runs it, per
  [docs/build-system.md](../docs/build-system.md) § Continuous Integration).

## Completeness
- Findings on the review surface, as
  [docs/conventions.md](../docs/conventions.md) § Branch and PR Workflow
  defines it, are the scope, surfaced incidentally: blocking ones MUST be
  fixed in the same pass, and non-blocking ones MUST be fixed in that batch
  when the reviewer verdict is `BLOCKING ISSUES` and otherwise recorded as
  that section says. Findings off the surface MUST be recorded in the same
  pass, never dropped: on the open Issue that already names the work, else
  on the follow-up Issue of its scope that section defines (filed with the
  user's approval).
- "Out of scope", "follow-up", and similar deferrals MUST NOT be used to
  avoid mechanically reachable blocking work on the surface; a non-blocking
  surface finding is deferred only by recording it on the follow-up Issue
  of its scope as [docs/conventions.md](../docs/conventions.md) § Branch
  and PR Workflow allows.
- Material scope expansions MUST be stated in one line and continued, not
  paused for permission.
- Genuine deferrals (different review surface, or expansion too large to
  absorb) MUST be filed as GitHub Issues per
  [docs/conventions.md](../docs/conventions.md), with user approval,
  before the task closes.

## Conflicts
- If any instruction, plan, or change conflicts with documented invariants or these constraints,
  the assistant MUST stop and surface the conflict explicitly.
