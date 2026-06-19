# Project Conventions

Conventions for versioning, backlog tracking, commit messages, branch and PR workflow, CI gating, and release production.

---

## Versioning

Three independent versioning axes; each axis answers a different question and bumps on its own cadence.

### Project version (Seraph `X.Y.Z`)

The top-level identifier. Workspace-inherited Cargo crate version and git tag at every release point are three views of the same number.

- `X = 0` — pre-stable notification. Stays `0` until the system is judged stable enough for a 1.0 commitment.
- `Y` — milestone counter. Each bump corresponds to a named milestone with documented contents.
- `Z` — patches between milestones. Bumps only when there is value in tagging a specific known-good point between `Y` releases. Stays at `0` if no patches ship.

The workspace root `Cargo.toml` carries `[workspace.package] version = "X.Y.Z"`. Every workspace member declares `version.workspace = true` and inherits the project version.

A workspace member MAY declare its own independent `version = "..."` only when **both** of the following hold:

- The member has distinct identity as a user-facing program that would be recognized as a separate thing (shell, terminal, editor, network tool, package manager) — not a demo, benchmark, or test fixture.
- The member is not core to the OS: the system boots and runs without it. It is the kind of component that could plausibly be optional, swapped for an alternative, or distributed separately — now or in the far future — even if today it is tightly interconnected with the rest of the tree and still primitive.

OS-internal services, kernel, bootloader, ABI crates, shared utility crates, `xtask`, runtime shims, and the demo/benchmark/test programs do not qualify and MUST stay workspace-inherited. The opt-out is a one-time decision per member, recorded with a comment in that member's `Cargo.toml` naming the criterion that justifies it.

An opted-out member's version is independent of the project version and MAY sit below it — a still-primitive `terminal` and `shell` at `0.0.1` while the project is at `0.1.0` is expected, not an error.

The opt-out covers the program's whole subtree: any internal library extracted from the program (for testability or structure) and the program's own test harness carry the **same** explicit version as the program and bump in lockstep with it. They are not independent version axes. Cargo cannot enforce this lockstep across separate manifests, so it is maintained by hand and noted in each child's `Cargo.toml`.

### ABI / wire-protocol versions

Hand-maintained integer constants inside ABI crates, read at runtime to gate compatibility.

- Constants live inside the ABI crate that owns the protocol (e.g., `BOOT_PROTOCOL_VERSION`, `PROCESS_ABI_VERSION`, `INIT_PROTOCOL_VERSION`, plus per-namespace `<NAMESPACE>_LABELS_VERSION`).
- One protocol = one version constant. Every breaking change to that protocol MUST bump its constant.
- ABI protocol versions are independent of the project version and of Cargo crate versions.

### Cargo crate versions

For workspace-inherited crates (the default), crate metadata version moves in lockstep with the project version. For opt-out crates (see above), the crate's `Cargo.toml` `version = "..."` is the source of truth and bumps on its own cadence.

## Backlog Tracking

Open Issues on GitHub are the canonical record of outstanding work. The repo URL is the authoritative listing surface.

### Labels

Every Issue MUST carry at least one **Subsystem** label and at least one **Class** label.

- **Subsystem labels** name a workspace component or area: one label per kernel/service/driver/ABI crate/shared crate/tooling area. The canonical set is whatever `gh label list` returns; new components add their own label when filed.
- **Class labels** name the work's nature:
  - `bug` — Defect against current code with a reproducer or clear failure mode.
  - `design` — Open question with no decided answer yet.
  - `cleanup` — Refactor, dead-code removal, audit-finding fix, structural realignment.
  - `feature` — Decided new functionality that needs building.
  - `perf` — Performance gap with a measurable target.
  - `security` — Vulnerability, hardening, or threat-model concern.
  - `infra` — CI, build, tooling, xtask, harness; non-shipping.

### Milestones

Each `Y` bump (`v0.1.0`, `v0.2.0`, …) and each shipped `Z` patch (`v0.1.1`, …) has a GitHub milestone. Issues blocking a milestone MUST be assigned to it; everything else MUST stay unassigned.

### Commit and PR cross-references

- Commit messages MAY reference Issues by `#N` where useful.
- Any commit (or PR description, when merging via PR) that closes an Issue MUST reference it via `Fixes #N` / `Closes #N` in the message so the push (or merge) auto-closes the Issue. Manual `gh issue close` after the fact is a procedural miss, not a substitute.

### Acceptance checklist discipline

- Issue bodies SHOULD list acceptance criteria under `## Acceptance` as GitHub task-list checkboxes (`- [ ]`).
- Before closing an Issue (or merging the PR that auto-closes it), every `- [ ]` under `## Acceptance` MUST be flipped to `- [x]`. An unticked box at close indicates either incomplete work or stale criteria; one of the two MUST be reconciled — finish the work, or edit the Issue to drop the obsolete criterion with a one-line rationale in the closing comment.
- Updating the Issue body is `gh issue edit <N> --body "$(cat <<'EOF' …EOF)"` or the web UI. PRs that close Issues SHOULD include the tick-through edit in the same merge action — the closing comment on the Issue MAY also confirm "all acceptance criteria met".
- This rule retro-applies: existing closed Issues with unticked boxes MAY be left alone, but no new Issue MAY close with unticked acceptance criteria.

### Historical naming

The identifier `usertest` formerly named the services-tier integration test
harness, which lived at `base/usertest/`. The `base/`→`programs/` and
`usertest`→`svctest` rename relocated that harness to `services/svctest/`
(log prefix `[svctest]`), freeing the `usertest` name. The reclaimed name now
identifies the programs-surface orchestrator at `services/usertest/` (log
prefix `[usertest]`) — see [testing.md](testing.md) for the current
tier taxonomy and conventions. References to `usertest` predating the rename
(commit messages, PR descriptions, closed Issues) refer to the historical
services-tier harness, not the current programs-surface one; open Issues
were swept to use `svctest` where they meant the services-tier harness.

## Commit Messages

### Title

- One line, SHOULD be ≤ 72 characters.
- Form: `<scope>: <summary>`.
- `<scope>` names what the commit touches: a component path (`kernel`, `xtask`, `services/init`), a directory (`docs`, `.github`), a workspace-wide topic (`treewide`), or comma-separated combinations (`ci, xtask`; `docs, claude`). Use the narrowest scope that covers the change.
- `<summary>` describes what changed and MAY use `;` to delimit independent sub-changes within one commit.
- `<summary>` MUST NOT contain planning labels (per [documentation-standards.md](documentation-standards.md) §"Incomplete Work Markers"): no "step X", "phase Y", "tier N", "stage M", "the deferred follow-up". Components and concrete what-changed text only.
- `<summary>` MUST NOT include task IDs, branch names, or other transient identifiers. Issue references belong in the body.

### Body

- Optional for trivial changes (typo fixes, single-line tweaks).
- Expected for substantive changes: explain the why, not the what (the diff shows the what).
- Wrap at ~72 columns.
- A commit (or its enclosing PR description) that closes an Issue MUST include `Fixes #N` / `Closes #N` so the merge auto-closes the Issue. Closing manually after the fact is a procedural miss, not a substitute.

### Style

- No emojis.
- No tool or assistant attribution trailers.
- No `Co-authored-by` trailers unless the change was genuinely co-authored.

### Operations

- Commits MUST NOT skip pre-commit hooks (`--no-verify`). Hook failure indicates a real problem; fix the underlying issue and commit again.
- Commits on `master` are immutable: no amend, no rewrite, no force push.
- On feature branches before merge, amending and force-pushing your own branch is fine and often preferable to a "fix typo" commit. The merge into `master` is the linear-green commit that lands.

## Branch and PR Workflow

All work — including single-line fixes and documentation changes — flows
through a short-lived feature branch and a PR. Direct commits to `master`
are forbidden; `master` MUST NOT receive force pushes.

- PRs are self-reviewed; the file-by-file diff view, line comments, and CI
  status integration are the value.
- CI MUST gate merge. `master` MUST stay linearly green: every commit on
  `master` is a passing CI state. Branches MAY have intermediate failures;
  merge is the green gate.
- PRs that close an Issue MUST carry `Fixes #N` / `Closes #N` in the PR
  description so merge auto-closes the Issue. The acceptance-checklist
  tick-through (see above) lands in the same merge action.

### Branch naming

`feature/<slug>`, `fix/<slug>`, `cleanup/<slug>`, `audit/<slug>` — matching the Class labels above.

### Merge method

`master` accepts merge commits only; rebase and squash merge are disabled
at the repo level. Merge via the GitHub web UI ("Create a merge commit")
or `gh pr merge <N> --merge --delete-branch`. `git log --first-parent master`
gives the PR-level linear view.

### Branch protection

`master` is protected by a GitHub branch protection rule enforcing:

- Pull request required before merging.
- Required status checks (strict, branch up-to-date): `host-tests`,
  `validate (x86_64, debug, ktest)`, `validate (x86_64, debug, svctest)`,
  `validate (x86_64, debug, usertest)`, `validate (x86_64, release, ktest)`,
  `validate (x86_64, release, svctest)`, `validate (x86_64, release, usertest)`,
  `validate (riscv64, debug, ktest)`, `validate (riscv64, debug, svctest)`,
  `validate (riscv64, debug, usertest)`, `validate (riscv64, release, ktest)`,
  `validate (riscv64, release, svctest)`, `validate (riscv64, release, usertest)`.
- Required signed commits.
- Force pushes blocked.
- Branch deletion blocked.
- Rules enforced for administrators.

### PR-body checklist discipline

- PRs are opened from `.github/pull_request_template.md`.
- Before merge, every `- [ ]` in the PR body MUST be `- [x]` or removed
  with a one-line rationale in the same edit. Same shape as the Issue
  acceptance rule under "Backlog Tracking" above.
- Edit via `gh pr edit <N> --body "$(cat <<'EOF' …EOF)"` or the web UI.

## CI Gating

CI status checks MUST pass before merge. The authoritative workflow
inventory and per-workflow shape live in
[build-system.md](build-system.md#continuous-integration); local
equivalents are the `cargo xtask` commands documented there.

## Release Production

See [docs/releases/README.md](releases/README.md) for per-tag release notes discipline.

Producing a release for tag `v<X>.<Y>.<Z>`:

1. Bump `[workspace.package] version` in the root `Cargo.toml` to `<X>.<Y>.<Z>`.
2. Copy `docs/releases/TEMPLATE.md` to `docs/releases/v<X>.<Y>.<Z>.md` and fill
   every section.
3. Land both changes on `master` through the normal PR workflow. The tag MUST
   point at a commit that contains them.
4. Tag that commit and push the tag:
   `git tag v<X>.<Y>.<Z> && git push origin v<X>.<Y>.<Z>`.
5. The tag push triggers `release.yml` and `burnin.yml`. The `preflight` job in
   `release.yml` aborts the run before any image is built if the workspace
   version does not match the tag or the notes file is missing or does not
   follow `TEMPLATE.md`'s structure.
6. The maintainer publishes the draft Release manually after verifying the
   `burnin.yml` run for the same tag completed successfully.

---

## Summarized By

[README.md](../README.md)
