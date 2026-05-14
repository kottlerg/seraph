# Project Conventions

Conventions for versioning, backlog tracking, commit messages, branch and PR workflow, CI gating, and release production.

---

## Versioning

Three independent versioning axes; each axis answers a different question and bumps on its own cadence.

### Project version (Seraph `X.Y.Z`)

The top-level identifier. Workspace-inherited Cargo crate version and git tag at every release point are three views of the same number.

- `X = 0` — pre-stable signal. Stays `0` until the system is judged stable enough for a 1.0 commitment.
- `Y` — milestone counter. Each bump corresponds to a named milestone with documented contents.
- `Z` — patches between milestones. Bumps only when there is value in tagging a specific known-good point between `Y` releases. Stays at `0` if no patches ship.

The workspace root `Cargo.toml` carries `[workspace.package] version = "X.Y.Z"`. Every workspace member declares `version.workspace = true` and inherits the project version.

A workspace member MAY declare its own independent `version = "..."` only when **all** of the following hold:

- The member has distinct identity as a user-facing program that would be recognized as a separate thing (shell, editor, network tool, package manager).
- The member evolves on its own cadence independent of the kernel-and-service cohort.
- The member would plausibly be packaged or shipped separately.

OS-internal services, kernel, bootloader, ABI crates, shared utility crates, `xtask`, and runtime shims do not qualify and MUST stay workspace-inherited. The opt-out is a one-time decision per member, recorded with a comment in that member's `Cargo.toml` naming the criterion that justifies it.

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

Each `Y` bump (`v0.1.0`, `v0.2.0`, …) has a GitHub milestone. Issues blocking a milestone MUST be assigned to it; everything else MUST stay unassigned.

### Commit and PR cross-references

- Commit messages MAY reference Issues by `#N` where useful.
- Once branch/PR workflow activates (below), PR descriptions MUST reference the Issue(s) they close via `Fixes #N` / `Closes #N` so merge auto-closes them.

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
- Reference Issues via `Fixes #N` / `Closes #N` to trigger auto-close on merge once PR workflow activates.

### Style

- No emojis.
- No tool or assistant attribution trailers.
- No `Co-authored-by` trailers unless the change was genuinely co-authored.

### Operations

- Commits MUST NOT skip pre-commit hooks (`--no-verify`). Hook failure indicates a real problem; fix the underlying issue and commit again.
- Existing commits MUST NOT be amended once pushed. Land a new commit instead.
- `master` MUST NOT receive force pushes.

## Branch and PR Workflow

### Before v0.1.0 tag

Direct commits to `master` are permitted. CI must stay green per commit.

### From v0.1.0 tag forward

- **Non-trivial work** MUST live on a feature branch and merge via PR. "Non-trivial" means: touches multiple components, or expects more than ~2 commits, or introduces a new subsystem.
- Trivial single-file fixes MAY land on `master` directly.
- PRs are self-reviewed; the file-by-file diff view, line comments, and CI status integration are the value.
- `master` MUST stay linearly green: every commit on `master` MUST be a passing CI state. Branches MAY have intermediate failures; merge is the green gate.
- PRs MUST reference the Issue(s) they close. CI MUST gate merge. Merge auto-closes the Issue(s).

### Branch naming

`feature/<slug>`, `fix/<slug>`, `cleanup/<slug>`, `audit/<slug>` — matching the Class labels above.

## CI Workflows

| Workflow file | Trigger | Purpose |
|---|---|---|
| `.github/workflows/build-test.yml` | push to `master`, PR to `master`, manual dispatch | Light validation: one `host-tests` job runs `cargo xtask test`; the matrix `validate` job builds each `arch × profile` cell, runs one usertest iteration against the default `boot.conf`, then swaps `boot.conf` to `init=ktest` and runs one ktest iteration. |
| `.github/workflows/burnin.yml` | tag push (`v*.*.*`), manual dispatch | Heavy validation: per `arch × profile` cell, builds and runs `4 × 20` usertest iterations against the default `boot.conf`, then swaps to ktest and runs `4 × 20` ktest iterations. |
| `.github/workflows/release.yml` | tag push (`v*.*.*`), manual dispatch | Builds release-profile disk images per architecture, compresses with zstd, generates `SHA256SUMS`, creates a draft GitHub Release whose body is `docs/releases/<tag>.md`. |

`build-test.yml` cancels stacked runs on the same ref (`cancel-in-progress: true`). `burnin.yml` and `release.yml` do not cancel on the same ref — a tag-push run completes even if a later tag pushes.

Local equivalents of the CI runs are documented in [build-system.md](build-system.md) and the `xtask` command surface lives in [`xtask/README.md`](../xtask/README.md).

## Release Production

See [docs/releases/README.md](releases/README.md) for per-tag release notes discipline. Each `Y` bump tag MUST have a corresponding `docs/releases/<tag>.md` file present at the tagged commit; `release.yml` aborts the publish step if the file is missing.

The maintainer publishes the draft Release manually after verifying the `burnin.yml` run for the same tag completed successfully.

---

## Summarized By

[README.md](../README.md)
