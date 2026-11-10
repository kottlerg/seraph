# Project Conventions

Conventions for versioning, backlog tracking, commit messages, branch and PR workflow, CI gating,
and release production.

---

## Versioning

Three independent versioning axes; each axis answers a different question and bumps on its own
cadence.

### Project version (Seraph `X.Y.Z`)

The top-level identifier. Workspace-inherited Cargo crate version and git tag at every release point
are three views of the same number.

- `X = 0` — pre-stable notification. Stays `0` until the system is judged stable enough for a 1.0
  commitment.
- `Y` — milestone counter. Each bump corresponds to a named milestone with documented contents.
- `Z` — patches between milestones. Bumps only when there is value in tagging a specific known-good
  point between `Y` releases. Stays at `0` if no patches ship.

The workspace root `Cargo.toml` carries `[workspace.package] version = "X.Y.Z"`. Every workspace
member declares `version.workspace = true` and inherits the project version.

A workspace member MAY declare its own independent `version = "..."` only when **both** of the
following hold:

- The member has distinct identity as a user-facing program that would be recognized as a separate
  thing (shell, terminal, editor, network tool, package manager) — not a demo, benchmark, or test
  fixture.
- The member is not core to the OS: the system boots and runs without it. It is the kind of
  component that could plausibly be optional, swapped for an alternative, or distributed separately
  — now or in the far future — even if today it is tightly interconnected with the rest of the tree
  and still primitive.

OS-internal services, kernel, bootloader, ABI crates, shared utility crates, `xtask`, runtime shims,
and the demo/benchmark/test programs do not qualify and MUST stay workspace-inherited. The opt-out
is a one-time decision per member, recorded with a comment in that member's `Cargo.toml` naming the
criterion that justifies it.

An opted-out member's version is independent of the project version and MAY sit below it — a
still-primitive `terminal` and `shell` at `0.0.1` below the project's `0.Y.Z` is expected, not an
error.

The opt-out covers the program's whole subtree: any internal library extracted from the program (for
testability or structure) and the program's own test harness carry the **same** explicit version as
the program and bump in lockstep with it. They are not independent version axes. Cargo cannot
enforce this lockstep across separate manifests, so it is maintained by hand and noted in each
child's `Cargo.toml`.

### ABI / wire-protocol versions

Hand-maintained integer constants that version cross-boundary protocols; where a protocol has a
handshake or handover point, the constant is checked there at runtime to gate compatibility.

- Constants live inside the crate that owns the protocol: the ABI crates for
  `BOOT_PROTOCOL_VERSION`, `PROCESS_ABI_VERSION`, and `INIT_PROTOCOL_VERSION`, and `shared/ipc` for
  the per-namespace `<NAMESPACE>_LABELS_VERSION` constants.
- One protocol = one version constant. Every breaking change to that protocol MUST bump its
  constant.
- ABI protocol versions are independent of the project version and of Cargo crate versions.

### Cargo crate versions

For workspace-inherited crates (the default), crate metadata version moves in lockstep with the
project version. For opt-out crates (see above), the crate's `Cargo.toml` `version = "..."` is the
source of truth and bumps on its own cadence.

## Backlog Tracking

Open Issues on GitHub are the canonical record of outstanding work. The repo URL is the
authoritative listing surface.

### Labels

Every Issue MUST carry at least one **Subsystem** label and at least one **Class** label.

- **Subsystem labels** name a workspace component or area: one label per kernel/service/driver/ABI
  crate/shared crate/tooling area. The canonical set is whatever `gh label list` returns; new
  components add their own label when filed.
- **Class labels** name the work's nature:
  - `bug` — Defect against current code with a reproducer or clear failure mode.
  - `design` — Open question with no decided answer yet.
  - `cleanup` — Refactor, dead-code removal, audit-finding fix, structural realignment.
  - `feature` — Decided new functionality that needs building.
  - `perf` — Performance gap with a measurable target.
  - `security` — Vulnerability, hardening, or threat-model concern.
  - `infra` — CI, build, tooling, xtask, harness; non-shipping.

### Milestones

Each `Y` bump (`v0.1.0`, `v0.2.0`, …) and each `Z` patch (`v0.1.1`, …), shipped or planned, has a
GitHub milestone. The current milestone is the lowest-versioned open one. An Issue a release will
absorb (a defect, a cleanup, scheduled work of any class) MUST carry a milestone from creation:
the current milestone, or the later release it is planned for. A follow-up Issue the pre-merge
review files (§ Follow-up Issues) MUST carry the current milestone: it records findings on work
the current release contains, and step 8 of § Release Production moves it on when the release
closes. Only future-state work no release has scheduled (a design umbrella, an unscheduled
feature) MAY stay unassigned; it is assigned when it is scheduled. The rule applies to open Issues
filed before it: the maintainer assigns each a milestone or confirms it as unscheduled work. An
Issue that closes without a milestone, or under one other than the current milestone, MUST be
assigned the current milestone when it closes; step 8 of § Release Production decides the release
a closed Issue settles on. A pull request MUST NOT carry a milestone; milestones are assigned to
Issues only.

### Commit and PR cross-references

- Commit messages MAY reference Issues by `#N` where useful.
- A commit or PR description that changes an Issue without closing it (ticking items on a
  follow-up Issue it drains in part) MUST reference it via `Refs #N`, which auto-closes nothing.
- A PR that closes an Issue MUST reference it via `Fixes #N` / `Closes #N` in its description, so
  the merge auto-closes the Issue. Manual `gh issue close` after the fact is a procedural miss,
  not a substitute.
- A GitHub closing keyword (`close`, `closes`, `closed`, `fix`, `fixes`, `fixed`, `resolve`,
  `resolves`, or `resolved`, in any letter case) directly before a reference to Issue N (`#N`,
  `<owner>/<repo>#N`, or the Issue's URL), with at most a colon and whitespace between them, MUST
  appear only in the description of a PR that closes Issue N, and MUST NOT appear in a commit
  message. GitHub closes the Issue when that text reaches `master`, whatever words follow the
  reference; an Issue closes by a PR's merge, since no commit reaches `master` without a PR; and
  a keyword in a commit cannot be withdrawn without rewriting the commit. Other forms of those
  verbs (`closing`, `fixing`, `resolving`) are not closing keywords. A keyword separated from the
  reference by other words, as in the `(fixed by PR #M)` marker of § Branch and PR Workflow, is
  not a closing reference.

### Acceptance checklist discipline

- Issue bodies SHOULD list acceptance criteria under `## Acceptance` as GitHub task-list checkboxes
  (`- [ ]`).
- Before closing an Issue (or merging the PR that auto-closes it), every `- [ ]` under
  `## Acceptance` MUST be flipped to `- [x]`. An unticked box at close indicates either incomplete
  work or stale criteria; one of the two MUST be reconciled — finish the work, or edit the Issue to
  drop the obsolete criterion with a one-line rationale in the closing comment.
- Updating the Issue body is `gh issue edit <N> --body "$(cat <<'EOF' …EOF)"` or the web UI. PRs
  that close Issues SHOULD include the tick-through edit in the same merge action — the closing
  comment on the Issue MAY also confirm "all acceptance criteria met".
- This rule retro-applies: existing closed Issues with unticked boxes MAY be left alone, but no new
  Issue MAY close with unticked acceptance criteria.

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

A departure from a SHOULD rule of this section is accepted when the PR body records the
maintainer's acceptance of it, as a statement of that decision.

### Title

- One line, SHOULD be ≤ 72 characters.
- Form: `<scope>: <summary>`.
- `<scope>` names what the commit touches: a component path (`kernel`, `xtask`, `services/init`), a
  directory (`docs`, `.github`), a workspace-wide topic (`treewide`), or comma-separated
  combinations (`ci, xtask`; `docs, claude`). Use the narrowest scope that covers the change.
- `<summary>` describes what changed and MAY use `;` to delimit independent sub-changes within one
  commit.
- `<summary>` MUST NOT contain planning labels as
  [documentation-standards.md](documentation-standards.md) § Incomplete Work Markers defines
  them. Components and concrete what-changed text only.
- `<summary>` MUST NOT include Issue references, task IDs, branch names, or other transient
  identifiers. Issue references belong in the body.
- A merge commit is exempt from the Title rules: git's default subject for a merge of the base
  branch into a feature branch and GitHub's PR-merge subject both name branches, and GitHub's also
  carries the PR number.

### Body

- Optional for trivial changes (typo fixes, single-line tweaks).
- Expected for substantive changes: explain the why, not the what (the diff shows the what).
- SHOULD wrap at ~72 columns.
- A body MUST NOT carry a closing keyword; the PR description closes an Issue
  (§ Commit and PR cross-references). `Refs #N` names an Issue the commit touches.

### Style

- No emojis.
- No tool or assistant attribution, in a commit message or a PR description: no attribution
  trailer and no link to an assistant session.
- No `Co-authored-by` trailers unless the change was genuinely co-authored.
- No quotation of the maintainer. [documentation-standards.md](documentation-standards.md)
  § Tone and Language owns the rule for permanent text, commit messages included: a decision of
  the maintainer is stated as a decision, in the project's own words, and what the maintainer
  wrote in a working session is not quoted. A PR description, an Issue, and a comment on
  either MUST follow the same rule.

### Operations

- Commits MUST NOT skip pre-commit hooks (`--no-verify`). Hook failure indicates a real problem; fix
  the underlying issue and commit again.
- Commits on `master` are immutable: no amend, no rewrite, no force push.
- On feature branches before merge, amending and force-pushing your own branch is fine and often
  preferable to a "fix typo" commit. The merge into `master` is the linear-green commit that lands.

## Branch and PR Workflow

All work — including single-line fixes and documentation changes — flows
through a short-lived feature branch and a PR. Direct commits to `master`
are forbidden; `master` MUST NOT receive force pushes.

- PRs have no second human reviewer; the file-by-file diff view, line
  comments, and CI status integration are the value, and the pre-merge
  review (§ Pre-merge review) gates the merge alongside CI.
- CI MUST gate merge. `master` MUST stay linearly green: every commit on
  `master` is a passing CI state. Branches MAY have intermediate failures;
  merge is the green gate.
- PRs that close an Issue MUST carry `Fixes #N` / `Closes #N` in the PR
  description so merge auto-closes the Issue. The acceptance-checklist
  tick-through (§ Acceptance checklist discipline) lands in the same merge
  action.

### Pre-merge review

Merge is gated by the pre-merge review: the `pr-reviewer` and `pr-auditor` agents
(`.claude/agents/`), invoked directly and in parallel, run the adversarial code review and the
closure audit, and their prose verdict lines are the gate. Findings are handled as one batch per
run, as the subsections below define. `.claude/skills/pr-review/SKILL.md` gives the
assistant's procedure.

A run MAY be made with the reviewer alone while the PR body's `## Validation` section reports
a build, a boot, or an owed local host run as pending, since an audit of that head would fail
on that report alone. Its record is a `full` or `delta` record that states the audit as not
run (`audit_verdict` `NOT RUN`, `audit` `null`). The audit that run leaves owed is made once
the runs are reported: with the next run when a fix round has moved the head, and otherwise
alone at the same head, as an `audit` record there that completes the run.

The reviewer verdict is:

- `BLOCKING ISSUES` when a blocking finding is on the review surface or a reviewer returned no
  result;
- `NON-BLOCKING ISSUES ONLY` when only non-blocking findings are on it;
- `READY TO MERGE` when none is.

A PR meets the merge condition when its CI is green, its head contains `master`, and the last
run at its head is a completed run (one with the reviewer and the auditor, a run of the
reviewer alone that its audit has completed, or the auditor-only run of § Auditor-only run)
with no failed agent and `AUDIT PASS`, whose reviewer verdict is one of:

- `READY TO MERGE`;
- `NON-BLOCKING ISSUES ONLY`, once every finding the run leaves on the surface is recorded
  (§ Recording findings) and no contested finding on the surface is unresolved. The findings
  of such a run MAY take one fix round before the merge. A PR takes at most one such round:
  what the run after it leaves on the surface is recorded, and no further round is taken for
  it.

A PR MUST NOT merge before it meets the merge condition, and a PR that meets it merges without
a further decision. `cargo xtask pr-check <N> --gate` checks the part of the condition a
script can decide and names the rest for its reader. In an orchestrated batch the orchestrator
merges such a PR; a session working alone with the maintainer reports that the PR meets the
condition and merges on the maintainer's instruction. Two things stay the maintainer's
whatever the gate says: a change to `.claude/CLAUDE.md`, to the assistant's settings, or to
its hooks is applied only on the maintainer's own word, and the release steps of § Release
Production are the maintainer's.

Every finding a run counts is fixed or recorded as the subsections below say. A finding MUST NOT
be waived or ruled outside the standards.

### Contested findings

A finding the PR's author disputes, on the facts or on the rule it cites, is contested. It MUST
NOT be waived, and it is decided, not left open:

- In an orchestrated batch the orchestrator decides it. Before deciding, it has the reviewer
  re-read the finding against the author's argument in one delta run, since the author and the
  orchestrator both want the PR merged and the reviewer does not; the re-read informs the
  decision, which stays the orchestrator's.
- It is put to the maintainer when it turns on a design question no document settles, when
  resolving it would materially expand the PR's scope, when the author and the orchestrator
  disagree, and always in a session working alone with the maintainer.

The decision resolves the finding:

- On the surface it MUST resolve in the same PR: as a fix; as a clarification of the rule it
  misread; or, when it is found false on the facts, as a clarification of the code or document
  it misread.
- Off the surface it is recorded, with the decision, on the Issue that records it
  (§ Recording findings); or, when it misread a rule, it is resolved by the clarification of
  that rule alone, which is its record.

### Auditor-only run

A fix round MAY be followed by an auditor-only run, the closure audit alone, when both hold:

- the last run with the reviewer completed with no failed agent;
- the round's delta (from the head that run reviewed to the new head) is documentation or
  comments only, as [testing.md](testing.md#coverage-tiers) § Coverage tiers defines it, apart
  from the incoming diff of a sync that owes no run with the reviewer (§ Syncing with
  `master`).

The audit checks the PR body's claims, the recording of findings, the validated head, and the
closing conditions at the new head. Since no code read covers a changed comment or document in
that run, it owes a contract-drift check: every comment or document statement the PR's own
change in the delta alters is compared against the code it describes, and one the code
contradicts is a FAIL. It reads that
last run's record, confirms that the delta delivers each fix the round claims, and fails a
finding that run left on the surface that is neither fixed by the delta nor recorded
(§ Recording findings).

The audit states the reviewer verdict: that of the last run with the reviewer, read with the
delta's fixes. It is `READY TO MERGE` when the delta fixes every finding that run left on the
surface, `NON-BLOCKING ISSUES ONLY` when every finding it leaves there is non-blocking and
recorded, and `BLOCKING ISSUES` otherwise.

Any later delta that changes anything but documentation or comments, or that holds a sync
owing a run with the reviewer, takes a run with the reviewer.

### Syncing with `master`

A PR's head MUST contain `master` when it merges (§ Branch protection). A sync is a merge of
`master` into the PR's branch, and its incoming diff is what that merge brings in: the diff
from the PR's merge base with `master` before the sync to its merge base after it.

- Every sync owes a passing CI run on the synced head, which builds and boots both
  architectures there.
- A sync whose incoming diff touches a file the PR's own diff touches, or whose merge resolves
  a conflict, also owes the PR's own validation again at the synced head (the builds and boots
  its `## Test plan` reports) and a run with the reviewer over the sync.
- Any other sync owes nothing more. The validated head before it stands, and the PR body's
  `## Validation` section states that the incoming diff touches none of the PR's files.

The local host runs of [testing.md](testing.md#coverage-tiers) § Coverage tiers keep their own
rule (When the runs are owed): a sync that leaves the PR's own changes to a run's surface as
they were owes no such run again.

### Review surface

The review surface of a change is what it touches:

- the changed hunks and the items that contain them (a function, a paragraph, a section, a table
  row, a list; for a hunk inside a file header, the header block of license, path, and
  description);
- everything the change introduces;
- the callers and reverse dependencies of what it changes;
- a correctness, soundness, safety, or contract defect anywhere in a touched file, unless an
  open Issue already names it.

In a re-review of a PR (a delta run), a standards, documentation-drift, coverage, or style
finding is on the surface only when the delta or the PR's own earlier commits introduced it,
wherever it anchors: a statement the delta made stale, a test the delta's new code lacks, or a
finding in a hunk an earlier commit of the PR introduced is one the PR introduced. Correctness,
soundness, safety, and contract findings stay on the surface as above.

Work an open Issue already names, filed with the maintainer's approval, is off the surface of
every other PR; a finding on it is recorded against that Issue. A follow-up Issue
(§ Follow-up Issues) names findings, not work: it takes nothing off any PR's surface, so a
finding it holds is, unless the ledger lists it (§ Ledger), reported, counted, and fixed or
recorded wherever this definition puts it.

### Tracks

A finding on the surface is on one of two tracks.

- **Blocking:** a finding of class correctness, safety (which covers soundness), or contract,
  wherever it anchors; or a MUST violation of a binding standard, of whatever class, anchored in
  a file that is not a Markdown document. A blocking finding on the surface MUST be fixed before
  merge.
- **Non-blocking:** every other finding on the surface, that is, one of class standards,
  documentation-drift, coverage, or style that is not a MUST violation or is one anchored in a
  Markdown document (wording, wrapping, nits). When the reviewer verdict is `BLOCKING ISSUES` it
  is fixed in the same batch; after a `NON-BLOCKING ISSUES ONLY` run it MUST be recorded
  (§ Recording findings) before the merge.

A document statement the code contradicts is a contract or safety defect when it states
behaviour a caller or user relies on (a syscall, ABI, IPC, or command-line contract, or a safety
invariant). Every other disagreement between a document and the code (a stale name, count, path,
or cross-reference, or a summary out of step with its owner) is documentation drift.

A finding off the surface MUST be recorded, not fixed: the pre-merge review reports it as out of
bound, and it is recorded (§ Recording findings) before the merge. No finding is dropped
for being off the surface.

### Follow-up Issues

The follow-up Issue of a scope is the one open Issue whose title is
`<scope>: defects found by review`, where `<scope>` is a commit-title scope (§ Commit Messages),
the narrowest that covers the file. Every PR's findings in that scope append to it, and so it is
also called the rolling Issue. It is filed only when the scope has none open, with the current
milestone (§ Milestones) and the labels § Labels requires. Filing it needs no approval of its
own: the maintainer's standing approval covers the rolling Issue of a scope that has none.

An open Issue whose title begins `<scope>: defects found by PR #N's review`, filed before the
rolling Issues, is a follow-up Issue under every rule of this section; a finding recorded in its
scope goes to the rolling Issue unless the recording PR drains it.

A follow-up Issue is drained in batch, by a PR that changes its scope for another reason or by a
sweep PR that drains several scopes' Issues; no merge requires a drain. A PR that fixes recorded
items:

- ticks each on the Issue in the same push, appending `(fixed by PR #M)` with its own number;
- copies those items, ticked, into its own `## Acceptance` section;
- MUST reference the Issue with `Refs #N`;
- closes an Issue of the earlier pattern (`<scope>: defects found by PR #N's review`) only when
  no item is left open once the findings of its last run are recorded, and then carries
  `Fixes #N` beside the `Refs #N`;
- MUST NOT close a rolling Issue. The rolling Issue is the one recording sink of its scope for
  the milestone, so that a scope has one such Issue per milestone and not one per PR. It is
  closed at step 8 of § Release Production when every item is ticked, and otherwise moves to
  the next milestone with its open items.

A drain PR MUST NOT file a successor: a finding its run leaves in the same scope is appended to
the Issue it drains, which stays open. When a follow-up Issue accumulates items of one pattern a
script can decide (a wrapping or layout rule), the preferred drain is a `cargo xtask lint-docs`
rule for the pattern, whose landing ticks those items.

### Recording findings

A finding is recorded as a `- [ ]` task-list item under the Issue's `## Acceptance` section,
carrying file, line, authority, fix, and the PR and head that reported it. The Issue that
records a finding is the first of these that applies:

1. An open follow-up Issue of its scope that already holds it. The finding is not recorded
   again on any Issue, and its fix ticks its item on the Issue that holds it.
2. For a finding off the surface, the open Issue that already names the work.
3. The follow-up Issue the PR drains in that scope (the lowest-numbered, when it drains several
   in that scope).
4. The rolling Issue of its scope.

A finding of class style that is not a MUST violation goes on no Issue. The run record that
reports it is its record, and the ledger keeps a later run from raising it again (§ Ledger);
where this document requires a finding to be recorded, the run record meets that for such a
finding.

### Ledger

A later run of the same PR, delta or full, MUST NOT re-raise a finding an earlier run recorded
or dropped, or that was decided as § Contested findings says, unless the hunk it anchors to
changed since the run that reported it, or that run no longer resolves in the clone. The
reviewer reads a ledger built from the saved run records, each entry naming its run; a finding
the ledger holds whose hunk is unchanged since the run its entry names, when that run resolves,
is listed, not counted.

### Branch naming

`feature/<slug>`, `fix/<slug>`, `cleanup/<slug>`, `audit/<slug>`.

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
- Every PR body MUST state the validated head in its `## Validation`
  section; for a documentation-only or comment-only delta since that head,
  it MUST say so (see [testing.md](testing.md#coverage-tiers)), and for a
  sync since that head that leaves it standing, it MUST say that the
  incoming diff touches none of the PR's files (§ Syncing with `master`).
- Every PR body MUST report, in its `## Validation` section, each local host
  run [testing.md](testing.md#coverage-tiers) § Coverage tiers owes (each
  boundary run, the memory variation, and each device cell: the storage cells,
  the no-IOMMU variant, the framebuffer cell, and the debug-port cell, per architecture), with its
  `--runs` count, its
  outcome, and the head it ran at (a run the PR does not owe that HANGs or
  fails as that section allows, with the link to its record), or state that
  none is owed and why (that the PR's changes outside Markdown are all inert,
  or that its non-inert lines change none of the CPU-count, memory, and device
  surfaces that section names and it states no concurrency-fix purpose as that
  section defines it).

## CI Gating

CI status checks MUST pass before merge. The authoritative workflow
inventory and per-workflow shape live in
[build-system.md](build-system.md#continuous-integration); local
equivalents are the `cargo xtask` commands documented there.

## Release Production

See [docs/releases/README.md](releases/README.md) for per-tag release notes discipline.

Producing a release for tag `v<X>.<Y>.<Z>`:

1. Once every Issue of the milestone `v<X>.<Y>.<Z>` is closed or is a
   follow-up Issue of § Branch and PR Workflow (any other open Issue the
   maintainer moves to a later milestone first), run the release review on
   `master` before the version bump: the `release-review` workflow
   (`.claude/workflows/release-review.js`) in `full` mode, from the previous
   release tag. It reviews the composition of the PRs merged since that tag,
   which no PR's own review saw: each file two or more of them touched line
   by line, and the whole range through lenses (agreement across `abi/`, the
   kernel, and the runtime; the whole text of every design document the
   range touched; `## Summarized By` integrity; new `unsafe` code and its
   safety contracts; test coverage of new syscalls and protocol messages;
   [limits.md](limits.md) and [platform-requirements.md](platform-requirements.md)
   against the code). Its ledger is the saved run records of those PRs and
   of the release's earlier runs, under the ledger rule of § Branch and PR
   Workflow. Its release audit checks the milestone state, the version, the
   release notes, the known issues, and the release host runs. Two
   independent refuters judge every finding that can block and every
   Critical or Should finding; a finding both refute on evidence is
   dropped. The workflow computes the verdict: `RELEASE BLOCKED` when a
   reviewer returned no result, when the audit fails, or when a finding on
   the blocking track of § Branch and PR Workflow survives and no open Issue
   names its work; `RELEASE READY` otherwise.
2. A blocking finding takes a fix PR through the normal PR workflow, and an
   audit failure its fix; the review then runs again in `delta` mode, since
   the head it last reviewed, and judges again each blocking finding that
   run left standing, apart from a contested one, which the maintainer's
   ruling settles. A blocking-track finding an open Issue names is a
   known issue of the release. Every other finding is recorded as § Branch
   and PR Workflow records a finding off the surface: on the open Issue that
   names the work, else on the follow-up Issue of its scope, which step 8
   moves to the next milestone. A finding contested on the facts or on its
   rule is put to the maintainer.
3. On `RELEASE READY` the run returns the draft of
   `docs/releases/v<X>.<Y>.<Z>.md`, built from `docs/releases/TEMPLATE.md`.
   One release PR bumps `[workspace.package] version` in the root
   `Cargo.toml` to `<X>.<Y>.<Z>` and adds the notes file from the draft, every
   section filled, through the normal PR workflow. The tag MUST point at a
   commit that contains both.
4. Run the release host runs ([testing.md](testing.md#coverage-tiers)
   § Coverage tiers) on the commit to be tagged, a `master` commit that
   contains the bump and the notes file: the whole
   boundary set (riscv64 16 and 128 harts, x86_64 16 and 128 vCPUs) three
   times each in the debug profile and once each in the release profile, and
   the memory variation, the disk variations (a 4Kn disk and three
   second-disk boots, on both architectures), the no-IOMMU variant
   (`--iommu absent`, svctest, on both architectures), the framebuffer
   cell (`--display framebuffer`, svctest, on both architectures), and the
   debug-port cell (`test-debug-port`, on both architectures) once each.
   Their report, each run's command, `--runs` count, outcome, and head, is
   written to `target/xtask/review/release-v<X>.<Y>.<Z>/host-runs.md`, the
   file the release audit reads; the release PR's body states its own local
   host runs as § PR-body checklist discipline requires.
5. Run the release review in `delta` mode at that commit, since the head it
   last reviewed, with that report. `RELEASE READY` there is the tag
   condition: tag that commit and push the tag:
   `git tag v<X>.<Y>.<Z> && git push origin v<X>.<Y>.<Z>`.
6. The tag push triggers `release.yml` and `burnin.yml`. The `preflight` job in
   `release.yml` aborts the run before any image is built if the workspace
   version does not match the tag or the notes file is missing or does not
   follow `TEMPLATE.md`'s structure.
7. The maintainer publishes the draft Release manually after verifying the
   `burnin.yml` run for the same tag completed successfully.
8. The maintainer creates `v<X>.<Y>.<Z+1>` when no `v<X>.<Y>.*` milestone above `v<X>.<Y>.<Z>`
   is open, and closes each rolling follow-up Issue of § Branch and PR Workflow whose items are
   all ticked. Every Issue in `v<X>.<Y>.<Z>` or a lower open milestone moves to `v<X>.<Y>.<Z>`
   when it is closed and no commit outside the tag closed it, and otherwise to the
   lowest-versioned open milestone above `v<X>.<Y>.<Z>`. The maintainer then closes
   `v<X>.<Y>.<Z>` and every lower open milestone; the lowest-versioned open milestone is current
   (§ Milestones).

---

## Summarized By

[abi/syscall/README.md](../abi/syscall/README.md), [Build System](build-system.md),
[Documentation Standards](documentation-standards.md),
[docs/releases/README.md](releases/README.md), [Testing](testing.md),
[shared/ipc/README.md](../shared/ipc/README.md), [xtask/README.md](../xtask/README.md)
