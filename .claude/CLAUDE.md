# Seraph — AI Project Context

Seraph is a microkernel operating system written in Rust for x86-64 and RISC-V. The root
`README.md` describes the top-level directories and links every design document under `docs/`;
read it to find the document a task needs.

## Authority

- `docs/` defines system-wide design and invariants. Each component's `README.md` defines its
  scope and structure, and `<component>/docs/*.md` its internal design
  ([docs/documentation-standards.md](../docs/documentation-standards.md) § Document Hierarchy).
  Read in that order, and only what the task needs.
- [docs/coding-standards.md](../docs/coding-standards.md) governs all source code,
  [docs/documentation-standards.md](../docs/documentation-standards.md) all documentation, and
  [docs/conventions.md](../docs/conventions.md) how work is tracked and shipped: versioning,
  Issues, commits, branches and PRs, CI, and releases. Every change complies with them.
- Existing code or history that breaks a written rule is not a convention; the rule governs new
  work.
- A lint suppression is narrowly scoped and carries its rationale where it is used
  ([docs/coding-standards.md](../docs/coding-standards.md) § E. Exception Policy).
- The project's rules and these instruction files are one system. Restating or restructuring a
  rule without changing what it requires needs no approval. A change to what a rule or standard
  requires needs the maintainer's approval of that specific change.

## Tooling constraints

- Build, run, clean, and test only through `cargo xtask`
  ([docs/build-system.md](../docs/build-system.md) § Convenience Commands). Do not invoke
  `cargo build`, `cargo run`, `cargo test`, or `cargo clippy` directly: they bypass the sysroot,
  the custom targets, and the lint configuration.
- Run `cargo xtask clean` before switching architectures
  ([docs/build-system.md](../docs/build-system.md) § Build Output: the Sysroot).

## PR workflow operations

- All work lands through a feature-branch PR; nothing is pushed to `master` directly
  ([docs/conventions.md](../docs/conventions.md) § Branch and PR Workflow).
- These are the maintainer's standing requests, so no session or worker asks before acting on
  them:
  - Given an Issue, commit to its feature branch, push it, and open the PR.
  - After a push, watch the PR's CI run with `gh pr checks <N> --watch` as a background command.
    The harness notifies on completion; do not poll or sleep.
  - On green, say so in one line and run the pre-merge review as the `pr-review` skill
    describes. On red, show the failing job's tail (`gh run view <run-id> --log-failed`).
- After a review run, whoever ran it gives both verdict lines verbatim to the one it reports to:
  a worker records them in its status line for its orchestrator
  (`.claude/agents/worker.md` § Reporting), a standalone session gives them to the maintainer.
  An orchestrator passes them on only when asked, or when a line is why something blocks, and
  otherwise reports as the `.claude/agents/orchestrator.md` § Reporting to the maintainer says.
- Hand searches and specified mechanical work to the `Explore` and `scribe` agents, as
  `.claude/agents/worker.md` § Delegation describes, and keep every judgement about the code.
- A commit message follows [docs/conventions.md](../docs/conventions.md) § Commit Messages and
  § Commit and PR cross-references; `cargo xtask commit-check` checks it. No commit message, PR
  body, Issue body, or comment carries a tool attribution line or a session link.
- A decision of the maintainer is stated as a decision, in the project's prose. Nothing tracked
  or outward-facing (a commit message, a PR body, an Issue, a comment, a file in the tree)
  quotes what they typed
  ([docs/documentation-standards.md](../docs/documentation-standards.md) § Tone and Language
  for a tracked file and a commit message; [docs/conventions.md](../docs/conventions.md)
  § Style for a PR body, an Issue and a comment); their words are kept only in the
  orchestrator's local record.
- A PR merges when it meets the merge condition of
  [docs/conventions.md](../docs/conventions.md) § Pre-merge review, which
  `cargo xtask pr-check <N> --gate` checks, never while CI is pending or failing (§ CI Gating),
  and with `gh pr merge <N> --merge --delete-branch` (§ Merge method). The orchestrator of a
  batch merges such a PR without asking. A session working alone with the maintainer merges on
  their instruction. A worker never merges.
- A change to this file, to `.claude/settings.json`, or to a hook is prepared as a patch and
  applied only on the maintainer's own word; no agent's message stands in for it.
- A batch of Issues is driven as the `orchestrate` skill and `.claude/agents/orchestrator.md`
  describe, a single Issue in one session as the `work` skill describes, and a release
  candidate is reviewed by the `release-review` workflow as § Release review of that agent file
  describes.

## Validation

- Validate a change beyond successful compilation. Host-side compilation, unit tests, and
  `cargo check` alone are not validation.
- At minimum, on both `x86_64` and `riscv64`: `cargo xtask build` succeeds, and a boot of ktest
  or the userspace services under QEMU (`cargo xtask run`, which does not build) shows the
  chosen mode's terminal pass marker.
- A change whose own diff makes a non-inert change to the CPU-count surface, the memory surface,
  or a device surface that [docs/testing.md](../docs/testing.md) § Coverage tiers names, or
  whose PR states a concurrency-fix purpose as that section defines it, also runs the local host
  runs that section owes for it, at the heads and repeat counts it sets. Any other change owes
  none, whatever directory it touches.
- A documentation-only or comment-only change, as that section defines it, needs none of the
  runs above, since the CI gate builds and boots both architectures. The pre-merge review still
  applies, and the PR body carries what [docs/conventions.md](../docs/conventions.md) § PR-body
  checklist discipline requires.
- `cargo xtask lint-docs` passes on every change
  ([docs/conventions.md](../docs/conventions.md) § CI Gating;
  [docs/build-system.md](../docs/build-system.md) § Continuous Integration).

## Completeness

- A review reports defects only ([docs/conventions.md](../docs/conventions.md) § Findings). A
  defect on the review surface (§ Review surface) is part of the task: fix it in the same pass.
- A finding off the surface is recorded in the same pass, never dropped, as
  [docs/conventions.md](../docs/conventions.md) § Recording findings says.
- Do not call work "out of scope" or a "follow-up" to avoid blocking work on the surface that is
  mechanically reachable.
- State a material expansion of the task in one line and continue; do not pause for permission.
- File a genuine deferral (a different review surface, or an expansion too large to absorb) as a
  GitHub Issue, with the maintainer's approval, before the task closes.

## Design decisions

- Whoever drives the work owns it technically: the orchestrator of a batch owns the batch's
  changes, the codebase, the standards and the documentation; a worker owns its PR; a session
  working alone owns its task. The owner makes the technical decisions, reads the code behind
  them, judges their quality and defends them. A technical choice is not handed to the
  maintainer, or down to a worker, because it is hard.
- Decide a major question (a mechanism, a lifetime, an interface, where a cost falls) from a
  blank sheet: state the project's principles the question touches, lay out every design those
  principles allow, including ones no Issue, plan or existing code proposes, and choose the best
  final state.
- Sunk work, rework, design time and the size of the change are not reasons for a choice. State
  them as costs beside the choice; they do not enter it.
- An option set that an Issue, a plan or a worker presents is input, not the limit of the
  answer. Before choosing among such options, ask what the existing structure already provides
  and what a design started today would look like.
- Read an Issue, a plan or an acceptance item for its intent. The project moves on after one is
  written, so its specifics (a mechanism, a file name, a number, a wording) may no longer be
  possible, relevant, or the best way to reach its goal. Check each against the code and the
  documents as they are now and work within the spirit of the Issue. When a specific no longer
  holds, say so and decide the best way to meet the goal. A change to an acceptance item's
  wording is a change to the Issue and is reported as one.
- A major change goes before the maintainer for approval before it is built or merged: a major
  design decision, a change to a standard, and a change to what a rule in `docs/` or an
  instruction file requires. That is an approval and management gate, not a request to decide.
  It is put as one owned pick with its reasons, its downsides, what it replaces, and what was
  read, what was estimated and what was not verified; never as a menu.
- The maintainer directs the workload and is the escalation point. Everything else technical is
  decided by its owner and reported.

## Conflicts

- When an instruction, plan, or change conflicts with a documented invariant or with this file,
  stop that action and say so at once. Continue with work that does not depend on it.
