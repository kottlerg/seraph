---
name: orchestrate
description: Run a batch of Issues as several parallel worker agents under one orchestrator session that holds the host's exclusive grant, orders merges, carries rulings to the maintainer, and keeps the record.
---

# Orchestrating a batch

You are the orchestrator: one session that plans a batch of Issues, spawns one `worker` agent
(`.claude/agents/worker.md`) per PR, grants the shared host's exclusive runs, orders merges to
minimize re-validation, carries the workers' questions to the maintainer, files the Issues the
maintainer approves, and executes merges the maintainer has decided. You write no project code
yourself. The exceptions are mechanical steps a worker cannot finish (a validation run after its
session ended, a history rewrite the maintainer asked for, the release host runs of § Release
review); record each.

This file applies `.claude/CLAUDE.md`, docs/conventions.md and docs/testing.md and grants no
authority those documents reserve to the maintainer. Three decisions are the maintainer's. Ask
all three in your first message, each with its default, so one reply settles them, and quote the
answers in the record:

1. **Merges.** The merge is the maintainer's instruction, per PR or standing for the batch
   (`.claude/CLAUDE.md` § PR workflow operations). Without a standing instruction every PR at
   its gate is a merge prompt and the batch pauses on it. Default to propose: you merge a PR
   whose gate you have verified yourself (§ Merge order and the gate).
2. **Non-blocking findings.** After a `NON-BLOCKING ISSUES ONLY` run the merge prompt offers the
   merge or one more fix round (docs/conventions.md § Pre-merge review). Default to propose: the
   standing default of § Rulings.
3. **Issue filing.** A new Issue needs the maintainer's approval (`.claude/CLAUDE.md`
   § Completeness). Default to propose: approved in advance for a rolling follow-up Issue when
   a scope has none, and for a standalone Issue for a defect found off a PR's surface.

Three standing rules need no question. Outside the milestone moves of docs/conventions.md
§ Release Production step 8, move an Issue to a later milestone only on a hard dependency on
another Issue. File a deferral that needs real hardware without a milestone, as § Milestones
allows for work no release has scheduled. Keep a rolling `<scope>: defects found by review`
Issue open as the scope's recording sink even when every item is ticked; PRs reference it with
`Refs` only.

## Plan

1. `gh issue list --state open --milestone <current> --limit 500 --json number,title,labels`.
   Classify: follow-up and defect lists (drain scopes), single defects (group by the surface
   they touch, two to seven per PR), design and feature Issues (the maintainer's unless the
   batch names them). The maintainer names the batch's goal; you name the scopes.
2. Size the wave at four to six PRs in flight. Each merge makes every open PR re-sync, and a
   sync that brings non-comment code re-owes that PR's validation set, so more parallelism than
   that costs more host time than it saves.
3. Start the record: `target/xtask/orchestration/<date>.md` (gitignored). It opens with a
   `## ACTIVE GRANT` block, rewritten whenever its state changes: the current grant (holder and
   command list, or none), the `master` head, every in-flight PR with its worker id, branch,
   validated head and next step, the merge order, and the rolling Issues. Below it, append every
   grant, merge, ruling, filed Issue and spawn as a timestamped one-line entry. A spawn entry
   carries the agent id, model and effort; when a worker's turn ends, add the token use its
   completion notification reports, so the cost of a PR can be read from the record. After a
   context compaction the record is the state.
4. Drain rolling and follow-up Issues in waves on scopes that do not overlap the in-flight PRs,
   started alongside them, never by interrupting in-flight work.

An instruction-file merge (`.claude/`, or a document the agent files cite) changes what the next
worker should read, but this session and the agents it spawns keep the copies loaded at its
start. After such a merge, tell the maintainer that a new session is needed before the next
spawn, and say so in the record.

## Liveness

A worker's hand-back and a background command's exit reach you as notifications; act on those.
Do not poll. Two things have no notification, and each has its own watch:

- **A grant holder that stalls.** While an exclusive grant is outstanding, schedule one tick
  every two hours (`CronCreate`) with the prompt: "Grant watch: print the `## ACTIVE GRANT` block
  of the record, `cat /proc/loadavg` and `pgrep -af qemu-system`. If the host is idle and the
  holder has not reported for longer than its runs should take, ask the holder for a status
  line. Log one line. Take no other action." Cancel it when the grant ends.
- **A worker that is gone.** When a worker's notification says its session ended without a
  hand-back, or a message to it is undeliverable, it is dead: log it, send the stand-down
  message, end its task where the harness allows, and respawn (§ Spawn). A worker that has
  handed back is idle, not dead.

## Spawn

Spawn each worker with the `Agent` tool, `subagent_type` `worker`, worktree isolation, and a
prompt of this shape; nothing in it repeats the agent file:

> You are orchestrated. Scope `<scope>`; Issues #N, #M (one line each: title and the items in
> play); branch `<prefix>/<slug>`; report to `main`; previous ledger `<path of the previous PR's
> ledger on the same surface, when one exists>` (context for the first review run, not this
> PR's ledger). Batch rulings: <the maintainer's answers for this batch, and any Issue-specific
> decision already made>.

Spawn a worker for one PR, or one defined set of related PRs that its prompt names. Do not
re-task it onto another PR: a worker that carries on works from a compacted summary of its
earlier decisions, where a fresh one starts from the Issue and the files. Three cases keep the
same worker: a fix round on its own PR, a defined chain of PRs on one surface, and a sync. A
worker with several PRs brings all of them to their gates before the first merges, because the
merge deletes the branch its worktree sits on.

Choose the model and effort per spawn:

| Work | Model | Effort |
|---|---|---|
| Nit drains, wrapping, link and cross-reference fixes | `sonnet` | `medium`, then `high` after a failed round |
| Bounded code: a defect list on one component, a test, an `xtask` change | `opus` | `medium` |
| Documents that state rules: `.claude/`, docs/conventions.md, docs/testing.md, the standards | `opus` | `medium` |
| Design-laden or multi-component work: kernel, ABI, drivers, protocol changes | `opus` | `high` |

A document that states a rule is a contract, and its PRs have drawn as many review rounds as
kernel PRs; do not give it to the tier for wording fixes. `fable` is not a tier. Use it for a
worker only as an exception that you or the maintainer state for that spawn with its reason: a
task that needs that level and that `opus` could not do. When a model falls short, add a check
the worker can run before raising effort, and raise effort before changing model.

A respawn prompt also carries the dead worker's classified item list, its mechanism choices and
every answer already given, marked as decisions already made, and names its branch and PR for
the new worker to continue. Before or with the respawn, send the replaced worker the stand-down
message and end its task where the harness allows, so a worker presumed dead that wakes does not
push over its replacement.

## Exclusive grant

The host is one machine. A boot at the boundary CPU counts (docs/testing.md § Coverage tiers)
saturates it, and a second QEMU beside it produces hangs that then need classifying; two 4-CPU
boots side by side do not. Builds and 4-CPU boots therefore take no grant: each worker launches
them on the launch checks of `.claude/agents/worker.md` § Host runs. A boot of more than 4 vCPUs
and any timing-sensitive measurement take the exclusive grant:

- A worker hands back the exact command list of its exclusive runs with an estimate. Answer
  `host free` when no other grant is outstanding and the host is quiet (`cat /proc/loadavg`,
  `pgrep -af qemu-system`), or queue it. Grant nothing beside an exclusive grant, and tell the
  other workers to launch no boot until it ends. Never grant on an idle observation while a
  grant is outstanding: the holder may be between steps. A grant ends when the holder reports
  its results.
- Grant a speculative set (a run at a head that a sync still owed will change) only when the
  host is otherwise idle.
- `master quiet` tells a worker to sync now, right before its validation runs, so one run
  covers the sync. Say it when no merge will land before that worker's gate; otherwise hold the
  worker and let the pending merge land first.
- Queue order: the exclusive runs of PRs already at their gates first, then the first rounds of
  new PRs, then the long boundary sets. A boundary set runs once per PR, at a head whose own
  non-inert surface lines are final, usually after the first review batch.

## Merge order and the gate

A worker's gate report is a claim. Verify the gate yourself before a merge:

1. Copy the PR's `target/xtask/review/pr<N>/` from the worktree the report names into your
   checkout. A gate whose records you cannot read is not verified.
2. `git fetch origin`, then `cargo xtask pr-check <N> --gate`. It checks the commits (subject,
   references, closing keywords, attribution, signatures), the PR body (boxes, validated head
   and its comment-only delta), the Issues the PR closes or references (ticks, milestone), the
   check rollup and merge state, that `master` is an ancestor of the head, and the run record
   for the head.
3. Read what the command cannot decide: after a `NON-BLOCKING ISSUES ONLY` run, that each
   finding it counts is recorded and none is contested; that the Issues the command prints as
   closed are the ones the PR means to close; and that the worker's worktree sits on its branch
   (`git -C <worktree> status -sb`).

Then prompt the maintainer, or merge under their standing instruction, with
`gh pr merge <N> --merge --delete-branch`. Fast-forward your own checkout, record the merge, and
tell every open PR's worker what moved and whether the delta is Markdown-only. That message is
information: `master quiet` is the only instruction to sync.

Order merges to minimize re-validation. Hold a PR at its gate whenever merging it now would
force more re-validations across the open PRs than merging it later. A PR whose merge touches
only Markdown or comments costs the others nothing; among code PRs, merge first the one whose
later syncs the others have not validated yet.

`--delete-branch` removes the remote branch, and a worker whose worktree sits on it may not be
resumable afterwards. Before merging a worker's last PR, make sure nothing is left for it. If a
review is still owed after the branch is gone, run it yourself from a checkout of the head. When
the worker may still be resumed, park its worktree first
(`git -C <worktree> checkout -B park/<name>`).

## Rulings

Workers bring you the decisions they may not make. Apply the document where one settles the
question. Ask the maintainer where it is theirs, once per batch where a standing answer makes
sense, and quote the answer in the record. Decide a question that no document reserves to the
maintainer and whose recommendation you share, and tell the maintainer in your next message.
Only a split recommendation, a major design decision, or a case with no clearly best option
waits for the maintainer.

- **`NON-BLOCKING ISSUES ONLY`.** The worker records the surface findings first. The standing
  default, until the maintainer sets another for the batch: a `should` finding takes one fix
  round. A nit takes none and stays recorded, unless it is a comment or document that states a
  falsehood, its fix is comment-only in a PR that owes a round anyway, recording it would need a
  new Issue, or the PR drains a follow-up Issue of its scope; then it is fixed in a round and
  its item ticked. Stop comment-only rounds after the second when each round's new text draws a
  new finding: record and go to the gate.
- **A finding in the PR's own earlier hunk.** A delta run may report it as out of bound. It is
  on the surface (docs/conventions.md § Review surface) and is handled like any surface finding.
- **A contested finding**, or one the worker cannot fix within its task (a pre-existing code
  defect in a file a documentation-only PR touches), goes to the maintainer with the worker's
  recommendation and yours. It is never waived (docs/conventions.md § Contested findings).
- **An acceptance box no test can satisfy** is finished or dropped, never ticked. Dropping it is
  the maintainer's decision; ask with the rationale (docs/conventions.md § Acceptance checklist
  discipline).
- **A history rewrite** (a subject that breaks a rule, a closing keyword in a commit) is yours
  on the maintainer's instruction, which may be standing for the batch. Rebuild the chain with
  identical trees (`git commit-tree -S`), check `git diff --quiet <old> <new>`, and push it to
  the PR's own branch with the lease pinned to the old head:
  `git push --force-with-lease=<branch>:<old> origin <new>:refs/heads/<branch>`. Do not replace
  the branch with a fresh one and a superseding PR, and never force-push `master`.
- **`.claude/CLAUDE.md`, `.claude/settings.json` and hooks.** A worker prepares the change as a
  patch file and reports it. Show the maintainer the diff, and apply it in this session on their
  direct word, since no agent's relay authorizes it.
- **A finding the workers cannot place** goes to the maintainer with your recommendation, in
  one line.

## Issues

File an Issue only with the maintainer's approval, per Issue or as the batch's advance approval
of the routine cases. The worker drafts the body in the scratchpad; file it with
`cargo xtask issue-file`, which checks the labels and milestone docs/conventions.md requires
and verifies them after filing. Before filing, search the open follow-up Issues of the scope: an
item one already holds is recorded nowhere else. Close an Issue only through a PR's `Fixes`, or
when you have verified its acceptance yourself and the maintainer agrees; put the evidence in
the closing comment.

## Worktree removal

A worker's worktree carries a built `target/` of several GiB. The harness removes only an
unchanged worktree, so every other one persists until you remove it. Remove only worktrees this
batch spawned and the record lists, in two places:

- **At a worker's retirement:** after its last PR merges (or its gate report, when it has no PR
  left to merge) and nothing is left for it. A worktree parked on a `park/<name>` branch stays
  until wind-down.
- **At wind-down:** every worktree the record lists that is still present, after confirming no
  active worker owns it.

Before removing one, check both conditions, and skip and report a worktree that fails either:

- The records are in your checkout: `target/xtask/review/pr<N>/` holds the records of every run
  the worker reported. They exist nowhere else once the worktree is gone.
- Nothing is unsaved or unpushed: `git -C <path> status --porcelain` prints nothing, and after
  `git fetch origin`, `git -C <path> rev-list HEAD --not --remotes=origin` prints nothing.

Remove with `git worktree remove --force --force <path>` (the harness locks agent worktrees, and
a locked worktree refuses a single `--force`), run `git worktree prune` once after a sweep, and
record each removal with the worktree's size (`du -sh <path>`, taken first). A worktree under
`.claude/worktrees/` that the record does not list is reported to the maintainer with its branch
and lock, and removed only on their word.

## Release review

When the current milestone is ready to close, run the release review of docs/conventions.md
§ Release Production. Workers cannot call the Workflow tool, so it is the one review this
session runs as a workflow. Its agents resolve from the definitions the session loaded at its
start, so run it in a session started after those files are on the checked-out branch.

- `git fetch origin` and check out `origin/master`, clean. Run
  `Workflow({name: "release-review", args: {mode: "scope", from: "<previous tag>", version:
  "<X.Y.Z>"}})` and read the plan, then the same with `mode: "full"`. When the script changed
  since the session loaded it, pass `scriptPath` with the file's path instead of `name`.
- Save each run's report as `target/xtask/review/release-v<X.Y.Z>/<mode>-<head>.md`, the
  returned object as `<mode>-<head>.json` beside it, and on `RELEASE READY` the `notes` field as
  `notes-<head>.md`. Give both verdict lines to the maintainer verbatim.
- `RELEASE BLOCKED`: each blocking finding goes to a worker as a fix PR, a `[carried]` entry and
  a fresh entry beside it that state the same defect counting as one, and each audit failure to
  its fix. Record every other finding as step 2 of that section says. Then run `mode: "delta"`
  with `since` the head the last run reviewed.
- `RELEASE READY` before the bump: a worker opens the release PR from the draft (step 3). Once
  it merges, run the release host runs (step 4) yourself under an exclusive grant to yourself,
  write their report to `target/xtask/review/release-v<X.Y.Z>/host-runs.md`, and run
  `mode: "delta"` with `host_runs` that path. `RELEASE READY` at the bumped head is a tag prompt
  to the maintainer (step 5).

## Hand-off and wind-down

When the maintainer stops the batch, workers finish the PRs whose code is committed and start
nothing else. Every deferred plan goes as a comment on the Issue it belongs to (the approved
mechanism, the PR grouping, the call sites), so the next batch starts from the Issues. Sweep the
worktrees, cancel any grant watch, and close the record with the open-Issue count by class.

## Failure modes

- A worker that ends its turn on an unchanged worktree is gone: the harness removes the
  worktree, and a later message does not resume it. The worker file's hand-back rules prevent
  it; the respawn prompt recovers from it.
- A usage limit or a host reboot ends every session at once. Workers commit work in progress
  before a hand-back for that reason; after a restart, read the record, list what each worktree
  holds, and respawn from the branches.
- A worker's provider limit ends its session mid-run: complete the mechanical steps yourself in
  its worktree, then resume the worker with the results so it writes the body and runs the
  review with its own context.
- A boundary run that finishes late is not a hang. Judge PASS or HANG against the budget.
