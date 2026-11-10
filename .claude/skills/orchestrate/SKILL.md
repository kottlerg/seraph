---
name: orchestrate
description: Run a batch of Issues as several parallel worker agents under one orchestrator session that holds the host's exclusive grant, orders merges, carries rulings to the maintainer, and keeps the record.
---

# Orchestrating a batch

You are the orchestrator: one session that plans a batch of Issues, spawns one `worker` agent
(`.claude/agents/worker.md`) per scope, grants the shared host's exclusive runs (the
exclusive grant), orders merges to minimize re-validation, carries the workers' questions to the
maintainer, files the Issues the maintainer approves, and executes merges the maintainer has
decided. You write no project code yourself; mechanical steps a worker cannot finish (a
validation run after its session ended, a history rewrite the maintainer asked for, the release
host runs of § Release review) are the exception, and each is recorded.

Everything in this file applies `.claude/CLAUDE.md`, docs/conventions.md and docs/testing.md;
nothing in it grants an authority those documents reserve to the maintainer. Three decisions
are the maintainer's by those documents; ask all three in your first message, each with the
proposed default below, so one reply settles them, and quote the answers in the record file.
Until an answer arrives, each case below is a prompt to the maintainer when it comes up:

1. **Merges.** Per `.claude/CLAUDE.md` § PR workflow operations the merge is the maintainer's
   call per PR. For a batch the maintainer may give a standing instruction in their own words;
   without one, every PR at its gate is a merge prompt to the maintainer, and the batch pauses
   on it. Proposed default: you execute the merge of a gate you have verified yourself
   (§ Merge order and the gate).
2. **Non-blocking findings.** After a `NON-BLOCKING ISSUES ONLY` run the merge prompt offers the
   merge or one more fix round (docs/conventions.md § Branch and PR Workflow). The maintainer
   may set a batch default, which replaces the standing one of § Rulings for the batch; without
   one, each case is a question. Proposed default: one fix round when a finding is a comment or
   document stating a falsehood, when its fix is comment-only and a later round is owed anyway,
   or when recording it would need a new Issue for a one-line change; otherwise the findings are
   recorded and the PR merges.
3. **Issue filing.** New Issues need the maintainer's approval (`.claude/CLAUDE.md`
   § Completeness). The maintainer may approve the routine cases for the batch in advance;
   without that, each is a question with the drafted body. Proposed default: approved for a
   rolling follow-up Issue when a scope has none and for a standalone Issue for a defect found
   off a PR's surface.

Three rules the maintainer has stated stand without a question. Outside the milestone moves of
docs/conventions.md § Release Production step 8, you move an Issue to a later milestone only on
a clear and hard dependency on another Issue. A deferral that needs real hardware is work no
release has scheduled, filed as an Issue without a milestone, as § Milestones allows for such
work. And you keep a rolling `<scope>: defects found by review` Issue open as the scope's
recording sink even when every item is ticked (PRs reference it with `Refs` only, as
`.claude/agents/worker.md` § Commits and the PR body says), which § Branch and PR Workflow
allows: it conditions closing, it does not require it.

## Plan

1. `gh issue list --state open --milestone <current> --limit 500 --json number,title,labels`.
   Classify: follow-up and defect lists (drain scopes), single defects (group by the surface
   they touch, two to seven per PR), design and feature Issues (the maintainer's unless the
   batch names them). The maintainer names the batch's goal; you name the scopes.
2. Size the wave at four to six PRs in flight. Each merge forces every open PR to re-sync, and
   a sync that brings non-comment code re-owes that PR's validation set, so more parallelism
   past that point costs more host time than it saves.
3. Start the record: `target/xtask/orchestration/<date>.md` (gitignored). It opens with a
   `## ACTIVE GRANT` block, which you rewrite whenever its state changes: the current grant
   (holder and command list, or none), the `master` head, every in-flight PR with its worker
   id, branch, validated head and next step, the merge order, and the rolling Issues. Below
   it, every grant, merge, ruling, filed Issue, spawn and agent id is appended as a
   timestamped one-line log entry. After a context compaction the record is the state.
4. Schedule the watchdog (`CronCreate`, every hour) with this prompt:
   "Orchestration watchdog tick: run one shell command that prints the `## ACTIVE GRANT`
   block of `target/xtask/orchestration/<date>.md`, `cat /proc/loadavg`,
   `pgrep -af qemu-system`, `git worktree list`, and each open PR's `mergeStateStatus` and
   check rollup, then call `ListAgents` once, and compare both against the record. If the host
   is idle and the grant holder has not reported for longer than its runs should take, ping
   the holder for a status report; if no grant is outstanding and a queued request fits the
   host (§ Exclusive grant), grant the next one. Liveness: compare the listing against the worker
   ids the record lists as active. A worker that lists as completed is idle, not dead. A
   worker the listing omits, whose last report was not its gate, and whose scope has no open
   PR at its gate is dead: log it, send it the stand-down message and end its task where the
   harness allows (§ Spawn), and respawn it with its plan and every answer already given
   folded into the prompt. Note any PR at its gate (clean verdicts, CI green) that is waiting
   on a merge. Log the tick as one line in the record. Take no action this prompt does not
   name." Beyond the ping, grant and respawn it names, the tick is that one shell command,
   that one `ListAgents` call and that one log line. Cancel the watchdog when the batch ends.
5. Drain rolling and follow-up Issues in waves on scopes that do not overlap the in-flight
   PRs, started alongside them, never by interrupting in-flight work. New work produces new
   rolling items, so the drain is continuous.

## Spawn

Spawn each worker with the `Agent` tool, `subagent_type` `worker`, worktree isolation, and a
prompt of this shape; nothing in it repeats the agent file:

> You are orchestrated. Scope `<scope>`; Issues #N, #M (one line each: title and the items in
> play); branch `<prefix>/<slug>`; report to `main`; review records go to `<path of your
> checkout>` (the destination of the worker's copy, `.claude/agents/worker.md` § Review);
> previous ledger `<path of the previous PR's ledger on the same surface, when one exists>`
> (context for the first review run, not this PR's ledger). Batch
> rulings: <the rulings below that the maintainer changed for this batch, and any
> Issue-specific decision already made>.

Spawn a worker for one PR, or one defined set of related PRs that its prompt names (its
lifetime, `.claude/agents/worker.md`), and never re-task it onto another PR, whether or not the
surface is shared. No token ceiling applies to a worker: one that has to compact, compacts.

Choose the model and effort per spawn, within three tiers:

- `model: sonnet`, effort `high`: documentation-only, comment-only and nit-drain PRs.
- `model: opus`, effort `medium`: bounded code PRs (a defect list on one component, a test or
  xtask change).
- `model: opus`, effort `high`: design-laden or multi-component PRs (kernel, ABI, drivers,
  protocol changes).

`model: fable` is never a worker's model. Record the agent id with its model and effort, the
scope, the branch, the worktree path and, once opened, the PR number in the record file; the
id is the address for every later message, and the record lists it as active until the worker's
last PR merges or a respawn replaces it.

A respawn prompt also carries the dead worker's classified item list, its mechanism choices and
every answer already given, marked as decisions already made, so the new worker neither
re-plans nor re-asks, and names the dead worker's branch and PR when either exists, for the new
worker to continue on. Before or with the respawn, send the replaced worker a stand-down
message (its PR and branch now belong to the new worker; it edits, commits and pushes nothing
further, per `.claude/agents/worker.md` § Reporting), and end that worker's task where the
harness allows, so a worker presumed dead that resumes does not push over its replacement.

## Exclusive grant

The host is one machine. A boundary-set boot (the 16- and 128-CPU boots docs/testing.md
§ Coverage tiers names) saturates it, and a second QEMU beside it produces hangs that then need
classifying; two canonical (4-CPU) boots side by side do not (the maintainer's ruling of
2026-10-31). Builds and canonical boots therefore take no grant: each worker launches them on
the launch checks of `.claude/agents/worker.md` § Host runs. The exclusive grant is what
a boot of more than 4 vCPUs and any timing-sensitive measurement take:

- A worker sends the exact command list of its exclusive runs and its estimate and ends its
  turn. You answer `host free` when no other grant is outstanding and the host is quiet
  (`cat /proc/loadavg`, `pgrep -af qemu-system`), or you queue it. Nothing else is granted
  beside an exclusive grant, and while one is outstanding you tell the other workers to launch
  no boot until it ends. The `## ACTIVE GRANT` block of the record names the grant; never
  grant on an idle observation while a grant is outstanding, since the holder may be between
  steps. A grant ends when the holder reports its results.
- A speculative set (a run at a head that a sync still owed will change) is granted only when
  the host is otherwise idle; when that sync brings non-comment code, it re-owes the set by
  rule, as `.claude/agents/worker.md` § Host runs says.
- `master quiet` tells a worker to sync now, right before its validation runs, so one run
  covers the sync. Say it when no merge will land before that worker's gate; otherwise hold the
  worker and let the pending merge land first.
- Queue order: exclusive runs of PRs already at their gates first (they merge soonest and free
  the others from a further sync), then first rounds of new PRs, then the long boundary sets. A
  boundary set runs once per PR, at a head whose own non-inert surface lines are final, usually
  after the first review batch; CI's build and boot cells cover compile, clippy and the 4-CPU
  boots meanwhile, so the first local boundary run is not urgent.
- Workers run builds and boots under `nice -n 10`; your own commands do not need it.

## Merge order and the gate

A PR is at its gate when every part below holds. Verify each part yourself, from the records in
your checkout and from GitHub, since a worker's report is a claim; a gate whose records are not
readable in your checkout is not verified, so copy them from the worktree the gate report names,
or ask the worker for the copy, before merging rather than merging on the report.

- `gh pr view <N> --json mergeStateStatus,statusCheckRollup` shows `CLEAN` and every check
  green (docs/conventions.md § CI Gating, § Branch protection).
- `origin/master` is an ancestor of the head (`git merge-base --is-ancestor origin/master
  <head>`).
- Neither the PR body nor a commit message carries a claude.ai link or session trailer, the ban
  `.claude/CLAUDE.md` § PR workflow operations states (`gh pr view <N> --json body --jq .body
  | grep -cE 'claude[.]ai|Claude-Session'` and `git log origin/master..<head> --format=%B
  | grep -cE 'claude[.]ai|Claude-Session'` both print `0`). Strip a surviving one from the body
  with `gh pr edit` before the merge; one in a commit message is a history rewrite (§ Rulings).
- A closing keyword appears only as `Fixes #N` (or the template's `Closes #N`) in the body,
  for an Issue the PR closes, and in no commit body.
- Every commit subject is at most 72 columns, and no non-merge subject carries an Issue
  reference (`git log origin/master..<head> --format=%s`).
- Every commit is signed (`git log origin/master..<head> --format='%G? %h'` shows no `N`).
- The merge-prompt condition of docs/conventions.md § Branch and PR Workflow holds: the last run
  record under `target/xtask/review/pr<N>/` in your checkout is a completed run with no failed
  agent whose verdict is `READY TO MERGE`, or `NON-BLOCKING ISSUES ONLY` with every surface
  finding recorded and no contested finding on the surface unresolved, and `AUDIT PASS` is on
  record for the validated head or for a later head whose delta is the one the next part allows
  (an auditor-only run's `audit-<head>.json`, which `.claude/agents/worker.md` § Review
  describes, carries the reviewer verdict that section gives it, as the audit states it).
- A delta since the validated head is comment-only or Markdown-only (§ PR-body checklist
  discipline; `git diff <validated> <head> -- . ':!*.md'` shows only comment lines).
- Every Issue the PR closes carries the current milestone (§ Milestones).
- Every item the PR fixes is ticked on its Issue with `(fixed by PR #<N>)`.
- The worker's worktree sits on its branch (`git -C <worktree> status -sb`).

Then prompt the maintainer, or merge under their standing instruction, with `gh pr merge <N>
--merge --delete-branch`; fast-forward your own checkout, record it, and tell every open PR's
worker what moved and whether the delta is Markdown-only. That message is information, and any
sync guidance it carries (whether the move re-owes the worker's set) is advice for the worker's
plan: `master quiet` (§ Exclusive grant) is the only instruction to sync, and the sync is the merge
of `master`, never a rebase, that `.claude/agents/worker.md` § Host runs describes.

Order merges to minimize re-validation: hold a PR at its gate, whether `CLEAN` or `BEHIND`,
whenever merging it now would force more re-validations across the open PRs than merging it
later. A PR whose merge touches only Markdown or comments costs the others nothing; among code
PRs, merge first the one whose later syncs the others have not validated yet.

`--delete-branch` removes the remote branch, and a worker whose worktree sits on that branch
may no longer be resumable afterwards. Before merging a worker's last PR, make sure nothing is
left for it: ask a worker with several PRs to bring all of them to their gates first, and if a
review is still owed after the branch is gone, run it yourself (`pr-reviewer` and
`pr-auditor` in parallel, from a checkout of the head). When the worker may still be resumed,
park its worktree on a `park/<name>` branch (`git -C <worktree> checkout -B park/<name>`)
before the merge.

## Rulings

Workers bring you the decisions they may not make. Those below are the recurring ones; each
is either settled by the documents (then you apply the document) or by the maintainer (then
you ask, once per batch where a standing answer makes sense, and quote it in the record).
A worker's question that neither a document nor this skill reserves to the maintainer and whose
recommendation you share is decided: answer it and surface the decision to the maintainer in
your next message. Beyond the reserved questions, only a split recommendation, a major design
decision, or a case with no clearly best option waits for the maintainer.

- `NON-BLOCKING ISSUES ONLY`: the worker records the surface findings on the scope's
  follow-up Issue; the merge prompt then offers the merge or one more fix round. The default,
  standing by the maintainer's ruling of 2026-10-30 ("If you are confident that it won't cause
  broad process issues going forwards, then I can approve that those nits after a ready to
  merge will go on the rolling issue for that scope.", then "approved" to the orchestrator's
  statement of it: "after a review returns NON-BLOCKING ISSUES ONLY consisting solely of nits
  (no should, no critical), the nits are recorded on the scope's rolling Issue and the PR
  proceeds to its gate instead of taking another fix round; a READY TO MERGE run has nothing to
  record; should or critical findings always take a fix round"), until the maintainer sets
  another: a `should` finding takes one fix round; a nit takes none and is recorded on the
  scope's follow-up Issue (the Issue the PR drains in that scope, the lowest-numbered when it
  drains several, else the rolling Issue, as docs/conventions.md § Branch and PR Workflow
  defines it, from which the drain routing follows rather than from the ruling), with two
  exceptions. A nit whose fix is comment-only, in a PR that owes a fix round anyway, is fixed
  in that round. A nit in a PR draining a follow-up Issue of its scope is fixed in the same
  PR. Each is recorded first, as that section requires after a `NON-BLOCKING ISSUES ONLY`
  run, and ticked `(fixed by PR #<M>)` when the round fixes it. The maintainer's answer to the
  non-blocking question of your first message replaces this default for the batch, and the
  spawn prompt carries it as a batch ruling.
- A finding a delta run reports as out of bound in a hunk the PR's own earlier commits
  introduced is on the surface (docs/conventions.md § Branch and PR Workflow): it is handled in
  the PR like any surface finding, on the track its class sets and under the default above,
  never recorded as off the surface.
- A reviewer's finding that a worker contests, or that the worker cannot fix within its scope
  (a pre-existing code defect in a file a documentation-only PR touches, for instance), is put
  to the maintainer with the worker's and your recommendation. A finding is never waived or
  ruled outside the standards (docs/conventions.md § Branch and PR Workflow): on the surface it
  resolves in the same PR as a fix or as a clarification of the rule or document it misread;
  off the surface it is recorded with the maintainer's answer.
- An acceptance box no test can satisfy (a path that needs a live QEMU to fail, a cap the
  harness cannot hold) is finished or dropped, never ticked: dropping removes the item from the
  Issue body, with the one-line rationale in the closing comment (docs/conventions.md
  § Acceptance checklist discipline). Dropping it is the maintainer's decision; ask with the
  rationale.
- A closing keyword in a commit body cannot be withdrawn without a rewrite: a worker whose PR
  nonetheless carries one and loses its `Fixes` takes the comment-only fix round instead of
  recording, or asks for the rewrite.
- A history rewrite (a commit subject over 72 columns, a wrong keyword) is yours only on the
  maintainer's instruction: rebuild the chain with identical trees (`git commit-tree -S`),
  check `git diff --quiet <old> <new>`, push it to the PR's own branch with the lease pinned to
  the old head (`git push --force-with-lease=<branch>:<old> origin <new>:refs/heads/<branch>`,
  which refuses whenever the remote branch is not at `<old>`), and record it. The rewritten
  chain goes to that branch and that PR, never to a fresh branch and a superseding PR; `master`
  is never force-pushed (the maintainer's ruling of 2026-11-04).
- `.claude/CLAUDE.md` edits need the maintainer's own words. A worker whose change has a copy
  there reports it and holds its push; you carry the copy to the maintainer, who applies it or
  authorizes the worker in their own words, which you pass on verbatim.
- A finding the workers cannot place is put to the maintainer with your recommendation, in one
  line.

## Issues

File Issues only with the maintainer's approval (per Issue, or the batch-wide approval of the
routine cases asked for at the start): a new rolling `<scope>: defects found by review` Issue
when a scope has none, a standalone Issue for a security or correctness defect a worker finds
off its surface (title in the style of the existing ones, labels per docs/conventions.md
§ Labels, current milestone). The worker drafts the body in its scratchpad; you file with
`gh issue create --body-file`. Before filing, search the open follow-up Issues of the scope;
an item one already holds is recorded nowhere else. Close an Issue only through a PR's `Fixes`
or when you have verified its acceptance yourself and the maintainer agrees (record the
evidence in the closing comment).

## Worktree removal

A worker's worktree carries a built `target/` (several GiB), and the harness removes only an
unchanged worktree (`.claude/agents/worker.md` § Reporting), so every other worktree persists
until you remove it. Removal is the orchestrator's mechanic, in two places, and only for
worktrees this batch spawned: the ones the record file lists, under `.claude/worktrees/` (an
unlisted one is removed only on the maintainer's word, below).

- **At a worker's retirement:** after its last PR merges (or its gate report, when it has no
  PR left to merge) and nothing is left for it (§ Merge order and the gate), remove its
  worktree. A worktree parked on a `park/<name>` branch for a possible resume (§ Merge order
  and the gate) stays until wind-down, when no worker is resumable.
- **At wind-down:** sweep every worktree the record lists as spawned in this batch that is
  still present (a parked one included), after confirming no worker the record lists as
  active owns it.

Before removing a worktree in either place, check both conditions and skip and report to the
maintainer any worktree that fails one:

- The records precondition: `target/xtask/review/pr<N>/` exists in your checkout for each of
  the worker's PRs and holds the records of every run the worker reported, since those records
  exist nowhere else once the worktree is gone (§ Failure modes). Copy any that are missing
  from the worktree, or ask the worker to; the worktree fails the condition, and is skipped and
  reported, only when they cannot be obtained.
- Nothing unsaved or unpushed: `git -C <path> status --porcelain` prints nothing (it lists
  uncommitted tracked changes and untracked files that are not ignored, and not `target/`),
  and, after `git fetch origin`, `git -C <path> rev-list HEAD --not --remotes=origin` prints
  nothing.

A worktree under `.claude/worktrees/` that the record does not list (left by an earlier
batch, or another session's) is reported to the maintainer with its branch (or its detached
state) and its lock, and is never removed by the retirement step or the sweep; you remove it
only on the maintainer's word, after the two conditions above.

Removal is `git worktree remove --force --force <path>`: the doubled flag is required because
the harness locks agent worktrees and a locked worktree refuses a single `--force`; the
gitignored `target/` never blocks removal. Run `git worktree prune` once after the sweep, and
record each removal in the record file with the worktree's size (`du -sh <path>`, taken before
it). It is a `git worktree` procedure and not an `xtask` command, since the worktrees sit under
`.claude/`, outside the sysroot and `target/` that `cargo xtask clean` removes
(`xtask/README.md` § `cargo xtask clean`).

## Release review

When the current milestone is ready to close, you run the release review of docs/conventions.md
§ Release Production; workers cannot call the Workflow tool, so it is the one review this session
runs as a workflow.

- `git fetch origin` and check out `origin/master`, clean, in your checkout. Run
  `Workflow({name: "release-review", args: {mode: "scope", from: "<previous tag>", version:
  "<X.Y.Z>"}})` and read the plan (its shards, lenses and agent count), then the same with
  `mode: "full"`. When the script changed since the session loaded it, pass `scriptPath` with
  the file's path instead of `name`.
- Save each run's report as `target/xtask/review/release-v<X.Y.Z>/<mode>-<head>.md`, the
  returned object as `<mode>-<head>.json` beside it (the next run's ledger reads it), and on
  `RELEASE READY` the `notes` field as `notes-<head>.md`; surface both verdict lines to the
  maintainer verbatim.
- `RELEASE BLOCKED`: each blocking finding goes to a worker as a fix PR (§ Spawn), each audit
  failure to its fix, and you record every other finding as step 2 of that section says; then
  run `mode: "delta"` with `since` the head the last run reviewed.
- `RELEASE READY` before the bump: a worker opens the release PR from the draft (step 3). Once
  it merges, run the release host runs (step 4) yourself, as an exclusive grant to yourself
  (§ Exclusive grant), and write their report to
  `target/xtask/review/release-v<X.Y.Z>/host-runs.md`; then run `mode: "delta"` with
  `host_runs` that path. `RELEASE READY` at the bumped head is a tag prompt to the maintainer
  (step 5).

## Hand-off and wind-down

When the maintainer stops the batch: workers finish the PRs whose code is committed and start
nothing else; every deferred plan goes as a comment on the Issue it belongs to (the approved
mechanism, the PR grouping, the call sites), so the next batch starts from the Issues, not from
this session. Sweep the worktrees (§ Worktree removal). Cancel the watchdog. Close the record
with the open-Issue count by class.

## Failure modes

- A worker that ends its turn on an unchanged worktree is gone: the harness removes the
  worktree, and a later message does not resume it. The worker's turn-ending rule
  (`.claude/agents/worker.md` § Reporting) prevents it; the watchdog's liveness check (§ Plan
  step 4) and the respawn prompt (§ Spawn) recover from it.
- A finished worker's worktree persists until you remove it (§ Worktree removal), and its
  records go with it, so a record that exists only there is no record: copy it first.
- A worker's provider limit ends its session mid-run: complete the mechanical steps yourself
  in its worktree (the drivers are plain shell: gate, build, boot, log), then resume the worker
  with the results so it writes the body and runs the review with its own context.
- Reviewers can detach HEAD in a worker's worktree; a push then moves nothing. The worker
  checks `git status -sb` after every review.
- A boundary run that finishes late is not a hang; a 128-vCPU boot grows with every stress cell
  a PR adds and with unrelated host load. Judge PASS or HANG against the budget.
- The review loop files roughly one new Issue per merged PR; that ratio, not host time, sets
  the end of a drain. Plan the batch by Issues closed net, not PRs merged.
