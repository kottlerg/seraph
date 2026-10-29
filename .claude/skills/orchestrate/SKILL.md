---
name: orchestrate
description: Run a batch of Issues as several parallel worker agents under one orchestrator session that holds the host token, orders merges, carries rulings to the maintainer, and keeps the record.
---

# Orchestrating a batch

You are the orchestrator: one session that plans a batch of Issues, spawns one `worker` agent
(`.claude/agents/worker.md`) per scope, serializes the shared host's builds and boots through a
token, orders merges to minimize re-validation, carries the workers' questions to the
maintainer, files the Issues the maintainer approves, and executes merges the maintainer has
decided. You write no project code yourself; mechanical steps a worker cannot finish (a
validation run after its session ended, a history rewrite the maintainer asked for) are the
exception, and each is recorded.

Everything in this file applies `.claude/CLAUDE.md`, docs/conventions.md and docs/testing.md;
nothing in it grants an authority those documents reserve to the maintainer. Three decisions
are the maintainer's by those documents; ask for all three in your first message and quote the
answers in the record file. Until an answer arrives, each case below is a prompt to the
maintainer when it comes up:

1. **Merges.** Per `.claude/CLAUDE.md` § PR workflow operations the merge is the maintainer's
   call per PR. For a batch the maintainer may give a standing instruction in their own words
   ("merge at the gate without asking", with any conditions); without one, every PR at its gate
   is a merge prompt to the maintainer, and the batch pauses on it.
2. **Non-blocking findings.** After a `NON-BLOCKING ISSUES ONLY` run the merge prompt offers the
   merge or one more fix round (docs/conventions.md § Branch and PR Workflow). The maintainer
   may set a batch default (see § Rulings); without one, each case is a question.
3. **Issue filing.** New Issues need the maintainer's approval (`.claude/CLAUDE.md`
   § Completeness). The maintainer may approve the routine cases for the batch in advance (a
   rolling follow-up Issue when a scope has none; a standalone Issue for a defect found off a
   PR's surface); without that, each is a question with the drafted body.

## Plan

1. `gh issue list --state open --milestone <current> --limit 500 --json number,title,labels`.
   Classify: follow-up and defect lists (drain scopes), single defects (group by the surface
   they touch, two to seven per PR), design and feature Issues (the maintainer's unless the
   batch names them). The maintainer names the batch's goal; you name the scopes.
2. Size the wave at four to six PRs in flight. Each merge forces every open PR to re-sync, and
   a sync that brings non-comment code re-owes that PR's validation set, so more parallelism
   past that point costs more host time than it saves.
3. Start the record: `target/xtask/orchestration/<date>.md` (gitignored). Every grant, merge,
   ruling, filed Issue and agent id goes there with a timestamp; after a context compaction
   it is the state.
4. Schedule the watchdog (`CronCreate`, every 20 minutes) with this prompt:
   "Orchestration watchdog tick: check the ACTIVE GRANT recorded in
   `target/xtask/orchestration/<date>.md` against the host (`cat /proc/loadavg`;
   `pgrep -af qemu-system`) and the holder's expected duration. If the host is idle and the
   holder has not reported for longer than its slot should take, ping the holder for a status
   report; if the host is idle with no active grant and a queued request exists, grant the
   next one. Call `ListAgents` and compare it against the worker ids the record lists as
   active; a worker that is not listed, whose last report was not its gate and whose worktree
   is gone (`git worktree list`), is dead: log it, send it the stand-down message and end its
   task where the harness allows (§ Spawn), and respawn it with its plan and every answer
   already given folded into the prompt. A worker that is not listed, whose last report was not
   its gate and that awaits no answer or grant, but whose worktree remains, is sent a message
   asking for a status report. Also check whether any PR at its gate (clean verdicts, CI green)
   is waiting on a merge. Do nothing else." Cancel it when the batch ends.

## Spawn

Spawn each worker with the `Agent` tool, `subagent_type` `worker`, worktree isolation, and a
prompt of this shape; nothing in it repeats the agent file:

> You are orchestrated. Scope `<scope>`; Issues #N, #M (one line each: title and the items in
> play); branch `<prefix>/<slug>`; report to `main`. Batch rulings: <the rulings below that the
> maintainer changed for this batch, and any Issue-specific decision already made>.

A documentation-only scope may run on `model: sonnet`; everything that compiles stays on the
agent file's default. Record the agent id, the scope, the branch, the worktree path and, once
opened, the PR number in the record file; the id is the address for every later message, and
the record lists it as active until the worker's last PR merges or a respawn replaces it.

A respawn prompt also carries the dead worker's classified item list, its mechanism choices and
every answer already given, marked as decisions already made, so the new worker neither
re-plans nor re-asks, and names the dead worker's branch and PR when either exists, for the new
worker to continue on. Before or with the respawn, send the replaced worker a stand-down
message (its PR and branch now belong to the new worker; it edits, commits and pushes nothing
further, per `.claude/agents/worker.md` § Reporting), and end that worker's task where the
harness allows, so a worker presumed dead that resumes does not push over its replacement.

## Host token

The host is one machine; a 512-vCPU boot saturates it and a second QEMU or build beside it
produces hangs that then need classifying. One slot at a time:

- A worker sends its exact command list and estimate and ends its turn. You answer `host free`
  when no grant is active and the load is low (`cat /proc/loadavg`, `pgrep -af qemu-system`),
  or you queue it. The record file names the ACTIVE GRANT; never grant on an idle observation
  while a grant is outstanding, since the holder may be between steps. A grant ends when the
  holder reports its results.
- `master quiet` tells a worker to sync now, right before its slot, so one run covers the sync.
  Say it when no merge will land before that worker's gate; otherwise hold the worker and let
  the pending merge land first.
- Queue order: validation-only rounds of PRs already at their gates first (they merge soonest
  and free the others from a further sync), then first rounds of new PRs, then the long
  boundary sets. A boundary set runs once per PR, at a head whose own non-inert surface lines
  are final, usually after the first review batch; CI's build and boot cells cover compile,
  clippy and the 4-CPU boots meanwhile, so the first local slot is not urgent.
- Workers run builds and boots under `nice -n 10`; your own commands do not need it.

## Merge order and the gate

A PR is at its gate when: `gh pr view <N> --json mergeStateStatus,statusCheckRollup` shows
`CLEAN` and every check green (docs/conventions.md § CI Gating, § Branch protection); the
merge-prompt condition of its § Branch and PR Workflow holds, that is, the last run record
under the worker's `target/xtask/review/pr<N>/` is a completed run with no failed agent whose
verdict is `READY TO MERGE`, or `NON-BLOCKING ISSUES ONLY` with every surface finding recorded
and no contested finding on the surface unresolved, and `AUDIT PASS` is on record for the
head; every Issue the body closes carries the current milestone (§ Milestones); and a delta
since the validated head is comment-only or Markdown-only (§ PR-body checklist discipline;
`git diff <validated> <head> -- . ':!*.md'` shows only comment lines). Verify each part
yourself, since a worker's report is a claim. Then prompt the maintainer, or merge under their
standing instruction, with `gh pr merge <N> --merge --delete-branch`; fast-forward your own
checkout, record it, and tell every open PR's worker what moved.

Order merges to minimize re-validation: a PR whose merge touches only Markdown or comments
costs the others nothing; among code PRs, merge first the one whose later syncs the others have
not validated yet, and hold a PR that is at its gate but `BEHIND` only when the pending merge
would otherwise force two re-validations instead of one.

`--delete-branch` removes the remote branch, and a worker whose worktree sits on that branch
may no longer be resumable afterwards. Before merging a worker's last PR, make sure nothing is
left for it: ask a worker with several PRs to bring all of them to their gates first, and if a
review is still owed after the branch is gone, run it yourself (`pr-reviewer` and
`pr-auditor` in parallel, from a checkout of the head).

## Rulings

Workers bring you the decisions they may not make. Those below are the recurring ones; each
is either settled by the documents (then you apply the document) or by the maintainer (then
you ask, once per batch where a standing answer makes sense, and quote it in the record).
A worker's question that neither a document nor this skill reserves to the maintainer and whose
recommendation you share is decided: answer it and surface the decision to the maintainer in
your next message. Beyond the reserved questions, only a split recommendation, a major design
decision, or a case with no clearly best option waits for the maintainer.

- `NON-BLOCKING ISSUES ONLY`: the worker records the surface findings on the scope's
  follow-up Issue; the merge prompt then offers the merge or one more fix round. A batch
  default the maintainer may set: one fix round when a finding is a comment or document that
  states a falsehood, when the fix is comment-only and a later round is owed anyway, or when
  recording would need a new Issue for a one-line change; otherwise merge with the record.
  Standing, by the maintainer's ruling of 2026-10-30 ("If you are confident that it won't cause
  broad process issues going forwards, then I can approve that those nits after a ready to
  merge will go on the rolling issue for that scope.", then "approved" to the orchestrator's
  precise statement of it): a run whose findings are all nits takes no fix round;
  the worker records them on the scope's follow-up Issue (the Issue the PR drains in that
  scope, else the rolling Issue, as docs/conventions.md § Branch and PR Workflow defines it)
  and reports the gate, except that a PR draining a follow-up Issue of that scope records its
  nits-only findings there and fixes them in the same PR, ticking each `(fixed by PR #<M>)`.
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
  check `git diff --quiet <old> <new>`, push with the lease pinned to the old head
  (`git push --force-with-lease=<branch>:<old> origin <new>:refs/heads/<branch>`, which refuses
  whenever the remote branch is not at `<old>`), and record it.
- `.claude/CLAUDE.md` edits need the maintainer's own words. A worker whose change has a copy
  there reports it and holds its push; you carry the copy to the maintainer, who applies it or
  authorizes the worker in their own words, which you pass on verbatim.
- A finding two independent refuters refute is dropped (that section); a finding the workers
  cannot place is put to the maintainer with your recommendation, in one line.

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

## Hand-off and wind-down

When the maintainer stops the batch: workers finish the PRs whose code is committed and start
nothing else; every deferred plan goes as a comment on the Issue it belongs to (the approved
mechanism, the PR grouping, the call sites), so the next batch starts from the Issues, not from
this session. Cancel the watchdog. Close the record with the open-Issue count by class.

## Failure modes

- A worker that ends its turn on an unchanged worktree is gone: the harness removes the
  worktree, and a later message does not resume it. The worker's turn-ending rule
  (`.claude/agents/worker.md` § Reporting) prevents it; the watchdog's liveness check (§ Plan
  step 4) and the respawn prompt (§ Spawn) recover from it.
- A worker's provider limit ends its session mid-slot: complete the mechanical steps yourself
  in its worktree (the drivers are plain shell: gate, build, boot, log), then resume the worker
  with the results so it writes the body and runs the review with its own context.
- Reviewers can detach HEAD in a worker's worktree; a push then moves nothing. The worker
  checks `git status -sb` after every review.
- A boundary run that finishes late is not a hang; a 512-vCPU boot grows with every stress cell
  a PR adds and with unrelated host load. Judge PASS or HANG against the budget.
- The review loop files roughly one new Issue per merged PR; that ratio, not host time, sets
  the end of a drain. Plan the batch by Issues closed net, not PRs merged.
