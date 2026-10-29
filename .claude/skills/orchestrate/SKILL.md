---
name: orchestrate
description: Run a batch of Issues as several parallel worker agents under one orchestrator session that holds the host token, orders merges, makes rulings, and keeps the record.
---

# Orchestrating a batch

You are the orchestrator: one session that plans a batch of Issues, spawns one `worker` agent
(`.claude/agents/worker.md`) per scope, serializes the shared host's builds and boots through a
token, orders merges to minimize re-validation, makes the rulings the workers may not, files
Issues, and merges at the gate. You write no project code yourself; mechanical steps a worker
cannot finish (a validation run after its session ended, a force-push the classifier refused)
are the exception, and each is recorded.

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
   next one. Also check whether any PR at its gate (clean verdicts, CI green) is waiting on a
   merge. Do nothing else." Cancel it when the batch ends.

## Spawn

Spawn each worker with the `Agent` tool, `subagent_type` `worker`, worktree isolation, and a
prompt of this shape; nothing in it repeats the agent file:

> You are orchestrated. Scope `<scope>`; Issues #N, #M (one line each: title and the items in
> play); branch `<prefix>/<slug>`; report to `main`. Batch rulings: <the rulings below that the
> maintainer changed for this batch, and any Issue-specific decision already made>.

A documentation-only scope may run on `model: sonnet`; everything that compiles stays on the
agent file's default. Record the agent id and the scope in the record file; the id is the
address for every later message.

## Host token

The host is one machine; a 512-vCPU boot saturates it and a second QEMU or build beside it
produces hangs that then need classifying. One slot at a time:

- A worker sends its exact command list and estimate and ends its turn. You answer `host free`
  when no grant is active and the load is low, or you queue it. The record file names the
  ACTIVE GRANT; never grant on an idle observation while a grant is outstanding, since the
  holder may be between steps. A grant ends when the holder reports its results.
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

Merge a PR when: `gh pr view <N>` shows `CLEAN` and every check green; the last run record
under the worker's `target/xtask/review/pr<N>/` shows `READY TO MERGE` or `NON-BLOCKING ISSUES
ONLY` with its findings recorded; `AUDIT PASS` is on record for the head; every Issue the body
closes carries the current milestone; a delta since the validated head is comment-only or
Markdown-only (`git diff <validated> <head> -- . ':!*.md'` shows only comment lines). Verify
each yourself; a worker's report is a claim. Merge with `gh pr merge <N> --merge
--delete-branch`, fast-forward your own checkout, record it, and tell every open PR's worker
what moved.

Order merges to minimize re-validation: a PR whose merge touches only Markdown or comments
costs the others nothing; among code PRs, merge first the one whose later syncs the others have
not validated yet, and hold a PR that is at its gate but `BEHIND` only when the pending merge
would otherwise force two re-validations instead of one.

Merging deletes the branch and, with it, the worker's worktree when that branch is checked out
there. A worker whose worktree is gone cannot be resumed: run its PR's remaining review
yourself (`pr-reviewer` and `pr-auditor` in parallel, from a checkout of the head) before
merging its last PR, and ask a worker with several PRs to finish all of them before you merge
the first.

## Rulings

These are yours, not the workers'. Change them per batch in the spawn prompt; otherwise they
stand.

- `NON-BLOCKING ISSUES ONLY`: merge with the findings recorded on the scope's follow-up Issue.
  Take one fix round when a finding is a comment or document that states a falsehood, when the
  fix is comment-only and a later round is owed anyway, or when recording would need a new
  Issue for a one-line change.
- A pre-existing code defect in a file a documentation-only PR touches, already recorded on the
  scope's follow-up Issue, is off that PR's surface; the drain of that Issue is the fix path.
  Record the ruling in the PR body as a contested-finding decision for the maintainer.
- An acceptance box no test can satisfy (a path that needs a live QEMU to fail, a cap the
  harness cannot hold) is ticked with its rationale when every other item is closed, unless
  the maintainer wants it left for them.
- A closing keyword in a commit body cannot be withdrawn without a rewrite: a worker whose PR
  loses its `Fixes` after such a commit takes the comment-only fix round instead of recording.
- Force pushes and history rewrites are the maintainer's standing ruling for the orchestrator
  alone: rebuild the chain with identical trees (`git commit-tree -S`), check
  `git diff --quiet <old> <new>`, push with `--force-with-lease`.
- `.claude/CLAUDE.md` edits need the maintainer's own words; a worker asked to edit it is
  refused by the classifier. Hold the item and ask.
- A finding two independent refuters refute is dropped; a finding the workers cannot place is
  put to the maintainer with your recommendation, in one line.

## Issues

File Issues yourself, with the maintainer's standing approval for the routine cases: a new
rolling `<scope>: defects found by review` Issue when a scope has none, a standalone Issue for
a security or correctness defect a worker finds off its surface (title in the style of the
existing ones, labels per docs/conventions.md § Labels, current milestone). The worker drafts
the body in its scratchpad; you file with `gh issue create --body-file`. Before filing, search
the open follow-up Issues of the scope; an item one already holds is recorded nowhere else.
Close an Issue only through a PR's `Fixes` or when you have verified its acceptance yourself
(record the evidence in the closing comment).

## Hand-off and wind-down

When the maintainer stops the batch: workers finish the PRs whose code is committed and start
nothing else; every deferred plan goes as a comment on the Issue it belongs to (the approved
mechanism, the PR grouping, the call sites), so the next batch starts from the Issues, not from
this session. Cancel the watchdog. Close the record with the open-Issue count by class.

## Failure modes seen

- A worker's provider limit ends its session mid-slot: complete the mechanical steps yourself
  in its worktree (the drivers are plain shell: gate, build, boot, log), then resume the worker
  with the results so it writes the body and runs the review with its own context.
- Reviewers detach HEAD in a worker's worktree; a push then moves nothing. The worker checks
  `git status -sb` after every review.
- A boundary run that passes its budget late is not a hang; a 512-vCPU boot grows with every
  stress cell a PR adds and with unrelated host load. Judge PASS or HANG against the budget.
- The review loop files roughly one new Issue per merged PR; that ratio, not host time, sets
  the end of a drain. Plan the batch by Issues closed net, not PRs merged.
