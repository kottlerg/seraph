---
name: pr-review
description: Run the pre-merge review of a pull request once its CI is green (the pr-reviewer and pr-auditor agents), save the run record, build the ledger, and handle the findings up to the merge prompt.
---

# The pre-merge review

docs/conventions.md § Branch and PR Workflow owns the rules: the review surface, the two tracks,
where a finding is recorded, the ledger, the auditor-only run, and the merge-prompt condition.
This skill is the procedure that applies them. `.claude/CLAUDE.md` carries the maintainer's
standing request to run it on every PR once CI is green.

## Before a run

1. `git fetch origin`. The auditor reads the PR's diff against `origin/master` and does not
   fetch.
2. Refresh the PR body to the head under review: the validated head, the Validation report, the
   Acceptance ticks, every claim.
3. `cargo xtask pr-check <N>`, and fix what it reports. It checks the commits, the body's boxes
   and validated head, and the ticks and milestone of each Issue the PR closes or references, so
   the audit spends its run on what needs a reader.
4. For every run after the first: `cargo xtask review-ledger <N>`, which writes
   `target/xtask/review/pr<N>/ledger.json` from the saved run records.

## The run

Invoke `pr-reviewer` and `pr-auditor` in parallel: one message, two `Agent` calls. Give both the
PR number and the open Issue list (`gh issue list --state open --limit 500 --json number,title`).
Give the reviewer, in addition:

- the ledger's path, once one exists;
- for a `delta` run (every run after the first), the `since` head, which is the head the last
  run with the reviewer reviewed, and the merge bases at `since` and at the head
  (`git merge-base <sha> origin/master` for each).

When docs/conventions.md § Auditor-only run allows it, the next run may be `pr-auditor` alone.
Tell it that it is that run, and give it the PR number, the `since` head, the path of the last
reviewer run's record, the fixes the round claims, and the open Issue list.

## The record

Save both agents' prose as `target/xtask/review/pr<N>/<mode>-<head>.md` and the run record as
`<mode>-<head>.json` beside it. `<mode>` is `full` for the first run, `delta` for a later run
with the reviewer, and `audit` for an auditor-only run or a re-audit; a further run at the same
head takes the suffix `-<n>`, counting from 2. `xtask/README.md` § `cargo xtask review-check`
defines the record. Four points it leaves to you:

- `stats.run` is the run's number among the PR's runs of every mode, counting from 1: one more
  than the highest `run` among the records already saved. It orders the runs, and the gate
  reads the highest one at the head; the `-<n>` suffix only keeps two file names apart.
- A finding's `status` is `unverified`, or `nit` for a nit that cannot block, or `contested`
  once the finding is put to the maintainer.
- `ledgered` holds the findings the reviewer lists under its `Ledger (not re-raised)` heading.
- In an `audit` record, `verdict` is the reviewer verdict the audit states, `findings` holds the
  surface findings of the last reviewer run that the audit lists as unfixed, each as that run's
  record states it, and `recorded`, `ledgered` and `dropped` are empty.

Run `cargo xtask review-check <N>` and fix the record until it passes: the ledger and the gate
read these files. Then give both verdict lines verbatim to the one you report to: a worker to
its orchestrator, a standalone session to the maintainer.

## Handling the findings

Handle a run's findings in one pass.

- `BLOCKING ISSUES`: fix every finding on the surface in one batch of commits, the non-blocking
  ones included.
- `NON-BLOCKING ISSUES ONLY`: record every finding on the surface on the Issue
  docs/conventions.md § Recording findings names, then prompt for the merge, offering one more
  fix round beside it. A batch default from the maintainer can settle that choice in advance.
- A finding off the surface is recorded in the same pass and not fixed.
- Before recording a finding, and after fixing one, search the open follow-up Issues of its
  scope for an item that states it (`gh issue list --state open --limit 500 --search
  '"defects found by" in:title' --json number,title`, then the titles beginning `<scope>:`).
  A finding one of them holds is recorded nowhere else, and its fix ticks that item.
- Record with `cargo xtask issue-edit <N> --body-file <file>`, from a body fetched in the same
  step. An item is a `- [ ]` line under `## Acceptance` carrying file, line, authority, fix, and
  the PR and head that reported it.
- A PR that fixes recorded items ticks each with `(fixed by PR #<M>)`, copies the ticked items
  into its own `## Acceptance`, and carries `Refs #N`; it carries `Fixes #N` only under the
  closing condition of docs/conventions.md § Follow-up Issues.
- When a scope has no rolling Issue, filing one needs the maintainer's approval. File it with
  `cargo xtask issue-file --title "<scope>: defects found by review" --label <subsystem>
  --label <class> --milestone <current> --body-file <file>`.
- `AUDIT FAIL`: fix each item with `gh pr edit`, `cargo xtask issue-edit`, or a commit, and
  re-run the audit.
- A finding you dispute is contested: put it to the maintainer, and resolve it as
  docs/conventions.md § Contested findings says. Never waive one.

Before pushing a fix, for every fact it changes (a symbol, a constant, a rule sentence, a
section name) walk the `## Summarized By` lists (docs/documentation-standards.md § Change
propagation procedure) and `git grep -n` the tree for every other statement of it. Update each
copy in the same push.

## After a fix round

Once the fixes are pushed and CI is green again, run a `delta` run, or the auditor-only run when
§ Auditor-only run allows it. Any later delta that changes anything but documentation or
comments, or that merges `master` in, takes a run with the reviewer, its `since` the head of the
last run with the reviewer.

## The merge prompt

Prompt for the merge only when `cargo xtask pr-check <N> --gate` passes. After a
`NON-BLOCKING ISSUES ONLY` run, read its warning and confirm that each finding it counts is
recorded and none is contested. The merge command is `gh pr merge <N> --merge --delete-branch`
(docs/conventions.md § Merge method), run only on the maintainer's instruction.
