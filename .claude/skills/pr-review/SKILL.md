---
name: pr-review
description: Run the pre-merge review of a pull request once its CI is green (the pr-reviewer and pr-auditor agents), save the run record, build the ledger, and handle the findings up to the merge condition.
---

# The pre-merge review

docs/conventions.md § Branch and PR Workflow owns the rules: what a finding is (a defect), the
review surface, the rounds, where a defect is recorded, the ledger, the auditor-only run, and the
merge condition.
This skill is the procedure that applies them. `.claude/CLAUDE.md` carries the maintainer's
standing request to run it on every PR once CI is green.

## Before a run

1. `git fetch origin`. The auditor reads the PR's diff against `origin/master` and does not
   fetch.
2. Refresh the PR body to the head under review: the validated head, the Validation report, the
   Acceptance ticks, every claim.
3. `cargo xtask pr-check <N>`, and fix what it reports. It checks the commits, the body's boxes
   and validated head, the ticks of each Issue the PR closes or references, and the milestone
   of each it closes, so the audit spends its run on what needs a reader.
4. For every run after the first: `cargo xtask review-ledger <N>`, which writes
   `target/xtask/review/pr<N>/ledger.json` from the saved run records.

## The run

Invoke `pr-reviewer` and `pr-auditor` in parallel: one message, two `Agent` calls. Give both the
PR number and the open Issue list (`gh issue list --state open --limit 500 --json number,title`).
Give the reviewer, in addition:

- the ledger's path, once one exists. The ledger of a previous PR on the same surface, when
  the spawn prompt names one, goes to the first run as that PR's settled findings, for context
  and not as this PR's ledger: a finding it lists that stands on this PR's surface is still
  reported and counted;
- for a `delta` run (every run after the first), the `since` head, which is the head the last
  run with the reviewer reviewed, the path of that run's record, the fixes the round claims,
  and the merge bases at `since` and at the head (`git merge-base <sha> origin/master` for
  each). It judges only those fixes and the delta's own change (docs/conventions.md § Rounds),
  and, when a sync owes the run, how the sync composes with the PR's change: say so;
- for the fix PR of a release review (docs/conventions.md § Release Production step 2), the
  list of defects it fixes, and that this run is the release fix verification.

While the PR body's `## Validation` section reports a run as pending, make the run with
`pr-reviewer` alone (docs/conventions.md § Pre-merge review): the audit would fail on that item
alone. Once the runs are reported, the audit is owed. When a fix round has moved the head, it
runs with the next run. When the head is the one the reviewer reviewed, run `pr-auditor` alone
on it as the audit that completes that run, not as the auditor-only run below: give it the path
of the reviewer-alone record, and save it as an `audit` record.

When docs/conventions.md § Auditor-only run allows it, the next run may be `pr-auditor` alone.
Tell it that it is that run, and give it the PR number, the `since` head, the path of the last
reviewer run's record, the fixes the round claims, and the open Issue list.

## The record

Save both agents' prose as `target/xtask/review/pr<N>/<mode>-<head>.md` and the run record as
`<mode>-<head>.json` beside it. `<mode>` is `full` for the first run, `delta` for a later run
with the reviewer, and `audit` for an auditor-only run, the audit that completes a run of the
reviewer alone, or a re-audit; a further run at the same
head takes the suffix `-<n>`, counting from 2. `xtask/README.md` § `cargo xtask review-check`
defines the record. Six points it leaves to you:

- `stats.form` is `defects`, and each finding carries `file`, `line`, `status`, `issue`,
  `claim`, and `fix`, with no class or bucket.
- `stats.run` is the run's number among the PR's runs of every mode, counting from 1: one more
  than the highest `run` among the records already saved. It orders the runs, and the gate
  reads the highest one at the head; the `-<n>` suffix only keeps two file names apart.
- A finding's `status` is `unverified`, or `contested` once the author disputes it.
- `findings` holds the reviewer's defect list, `recorded` its `Out of bound (recorded)` list,
  and `ledgered` its `Ledger (not re-raised)` list.
- In an auditor-only `audit` record, `verdict` is the reviewer verdict the audit states and
  `findings` holds the defects of the last reviewer run that the audit lists as unfixed, each as
  that run's record states it. In the `audit` record that completes a run of the reviewer alone,
  `verdict` and `findings` are that run's, as its record states them. In both, `recorded`,
  `ledgered` and `dropped` are empty.
- A run of the reviewer alone, made while the PR body reports a run as pending, is a `full` or
  `delta` record with `audit_verdict` `NOT RUN` and `audit` `null`. The gate still needs
  `AUDIT PASS` in the last record at the head, so the audit it leaves owed is a later `audit`
  record there.

Run `cargo xtask review-check <N>` and fix the record until it passes: the ledger and the gate
read these files. Then give both verdict lines verbatim to the one you report to: a worker to
its orchestrator, a standalone session to the maintainer.

## Handling the findings

Handle a run's findings in one pass.

- `BLOCKING ISSUES`: fix every defect on the surface in one batch of commits, then run a
  `delta` run (§ After a fix round).
- `READY TO MERGE`: go to the gate.
- A defect off the surface (the `Out of bound (recorded)` list) is recorded in the same pass
  on the Issue docs/conventions.md § Recording findings names, and not fixed.
- Before recording a defect, and after fixing one, search the open follow-up Issues of its
  scope for an item that states it (`gh issue list --state open --limit 500 --search
  '"defects found by" in:title' --json number,title`, then the titles beginning `<scope>:`).
  A defect one of them holds is recorded nowhere else, and its fix ticks that item.
- Record with `cargo xtask issue-edit <N> --body-file <file>`, from a body fetched in the same
  step. An item is a `- [ ]` line under `## Acceptance` carrying file, line, authority, fix, and
  the PR and head that reported it.
- A PR that fixes recorded items ticks each with `(fixed by PR #<M>)`, copies the ticked items
  into its own `## Acceptance`, and carries `Refs #N`; it carries `Fixes #N` only under the
  closing condition of docs/conventions.md § Follow-up Issues.
- When a scope has no rolling Issue, one is filed without asking the maintainer
  (docs/conventions.md § Follow-up Issues): a worker drafts the body and its orchestrator
  files it, and a standalone session files it itself. The command is
  `cargo xtask issue-file --title "<scope>: defects found by review" --label <subsystem>
  --label <class> --milestone <current> --body-file <file>`.
- `AUDIT FAIL`: fix each item with `gh pr edit`, `cargo xtask issue-edit`, or a commit, and
  re-run the audit.
- A finding you dispute is contested: put it to the one docs/conventions.md § Contested
  findings names (a worker to its orchestrator, a standalone session to the maintainer), and
  resolve it as that section says. Never waive one. A finding that is not a defect as
  docs/conventions.md § Findings defines one is disputed on that rule.

Before pushing a fix, for every fact it changes (a symbol, a constant, a rule sentence, a
section name) walk the `## Summarized By` lists (docs/documentation-standards.md § Change
propagation procedure) and `git grep -n` the tree for every other statement of it. Update each
copy in the same push.

## After a fix round

Once the fixes are pushed and CI is green again, run a `delta` run, or the auditor-only run when
§ Auditor-only run allows it. Any later delta that changes anything but documentation or
comments, or that holds a sync owing a reviewer run (docs/conventions.md § Syncing with
`master`), takes a run with the reviewer, its `since` the head of the last run with the
reviewer.

## The merge condition

The PR meets the merge condition of docs/conventions.md § Pre-merge review when
`cargo xtask pr-check <N> --gate` passes. When it prints `gate-defects-recorded`, confirm that
each defect a run recorded off the surface is on its Issue before the merge. For a PR whose
records are of the earlier form, read its `gate-findings-recorded` warning, when it prints one,
and confirm that each finding it counts is recorded and none is contested. For the
release PR the command prints `gate-release-approval`: that PR meets the condition only once the
maintainer has approved its merge. A worker then hands its gate report to the orchestrator,
which verifies the gate and merges. A standalone session tells the maintainer that the PR meets
the condition and merges on their instruction. The merge command is
`gh pr merge <N> --merge --delete-branch` (docs/conventions.md § Merge method).

After the merge, the composition check of docs/conventions.md § Composition check is owed when
the merge shares a file with another merge since the previous release tag: the orchestrator
asks the PR's worker for it, and a standalone session runs it itself.
