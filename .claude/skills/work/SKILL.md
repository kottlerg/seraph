---
name: work
description: Drive one Issue (or one scope) to a pull request at its merge gate in this session, following the worker rules without an orchestrator.
---

# Working one Issue

`/work <issue> [<issue> ...] [scope]` makes this session the worker for one scope: the Issue
numbers are the worker prompt's Issues, the scope is the commit-title scope that covers them
(derived from the Issues' files when not given), and the branch name takes the
docs/conventions.md § Branch naming prefix that matches the work's purpose (`fix/` for a bug
or security defect, `cleanup/` for cleanup and follow-up drains, `feature/` for feature and
perf work, `audit/` for an audit) and a slug naming the scope. Follow `.claude/agents/worker.md`
in **standalone** mode: the same authorities, planning report, branch and PR discipline, tests,
§ Delegation, host runs and review, with these differences.

- There is no exclusive grant. The launch checks of the worker file's § Host runs are the
  whole protocol; `nice` is optional.
- Reports go to the maintainer in this conversation: the plan before coding, the host-run
  results, each review's verdict lines verbatim, and the gate.
- Decisions the worker file routes to "the orchestrator" are the maintainer's: ask them in the
  conversation and wait. `.claude/skills/orchestrate/SKILL.md` § Rulings lists the recurring
  ones and which document settles each.
- Issues the worker file says to draft are filed with the maintainer's approval in the
  conversation, then with `gh issue create`.
- Sync onto `master` yourself right before the validation run, and again (Markdown-only syncs
  owe nothing) if `master` moves before the gate.
- The review runs as the worker file's § Review says, its auditor-only run included: when the
  last run with the reviewer had no failed agent and the fix round's delta since it is
  documentation or comments only and merges no `master` in, run `pr-auditor` alone with that
  run's record, save `audit-<head>.md` and `audit-<head>.json` in the shape that section
  gives, and surface the reviewer verdict the audit states beside the audit line.

This session's worktree, when the session runs in one, holds a built `target/` that nothing
removes by itself, since the harness removes only an unchanged worktree
(`.claude/agents/worker.md` § Reporting). The review records of the PR sit under
`target/xtask/review/pr<N>/` in the checkout the session works in, which is the only copy.
After the merge, and not before, the session copies the records into the main checkout at the
same path (a later PR on the same surface takes them as its ledger context); when its sandbox
refuses that write, the gate report names the worktree's path and the maintainer copies. Once
the copy exists, the maintainer removes the worktree (`git worktree remove --force --force
<path>` from the main checkout, the doubled flag because the harness locks the worktree, then
`git worktree prune`), or the session does so when the maintainer asks it to.

At the gate, surface both verdict lines verbatim and prompt for the merge decision per
`.claude/CLAUDE.md` § PR workflow operations; merge only on the maintainer's instruction.
