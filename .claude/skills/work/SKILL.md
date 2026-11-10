---
name: work
description: Drive one Issue (or one scope) to a pull request at its merge gate in this session, following the worker rules without an orchestrator.
---

# Working one Issue

`/work <issue> [<issue> ...] [scope]` makes this session the worker for one PR. The Issue
numbers are the worker prompt's Issues. The scope is the commit-title scope that covers them,
derived from the Issues' files when not given. The branch takes the docs/conventions.md
§ Branch naming prefix that fits the work (`fix/` for a bug or security defect, `cleanup/` for
cleanup and follow-up drains, `feature/` for feature and perf work, `audit/` for an audit) and a
slug naming the scope.

Read `.claude/agents/worker.md` and follow it in **standalone** mode, with these differences:

- The session's own model and effort do the work. The tiers of
  `.claude/skills/orchestrate/SKILL.md` § Spawn say which fit the task; when the session runs
  above the tier the task needs, say so before starting, so the maintainer can restart it lower.
- There is no exclusive grant. The launch checks of the worker file's § Host runs are the whole
  protocol, and `nice` is optional.
- Reports and hand-backs are replies to the maintainer in this conversation: the plan before
  coding, the host-run results, each review's verdict lines verbatim, and the gate.
- A decision the worker file routes to the orchestrator is the maintainer's: ask in the
  conversation. `.claude/skills/orchestrate/SKILL.md` § Rulings lists the recurring ones and
  which document settles each.
- An Issue the worker file says to draft is filed with the maintainer's approval in the
  conversation, with `cargo xtask issue-file`.
- Sync onto `master` yourself right before the validation run, and again if `master` moves
  before the gate. A Markdown-only sync owes nothing.

The review records of the PR sit under `target/xtask/review/pr<N>/` in the checkout the session
works in, which is the only copy. When the session runs in a worktree, copy them into the main
checkout at the same path after the merge, since a later PR on the same surface takes them as
its ledger context; when the session cannot write there, tell the maintainer the path. The
worktree holds a built `target/` that nothing removes by itself. Once the copy exists and the
worktree holds nothing unsaved or unpushed (the second check of
`.claude/skills/orchestrate/SKILL.md` § Worktree removal), the maintainer removes it, or the
session does when asked, as that section describes.

At the gate, give both verdict lines verbatim and prompt for the merge decision. Merge only on
the maintainer's instruction.
