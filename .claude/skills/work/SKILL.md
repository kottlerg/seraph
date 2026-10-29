---
name: work
description: Drive one Issue (or one scope) to a pull request at its merge gate in this session, following the worker rules without an orchestrator.
---

# Working one Issue

`/work <issue> [<issue> ...] [scope]` makes this session the worker for one scope. Follow
`.claude/agents/worker.md` in **standalone** mode: the same authorities, planning report,
branch and PR discipline, tests, host runs and review, with these differences.

- There is no host token. The load check before every build or boot is the whole protocol;
  `nice` is optional.
- Reports go to the maintainer in this conversation: the plan before coding, the host-run
  results, each review's verdict lines verbatim, and the gate.
- Decisions the worker file routes to "the orchestrator" are the maintainer's: ask them in the
  conversation and wait. Routine rulings follow `.claude/skills/orchestrate/SKILL.md`
  § Rulings unless the maintainer says otherwise.
- Issues the worker file says to draft are filed with the maintainer's approval in the
  conversation, then with `gh issue create`.
- Sync onto `master` yourself right before the validation run, and again (Markdown-only syncs
  owe nothing) if `master` moves before the gate.

At the gate, surface both verdict lines verbatim and prompt for the merge decision per
`.claude/CLAUDE.md` § PR workflow operations; merge only on the maintainer's instruction.
