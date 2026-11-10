# Removing a worker's worktree

Supporting file of `.claude/skills/orchestrate/SKILL.md` § Worktree removal.

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
