# Removing a worker's worktree

Supporting file of `.claude/agents/orchestrator.md` § Worktree removal.

A worker's worktree carries a built `target/` of several GiB. The harness removes only an
unchanged worktree, so every other one persists until you remove it. Remove only worktrees this
batch spawned and the record lists (the state, or the log for a worker that
`cargo xtask orch worker <name> --remove` has taken out of the state), in two places:

- **At a worker's retirement:** after its last PR merges (or its gate report, when it has no PR
  left to merge) and nothing is left for it. A worktree parked on a `park/<name>` branch for a
  composition check is removed once nothing is left for its worker: the check has handed back
  and leaves it no PR, having found no defect or recorded each on an open Issue. A defect that
  becomes the worker's next PR keeps the worktree until that PR merges and the composition
  check its merge owes, when it owes one, hands back the same way.
- **At wind-down:** every worktree the record lists that is still present, after confirming no
  active worker owns it.

Before removing one, check both conditions, and skip and report a worktree that fails either:

- The records are in your checkout: `target/xtask/review/pr<N>/` holds the records of every run
  the worker reported. They exist nowhere else once the worktree is gone.
- Nothing is unsaved or unpushed: `git -C <path> status --porcelain` prints nothing, and after
  `git fetch origin`, every commit `git -C <path> rev-list HEAD --not --remotes=origin` prints
  (none, when nothing is unpushed) passes one of two tests, each passed by an exit status of 0:
  - It changes no file, a park or keep-alive commit:
    `git -C <path> diff --quiet <commit>^ <commit>`.
  - Its tree is the tree of a commit reachable from `origin`, the state an approved history
    rewrite leaves, whose content was pushed under another commit:

    ```
    tree=$(git -C <path> rev-parse <commit>^{tree})
    git -C <path> log --remotes=origin --format=%T | grep -qxF "$tree"
    ```

  A commit that passes neither is unpushed work, and the worktree fails the check.

Remove with `git worktree remove --force --force <path>` (the harness locks agent worktrees, and
a locked worktree refuses a single `--force`), run `git worktree prune` once after a sweep, and
record each removal with the worktree's size (`du -sh <path>`, taken first). A worktree under
`.claude/worktrees/` that the record does not list is reported to the maintainer with its branch
and lock, and removed only on their word.
