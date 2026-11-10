# The release review

Supporting file of `.claude/skills/orchestrate/SKILL.md` § Release review.

When the current milestone is ready to close, run the release review of docs/conventions.md
§ Release Production. Workers cannot call the Workflow tool, so it is the one review this
session runs as a workflow. Its agents resolve from the definitions the session loaded at its
start, so run it in a session started after those files are on the checked-out branch.

- `git fetch origin` and check out `origin/master`, clean. Run
  `Workflow({name: "release-review", args: {mode: "scope", from: "<previous tag>", version:
  "<X.Y.Z>"}})` and read the plan, then the same with `mode: "full"`. When the script changed
  since the session loaded it, pass `scriptPath` with the file's path instead of `name`.
- Save each run's report as `target/xtask/review/release-v<X.Y.Z>/<mode>-<head>.md`, the
  returned object as `<mode>-<head>.json` beside it, and on `RELEASE READY` the `notes` field as
  `notes-<head>.md`. Give both verdict lines to the maintainer verbatim.
- `RELEASE BLOCKED`: each blocking finding goes to a worker as a fix PR, a `[carried]` entry and
  a fresh entry beside it that state the same defect counting as one, and each audit failure to
  its fix. Record every other finding as step 2 of that section says. Then run `mode: "delta"`
  with `since` the head the last run reviewed.
- `RELEASE READY` before the bump: a worker opens the release PR from the draft (step 3). Once
  it merges, run the release host runs (step 4) yourself under an exclusive grant to yourself,
  write their report to `target/xtask/review/release-v<X.Y.Z>/host-runs.md`, and run
  `mode: "delta"` with `host_runs` that path. `RELEASE READY` at the bumped head is a tag prompt
  to the maintainer (step 5).
