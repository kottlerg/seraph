# The release review

Supporting file of `.claude/agents/orchestrator.md` § Release review.

When the current milestone is ready to close, run the release review of docs/conventions.md
§ Release Production. Only the top session has the Workflow tool, so the supervisor makes each
workflow call for you: send it the exact call and the paths to save to, and it answers with the
two verdict lines and the paths. The workflow's agents resolve from the definitions the top
session loaded at its start, so the release review needs a session started after those files
are on the checked-out branch; say so to the maintainer if the session is older.

- `git fetch origin` and check out `origin/master`, clean. The first call is
  `Workflow({name: "release-review", args: {mode: "scope", from: "<previous tag>", version:
  "<X.Y.Z>"}})`; read the plan it saved, then ask for the same with `mode: "full"`. When the
  script changed since the session loaded it, the call passes `scriptPath` with the file's path
  instead of `name`.
- The supervisor saves each run's report as
  `target/xtask/review/release-v<X.Y.Z>/<mode>-<head>.md`, the returned object as
  `<mode>-<head>.json` beside it, and on `RELEASE READY` the `notes` field as `notes-<head>.md`.
  Both verdict lines go to the maintainer verbatim: the release is their step.
- `RELEASE BLOCKED`: each blocking finding goes to a worker as a fix PR, and each audit failure
  to its fix. A `[carried]` entry and a fresh entry that state the same defect count as one
  finding. Record every other finding as step 2 of that section says. Then run `mode: "delta"`
  with `since` the head the last run reviewed.
- `RELEASE READY` before the bump: a worker opens the release PR from the draft (step 3). Once
  it merges, run the release host runs (step 4) yourself under an exclusive grant to yourself,
  write their report to `target/xtask/review/release-v<X.Y.Z>/host-runs.md`, and run
  `mode: "delta"` with `host_runs` that path. `RELEASE READY` at the bumped head is a tag prompt
  to the maintainer (step 5).
