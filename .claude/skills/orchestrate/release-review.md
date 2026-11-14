# The release review

Supporting file of `.claude/agents/orchestrator.md` § Release review.

When the current milestone is ready to close, run the release review of docs/conventions.md
§ Release Production. Only the top session has the Workflow tool, so the supervisor makes each
workflow call for you: send it the exact call and the paths to save to, and it answers with the
two verdict lines and the paths. This is the one place where an instruction-file merge needs a
new session (`.claude/agents/orchestrator.md` § Plan). The workflow's agents resolve from the
definitions the top session loaded at its start, and the script's prompts do not tell them to
read their file from disk, so a changed `release-auditor` or `release-verifier` definition needs a
session started after the change is on the checked-out branch; say so to the maintainer when
the session is older. A changed `.claude/workflows/release-review.js` needs no new session: the
call passes `scriptPath`, below.

- `git fetch origin` and check out `origin/master`, clean. The first call is
  `Workflow({name: "release-review", args: {mode: "scope", from: "<previous tag>", version:
  "<X.Y.Z>"}})`: it returns the plan and the agent count before verification, which grows by
  two per defect that can block. The scope is read from `cargo xtask release-scope` and checked
  against the range; a call that returns an `error` instead of a plan made none, and the error
  goes to the maintainer before any other call. Send the count to the maintainer with the
  ceiling you propose (`max_agents`, 250 by default), then ask for the same call with
  `mode: "full"` and that `max_agents`. When the script changed since the session loaded it,
  the call passes `scriptPath` with the file's path instead of `name`. The release review runs
  once; it is not run again over the fixes.
- The supervisor saves each run's report as
  `target/xtask/review/release-v<X.Y.Z>/<mode>-<head>.md`, the returned object as
  `<mode>-<head>.json` beside it, and the `notes` field as `notes-<head>.md`. Both verdict
  lines go to the maintainer verbatim: the steps that follow need their approval.
- The run's list goes to the maintainer as one message (docs/conventions.md § Release
  Production step 2): the blocking defects, recommended for a fix before the tag; the defects
  that predate the range and those an open Issue names, recommended as known issues; the
  contested and unverified ones, undecided. A run that reached its ceiling says so, and the
  maintainer decides whether it goes on with a higher `max_agents`. Save each decision on a
  contested or unverified entry of the saved record as its `ruling`, so the release ledger
  (`cargo xtask review-ledger --release`) takes it.
- The defects the maintainer decides to fix go to one worker as one fix PR, told that its
  review is the release fix verification (the `pr-review` skill § The run). Each defect they
  decide to ship gets an open Issue that names it, filed with their approval, and each audit
  failure its fix.
- Once the fix PR has merged, a worker opens the release PR from the draft (step 3), its Known
  Issues as the maintainer decided them. At its gate, ask the maintainer to approve its merge,
  and merge it once they do. Then run the release host runs (step 4) yourself under an
  exclusive grant to yourself and write their report to
  `target/xtask/review/release-v<X.Y.Z>/host-runs.md`.
- Run `mode: "audit"` at the commit to tag with `host_runs` that path. When it passes and the
  commit's CI is green, ask the maintainer to approve the tag (step 5), and create and push it
  once they do. The publishing of the Release (step 7) and the milestone work (step 8) each take
  their own approval in the same way.
