## Summary
<one to three sentences: what changed and why>

Closes #<issue>
<!-- For a follow-up Issue this PR drains, write `Refs #<issue>` (or `Fixes #<issue>` when no item
is left open once the PR's last run is recorded), tick each fixed item on the Issue with
`(fixed by PR #<this PR>)`, and copy only those items below
(docs/conventions.md § Branch and PR Workflow). -->

## Acceptance
<copy the Acceptance section of the linked Issue verbatim (for a follow-up Issue, only the items
this PR fixes); tick items completed by this PR>
- [ ]

## Test plan
- [ ] `cargo xtask lint-docs`
- [ ] `cargo xtask build` (x86_64)
- [ ] `cargo xtask run` (x86_64), terminal pass marker observed
- [ ] `cargo xtask build --arch riscv64`
- [ ] `cargo xtask run --arch riscv64`, terminal pass marker observed
- [ ] additional component-specific checks: <…>

## Validation
<validated head; for a documentation-only or comment-only delta since it, say so>

## Notes
<design tradeoffs; follow-ups filed as Issues; anything reviewers should see>
