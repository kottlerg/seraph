## Summary
<one to three sentences: what changed and why>

Closes #<issue>
<!-- For a follow-up Issue this PR drains in part, write `Refs #<issue>` instead and tick each
fixed item with `(fixed by PR #<this PR>)` (docs/conventions.md § Branch and PR Workflow). -->

## Acceptance
<copy the Acceptance section of the linked Issue verbatim; tick items completed by this PR>
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
