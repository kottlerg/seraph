## Summary
<one to three sentences: what changed and why>

Closes #<issue>

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
<validated head; for a documentation-only or comment-only delta since it, say so; for each
behaviour-neutral change on a trigger path (docs/testing.md § Coverage tiers), name it and why no
local host run is owed>

## Notes
<design tradeoffs; follow-ups filed as Issues; anything reviewers should see>
