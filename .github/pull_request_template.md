## Summary
<one to three sentences: what changed and why>

Closes #<issue>

## Acceptance
<copy the Acceptance section of the linked Issue verbatim; tick items completed by this PR>
- [ ]

## Test plan
- [ ] `cargo xtask build` (x86_64)
- [ ] `cargo xtask run` (x86_64), terminal pass marker observed
- [ ] `cargo xtask build --arch riscv64`
- [ ] `cargo xtask run --arch riscv64`, terminal pass marker observed
- [ ] additional component-specific checks: <…>

## Notes
<design tradeoffs; follow-ups filed as Issues; anything reviewers should see>
