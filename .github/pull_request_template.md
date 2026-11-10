## Summary
<one to three sentences: what changed and why>

Fixes #<issue>
<!-- For an Issue this PR changes without closing, and for a rolling follow-up Issue, write
`Refs #<issue>`. Tick each fixed item on the Issue with `(fixed by PR #<this PR>)` and copy only
those items below (docs/conventions.md § Follow-up Issues). -->

## Acceptance
<copy the Acceptance section of the linked Issue verbatim (for a follow-up Issue, only the items
this PR fixes); tick items completed by this PR>
- [ ]

## Test plan
- [ ] `cargo xtask lint-docs`
- [ ] `cargo xtask build` (x86_64)
- [ ] boot on x86_64 (`cargo xtask run`, or `run-parallel --parallel 1 --runs 1`), terminal pass
      marker observed
- [ ] `cargo xtask build --arch riscv64`
- [ ] boot on riscv64, terminal pass marker observed
- [ ] additional component-specific checks: <…>

## Validation
<validated head; for a documentation-only or comment-only delta since it, say so; each local host
run docs/testing.md § Coverage tiers owes (each boundary run, the memory variation, and each device
cell: the storage cells 4kn, second-disk, shared-line, and oversize-block, no-iommu, and
framebuffer, per architecture), with its `--runs` count, its outcome, and the head it ran at (a run
not owed that HANGs or fails as that section allows, with the link to its record), or that none is
owed and why>

## Notes
<design tradeoffs; follow-ups filed as Issues; anything reviewers should see>
