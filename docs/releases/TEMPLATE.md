# Seraph v<X>.<Y>.<Z>

<One-sentence summary of the milestone or patch.>

---

## Highlights

- <Top-level user-visible change.>
- <Top-level user-visible change.>

## Components Shipped

Summarize notable changes as short descriptive paragraphs grouped by area (kernel
mechanisms, core services, drivers, storage, runtime, userspace programs) — one paragraph
per area, led by the area name in bold. Describe what changed per area; do not enumerate
every crate. For the initial release, describe each area's initial state rather than a delta.

**<Area>** — <what changed in this area; its initial state for the first release.>

## ABI and Protocol Versions

List each ABI/protocol version constant whose value changed this release; omit constants
that did not change. For the initial release, list the constants that define the shipped
ABI surface with their initial values, marked `initial`. The kernel version equals the
project version (the tag) and is not listed here.

| Constant | Value | Bumped this release? |
|---|---|---|
| `<CONSTANT>` | <n> | <yes / no / initial> |

## Breaking Changes

- <Concrete description of the breaking change and migration path.>

## Known Issues

Defects and regressions present in the shipped build of this release only: behaviour that
is broken, degraded, or unreliable in the tagged artifacts. Missing or planned functionality
is NOT a known issue and MUST NOT be listed here — absent features belong in the issue
tracker, not in release notes. Use `None` when the release ships no known defects.

- <Defect or regression in this release, with a link to its tracking Issue.>

## Verification

Disk images:

- `seraph-v<X>.<Y>.<Z>-x86_64.img.zst`
- `seraph-v<X>.<Y>.<Z>-riscv64.img.zst`

Verify with `sha256sum -c SHA256SUMS` against the attached `SHA256SUMS` file.
