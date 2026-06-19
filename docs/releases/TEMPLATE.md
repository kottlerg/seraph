# Seraph v<X>.<Y>.<Z>

<One-sentence summary of the milestone or patch.>

---

## Highlights

- <Top-level user-visible change.>
- <Top-level user-visible change.>

## Components Shipped

Summarize notable changes grouped by area (kernel mechanisms, core services, drivers,
storage, runtime, userspace programs). Describe what changed per area; do not enumerate
every crate. For the initial release, describe each area's initial state rather than a delta.

| Area / component | Change since previous release |
|---|---|
| <area or component> | <what changed; "initial" for the first release> |

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

- <Specific failure mode or limitation with a link to the tracking Issue.>

## Verification

Disk images:

- `seraph-v<X>.<Y>.<Z>-x86_64.img.zst`
- `seraph-v<X>.<Y>.<Z>-riscv64.img.zst`

Verify with `sha256sum -c SHA256SUMS` against the attached `SHA256SUMS` file.

## Validation

- Burn-in workflow (`burnin.yml`) on this tag: <run URL>
- Build-test workflow (`build-test.yml`) on the tagged commit: <run URL>

---

## Summarized By

None
