# Seraph v<X>.<Y>.<Z>

<One-sentence summary of the milestone or patch.>

---

## Highlights

- <Top-level user-visible change.>
- <Top-level user-visible change.>

## Components Shipped

| Component | State |
|---|---|
| kernel | <delta vs previous release; "no change" if applicable> |
| bootloader | <delta vs previous release> |
| init | <delta vs previous release> |
| procmgr | <delta vs previous release> |
| memmgr | <delta vs previous release> |
| vfsd | <delta vs previous release> |
| svcmgr | <delta vs previous release> |
| devmgr | <delta vs previous release> |
| drivers/virtio-blk | <delta vs previous release> |
| fs/fat | <delta vs previous release> |
| runtime/ruststd | <delta vs previous release> |

## ABI and Protocol Versions

| Constant | Value | Bumped this release? |
|---|---|---|
| `BOOT_PROTOCOL_VERSION` | <n> | <yes/no> |
| `PROCESS_ABI_VERSION` | <n> | <yes/no> |
| `INIT_PROTOCOL_VERSION` | <n> | <yes/no> |
| `<NAMESPACE>_LABELS_VERSION` | <n> | <yes/no> |

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
