# abi/init-protocol

Binary handover contract between the kernel and the init process.

Defines [`InitInfo`] and all associated types placed in a read-only page at
`INIT_INFO_VADDR` before init runs. Includes `INIT_PROTOCOL_VERSION`; init
MUST check the version field before accessing any other fields.

**Constraints:** `no_std`, `#[repr(C)]` for all types, no dependencies outside
`core`. Changes that alter `InitInfo` layout or CSpace population order MUST
increment `INIT_PROTOCOL_VERSION`.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | Bootstrap sequence, init role |
| [abi/boot-protocol/](../boot-protocol/) | Bootloader-to-kernel contract; InitImage, boot modules |
| [docs/capability-model.md](../../docs/capability-model.md) | Initial capability distribution |

---

## Summarized By

None
