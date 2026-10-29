# abi/init-protocol

Binary handover contract between the kernel and the init process.

---

## Overview

Defines `InitInfo` and all associated types placed in a read-only region of one or more pages
(at most `INIT_INFO_MAX_PAGES`) before init runs. The kernel chooses the region's virtual
address per-boot and delivers it to init in the entry register (`rdi`/`a0`), so the address is
not an ABI constant (see [`docs/userspace-memory-model.md`](../../docs/userspace-memory-model.md)
§ Bootstrap Cross-Boundary VAs). Includes `INIT_PROTOCOL_VERSION`; init MUST check the version
field before accessing any other fields.

**Constraints:** `no_std`, `#[repr(C)]` structs and fixed-width integer-repr enums, no
dependencies outside `core`. Changes that alter the `InitInfo` layout, field semantics, or
`CSpace` population order MUST increment `INIT_PROTOCOL_VERSION`.

`InitInfo` delivers the full RAM Memory cap range (`memory_base`/`memory_count`) to init's
CSpace. init copies the RAM Memory caps left after its own bootstrap allocations to memmgr
(derive-twice; one bootstrap round, the remainder at the init reap) before starting procmgr; see
[`docs/process-lifecycle.md`](../../docs/process-lifecycle.md) § Init → memmgr, which is the
authoritative description of the userspace boot order.

---

## Source Layout

```
init-protocol/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs      # InitInfo, CapDescriptor and CapType, InitModuleName, InitFramebufferInfo,
                    #   INIT_PROTOCOL_VERSION and the page-bound constants, find_module_slot
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | Bootstrap sequence, init role |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Userspace boot order, init→memmgr→procmgr capability transfer |
| [abi/boot-protocol/README.md](../boot-protocol/README.md) | Bootloader-to-kernel contract; InitImage, boot modules |
| [docs/capability-model.md](../../docs/capability-model.md) | Initial capability distribution |

---

## Summarized By

[abi/process-abi/README.md](../process-abi/README.md),
[Capability Subsystem Internals](../../core/kernel/docs/capability-internals.md),
[Process Lifecycle](../../docs/process-lifecycle.md),
[services/procmgr/README.md](../../services/procmgr/README.md)
