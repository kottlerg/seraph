# shared

Internal utility crates with no cross-boundary stability obligation. See
[abi/README.md](../abi/README.md) for the contract crates.

| Crate | Purpose |
|---|---|
| `elf/` | ELF64 parser — header validation, segment enumeration |
| `font/` | Embedded 9×20 bitmap font for early console output |
| `ipc/` | IPC helpers — `IpcMessage` snapshot type, `ipc_call`/`recv`/`reply` wrappers, bootstrap protocol |
| `log/` | System log primitives — wire-format helpers and process-global cache for the tokened log cap |
| `mmio/` | Architecture-specific MMIO ordering barriers for device drivers |
| `namespace-protocol/` | Cap-native namespace wire format, name validation, rights composition, and `NamespaceBackend` dispatch loop shared by every namespace server |
| `registry/` | Fixed-capacity name→endpoint-cap registry used by supervisor services |
| `shmem/` | Shared-memory byte transport — multi-frame `SharedBuffer` plus SPSC ring |
| `syscall/` | Userspace syscall wrappers — inline asm over `abi/syscall/` |

---

## Summarized By

None
