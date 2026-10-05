# shared

Internal utility crates with no cross-boundary stability obligation;
[abi/README.md](../abi/README.md) indexes the contract crates.

| Crate | Purpose |
|---|---|
| [`ansi/`](ansi/README.md) | Incremental ANSI SGR colour parser for the terminal output path |
| [`crypto/`](crypto/README.md) | In-OS crypto primitives — SHA-512 hashing and Ed25519 signature verification, `no_std`, zero-dependency |
| [`elf/`](elf/README.md) | ELF64 parser — header validation, segment enumeration |
| [`font/`](font/README.md) | Embedded 9×20 bitmap font for early console output |
| `ipc/` | IPC helpers — `IpcMessage` snapshot type, `ipc_call`/`recv`/`reply` wrappers, bootstrap protocol, and the `RecvGuard` receive-failure policy for blocking recv loops |
| `log/` | System log primitives — wire-format helpers and process-global cache for the badged log cap |
| `mmio/` | Architecture-specific MMIO ordering barriers for device drivers |
| [`namespace-protocol/`](namespace-protocol/README.md) | Cap-native namespace wire format, name validation, rights composition, and `NamespaceBackend` dispatch loop shared by every namespace server |
| `ns-client/` | `no_std` namespace walk helpers for holders of a vfsd namespace cap |
| [`process-layout/`](process-layout/README.md) | Per-process bootstrap virtual-address layout for process creators |
| `registry/` | Fixed-capacity name→endpoint-cap registry used by supervisor services |
| `registry-client/` | Client-side helper for the svcmgr name→cap discovery registry |
| `shmem/` | Shared-memory byte transport — multi-page `SharedBuffer` plus SPSC ring |
| [`syscall/`](syscall/README.md) | Userspace syscall wrappers — inline asm over `abi/syscall/` |
| [`text/`](text/README.md) | Byte-stream → glyph primitives shared by every framebuffer console |

---

## Summarized By

None
