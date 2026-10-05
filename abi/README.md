# abi

Binary contract crates that cross component or privilege boundaries; a change to one is an ABI
break. [shared/README.md](../shared/README.md) indexes the non-contract crates.

| Crate | Purpose |
|---|---|
| [`boot-protocol/`](boot-protocol/README.md) | `BootInfo` and associated types — boot ABI between bootloader and kernel |
| [`init-protocol/`](init-protocol/README.md) | `InitInfo` and associated types — kernel-to-init handover contract |
| [`process-abi/`](process-abi/README.md) | `ProcessInfo`, `StartupInfo`, and `main()` convention — process startup ABI |
| [`syscall/`](syscall/README.md) | Syscall numbers, error codes, and constants — ABI between kernel and userspace |

---

## Summarized By

None
