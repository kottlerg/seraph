# abi

Binary ABI contract crates for the boot, kernel/userspace, and process-startup boundaries;
[shared/README.md](../shared/README.md) indexes the shared utility crates.

| Crate | Purpose |
|---|---|
| [`boot-protocol/`](boot-protocol/README.md) | `BootInfo` and associated types — boot ABI between bootloader and kernel |
| [`init-protocol/`](init-protocol/README.md) | `InitInfo` and associated types — kernel-to-init handover contract |
| [`process-abi/`](process-abi/README.md) | `ProcessInfo`, `StartupInfo`, and `main()` convention — process startup ABI |
| [`syscall/`](syscall/README.md) | Syscall numbers, error codes, and constants — ABI between kernel and userspace |

---

## Summarized By

None
