# core

Core OS: bootloader, kernel, and the kernel-validation harness. All `no_std`.

| Crate | Purpose |
|---|---|
| `boot/` | UEFI bootloader |
| `kernel/` | Microkernel — scheduler, IPC, memory, capabilities |
| `ktest/` | Kernel validation harness, loaded in place of `init` |

---

## Summarized By

None
