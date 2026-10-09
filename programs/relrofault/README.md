# relrofault

Test fixture for the `PT_GNU_RELRO` enforcement test: it writes into its own `.data.rel.ro` and
is expected to fault. It is installed at `/programs/relrofault` with the other test fixtures
the harnesses spawn (see [docs/testing.md](../../docs/testing.md#sysroot-layout)), and
[`svctest`](../../services/svctest/README.md)'s `relro_write` phase spawns it.

---

## Source Layout

```
programs/relrofault/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Logs the target address, then the deliberate RELRO write
```

---

## Behavior

`MESSAGE` is an immutable `&'static str` static. Its initializer carries a relocated pointer,
so the linker places it in `.data.rel.ro`, inside the image's `PT_GNU_RELRO` region, which the
loader maps read-only once relocations are applied (see
[docs/userspace-memory-model.md](../../docs/userspace-memory-model.md#image-placement)).
`main` keeps the static live with `std::hint::black_box`, logs
`relrofault: writing to <address>`, and performs a volatile 64-bit write of `0xDEAD` to the
static's address.

The write is expected to fault, so nothing after it runs. If it does not fault, the fixture
logs `relrofault: WRITE SUCCEEDED (RELRO not enforced)` and returns from `main`, exiting
cleanly.

The `relro_write` phase in
[`services/svctest/src/phases/process_faults.rs`](../../services/svctest/src/phases/process_faults.rs)
waits for the child and fails on a clean exit. It also fails unless the exit reason falls in
the fault range `EXIT_FAULT_BASE..EXIT_KILLED` (`0x1000..0x2000`), as defined in
[docs/process-lifecycle.md](../../docs/process-lifecycle.md#exit-reason).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | Image placement, relocation, and RELRO sealing |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Exit-reason ranges the harness checks |
| [docs/fault-handling.md](../../docs/fault-handling.md) | How a userspace fault is handled or ends the thread |
| [docs/testing.md](../../docs/testing.md) | How harnesses and fixtures are staged |

---

## Summarized By

None
