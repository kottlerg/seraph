# fsbench

Test fixture that measures the cycles `std::fs::File` takes to read each of several sizes
through its two read paths, inline `FS_READ` and memory-cap `FS_READ_MEMORY`.

---

## Invocation

The [`svctest`](../../services/svctest/README.md) phase `fs_crossover_bench`
([fs_ipc.rs](../../services/svctest/src/phases/fs_ipc.rs)) spawns `fsbench` from
`/programs/fsbench` and passes when it exits cleanly; `fsbench` is one of the test-only
fixtures installed under `/programs/`, per
[docs/testing.md § Sysroot layout](../../docs/testing.md#sysroot-layout).

---

## Source Layout

```
programs/fsbench/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Fixture check, then the timed inline and memory-cap read loops
```

---

## Fixture

`fsbench` reads `/data/svctest/bench.bin`, a 64 KiB file that xtask synthesises into the
sysroot at build time rather than storing it under `rootfs/`
([rootfs/README.md](../../rootfs/README.md)). Byte `i` holds `i & 0xFF`. Before timing,
`fsbench` checks the first 64 bytes against that pattern and checks that a read starting at
offset 4080, which straddles a page tail, returns `0xF0` first.

---

## Method

The std client picks the read path itself: inline when the request fits the inline ceiling
without crossing a page tail, memory cap otherwise, per
[Inline-vs-memory-cap crossover](../../services/fs/docs/fs-driver-protocol.md#inline-vs-memory-cap-crossover-client-policy).
`fsbench` forces each path through the size of the buffer it passes to `read`:

| Path     | Buffer per `read` call                                        |
|----------|---------------------------------------------------------------|
| `inline` | At most 504 bytes, trimmed so the read ends at or before a page tail |
| `frame` (memory cap) | A full 4096-byte page                           |

For each size in 16 B, 1 KiB, 4 KiB, 16 KiB, and 64 KiB, and for each path, it runs 8
untimed warm-up iterations, then 256 timed ones. Each iteration seeks to offset 0 and reads the
full size through as many `read` calls as the path's buffer needs: 144 inline or 16 memory-cap
calls for 64 KiB. Cycles come from `rdtsc` on x86_64 and `csrr cycle` on riscv64. A timed
iteration that reads fewer bytes than the size panics.

---

## Output

Lines are logged under the name `fsbench`. The run opens with
`starting, fixture=/data/svctest/bench.bin`, emits one result line per size and path, and
closes with `done`. Each result line has the form below, where `<arch>` is `x86_64` or
`riscv64` and `<path>` is `inline` or `frame`:

```text
arch=<arch> size=<bytes> path=<path> iters=256 cycles_min=<n> cycles_mean=<n> cycles_max=<n>
```

Each `cycles_*` value is taken over the timed iterations, and one iteration covers all the
`read` calls that one size needs, not a single call.

A failed open, fixture check, seek, or read panics, so the process exits unsuccessfully and the
`fs_crossover_bench` phase fails.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Test fixtures under `/programs/` and the `/data/` fixtures |
| [Filesystem Driver Protocol](../../services/fs/docs/fs-driver-protocol.md) | `FS_READ` and `FS_READ_MEMORY`, the client read policy, and recorded `fsbench` results |
| [rootfs/README.md](../../rootfs/README.md) | Build-synthesised data fixtures |

---

## Summarized By

[Filesystem Driver Protocol](../../services/fs/docs/fs-driver-protocol.md)
