# shared/shmem

Shared-memory byte transport for Seraph userspace, in two layers. `SharedBuffer` maps Memory
caps received from a peer contiguously at a chosen VA (`SharedBuffer::attach`, at most
`MAX_PAGES` = 4 pages); the granting side owns allocation and release of the backing pages.
`SpscHeader`, `SpscWriter`, and `SpscReader` form a single-producer, single-consumer byte ring
over a `SharedBuffer`: two `AtomicU32` indices at the head of the region, then a power-of-two
byte buffer, ordered with Acquire/Release on the indices. The crate holds only the mechanism;
blocking and wake-up use a notification cap out of band.

`no_std`; builds inside std's dependency graph through the `rustc-dep-of-std` feature.

---

## Source Layout

```
shared/shmem/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # ShmemError, SharedBuffer, SPSC ring
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-design.md](../../docs/ipc-design.md) | Large data transfers via shared memory caps; notifications |
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | Userspace VA surfaces the buffer maps into |

---

## Summarized By

None
