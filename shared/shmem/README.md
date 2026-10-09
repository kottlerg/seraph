# shared/shmem

Shared-memory byte transport for Seraph userspace, in two layers. `SharedBuffer` maps Memory
caps received from a peer contiguously at a chosen VA (`SharedBuffer::attach`, at most
`MAX_PAGES` = 4 pages); the granting side owns allocation and release of the backing pages.
`SpscHeader`, `SpscWriter`, and `SpscReader` form a single-producer, single-consumer byte ring
over any mapped shared region, given by its base VA (for example one attached with
`SharedBuffer`). The region starts with an `SpscHeader`: the `head` and `tail` `AtomicU32`
indices, ordered with Acquire/Release; the power-of-two `capacity`; and a `closed` flag that the
first peer to drop sets (Release) and the surviving peer reads (Acquire) to tell an empty or full
ring from a gone peer (reader EOF, writer `BrokenPipe`). `capacity` bytes of ring storage follow
at offset `SpscHeader::SIZE`. The crate holds only the mechanism; blocking and wake-up use a
notification cap out of band.

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
