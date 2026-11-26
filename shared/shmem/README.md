# shared/shmem

Shared-memory byte transport for Seraph userspace, in two layers.

---

## Overview

`SharedBuffer` maps Memory
caps received from a peer contiguously at a chosen VA (`SharedBuffer::attach`, one
`SharedRegion` per cap, each mapped whole, so a buffer spans as many pages as its caps cover);
the granting side owns allocation and release of the backing pages.
`SpscHeader`, `SpscWriter`, and `SpscReader` form a single-producer, single-consumer byte ring
over any mapped shared region, given by its base VA (for example one attached with
`SharedBuffer`). The region starts with an `SpscHeader`, six `AtomicU32` words in this order: the
`head` and `tail` indices, ordered with Acquire/Release; the power-of-two `capacity`, atomic since
the peer can write it; a `closed` flag that the first peer to drop sets (Release) and the
surviving peer reads (Acquire) to tell an empty or full ring from a gone peer (reader EOF, writer
`BrokenPipe`); and the `reader_waiting` and `writer_waiting` waiter words of the doorbell
protocol below. `capacity` bytes of ring storage follow at offset `SpscHeader::SIZE` (24). Each
end supplies the capacity it mapped when it builds its half; a half is refused when that is not a
power of two or the header's `capacity` disagrees, so a peer that rewrites the shared field
cannot steer the local end past its mapping. A write or a read moves its bytes as at most two
contiguous copies, split where the body ends, its length bounded by the capacity the end mapped
whatever the peer wrote into the indices; a read copies each body byte once, into the caller's
buffer, and reads the body no further. The crate holds the mechanism and the doorbell
protocol; blocking and wake-up use a notification per direction out of band, which the user of
the ring rings and waits on.

`no_std`; builds inside std's dependency graph through the `rustc-dep-of-std` feature.

---

## Doorbell protocol

Each direction of the ring has a doorbell, a notification out of band: the reader waits on one
for bytes and the writer on the other for space. Notifications are sticky
([docs/ipc-design.md](../../docs/ipc-design.md) § Notifications), so a doorbell rung before its
waiter blocks is taken by the wait. An end rings its peer's doorbell only when the peer announced
a wait in its waiter word, so a stream that never empties or fills the ring rings none:

- An end that finds the ring empty (a reader) or full (a writer) sets its own waiter word, issues
  a `SeqCst` fence, and looks at the ring again (`prepare_wait`). When the peer's progress has
  arrived, it clears its word and goes on without blocking; otherwise it blocks on its doorbell,
  and clears its word when the wait returns, whatever woke it (`end_wait`).
- An end that has moved bytes publishes its index, issues a `SeqCst` fence, and reads the peer's
  waiter word; when the word is set, it clears it with a swap and, when the swap found it set,
  rings the peer's doorbell (`take_waiting_reader`, `take_waiting_writer`). A wait is so rung at
  most once, and every doorbell claims one announced wait.

The fence pair orders each side's store before its load: either the waiter's second look sees the
progress, or the progressing side sees the waiter's word, so no wake is lost. Without the fences a
store can sit in the issuing CPU's store buffer past its later load (x86-64's TSO allows this, and
RISC-V's RVWMO with it), and both sides can miss each other. A host test runs the protocol's own
steps over a model memory with a store buffer per thread through every interleaving of a writer
and a waiting reader, and finds no lost wake and no doorbell beyond the announced waits; with the
model's fences made inert it finds the lost wake.

A peer can write the waiter words as it can the indices. A word the peer clears or never sets
costs only that peer's wakes; a word it sets without waiting costs this end a notification. A
close is not part of the protocol: the closing end sets `closed` and rings its peer's doorbell
whether or not the peer waits.

---

## Source Layout

```
shared/shmem/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # ShmemError, SharedRegion, SharedBuffer, SPSC ring
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-design.md](../../docs/ipc-design.md) | Large data transfers via shared memory caps; notifications, whose sticky bits the doorbell protocol relies on |
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | Userspace VA surfaces the buffer maps into |

---

## Summarized By

None
