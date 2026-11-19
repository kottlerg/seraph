# swapd

The swap service: it holds the swap partition and moves memmgr's sealed chunks between the
partition and memmgr, writing chunks out while memory is critical and restoring each chunk on disk
a fault or a debugger's read wants.

---

## Role

memmgr evicts cold chunks into a compressed store in RAM, and its disk tier moves a compressed
chunk to a slot of a swap partition ([memmgr Memory Pool](../memmgr/docs/memory-pool.md#disk-tier)
§ Disk tier). memmgr performs no device I/O and waits on no swap service: it seals a chunk's stream
into a buffer the swap service lends it, redirects a fault on a chunk on disk to the swap service's
endpoint, and opens a slot's bytes the swap service hands back ([memmgr IPC
Interface](../memmgr/docs/ipc-interface.md) § Labels 22 to 26). swapd is that swap service.

swapd holds the swap partition, a partition-badged SEND on the block driver of the disk that holds
it, which vfsd hands out for the swap GPT type GUID
([vfsd IPC Interface](../vfsd/docs/vfs-ipc-interface.md) § Label 14), and the swap authority on
memmgr. It registers the partition's slots with memmgr, so memmgr owns the slots and swapd keeps no
table. It never maps a slot's bytes: the block driver moves them by DMA between the partition and
swapd's buffers, which memmgr writes into and reads from through its own mapping. The bytes are
ciphertext under memmgr's per-boot key ([docs/storage.md](../../docs/storage.md) § Data at Rest).

svcmgr starts swapd from `rootfs/config/svcmgr/services/swapd.svc`, which provides its endpoint,
seeds `vfsd.swap` and `memmgr.swap`, and sets `reserve = yes`: swapd acts to end a pressure
episode. With no swap partition on any disk swapd exits cleanly and swap stays in RAM. Its threads,
its policy and its failure handling are in [docs/operation.md](docs/operation.md).

---

## Source Layout

```
swapd/
├── Cargo.toml
├── README.md
├── docs/
│   └── operation.md       # Startup, the three threads, failures, supervision, bounds
├── layout/                # Slot extents, held-fault replies, write-out moves (host-tested)
│   ├── Cargo.toml
│   └── src/lib.rs
└── src/
    └── main.rs            # Startup, registration, the restore, want and write-out threads
```

Every decision swapd makes is `layout/`'s, host-tested there: where a slot's bytes lie on the
partition, how a held fault is answered once its restore was tried, what a block request's outcome
means, and what the write-out does after a `SWAP_TAKE`. `src/` makes the calls.

---

## Testing

`layout/`'s host tests cover the geometry (block sizes, whole slots, the extent of a slot word and
its bounds), the reply to a held fault for each `SWAP_RESTORE` outcome, the block outcomes, and the
write-out's sweep, back-off and full partition. The svctest `swapd` phase drives swapd end to end on
both architectures with a swap partition in `disk.img`: under pressure it writes chunks out, a fault
on a chunk on disk is restored with its pattern intact, a `MAKE_RESIDENT` of chunks on disk is
served through the want thread, the storage path's pages are never evicted, memmgr serves faults,
grants and `MAKE_RESIDENT` while a write and a restore are in flight, and a restarted swapd restores
the chunks an earlier instance wrote (services/svctest/README.md).

---

## Summarized By

[services/README.md](../README.md)
