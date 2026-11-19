# swapd Operation

How swapd starts, the work of each of its threads, what it does when the disk fails, how svcmgr
supervises it, and its bounds. The swap labels are specified in
[memmgr IPC Interface](../../memmgr/docs/ipc-interface.md) § Labels 22 to 26, the disk tier in
[memmgr Memory Pool](../../memmgr/docs/memory-pool.md#disk-tier) § Disk tier.

---

## Startup

1. swapd reads its bootstrap slots: the RECV of the endpoint svcmgr provides it (`swapd.restore`,
   seeded by no recipe), `vfsd.swap` and `memmgr.swap`.
2. It asks vfsd for the swap partition (`GET_SWAP_PARTITION`). `NO_MOUNT`, no swap partition on any
   disk, makes it log `no swap partition; swap stays in RAM` and exit cleanly, and svcmgr does not
   restart it. Any other failure ends it with a fault, and svcmgr restarts it within its budget.
3. It reads the partition's geometry (`BLK_GET_GEOMETRY`). Slot `n` lies at `n` times 64 KiB into
   the partition, so the partition holds its length in 64 KiB slots, a partial slot at its end
   unused. A partition of no slot makes it log so and exit cleanly.
4. It takes three buffers from memmgr, each a contiguous grant of a slot's 16 pages, which it never
   maps, and a Notification, touches its stack and heap, and allocates nothing after.
5. It registers with memmgr (`SWAP_REGISTER`): the slot count, a SEND on its endpoint badged with
   the redirect badge, and a Notify derivation of its Notification. A registration ends the writes
   in flight of an earlier instance and keeps every chunk on disk, which this instance restores. It
   logs `swap partition: <n> slots of 64 KiB, memmgr uses <m>`, `m` the slot count memmgr replies,
   clamped to its slot map's window.
6. It starts the write-out thread, at level 12 (`WRITE_OUT_PRIORITY`), and the want thread, at its
   recipe's level, 20, and serves restores on its main thread, at that level too.

---

## Restore

The main thread receives each message on the endpoint. A fault memmgr redirected arrives as
`FAULT_LABEL` with the redirect badge and the slot word at data word `FAULT_REDIRECT_WORD`; any
other message is answered `FAULT_REPLY_FORWARD` with word `0` and its caps deleted, so a holder of
svcmgr's published SEND on the endpoint reaches nothing. For a fault, swapd reads the bytes the word
names (`BLK_READ_INTO_MEMORY` into its restore buffer, the slot's byte count in whole blocks) and
hands them to memmgr with the word (`SWAP_RESTORE`). It resumes the fault (`FAULT_REPLY_RESUME`) on
`SUCCESS` or `RESTORE_STALE`, and forwards it (`FAULT_REPLY_FORWARD`) with memmgr's decline word on
`RESTORE_DECLINED`. A read the device fails is made again, three reads in all (`READ_TRIES`); a slot
swapd cannot read, a word that names no slot of the partition, and swapd's own malformed request
(`INVALID_ARGUMENT`) forward the fault with code 12 and detail 2, the slot unreadable, the chunk
staying on disk.

## Want

A debugger's or crashd's `MAKE_RESIDENT` over a chunk on disk has memmgr post the chunk's slot word
and send on swapd's Notification ([memmgr IPC Interface](../../memmgr/docs/ipc-interface.md)
§ Label 21). The want thread wakes, takes the words posted (`SWAP_WANTED`, at most eight), and
restores each as the main thread restores a fault's, ahead of any fault; the reader asks again and
finds the chunk resident. A word whose chunk a fault restored meanwhile is `RESTORE_STALE` and
changes nothing.

## Write-out

The write-out thread waits on the runtime's memory-pressure Notification and reads memmgr's level.
While the level reads `CRITICAL`, it takes a chunk (`SWAP_TAKE`): memmgr seals the chunk's stream
into the write buffer and names its slot. swapd writes the bytes to the slot
(`BLK_WRITE_FROM_MEMORY`) and ends the write (`SWAP_DONE`, `0` when written), which returns the
chunk's store pages to the free pool; a write that failed ends with `1`, and memmgr compresses the
chunk again on its store runs. `NOTHING_TO_TAKE` is asked again at once, 64 times in a row at most
(`TAKE_SWEEP`), since each walk covers a bounded part of memmgr's records; after that sweep, or on
`QUOTA`, the thread waits 50 ms (`TAKE_BACKOFF_MS`) or until the level changes. `SWAP_FULL` and a
refusal make it wait 1 s (`FULL_BACKOFF_MS`) or until the level changes, since a restore frees a
slot without a change of the level.

Only `CRITICAL` writes. The compressed store is the cheaper tier: a restore from it takes no device
read, where a restore from disk takes a slot's read and the open, a few milliseconds
([memmgr Memory Pool](../../memmgr/docs/memory-pool.md#disk-tier) § Disk tier). At `LOW` memmgr's
eviction is still making room; at `CRITICAL` it no longer can, and the disk is the tier of last
resort before oomd stops a process. Each write returns its chunk's store pages, so swapd writes only
while the level stays at the floor, and the level's hysteresis stops it.

The three threads own one buffer each, so a restore never waits for a buffer behind a write-out. The
block driver serves one request at a time, so a restore can wait behind one write in flight, about
2.5 ms under KVM and 3.6 ms under TCG for a slot.

---

## Disk Failure

The block driver fails every request once a device lost one (`DEVICE_FAULT`). swapd then marks the
partition lost and logs it once: every fault on a chunk on disk is forwarded with code 12 and detail
2, killing its process, and nothing more is written. It does not exit: a new instance would hold the
same failed driver. A call to the block driver that fails, the driver dead, counts as a lost
partition too.

---

## Supervision

The recipe sets `restart = on_failure` and `critical = no`. svcmgr creates the endpoint and holds it
across restarts ([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md) §
`provides`), and memmgr's redirect SEND is a derivation of it. While swapd is down, nothing is
written, and each fault on a chunk on disk waits on the endpoint for the next instance, which
registers again and serves it; a fault the dead instance held is unhandled, and its thread dies
([docs/fault-handling.md](../../../docs/fault-handling.md) § Delivery, Resume, and Kill). Once swapd
is permanently down, its restarts spent, those faults wait for good, and the system runs degraded:
every `critical = yes` service is a reserve node, which memmgr never evicts, so the core keeps
running, and oomd can still stop a process whose fault waits. `critical = yes` would instead power
off a system that can run.

---

## Bounds

| Bound | Value | Why |
|---|---|---|
| `READ_TRIES` | 3 reads of a slot | a device I/O error can be transient |
| `TAKE_SWEEP` | 64 `NOTHING_TO_TAKE` replies in a row | each walk covers part of memmgr's records |
| `TAKE_BACKOFF_MS` | 50 ms | the wait after a sweep that found nothing, or after `QUOTA` |
| `FULL_BACKOFF_MS` | 1 s | the wait with every slot taken |
| `WRITE_OUT_PRIORITY` | 12 | below the restore and want threads (20) |

---

## Summarized By

[services/swapd/README.md](../README.md)
