# shared/death-set

Growable death-queue set and the wait set that holds it, for supervisor services, and the overflow
watch of a death-queue drain.

---

## Overview

A service that binds kernel death observers (procmgr, svcmgr and devmgr) holds a `DeathSet`: its
death `EventQueue`s and the wait set that holds them. In the form svcmgr holds (`DeathSet::new`),
the queues share that wait set with the service endpoint and the members of the service's own it
reserves room for (`add_member`; svcmgr's memory-pressure Notification), as its main wait set; in
the death-only
form procmgr's reaper waits on (`DeathSet::new_death_only`), the wait set holds the queues alone,
and the growth policy still counts one member for a service endpoint. Each bind takes
one node from its queue's pool, fixed when the queue is created, so when every queue is out of
nodes the set creates a further queue with twice the last pool, funded from the service's own
memory, retried at half the pool, down to the first pool's size, when memmgr refuses a contiguous
grant that large. When the queues fill the wait set, the set replaces it with one of twice the
members, up to `WAIT_SET_MAX_MEMBERS`, and moves every member across. Each service sets its
queues' ring capacity and its first pool when it creates the set; `bind_thread` and `bind_aspace`
bind a thread's death observer and an address space's terminal-fault observer, `bind_with` binds
one through a closure the service makes the bind with (a procmgr request, for one), and `drain`
hands every pending death event to the service, reporting a queue that gave up a full ring's worth
so the service resyncs; `try_recv` takes one, uncounted, for a counted set. A `DeathSet` is `Send`
and not `Sync`: a service whose threads share one holds it behind a lock.

In the counted form devmgr holds (`DeathSet::new_counted`), the wait set reserves room for members
of the service's own, which `add_member` and `remove_member` put in and take out and a
replacement of the wait set moves across, and each queue takes no more binds than its pool holds,
its ring an entry per node: since each observer posts at most once, no post is dropped and no
resync is needed, at the cost of a queue's ring entry held per bind for the life of the set.

### Overflow detection

The kernel drops a death post to a full queue, so a queue of a fixed ring can lose a death. A
dropped post leaves the ring full behind it: its capacity of events, each taken after the drop,
with the queue never found empty until the last of them is taken. `OverflowWatch` counts the takes
from one queue since a take last found it empty, and reports when the count reaches the ring's
capacity, counting again from zero; so it reports at a take after any drop, and the caller resyncs
from the kernel's records, which the kernel writes before it posts. It also reports a ring's worth
taken with no drop, which costs only a resync that finds nothing. Every take from the queue goes
through one watch: `drain_queues`, which `DeathSet::drain` calls, drains each queue of a set until
it is empty and counts each drain from zero, which holds for a service with one drainer (procmgr's
reaper, svcmgr's main loop); logd, whose threads take from its one death queue in turn, keeps one
watch under the lock it takes under
([services/logd/docs/ipc-interface.md](../../services/logd/docs/ipc-interface.md) § Death-queue
resync).

### Host tests

Where a bind goes and when the set grows is the `DeathQueues` policy of
[`runtime/ruststd/death-queues`](../../runtime/ruststd/README.md), host-tested there. The set itself
makes the syscalls and funds the objects through `std::os::seraph`, so it compiles only for seraph
(`src/set.rs`, under `cfg(target_os = "seraph")`, which `build.rs` declares an expected cfg on
the host). The overflow watch and the drain are host-tested here against `model::KernelQueue`, a
model of the kernel's event-queue ring (FIFO, a post to a full ring dropped): every interleaving of
posts and takes up to a bound is checked to leave no dropped post without a later report. The
`model` feature gives the same model to the host tests of each service's resync, which drain it as
the service does and check that the resync recovers every death a full queue dropped: procmgr's in
`procmgr-process-table` (`ProcessTable::resync_dead`), svcmgr's in `svcmgr-defs`
(`death_caps::resync`), and logd's in `logd-slot-table` (with `logd_codec::resync`). No service
build enables the feature. The crate depends on `ruststd-death-queues`, `shared/syscall` and
`abi/syscall`.

---

## Source Layout

```
shared/death-set/
├── Cargo.toml
├── README.md
├── build.rs                    # Declares cfg(target_os = "seraph") expected on the host
└── src/
    ├── lib.rs                  # Crate root: the modules and their exports
    ├── set.rs                  # DeathSet: queue and wait-set creation, binds, growth, drain
    ├── overflow.rs             # OverflowWatch and drain_queues: a drain's overflow report
    └── model.rs                # KernelQueue: the kernel's event-queue ring, for host tests
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/procmgr/README.md](../../services/procmgr/README.md) | procmgr's death queues, the reaper's wait set, and the death-set lock |
| [services/svcmgr/docs/restart-protocol.md](../../services/svcmgr/docs/restart-protocol.md) | svcmgr's death queues and main wait set |
| [services/devmgr/docs/responsibilities.md](../../services/devmgr/docs/responsibilities.md) | devmgr's driver death queues and the settle wait set |
| [services/logd/docs/ipc-interface.md](../../services/logd/docs/ipc-interface.md) | logd's death queue, the drain's count, and its resync |
| [docs/limits.md](../../docs/limits.md) | The death-queue sizes and the set's floor |

---

## Summarized By

None
