# shared/death-set

Growable death-queue set and the wait set that holds it, for supervisor services.

---

## Overview

A supervisor service that binds kernel death observers (procmgr and svcmgr) holds a `DeathSet`: its
death `EventQueue`s and the wait set that holds them. In the form svcmgr holds (`DeathSet::new`),
the queues share that wait set with the service endpoint, as its main wait set; in the death-only
form procmgr's reaper waits on (`DeathSet::new_death_only`), the wait set holds the queues alone,
and the growth policy still counts one member for a service endpoint. Each bind takes
one node from its queue's pool, fixed when the queue is created, so when every queue is out of
nodes the set creates a further queue with twice the last pool, funded from the service's own
memory, retried at half the pool, down to the first pool's size, when memmgr refuses a contiguous
grant that large. When the queues fill the wait set, the set replaces it with one of twice the
members, up to `WAIT_SET_MAX_MEMBERS`, and moves every member across. Each service sets its
queues' ring capacity and its first pool when it creates the set; `bind_thread` and `bind_aspace`
bind a thread's death observer and an address space's terminal-fault observer, and `drain` hands
every pending death event to the service, reporting a queue that gave up a full ring's worth so
the service resyncs. A `DeathSet` is `Send` and not `Sync`: a service whose threads share one holds
it behind a lock.

Where a bind goes and when the set grows is the `DeathQueues` policy of
[`runtime/ruststd/death-queues`](../../runtime/ruststd/README.md), host-tested there; this crate
makes the syscalls and funds the objects through `std::os::seraph`, so its contents compile only
for seraph and no host test reaches them. It depends on `ruststd-death-queues`, `shared/syscall`
and `abi/syscall`.

---

## Source Layout

```
shared/death-set/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # DeathSet: queue and wait-set creation, binds, growth, drain
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/procmgr/README.md](../../services/procmgr/README.md) | procmgr's death queues, the reaper's wait set, and the death-set lock |
| [services/svcmgr/docs/restart-protocol.md](../../services/svcmgr/docs/restart-protocol.md) | svcmgr's death queues and main wait set |
| [docs/limits.md](../../docs/limits.md) | The death-queue sizes and the set's floor |

---

## Summarized By

None
