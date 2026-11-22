# oomd Operation

How oomd reads its configuration, follows memmgr's pressure level, finds its stop sources, chooses
the candidate it stops, and bounds its calls.

---

## Startup

oomd takes the stop authority from bootstrap slot 0: its recipe sets `stop_authority = yes` and no
seeds or debug authority, so the cap is the first slot
([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md) § `stop_authority`). It
takes the Notification on which the runtime receives memmgr's pressure-level changes
(`std::os::seraph::memory_pressure_notification`). With either missing it logs an error and exits,
stopping nothing.

It then reads its configuration ([Configuration](#configuration)), reads its clock once so the
clock's state is made, touches 32 KiB of its stack (`STACK_TOUCH_BYTES`) and 16 KiB of heap
(`HEAP_TOUCH_BYTES`), funds its CSpace's headroom for the caps a walk holds at once
([Stop Sources](#stop-sources)), five slots (`WALK_CAPS_MAX`), with
`std::os::seraph::fund_cspace_slot_budget`, logging a warning when memmgr does not grant it, and
logs one line:

```
[oomd] watching memory: stopping after 2000 ms critical, one per 5000 ms
```

`stopping` reads `advising only (OOMD_STOP=no)` in advice mode. After this oomd allocates nothing:
its walk of the stop sources, its stop and its log lines use the stack and the IPC buffer, and
the caps a walk receives take CSpace slots, which come from the CSpace's own donated pool and never
from memmgr at the call: `fund_cspace_slot_budget` is the only call that asks memmgr for them, and
oomd makes it only here. Its
recipe sets `reserve = yes`, so its budget node is a reserve node, and a page past what it touched
is taken from the system reserve
([memmgr Memory Pool § Distribution policy](../../memmgr/docs/memory-pool.md#distribution-policy)).

---

## Configuration

oomd reads three entries of its recipe's `env`; the policy crate's `parse_ms` and `parse_stop`
parse them, host-tested.

| Entry | Default | Meaning |
|---|---|---|
| `OOMD_GRACE_MS` | 2000 (`GRACE_DEFAULT_MS`) | How long the level reads `CRITICAL` before oomd acts |
| `OOMD_COOLDOWN_MS` | 5000 (`COOLDOWN_DEFAULT_MS`) | How long after an act before the next |
| `OOMD_STOP` | `yes` | `yes` stops the candidate; `no` names it and stops nothing |

A duration is decimal digits of milliseconds. One that is not is logged as a warning and the default
holds; one past 600 000 ms (`DURATION_MAX_MS`, ten minutes) is clamped to it, logged. An
`OOMD_STOP` other than `yes` or `no` is logged and gives advice, so a misspelt setting stops
nothing.

The shipped recipe, `rootfs/config/svcmgr/services/oomd.svc`, sets the defaults. crashd's shipped
recipe holds a fault declined for want of memory for 10 000 ms (`CRASHD_OOM_STALL_MS`), longer than
the grace and the cooldown together, so a fault held from the level's rise outlasts the first two
acts and the time after the second in which its stop's memory comes back. An act past the stall,
due when the stops before it gave back too little to lift the level, finds the fault reported and
declined: the stall bounds the hold, and does not grow with the ladder
([services/crashd/docs/operation.md](../../crashd/docs/operation.md) § Hold, The stall and oomd's
ladder).

---

## Ladder

oomd waits on the pressure Notification, with a timeout of the next act's deadline while the level
reads `CRITICAL` and with none otherwise. On each wake, a change or the deadline, it reads the level
with memmgr's `QUERY_POOL_STATUS` (`data[7]`;
[memmgr Memory Pool § Memory pressure](../../memmgr/docs/memory-pool.md#memory-pressure)) and gives
it to the policy crate's `Ladder`, which says what changed and whether an act is due. A level
memmgr does not give changes nothing and makes no act due: oomd acts on no level it did not read.

**Episodes.** An episode begins when the level leaves `NORMAL` and ends when it reads `NORMAL`
again. oomd logs each change once:

| Change | Line |
|---|---|
| `NORMAL` to `LOW` | `memory low` |
| `NORMAL` or `LOW` to `CRITICAL` | `memory critical` |
| `CRITICAL` to `LOW` | `memory low after <ms> ms critical` |
| `LOW` or `CRITICAL` to `NORMAL` | `memory normal after <ms> ms`, the episode's length |

On `LOW` oomd does nothing more: memmgr's broadcast is the request to give memory back, which a
service holding a cache answers ([memmgr Memory Pool § Memory
pressure](../../memmgr/docs/memory-pool.md#memory-pressure)).

**Act.** An act falls due when the level has read `CRITICAL` for the grace since it last rose to
`CRITICAL`, and the cooldown has passed since the last act, whichever is later. A fall below
`CRITICAL` ends the grace, so the next rise waits the whole grace again; the cooldown runs across
episodes. Each act counts against the cooldown, whether or not it stopped a service, which gives a
stopped service's death, svcmgr's teardown and memmgr's reclaim of its pages the cooldown to lift
the level before oomd stops another. An act:

1. walks the stop sources ([Stop Sources](#stop-sources)) and keeps the candidate stopped first.
   With none, it logs `memory critical for <ms> ms: nothing to stop`, once per rise to
   `CRITICAL`, and ends;
2. reads the level again, and ends when it no longer reads `CRITICAL`, since the walk took calls
   to each source;
3. with `OOMD_STOP=no`, logs `would stop <name>: <pages> pages, memory critical for <ms> ms
   (OOMD_STOP=no)` and ends;
4. stops the candidate through its source, then logs `stopped <name>: <pages> pages, memory
   critical for <ms> ms`, or `stop of <name> failed: <why>` as a warning. The stop is made before
   its line, so a log write that waits does not delay it.

oomd stops at most one candidate per cooldown and never one no source lists. It holds no fault:
crashd holds the faults memmgr declines, and resumes each when the memory it waits for is there: the
level below `CRITICAL` or, for a fault of a commit overrun or of a restore, memmgr's draw room
open ([`services/crashd/docs/operation.md`](../../crashd/docs/operation.md) § Hold).

---

## Stop Sources

A stop source lists the candidates oomd may stop, each with a key, a rank and the pages its memory
budget subtree holds, and stops the one oomd names by its key, through authority oomd does not
hold ([docs/session-supervision.md](../../../docs/session-supervision.md) § Stop Sources). Every
source serves the same two labels, `STOP_CANDIDATE` and `LIST_CANDIDATES` of `ipc::stop_labels`,
on a badge carrying the stop bit ([svcmgr IPC Interface](../../svcmgr/docs/ipc-interface.md)
§ Label 5, § Label 6).

svcmgr is the source of the service class, reached on the stop authority itself. It lists a
service only when its recipe sets `oom_stop = yes` and the eligibility rule admits it, an instance
runs and its usage reads, and checks the rule and the instance again on the stop
([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md) § `oom_stop`). Every
other source is a service whose recipe sets `stop_source`, of the program class, which ranks its
jobs before its whole sessions. sessiond's recipe, the default image's, sets the key; the `stopsrc`
test fixture's sets it too.

**Discovery.** oomd keeps no source between acts: each act's walk asks svcmgr, on the stop
authority, for the sources that run then (`LIST_STOP_SOURCES`; [svcmgr IPC
Interface](../../svcmgr/docs/ipc-interface.md) § Label 7), so a source that started, restarted or
ended since the last act is found as it is. A page lists at most four sources (`MSG_CAP_SLOTS_MAX`),
each with the class svcmgr reads from its recipe and a SEND on its endpoint badged with the stop
bit. svcmgr derives each SEND for the reply, an endpoint derive that makes no kernel body
([capability-internals.md](../../../core/kernel/docs/capability-internals.md) § Body Arena), and
the reply moves it out of svcmgr's CSpace, so svcmgr keeps none. oomd walks each source a page
lists before it asks for the next page, deletes each source's cap once its candidates are read,
unless the candidate it keeps is that source's, and deletes that one after the act. A walk so holds
at most a page of sources' caps and the kept candidate's source's, five, the headroom oomd funds at
start. The received caps take IPC transfer slots, which may take a CSpace's IPC receive reserve
([capability-internals.md](../../../core/kernel/docs/capability-internals.md) § IPC Receive
Reserve) and grow the CSpace only when no slot is free. A source whose class oomd does not know is
logged and passed over. svcmgr's own candidates are walked last.

**Order.** A walk asks each source in turn for its whole list, a page per call, and offers every
entry to the policy crate's `Best`, which keeps the one stopped first: the earliest class, the
program class before the service class, then the lowest rank within it, then the most pages, a tie
going to the candidate offered first, so to the earlier source and then to its earlier entry.
Sources are walked in svcmgr's table order. svcmgr lists in its table order and gives every service
rank 0, so among services oomd stops the one with the most pages, a tie going to the one earlier in
svcmgr's table. The order is host-tested in the policy crate.

**Adding a source.** A source of the program class is one recipe that sets `stop_source` and
serves the stop labels; it changes no oomd code. A new class is a class code in
`ipc::stop_labels`, a value of the recipe key, and a `Class` in the policy crate placed where
it is stopped; the ladder and the walk do not change. sessiond is the default image's source of the
program class ([services/sessiond/README.md](../../sessiond/README.md)).

---

## Bounds

Each call to a source, a page of its list or a stop, is an `ipc_call_timeout` of at most 2000 ms
(`CALL_TIMEOUT_MS`), the wait for the source to receive it and for its reply, and the walk of one
source's list ends 4000 ms after it began (`LIST_WALK_MS`), each page's call bounded by the time
left. A time bound, not a count of pages, so a list of any length that its source answers at its
usual pace is read whole. A call that fails, times out or is refused, a reply that breaks the
protocol (an entry that does not decode, a page longer than `LIST_CANDIDATES_PAGE`, a cursor that
does not advance), or a list not read whole in time, is logged as `<source>: candidates not read:
<why>` and the walk goes on with what that source listed before it and with the next source.
svcmgr's list of sources is bounded the same way, its calls to svcmgr within 4000 ms whatever time
the sources it lists take; one that fails is logged as `svcmgr: stop sources not read: <why>`, and
the walk goes on with the sources read before it and with svcmgr's own candidates. A page whose caps
do not match its entries is out of protocol, and oomd deletes every cap it carried. So an act takes
at most 4000 ms per source, 4000 ms for the list of sources, and 2000 ms for its stop, and a wedged
source delays the ladder by that bound, never more. A stop that times out may still have stopped its
candidate; the next act, a cooldown later, finds the level and the list as they are then.

A read of the level waits for memmgr's answer, as every process's does: memmgr is the pager of every
process, oomd included, and a memmgr that does not answer leaves nothing for oomd to act through. A
wait on the Notification that fails with an error other than a timeout or an interruption is logged
and retried after 100 ms (`WAIT_RETRY_MS`).

---

## Limits

- oomd reaches only services that opt in and what a stop source lists. The processes svcmgr does
  not launch (memmgr, procmgr, devmgr, vfsd), the drivers devmgr starts, and fatfs are no source's
  candidates; the programs a user starts are candidates when sessiond, the program class's
  source, lists them.
- It stops the whole candidate: a service's memory is given back only by its death, and its
  supervisor restarts it under its restart policy and budget.
- It asks no service to give memory back and evicts nothing: memmgr's `LOW` broadcast asks, and
  eviction is #230's.
- It reads one level for the whole pool: a process at its own budget node's max is refused by its
  budget (decline code 10) at any level, and oomd does not act on it.

---

## Summarized By

[services/oomd/README.md](../README.md)
