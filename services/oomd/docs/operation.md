# oomd Operation

How oomd reads its configuration, follows memmgr's pressure level, chooses the service it stops,
and bounds its calls.

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
(`HEAP_TOUCH_BYTES`), and logs one line:

```
[oomd] watching memory: stopping after 2000 ms critical, one per 5000 ms
```

`stopping` reads `advising only (OOMD_STOP=no)` in advice mode. After this oomd allocates nothing:
its walk of the stop sources, its stop and its log lines use the stack and the IPC buffer. Its
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
the grace and the cooldown together, so a fault held from the level's rise outlasts the first stop
and the cooldown that lets its memory come back
([services/crashd/docs/operation.md](../../crashd/docs/operation.md) § Hold).

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
crashd holds the faults memmgr declines, and resumes them when the level falls below `CRITICAL`.

---

## Stop Sources

A stop source lists the candidates oomd may stop, each with the pages its memory budget subtree
holds, and stops the one oomd names, through authority oomd does not hold
([docs/session-supervision.md](../../../docs/session-supervision.md) § Stop Sources). oomd keeps
an ordered list of sources, each with its class and the cap oomd calls it on. svcmgr is the one
source: the service class, reached on the stop authority, listing with `LIST_STOPPABLE` and
stopping with `STOP_SERVICE`
([svcmgr IPC Interface](../../svcmgr/docs/ipc-interface.md) § Label 5, § Label 6). svcmgr lists a
service only when its recipe sets `oom_stop = yes` and the eligibility rule admits it, an instance
runs and its usage reads, and checks the rule again on the stop
([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md) § `oom_stop`).

**Order.** A walk asks each source in turn for its whole list, a page per call, and offers every
entry to the policy crate's `Best`, which keeps the one stopped first: the earliest class, then the
lowest rank within it, then the most pages, a tie going to the candidate offered first, so to the
earlier source and then to its earlier entry. svcmgr lists in its table order and gives every
service rank 0, so among services oomd stops the one with the most pages, a tie going to the one
earlier in svcmgr's table. The order is host-tested in the policy crate.

**Adding a source.** A source of another class is one more entry in oomd's list, with a class
declared after or before `Service` in the policy crate's `Class`; the ladder and the order do not
change. The program class, sessiond as its source, and svcmgr's list of sources are #1233's.

---

## Bounds

Each call to a source, a page of its list or a stop, is an `ipc_call_timeout` of at most 2000 ms
(`CALL_TIMEOUT_MS`), the wait for the source to receive it and for its reply, and the walk of one
source's list ends 4000 ms after it began (`LIST_WALK_MS`), each page's call bounded by the time
left. A time bound, not a count of pages, so a list of any length that its source answers at its
usual pace is read whole. A call that fails, times out or is refused, a reply that breaks the
protocol (an entry that does not decode, a page longer than `LIST_STOPPABLE_PAGE`, a cursor that
does not advance), or a list not read whole in time, is logged as
`<source>: candidates not read: <why>` and the walk goes on with what that source listed before it
and with the next source. So an act takes at most 4000 ms per source and 2000 ms for its stop, and
a wedged source delays the ladder by that bound, never more. A stop that times out may still have
stopped its candidate; the next act, a cooldown later, finds the level and the list as they are
then.

A read of the level waits for memmgr's answer, as every process's does: memmgr is the pager of every
process, oomd included, and a memmgr that does not answer leaves nothing for oomd to act through. A
wait on the Notification that fails with an error other than a timeout or an interruption is logged
and retried after 100 ms (`WAIT_RETRY_MS`).

---

## Limits

- oomd reaches only services that opt in. The processes svcmgr does not launch (memmgr, procmgr,
  devmgr, vfsd), the drivers devmgr starts, fatfs, and the programs a user starts are no source's
  candidates; a session's programs become candidates with #1233's program class.
- It stops the whole service: a service's memory is given back only by its death, and its
  supervisor restarts it under its restart policy and budget.
- It asks no service to give memory back and evicts nothing: memmgr's `LOW` broadcast asks, and
  eviction is #230's.
- It reads one level for the whole pool: a process at its own budget node's max is refused by its
  budget (decline code 10) at any level, and oomd does not act on it.

---

## Summarized By

[services/oomd/README.md](../README.md)
