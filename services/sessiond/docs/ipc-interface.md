# sessiond IPC Interface

IPC interface specification for sessiond: the operator labels an interface registers itself and
opens sessions with, and the stop labels a stop-authority holder lists and stops a session's
programs with. The label values, the reply codes and their documentation are
`shared/ipc/src/sessiond_labels.rs`; the stop labels are `shared/ipc/src/stop_labels.rs`, shared
with every stop source.

---

## Endpoint

sessiond serves one endpoint, the one its recipe provides. svcmgr publishes a SEND on it as
`sessiond.operator`, badged `OPERATOR_AUTHORITY` (bit 63, the recipe's `:grant` entry) with
`SEND|GRANT`, and seeds it only to the recipes that name it. The `GRANT` lets an interface move its
end queue, relay and stdio caps to sessiond, and so lets it send any cap: sessiond checks the type
and rights of each cap a request carries (`cap_info`) before it keeps or forwards one, replies
`INVALID_ARGUMENT` to a cap that fails, and deletes every cap it does not keep. A stop-authority
holder receives a SEND on it badged `stop_labels::STOP_AUTHORITY` from svcmgr's `LIST_STOP_SOURCES`
([svcmgr IPC Interface](../../svcmgr/docs/ipc-interface.md) § Label 7). The endpoint persists across
sessiond's restarts, so a SEND that is held reaches the next instance.

| Badge carries | Labels served | Any other label |
|---|---|---|
| `STOP_AUTHORITY` | `STOP_CANDIDATE` (5), `LIST_CANDIDATES` (6) | `UNAUTHORIZED` for an operator label, `UNKNOWN_OPCODE` otherwise |
| `OPERATOR_AUTHORITY` | `REGISTER_INTERFACE` (1), `OPEN_SESSION` (2), `SESSION_STDIO` (3), `START_SESSION` (4) | `UNAUTHORIZED` for a stop label, `UNKNOWN_OPCODE` otherwise |
| neither | none | `UNAUTHORIZED` |

Every cap a request carries that sessiond does not keep or move is deleted, whatever the reply.

---

## Names

- **Nonce.** An interface names itself by a nonzero random value it draws and registers. The nonce
  confers nothing beyond the badge of the call that carries it; a new sessiond instance knows no
  nonce, and answers `UNKNOWN_INTERFACE` until the interface registers again.
- **Key.** A session is named by its key, to its interface and to a stop-authority holder alike: a
  value with bit 63 set, a generation and the session's table slot. A job is named, to a
  stop-authority holder, by its procmgr process badge, which never has bit 63 set. A key names one
  candidate and no other across sessiond's instances: each instance starts its slots' generations
  at a random draw of its own, so a session key an earlier instance handed out names a session of a
  later one with a probability of about 2^-31, and procmgr never hands out a process badge twice.

---

## Opening a session

An interface registers once per sessiond instance, then opens each session in three steps, all on
the operator SEND:

1. `OPEN_SESSION` with its nonce and a POST cap on an event queue of its own, the leader's death
   relay. sessiond makes the session's node and creates the leader, suspended, and replies the
   key.
2. `SESSION_STDIO` once per stream (stdin, stdout, stderr), with the key, the direction, the ring
   capacity and the ring's three caps, which sessiond installs on the leader with procmgr's
   `CONFIGURE_PIPE` ([procmgr IPC Interface](../../procmgr/docs/ipc-interface.md)).
3. `START_SESSION` with the key: sessiond hands the leader a copy of its namespace root and starts
   it.

The interface learns of the session's end from the relay, which procmgr posts once, after it has
torn the leader down: the leader's exit reason, its fault, or `EXIT_KILLED` for a destroy. No ring
is mapped by a leader before step 2, so after a refusal at step 1 no leader holds one. A refusal at
step 2 other than `UNKNOWN_INTERFACE` and `NO_SESSION`, and a refusal at step 3 other than those
two, ends the session, and its relay is posted. ruststd's
`std::os::seraph::process::SessionStdio` makes the three pipes and the relay, hands over their
caps, and returns each ring to memmgr once the relay has been read, or at once after a refusal at
step 1 ([runtime/ruststd/README.md](../../../runtime/ruststd/README.md)).

---

## Label 1: `REGISTER_INTERFACE`

| Field | Value |
|---|---|
| `data[0]` | The interface's nonce, nonzero |
| `data[1]` | `SESSIOND_LABELS_VERSION` (currently `1`) |
| `caps[0]` | A RECV cap on the end queue the interface registered on itself with procmgr's `REGISTER_END_QUEUE`; kept on success |

sessiond adds the queue to its wait set, and ends every session of the interface when the queue
receives an entry, the interface's end, whatever ended it.

| Reply | When |
|---|---|
| `SUCCESS` (0) | Registered |
| `VERSION_MISMATCH` (8) | `data[1]` is another version |
| `INVALID_ARGUMENT` (5) | A zero nonce, a nonce already registered, no cap or a cap that is not an EventQueue with `RECV`, or a queue the wait set refuses |
| `TABLE_FULL` (4) | `INTERFACE_MAX` interfaces are registered |

---

## Label 2: `OPEN_SESSION`

| Field | Value |
|---|---|
| `data[0]` | The interface's nonce |
| `caps[0]` | A POST cap on the interface's relay queue; moved to procmgr with the leader's create, or deleted |

| Reply | When |
|---|---|
| `SUCCESS` (0) | The leader is created, suspended; `data[0]` is the session's key |
| `UNKNOWN_INTERFACE` (2) | No interface holds the nonce |
| `INVALID_ARGUMENT` (5) | No cap, or a cap that is not an EventQueue with `POST` |
| `MEMORY_CRITICAL` (3) | memmgr's pressure level reads `CRITICAL`; the interface waits for it to change and asks again |
| `TABLE_FULL` (4) | `SESSION_MAX` sessions are held |
| `CREATE_FAILED` (6) | The node or the leader was not made; `data[0]` is memmgr's or procmgr's error, or 0 for a step of sessiond's own (the lookup of the leader's binary, a derivation, a death binding) |

On every refusal no leader exists: the relay is deleted, or posted when a leader was made and
destroyed again because its death could not be watched.

---

## Label 3: `SESSION_STDIO`

| Field | Value |
|---|---|
| `data[0]` | The interface's nonce |
| `data[1]` | The session's key |
| `data[2]` | The direction: `PIPE_DIR_STDIN` (0), `PIPE_DIR_STDOUT` (1) or `PIPE_DIR_STDERR` (2) |
| `data[3]` | The ring capacity in bytes |
| `caps[0..3]` | The ring's memory cap, its data notification and its space notification; moved to procmgr, or deleted |

| Reply | When |
|---|---|
| `SUCCESS` (0) | Installed |
| `UNKNOWN_INTERFACE` (2) | No interface holds the nonce |
| `NO_SESSION` (7) | The key names no session of the interface that has not started |
| `INVALID_ARGUMENT` (5) | A direction past `PIPE_DIR_STDERR`, or a cap missing or of the wrong type or rights (a Memory cap with `MAP\|WRITE`, two Notifications with `NOTIFY\|WAIT`); the session is ended |
| `CREATE_FAILED` (6) | procmgr refused `CONFIGURE_PIPE`; `data[0]` is its error, or 0 for a failed call; the session is ended |

---

## Label 4: `START_SESSION`

| Field | Value |
|---|---|
| `data[0]` | The interface's nonce |
| `data[1]` | The session's key |

sessiond sends the leader procmgr's `CONFIGURE_NAMESPACE` with a copy of its own root and no
working directory, then `START_PROCESS`.

| Reply | When |
|---|---|
| `SUCCESS` (0) | The leader runs; the session is a candidate |
| `UNKNOWN_INTERFACE` (2) | No interface holds the nonce |
| `NO_SESSION` (7) | The key names no session of the interface that has not started |
| `CREATE_FAILED` (6) | procmgr refused a step; `data[0]` is its error, or 0 for a failed call or copy; the session is ended |

---

## Label 5: `STOP_CANDIDATE`

On a `STOP_AUTHORITY` badge, as [svcmgr IPC Interface](../../svcmgr/docs/ipc-interface.md)
§ Label 5 specifies the label for every source. `data[0]` is the key:

- A session's key, of a started session: sessiond destroys the leader, procmgr destroys every
  process below it and posts the relay, and sessiond releases the session's node. `SUCCESS`.
- A job's key: sessiond sends `DESTROY_CHILD` with the badge on each started leader's handle until
  one destroys it. `SUCCESS`; `UNAVAILABLE` (3) when procmgr refuses otherwise than for a badge
  that is not that leader's child.
- Any other value, a session not started, or a job no leader has: `NO_CANDIDATE` (2).

---

## Label 6: `LIST_CANDIDATES`

On a `STOP_AUTHORITY` badge, as [svcmgr IPC Interface](../../svcmgr/docs/ipc-interface.md)
§ Label 6 specifies the label for every source. The walk visits each started session in slot
order, the session first, then each child of its leader:

| Candidate | Key | Rank | Pages | Name |
|---|---|---|---|---|
| A session | Its key | `RANK_SESSION` (1) | Its node's subtree pages (memmgr's `NODE_QUERY_USAGE`) | `session <slot>` |
| A job | Its process badge | `RANK_JOB` (0) | Its subtree pages (procmgr's `LIST_CHILDREN`) | procmgr's name of the child, or `job` when it has none |

The cursor is the ordinal of the next entry of the walk, which sessiond makes again for each page;
a reply's next cursor is greater than the one asked. A session not started is not listed. The reply
is `UNAVAILABLE` (3) when memmgr or procmgr does not answer.

---

## Summarized By

[services/sessiond/README.md](../README.md)
