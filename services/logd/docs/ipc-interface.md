# logd IPC interface

logd is the receive-side of the master log endpoint. It does not
publish a separate service endpoint; every userspace sender already
holds a tokened SEND cap on the log endpoint (seeded by procmgr at
spawn time, or installed by init for itself / procmgr-self). The
labels documented below are the ones logd's receive loop dispatches
on.

logd additionally calls procmgr's
[`procmgr_labels::REGISTER_DEATH_EQ`](../../procmgr/docs/ipc-interface.md)
once during its own startup; see that document for the wire format.

## Endpoint

| Cap holder | Right | Purpose |
|---|---|---|
| logd's main thread | `RECV` | drains the endpoint via `ipc_recv` inside the wait-set loop |
| every userspace sender | `SEND` (tokened) | `STREAM_BYTES`, `STREAM_REGISTER_NAME` |
| real-logd at bootstrap | `SEND` (un-tokened) | single-use `HANDOVER_PULL` to init-logd; deleted immediately after `DONE` |

## Labels accepted

### `stream_labels::STREAM_BYTES` (10)

Per-line byte stream. Sender packs the chunk byte length into the
label's upper 16 bits (`label | ((len << 16))`). Inline bytes
arrive in the IPC message's data words, packed at word 0. logd
appends the bytes to the slot keyed by the kernel-delivered
`msg.token`; every `\n` flushes the slot's partial buffer as one
line (rendered to serial as `[sec.usfrac] [name] <line>\r\n` and
appended to the slot's history ring).

Lines exceeding `LINE_BUF_SIZE` (256 bytes) flush without a
trailing `\n` to keep the per-line attribution visible. Senders
that have not yet called `STREAM_REGISTER_NAME` render as `[?]`.

Reply: `label = 0` (success), empty payload. Sender unblocks.

### `stream_labels::STREAM_REGISTER_NAME` (11)

Register or update the display name for the sender identified by
`msg.token`. Inline bytes carry the name; the label's upper 16
bits carry the name length. Long names truncate at `MAX_NAME_LEN`
(48 bytes).

No collision-suffix policy: procmgr's per-child process token is
unique within the system, so display-name collisions only occur if
two processes intentionally pick the same string. logd allows
that.

Reply: `label = 0`. Sender unblocks.

### `log_labels::HANDOVER_PULL` (13)

One-shot init-logd → real-logd state transfer. Documented in
[`handover-protocol.md`](handover-protocol.md). logd's own receive
loop accepts the label too, but real-logd never receives it post-
handover (no caller in the system holds a SEND cap suitable for
the handover after init-logd exits). The handler in real-logd is
unreachable; init-logd is the only intended target.

### `log_labels::GET_LOG_CAP` (12) — legacy

Pre-pivot discovery path. Reserved in the label table for backward
compatibility but no caller in the current codebase issues it
(every spawn receives a pre-installed tokened SEND cap in
`ProcessInfo.log_send_cap`). logd replies empty if it ever
arrives, so an out-of-tree v0 caller fails closed without crashing
logd. A follow-up PR removes the label entirely once the
pre-pivot discovery path is gone for good.

## Wait-set

logd's main loop waits on a 2-member `WaitSet`:

| Token | Source | Purpose |
|---|---|---|
| `WS_TOKEN_LOG` (0) | RECV on the master log endpoint | `STREAM_BYTES` / `STREAM_REGISTER_NAME` arrivals |
| `WS_TOKEN_DEATH` (1) | RECV on logd's death-notification `EventQueue` | drained per loop iteration before service dispatch |

Death events are drained inside every loop iteration (before
servicing the log endpoint) so a recently-died sender's slot is
evicted before logd processes any of its still-queued
`STREAM_BYTES`. Mirrors procmgr's drain-deaths-first pattern.

## Death-notification cascade

Every process spawned by procmgr is bound to two death observers
at creation:

1. Procmgr's own death `EventQueue` (correlator = process token,
   for procmgr's auto-reap path).
2. logd's death `EventQueue` (correlator = process token, for
   logd's slot eviction).

Procmgr installs the second binding inside
[`finalize_creation`](../../procmgr/src/process.rs) when its
`LOGD_DEATH_EQ` static is non-zero, AND retroactively across every
existing process table entry when logd's
`REGISTER_DEATH_EQ` IPC arrives. Children spawned before logd
registers see only the first binding until the retroactive bind
catches them up.

logd's drain consumes each event as
`(process_token as u32) << 32 | exit_reason` and evicts the
matching slot from the hash-keyed token table. Idempotent on
already-evicted tokens.
