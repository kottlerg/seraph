# crasher

Test-tier fixture that validates svcmgr's restart path by crashing on purpose. It is gated and
opt-in: its recipe lives in `/config/svcmgr/tests/`, is co-staged with `svctest` in CI, and is
never launched on a normal boot.

On every spawn it checks that the recipe surfaces (argv, env, cwd, and bootstrap seeds) survived
and logs `<surface> ok` for each. It then logs `alive` and probes the svcmgr seed with a
`QUERY_ENDPOINT` for the unknown name `__probe__`, logging the reply label; any reply shows the
cap is live, and a call that gets no reply is a failed round-trip. Finally it faults on purpose
(a NULL write) so svcmgr respawns it under `restart = always`. A surface that fails to
round-trip, such as one dropped on restart, is logged with a `FATAL:` prefix, which the
`run-parallel` fail regex catches to fail the run. The deliberate `USERSPACE FAULT` does not
count as a failure.

A second role, selected by argv `crasher worker-fault`, checks that svcmgr routes the fault of a
thread other than the main thread. Its recipe, `rootfs/config/svcmgr/tests/crasher-worker.svc`
(`restart = on_failure`, `critical = no`, `namespace = none`, `provides = crasher.worker`,
`oom_stop = yes`), is
co-staged with `svctest` wherever `crasher.svc` is. The role takes the provided name's service
endpoint from bootstrap slot 0, logs `worker-fault: serving`, and serves
`ipc::restart_probe_labels`: `PROBE_INSTANCE` replies a per-instance random nonce in word 0, and
`PROBE_FAULT_WORKER` replies, then receives nothing more while a worker thread takes a terminal
fault after `FAULT_DELAY_MS` (200 ms), logging `worker-fault: worker thread faulting`. procmgr
tears the process down, and svcmgr restarts it through its address-space observer; svctest's
`svcmgr_worker_fault_restart` phase, which runs when this recipe is staged, reads a new nonce from
the restarted instance. `oom_stop = yes` makes it a service of that boot a stop-authority holder may
stop, as the `memhog` fixture does ([memhog](../memhog/README.md)): svctest's `svcmgr_stop_service`
phase lists it, has svcmgr stop it, and reads the restarted instance's nonce the same way. A role
that lacks its endpoint or nonce, or cannot start the worker, logs `FATAL: worker-fault: ...`.

A third role, selected by argv `crasher boot-fault`, checks that svcmgr routes the death of a
service that dies before its bootstrap request. Its recipe,
`rootfs/config/svcmgr/tests/crasher-boot.svc` (`restart = on_failure`, `critical = no`,
`namespace = subtree:/data/crasher-boot:LOOKUP+STAT+MUTATE_DIR`, `provides = crasher.boot`), is
co-staged with `svctest` wherever `crasher.svc` is. Before it asks for its bootstrap round, an
instance removes the token `/die-early` of its namespace (`/data/crasher-boot/die-early`): when the
removal succeeds it logs `boot-fault: token taken; faulting before the bootstrap request` and
faults its main thread; when the token is not there it serves as the `worker-fault` role does, on
`crasher.boot`. Any other failure of the removal logs `FATAL: boot-fault: ...`. The data partition
ships the token (`rootfs/data/crasher-boot/die-early`), so the first launch dies so, and svctest's
`svcmgr_boot_death` phase writes it again before it faults a serving instance's worker, so a
restart dies so too.

---

## Source Layout

```
crasher/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Surface checks, then the deliberate fault; the worker-fault and
                           #   boot-fault roles
```

---

## Capabilities

The bootstrap round delivers the recipe's two seeds again on every spawn and respawn (the
`worker-fault` and `boot-fault` roles instead receive their provided service endpoint in
`caps[0]`):

| Slot      | Cap                       |
|-----------|---------------------------|
| `caps[0]` | svcmgr service endpoint   |
| `caps[1]` | pwrmgr deny twin          |

The log and procmgr endpoints come in through `ProcessInfo`, so they are not part of the
bootstrap round.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | How harnesses and fixtures are staged and co-staged |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Process startup and `ProcessInfo` handover |
| [Restart Protocol](../svcmgr/docs/restart-protocol.md) | svcmgr restart policy |

---

## Summarized By

None
