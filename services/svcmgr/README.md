# svcmgr

Service health monitor and restart manager. Started by init before init exits;
runs for the lifetime of the system. svcmgr monitors registered services,
detects crashes (via thread lifecycle notifications), and requests restarts
through procmgr.

svcmgr also holds raw process-creation syscall capabilities as a fallback to
restart procmgr if procmgr itself crashes. This is the only service that can
create a process without going through procmgr.

---

## Source Layout

```
svcmgr/
├── Cargo.toml                  # Workspace member; no_std binary
├── README.md
├── src/
│   └── main.rs                 # _start() entry point, service manager stub
└── docs/
    └── restart-protocol.md     # Restart protocol and procmgr fallback
```

---

## Responsibilities

- **Service registration** — accept service registrations from init during
  bootstrap; record the service name, capability set, restart policy, and
  namespace-policy descriptor (`ns_policy_kind` / `ns_subtree_path` /
  `ns_subtree_rights`)
- **Health monitoring** — hold thread lifecycle notification capabilities for
  monitored services; detect crashes via async notifications
- **Restart management** — on detected crash, request a restart through procmgr
  with the service's recorded initial capability set; re-apply the stored
  namespace policy on every restart so attenuation survives crash cycles
- **procmgr fallback** — if procmgr crashes, use raw syscall capabilities to
  recreate procmgr from its boot module, then resume normal service monitoring
- **Shutdown** — coordinate ordered service shutdown when requested

---

## Namespace authority

Init spawns svcmgr with a namespace cap attenuated to the `/bin`
subtree at `LOOKUP|STAT|READ` rights (the precise mask the ELF
loader needs to walk and read child binaries). All svcmgr-side path
operations therefore start from a `/bin`-rooted cap:

- **Restart-time binary lookup** — when a registered VFS-loaded
  service crashes, svcmgr strips the `/bin/` prefix from the
  registered `vfs_path` (`b"/bin/crasher"` → `b"crasher"`) and walks
  its attenuated root. A registered path outside `/bin/` is rejected
  fail-closed; the partial child is torn down before the supervision
  loop retries.
- **Restart-time `NS_POLICY_SUBTREE` re-application** — the same
  `/bin/` strip applies to the stored subtree path; the walk uses
  the stored rights mask. The recovered directory cap is delivered
  to the restarted child via `procmgr_labels::CONFIGURE_NAMESPACE`.

The descriptor consumed by both paths arrives on the
`REGISTER_SERVICE` wire — see
[shared/ipc/src/lib.rs](../../shared/ipc/src/lib.rs) for the layout
and [docs/restart-protocol.md](docs/restart-protocol.md) for the
restart sequencing.

---

## Restart Policy

Each registered service has a restart policy:
- **Always** — restart unconditionally on crash (default for system services)
- **OnFailure** — restart only on non-zero exit (not on clean exit)
- **Never** — do not restart; notify operator only

Restart attempts are counted. After a configurable maximum (default: 5) in a
short window, the service is marked degraded and not restarted automatically.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System design, init/procmgr/svcmgr roles |
| [docs/capability-model.md](../../docs/capability-model.md) | Capability types and revocation |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md), [System Bootstrap](../../docs/bootstrap.md), [Process Lifecycle](../../docs/process-lifecycle.md)
