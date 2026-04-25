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
  bootstrap; record the service name, capability set, and restart policy
- **Health monitoring** — hold thread lifecycle notification capabilities for
  monitored services; detect crashes via async notifications
- **Restart management** — on detected crash, request a restart through procmgr
  with the service's recorded initial capability set
- **procmgr fallback** — if procmgr crashes, use raw syscall capabilities to
  recreate procmgr from its boot module, then resume normal service monitoring
- **Shutdown** — coordinate ordered service shutdown when requested

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
| [docs/architecture.md](../docs/architecture.md) | System design, init/procmgr/svcmgr roles |
| [docs/capability-model.md](../docs/capability-model.md) | Capability types and revocation |
| [docs/coding-standards.md](../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
