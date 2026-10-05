# netd

Network stack daemon (design intent; not yet implemented). Manages network interfaces via
driver IPC (receiving network device endpoints from devmgr), implements the protocol stack,
and exposes socket-like endpoints to applications.

netd talks to NIC drivers for packet send/receive and to applications for socket operations
(design intent; not yet implemented). No kernel networking code exists; network stacks run in
userspace (see [Architecture Overview](../../docs/architecture.md)).

---

## Source Layout

```
netd/
├── README.md
├── docs/
│   └── .gitkeep    # Placeholder; no component design documents yet
└── src/
    └── .gitkeep    # Placeholder; no source yet
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System-wide service inventory; netd's role; network stacks run in userspace |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md)
