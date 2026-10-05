# shared/registry-client

Client-side helper for the svcmgr name-to-cap discovery registry. Each process holds at most
one cap on svcmgr's service endpoint, the `service_registry_cap` procmgr seeds in
`process_abi::ProcessInfo`; `install_registry_cap` caches it in a process-global atomic once
in `_start`, and `registry_cap` reads it back so callers can issue `QUERY_ENDPOINT` without
threading the cap through every API. `pack_name` packs a name of at most `NAME_MAX` = 16 bytes
into `NAME_WORDS` payload words. Lookups are reentrant; svcmgr derives a fresh SEND on every
lookup, and callers cache the returned cap themselves.

`no_std`; builds inside std's dependency graph through the `rustc-dep-of-std` feature.

---

## Source Layout

```
shared/registry-client/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # Cap cache, pack_name, lookup
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/svcmgr/README.md](../../services/svcmgr/README.md) | Cap publication and the discovery registry |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | `ProcessInfo` handover that seeds the registry cap |
| [shared/registry/README.md](../registry/README.md) | Server-side registry storage |

---

## Summarized By

None
