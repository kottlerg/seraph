# shared/registry-client

Client-side helper for the svcmgr name-to-cap discovery registry. Each process's
`process_abi::ProcessInfo` carries at most one registry cap, the `service_registry_cap` procmgr
seeds (per [abi/process-abi/README.md](../../abi/process-abi/README.md)); this crate caches
that one cap. `install_registry_cap` stores it in a process-global atomic once in `_start`, and
`registry_cap` reads it back so callers can issue `QUERY_ENDPOINT` without threading the cap
through every API. `pack_name` packs a name of at most `NAME_MAX` = 16 bytes into `NAME_WORDS`
payload words. Lookups are reentrant; svcmgr derives a fresh SEND on every lookup (per
[services/svcmgr/docs/ipc-interface.md](../../services/svcmgr/docs/ipc-interface.md) § Label 4:
`QUERY_ENDPOINT`), and callers cache the returned cap themselves. `publish` issues
`PUBLISH_ENDPOINT` and succeeds only when the cached cap is stamped with `PUBLISH_AUTHORITY`.

`no_std`; builds inside std's dependency graph through the `rustc-dep-of-std` feature.

---

## Source Layout

```
shared/registry-client/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # Cap cache, pack_name, lookup, publish
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/svcmgr/README.md](../../services/svcmgr/README.md) | Cap publication and the discovery registry |
| [abi/process-abi/README.md](../../abi/process-abi/README.md) | `ProcessInfo` field `service_registry_cap` that seeds the registry cap |
| [services/svcmgr/docs/ipc-interface.md](../../services/svcmgr/docs/ipc-interface.md) | `PUBLISH_ENDPOINT` and `QUERY_ENDPOINT` wire format and replies |
| [shared/registry/README.md](../registry/README.md) | Server-side registry storage |

---

## Summarized By

None
