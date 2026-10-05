# shared/registry

Fixed-capacity name-to-endpoint-cap registry for supervisor services. A supervisor (svcmgr)
holds a `Registry<N>` that maps short ASCII names (at most `NAME_MAX` = 16 bytes) to
capability-slot indices in its own CSpace; its `QUERY_ENDPOINT` handler calls
`Registry::lookup` and attaches the cap to the reply. Storage is statically sized for the
`no_std`, no-allocator userspace, and a lookup requires a full name match, with no prefix or
glob matching.

`no_std`, no dependencies.

---

## Source Layout

```
shared/registry/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # NAME_MAX, Entry, Registry<N>
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/svcmgr/README.md](../../services/svcmgr/README.md) | Cap publication and the discovery registry |
| [shared/registry-client/README.md](../registry-client/README.md) | Client side of `QUERY_ENDPOINT` |

---

## Summarized By

None
