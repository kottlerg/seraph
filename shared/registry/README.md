# shared/registry

Fixed-capacity name-to-endpoint-cap registry for supervisor services. A supervisor (svcmgr)
holds a `Registry<N>` that maps short byte-string names (at most `NAME_MAX` = 16 bytes) to
capability-slot indices in its own CSpace. Storage is statically sized (`N` entries of
`NAME_MAX`-byte names) and the crate needs no allocator. A lookup requires a full bytewise
name match, with no prefix or glob matching.

Each entry is published `Public` or `SeedOnly`. A lookup names its resolver: `Query` (a
`QUERY_ENDPOINT` caller) sees only `Public` entries, and `Seed` (the supervisor itself: its
recipes' seed lists and its own lookups) sees both, so a `SeedOnly` name reaches only the
recipes that seed it.

`no_std` outside host tests, no dependencies.

---

## Source Layout

```
shared/registry/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # NAME_MAX, Visibility, Resolver, Entry, Registry<N>; host tests
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
