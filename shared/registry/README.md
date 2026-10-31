# shared/registry

Growable name-to-endpoint-cap registry for supervisor services.

---

## Overview

A supervisor (svcmgr) holds a `Registry` that maps short byte-string names (at most `NAME_MAX` =
64 bytes, the svcmgr protocol's one name limit `ipc::svcmgr_labels::NAME_MAX`) to
capability-slot indices in its own CSpace. Entries live on the heap, one per published name, so
the table has no fixed count; a publish fails only when the heap cannot grow it. A lookup
requires a full bytewise name match, with no prefix or glob matching.

Each entry is published `Public` or `SeedOnly`. A lookup names its resolver: `Query` (a
`QUERY_ENDPOINT` caller) sees only `Public` entries, and `Seed` (the supervisor itself: its
recipes' seed lists and its own lookups) sees both, so a `SeedOnly` name reaches only the
recipes that seed it (per
[services/svcmgr/docs/ipc-interface.md](../../services/svcmgr/docs/ipc-interface.md)
§ Label 4: `QUERY_ENDPOINT`).

`no_std` outside host tests, with `alloc`; its one dependency is `shared/ipc`, for the name
limit.

---

## Source Layout

```
shared/registry/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # NAME_MAX, Visibility, Resolver, Entry, Registry; host tests
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
