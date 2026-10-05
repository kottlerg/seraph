# shared/ns-client

`no_std` namespace walk helpers for any service holding a badged SEND on a vfsd namespace
endpoint. `walk_to_file` resolves a path to a per-file cap, for example before
`procmgr_labels::CREATE_FROM_FILE`; `walk_to_dir` derives an attenuated subtree or cwd cap to
install on a child through `procmgr_labels::CONFIGURE_NAMESPACE`. Both issue one `NS_LOOKUP`
per path component, mirroring the walk in `runtime/ruststd/src/sys/fs/seraph.rs`, and send
`requested_rights` on every hop, so the returned cap carries at most those rights; `0xFFFF`
selects each entry's full `max_rights`.

---

## Source Layout

```
shared/ns-client/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # WalkedFile, walk_to_file, walk_to_dir
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/namespace-model.md](../../docs/namespace-model.md) | Node caps, rights narrowing, walking |
| [shared/namespace-protocol/README.md](../namespace-protocol/README.md) | `NS_LOOKUP` wire format and rights composition |

---

## Summarized By

None
