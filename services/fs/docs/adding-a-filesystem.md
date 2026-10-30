# Adding a Filesystem

The procedure for adding a filesystem driver under `services/fs/`. The driver model is in
[README.md](../README.md), and the protocol a driver serves in
[fs-driver-protocol.md](fs-driver-protocol.md).

---

## Procedure

1. Create a subdirectory under `fs/` named for the filesystem (e.g.
   `ext4/`, `tmpfs/`).
2. Add a `Cargo.toml` for a binary crate that depends on the
   `namespace-protocol` and `ipc` crates from `shared/`.
3. Implement `namespace_protocol::NamespaceBackend` for your
   storage layer; route incoming `NS_*` labels through
   `namespace_protocol::dispatch_request` (see
   [`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md)
   § Backend trait) and the surviving `FS_*` labels through your own
   dispatcher (see [`docs/fs-driver-protocol.md`](fs-driver-protocol.md)).
4. For disk-backed filesystems, read from the partition-scoped block
   device endpoint vfsd delivers at mount time (see
   [`docs/fs-driver-protocol.md`](fs-driver-protocol.md) § Bootstrap caps).
5. For in-memory filesystems (e.g. tmpfs), no block device endpoint
   is needed; the storage layer lives in driver-private RAM.

---

## Summarized By

[services/fs/README.md](../README.md)
