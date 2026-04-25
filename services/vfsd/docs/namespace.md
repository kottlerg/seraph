# Namespace

Mount point management and path resolution for the virtual filesystem namespace.

---

## Mount Table

vfsd maintains a fixed-size mount table mapping path prefixes to filesystem
driver endpoints. Maximum 4 mount entries.

Each entry contains:

| Field | Type | Description |
|---|---|---|
| `path` | `[u8; 64]` | Null-terminated mount path prefix (e.g., `/`, `/mnt/data`) |
| `path_len` | `usize` | Length of the path prefix in bytes |
| `driver_ep` | `u32` | Send-side capability to the filesystem driver's IPC endpoint |
| `active` | `bool` | Whether this entry is in use |

Mount entries are added during vfsd startup (from the startup message) and
potentially via future mount operations. Entries are removed on unmount or
driver crash.

---

## Path Resolution

Given an absolute path, vfsd resolves it to a mount entry using longest-prefix
matching:

1. Iterate all active mount entries.
2. For each entry, check whether the path starts with the entry's prefix.
3. Select the entry with the longest matching prefix.
4. Strip the matched prefix from the path to produce the driver-relative path.

For a mount at `/`, all paths match and the full path (minus the leading `/`)
is forwarded to the driver.

Case sensitivity depends on the underlying filesystem. vfsd performs
case-sensitive prefix matching on the mount path; case-insensitive matching
is the filesystem driver's responsibility.

---

## Design Status

The global mount namespace is a bootstrap-phase design. All processes share a
single, flat namespace managed by vfsd, and all mount operations are issued by
init during boot. This is sufficient for the current single-user, early-boot
service architecture but does not scale to multi-tenant or sandboxed workloads.

The long-term direction is per-process namespace capabilities: each process
receives a namespace cap that determines its filesystem view. A process could
hold a restricted namespace that omits sensitive mount points, or a completely
isolated namespace for containerized services. This requires no kernel changes
— the capability model already supports it — but requires vfsd to manage
multiple namespace objects and the process creation protocol to bind namespace
caps at creation time.

---

## Summarized By

None
