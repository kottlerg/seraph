# `.svc` Service Definitions

Authoritative spec for the `/config/svcmgr/services/<name>.svc` files
svcmgr scans at `HANDOVER_COMPLETE` to reconcile init's pending
`REGISTER_SERVICE` announcements with the on-disk service recipes.

## Authority

`.svc` files are the **single source of truth** for a service's
recipe. First-launch (svcmgr launches the service post-handover) and
restart (svcmgr respawns a crashed service) read the same file. No
recipe travels on the wire.

## Filesystem layout

* Directory: `/config/svcmgr/services/`
* Filename: `<name>.svc`. The `<name>` portion is the key under which
  the service registers with svcmgr (the `name` field of the
  [v3 `REGISTER_SERVICE`](ipc-interface.md#label-1-register_service)
  wire). Filenames are ASCII; case-sensitive `.svc` suffix.
* Files are shipped via `rootfs/config/svcmgr/services/` and installed
  into the sysroot by xtask's recursive `install_rootfs` copy. No
  build-system change is required to add a new recipe — drop the
  file in `rootfs/config/svcmgr/services/` and rebuild.

## Grammar

Line-oriented `key = value`. Lines starting with `#` are comments.
Blank lines are tolerated. Whitespace around `=` is tolerated.
Unknown keys are **hard errors** — a typo cannot silently degrade a
service.

```
# /tests/svctest — services-surface test harness.
binary    = /tests/svctest
argv      = svctest run
env       = SERAPH_TEST=1 SERAPH_MODE=boot
restart   = never
critical  = low
namespace = universal
cwd       = /data
seed      = rootfs.root pwrmgr.shutdown pwrmgr.deny
```

## Keys

| Key | Required | Value |
|---|---|---|
| `binary` | yes | Absolute path under svcmgr's root. Walked from `system_root_cap` at launch / restart. |
| `argv` | no | Space-separated tokens. Becomes NUL-separated, NUL-terminated bytes on the wire. |
| `env` | no | Space-separated `KEY=VAL` tokens. Same NUL packing as `argv`. |
| `restart` | yes | One of `never`, `on_failure`, `always`. |
| `critical` | yes | One of `low`, `normal`, `high`. |
| `namespace` | yes | One of `none`, `universal`, `subtree:<path>:<rights>`. |
| `cwd` | no | Path interpreted relative to svcmgr's universal root. Forbidden when `namespace = none`. |
| `seed` | no | Space-separated discovery-registry names, resolved positionally (cap[i] = i-th name). |

## `restart`

| Value | Semantics |
|---|---|
| `never` | Service is one-shot; never restarted, even on fault. Used for integration-test fixtures (e.g. `svctest`) whose clean exit is the success signal. |
| `on_failure` | Restart only on a fault exit (`exit_reason >= EXIT_FAULT_BASE`). Clean exits are treated as intentional. |
| `always` | Restart on every exit, clean or faulty. Default for daemons that should never terminate during normal operation. |

Restart attempts are counted per service. After
`service::MAX_RESTARTS` (currently `1`) consecutive restarts in a
short window, the service is marked degraded and not restarted
automatically — see [restart-protocol.md](restart-protocol.md).

## `critical`

| Value | Behaviour on death |
|---|---|
| `low` | Logged; service marked inactive. No further action. |
| `normal` | Existing restart-budget envelope applies. Once exhausted the service is left dead; system continues degraded. |
| `high` | When `should_restart` says no (either `restart = never`, budget exhausted, or restart attempt failed), svcmgr logs `critical service unrecoverable: <name>; initiating graceful shutdown` and issues [`pwrmgr_labels::SHUTDOWN`](../../../shared/ipc/src/lib.rs) via the cap it resolves from [`published_names::PWRMGR_SHUTDOWN`](../../../shared/ipc/src/lib.rs). |

**pwrmgr's own death** is the edge case. If a `critical = high`
service that *is* `pwrmgr` dies unrecoverably, the shutdown source is
itself gone; svcmgr logs `critical service unrecoverable: pwrmgr;
graceful shutdown impossible; system in degraded state` and takes no
further action. No fallback raw-shutdown path is provided — the
same shape as today's lack of a recovery story for procmgr / memmgr
death.

## `namespace`

The primary lever for confining a service to only what it needs.

| Form | Effect |
|---|---|
| `none` | No namespace cap delivered. The child's `ProcessInfo.system_root_cap` stays zero; std-side absolute-path filesystem operations return `Unsupported`. Default tight choice for services with no filesystem dependency. |
| `universal` | `cap_copy` of svcmgr's own root (post-#21: the system universal root). Reserved for services that need genuine root authority (vfsd as the namespace authority, devmgr for `/dev`, procmgr for walking `/services` and `/programs`, svctest as the namespace tester). |
| `subtree:<path>:<rights>` | Walk `<path>` from svcmgr's root requesting `<rights>` per hop, hand the resulting directory cap to the child. `<rights>` is a `+`-joined list of named tokens (`LOOKUP`, `READDIR`, `STAT`, `READ`, `WRITE`, `EXEC`, `MUTATE_DIR`, `ADMIN` — see [`shared/namespace-protocol/src/rights.rs`](../../../shared/namespace-protocol/src/rights.rs)). Unknown tokens are parser errors. Empty rights list is a parser error. |

Example subtree clause:

```
namespace = subtree:/data:LOOKUP+READDIR+STAT+READ+WRITE
```

## `cwd`

When set, svcmgr walks `<cwd>` from its own root with
`LOOKUP+READDIR+STAT+READ` rights and passes the resulting directory
cap as the child's `ProcessInfo.current_dir_cap`. The path must
resolve inside the namespace. With `namespace = none`, `cwd` is a
parser error.

`std::env::current_dir()` returns `Unsupported` until a path string
is recorded via `std::env::set_current_dir`; the cap and the
path-string surface are independent. See svctest's
`env_cwd_unset_phase` for the assertion.

## `seed`

Space-separated discovery-registry names. svcmgr resolves each name
to a freshly-derived `RIGHTS_SEND` cap on the published endpoint and
injects them positionally into the child's bootstrap round:

```
seed = rootfs.root pwrmgr.shutdown pwrmgr.deny
```

becomes `caps = [rootfs_root_send, pwrmgr_shutdown_send,
pwrmgr_deny_send]` on the child's `bootstrap::request_round`. The
list is truncated to `MSG_CAP_SLOTS_MAX` (currently 4) entries; any
truncation is logged.

An unresolved name leaves slot `i` as `0`. Consumers that already
tolerate `cap == 0 → skip` (e.g. svctest's pwrmgr phases) continue
to work; consumers that don't fail on first use, which is the right
surface for a real misconfiguration.

Well-known names are centralised in
[`ipc::published_names`](../../../shared/ipc/src/lib.rs):

| Name | Publisher (today) | Cap shape |
|---|---|---|
| `rootfs.root` | init Phase 3 | tokened SEND on the root filesystem's namespace endpoint at its root directory (FS-driver-agnostic) |
| `pwrmgr.shutdown` | init Phase 3 | `SHUTDOWN_AUTHORITY`-tokened SEND on pwrmgr's service endpoint |
| `pwrmgr.deny` | init Phase 3 | no-authority SEND on pwrmgr's service endpoint (negative-test twin) |
| `svcmgr` | init Phase 3 | un-tokened SEND on svcmgr's own service endpoint |

## Reconciliation

At `HANDOVER_COMPLETE` svcmgr scans `/config/svcmgr/services/`, parses each
`<name>.svc`, and reconciles against init's pending-registration
table:

| Definition | Pending registration | Outcome |
|---|---|---|
| present | present | **bind only** — bind death-notification on the registered thread cap; record a `ServiceEntry` with the parsed recipe for restart use. |
| present | absent | **launching** — svcmgr launches the service via [`definitions::launch`](../src/definitions/launch.rs): walk `binary`, `CREATE_FROM_FILE` with argv/env, `CONFIGURE_NAMESPACE` with the namespace+cwd, `START_PROCESS`, serve the seed bootstrap round. If `restart != never`, bind death-notification and record a `ServiceEntry`. |
| absent | present | **error** — `registered without definition: <name>; refusing to bind`. svcmgr has no recipe; a registration without a matching `.svc` is a configuration error. |

## Relevant Design Documents

| Document | Content |
|---|---|
| [README.md](../README.md) | Component scope, responsibilities, restart policy |
| [ipc-interface.md](ipc-interface.md) | v3 `REGISTER_SERVICE` wire, `HANDOVER_COMPLETE`, `PUBLISH_ENDPOINT` / `QUERY_ENDPOINT` |
| [restart-protocol.md](restart-protocol.md) | Restart sequencing, shared spawn primitives, criticality semantics |
| [shared/ipc/src/lib.rs](../../../shared/ipc/src/lib.rs) | `published_names` constants, `svcmgr_labels::*`, `svcmgr_errors::*` |

---

## Summarized By

[svcmgr/README.md](../README.md)
