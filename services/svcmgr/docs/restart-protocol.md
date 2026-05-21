# Restart Protocol

Crash detection via thread death notifications, restart sequencing,
shared spawn primitives, and criticality handling.

---

## Death detection

svcmgr binds every supervised service's main thread to one shared
EventQueue (`deaths_eq`) via `SYS_THREAD_BIND_NOTIFICATION`, using the
service's table index as the correlator. When a thread exits — either
cleanly via `SYS_THREAD_EXIT` or due to an unhandled fault — the
kernel posts `(correlator << 32) | exit_reason` to `deaths_eq`.

The WaitSet has two members: the service endpoint (token 0) and the
deaths queue (token 1). On wakeup svcmgr drains the queue and routes
each payload to its `ServiceEntry` via the correlator, then dispatches
through [`restart::handle_death`](../src/restart.rs).

Exit reason encoding:

| Value | Meaning |
|---|---|
| `0` | Clean exit (thread called `SYS_THREAD_EXIT`) |
| `EXIT_FAULT_BASE..` | Fault (exception vector / scause + base) |

---

## Decision tree

[`restart::handle_death`](../src/restart.rs) returns a
[`DeathOutcome`](../src/restart.rs) the dispatch loop routes:

1. **`critical = low`** → log `low-criticality death; informational`,
   mark service inactive, return `Degraded`.
2. **`should_restart(svc, exit_reason)`** evaluates the restart
   policy:
   * `POLICY_NEVER` → no restart.
   * `POLICY_ON_FAILURE` → restart iff `exit_reason >= EXIT_FAULT_BASE`.
   * `POLICY_ALWAYS` → restart unconditionally.
   * The restart-count budget (`MAX_RESTARTS`, currently `1`) is
     enforced here; an exhausted budget reports "max restarts reached,
     marking degraded" and returns false.
   * A missing restart source (`module_cap == 0` AND
     `vfs_path_len == 0`) reports "no restart source" and returns false.
3. **Restart not permitted** → mark service inactive; route to
   `unrecoverable_or_degraded`:
   * `critical = high` → log `critical service unrecoverable:
     <name>; initiating graceful shutdown`, return `Unrecoverable`.
   * Otherwise → return `Degraded`.
4. **Restart permitted** → call `restart_process`:
   * If `process_handle != 0` (svcmgr-launched services), send
     `procmgr_labels::DESTROY_PROCESS` to reclaim the previous
     instance's kernel objects. Init-spawned services start with
     `process_handle == 0`, so the first death cannot destroy;
     subsequent deaths can.
   * Spawn a fresh instance via the shared primitive
     [`walk_and_create_from_file`](#shared-spawn-primitives) (VFS
     path) or `CREATE_PROCESS` with a fresh module-cap derivation.
   * Re-apply the per-service namespace policy via
     [`apply_namespace_policy`](#shared-spawn-primitives).
   * Serve the restart bootstrap round (empty caps today; future
     work re-injects per-service seeds).
   * Rebind death-notification on the new thread cap using the same
     correlator so subsequent crashes route back to the same entry.
   * On success: increment `restart_count`, return `Restarted`.
   * On failure: route through `unrecoverable_or_degraded`.

`dispatch_deaths` reacts to `Unrecoverable` by calling
`initiate_graceful_shutdown`, which resolves
`ipc::published_names::PWRMGR_SHUTDOWN` from svcmgr's discovery
registry and issues `pwrmgr_labels::SHUTDOWN`. Edge case: a
`critical = high` pwrmgr death cannot trigger graceful shutdown
(the shutdown source is itself gone); svcmgr logs the degraded
state and returns.

---

## Shared spawn primitives

First-launch ([`definitions::launch`](../src/definitions/launch.rs))
and restart ([`restart::create_process`](../src/restart.rs)) share
the same procmgr-side primitives so a service's spawn shape is
identical across both code paths:

* [`mint_child_creator`](../src/restart.rs) — allocate a fresh
  bootstrap token + tokened SEND on svcmgr's `bootstrap_ep`.
* [`walk_and_create_from_file`](../src/restart.rs) — walk svcmgr's
  universal `root_dir_cap` for the binary path, then call
  `procmgr_labels::CREATE_FROM_FILE` with optional argv / env blobs.
  Restart-path callers pass `StartupBlobs::default()`; launch-path
  callers pass the argv / env blobs built from the `.svc` recipe.
* [`apply_namespace_policy`](../src/restart.rs) — `CONFIGURE_NAMESPACE`
  for `NS_POLICY_NONE` / `_UNIVERSAL` / `_SUBTREE` against svcmgr's
  universal root. Launch-path extends this locally with the optional
  `cwd` walk (cwd is launch-only; restart does not preserve cwd
  today).
* [`start_process`](../src/restart.rs) — `procmgr_labels::START_PROCESS`.

The launch path is documented in
[service-definitions.md](service-definitions.md#reconciliation); the
single-source-of-truth principle means both paths walk the same
`.svc` recipe on every spawn, so a binary update on disk is picked
up by the next restart without code changes.

---

## Recipe storage

svcmgr's `ServiceEntry` stores the parsed `.svc` recipe at
reconciliation time:

| Field | Source |
|---|---|
| `name` / `name_len` | `<name>.svc` filename |
| `vfs_path` / `vfs_path_len` | `binary = ...` |
| `restart_policy` | `restart = never \| on_failure \| always` |
| `criticality` | `critical = low \| normal \| high` |
| `ns_policy_kind` / `ns_subtree_path` / `ns_subtree_rights` | `namespace = ...` |
| `thread_cap` | v3 `REGISTER_SERVICE` cap (bind-only) or `Launched.thread_cap` (svcmgr-launched) |
| `process_handle` | `Launched.process_handle` for svcmgr-launched; `0` for init-spawned (see DESTROY_PROCESS comment above) |
| `module_cap` | `0` (no module-loaded services in the post-#21 model) |

argv / env / cwd / seed are not preserved on `ServiceEntry` today;
restart respawns with empty surfaces and the
`namespace`-recorded policy. Re-running the launch path on restart
(reading the `.svc` file from disk) is the natural follow-up when a
service requires those surfaces across crashes.

---

## Supervision hierarchy

svcmgr only supervises top-level services. Drivers (cmos / virtio-rtc
/ future block / net) are supervised by devmgr. Filesystem drivers
(fatfs / future ext / btrfs) are supervised by vfsd. None of those
flow through `REGISTER_SERVICE`.

The set of services svcmgr currently supervises (per the shipped
`.svc` files):

| Service | Source | Restart | Critical |
|---|---|---|---|
| `svctest` | svcmgr-launched | `never` | `low` |
| `crasher` | svcmgr-launched | `always` | `low` |
| `memmgr` | init-registered (bind only) | `never` | `high` |
| `procmgr` | init-registered (bind only) | `never` | `high` |
| `devmgr` | init-registered (bind only) | `never` | `high` |
| `vfsd` | init-registered (bind only) | `never` | `high` |
| `logd` | init-registered (bind only) | `never` | `high` |
| `timed` | init-registered (bind only) | `never` | `normal` |
| `pwrmgr` | init-registered (bind only) | `never` | `high` |

Restart paths for the bind-only set are aspirational today: most of
them were spawned with arch-/firmware-authority caps that init holds
and svcmgr cannot re-mint (memmgr/procmgr via raw `cap_create_*`
syscalls; devmgr/vfsd/logd with one-shot authority handover; pwrmgr
with `IoPortRange` / `SbiControl` / ACPI frames). When their
`.svc` `restart` value moves off `never` in the future, the spawn
path needs to gain access to those caps — either via a new
init→svcmgr handover round, or by relocating the spawn entirely
into svcmgr.

---

## procmgr Fallback

If procmgr itself crashes, svcmgr cannot use procmgr IPC to restart it.
svcmgr holds raw kernel capabilities (AddressSpace, CSpace, Thread
creation syscalls) as a documented future fallback to reconstruct
procmgr from its boot module. Not implemented today; procmgr's death
falls into the `CRITICALITY_HIGH` graceful-shutdown path.

---

## Summarized By

[svcmgr/README.md](../README.md)
