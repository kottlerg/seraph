# svcmgr

Service supervisor and discovery registry. Started by init before
init exits; runs for the lifetime of the system. svcmgr is a
self-driven process: it spawns into an already-running system (root
mounted; vfsd, procmgr, devmgr, fs/block drivers up), reads service
*definitions* from `/config/svcmgr/services/`, and reconciles them
against the substrate registrations init delivers in the handover
endowment to either supervise the running instance or launch a fresh
one.

svcmgr also owns the system-wide discovery registry: it publishes the
well-known names it owns (`rootfs.root`, `svcmgr`, `devmgr.registry`,
and each provider's `provides` names like `pwrmgr.shutdown` / `timed`)
into the registry itself — from the source caps init endows it with at
handover, and from each provider's launch — and consumers resolve them
via `QUERY_ENDPOINT` (or transparently through their `.svc` `seed = ...`
line at launch time).

svcmgr also holds raw process-creation syscall capabilities as a
documented future fallback to restart procmgr if procmgr itself
crashes. This is the only service that can create a process without
going through procmgr.

---

## Source layout

```
svcmgr/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs                    # _start, IPC dispatch, dispatch_deaths,
│   │                              # initiate_graceful_shutdown
│   ├── service.rs                 # ServiceEntry, RestartRecipe, SvcmgrCaps,
│   │                              # restart-policy constants
│   ├── restart.rs                 # Shared spawn primitives
│   │                              # (walk_and_create_from_file, mint_child_creator,
│   │                              # start_process, apply_namespace_policy),
│   │                              # death handling, DeathOutcome
│   ├── definitions/
│   │   ├── mod.rs                 # Definition struct + RestartPolicy /
│   │   │                          # NamespaceShape enums
│   │   ├── parse.rs               # `.svc` key=value parser
│   │   ├── launch.rs              # First-launch path
│   │   └── reconcile.rs           # PendingRegistration + reconcile_and_launch
│   └── arch/                      # Per-arch halt() entry
└── docs/
    ├── ipc-interface.md           # handover endowment, HANDOVER_COMPLETE,
    │                              # PUBLISH_ENDPOINT / QUERY_ENDPOINT
    ├── restart-protocol.md        # Death detection, restart sequencing,
    │                              # shared spawn primitives, criticality
    │                              # semantics
    └── service-definitions.md     # `.svc` recipe authoritative spec
```

---

## Responsibilities

- **Handover endowment** — drain init's bootstrap-round endowment in
  [`service::bootstrap_caps`](src/service.rs): svcmgr's own endpoints,
  the publish-role source caps (`rootfs.root` SEND, devmgr-registry
  `SEND|GRANT` source), and one `(name, thread_cap)` round per substrate
  service init bootstrapped before svcmgr existed. Recipes (binary,
  argv, env, restart policy, criticality, namespace shape, seed names)
  live on disk, not on the wire — see
  [docs/service-definitions.md](docs/service-definitions.md).
- **Reconciliation** — at `HANDOVER_COMPLETE` scan
  `/config/svcmgr/services/`, parse each `<name>.svc`, and pair it
  with the pending-registration table (substrate pairs parked from the
  endowment). Three outcomes: `bind only` (parked AND defined),
  `launching` (defined only), `registered without definition`
  (parked AND no recipe → hard error).
- **Launch** — for `defined only` services, spawn via the shared
  primitives in [`restart.rs`](src/restart.rs)
  (`walk_and_create_from_file`, `apply_namespace_policy`,
  `start_process`) and serve the seed bootstrap round.
- **Health monitoring** — bind every supervised service's main
  thread to one shared `deaths_eq` with `correlator =
  service_index`. Detect crashes via async notifications.
- **Restart management** — on detected crash, route through
  [`restart::handle_death`](src/restart.rs); shared spawn primitives
  re-spawn the service from the recorded recipe. The `.svc` file is the
  single source of truth for both launch and restart — fixed fields on
  `ServiceEntry`, the heap-backed argv/env/cwd/seed on a parallel
  `RestartRecipe` — so a restart reproduces the first-launch surfaces.
  Whether a service restarts is decided by its `restart` policy + budget
  alone; `critical` is orthogonal (see graceful shutdown below).
- **Discovery registry** — svcmgr publishes the names it owns directly
  (internal `registry.publish`); `PUBLISH_ENDPOINT` is the external
  write-API (reserved for a future devmgr publisher) and `QUERY_ENDPOINT`
  the lookup, served on the per-process SEND seeded into
  `ProcessInfo.service_registry_cap`.
- **Graceful shutdown** — when a `critical = yes` service is permanently
  down (restart not attempted or budget exhausted), resolve
  `ipc::published_names::PWRMGR_SHUTDOWN` from the registry and issue
  `pwrmgr_labels::SHUTDOWN`.

---

## Namespace authority

Init spawns svcmgr with the **universal** `system_root_cap` (post-#21).
svcmgr reads `/config/svcmgr/services/*.svc` directly via `std::fs`,
walks the recipe's `binary` path for first-launch, and applies per-service
namespace attenuation from each `.svc` `namespace = ...` line via
`procmgr_labels::CONFIGURE_NAMESPACE`. Restart-time attenuation reads
the same `ServiceEntry`-stored policy that reconcile installed.

svcmgr scans only `/config/svcmgr/services/`. The sibling directory
`/config/svcmgr/tests/` holds opt-in test-harness recipes; svcmgr never
reads it. The test gating contract — copy a `tests/<harness>.svc` into
`services/` between build and run — is owned by
[docs/testing.md](../../docs/testing.md).

---

## Service definitions

The authoritative spec lives in
[docs/service-definitions.md](docs/service-definitions.md). A
minimal example:

```
binary    = /tests/svctest
argv      = svctest run
env       = SERAPH_TEST=1 SERAPH_MODE=boot
restart   = never
critical  = no
namespace = universal
cwd       = /data
seed      = rootfs.root pwrmgr.shutdown pwrmgr.deny
```

Recognised keys: `binary` (required), `argv`, `env`, `restart`
(required), `critical` (required), `namespace` (required), `cwd`,
`seed`. Unknown keys are hard errors. Restart values:
`never | on_failure | always`. Critical values: `yes | no`.
Namespace forms: `none | universal | subtree:<path>:<rights>`.

---

## Cap publication

svcmgr publishes every well-known name into its own registry — there is
no init-side `PUBLISH_ENDPOINT` traffic. The first three are published in
`main()` right after the endowment is drained, from the source caps init
endows svcmgr with at handover; the provider names are published on each
provider's launch path. Names are FS-driver- and platform-agnostic by
design; consumers resolve them through their `.svc` `seed = ...` lines or
via direct `QUERY_ENDPOINT` calls.

| Name | Source | Cap shape |
|---|---|---|
| `rootfs.root` | svcmgr (endowed `rootfs.root` SEND) | tokened SEND on the root filesystem's namespace endpoint at its root directory |
| `svcmgr` | svcmgr (its own service ep) | un-tokened SEND on svcmgr's own service endpoint |
| `devmgr.registry` | svcmgr (minted from the endowed devmgr-registry source) | `REGISTRY_QUERY_AUTHORITY`-tokened SEND on devmgr's registry endpoint |
| `pwrmgr.shutdown` | svcmgr (`pwrmgr.svc` provider) | `SHUTDOWN_AUTHORITY`-tokened SEND on pwrmgr's service endpoint |
| `pwrmgr.deny` | svcmgr (`pwrmgr.svc` provider) | no-authority SEND on pwrmgr's service endpoint (negative-test twin) |
| `timed` | svcmgr (`timed.svc` provider) | SEND on timed's service endpoint |

Centralised name constants live in `ipc::published_names`.

---

## Criticality

`critical` is binary (`yes` / `no`) and orthogonal to `restart`: it
governs only what happens once a service is permanently down, not
whether it restarts. A `critical = yes` service triggers a graceful
shutdown via pwrmgr on permanent death (restart not attempted, or budget
exhausted); a `critical = no` service is logged and the system continues
degraded. Edge case: pwrmgr itself cannot trigger shutdown on its own
death (the shutdown source is gone); svcmgr logs the degraded state. See
[docs/restart-protocol.md](docs/restart-protocol.md) for the decision
tree.

---

## Restart policy

Each `.svc` carries `restart = never | on_failure | always`. Restart
attempts are counted per service. After a configurable maximum
(`MAX_RESTARTS`, currently `1`) in a short window, the service is
marked degraded and not restarted automatically. See
[docs/restart-protocol.md](docs/restart-protocol.md).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System design, init/procmgr/svcmgr roles |
| [docs/capability-model.md](../../docs/capability-model.md) | Capability types, verb-bit authority, revocation |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Userspace boot order, Phase 3 handover, process-death flow |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |
| [docs/documentation-standards.md](../../docs/documentation-standards.md) | Document hierarchy, authority, backlinks |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md), [System Bootstrap](../../docs/bootstrap.md), [Process Lifecycle](../../docs/process-lifecycle.md), [Testing](../../docs/testing.md)
