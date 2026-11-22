// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/published_names.rs

//! Well-known names published into svcmgr's discovery registry.
//!
//! Centralised so the publisher (`svcmgr`, post-handover — from source
//! caps init endows it in the handover endowment, plus each provider's
//! `provides` names) and consumers (`svcmgr` resolving each `.svc`'s
//! `seed = ...` list during launch, and any process via
//! `QUERY_ENDPOINT`) share the exact spelling. A typo on either side
//! leaks out as `svcmgr_errors::UNKNOWN_NAME` rather than
//! `INSUFFICIENT_CAPS`.
//!
//! Names are FS-driver- and platform-agnostic by design: swapping the
//! root filesystem from fatfs to e.g. ext4, or replacing pwrmgr's
//! platform shutdown source, changes only the publisher's local
//! derivation, not the published name nor any consumer.
//!
//! A name whose cap carries authority is seed-only: `rootfs.root`, the
//! five `devmgr.*` names, [`published_names::VFSD_MOUNT`](crate::published_names::VFSD_MOUNT),
//! [`published_names::VFSD_SWAP`](crate::published_names::VFSD_SWAP),
//! [`published_names::MEMMGR_SWAP`](crate::published_names::MEMMGR_SWAP),
//! [`published_names::LOGD_QUERY`](crate::published_names::LOGD_QUERY), and each
//! provider name whose badge carries a verb bit ([`crate::VERB_BIT_MASK`]; the
//! `:auth` and `:grant` entries, today `pwrmgr.shutdown`, `acpid.power`,
//! `swapd.restore`, `sessiond.operator` and `crashd.core`) resolve only
//! through a recipe's `seed = ...` line, and
//! `QUERY_ENDPOINT` answers them `UNKNOWN_NAME`. A name resolves to a SEND
//! without `GRANT`, apart from [`published_names::DEVMGR_BIND`](crate::published_names::DEVMGR_BIND), which its
//! seeds receive with `GRANT`, since `devmgr_labels::BIND_DRIVERS` moves a cap
//! to devmgr, [`published_names::MEMMGR_SWAP`](crate::published_names::MEMMGR_SWAP), whose seeds move caps to memmgr,
//! and `sessiond.operator` and `crashd.core` (`:grant` entries), whose seeds move
//! caps to sessiond and crashd;
//! `QUERY_ENDPOINT` never yields `GRANT`.
//! [`published_names::VFSD_DENY`](crate::published_names::VFSD_DENY) carries no authority but is seed-only
//! too, as svctest's test twin, and so is
//! [`published_names::SVCMGR_GRANT`](crate::published_names::SVCMGR_GRANT), whose seeds keep
//! `GRANT`. `svcmgr`, `pwrmgr.deny`, `acpid.deny`, `timed`, and any
//! name published through [`svcmgr_labels::PUBLISH_ENDPOINT`](crate::svcmgr_labels::PUBLISH_ENDPOINT) are public
//! (services/svcmgr/docs/ipc-interface.md § Label 4).

/// Badged SEND on vfsd's namespace endpoint at its synthetic root:
/// the namespace root, which crosses mounts. The fs drivers behind
/// it are opaque to consumers.
pub const ROOTFS_ROOT: &[u8] = b"rootfs.root";

/// `pwrmgr_labels::SHUTDOWN_AUTHORITY`-badged SEND on pwrmgr's
/// service endpoint. Seed-only: consumers needing power-off authority
/// seed this name and call [`pwrmgr_labels::SHUTDOWN`] /
/// [`pwrmgr_labels::REBOOT`] through the returned cap.
pub const PWRMGR_SHUTDOWN: &[u8] = b"pwrmgr.shutdown";

/// No-authority SEND on pwrmgr's service endpoint, badgeised
/// with a non-`SHUTDOWN_AUTHORITY` sentinel. Used by negative
/// tests (e.g. svctest's `pwrmgr_cap_deny`) that need a cap
/// pointing at pwrmgr without the shutdown bit to verify the
/// authority gate rejects it.
pub const PWRMGR_DENY: &[u8] = b"pwrmgr.deny";

/// SEND on svcmgr's own service endpoint. Consumers resolve this
/// when they need to call into svcmgr beyond the per-process
/// `service_registry_cap` (today: crasher's `seed = svcmgr`).
pub const SVCMGR: &[u8] = b"svcmgr";

/// `REGISTRY_QUERY_AUTHORITY`-badged SEND on devmgr's registry
/// endpoint: the `QUERY_ACPI_TABLE` surface, which reaches no device
/// driver (a driver is reached through its class's
/// [`DEVMGR_CLASS_PREFIX`] publication). svcmgr publishes it seed-only,
/// post-handover, from the devmgr-registry source cap init endows it
/// with; the `REGISTRY_QUERY_AUTHORITY` badge bit is preserved through
/// svcmgr's plain `cap_derive` in `registry_lookup_derived`.
pub const DEVMGR_REGISTRY: &[u8] = b"devmgr.registry";

/// Prefix of the names svcmgr publishes devmgr's class SENDs under:
/// `devmgr.class.<stem>`, one for each class file of
/// `/config/devmgr/classes/`, each the SEND
/// `devmgr_labels::MINT_CLASS_SEND` returns for the class with the verb
/// mask its file sets. Seed-only: a service reaches a class's drivers
/// only when its definition seeds the class's name, or, for logd, when
/// svcmgr fills its bootstrap slots from them.
pub const DEVMGR_CLASS_PREFIX: &[u8] = b"devmgr.class.";

/// SEND on devmgr's registry endpoint badged
/// `REGISTRY_QUERY_AUTHORITY | SHUTDOWN_DEVICE_AUTHORITY`: the
/// `devmgr.registry` surface plus `QUERY_SHUTDOWN_DEVICE`. Seed-only and
/// seeded only by pwrmgr, which acquires the RISC-V SBI shutdown
/// authority through it.
pub const DEVMGR_SHUTDOWN: &[u8] = b"devmgr.shutdown";

/// SEND on devmgr's registry endpoint badged
/// `REGISTRY_QUERY_AUTHORITY | BIND_AUTHORITY`: the `devmgr.registry`
/// surface plus `devmgr_labels::BIND_DRIVERS`, which binds the drivers of
/// a directory the caller names to the devices still unbound. Seed-only
/// and seeded only by svctest, which binds the test fixtures of
/// `/tests/drivers/` through it.
pub const DEVMGR_BIND: &[u8] = b"devmgr.bind";

/// SEND on devmgr's registry endpoint badged
/// `REGISTRY_QUERY_AUTHORITY | ACPI_AUTHORITY`: the `devmgr.registry`
/// surface plus the labels through which acpid acquires its register
/// blocks, regions and configuration-space accesses, pushes its results,
/// and posts the firmware's hotplug events, each of which has devmgr run
/// a slot's add or removal job (`devmgr_labels::ACPI_AUTHORITY`).
/// Seed-only and seeded only by acpid.
pub const DEVMGR_ACPI: &[u8] = b"devmgr.acpi";

/// `acpid_labels::POWER_AUTHORITY`-badged SEND on acpid's service
/// endpoint: `acpid_labels::SLEEP`, `acpid_labels::QUERY_SLEEP`,
/// `acpid_labels::RESET` and `acpid_labels::WAIT_EVENT`. Seed-only and seeded
/// only by pwrmgr.
pub const ACPID_POWER: &[u8] = b"acpid.power";

/// SEND on acpid's service endpoint badged with a sentinel that carries
/// no verb bit, so acpid's gate refuses it: the public negative-test twin
/// of [`ACPID_POWER`], which svctest resolves through `QUERY_ENDPOINT`.
pub const ACPID_DENY: &[u8] = b"acpid.deny";

/// SEND on vfsd's service endpoint badged
/// `vfsd_labels::MOUNT_AUTHORITY` alone: the `MOUNT` surface, without
/// `GET_SYSTEM_ROOT_CAP`. Seed-only and seeded only by svctest, whose
/// vfsd phases drive `MOUNT`'s rejection paths.
pub const VFSD_MOUNT: &[u8] = b"vfsd.mount";

/// SEND on vfsd's service endpoint badged `vfsd_labels::DENY_BADGE`,
/// which carries no verb bit: the negative-test twin of [`VFSD_MOUNT`].
/// Seed-only and seeded only by svctest.
pub const VFSD_DENY: &[u8] = b"vfsd.deny";

/// `SEND|GRANT` on svcmgr's service endpoint badged
/// `svcmgr_labels::PUBLISHED_SEND_BADGE`, the published [`SVCMGR`] SEND's
/// badge, which carries no verb bit: a request through it can carry caps,
/// which svcmgr deletes on every label. Seed-only, its seeds keeping
/// `GRANT`, and seeded only by svctest, whose stray-cap phase drives that
/// deletion.
pub const SVCMGR_GRANT: &[u8] = b"svcmgr.grant";

/// SEND on vfsd's service endpoint badged
/// `vfsd_labels::SWAP_AUTHORITY` alone: the `GET_SWAP_PARTITION`
/// surface. Seed-only; swapd's recipe seeds it, and
/// svctest's recipe seeds it too, to drive only the stale-version refusal,
/// which hands nothing out.
pub const VFSD_SWAP: &[u8] = b"vfsd.swap";

/// `SEND|GRANT` on memmgr's endpoint badged
/// `memmgr_labels::SWAP_AUTHORITY` alone: the swap service's interface to
/// memmgr's disk tier (`SWAP_REGISTER` to `SWAP_WANTED`). Seed-only, its
/// seeds keeping `GRANT`, since the swap labels move caps to memmgr; swapd's
/// recipe seeds it, and svctest's recipe seeds it too, as a second swap
/// client that registers nothing.
pub const MEMMGR_SWAP: &[u8] = b"memmgr.swap";

/// SEND on the master log endpoint badged
/// `log_labels::LOG_QUERY_AUTHORITY`: logd's `QUERY_SLOTS` and
/// `QUERY_HISTORY` surface. svcmgr mints it from its master-log source.
/// Seed-only; seeded only by svctest, whose `logd_death_forward` phase
/// reads a dead child's retired slot through it.
pub const LOGD_QUERY: &[u8] = b"logd.query";

/// SEND on sessiond's service endpoint badged
/// `sessiond_labels::OPERATOR_AUTHORITY`: the interface labels, through
/// which an interface opens operator sessions
/// (services/sessiond/docs/ipc-interface.md). Seed-only; seeded by the
/// terminal, and by svctest, whose sessiond phases open sessions through it.
pub const SESSIOND_OPERATOR: &[u8] = b"sessiond.operator";

/// SEND|GRANT on crashd's live-core endpoint badged
/// `crashd_labels::LIVE_CORE_AUTHORITY`: the authority to ask crashd for an
/// ELF core of a live process (services/crashd/docs/operation.md § Live
/// Core), whose request moves the account the snapshot is charged to.
/// Seed-only; seeded only by usertest, which hands it to the crashme tester.
pub const CRASHD_CORE: &[u8] = b"crashd.core";
