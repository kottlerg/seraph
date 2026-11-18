// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/sched_policy.rs

//! System-wide scheduling-policy constants: the per-service priority level
//! map. Pure userspace policy — the kernel defines the level space
//! (`[PRIORITY_MIN, PRIORITY_MAX]`, level 31 reserved), the `SchedControl`
//! band mechanism, and how each level is scheduled (strict priority above its
//! RT/fair boundary, weighted fair below it; `core/kernel/docs/scheduler.md`
//! § Scheduling Classes); every number here is a placement choice and can
//! change without touching the kernel.
//!
//! Level map (30 = init, kernel-assigned; 31 reserved):
//!
//! | Level | Occupant |
//! |---|---|
//! | 30 | init (kernel-assigned `INIT_PRIORITY`) |
//! | 28 | memmgr |
//! | 27 | procmgr |
//! | 26 | init-logd, serial, virtio-blk, devmgr's DMA thread |
//! | 25 | framebuffer, rtc, virtio-input, virtio-console, virtio-rng |
//! | 24 | devmgr, every thread but its DMA thread |
//! | 23 | vfsd, fs drivers (fatfs) |
//! | 21 | svcmgr |
//! | ≤21 | svcmgr-launched services, per `.svc` recipe (crashd 20, logd 18, timed/pwrmgr 16, terminal/svctest/usertest 10, crasher 5), and what they spawn (the shell, at 5 from terminal) |
//!
//! Levels for svcmgr-launched services live in their `.svc` recipes
//! (`priority = ...` / `sched_max = ...`), not here — this module carries
//! only the levels assigned by init, procmgr, devmgr, and vfsd directly.

/// Upper bound of the baseline `SchedControl` band init delegates to
/// the spawn chain: init splits its root `[1, 30]` cap at
/// `BASELINE_PRIORITY_MAX + 1`, keeps the elevated remainder
/// (`[29, 30]`, released when init's reap frees its `CSpace`, per
/// `docs/process-lifecycle.md` § Init reap), and hands the baseline
/// `[1, 28]` to memmgr and procmgr.
/// Every band procmgr mints for a child is a (possibly narrowed)
/// descendant of this baseline, so no spawned process can ever reach
/// `[29, 30]`.
pub const BASELINE_PRIORITY_MAX: u8 = 28;

/// Priority procmgr assigns when a `CREATE_PROCESS` /
/// `CREATE_FROM_FILE` label carries no `CREATE_PRIORITY` field,
/// clamped to the child's band.
pub const DEFAULT_SPAWN_PRIORITY: u8 = 10;

/// memmgr — the system pager and frame-pool owner. Everything below
/// it can fault into it, so it outranks all of them.
pub const MEMMGR_PRIORITY: u8 = 28;

/// procmgr — process lifecycle authority.
pub const PROCMGR_PRIORITY: u8 = 27;

/// init's log-mediator thread (init-logd). Above every log producer
/// it serves during bootstrap; matches the boot-critical drivers.
pub const INIT_LOGD_PRIORITY: u8 = 26;

/// Boot-critical device drivers: serial (console path) and
/// virtio-blk (root-disk path); also devmgr's DMA thread, which
/// virtio-blk blocks on for every transfer.
pub const BOOT_DRIVER_PRIORITY: u8 = 26;

/// Non-boot-critical device drivers: framebuffer, RTC, virtio-input, virtio-rng,
/// and the debug port's virtio-console.
pub const AUX_DRIVER_PRIORITY: u8 = 25;

/// devmgr — device enumeration and driver supervision.
pub const DEVMGR_PRIORITY: u8 = 24;

/// devmgr's band ceiling. Deliberately above its own level so it can
/// place the drivers it spawns at [`BOOT_DRIVER_PRIORITY`] /
/// [`AUX_DRIVER_PRIORITY`], and its own DMA thread, which virtio-blk
/// blocks on, at [`BOOT_DRIVER_PRIORITY`].
pub const DEVMGR_BAND_MAX: u8 = 26;

/// vfsd — the namespace/VFS authority.
pub const VFSD_PRIORITY: u8 = 23;

/// Filesystem drivers (fatfs), spawned by vfsd at its own level: an
/// fs driver is the blocking dependency of every vfsd read.
pub const FS_DRIVER_PRIORITY: u8 = 23;

/// svcmgr — service supervisor and discovery registry. Above every
/// service it launches (recipes are validated against its band).
pub const SVCMGR_PRIORITY: u8 = 21;
