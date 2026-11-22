// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/devmgr_labels.rs

//! IPC labels for the device manager (`devmgr`).
//!
//! Every request carries the caller's compiled [`DEVMGR_LABELS_VERSION`](crate::DEVMGR_LABELS_VERSION) in
//! `data[0]`; after any badge check the label makes, devmgr replies
//! [`devmgr_errors::LABEL_VERSION_MISMATCH`](crate::devmgr_errors::LABEL_VERSION_MISMATCH) when it differs.

/// Query the served driver of a device class: the one class SEND
/// ([`MINT_CLASS_SEND`]) reaches.
///
/// The class and the verb bits of the reply come from the caller's badge
/// ([`class_badge`]), not from the message: a SEND badged otherwise (a
/// registry SEND of an authority bit included) gets
/// [`super::devmgr_errors::UNAUTHORIZED`]. Request: `data[0]` = caller's
/// compiled [`super::DEVMGR_LABELS_VERSION`]; `data[1]`, when sent, the
/// instance ordinal, an absent one being 0, the first. Reply
/// ([`super::devmgr_errors::SUCCESS`]): `caps[0]` = a `SEND_GRANT` cap on
/// the driver's service endpoint badged with the class SEND's verb bits.
///
/// An ordinal counts the class's served drivers in the order devmgr
/// served them (a settle batch's drivers in spawn order, PCI drivers in
/// PCI segment, bus, device, function order), not stable across boots. A
/// driver is served once it has reported its device ready
/// ([`DRIVER_READY`]); one whose spawn failed, or that died or did not
/// report within devmgr's settle bound, counts in no ordinal. A served
/// driver that dies later is withdrawn, its ordinal replies
/// [`super::devmgr_errors::WITHDRAWN`] for the rest of the boot, and the
/// ordinals after it keep their drivers, so a client probing ordinals 0,
/// 1, ... passes a `WITHDRAWN` reply and stops at the first other reply
/// that is not `SUCCESS`. A driver devmgr restarts after its death
/// (services/devmgr/docs/responsibilities.md § Driver Restart) is a new
/// instance, served at the class's next ordinal: its clients find it as
/// they find any driver served later. Replies [`super::devmgr_errors::NO_DEVICE`]
/// past the last served driver, which before [`SET_DRIVERS_DIR`] includes
/// every ordinal of a class whose drivers devmgr spawns from disk, and
/// `INVALID_REQUEST` when the derivation fails. A query received once
/// a bind pass is posted ([`SET_DRIVERS_DIR`]'s or [`BIND_DRIVERS`]'s),
/// whose answer would name no driver, waits until that pass and the
/// settle of its drivers are done and is then answered from the settled
/// drivers; so does one received once devmgr has taken the death of a
/// driver it restarts, until the restart's settle is done. A query that
/// names a served driver is answered at once.
///
/// The handler logs nothing: logd is a caller, blocked in this call
/// outside its log loop, so a log line here would deadlock.
pub const QUERY_DEVICE: u64 = 20;
/// Watch a device class: register a Notification devmgr signals,
/// without blocking, each time the class gains a served driver (a new
/// ordinal) and each time one of its drivers is withdrawn.
///
/// Served on a class SEND ([`MINT_CLASS_SEND`]) alone, which carries no
/// grant right: devmgr creates the Notification and keeps it, so a
/// caller moves no cap. A SEND badged otherwise gets
/// [`super::devmgr_errors::UNAUTHORIZED`]. Request: `data[0]` = caller's
/// compiled [`super::DEVMGR_LABELS_VERSION`]. Reply
/// ([`super::devmgr_errors::SUCCESS`]): `caps[0]` = the Notification,
/// with the wait right only; `data[0]` = the ordinals the class has
/// served when the watch is registered, withdrawn ones included, which
/// is the ordinal the class's next driver takes. A change after the
/// registration signals [`WATCH_CLASS_CHANGED`], so a caller that
/// registers and then probes [`QUERY_DEVICE`] misses none; the bits
/// accumulate until the caller waits, so several changes can wake it
/// once.
///
/// A class holds at most [`MAX_CLASS_WATCHERS`] watches; a registration
/// past it gets [`super::devmgr_errors::WATCHERS_FULL`]. A watch lasts
/// while the caller holds a copy of its Notification: once devmgr's own
/// copy is the only reference left (the caller deleted its copies, or
/// exited), devmgr drops the watch the next time it signals the class or
/// finds the class full. [`super::devmgr_errors::OUT_OF_RESOURCES`] when
/// devmgr cannot create the Notification, or its `CSpace` is short of its
/// slot headroom and a top-up was refused, since each watch keeps a slot.
/// The handler logs nothing, as [`QUERY_DEVICE`]'s does not.
pub const WATCH_CLASS: u64 = 23;
/// The bit devmgr signals on a [`WATCH_CLASS`] Notification.
pub const WATCH_CLASS_CHANGED: u64 = 1;
/// The most [`WATCH_CLASS`] watches one class holds.
pub const MAX_CLASS_WATCHERS: usize = 8;
/// Query a device's startup-info payload from devmgr's catalog.
///
/// Served only while a driver's spawn batch settles, on that batch's
/// private driver endpoint, which every devmgr-spawned driver's query
/// cap names (see [`DRIVER_READY`]); the registry endpoint replies
/// `UNKNOWN_OPCODE` to it.
///
/// The caller's badge identifies the device by indexing devmgr's
/// `DeviceCatalog` (badge == entry index + 1); a badge that indexes no
/// entry, or an entry that carries no startup info (the serial driver's,
/// the goldfish RTC driver's, a CMOS RTC driver's when the FADT names no
/// century register, and that of a PCI function whose driver declares no
/// `VirtIO` status reset, and so is given no `VirtIO` register layout),
/// gets `INVALID_REQUEST`. A CMOS RTC driver's entry
/// otherwise carries [`super::device_info_kind::RTC_CENTURY`]. The
/// catalog only grows (the entry of a driver that failed to spawn or was
/// withdrawn stays), so a badge is never recycled and its `u64` width
/// bounds no catalog size. No authority bit is checked. Devmgr stores the
/// payload bytes opaquely; the per-class shape lives in the driver crate.
/// Reply schema (generic for every kind):
/// - `word[0]` = `kind` discriminant ([`super::device_info_kind`])
/// - `word[1]` = `version` (per-kind payload schema version)
/// - `word[2]` = `byte_len` (valid bytes in the payload)
/// - `word[3..3 + byte_len.div_ceil(8)]` = payload bytes packed as
///   `u64` words (`repr(C)` of the kind's struct).
///
/// The driver verifies `kind` and `version` before deserialising
/// the payload. Devmgr does not interpret payload bytes.
pub const QUERY_DEVICE_INFO: u64 = 2;
/// svcmgr-only handshake: install the
/// `LOOKUP | READ | READDIR`-attenuated `/services/drivers/` namespace
/// cap from which devmgr lists, reads the declarations of, and walks to
/// its on-disk driver binaries.
///
/// Request: `data[0]` = caller's compiled
/// [`super::DEVMGR_LABELS_VERSION`]; `caps[0]` = badged SEND on the
/// `/services/drivers/` directory node, which svcmgr walks from its
/// system root via `namespace_lookup_dir(root_dir_cap, …, LOOKUP |
/// READ | READDIR)` (so the node is served by the root filesystem, and
/// devmgr can list it with `NS_READDIR`); from word
/// [`DRIVERS_DIR_PATH_WORD`], the directory's absolute path
/// (`/services/drivers`) as a name block (`crate::with_name_block`, at
/// most [`DRIVERS_DIR_PATH_MAX`] bytes), under which devmgr names each
/// entry it starts, `<path>/<entry>`, the name procmgr verifies the entry
/// was signed under (docs/signing.md § Signed Attributes); optionally
/// `caps[1]` = the `LOOKUP | READ | READDIR` directory cap of
/// [`PLATFORM_TABLES_PATH`], walked the same way, which svcmgr sends when
/// the walk succeeds (an architecture that installs no platform
/// description table has no such directory).
/// Caller's badge MUST carry [`DRIVERS_DIR_AUTHORITY`]; the handler
/// replies [`super::devmgr_errors::UNAUTHORIZED`] otherwise and
/// [`super::devmgr_errors::INVALID_REQUEST`] when `caps[0]` or the
/// path is absent, releasing every cap the request carried. A repeated
/// request keeps the first caps and path, releases its own, and replies
/// `SUCCESS`.
///
/// Devmgr stashes the caps and replies
/// [`super::devmgr_errors::SUCCESS`] **before** doing any spawn
/// work, so svcmgr never blocks on driver bring-up. Unless a platform
/// description table among its boot modules matched the machine, devmgr
/// first reads the tables of the `caps[1]` directory, each through
/// [`super::procmgr_labels::READ_VERIFIED`] under
/// `<PLATFORM_TABLES_PATH>/<entry>`, takes the one whose OEM table ID is
/// the XSDT's and adds its device records, then deletes the cap
/// (docs/driver-binding.md § Platform Description Tables). The
/// drivers-directory pass (the listing, the read of each entry's driver
/// declaration, and the bind of every PCI device and platform device
/// record still unbound that a declaration matches, the RTC's among
/// them), the
/// [`super::procmgr_labels::CREATE_FROM_FILE`] calls and bootstrap
/// rounds they make, and the settle that waits for each driver to
/// report ready ([`DRIVER_READY`]), run on devmgr's control thread
/// after the reply, while its registry workers go on serving. A
/// [`QUERY_DEVICE`] whose answer would name no driver waits until that
/// work is done, and then sees the served drivers (or the
/// sticky-failure state); one that names a driver is answered at
/// once.
///
/// Each spawn is attempted once per boot, with two exceptions: a restart
/// after a served driver's death, and a create procmgr refused with
/// `IO_ERROR` or `OUT_OF_MEMORY`, which devmgr retries a bounded number
/// of times (`services/devmgr/docs/responsibilities.md` § Create retry).
/// On a failure that is not retried (missing binary, ELF corrupt, carve
/// failure, a refused signature, a driver that died or did not report
/// ready within the settle bound, etc.), or once the retries are given
/// up, devmgr marks the driver unavailable for this boot and replies
/// [`super::devmgr_errors::NO_DEVICE`] to a subsequent [`QUERY_DEVICE`]
/// for it; the retry rule is [`super::devmgr_errors::NO_DEVICE`]'s.
pub const SET_DRIVERS_DIR: u64 = 6;

/// The data word of [`SET_DRIVERS_DIR`] and [`BIND_DRIVERS`] that holds
/// the length of the directory's path, whose bytes follow
/// (`crate::with_name_block`).
pub const DRIVERS_DIR_PATH_WORD: usize = 1;

/// The absolute path of the directory of platform description tables
/// whose cap [`SET_DRIVERS_DIR`] carries as `caps[1]`; devmgr names each
/// table it reads `<PLATFORM_TABLES_PATH>/<entry>`, its install path, the
/// name procmgr verifies it was signed under in the data role.
pub const PLATFORM_TABLES_PATH: &str = "/config/devmgr/platform";

/// Longest drivers-directory path, in bytes, [`SET_DRIVERS_DIR`] and
/// [`BIND_DRIVERS`] carry: the longest name procmgr verifies an object
/// under (`procmgr_labels::CREATE_NAME_MAX`), which a driver's name,
/// the path and an entry, must also fit.
pub const DRIVERS_DIR_PATH_MAX: usize = super::procmgr_labels::CREATE_NAME_MAX;

/// Locate an ACPI table and serve a read-only view of it.
///
/// devmgr is the sole owner of ACPI data and the only service that
/// navigates the table tree (RSDP → XSDT). A caller that needs a table
/// (acpid, for the DSDT and every SSDT it loads) requests it here rather
/// than holding ACPI Memory caps of its own.
///
/// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
/// `data[1]` = 4-byte table signature packed little-endian (e.g.
/// `FACP`), or `0` to look up by physical address; `data[2]` =
/// table physical address (used when `data[1] == 0`, e.g. the DSDT,
/// whose address the caller reads from the FADT); `data[3]`, when sent,
/// the index of the table among those the XSDT lists with the signature,
/// an absent one being 0, the first (`SSDT` has one table per index). The
/// signature `DSDT`, which the XSDT does not list, names the DSDT the
/// FADT points to, at index 0 alone. Caller's badge MUST carry
/// [`REGISTRY_QUERY_AUTHORITY`]; the handler replies
/// [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
///
/// Reply ([`super::devmgr_errors::SUCCESS`]): `caps[0]` = a derived
/// **read-only-intended** Memory cap on the ACPI region containing the
/// table (the caller maps it read-only); `data[0]` = region
/// physical base, `data[1]` = region size in bytes, `data[2]` = the
/// table's physical address. The caller maps the region and reads the
/// table at `table_phys - region_base`. devmgr reads only the
/// directory (RSDP/XSDT) and table headers (signatures) to locate the
/// table — never a table body. Replies
/// [`super::devmgr_errors::NO_DEVICE`] when the table is not found
/// (an index past the last table of the signature included), both
/// `data[1]` and `data[2]` are zero, or `data[1]` has bits above its
/// low 32, [`super::devmgr_errors::INVALID_REQUEST`] when deriving
/// the reply's Memory cap from the region fails, and
/// [`super::devmgr_errors::LABEL_VERSION_MISMATCH`] when `data[0]` is
/// not `DEVMGR_LABELS_VERSION`.
pub const QUERY_ACPI_TABLE: u64 = 7;

/// Serve the platform's firmware shutdown authority (RISC-V).
///
/// devmgr is the hardware authority and performs no shutdown logic. On
/// RISC-V the power manager (`pwrmgr`) powers off and resets through
/// SBI SRST; on x86-64 it reaches the ACPI sleep and reset registers
/// through acpid ([`super::acpid_labels`]), and devmgr serves nothing
/// here.
///
/// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`].
/// Caller's badge MUST carry [`SHUTDOWN_DEVICE_AUTHORITY`]; the handler
/// replies [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
///
/// Reply ([`super::devmgr_errors::SUCCESS`], RISC-V): `caps[0]` = a
/// Reset-only derivation of devmgr's `SbiControl` cap (SBI SRST
/// authority), derived on every call, so a pwrmgr restart re-acquires it.
///
/// Replies [`super::devmgr_errors::NO_DEVICE`] on x86-64 and when the
/// `SbiControl` cap is absent,
/// [`super::devmgr_errors::INVALID_REQUEST`] when the Reset-only
/// derivation fails, and [`super::devmgr_errors::LABEL_VERSION_MISMATCH`]
/// when `data[0]` is not `DEVMGR_LABELS_VERSION`.
pub const QUERY_SHUTDOWN_DEVICE: u64 = 8;

/// Serve acpid the capability over one fixed ACPI register block the FADT
/// declares, or the SCI's `Interrupt` (x86-64).
///
/// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
/// `data[1]` = the block ([`ACPI_PM1A_EVT`], [`ACPI_PM1A_CNT`],
/// [`ACPI_GPE0`], [`ACPI_SMI_CMD`], [`ACPI_RESET`],
/// [`ACPI_SLEEP_CONTROL`], [`ACPI_SLEEP_STATUS`], or [`ACPI_SCI`]).
/// Caller's badge MUST carry [`ACPI_AUTHORITY`]; the handler replies
/// [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
///
/// Reply ([`super::devmgr_errors::SUCCESS`]) for a register block:
/// `caps[0]` = a narrow `IoPort` over the block, derived from devmgr's
/// full-rights `IoPort` on every call, or, for `RESET_REG` or a sleep
/// register in the memory space, an `Mmio` over the page that holds it, a
/// derivation of the grant of that page devmgr keeps for acpid, as
/// [`ACPI_REGION_GRANT`] keeps it; `data[0]` = its first port, or the
/// register's physical address; `data[1]` = its port or byte count;
/// `data[2]` = the FADT's `ACPI_ENABLE` value for [`ACPI_SMI_CMD`], its
/// `RESET_VALUE` for [`ACPI_RESET`], and 0 for the others; `data[3]` =
/// its space, [`ACPI_SPACE_IO`], or [`ACPI_SPACE_MEMORY`] for a register
/// in the memory space. The sleep registers, served only for a FADT that
/// sets `HW_REDUCED_ACPI`, and a `RESET_REG` in the memory space are checked
/// as [`ACPI_REGION_GRANT`] checks a range, and a register a holder overlaps
/// is refused, logged, with [`super::devmgr_errors::REFUSED`]. For
/// [`ACPI_SCI`]: `caps[0]` = an `Interrupt` cap carrying `RIGHTS_IRQ_NOTIFY`
/// on the SCI's line, a derivation of the line devmgr holds for the boot,
/// made on every call; `data[0]` = the line's GSI; `data[1]` = the
/// `SYS_IRQ_REGISTER` mode it is routed in; `data[2]` = 1 when devmgr served
/// the SCI earlier in this boot (the caller is a restarted acpid), else 0.
/// Replies [`super::devmgr_errors::NO_DEVICE`] when the platform has no such
/// block or SCI (on RISC-V, which has no I/O space and no SCI, all but a
/// register in the memory space; a zero FADT field, a hardware-reduced FADT
/// for the fixed blocks and the SCI, a FADT that is not hardware-reduced or
/// names no usable 8-bit register for the sleep registers, a clear
/// `RESET_REG_SUP`, a zero port or one past 0xFFFF in the I/O space, or no
/// usable 8-bit register in the memory space for `RESET_REG`), the FADT
/// cannot be read, or the carve or the derivation fails, and
/// [`super::devmgr_errors::INVALID_REQUEST`] for an unknown block.
/// The SCI, `RESET_REG` and the sleep registers are answered on devmgr's
/// control thread, the other blocks on the registry worker that receives the
/// request.
pub const QUERY_ACPI_RESOURCES: u64 = 24;
/// [`QUERY_ACPI_RESOURCES`] block: `PM1a_EVT_BLK`, `PM1_EVT_LEN` ports.
pub const ACPI_PM1A_EVT: u64 = 1;
/// [`QUERY_ACPI_RESOURCES`] block: `PM1a_CNT_BLK`, `PM1_CNT_LEN` ports.
pub const ACPI_PM1A_CNT: u64 = 2;
/// [`QUERY_ACPI_RESOURCES`] block: `GPE0_BLK`, `GPE0_BLK_LEN` ports.
pub const ACPI_GPE0: u64 = 3;
/// [`QUERY_ACPI_RESOURCES`] block: the `SMI_CMD` port.
pub const ACPI_SMI_CMD: u64 = 4;
/// [`QUERY_ACPI_RESOURCES`] block: the FADT's `RESET_REG`, one byte in the
/// memory or the I/O space, with its `RESET_VALUE`.
pub const ACPI_RESET: u64 = 5;
/// [`QUERY_ACPI_RESOURCES`] resource: the SCI, the FADT's `SCI_INT` line.
pub const ACPI_SCI: u64 = 6;
/// [`QUERY_ACPI_RESOURCES`] block: the FADT's `SLEEP_CONTROL_REG`, one
/// byte in the memory or the I/O space, on a hardware-reduced platform.
pub const ACPI_SLEEP_CONTROL: u64 = 7;
/// [`QUERY_ACPI_RESOURCES`] block: the FADT's `SLEEP_STATUS_REG`, one
/// byte in the memory or the I/O space, on a hardware-reduced platform.
pub const ACPI_SLEEP_STATUS: u64 = 8;

/// Grant acpid part of an operation region it evaluated: a `SystemIO`
/// range, or the `SystemMemory` page an access reaches, that no device
/// record, driver or the kernel holds.
///
/// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
/// `data[1]` = the space, [`ACPI_SPACE_MEMORY`] or [`ACPI_SPACE_IO`];
/// `data[2]` = the base; `data[3]` = the length. A memory request lies
/// within one page, and is granted that page. Caller's badge MUST carry
/// [`ACPI_AUTHORITY`]; the handler replies
/// [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
///
/// devmgr refuses, logged, a range that overlaps a resource of any device
/// record (a PCI BAR, a platform record's `Mmio` or `IoPort`), an
/// interrupt controller the MADT describes or a legacy port the kernel
/// drives, the configuration-mechanism ports 0xCF8-0xCFF,
/// or the FACS, and memory that no `Mmio` aperture devmgr still holds
/// covers (RAM, ACPI NVS, and the ranges devmgr has carved for itself or a
/// driver). A memory page granted is kept by devmgr, so it is granted
/// again to a restarted acpid. The policy is services/acpid/README.md
/// § Region grants.
///
/// Reply ([`super::devmgr_errors::SUCCESS`]): `caps[0]` = an `IoPort`
/// over exactly the range, or an `Mmio` over the page; `data[0]` = the
/// grant's base (the page's address for memory); `data[1]` = its length.
/// Replies [`super::devmgr_errors::REFUSED`] for a refused range, and
/// [`super::devmgr_errors::INVALID_REQUEST`] for a short request, an
/// unknown space, an empty or overflowing range, memory that crosses a
/// page boundary, a port range past 0xFFFF, or a failed carve or
/// derivation.
pub const ACPI_REGION_GRANT: u64 = 25;
/// [`ACPI_REGION_GRANT`] space: `SystemMemory` (ACPI address space 0).
pub const ACPI_SPACE_MEMORY: u64 = 0;
/// [`ACPI_REGION_GRANT`] space: `SystemIO` (ACPI address space 1).
pub const ACPI_SPACE_IO: u64 = 1;

/// Read or write one register of a PCI function's configuration space
/// for acpid, one access per call.
///
/// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
/// `data[1]` = [`ACPI_CONFIG_READ`] or [`ACPI_CONFIG_WRITE`]; `data[2]` =
/// the function, [`pci_function`]'s packing; `data[3]` = the offset;
/// `data[4]` = the width in bytes, 1, 2 or 4; `data[5]` = the value
/// written. Caller's badge MUST carry [`ACPI_AUTHORITY`]; the handler
/// replies [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
///
/// A read of any function is allowed; one of a function no device record
/// holds reads all-ones, as an absent function does, without an access. A
/// write is allowed only at offset 0x40 and above of a function whose
/// record is unbound: no driver has been started for it, and devmgr has
/// not taken it as a RISC-V IOMMU unit or as a managed hotplug slot's
/// port. Any other write is refused,
/// logged. The access runs on devmgr's control thread, so no bind of the
/// function interleaves with it.
///
/// Reply ([`super::devmgr_errors::SUCCESS`]): `data[0]` = the value read
/// (0 for a write). Replies [`super::devmgr_errors::REFUSED`] for a
/// refused write, and [`super::devmgr_errors::INVALID_REQUEST`] for a
/// short request, an unknown operation, a width other than 1, 2 or 4, an
/// offset not aligned to the width or past the 4096-byte configuration
/// space, or a configuration page devmgr cannot map.
pub const ACPI_PCI_CONFIG: u64 = 26;
/// [`ACPI_PCI_CONFIG`] operation: read.
pub const ACPI_CONFIG_READ: u64 = 0;
/// [`ACPI_PCI_CONFIG`] operation: write.
pub const ACPI_CONFIG_WRITE: u64 = 1;

/// The word [`ACPI_PCI_CONFIG`] names a function by: the segment in bits
/// 16..=31, the bus in bits 8..=15, the device in bits 3..=7 and the
/// function in bits 0..=2.
#[must_use]
pub const fn pci_function(segment: u16, bus: u8, device: u8, function: u8) -> u64
{
    ((segment as u64) << 16)
        | ((bus as u64) << 8)
        | (((device & 0x1F) as u64) << 3)
        | ((function & 0x7) as u64)
}

/// Push the `_OSC` result of one PCI host bridge from acpid.
///
/// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
/// `data[1]` = the bridge's segment (`_SEG`); `data[2]` = its bus
/// (`_BBN`); `data[3]` = 1 when `_OSC` was evaluated, 0 when the bridge
/// has none or its evaluation failed; `data[4]` = the status dword
/// `_OSC` returned; `data[5]` = the control dword it returned, the
/// features whose native control the firmware grants; `data[6]` = the
/// control dword acpid asked for. Caller's badge MUST carry
/// [`ACPI_AUTHORITY`]; the handler replies
/// [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
///
/// devmgr keeps the first result of each bridge for the boot and logs a
/// later one that differs from it, so an acpid restart cannot change a
/// grant devmgr acts on. Reply: [`super::devmgr_errors::SUCCESS`];
/// [`super::devmgr_errors::INVALID_REQUEST`] for a short push or a
/// bridge devmgr cannot record.
pub const OSC_RESULT: u64 = 27;

/// Push the `_CRS` windows of one PCI host bridge from acpid: the buses,
/// I/O ports, and memory it decodes.
///
/// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
/// `data[1]` = the bridge's segment; `data[2]` = its bus; `data[3]` = the
/// window count, at most [`MAX_BRIDGE_WINDOWS`]; `data[4..]` = one
/// `(kind, base, length)` triple per window, `kind` being
/// [`WINDOW_MEMORY`], [`WINDOW_IO`], or [`WINDOW_BUS`], the base and
/// length on the bus side of the bridge. Caller's badge MUST carry
/// [`ACPI_AUTHORITY`]; the handler replies
/// [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
///
/// devmgr checks the windows against its boot records: every boot
/// function on a bus of the bus window, each memory BAR inside a memory
/// window and inside an aperture devmgr was given at boot, each I/O BAR
/// inside an I/O window. It keeps the first windows of each bridge that
/// pass, for the boot, and logs a later push that differs. Reply:
/// [`super::devmgr_errors::SUCCESS`] when devmgr holds the bridge's
/// windows; [`super::devmgr_errors::REFUSED`], logged, for windows that
/// fail the check, which is fail-closed: the bridge has no windows from
/// acpid until a push passes; [`super::devmgr_errors::INVALID_REQUEST`]
/// for a count past [`MAX_BRIDGE_WINDOWS`], a push shorter than its count,
/// an unknown kind, or a bridge devmgr cannot record.
pub const BRIDGE_WINDOWS: u64 = 28;
/// The most windows one [`BRIDGE_WINDOWS`] push carries.
pub const MAX_BRIDGE_WINDOWS: usize = 16;
/// [`BRIDGE_WINDOWS`] kind: a memory window.
pub const WINDOW_MEMORY: u64 = 0;
/// [`BRIDGE_WINDOWS`] kind: an I/O port window.
pub const WINDOW_IO: u64 = 1;
/// [`BRIDGE_WINDOWS`] kind: a bus number range.
pub const WINDOW_BUS: u64 = 2;

/// Push the interrupt routes of one PCI host bridge's root bus from
/// acpid: its `_PRT`, each entry's link device resolved to the line its
/// current resources name.
///
/// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
/// `data[1]` = the bridge's segment; `data[2]` = its bus; `data[3]` =
/// [`PRT_ROUTES`] or [`PRT_PIC_MODE`]; `data[4..36]` = one word per
/// device 0 to 31, holding the line of pin `INTA` to `INTD` in its 16-bit
/// lanes 0 to 3 (bits `16 * pin` up), [`PRT_NO_ROUTE`] for a pin the table
/// does not route. Caller's badge MUST carry [`ACPI_AUTHORITY`]; the
/// handler replies [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
///
/// devmgr checks one mode's table against the boot functions with an
/// interrupt pin on the buses of the bridge's windows ([`BRIDGE_WINDOWS`]),
/// each at the root-bus device and pin its interrupt reaches: on x86-64 the
/// [`PRT_PIC_MODE`] table against each function's Interrupt Line
/// register, which the firmware programmed in that model; on RISC-V the
/// [`PRT_ROUTES`] table against the line devmgr gives each function. It
/// keeps the first table of each bridge and mode that passes, for the
/// boot, and logs a later push that differs; on x86-64 it keeps a
/// [`PRT_ROUTES`] table only once it holds the bridge's
/// [`PRT_PIC_MODE`] table, the same `_PRT` read in the other model,
/// whose routes it checks only for being routed and reads for nothing else.
/// On x86-64 it also routes a function whose Interrupt Line is unset (one
/// hot-added) by the [`PRT_PIC_MODE`] table, at the pin and root-bus device
/// its interrupt reaches. A refusal is fail-closed:
/// the bridge has no table of the mode from acpid until a push passes.
/// Reply: [`super::devmgr_errors::SUCCESS`] when devmgr holds the
/// bridge's table of the mode; [`super::devmgr_errors::REFUSED`], logged,
/// for a table that fails the check or comes before the bridge's windows
/// or the table it waits for; [`super::devmgr_errors::INVALID_REQUEST`] for an unknown mode, a
/// mode the architecture does not serve, a short push, or a bridge devmgr
/// cannot record.
pub const PRT_TABLE: u64 = 29;
/// [`PRT_TABLE`] mode: the routes of the interrupt model acpid selected
/// (`_PIC(1)`, the APIC model, on x86-64; the only model on RISC-V),
/// whose lines are GSIs.
pub const PRT_ROUTES: u64 = 0;
/// [`PRT_TABLE`] mode, x86-64: the routes evaluated before `_PIC(1)`, in
/// the PIC model the firmware hands over in, whose link devices read the
/// PIRQ routing the firmware programmed and wrote into each function's
/// Interrupt Line register.
pub const PRT_PIC_MODE: u64 = 1;
/// [`PRT_TABLE`] lane value: no route.
pub const PRT_NO_ROUTE: u64 = 0xFFFF;
/// The `data` words of a [`PRT_TABLE`] push: the header and one word per
/// device.
pub const PRT_TABLE_WORDS: usize = 4 + 32;

/// Read what devmgr holds for one PCI host bridge from acpid's pushes:
/// whether the firmware granted the OS native control of each PCI Express
/// feature (`_OSC`), and whether devmgr trusts the bridge's interrupt
/// routes and windows.
///
/// A service that drives a PCI Express port feature (native hotplug,
/// AER, PME) reads here whether the OS owns that feature on its bridge;
/// svctest reads it to check acpid's evaluation on every boot.
///
/// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
/// `data[1]` = the bridge's ordinal among the bridges devmgr holds a push
/// for, in segment, then bus order. Caller's badge MUST carry
/// [`REGISTRY_QUERY_AUTHORITY`]; the handler replies
/// [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
///
/// Reply ([`super::devmgr_errors::SUCCESS`]): `data[0]` = the segment;
/// `data[1]` = the bus; `data[2]` = 1 when devmgr holds the bridge's
/// [`OSC_RESULT`] and `_OSC` was evaluated; `data[3]` = its status dword;
/// `data[4]` = its control dword; `data[5]` = 1 when devmgr holds the
/// bridge's [`PRT_ROUTES`] table; `data[6]` = the boot functions the
/// routes check covered; `data[7]` = 1 when devmgr holds its
/// [`BRIDGE_WINDOWS`]; `data[8]` = the boot functions the windows check
/// covered. Replies [`super::devmgr_errors::NO_DEVICE`] past the last
/// bridge.
pub const QUERY_HOST_BRIDGE: u64 = 30;

/// A hotplug event of a slot whose firmware drives hotplug, from acpid:
/// the `Notify` of a device below a PCI Express port, which acpid
/// resolved to the port (services/acpid/README.md § Hotplug). devmgr runs
/// the slot's add or removal job (services/devmgr/docs/hotplug.md) and
/// replies once it is done, so a removal's reply tells acpid it may run
/// `_EJ0`.
///
/// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
/// `data[1]` = [`HOTPLUG_ADDED`] or [`HOTPLUG_REMOVED`]; `data[2]` = the
/// port's address, packed as [`pci_function`] packs it. Caller's badge
/// MUST carry [`ACPI_AUTHORITY`]; the handler replies
/// [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
///
/// Reply ([`super::devmgr_errors::SUCCESS`]): `data[0]` = the functions
/// the job recorded or removed; an add on a slot whose functions are
/// recorded already records none. [`super::devmgr_errors::NO_DEVICE`],
/// logged, when the port is not a hotplug slot devmgr's boot scan found;
/// [`super::devmgr_errors::REFUSED`], logged, when the slot's hotplug is
/// not the firmware's (devmgr manages it natively, has no grant for it
/// yet, or could not hold it); [`super::devmgr_errors::OUT_OF_RESOURCES`],
/// logged, for an add while devmgr's `CSpace` headroom is short, which
/// records nothing; [`super::devmgr_errors::INVALID_REQUEST`]
/// for an unknown event, a short request, or a malformed address.
pub const ACPI_HOTPLUG: u64 = 31;
/// [`ACPI_HOTPLUG`] event: a card is present in the slot (a device check).
pub const HOTPLUG_ADDED: u64 = 0;
/// [`ACPI_HOTPLUG`] event: the slot's card is to be ejected (an eject
/// request).
pub const HOTPLUG_REMOVED: u64 = 1;

/// Mint a class SEND: a SEND on the registry endpoint whose badge names
/// a device class and the verb bits its [`QUERY_DEVICE`] replies carry
/// ([`class_badge`]), and nothing else, so its holder reaches that
/// class's drivers and no other registry label.
///
/// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
/// `data[1]` = the verb mask, a non-empty subset of
/// [`super::VERB_BIT_MASK`] (an empty one would yield a SEND whose
/// queries return un-badged caps, which their holder could badge at
/// will); `data[2]` = the class name's length, 1 to
/// [`MAX_CLASS_NAME_BYTES`]; `data[3..]` = the name's
/// bytes, packed little-endian, lowercase ASCII letters, digits, `-`, and
/// `_` (docs/driver-binding.md § Device Classes). Caller's badge MUST
/// carry [`CLASS_AUTHORITY`]; the handler replies
/// [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
///
/// devmgr interns the name in its class table, which only grows, and
/// marks the class configured.
/// Reply ([`super::devmgr_errors::SUCCESS`]): `caps[0]` = the class SEND.
/// `INVALID_REQUEST` for an empty or out-of-mask verb mask, a bad name,
/// a full class table, or a failed derivation. The handler logs nothing, as [`QUERY_DEVICE`]'s does not.
pub const MINT_CLASS_SEND: u64 = 21;
/// Longest class name [`MINT_CLASS_SEND`] carries: the declaration
/// format's class-name bound.
pub const MAX_CLASS_NAME_BYTES: usize = 32;

/// Bind the drivers of a directory the caller names to the devices no
/// driver is bound to: the on-demand bind, for a driver installed after
/// the drivers-directory pass (docs/driver-binding.md § Matching).
///
/// Request: `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
/// `caps[0]` = a SEND on a directory node carrying
/// `LOOKUP | READ | READDIR`, as [`SET_DRIVERS_DIR`]'s does; from word
/// [`DRIVERS_DIR_PATH_WORD`], the directory's absolute path as a name
/// block, as [`SET_DRIVERS_DIR`]'s, under which devmgr names each entry
/// it starts. Caller's
/// badge MUST carry [`BIND_AUTHORITY`]; the handler replies
/// [`super::devmgr_errors::UNAUTHORIZED`] otherwise.
///
/// devmgr replies [`super::devmgr_errors::SUCCESS`] before any bind work,
/// as for [`SET_DRIVERS_DIR`]; its control thread then runs a
/// drivers-directory pass over the directory, under that pass's
/// declaration bounds (the auxiliary tier, no physical access, no IOMMU
/// family key), against the device records still
/// unbound, starts each driver it binds in a settle batch of its own, and
/// serves the batch once it settles, within [`SETTLE_TIMEOUT_MS`]. A
/// [`QUERY_DEVICE`] whose answer would name no driver waits until that
/// pass and its settle are done. A pass binds a record at most once a
/// boot, and none binds it again once its driver is withdrawn, so a device
/// whose driver was started before (served, failed, or withdrawn) is not
/// bound again, and a second request over the same
/// directory binds nothing. A driver this pass starts is never restarted,
/// since it is not installed in the drivers directory. devmgr deletes the directory cap once the
/// pass ends. Replies `INVALID_REQUEST`, deleting the cap, when `caps[0]`
/// or the path is absent, before [`SET_DRIVERS_DIR`] (whose pass binds first), and
/// while an earlier request's pass or settle is not done.
pub const BIND_DRIVERS: u64 = 22;
/// Decline the restart of a served driver: the caller cannot run on without
/// it, so devmgr withdraws it at its death and starts no new instance
/// (services/devmgr/docs/responsibilities.md § Driver Restart). vfsd sends
/// it for the disk its root filesystem sits on, once it has mounted the
/// root and before it serves anything (services/vfsd/README.md).
///
/// Served on a class SEND ([`MINT_CLASS_SEND`]) alone; a SEND badged
/// otherwise gets [`super::devmgr_errors::UNAUTHORIZED`]. Request:
/// `data[0]` = caller's compiled [`super::DEVMGR_LABELS_VERSION`];
/// `data[1]`, when sent, the instance ordinal of the class's driver, an
/// absent one being 0. Reply: [`super::devmgr_errors::SUCCESS`] once the
/// driver is marked; [`super::devmgr_errors::REFUSED`] once
/// [`SET_DRIVERS_DIR`] has arrived, from which point devmgr can restart a
/// driver, so the marks a restart reads are sealed and a class SEND holder
/// can decline a driver's restart only in the bootstrap window;
/// [`super::devmgr_errors::WITHDRAWN`] at a withdrawn driver's ordinal and
/// [`super::devmgr_errors::NO_DEVICE`] past the last served driver. A
/// mark lasts as long as the driver it marks. The handler logs nothing, as
/// [`QUERY_DEVICE`]'s does not.
pub const DECLINE_RESTART: u64 = 32;
/// The bound of a bind pass's settle, in milliseconds: how long devmgr
/// waits, from the start of a batch's settle (after its last spawn), for
/// each of the batch's drivers to report ready or die before it destroys
/// the drivers still pending. A query that waits for a settle
/// ([`QUERY_DEVICE`]) can wait this long past the batch's spawns.
pub const SETTLE_TIMEOUT_MS: u64 = 10_000;

/// Driver-only: report that the driver has set its device up and is
/// entering its service loop, so devmgr may serve its endpoint.
///
/// Sent by every driver devmgr spawns (a driver bound to a PCI device by
/// its declaration, and the serial, framebuffer, and RTC drivers) on its
/// devmgr query cap, a SEND badged with its device badge on the private
/// driver endpoint of its spawn batch; the
/// registry endpoint replies `UNKNOWN_OPCODE` to it. Request: `data[0]` =
/// caller's compiled [`super::DEVMGR_LABELS_VERSION`]. Reply: `SUCCESS`
/// when the badge names a driver of the batch that has not died (a
/// repeated report included); `INVALID_REQUEST` otherwise, and the driver
/// then exits, since devmgr will not serve it. devmgr serves the label
/// only until the batch settles, every driver of it having reported
/// ready or died, or until devmgr's settle bound elapses, and then
/// revokes the private endpoint; a driver that has not reported by then
/// is destroyed and never served. [`report_driver_ready`](super::report_driver_ready)
/// sends it.
pub const DRIVER_READY: u64 = 13;

/// Authority bit gating [`QUERY_ACPI_TABLE`] and [`QUERY_HOST_BRIDGE`].
/// Set on svcmgr's `devmgr.registry`, `devmgr.shutdown`, `devmgr.bind`,
/// and `devmgr.acpi` publications; a class SEND ([`MINT_CLASS_SEND`]) and the per-device
/// SENDs drivers hold for [`QUERY_DEVICE_INFO`] lack it. Without it the
/// handler replies `UNAUTHORIZED`. It admits no device query: a device
/// is reached through its class SEND alone.
pub const REGISTRY_QUERY_AUTHORITY: u64 = 1u64 << 63;
/// Authority bit gating [`SET_DRIVERS_DIR`]. svcmgr mints a SEND
/// cap carrying this bit from the devmgr-registry source cap init
/// endows it with at handover; the `REGISTRY_QUERY_AUTHORITY`-only
/// copy svcmgr publishes seed-only as `devmgr.registry` (which recipes
/// seed) lacks this bit, so no seeding consumer can call
/// `SET_DRIVERS_DIR`. Disjoint position from
/// [`REGISTRY_QUERY_AUTHORITY`].
pub const DRIVERS_DIR_AUTHORITY: u64 = 1u64 << 62;
/// Authority bit gating [`QUERY_SHUTDOWN_DEVICE`]. svcmgr mints it,
/// beside [`REGISTRY_QUERY_AUTHORITY`], only onto the SEND it publishes
/// seed-only as [`crate::published_names::DEVMGR_SHUTDOWN`], which
/// pwrmgr alone seeds and `QUERY_ENDPOINT` refuses, so no other process
/// holds the bit. Disjoint position from the other authority bits.
pub const SHUTDOWN_DEVICE_AUTHORITY: u64 = 1u64 << 61;
/// Authority bit gating [`BIND_DRIVERS`]. svcmgr mints it, beside
/// [`REGISTRY_QUERY_AUTHORITY`], only onto the SEND it publishes
/// seed-only as [`crate::published_names::DEVMGR_BIND`], which svctest
/// alone seeds. Disjoint position from the other authority bits.
pub const BIND_AUTHORITY: u64 = 1u64 << 60;
/// Authority bit gating [`MINT_CLASS_SEND`], which decides which
/// classes' drivers a SEND reaches. init and svcmgr mint it from the
/// devmgr-registry sources they hold, only onto a SEND they call
/// `MINT_CLASS_SEND` on and then delete; no consumer holds it. Disjoint
/// position from the other authority bits.
pub const CLASS_AUTHORITY: u64 = 1u64 << 59;
/// Authority bit gating the labels acpid alone calls:
/// [`QUERY_ACPI_RESOURCES`], [`ACPI_REGION_GRANT`], [`ACPI_PCI_CONFIG`],
/// [`OSC_RESULT`], [`BRIDGE_WINDOWS`], [`PRT_TABLE`], and [`ACPI_HOTPLUG`],
/// which has devmgr add or remove a firmware-driven slot's devices and
/// withdraw their drivers. svcmgr mints it, beside
/// [`REGISTRY_QUERY_AUTHORITY`], only onto the SEND it publishes
/// seed-only as [`crate::published_names::DEVMGR_ACPI`], which acpid
/// alone seeds. Disjoint position from the other authority bits.
pub const ACPI_AUTHORITY: u64 = 1u64 << 58;

/// The badge of a class SEND ([`MINT_CLASS_SEND`]): the class's slot in
/// devmgr's class table plus one in bits 0..=15, and the verb bits its
/// [`QUERY_DEVICE`] replies carry, moved down from
/// [`crate::VERB_BIT_MASK`] into bits 16..=21. No other bit is set, so a
/// class badge carries none of the registry's authority bits and reaches
/// `QUERY_DEVICE`, `WATCH_CLASS` and `DECLINE_RESTART` alone, and no
/// registry SEND of an authority bit reads as a class badge.
pub mod class_badge
{
    use core::prelude::rust_2024::*;

    /// Bits holding the class slot plus one; 0 is no class.
    pub const SLOT_MASK: u64 = 0xFFFF;
    /// How far the verb bits move down from their place in
    /// [`crate::VERB_BIT_MASK`].
    const VERB_SHIFT: u32 = 42;
    /// Bits holding the verb bits.
    pub const VERBS_MASK: u64 = crate::VERB_BIT_MASK >> VERB_SHIFT;
    /// Slots a class badge can name.
    pub const MAX_SLOTS: usize = 0xFFFF;
    const _: () = assert!(
        SLOT_MASK & VERBS_MASK == 0
            && VERBS_MASK & crate::VERB_BIT_MASK == 0
            && VERBS_MASK << VERB_SHIFT == crate::VERB_BIT_MASK
    );

    /// The badge naming class slot `slot` with verb bits `verbs`; `None`
    /// when `slot` is past [`MAX_SLOTS`] or `verbs` is empty or not a
    /// subset of [`crate::VERB_BIT_MASK`].
    #[must_use]
    pub fn encode(slot: usize, verbs: u64) -> Option<u64>
    {
        if slot >= MAX_SLOTS || verbs == 0 || verbs & !crate::VERB_BIT_MASK != 0
        {
            return None;
        }
        let slot = u64::try_from(slot).ok()?.checked_add(1)?;
        Some(slot | (verbs >> VERB_SHIFT))
    }

    /// The class slot and verb bits `badge` names; `None` for a badge
    /// [`encode`] does not produce.
    #[must_use]
    pub fn decode(badge: u64) -> Option<(usize, u64)>
    {
        let slot = badge & SLOT_MASK;
        let verbs = (badge & VERBS_MASK) << VERB_SHIFT;
        if slot == 0 || verbs == 0 || badge & !(SLOT_MASK | VERBS_MASK) != 0
        {
            return None;
        }
        usize::try_from(slot.checked_sub(1)?)
            .ok()
            .map(|s| (s, verbs))
    }
}

#[cfg(test)]
mod tests
{
    use crate::{VERB_BIT_MASK, blk_labels, devmgr_labels, serial_labels};

    #[test]
    fn a_class_badge_round_trips_and_carries_no_authority_bit()
    {
        use devmgr_labels::class_badge::{MAX_SLOTS, decode, encode};
        let verbs = serial_labels::WRITE_AUTHORITY | serial_labels::READ_AUTHORITY;
        for slot in [0, 1, 63, MAX_SLOTS - 1]
        {
            let badge = encode(slot, verbs).unwrap();
            assert_eq!(badge & VERB_BIT_MASK, 0, "slot {slot}");
            assert_eq!(decode(badge), Some((slot, verbs)));
        }
        assert_eq!(
            decode(encode(5, VERB_BIT_MASK).unwrap()),
            Some((5, VERB_BIT_MASK))
        );
    }

    #[test]
    fn a_class_badge_refuses_what_it_cannot_name()
    {
        use devmgr_labels::class_badge::{MAX_SLOTS, decode, encode};
        assert_eq!(encode(MAX_SLOTS, blk_labels::MOUNT_AUTHORITY), None);
        assert_eq!(encode(0, 0), None);
        assert_eq!(encode(0, 1), None);
        // No registry SEND of an authority bit reads as a class badge.
        for badge in [
            0,
            devmgr_labels::REGISTRY_QUERY_AUTHORITY,
            devmgr_labels::REGISTRY_QUERY_AUTHORITY | devmgr_labels::BIND_AUTHORITY,
            devmgr_labels::CLASS_AUTHORITY,
            devmgr_labels::DRIVERS_DIR_AUTHORITY,
        ]
        {
            assert_eq!(decode(badge), None, "badge {badge:#x}");
        }
        // A slot without verbs, verbs without a slot, and a class badge with
        // an authority bit added are refused.
        assert_eq!(decode(1), None);
        let good = encode(2, blk_labels::MOUNT_AUTHORITY).unwrap();
        assert_eq!(decode(good & !devmgr_labels::class_badge::SLOT_MASK), None);
        assert_eq!(decode(good | devmgr_labels::REGISTRY_QUERY_AUTHORITY), None);
        assert_eq!(decode(good | (1 << 30)), None);
    }
}
