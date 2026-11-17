# acpid

The ACPI service: it runs the firmware's AML and gives devmgr what the AML says about each PCI
host bridge.

---

## Source Layout

```
acpid/
├── Cargo.toml
├── README.md
├── docs/
│   ├── startup.md        # The start-up sequence, the interrupt model, failures, restart
│   └── devmgr.md         # Capabilities, region grants, configuration access, pushes, checks
└── src/
    ├── lib.rs            # Host-tested library: `Failure`, `Why`
    ├── power.rs          # Power requests: decode, `\_S5_`, `\_PTS`, the `PM1a_CNT` values
    ├── walk.rs           # The `_STA` / `_INI` initialization walk
    ├── bridge.rs         # Host bridges: `_HID`/`_CID`, `_SEG`, `_BBN`, `_OSC`, `_CRS`, `_PRT`
    ├── table.rs          # Where a served table sits in its region's mapping
    ├── sim.rs            # Test host over the captured QEMU tables (tests only)
    ├── main.rs           # Entry, bootstrap, the evaluation thread
    ├── caps.rs           # svcmgr bootstrap: the service endpoint, the `devmgr.acpi` seed
    ├── devmgr.rs         # The calls acpid makes on devmgr
    ├── platform.rs       # The evaluator's `Host`: region grants, configuration access
    ├── startup.rs        # The start-up sequence and the pushes
    ├── server.rs         # The power requests' service loop
    └── arch/
        ├── mod.rs            # Arch dispatch: `arch::current`
        ├── x86_64/mod.rs     # ACPI mode, port I/O, the APIC model, PM1a_CNT, RESET_REG
        └── riscv64/mod.rs    # No I/O space, one interrupt model, no power registers
```

The library (`lib.rs`, `walk.rs`, `bridge.rs`, `table.rs`, `power.rs`) holds the evaluation
logic and is host-tested over the QEMU tables `shared/aml/fixtures/` holds; the binary gives it a
`Host` that reaches hardware only through devmgr.

---

## Responsibilities

acpid is a svcmgr service, launched on every boot of both architectures from
`rootfs/config/svcmgr/services/acpid.svc` (`restart = on_failure`, `critical = no`). It is
the only process that evaluates AML: devmgr evaluates none
([docs/driver-binding.md](../../docs/driver-binding.md) § Device Records). It loads the DSDT
and the SSDTs devmgr serves, switches an x86-64 platform into ACPI mode, runs the
initialization walk, and evaluates each PCI host bridge's `_OSC`, `_CRS` and `_PRT`
([docs/startup.md](docs/startup.md)). It pushes the results to devmgr, which keeps those that
agree with its boot records and serves them per bridge with `QUERY_HOST_BRIDGE`
([docs/devmgr.md](docs/devmgr.md) § Pushes).

acpid is a provider: its recipe's `provides = acpid.power:auth acpid.deny:deny` makes svcmgr
create its service endpoint and publish two SENDs on it, the seed-only `acpid.power`, carrying
`POWER_AUTHORITY`, which only pwrmgr seeds, and the public `acpid.deny` without it. Once its
start-up ends, the evaluation thread serves the power requests on that endpoint (§ Power
requests); a request sent during start-up waits in the endpoint's queue.

---

## Power requests

acpid serves `ipc::acpid_labels` on its endpoint, from the evaluation thread, so every evaluation
runs in turn on the one thread that owns the namespace. A request is checked in order: the label
(`UNKNOWN_OPCODE`), the badge's `POWER_AUTHORITY` (`UNAUTHORIZED`), `ACPID_LABELS_VERSION` in
`data[0]` (`LABEL_VERSION_MISMATCH`), then the argument.

- `SLEEP`, with the state in `data[1]`, of which only S5 (soft-off) is served
  (`INVALID_REQUEST` for another): acpid evaluates `\_S5_` for `SLP_TYPa` (its first element,
  at most 7), runs `\_PTS(5)` when the tables define it (a fault is logged and the sleep goes
  on), then writes `PM1a_CNT` twice, keeping its other bits: `SLP_TYPa` with `SLP_EN` clear,
  then with `SLP_EN` (bit 13) set, and logs `SLEEP(5): PM1a_CNT ...` before the writes.
- `RESET`: acpid writes the FADT's `RESET_VALUE` to its `RESET_REG` port and logs
  `RESET: RESET_REG ...` before the write.

On the success path the platform powers off or resets and no reply arrives. A `SUCCESS` reply
means the writes returned and the platform still runs; the caller decides how long to wait.
`NO_DEVICE` means the platform lacks what the request needs: `PM1a_CNT`, a usable `\_S5_` or
loaded AML for `SLEEP`, an I/O-space `RESET_REG` for `RESET`, and always on RISC-V, whose
platforms power off and reset through SBI. acpid acquires `PM1a_CNT` and `RESET_REG` from
devmgr (`QUERY_ACPI_RESOURCES`) at the start of its start-up and binds them to the evaluation
thread. The endpoint is served even when the DSDT did not load. A receive that keeps failing exits
acpid (`ipc::recv_guard`), and svcmgr restarts it on the same endpoint.

---

## Region grants

acpid holds no hardware capability of its own. Beside its service endpoint's `RECV`, its one
capability, the `devmgr.acpi` seed, carries `ACPI_AUTHORITY`, under which devmgr serves it the
FADT's register blocks and grants it, on first use, each `SystemIO` or `SystemMemory` operation
region its AML reaches. devmgr refuses, logged, a range that a device record, a driver or the kernel
holds (the interrupt controllers and, on x86-64, the legacy ports it drives), the
configuration-mechanism ports 0xCF8-0xCFF, the FACS, and memory outside the `Mmio` apertures it
still holds, which leaves out RAM and ACPI NVS. Memory is granted a page at a time. A field access
in a refused region fails and its method aborts. `PCI_Config` regions are reached one access at a
time through devmgr, which allows reads, and writes only at offset 0x40 and above of a function with
no bound driver. The policy is [docs/devmgr.md](docs/devmgr.md) § Region grants and § Configuration
access.

---

## Checks

devmgr keeps a bridge's `_OSC` result as acpid pushes it, the first one for the boot. It keeps
a bridge's `_CRS` windows and `_PRT` routes only when they agree with its boot records: each
boot function's bus inside the bus window, its memory BARs inside a memory window and an
aperture, its I/O BARs inside an I/O window, and its interrupt pin routed (on x86-64 to the line
the firmware programmed, read in the PIC model; on RISC-V to the `virt` swizzle). A push that
disagrees is refused, fail-closed: the bridge then has no windows or routes from acpid for the
boot. The checks are [docs/devmgr.md](docs/devmgr.md) § Pushes.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/driver-binding.md](../../docs/driver-binding.md) | Device records; devmgr evaluates no AML, acpid does |
| [docs/capability-model.md](../../docs/capability-model.md) | Capability authority; how acpid's capabilities derive from devmgr's |
| [docs/limits.md](../../docs/limits.md) | The evaluator's bounds and acpid's own |
| [shared/aml/README.md](../../shared/aml/README.md) | The parser, namespace and evaluator acpid runs |
| [shared/ipc/src/lib.rs](../../shared/ipc/src/lib.rs) | The `devmgr_labels` acpid calls, the `acpid_labels` it serves, and their wire contract |
| [services/pwrmgr/README.md](../pwrmgr/README.md) | The holder of `acpid.power`; powers off and resets x86-64 through acpid |
| [services/devmgr/README.md](../devmgr/README.md) | The hardware authority that grants acpid's regions and keeps its results |
| [services/svcmgr/README.md](../svcmgr/README.md) | Launcher and supervisor; mints the `devmgr.acpi` seed and publishes `acpid.power` and `acpid.deny` |
| [services/svctest/README.md](../svctest/README.md) | Services harness; checks what devmgr holds from acpid, the `ACPI_AUTHORITY` gate, and the `POWER_AUTHORITY` gate through `acpid.deny` |

---

## Summarized By

[ACPI Parsing](../../core/boot/docs/acpi.md),
[Firmware Parsing](../../core/boot/docs/firmware-parsing.md),
[Architecture Overview](../../docs/architecture.md),
[Driver Binding](../../docs/driver-binding.md),
[services/pwrmgr/README.md](../pwrmgr/README.md),
[shared/aml/README.md](../../shared/aml/README.md)
