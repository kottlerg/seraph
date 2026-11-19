# tpm

TPM 2.0 driver: a member of the `hwrng` device class that serves
[`hwrng_protocol::READ`](../../../shared/hwrng-protocol/README.md) with `TPM2_GetRandom`, over
the FIFO or the CRB register interface. It holds the TPM's registers and nothing more: no kernel
authority, and no say in what the bytes are used for. Its design is in
[services/drivers/docs/tpm.md](../docs/tpm.md).

---

## Source Layout

```
tpm/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                 # Interface id, TPM2_GetRandom loop, READ gate (host-tested)
    ├── command.rs             # TPM2 command marshalling, response checks (host-tested)
    ├── regs.rs                # Register access, wait bound, and fault types the interfaces run on
    ├── fifo.rs                # FIFO (TIS) interface state machine (host-tested)
    ├── crb.rs                 # CRB interface state machine (host-tested)
    ├── sim.rs                 # Simulated TPM behind FIFO and CRB windows (test only)
    └── main.rs                # Driver entry, register window, probe, IPC service loop
```

---

## Endpoint

The driver carries a declaration in the ELF note section `.note.seraph.driver` (ACPI `_HID`
`MSFT0101`, class `hwrng`, no interrupt, no DMA, auxiliary tier, at most one instance). Devmgr
binds it to the TPM's ACPI namespace record and delivers the record's register window as one
`Mmio` capability, which it carves from the aperture the bootloader seeds from the ACPI `TPM2`
table ([services/drivers/docs/tpm.md](../docs/tpm.md) § Discovery). It is not
bootstrap-essential, so it loads lazily through devmgr's `SET_DRIVERS_DIR` subtree cap (see
[docs/device-management.md](../../../docs/device-management.md)), from
`/services/drivers/tpm`, on x86-64 alone. The driver reports `DRIVER_READY` on its devmgr query
endpoint once a first `TPM2_GetRandom` has answered, immediately before its service loop; a TPM
that does not answer ends the driver before that report, and the system runs on without it.
Devmgr owns the service endpoint and mints clients a SEND badged with the `hwrng` class file's
verb bits (`rootfs/config/devmgr/classes/hwrng.class`: `hwrng_protocol::READ_AUTHORITY`) via
`devmgr_labels::QUERY_DEVICE` on the `devmgr.class.hwrng` class SEND (see [devmgr
Responsibilities](../../devmgr/docs/responsibilities.md#responsibilities)).

---

## Messages

Synchronous call/reply (`SYS_IPC_CALL`). The label, its reply codec, the verb bit and the error
codes live in [`shared/hwrng-protocol`](../../../shared/hwrng-protocol/README.md), which
specifies the wire shape. No label takes a cap: the driver deletes every cap a request carries
before it replies.

### Label 1: `READ`

**Request:** `data[0]` is `n`, the most bytes the caller takes. Gated by `READ_AUTHORITY`: a
caller whose badge lacks it gets `UNAUTHORIZED` (`2`) at once, and no command reaches the TPM.

**Reply (`SUCCESS`):** `data[0]` is the byte count `k`, at most `min(n, MAX_READ_BYTES)`
(504), and the bytes follow from `data[1]`, packed little-endian. A read sends
`TPM2_GetRandom` until it holds `k` bytes, as many times as the TPM's per-call limit needs, and
answers with fewer when its bound (1.5 s) passes first. `READ(0)` answers `k` = 0 without
touching the TPM. **Reply `NOT_READY` (`3`)**, with no
data, when no byte arrived within the bound; the caller asks again later
([services/drivers/docs/tpm.md](../docs/tpm.md) § Bounds and Failure).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/drivers/docs/tpm.md](../docs/tpm.md) | Discovery, the FIFO and CRB interfaces, the commands, bounds and failure, testing |
| [shared/hwrng-protocol/README.md](../../../shared/hwrng-protocol/README.md) | The `hwrng` class protocol: `READ`, its reply, the verb bit |
| [services/drivers/docs/driver-model.md](../docs/driver-model.md) | Driver lifecycle and capability delegation |
| [docs/driver-binding.md](../../../docs/driver-binding.md) | Driver declarations, ACPI namespace records, and device classes |
| [docs/device-management.md](../../../docs/device-management.md) | Driver lifecycle, on-disk loading |
| [core/boot/docs/acpi.md](../../../core/boot/docs/acpi.md) | The bootloader's `TPM2` table read and the aperture it seeds |
| [core/kernel/docs/entropy.md](../../../core/kernel/docs/entropy.md) | The kernel entropy pool the class is meant to feed |

---

## Summarized By

None
