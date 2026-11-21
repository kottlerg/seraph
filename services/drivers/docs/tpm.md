# TPM 2.0 Driver

Design of the TPM 2.0 driver (`services/drivers/tpm/`): how the system finds a TPM, the two
register interfaces the driver speaks, the commands it sends, and the bounds within which it serves
the `hwrng` class.

---

## Role

A TPM 2.0 has a random number generator of its own, reached with `TPM2_GetRandom` (TPM 2.0
Library, Part 3, § 16.1). It is a hardware source independent of the CPU's instructions (RDSEED and
RDRAND on x86-64), so the kernel pool, which mixes every source and replaces none, stays sound
while either is good ([core/kernel/docs/entropy.md](../../../core/kernel/docs/entropy.md)
§ Central pool and multi-source mixing). The driver is a member of the `hwrng` class
([shared/hwrng-protocol/README.md](../../../shared/hwrng-protocol/README.md)): it answers
`READ(n)` with bytes from the TPM, and `entropyd` reads it as it reads every member and
contributes the bytes ([services/entropyd/README.md](../../entropyd/README.md) § Operation). The
driver holds the TPM's registers and no kernel authority, and sends no command but the two below:
it reads no PCR, holds no key, and takes no part in measured boot.

---

## Discovery

Two firmware descriptions of the TPM meet at the bind:

- **The ACPI `TPM2` table** names the interface by its start method and, for the CRB interface,
  the address of the CRB control area. It names no register range: its one address lies inside
  locality 0, and the FIFO interface has none. The bootloader's aperture-seed walk reads it
  ([core/boot/docs/acpi.md](../../../core/boot/docs/acpi.md) § Tables Consumed): for start
  method 6 (the FIFO interface, memory-mapped) and for start method 7 (the CRB interface, started
  through `TPM_CRB_CTRL_START`) with the control area inside the platform's TPM window, it seeds
  that window as an MMIO aperture. The window is the architecture's
  (`arch::current::tpm_register_window`): on x86-64 the PC Client TPM range, `0xFED4_0000` for
  `0x5000` bytes, the five localities; riscv64 has none. No other table names the range and the
  UEFI memory map need not describe it, and devmgr carves a record's `Mmio` only from what the
  boot handed it, so without the seed devmgr could not give the driver its registers. Without a
  `TPM2` table the walk seeds nothing, and a boot without a TPM is unchanged.
- **The ACPI namespace** holds the TPM's `Device` object, whose `_HID` `MSFT0101` is the
  TCG's identifier of a TPM 2.0 and whose `_CRS` names the register range. devmgr's namespace
  enumerator records it ([docs/driver-binding.md](../../../docs/driver-binding.md) § Device
  Records), and the driver's declaration matches it: `Match::AcpiHid("MSFT0101")`, class
  `hwrng`, no interrupt, no DMA, auxiliary tier, at most one instance. devmgr delivers the
  record's range as one `Mmio` capability, with the service endpoint and the devmgr query cap
  (`driver_binding::resources::PlatformDelivery`).

The driver takes a range that is page-aligned and spans one to five pages (`WINDOW_MIN` to
`WINDOW_MAX`), maps it whole, and drives locality 0 alone. Every register access is checked
against the mapped length: one outside it reads all-ones and writes nothing, so no offset the
driver computes from the TPM's values reaches past the window.

A TPM started any other way is not driven: the ACPI-started CRB (start methods 2 and 8), which
firmware TPMs with their buffers in memory use, AMD's among them, and the start methods of other
architectures. The walk seeds no aperture for it, so devmgr cannot carve the record's range and
starts no driver.

---

## Interfaces

The driver reads `TPM_INTERFACE_ID` (offset `0x30` of locality 0 on both interfaces) and takes
the interface its low nibble, `InterfaceType`, names (TCG PC Client Platform TPM Profile,
§ 6.4 and § 6.5): 0, the FIFO interface; `0xF`, the FIFO interface of a TIS 1.3 TPM, whose
register is reserved and reads all-ones; 1, the CRB interface. Any other value ends the driver
before it reports ready. Each command takes locality 0, runs, and gives the locality up and leaves
the TPM idle whatever its outcome.

**FIFO.** The driver requests locality 0 through `TPM_ACCESS` and waits for it to be active, sets
`commandReady` in `TPM_STS` and waits for it, writes the command into `TPM_DATA_FIFO` in
bursts no longer than `burstCount`, checking after each that the TPM expects more until the last
byte and no more after it, sets `tpmGo`, and waits for `dataAvail`. It reads the response's
10-byte header, then the rest of the size the header gives, then checks that the FIFO holds
nothing past it. `commandReady` then aborts whatever the TPM still holds, and a write of
`activeLocality` gives the locality up.

**CRB.** The control area names the command and response buffers by address and size. Both must
lie inside the mapped window and hold at least a response header, or the driver ends before it
reports ready; on the PC Client profile they lie in locality 0. Per command the driver requests
locality 0 through `TPM_LOC_CTRL` and waits for `TPM_LOC_STS` to grant it, withdraws any cancel
an earlier command left, requests `cmdReady` and waits for it, checks `TPM_CRB_CTRL_STS` for a
fatal error, writes the command into the command buffer, writes `TPM_CRB_CTRL_START`, and waits
for the TPM to clear it. A command still running at its bound is cancelled through
`TPM_CRB_CTRL_CANCEL`. It reads the header and the rest of the response, refusing a size past the
response buffer, then requests `goIdle` and relinquishes the locality.

---

## Commands

Both commands carry no sessions (`TPM_ST_NO_SESSIONS`) and one `u16` parameter, and every
field is big-endian (TPM 2.0 Library, Part 3):

- `TPM2_GetRandom` (`TPM_CC_GetRandom`, `0x17B`) asks for `bytesRequested` bytes. A TPM
  returns at most the size of its largest digest per call (32 or 48 bytes on a common TPM),
  whatever is asked, so a read sends the command again, each asking for what is left, at most
  `MAX_READ_BYTES` (504), until the read is full. A response is accepted only when its tag, its
  size and the size of its `TPM2B_DIGEST` agree, and the digest holds no more than was asked.
- `TPM2_Startup(TPM_SU_CLEAR)` (`0x144`) is sent once, when `TPM2_GetRandom` answers
  `TPM_RC_INITIALIZE`: no firmware started the TPM. A start-up answered `TPM_RC_INITIALIZE`
  found the TPM started by another party, and the read goes on.

A TPM that answers `TPM_RC_RETRY` (busy), `TPM_RC_TESTING` (its self-tests run, as they can
after a start-up) or `TPM_RC_YIELDED`, or returns no bytes, is asked again after a pause. Any
other response code, `TPM_RC_FAILURE` among them, ends the read.

---

## Bounds and Failure

The driver polls: its declaration asks for no interrupt, and a `TPM2_GetRandom` completes in
milliseconds. Every wait a command makes, and every pause between the commands of one read, polls
every millisecond against one deadline for the whole read.

- **The probe.** Before it reports `DRIVER_READY`, the driver reads 8 bytes, and discards them,
  within `PROBE_WAIT` (5 s), inside devmgr's settle bound and long enough for a TPM that runs
  its self-tests after the start-up. A TPM that fails the probe, like a window, an interface or a
  buffer the driver refuses, ends the driver before it reports ready: devmgr serves no client a
  driver that could only answer `NOT_READY`, and the system runs on without it, as it does
  without a TPM.
- **A read.** A `READ` is bounded by `READ_WAIT` (1.5 s), below the 2 s `entropyd` waits for
  a reply, so the reply always reaches it. A read that ends with some bytes, its bound passed or a
  command failed after they arrived, replies with those bytes and their count; one that ends with
  none replies `NOT_READY`, and the caller asks again later. A run of failed reads is logged at
  its first and once the TPM reads again.

The driver serves one request at a time and keeps no byte for a later reply: each `READ` asks
the TPM for fresh bytes, so no byte is handed out twice. It does not scrub the copies of a reply
it has sent, which stay in its own address space until they are overwritten.

---

## Service

The driver serves `hwrng_protocol::READ` on its service endpoint as
[shared/hwrng-protocol/README.md](../../../shared/hwrng-protocol/README.md) specifies: gated by
`READ_AUTHORITY`, at most `min(n, MAX_READ_BYTES)` bytes per reply, `UNKNOWN_OPCODE` for
any other label, and every capability a request carries deleted before the reply. Its log names
the interface it found, the probe's success, and the first `READ` answered with bytes.

---

## Testing

The library (`src/lib.rs` and its modules) holds everything the driver does with the window, and
its host tests run it against a simulated TPM 2.0 behind a FIFO window and a CRB window
(`src/sim.rs`): the interface id, both interfaces' transactions, the start-up on
`TPM_RC_INITIALIZE`, the retried codes, the per-call limit, the bounds, malformed responses, CRB
buffers outside the window, and the verb-bit gate. The bootloader's host tests cover the `TPM2`
table's seed.

`cargo xtask test tpm` (x86-64) boots the default boot set once with QEMU's `tpm-tis` device
and once with `tpm-crb`, each backed by `swtpm` on a fresh state, and passes when the driver
names the interface, answers its first `READ` with bytes, and `entropyd` has a contribution
from it accepted ([docs/testing.md](../../../docs/testing.md#tpm-tpm-case) § TPM). On real
hardware, an x86-64 machine whose firmware enables a TPM 2.0 and reports it with start method 6
or 7 binds the driver the same way: a discrete TPM on the FIFO interface, or a firmware TPM on the
CRB interface with its buffers in locality 0.

---

## Summarized By

[Kernel Entropy Subsystem](../../../core/kernel/docs/entropy.md),
[Platform Requirements](../../../docs/platform-requirements.md),
[services/drivers/tpm/README.md](../tpm/README.md)
