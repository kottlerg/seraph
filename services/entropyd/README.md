# entropyd

The kernel entropy pool's userspace contributor: entropyd reads each hardware random-number
generator driver of the `hwrng` device class and mixes the bytes into the kernel pool with
`SYS_ENTROPY_CONTRIBUTE`, which gives them no entropy credit.

---

## Role

The kernel pool takes bytes from the kernel's own sources (the boot seed, RDSEED or RDRAND on
x86-64, the Zkr `seed` CSR on riscv64, timing jitter). A hardware RNG that only a userspace
driver reaches, such as a `virtio-rng` device, adds to it through entropyd. Every source is mixed
into the one pool and none replaces another, so the pool's output stays sound while any one source
is good, and a weak or hostile device cannot weaken it
([core/kernel/docs/entropy.md](../../core/kernel/docs/entropy.md) § Sources and graceful
degradation). A machine with no hardware RNG driver runs on the kernel's sources alone.

entropyd holds the one `EntropyControl` capability svcmgr gives, which carries `Contribute`
([docs/capability-model.md § `EntropyControl`](../../docs/capability-model.md#entropycontrol)).
svcmgr derives it for the one recipe that sets
[`entropy_authority = yes`](../svcmgr/docs/service-definitions.md#entropy_authority).

---

## Source Layout

```
entropyd/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Bootstrap, the class walk, the contribution, the wait
```

No `arch/` subdirectory: entropyd holds no hardware code, and the same binary runs on both
architectures. It holds no logic a host test can reach apart from the `hwrng` codec, which
`hwrng-protocol` tests; svctest's `entropyd_contribution` phase checks it end to end.

---

## Bootstrap

One round from svcmgr (recipe `rootfs/config/svcmgr/services/entropyd.svc`:
`seed = devmgr.class.hwrng`, `entropy_authority = yes`, no `provides`):

| Slot | Cap |
|---|---|
| `caps[0]` | `devmgr.class.hwrng`: the `hwrng` class SEND |
| `caps[1]` | the `EntropyControl` capability, carrying `Contribute` |

Both are required; with either absent entropyd logs `bootstrap missing caps` and exits.

---

## Operation

entropyd registers a `WATCH_CLASS` watch on the class before anything else, so a driver served
after it last looks is signalled to it. Then it makes a pass at once, and another on every wake:

1. Walk the class's ordinals from 0 with `QUERY_DEVICE`
   ([shared/ipc/src/devmgr_labels.rs](../../shared/ipc/src/devmgr_labels.rs)): pass an ordinal that
   replies `WITHDRAWN`, and stop at `NO_DEVICE`, the end of the served drivers, or at any other
   refusal.
2. For each live driver, send `hwrng_protocol::READ` for `READ_BYTES` bytes, bounded by
   `READ_TIMEOUT_MS` (2 s, twice the virtio-rng driver's own wait bound), decode the reply with
   `hwrng_protocol::decode_reply`, contribute the bytes in one `SYS_ENTROPY_CONTRIBUTE` call, and
   overwrite the buffer
   ([shared/hwrng-protocol/README.md](../../shared/hwrng-protocol/README.md)).
3. Delete the driver's SEND: entropyd keeps no driver cap between passes, so a withdrawn driver's
   revoked endpoint is never called twice.

After a pass that reached a live driver, entropyd sleeps for `PACE` and makes the next. After a
pass that reached none, it waits on the watch without a bound and makes the next pass when devmgr
signals a change, never polling `QUERY_DEVICE` for a device that is absent
(`devmgr_errors::NO_DEVICE`). Without a watch (devmgr refused it) and with no live driver,
entropyd logs that and exits.

A driver that refuses, times out, or replies malformed words yields nothing that pass; the next
pass asks again.

### Pacing

At its start and then every `PACE` (10 s), entropyd reads `READ_BYTES` (64) from each live
driver and contributes them:

- **64 bytes.** One contribution call fits `MAX_ENTROPY_CONTRIBUTE_LEN` (256), and one absorb
  under the pool's 136-byte sponge rate, so a contribution costs one permutation under the pool
  lock, which holds interrupts off. 64 bytes is twice `RESEED_BYTES` (32), the seed material a
  generator draws per reseed. More bytes per call add nothing: the bytes carry no credit, and the
  pool is sound while any one source is good.
- **10 s.** The bytes cannot seed the pool, which the kernel seeds before any contribution is
  admitted, so the pace buys recovery from a compromise of the pool's state, not seeding. Every
  CPU's generator reseeds from the pool within its time budget, `RESEED_TIME_BUDGET_US` (1 s),
  so the recovery window is about the pace. 10 s keeps the device traffic, the IPC, and the
  interrupts-off pool hold negligible.

### Log

entropyd logs `entropy contribution accepted: <n> bytes from hwrng ordinal <o>` once, on the
first contribution the kernel accepts, which svctest's `entropyd_contribution` phase awaits. A
failure (a refused query, a failed or refused `READ`, a malformed reply, a refused contribution)
is logged on the first pass of a driver's run of failures, and not again for that driver's ordinal
until a contribution from it is accepted, so a failing driver beside a working one logs once.

---

## What entropyd never does

- **Serve draws.** It provides no endpoint. `SYS_GETRANDOM` is the only draw surface.
- **Hold a device capability.** It holds a class SEND and, for the length of one `READ`, a SEND
  on a driver's endpoint; the device is the driver's
  ([docs/driver-binding.md](../../docs/driver-binding.md) § Device Classes).
- **Derive or pass on its capability.** The `EntropyControl` capability is used only in its own
  `SYS_ENTROPY_CONTRIBUTE` calls.
- **Claim credit.** The kernel gives contributed bytes no entropy credit, and entropyd neither asks
  for nor counts any.
- **Log the bytes.** Its lines name byte counts and ordinals, never byte values.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [core/kernel/docs/entropy.md](../../core/kernel/docs/entropy.md) | The pool, its sources, the contributed source class, the reseed policy |
| [docs/capability-model.md](../../docs/capability-model.md) | `EntropyControl` and the `Contribute` right |
| [docs/driver-binding.md](../../docs/driver-binding.md) | Device classes, `QUERY_DEVICE` through a class SEND |
| [docs/device-management.md](../../docs/device-management.md) | devmgr's class broker, `WITHDRAWN` and `NO_DEVICE` |
| [shared/hwrng-protocol/README.md](../../shared/hwrng-protocol/README.md) | The `hwrng` class's `READ` label and its reply codec |
| [services/svcmgr/docs/service-definitions.md](../svcmgr/docs/service-definitions.md) | The `entropy_authority` recipe key |

---

## Summarized By

[Kernel Entropy Subsystem](../../core/kernel/docs/entropy.md),
[Architecture Overview](../../docs/architecture.md),
[Capability Model](../../docs/capability-model.md),
[Device Management](../../docs/device-management.md),
[services/README.md](../README.md)
