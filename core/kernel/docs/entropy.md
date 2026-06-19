# Kernel Entropy Subsystem

Kernel-internal randomness: a multi-source entropy pool feeding per-CPU
forward-secure CSPRNGs, with a small draw API, hardware-source health gating,
and a boot-time power-on self-test.

---

## Scope and threat model

This subsystem is the kernel's sole internal source of randomness. It is
**kernel-internal only**: it adds no syscall and exposes nothing to userspace.
Userspace randomness is a separate concern obtained through language runtimes
and userspace services; the two surfaces share no state.

The subsystem must yield values an attacker cannot predict or reconstruct even
after a later full-state compromise (forward secrecy), and must remain
functional — degraded, not absent — on platforms with no hardware RNG. It is
not a general-purpose KDF or a userspace `getrandom`; consumers are kernel
hardening primitives (address-space layout randomization, handle/identifier
randomization, key/nonce generation).

The hardware RNG is treated as untrusted until it passes startup health tests
and is **never the sole input** regardless of those tests: its output is always
mixed with timing jitter before any byte is drawn.

## Sources and graceful degradation

Two source classes are mixed into the pool:

- **Hardware RNG** — drawn through the `arch::current::entropy` contract
  (`hw_rng_available`, `hw_rng_u64`). On x86-64 this is RDSEED (a conditioned,
  seed-grade source, preferred) with an RDRAND fallback, CPUID-gated, each with
  bounded retry on the transient not-ready condition the ISA permits. Hardware
  output is health-gated (below) before it is trusted.
- **Timing jitter** — cycle-counter samples (`read_cycle_counter`: TSC on
  x86-64; the `time` CSR on riscv64) taken at distinct interrupt event classes.
  This is the always-available source.

On a platform without a hardware RNG — riscv64 under default firmware, where
`hw_rng_available` is false — the subsystem degrades gracefully to **jitter
only**. The pool and per-CPU generators are otherwise identical; only the seed
material differs.

## Keccak duplex construction

The cryptographic core is the Keccak-f[1600] permutation (FIPS 202), in
`entropy::keccak`. `entropy::sponge::Prng` runs it as a sponge in duplex mode:

- **Rate** `RATE` = 136 bytes (1088-bit), matching SHAKE256.
- **Capacity** = 512 bits, never output — the perpetual secret carried forward,
  giving 256-bit security.
- `Prng::absorb` XORs entropy into the rate and permutes (seeding/reseeding).
- `Prng::fill` permutes, squeezes output, then provides **forward secrecy by
  fast key erasure**: it zeroes the just-exposed rate region and permutes once
  more. Because the permutation is invertible, the extra permute alone would not
  hide the output; zeroing the rate first is what makes returned bytes
  unrecoverable from the post-fill state.

The absorb/squeeze plumbing is anchored against the NIST `SHAKE256("")` known
answer; the permutation against the FIPS-202 zero-state vector (see Testing).

## Central pool and multi-source mixing

`entropy::pool` is a single `Prng` that accumulates every source and hands
**seed material** to the per-CPU generators. It is guarded by a leaf
`Spinlock`:

- The lock is **never taken at interrupt time** — interrupt-time jitter lands in
  a per-CPU buffer and is folded in off the interrupt path — and is never held
  across a blocking operation.
- The raw pool is never exposed. Callers either `absorb` into it or `draw_seed`
  from it; consumer-facing output comes only from the per-CPU generators.
- A `SEEDED` flag gates draws: `draw_seed` is valid only after `mark_seeded`.

Pool storage is a buddy-allocated slab published through an `AtomicPtr`
(`install`); `absorb` is a no-op before installation, so early callers are safe.

## Per-CPU CSPRNG and reseed policy

`entropy::cpurng::CpuRng` is one forward-secure generator per CPU, stored in a
per-CPU slab. Each instance is touched only by its owning CPU under
interrupt-disabled exclusivity, so it carries **no lock**.

Reseed policy:

- A generator reseeds **on first use** and then **every `RESEED_DRAW_INTERVAL`
  (256) draws**.
- Each reseed folds that CPU's accumulated jitter into the pool
  (`jitter::contribute_to_pool`), draws `RESEED_BYTES` (32 — a 256-bit reseed)
  of fresh seed material, and absorbs it; the seed buffer is then zeroed.
- The interval bounds how much output depends on any single seed without making
  the reseed cost (a pool lock plus permutations) a per-draw expense.

Forward secrecy *across* draws is provided by the sponge's per-fill erasure;
reseeding additionally bounds the blast radius of any single seed.

## Boot-time entropy and the riscv64 jitter-only path

At boot, runtime jitter has not yet accumulated. `seed_pool_from_sources` mixes:

1. The hardware RNG where present, drawn under a fresh health monitor up to a
   bounded number of words (margin for RDSEED retries), absorbed only while the
   source has not failed.
2. A boot jitter scrape: cycle-counter samples taken across intervening pool
   work, whose microarchitectural timing perturbs successive reads.

This is the **documented boot-entropy hole**: on a jitter-only platform the
initial seed is weaker than at steady state. It is narrowed continuously at
runtime by the timer-tick jitter hook, which feeds a fresh sample into each
CPU's accumulator on every tick (and per device IRQ). 

TODO: persist a saved seed across boots (read at `init_storage`, rewritten at
shutdown) to close the boot-entropy hole on jitter-only platforms; deferred —
it requires a storage-stack dependency the kernel does not have at Phase 4.

## Health tests (hardware RNG gating)

`entropy::health::Health` implements the NIST SP 800-90B §4.4 continuous tests,
byte-wise:

- **Repetition Count Test** (§4.4.1): cutoff `RCT_CUTOFF` = `1 + ceil(30 / H)` =
  31 for the conservative assessed min-entropy `ASSESSED_H` = 1 bit/byte
  (α = 2⁻³⁰).
- **Adaptive Proportion Test** (§4.4.2): `APT_WINDOW` = 512 samples; reject when
  the window's first value recurs past `APT_CUTOFF` = 384 (¾ of the window).
- **Startup** (§4.3): `STARTUP_BYTES` = 1024 bytes must pass both tests before
  the source is `trusted`.

On any failure the source is permanently distrusted (`failed`) and the
subsystem proceeds on jitter alone. Because the hardware RNG is never the sole
input, a source that passes startup but later degrades still cannot by itself
determine pool output.

## Draw API and consumers

The kernel-internal draw API is `entropy::fill_bytes(out: &mut [u8])`: it fills
`out` with CSPRNG bytes from the **calling CPU's** generator. Interrupts are
disabled for the draw to pin the CPU and bar ISR reentry, giving exclusive,
migration-free access to that generator. It MUST NOT be called from interrupt
context (it takes non-reentrant per-CPU state) or before the pool is seeded.

There is no production consumer in the kernel today; the API is foundational for
the hardening primitives named under Scope. The boot self-test is its current
exerciser and continuous validator.

## Boot wiring and lifecycle

- **Phase 4** (`init_storage`): allocate the per-CPU generators, the pool, the
  per-CPU jitter accumulators, and the self-test sample slab from the buddy
  allocator — alongside the scheduler slabs and for the same reason: before the
  user-capability drain, while the buddy still holds large contiguous blocks.
- **Phase 5** (`init`, BSP): seed the pool from all sources, mark it seeded
  (opening the draw API), and capture the BSP's self-test sample.
- **Phase 8** (`init_ap`, each AP): capture that AP's self-test sample; the AP's
  generator seeds lazily from the already-seeded pool on its first draw.
- **Post-SMP** (`selftest::run`, BSP): run the power-on self-test across all
  CPUs.
- **Runtime**: the scheduler timer tick and device-IRQ dispatch feed jitter
  samples into the per-CPU accumulators.

## Testing

- **Host known-answer and property tests** (`cargo xtask test`): the
  Keccak-f[1600] zero-state vector; the NIST `SHAKE256("")` FIPS-202 vector and
  a multi-block squeeze; sponge determinism, seed-sensitivity, fill advancement,
  and forward-secrecy erasure; health-test cutoffs and stuck/biased-source
  trips. The permutation and sponge are pure and host-testable; the pool,
  per-CPU generators, jitter, and draw API are hardware-coupled and built only
  for the kernel target.
- **In-kernel power-on self-test**: each CPU captures a sample from its own
  generator as it comes online; after SMP bringup the BSP asserts every sample
  is non-trivial, samples are pairwise distinct (per-CPU independence), and the
  aggregate bit balance is sane. The result prints as `entropy: SELFTEST PASS`
  or `entropy: SELFTEST FAIL`; the FAIL marker is matched by the run-parallel
  fail-regex, turning a QEMU run red on either architecture. Validated on
  x86_64 (hardware-seeded) and riscv64 (jitter-only).

---

## Summarized By

[Kernel](../README.md)
