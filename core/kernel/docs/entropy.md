# Kernel Entropy Subsystem

Kernel-internal randomness: a multi-source entropy pool feeding per-CPU
forward-secure CSPRNGs, with a small draw API, hardware-source health gating,
and a boot-time power-on self-test.

---

## Scope and threat model

This subsystem is the kernel's sole source of randomness, for both
kernel-internal consumers and the userspace `SYS_GETRANDOM` syscall (see
`docs/syscalls.md`). Kernel consumers call `fill_bytes` directly; userspace
draws through the syscall, which fills the caller's buffer from the same
per-CPU generators. Userspace holds **no** generator state of its own — every
draw advances the kernel generator — so the two surfaces share the per-CPU
generators but no userspace-resident secret.

This shared sourcing is safe by construction. The sponge's per-fill fast key
erasure (below) makes returned bytes unrecoverable from post-fill state and
makes successive fills independent, so a userspace observer of `getrandom`
output learns nothing about prior or subsequent kernel draws (ASLR offsets,
nonces, keys): forward secrecy holds across the kernel/userspace boundary, not
only within the kernel. The userspace path adds no authority-bearing surface —
`SYS_GETRANDOM` is ambient and draw-only; it injects no entropy — and per-call
length is capped (`MAX_GETRANDOM_LEN`) so a draw never holds interrupts off for
an unbounded window. Because userspace keeps no RNG state, two processes (or a
forked/cloned address space) cannot share or duplicate a seed: each diverges
from its first draw by independently advancing the generator. Whole-VM-snapshot
reuse — a resumed snapshot replaying pool and per-CPU generator state, so two
clones would emit identical streams — is a pool-level concern that applies
equally to kernel consumers; it is handled by VMGENID generation-change
detection on x86-64 and bounded by the reseed time budget on riscv64 (see
"Whole-VM-snapshot detection").

The subsystem must yield values an attacker cannot predict or reconstruct even
after a later full-state compromise (forward secrecy), and must remain
functional — degraded, not absent — on platforms with no hardware RNG. It is
not a general-purpose KDF; kernel consumers are hardening primitives
(address-space layout randomization, handle/identifier randomization, key/nonce
generation), and userspace consumers draw raw CSPRNG bytes through
`SYS_GETRANDOM`.

The hardware RNG is treated as untrusted until it passes startup health tests
and is **never the sole input** regardless of those tests: its output is always
mixed with timing jitter before any byte is drawn.

## Sources and graceful degradation

Three source classes are mixed into the pool:

- **Firmware boot seed** — a conditioned random draw the bootloader obtains from
  UEFI `EFI_RNG_PROTOCOL` while boot services are live and passes to the kernel
  in `BootInfo` (`boot_entropy_seed` / `boot_entropy_len`, boot protocol v9).
  Arch-neutral mechanism; already conditioned (a DRBG output), so it is absorbed
  directly rather than health-gated. Present only where the firmware implements
  the protocol — x86-64 OVMF does (RDRAND-backed); the current riscv64 EDK2 does
  not, so `boot_entropy_len == 0` there and riscv64 falls back to jitter (see
  "Boot-time entropy").
- **Hardware RNG** — drawn through the `arch::current::entropy` contract
  (`hw_rng_available`, `hw_rng_u64`). On x86-64 this is RDSEED (a conditioned,
  seed-grade source, preferred) with an RDRAND fallback, CPUID-gated, each with
  bounded retry on the transient not-ready condition the ISA permits. Hardware
  output is health-gated (below) before it is trusted. riscv64 has no S-mode
  hardware RNG — the `Zkr` `seed` CSR is M-mode-owned (`mseccfg.SSEED`) — so
  `hw_rng_available` is false there.
- **Timing jitter** — cycle-counter samples (`read_cycle_counter`: TSC on
  x86-64; the `time` CSR on riscv64) taken at distinct interrupt event classes.
  This is the always-available source.

Where a VMGENID device is present (x86-64 under QEMU), the initial 16-byte
generation GUID is additionally absorbed at Phase 5 — with `guid=auto` a free
128-bit host-random boot contribution — and each generation *change* is
absorbed before any post-resume output (below). The GUID is a detection
channel first and a source second; it is never counted on as secret.

With neither a firmware seed nor a hardware RNG the subsystem degrades
gracefully to **jitter only**. The pool and per-CPU generators are otherwise
identical; only the seed material differs.

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
- Both operations exist in blocking and non-spinning forms (`try_absorb`,
  `try_draw_seed`, built on `Spinlock::try_lock_raw`). Mandatory reseeds use
  the blocking forms (short, bounded critical sections); the frequent
  interval/budget reseeds use the try-forms and defer one draw on contention,
  so a tight-loop `getrandom` caller cannot amplify cross-CPU interrupts-off
  tail latency on the pool leaf lock.

Pool storage is a buddy-allocated slab published through an `AtomicPtr`
(`install`); `absorb` is a no-op before installation, so early callers are safe.

## Per-CPU CSPRNG and reseed policy

`entropy::cpurng::CpuRng` is one forward-secure generator per CPU, stored in a
per-CPU slab. Each instance is touched only by its owning CPU under
interrupt-disabled exclusivity, so it carries **no lock**.

The reseed policy is a pure, host-tested decision function
(`entropy::reseed_policy::decide`), evaluated on every fill:

| Trigger | Action |
|---|---|
| Never seeded (first use, or marked stale) | **Mandatory** — blocking reseed before any output |
| VMGENID GUID differs from the one last reseeded under | **Mandatory** |
| Time budget ≥ 2× overdue (`RESEED_TIME_BUDGET_US` × `RESEED_OVERDUE_FACTOR`) | **Mandatory** |
| `RESEED_DRAW_INTERVAL` (256) draws since last reseed | **Opportunistic** — try-lock reseed; defer one draw on contention |
| Time budget (`RESEED_TIME_BUDGET_US`, 1 s) elapsed | **Opportunistic** |
| Otherwise | Draw from current state |

- Each reseed folds that CPU's accumulated jitter into the pool
  (`jitter::collect` — the staging words, the sample count, and the
  instantaneous cycle counter, so every contribution carries fresh timing),
  draws `RESEED_BYTES` (32 — a 256-bit reseed) of fresh seed material, and
  absorbs it; the seed buffer is then zeroed. A mandatory reseed triggered by
  a GUID change additionally absorbs the new GUID into the pool first.
- The draw interval bounds how much output depends on any single seed without
  making the reseed cost (a pool lock plus permutations) a per-draw expense;
  the time budget bounds it in wall-clock terms and is the riscv64
  snapshot-resume bound (below). The 2× escalation keeps the budget a hard
  bound even under sustained pool-lock contention.
- The uncalibrated-timer case (`elapsed_us` not yet available) disables only
  the time-budget triggers; first-use and draw-interval policy still apply.

Forward secrecy *across* draws is provided by the sponge's per-fill erasure;
reseeding additionally bounds the blast radius of any single seed.

## Whole-VM-snapshot detection (VMGENID)

A resumed VM snapshot replays the entire kernel state — pool and per-CPU
generators included — so two clones resumed from one snapshot would emit
identical streams until something distinguishes them. The VM Generation ID is
the hypervisor's detection channel: a 16-byte GUID in guest RAM, rewritten
(with the vCPUs paused, before any of them runs again) whenever the VM's
execution history forks.

- **Discovery** is bootloader-side and QEMU-specific: the VMGENID SSDT's
  `VGIA` named DWORD holds the linker-patched `etc/vmgenid_guid` blob base;
  the GUID sits 40 bytes in. There is no AML interpreter anywhere in the tree,
  so the generic (AML `ADDR`-evaluating) discovery path is out of scope. The
  address reaches the kernel as `BootInfo.vmgenid_paddr` (boot protocol v13;
  zero = absent).
- **Detection** is per-draw and per-CPU (`entropy::vmgenid`): each generator
  records the GUID it last reseeded under, and every fill volatile-reads the
  live GUID through the direct map and compares. Because the hypervisor
  rewrites the GUID before any vCPU resumes, every post-resume draw on every
  CPU sees the change *before producing output* and performs a mandatory
  reseed that absorbs the new GUID — so clone streams diverge by construction,
  even under identical post-resume jitter. There is no cross-CPU detection
  state: the GUID in guest RAM is the shared authority.
- **Observability**: the BSP timer tick polls the same GUID and prints
  `entropy: VM generation change detected` once per change. The reseed
  guarantee never depends on this poll.
- **riscv64 residual**: QEMU's riscv64 `virt` machine has no VMGENID, so
  detection stays disarmed there and the reseed **time budget** is the bound:
  a resumed clone can emit from replayed generator state for at most
  `RESEED_TIME_BUDGET_US` (opportunistic) to 2× that (hard) of guest time per
  CPU, and post-window divergence relies on accrued timing jitter differing
  across clones — two clones resumed simultaneously may collide within that
  window. No firmware detection channel exists on riscv64 QEMU/EDK2 today;
  this residual is accepted and bounded, not hidden.

## Boot-time entropy

At boot, runtime jitter has not yet accumulated. `seed_pool_from_sources` mixes:

1. The firmware boot seed where the bootloader supplied one, absorbed directly
   (it is already conditioned).
2. The hardware RNG where present, drawn under a fresh health monitor up to a
   bounded number of words (margin for RDSEED retries), absorbed only while the
   source has not failed.
3. A boot jitter scrape: cycle-counter samples taken across intervening pool
   work, whose microarchitectural timing perturbs successive reads.

The **boot-entropy hole** is the residual weakness when the only source is
jitter: the initial seed is then weaker than at steady state. The firmware boot
seed closes it wherever UEFI `EFI_RNG_PROTOCOL` is available: x86-64 OVMF
implements it today. The current riscv64 EDK2 does **not** expose it, so riscv64
still falls back to jitter only — narrowed continuously at runtime by the
timer-tick jitter hook, which feeds a fresh sample into each CPU's accumulator
on every tick (and per device IRQ). Closing the riscv64 boot hole therefore
needs the firmware/boot environment to provide a seed (RNG protocol or DT
`rng-seed`); that firmware provisioning is tracked separately.

The first *consumer* draw is decoupled from the boot scrape: the Phase 5/8
self-test capture is each generator's first draw and necessarily seeds from
the boot-time pool (scrape-dominated on riscv64), so the capture is followed
by marking the generator stale (`CpuRng::mark_stale`). The first real
consumer draw — Phase 9 ASLR on the BSP, typically seconds later — then
performs a mandatory reseed carrying the tick/IRQ jitter accrued in between,
rather than riding the 64-sample scrape.

The riscv64 *runtime* hardware-RNG path — a virtio-rng/hwrng device owned by a
userspace driver, the mechanism the RISC-V design intends for lower privilege
levels to obtain entropy — is also future work, tracked separately.

TODO: persist a saved seed across boots (read at `init_storage`, rewritten at
shutdown) as a second mitigation for jitter-only platforms; deferred — it
requires a storage-stack dependency the kernel does not have at Phase 4.

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

These tests gate the *raw* hardware RNG only. The firmware boot seed is a
pre-conditioned DRBG output (`EFI_RNG_PROTOCOL`), so it is absorbed directly and
is not subject to the raw-source tests.

## Draw API and consumers

The kernel-internal draw API is `entropy::fill_bytes(out: &mut [u8])`: it fills
`out` with CSPRNG bytes from the **calling CPU's** generator. `entropy::next_u32`
is a convenience wrapper returning a random `u32`. Interrupts are disabled for the
draw to pin the CPU and bar ISR reentry, giving exclusive, migration-free access
to that generator. It MUST NOT be called from interrupt context (it takes
non-reentrant per-CPU state) or before the pool is seeded.

Kernel-internal production consumers are the structural-unguessability hardening
(#248) — the CSpace recycling epoch (`cap::free_cspace_id`) and thread-id
correlators (`sched::alloc_thread_id`) draw via `next_u32` — and ASLR (#39):
`mm::address_space::choose_init_layout` draws init's `InitInfo` VA and stack
placement via `fill_bytes` on its first call, and Phase 9's PIE rebase draws
init's image load bias the same way (both Phase 9, boot thread). All run after
Phase 5 seeding and never in interrupt context. Userspace ASLR (the
per-process bootstrap-layout, image-bias, heap-base, and reservation-arena
draws in procmgr/init/`std::sys::seraph`) consumes the same generators through
`SYS_GETRANDOM`. On riscv64 the pool currently seeds from timing jitter alone
(#393), so those draws carry the boot-entropy-hole caveat above until a hardware
source lands. The boot self-test is the API's continuous validator.

## Boot wiring and lifecycle

- **Phase 4** (`init_storage`): allocate the per-CPU generators, the pool, the
  per-CPU jitter accumulators, and the self-test sample slab from the buddy
  allocator — alongside the scheduler slabs and for the same reason: before the
  user-capability drain, while the buddy still holds large contiguous blocks.
- **Phase 5** (`init`, BSP): seed the pool from all sources, arm VMGENID
  detection (`vmgenid::init`, absorbing the initial GUID) before the pool is
  marked seeded — so no draw ever precedes snapshot detection — capture the
  BSP's self-test sample, and mark its generator stale.
- **Phase 8** (`init_ap`, each AP): capture that AP's self-test sample (the
  AP's generator seeds lazily from the already-seeded pool on that first
  draw), then mark it stale.
- **Post-SMP** (`selftest::run`, BSP): run the power-on self-test across all
  CPUs.
- **Runtime**: the scheduler timer tick and device-IRQ dispatch feed jitter
  samples into the per-CPU accumulators; the BSP tick additionally runs the
  VMGENID observability poll.

## Testing

- **Host known-answer and property tests** (`cargo xtask test`): the
  Keccak-f[1600] zero-state vector; the NIST `SHAKE256("")` FIPS-202 vector and
  a multi-block squeeze; sponge determinism, seed-sensitivity, fill advancement,
  and forward-secrecy erasure; health-test cutoffs and stuck/biased-source
  trips; the full reseed-policy decision matrix (boundaries included); and the
  bootloader's VGIA scanner. The permutation, sponge, and reseed policy are
  pure and host-testable; the pool, per-CPU generators, jitter, VMGENID
  consumer, and draw API are hardware-coupled and built only for the kernel
  target.
- **In-kernel power-on self-test**: each CPU captures a sample from its own
  generator as it comes online; after SMP bringup the BSP asserts every sample
  is non-trivial, samples are pairwise distinct (per-CPU independence), and the
  aggregate bit balance is sane. The result prints as `entropy: SELFTEST PASS`
  or `entropy: SELFTEST FAIL`; the FAIL marker is matched by the run-parallel
  fail-regex, turning a QEMU run red on either architecture. Validated on
  x86_64 (firmware-seeded — `entropy: seeded from firmware RNG` — since OVMF
  implements `EFI_RNG_PROTOCOL`) and riscv64 (jitter-only — its current EDK2
  exposes no RNG protocol).
- **Guest reseed coverage**: ktest's
  `entropy::getrandom_reseed_interval_stream` streams 300 draws across the
  256-draw interval on both architectures; svctest's `random-contention`
  phase drives four concurrent draw threads through repeated interval
  reseeds, exercising the non-spinning defer path under SMP.
- **Snapshot-resume test** (`cargo xtask test-vmgenid`, x86_64): boots with a
  fixed generation GUID, saves the guest via QMP migrate-to-file, restores it
  under a different GUID with `-incoming`, and asserts the kernel's
  `entropy: VM generation change detected` line plus a post-resume
  interactive liveness round. See `docs/testing.md`.

---

## Summarized By

[Kernel](../README.md)
