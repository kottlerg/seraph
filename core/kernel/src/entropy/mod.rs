// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/entropy/mod.rs

//! Kernel entropy subsystem and per-CPU CSPRNG.
//!
//! Provides the kernel-internal source of randomness: a multi-source entropy
//! pool feeding per-CPU forward-secure generators, with a small draw API for
//! in-kernel consumers such as ASLR, handle randomization, and crypto
//! key/nonce generation. A boot-time self-test exercises the draw path on
//! every CPU. The design and threat model are specified in
//! `core/kernel/docs/entropy.md`.
//!
//! Layering:
//! - [`keccak`] — the Keccak-f[1600] permutation (FIPS 202).
//! - [`sponge`] — forward-secure duplex PRNG over the permutation.
//! - [`pool`] — central multi-source entropy pool (seed authority).
//! - [`cpurng`] — per-CPU generators reseeded from the pool.
//! - [`jitter`] — per-CPU interrupt-time jitter accumulator.
//!
//! The permutation and sponge are pure and host-testable; the pool, per-CPU
//! generators, jitter source, and draw API are hardware-coupled and compiled
//! only for the kernel target.

pub mod health;
pub mod keccak;
pub mod sponge;

#[cfg(not(test))]
pub mod cpurng;
#[cfg(not(test))]
pub mod jitter;
#[cfg(not(test))]
pub mod pool;
#[cfg(not(test))]
pub mod selftest;

#[cfg(not(test))]
mod imp
{
    use core::sync::atomic::{AtomicPtr, Ordering};

    use super::cpurng::CpuRng;
    use super::pool;
    use super::sponge::Prng;
    use crate::mm::BuddyAllocator;

    static CPURNG_PTR: AtomicPtr<CpuRng> = AtomicPtr::new(core::ptr::null_mut());

    /// Allocate per-CPU generator storage and the central pool from the buddy
    /// allocator. Phase 4; must precede [`init`]. Called exactly once.
    pub fn init_storage(cpu_count: u32, allocator: &mut BuddyAllocator)
    {
        let n = cpu_count as usize;

        let rng_bytes = n * core::mem::size_of::<CpuRng>();
        let rng_ptr =
            crate::sched::alloc_zeroed_slab::<CpuRng>(rng_bytes, allocator, "ENTROPY_CPURNG");
        // SAFETY: slab covers n slots; CpuRng::new() is const, overwriting the
        // (already valid) zero-fill in place.
        unsafe {
            for cpu in 0..n
            {
                core::ptr::write(rng_ptr.add(cpu), CpuRng::new());
            }
        }
        CPURNG_PTR.store(rng_ptr, Ordering::Release);

        let pool_ptr = crate::sched::alloc_zeroed_slab::<Prng>(
            core::mem::size_of::<Prng>(),
            allocator,
            "ENTROPY_POOL",
        );
        // SAFETY: slab covers one Prng; Prng::new() is const.
        unsafe {
            core::ptr::write(pool_ptr, Prng::new());
        }
        pool::install(pool_ptr);

        super::jitter::init_storage(n, allocator);
        super::selftest::init_storage(n, allocator);
    }

    /// Seed the pool from all available sources and open the draw API. Phase 5,
    /// BSP, after the cycle counter is available. Called exactly once.
    ///
    /// `boot_seed` is the conditioned early-boot seed the bootloader drew from
    /// UEFI `EFI_RNG_PROTOCOL` (empty when the firmware exposed no RNG).
    pub fn init(boot_seed: &[u8])
    {
        seed_pool_from_sources(boot_seed);
        pool::mark_seeded();
        super::selftest::capture(crate::arch::current::cpu::current_cpu() as usize);
    }

    /// Per-AP entry hook (Phase 8). The AP's generator seeds lazily on its
    /// first draw; this captures its self-test sample.
    pub fn init_ap()
    {
        super::selftest::capture(crate::arch::current::cpu::current_cpu() as usize);
    }

    /// Mix every available entropy source into the pool.
    ///
    /// The firmware boot seed (a conditioned `EFI_RNG_PROTOCOL` draw, where the
    /// bootloader supplied one) and the hardware RNG (where present,
    /// health-gated) are mixed *with* boot-time jitter — never trusted alone.
    /// With neither a firmware seed nor a hardware RNG this degrades to jitter
    /// only.
    fn seed_pool_from_sources(boot_seed: &[u8])
    {
        use crate::arch::current::entropy as hw;

        let mut seeded = false;

        // Firmware-provided boot seed: already conditioned (a DRBG output), so
        // absorb it directly rather than through the raw-source health gate
        // (which expects raw samples and a 1024-byte startup run).
        if !boot_seed.is_empty()
        {
            pool::absorb(boot_seed);
            seeded = true;
            crate::kprintln!(
                "entropy: seeded from firmware RNG (boot seed, {} bytes)",
                boot_seed.len()
            );
        }

        let hw_available = hw::hw_rng_available();
        if hw_available
        {
            let mut health = super::health::Health::new();
            let mut words = 0u32;
            // Bounded draw: startup needs 1024 bytes (128 words); the 512 cap
            // bounds the loop (each hw_rng_u64 retries internally), and a None
            // means the source gave up — stop and fall through to jitter.
            for _ in 0..512
            {
                let Some(w) = hw::hw_rng_u64()
                else
                {
                    break;
                };
                health.push_word(w);
                if health.failed()
                {
                    break;
                }
                pool::absorb(&w.to_le_bytes());
                words += 1;
                if health.trusted()
                {
                    break;
                }
            }
            if health.trusted()
            {
                seeded = true;
                crate::kprintln!("entropy: seeded from hardware RNG ({words} words)");
            }
            else
            {
                crate::kprintln!("entropy: hardware RNG not trusted; using jitter only");
            }
        }

        if !seeded && !hw_available
        {
            crate::kprintln!("entropy: no seeded source; using jitter (graceful degradation)");
        }

        boot_jitter_scrape();
    }

    /// Absorb cycle-counter samples taken across intervening pool work. The
    /// microarchitectural timing of each absorb perturbs successive reads — a
    /// weak source, but distinct from the hardware RNG. This is the documented
    /// boot-time entropy hole, narrowed continuously at runtime by the
    /// timer-tick jitter hook.
    fn boot_jitter_scrape()
    {
        for _ in 0..64
        {
            let c = crate::arch::current::entropy::read_cycle_counter();
            pool::absorb(&c.to_le_bytes());
        }
    }

    /// Borrow CPU `cpu`'s generator.
    ///
    /// # Safety
    /// `cpu` must be `< CPU_COUNT` and the caller must hold exclusive,
    /// non-reentrant access to this CPU's generator (interrupts disabled).
    unsafe fn cpu_rng(cpu: usize) -> &'static mut CpuRng
    {
        let base = CPURNG_PTR.load(Ordering::Acquire);
        debug_assert!(!base.is_null(), "entropy draw before init_storage");
        // SAFETY: caller contract — slab sized to CPU_COUNT, exclusive access.
        unsafe { &mut *base.add(cpu) }
    }

    /// Fill `out` with cryptographically-secure random bytes from the calling
    /// CPU's generator.
    ///
    /// Kernel-internal. MUST NOT be called from interrupt context (it takes
    /// non-reentrant per-CPU generator state). Interrupts are disabled for the
    /// draw to guarantee exclusive, migration-free access.
    pub fn fill_bytes(out: &mut [u8])
    {
        debug_assert!(pool::is_seeded(), "entropy draw before pool seeded");
        // SAFETY: kernel context; disabling interrupts pins this CPU and bars
        // ISR reentry, giving exclusive access to its generator for the draw.
        let saved = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
        let cpu = crate::arch::current::cpu::current_cpu() as usize;
        // SAFETY: cpu < CPU_COUNT; exclusivity established above.
        unsafe {
            cpu_rng(cpu).fill(cpu, out);
        }
        // SAFETY: `saved` came from the matching disable above.
        unsafe {
            crate::arch::current::cpu::restore_interrupts(saved);
        }
    }

    /// Draw a uniformly-random `u32` from the calling CPU's generator.
    ///
    /// Convenience over [`fill_bytes`]; shares its contract — kernel-internal,
    /// MUST NOT be called from interrupt context, valid only after the pool is
    /// seeded (Phase 5).
    pub fn next_u32() -> u32
    {
        let mut b = [0u8; 4];
        fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    /// Whether the pool has been seeded and the draw API is open.
    ///
    /// The pool is seeded in Phase 5, before any userspace process exists
    /// (Phase 9), so this is always true on the userspace draw path. The
    /// `SYS_GETRANDOM` handler checks it so the "draw before seeded" invariant
    /// (a debug-assert in [`fill_bytes`], compiled out in release) becomes an
    /// enforced error on the userspace entry point rather than an unchecked draw.
    pub fn is_seeded() -> bool
    {
        pool::is_seeded()
    }
}

#[cfg(not(test))]
pub use imp::{fill_bytes, init, init_ap, init_storage, is_seeded, next_u32};
