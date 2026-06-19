// seraph-overlay: std::sys::random::seraph
//
// Userspace randomness backing for `std::sys::random`: `fill_bytes` (the
// public `std::random` surface) and `hashmap_random_keys` (the per-process
// SipHash keys that seed `RandomState`/`HashMap` against hash-flooding).
//
// Every draw is a `SYS_GETRANDOM` syscall into the kernel entropy pool (see
// `core/kernel/docs/entropy.md`). Userspace holds no generator state: the
// kernel's per-CPU forward-secure CSPRNG advances on each draw, so the surface
// inherits the kernel's forward secrecy and is prediction- and fork/clone-safe
// by construction. The kernel never blocks for entropy — the pool is seeded
// before any userspace process runs — so a well-formed request always fills
// completely.

/// Fill `bytes` with cryptographically-secure random data from the kernel.
///
/// Draws in `MAX_GETRANDOM_LEN`-byte chunks (the kernel's per-call cap) until
/// the buffer is full.
pub fn fill_bytes(bytes: &mut [u8]) {
    for chunk in bytes.chunks_mut(syscall::MAX_GETRANDOM_LEN) {
        match syscall::getrandom(chunk.as_mut_ptr(), chunk.len()) {
            Ok(n) if n as usize == chunk.len() => {}
            // The kernel fills a well-formed in-bounds buffer completely and
            // never blocks once seeded, so a short count or error is a kernel
            // contract violation. Treat it as fatal, matching other platforms
            // that consider getrandom infallible after argument validation.
            _ => panic!("seraph: SYS_GETRANDOM failed on a valid buffer"),
        }
    }
}

/// Two SipHash keys for `RandomState`. Draws 16 bytes and splits them into a
/// pair of native-endian `u64`s.
pub fn hashmap_random_keys() -> (u64, u64) {
    let mut buf = [0u8; 16];
    fill_bytes(&mut buf);
    let k0 = u64::from_ne_bytes(buf[..8].try_into().unwrap());
    let k1 = u64::from_ne_bytes(buf[8..].try_into().unwrap());
    (k0, k1)
}
