// seraph-overlay: std::sys::pipe::seraph
//
// Anonymous shmem-backed pipe for `Stdio::piped()` / `Command::output()`
// and the per-direction backing of `std::io::{stdin, stdout, stderr}` on
// children spawned with piped stdio.
//
// Each pipe is one 4 KiB shmem frame holding a `shmem::SpscHeader` plus
// a power-of-two byte ring, plus two signal caps:
//
//   * data_signal  — writer kicks reader after producing bytes; reader
//                    waits on this when the ring is empty.
//   * space_signal — reader kicks writer after consuming bytes; writer
//                    waits on this when the ring is full.
//
// Each `Pipe` instance represents one end (Reader or Writer). Both ends
// hold caps to all three objects (the same frame and both signals are
// mapped/copied into both processes' CSpaces); read/write logic drives
// the appropriate signal direction. EOF/BrokenPipe is signalled via
// the header's `closed` flag, set on Drop with one final signal kick
// so the surviving peer wakes and observes the flag.
//
// `pipe()` itself returns `Unsupported`: the symmetric upstream
// constructor doesn't fit our two-process model. `Command::spawn` and
// `stdio::stdio_init` build `Pipe` instances directly via
// `Pipe::create_for_child` / `Pipe::attach_from_caps`.

use crate::fmt;
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut};
use crate::os::seraph::{current_ipc_buf, try_startup_info};
use crate::sync::Arc;
use crate::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use shmem::{SharedBuffer, SpscHeader, SpscReader, SpscWriter};

/// Ring data byte capacity. One 4 KiB page = 16-byte header + 4080 bytes
/// data area; largest power of two ≤ 4080 is 2048.
pub const RING_CAPACITY: u32 = 2048;

const PAGE_SIZE: u64 = 0x1000;

// Parent-side ring VA pool. 64 slots × 1 page = 256 KiB. A spawner that
// holds more than 64 outstanding piped children at once must wait for
// some to drop before allocating more — surfaces as `OutOfMemory` from
// `Pipe::create_for_child`. Region picked above the heap (HEAP_MAX =
// 0x8000_0000) and well below the read-only `ProcessInfo` page.
const PARENT_PIPE_REGION_BASE: u64 = 0x0000_7FFF_C000_0000;
const MAX_PIPE_SLOTS: usize = 64;

static PIPE_SLOTS: [AtomicU8; MAX_PIPE_SLOTS] =
    [const { AtomicU8::new(0) }; MAX_PIPE_SLOTS];

fn alloc_parent_va() -> Option<u64> {
    for (i, slot) in PIPE_SLOTS.iter().enumerate() {
        if slot
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return Some(PARENT_PIPE_REGION_BASE + (i as u64) * PAGE_SIZE);
        }
    }
    None
}

fn free_parent_va(va: u64) {
    if va < PARENT_PIPE_REGION_BASE {
        return;
    }
    let off = va - PARENT_PIPE_REGION_BASE;
    let i = (off / PAGE_SIZE) as usize;
    if i < MAX_PIPE_SLOTS {
        PIPE_SLOTS[i].store(0, Ordering::Release);
    }
}

/// Role of a `Pipe` end.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Reader,
    Writer,
}

/// Cap triple for cross-process pipe handoff. Returned by
/// `create_for_child`. Each field is a *derived handoff slot* in the
/// caller's `CSpace` — distinct from the originals the parent-side
/// `Pipe` retains. The kernel transfers handoff slots into procmgr's
/// `CSpace` when they appear in the cap-list of an `ipc_call`, leaving
/// the parent's originals untouched. Callers consume `PipeCaps` by
/// passing it through `CONFIGURE_PIPE`; cap_delete is the kernel's
/// responsibility once the transfer completes (no caller cleanup).
#[derive(Clone, Copy)]
pub struct PipeCaps {
    pub frame: u32,
    pub data_signal: u32,
    pub space_signal: u32,
}

/// One end of a shmem-backed pipe.
///
/// Read and write operations are non-blocking on partial progress and
/// block (via `signal_wait`) only when the ring is empty (reader) or
/// full (writer). EOF / BrokenPipe is observed via the ring header's
/// `closed` flag, set by the peer's `Drop`, OR via the parent-side
/// `peer_dead` flag set by the spawner's death-bridge thread when the
/// peer process exits without running `Drop` (fault, abort).
pub struct Pipe {
    frame_cap: u32,
    ring_vaddr: u64,
    data_signal: u32,
    space_signal: u32,
    role: Role,
    aspace: u32,
    /// True when this end allocated its VA from the parent slot pool
    /// (`alloc_parent_va`). Child-side ends map at fixed per-direction
    /// VAs and clear this bit so Drop does not free a parent slot.
    owns_parent_slot: bool,
    /// Spawner-side abnormal-exit flag, shared with the per-spawn
    /// death-bridge thread. `None` for child-side ends and for
    /// parent-side ends not yet attached to a spawn (the bridge sets
    /// it after the child is constructed). When set, `read` returns
    /// EOF and `write` returns `BrokenPipe` regardless of the ring
    /// header's `closed` flag — covering the abnormal-exit case where
    /// the peer never ran `Pipe::Drop` to mark the ring closed.
    peer_dead: Option<Arc<AtomicBool>>,
}

// SAFETY: Pipe holds raw cap-slot indices and a process-local VA; no
// pointer indirection, no Cell. Send across threads is fine; the SPSC
// header is accessed via atomics.
unsafe impl Send for Pipe {}
// SAFETY: Read/Write traits operate via atomics on the shared header.
// Concurrent reads (or concurrent writes) from the same Pipe end break
// the SPSC invariant — callers (BufReader/BufWriter, ChildStdin/...)
// hold &mut Pipe in practice. Sync is asserted to match upstream Pipe's
// trait surface; misuse is a usage bug, not a soundness hole at the
// type level.
unsafe impl Sync for Pipe {}

impl Pipe {
    fn header(&self) -> &SpscHeader {
        // SAFETY: ring_vaddr points at a frame mapped read-write for the
        // lifetime of this Pipe; layout starts with SpscHeader.
        unsafe { &*(self.ring_vaddr as *const SpscHeader) }
    }

    fn writer(&self) -> SpscWriter<'_> {
        // SAFETY: header at ring_vaddr is initialised; this Pipe holds
        // exclusive access to the writer half (callers honour the SPSC
        // single-writer invariant via &mut on Stdio wrappers).
        unsafe { SpscWriter::from_raw(self.ring_vaddr) }
    }

    fn reader(&self) -> SpscReader<'_> {
        // SAFETY: as above, single-reader half.
        unsafe { SpscReader::from_raw(self.ring_vaddr) }
    }

    /// Allocate a fresh shmem frame + two signals, map the frame at a
    /// parent-side VA, initialise the ring header, and build the
    /// parent-side `Pipe` for `parent_role`. Returns the parent-side
    /// `Pipe` plus the cap triple to install in the child via
    /// `CONFIGURE_PIPE`. Cap delete on the triple is the caller's
    /// responsibility post-handoff (procmgr will cap_copy each into
    /// the child's CSpace).
    pub fn create_for_child(parent_role: Role) -> io::Result<(Pipe, PipeCaps)> {
        let info = try_startup_info().ok_or_else(|| {
            io::Error::other("seraph pipe: startup info not installed")
        })?;
        let memmgr_ep = info.memmgr_endpoint;
        if memmgr_ep == 0 {
            return Err(io::Error::other(
                "seraph pipe: spawning process has no memmgr endpoint",
            ));
        }
        let aspace = info.self_aspace;
        let ipc_buf = current_ipc_buf();
        if ipc_buf.is_null() {
            return Err(io::Error::other(
                "seraph pipe: IPC buffer not registered",
            ));
        }

        let parent_va = alloc_parent_va()
            .ok_or_else(|| io::Error::other("seraph pipe: parent VA pool exhausted"))?;

        // Allocate one shmem page mapped at parent_va in this process.
        let (sb, frames) = SharedBuffer::create(memmgr_ep, aspace, parent_va, 1, ipc_buf)
            .map_err(|_| {
                free_parent_va(parent_va);
                io::Error::other("seraph pipe: SharedBuffer::create failed")
            })?;
        let frame_cap = frames[0];

        // Initialise the ring header in shared memory before either end
        // touches it. SAFETY: parent_va is mapped writable for one page;
        // header lives at offset 0; we are the unique initialiser.
        unsafe {
            SpscHeader::init(parent_va as *mut SpscHeader, RING_CAPACITY);
        }

        let data_signal = match syscall::cap_create_signal() {
            Ok(s) => s,
            Err(_) => {
                drop(sb);
                let _ = syscall::cap_delete(frame_cap);
                free_parent_va(parent_va);
                return Err(io::Error::other(
                    "seraph pipe: cap_create_signal (data) failed",
                ));
            }
        };
        let space_signal = match syscall::cap_create_signal() {
            Ok(s) => s,
            Err(_) => {
                let _ = syscall::cap_delete(data_signal);
                drop(sb);
                let _ = syscall::cap_delete(frame_cap);
                free_parent_va(parent_va);
                return Err(io::Error::other(
                    "seraph pipe: cap_create_signal (space) failed",
                ));
            }
        };

        // SharedBuffer's Drop unmaps; we own the mapping for the
        // lifetime of the parent-side Pipe and want to forget the SB so
        // its Drop does not run. The Pipe's own Drop unmaps explicitly.
        core::mem::forget(sb);

        // Derive handoff copies for the child. The parent's Pipe holds
        // the originals; the kernel transfers the derived slots into
        // procmgr's CSpace when they appear in CONFIGURE_PIPE's
        // cap-list, leaving the originals intact. On any error here we
        // free the originals and the parent VA before returning.
        let frame_handoff = match syscall::cap_derive(frame_cap, syscall::RIGHTS_MAP_RW) {
            Ok(s) => s,
            Err(_) => {
                let _ = syscall::cap_delete(space_signal);
                let _ = syscall::cap_delete(data_signal);
                let _ = syscall::mem_unmap(aspace, parent_va, 1);
                let _ = syscall::cap_delete(frame_cap);
                free_parent_va(parent_va);
                return Err(io::Error::other(
                    "seraph pipe: cap_derive (frame handoff) failed",
                ));
            }
        };
        let data_handoff = match syscall::cap_derive(data_signal, syscall::RIGHTS_ALL) {
            Ok(s) => s,
            Err(_) => {
                let _ = syscall::cap_delete(frame_handoff);
                let _ = syscall::cap_delete(space_signal);
                let _ = syscall::cap_delete(data_signal);
                let _ = syscall::mem_unmap(aspace, parent_va, 1);
                let _ = syscall::cap_delete(frame_cap);
                free_parent_va(parent_va);
                return Err(io::Error::other(
                    "seraph pipe: cap_derive (data handoff) failed",
                ));
            }
        };
        let space_handoff = match syscall::cap_derive(space_signal, syscall::RIGHTS_ALL) {
            Ok(s) => s,
            Err(_) => {
                let _ = syscall::cap_delete(data_handoff);
                let _ = syscall::cap_delete(frame_handoff);
                let _ = syscall::cap_delete(space_signal);
                let _ = syscall::cap_delete(data_signal);
                let _ = syscall::mem_unmap(aspace, parent_va, 1);
                let _ = syscall::cap_delete(frame_cap);
                free_parent_va(parent_va);
                return Err(io::Error::other(
                    "seraph pipe: cap_derive (space handoff) failed",
                ));
            }
        };

        Ok((
            Pipe {
                frame_cap,
                ring_vaddr: parent_va,
                data_signal,
                space_signal,
                role: parent_role,
                aspace,
                owns_parent_slot: true,
                peer_dead: None,
            },
            PipeCaps {
                frame: frame_handoff,
                data_signal: data_handoff,
                space_signal: space_handoff,
            },
        ))
    }

    /// Child-side attach. Maps the frame received from the parent at
    /// `child_va` in `aspace`; assumes the header is already
    /// initialised by the parent. Used by `stdio::stdio_init` once per
    /// piped direction.
    pub fn attach_from_caps(
        frame_cap: u32,
        data_signal: u32,
        space_signal: u32,
        role: Role,
        aspace: u32,
        child_va: u64,
    ) -> io::Result<Pipe> {
        let frames = [frame_cap, 0, 0, 0];
        let sb = SharedBuffer::attach(&frames, 1, aspace, child_va).map_err(|_| {
            io::Error::other("seraph pipe: SharedBuffer::attach failed")
        })?;
        // Same forget-the-SharedBuffer trick: Pipe's Drop unmaps.
        core::mem::forget(sb);
        Ok(Pipe {
            frame_cap,
            ring_vaddr: child_va,
            data_signal,
            space_signal,
            role,
            aspace,
            owns_parent_slot: false,
            peer_dead: None,
        })
    }

    /// Attach a spawner-side abnormal-exit flag. Called by
    /// `Command::spawn` after constructing each parent-side end so the
    /// per-spawn death-bridge thread can flip the flag on child fault
    /// and have the next `read` / `write` see EOF / `BrokenPipe`.
    pub fn set_peer_dead(&mut self, flag: Arc<AtomicBool>) {
        self.peer_dead = Some(flag);
    }

    /// Parent-side `data_signal` cap slot. Exposed for the death-bridge
    /// thread to `signal_send` on, to wake any blocked reader after
    /// `peer_dead` is flipped.
    pub fn data_signal_cap(&self) -> u32 {
        self.data_signal
    }

    /// Parent-side `space_signal` cap slot. Symmetric to
    /// `data_signal_cap`; the bridge kicks this to wake any blocked
    /// writer.
    pub fn space_signal_cap(&self) -> u32 {
        self.space_signal
    }

    /// Snapshot the abnormal-exit flag if attached.
    fn peer_dead(&self) -> bool {
        self.peer_dead
            .as_ref()
            .is_some_and(|f| f.load(Ordering::Acquire))
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        // Pipe ends are not cloneable: each holds unique cap slots whose
        // lifetimes are tied to this end's Drop.
        Err(io::Error::other(
            "seraph pipe: try_clone not supported (each end is unique)",
        ))
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.role != Role::Reader {
            return Err(io::Error::other(
                "seraph pipe: read on non-Reader end",
            ));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let mut reader = self.reader();
            let n = reader.read(buf);
            if n > 0 {
                // Wake any blocked writer that's waiting for space.
                let _ = syscall::signal_send(self.space_signal, 1);
                return Ok(n);
            }
            if self.header().is_closed() {
                // Drain race: peer may have written then marked closed.
                // Re-check ring once after observing closed; if still
                // empty, EOF.
                let mut reader = self.reader();
                let n2 = reader.read(buf);
                if n2 > 0 {
                    let _ = syscall::signal_send(self.space_signal, 1);
                    return Ok(n2);
                }
                return Ok(0);
            }
            if self.peer_dead() {
                // Peer process exited without running `Drop` (fault,
                // abort). Bridge has flipped the flag and kicked our
                // signal; ring may still hold buffered bytes the peer
                // wrote before faulting, but we already drained above.
                return Ok(0);
            }
            if self.data_signal == 0 {
                // No wakeup signal attached — fall back to immediate EOF
                // rather than spin (silent-drop init path).
                return Ok(0);
            }
            // Block until writer kicks the data signal, peer closes,
            // or the death bridge fires.
            let _ = syscall::signal_wait(self.data_signal);
        }
    }

    pub fn read_buf(&self, mut cursor: BorrowedCursor<'_>) -> io::Result<()> {
        let cap = cursor.capacity();
        if cap == 0 {
            return Ok(());
        }
        // Stage into a stack buffer to bridge to byte-slice read.
        let mut tmp = [0u8; 512];
        let len = cap.min(tmp.len());
        let n = self.read(&mut tmp[..len])?;
        cursor.append(&tmp[..n]);
        Ok(())
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        for b in bufs.iter_mut() {
            if !b.is_empty() {
                return self.read(b);
            }
        }
        Ok(0)
    }

    pub fn is_read_vectored(&self) -> bool {
        false
    }

    pub fn read_to_end(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let mut total = 0;
        let mut chunk = [0u8; 512];
        loop {
            let n = self.read(&mut chunk)?;
            if n == 0 {
                return Ok(total);
            }
            buf.extend_from_slice(&chunk[..n]);
            total += n;
        }
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if self.role != Role::Writer {
            return Err(io::Error::other(
                "seraph pipe: write on non-Writer end",
            ));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.header().is_closed() {
                return Err(io::const_error!(
                    io::ErrorKind::BrokenPipe,
                    "seraph pipe: peer closed",
                ));
            }
            if self.peer_dead() {
                return Err(io::const_error!(
                    io::ErrorKind::BrokenPipe,
                    "seraph pipe: peer died abnormally",
                ));
            }
            let mut writer = self.writer();
            let n = writer.write(buf);
            if n > 0 {
                // Wake any blocked reader.
                let _ = syscall::signal_send(self.data_signal, 1);
                return Ok(n);
            }
            if self.space_signal == 0 {
                // No wakeup signal — drop bytes silently to avoid spin.
                return Ok(buf.len());
            }
            // Block until reader kicks the space signal, peer closes,
            // or the death bridge fires.
            let _ = syscall::signal_wait(self.space_signal);
        }
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut total = 0;
        for b in bufs {
            let n = self.write(b)?;
            total += n;
            if n < b.len() {
                break;
            }
        }
        Ok(total)
    }

    pub fn is_write_vectored(&self) -> bool {
        true
    }

    /// Diverging stub for upstream conversions that go through `From<Pipe>
    /// for Stdio` on platforms where the type is uninhabited. Our `Pipe`
    /// is inhabited; this branch is unreachable in practice — keep it
    /// loud so any code path that does land here is obvious in the log.
    pub fn diverge(&self) -> ! {
        panic!("seraph pipe: diverge called on inhabited Pipe");
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        // Closer protocol: mark the ring closed, then send one final
        // signal kick on the *opposite-direction* signal so the peer
        // wakes from any blocking signal_wait and observes the flag.
        self.header().mark_closed();
        match self.role {
            Role::Reader =>
            {
                // Wake writer (it's waiting on space_signal).
                let _ = syscall::signal_send(self.space_signal, 1);
            }
            Role::Writer =>
            {
                // Wake reader (it's waiting on data_signal).
                let _ = syscall::signal_send(self.data_signal, 1);
            }
        }
        // Unmap the ring page from this process's aspace.
        let _ = syscall::mem_unmap(self.aspace, self.ring_vaddr, 1);
        // Release this side's cap slots. The peer's Drop releases its
        // own copies; the underlying kernel objects free when refcount
        // hits zero.
        if self.frame_cap != 0 {
            let _ = syscall::cap_delete(self.frame_cap);
        }
        if self.data_signal != 0 {
            let _ = syscall::cap_delete(self.data_signal);
        }
        if self.space_signal != 0 {
            let _ = syscall::cap_delete(self.space_signal);
        }
        if self.owns_parent_slot {
            free_parent_va(self.ring_vaddr);
        }
    }
}

impl fmt::Debug for Pipe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pipe")
            .field("role", &self.role)
            .field("frame_cap", &self.frame_cap)
            .field("ring_vaddr", &format_args!("{:#x}", self.ring_vaddr))
            .finish()
    }
}

/// Stub for the upstream symmetric pipe constructor. Our pipe model is
/// asymmetric (parent-side reader holds the same frame the child-side
/// writer maps elsewhere), so a single-process `(read, write)` pair is
/// not constructible; callers use [`Pipe::create_for_child`].
#[inline]
pub fn pipe() -> io::Result<(Pipe, Pipe)> {
    Err(io::const_error!(
        io::ErrorKind::Unsupported,
        "seraph pipe: symmetric pipe() unsupported; use create_for_child",
    ))
}
