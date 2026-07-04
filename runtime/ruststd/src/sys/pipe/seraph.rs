// seraph-overlay: std::sys::pipe::seraph
//
// Anonymous shmem-backed pipe for `Stdio::piped()` / `Command::output()`
// and the per-direction backing of `std::io::{stdin, stdout, stderr}` on
// children spawned with piped stdio.
//
// Each pipe is one 4 KiB shmem page holding a `shmem::SpscHeader` plus
// a power-of-two byte ring, plus two notification caps:
//
//   * data_notification  — writer kicks reader after producing bytes; reader
//                    waits on this when the ring is empty.
//   * space_notification — reader kicks writer after consuming bytes; writer
//                    waits on this when the ring is full.
//
// Each `Pipe` instance represents one end (Reader or Writer). Both ends
// hold caps to all three objects (the same memory cap and both notifications
// are mapped/copied into both processes' CSpaces); read/write logic drives
// the appropriate notification direction. EOF/BrokenPipe is notified via
// the header's `closed` flag, set on Drop with one final notification kick
// so the surviving peer wakes and observes the flag. A reader returns EOF
// only after a drain performed AFTER observing `closed` (or the bridge's
// `peer_dead`) comes back empty — the flags are Release-stored after the
// writer's last ring write, so flag-then-drain ordering cannot lose bytes.
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

use crate::sys::reserve::{ReservedRange, reserve_pages, unreserve_pages};
use shmem::{SharedBuffer, SpscHeader, SpscReader, SpscWriter};

/// Ring data byte capacity. One 4 KiB page = 16-byte header + 4080 bytes
/// data area; largest power of two ≤ 4080 is 2048.
pub const RING_CAPACITY: u32 = 2048;

// Ring VAs come from the process's page-reservation arena
// (`sys::reserve::seraph`), so they inherit the arena's per-process
// randomised base (ASLR, #39). The count of outstanding pipe rings is
// bounded only by arena capacity; exhaustion surfaces as `OutOfMemory`
// from `Pipe::create_for_child`.

/// Role of a `Pipe` end.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Reader,
    Writer,
}

/// [`RingRelease`] states. Linear lifecycle: `NO_PEER` until the spawn
/// wires a death bridge (`ARMED`), then whichever of parent-drop /
/// peer-death happens second performs the release (`RELEASED`).
const RING_NO_PEER: u8 = 0;
const RING_ARMED: u8 = 1;
const RING_PARENT_DROPPED: u8 = 2;
const RING_PEER_DEAD: u8 = 3;
const RING_RELEASED: u8 = 4;

/// Exactly-once return of a pipe ring page's memmgr grant.
///
/// The ring page is granted to the spawner via `REQUEST_MEMORY_CAPS` and
/// stays in memmgr's per-process accounting until returned with
/// `RELEASE_MEMORY_CAPS` (named by phys base) or until the spawner dies.
/// Without the return, every piped spawn strands one grant in memmgr;
/// a few hundred spawns by one long-lived process exhaust memmgr's
/// CSpace and wedge every memmgr client system-wide.
///
/// Returning the page is safe only once neither side can write through
/// it: the parent end must be dropped (unmapped, caps deleted) AND the
/// child must be dead (its threads are stopped by death-post time; the
/// child's mapping may outlive that until procmgr's teardown, which
/// memmgr's release contract tolerates) or never wired. `Pipe::Drop`
/// and the spawn's death-bridge thread each report their side's
/// completion here; whichever observes the other side already done
/// gets `true` back and sends the release.
pub struct RingRelease {
    phys: u64,
    state: AtomicU8,
}

impl RingRelease {
    fn new(phys: u64) -> Self {
        Self {
            phys,
            state: AtomicU8::new(RING_NO_PEER),
        }
    }

    /// Ring page physical base, for the `RELEASE_MEMORY_CAPS` sender.
    pub fn phys(&self) -> u64 {
        self.phys
    }

    /// A live child observer now exists; defer release to the two-party
    /// protocol. Called once by `Command::spawn` when wiring the bridge.
    fn arm(&self) {
        let _ = self.state.compare_exchange(
            RING_NO_PEER,
            RING_ARMED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    /// Parent end dropped. Returns `true` when the caller must send the
    /// release now (child already dead, or no child was ever wired).
    fn on_parent_drop(&self) -> bool {
        match self.state.compare_exchange(
            RING_ARMED,
            RING_PARENT_DROPPED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            // Bridge releases when the death event arrives.
            Ok(_) => false,
            // Never armed (spawn failed before bridge wiring) or the
            // child is already dead: this side is last out.
            Err(RING_NO_PEER) | Err(RING_PEER_DEAD) => {
                self.state.store(RING_RELEASED, Ordering::Release);
                true
            }
            Err(_) => false,
        }
    }

    /// Child died (death bridge). Returns `true` when the caller must
    /// send the release now (parent end already dropped).
    pub fn on_peer_death(&self) -> bool {
        match self.state.compare_exchange(
            RING_ARMED,
            RING_PEER_DEAD,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            // Parent's Drop releases.
            Ok(_) => false,
            Err(RING_PARENT_DROPPED) => {
                self.state.store(RING_RELEASED, Ordering::Release);
                true
            }
            Err(_) => false,
        }
    }
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
    pub memory: u32,
    pub data_notification: u32,
    pub space_notification: u32,
}

/// One end of a shmem-backed pipe.
///
/// Read and write operations are non-blocking on partial progress and
/// block (via `notification_wait`) only when the ring is empty (reader) or
/// full (writer). EOF / BrokenPipe is observed via the ring header's
/// `closed` flag, set by the peer's `Drop`, OR via the parent-side
/// `peer_dead` flag set by the spawner's death-bridge thread on every
/// child death (clean exit or fault). Readers drain the ring once more
/// after observing either flag before reporting EOF.
pub struct Pipe {
    memory_cap: u32,
    ring_vaddr: u64,
    data_notification: u32,
    space_notification: u32,
    role: Role,
    aspace: u32,
    /// Reservation-arena range backing `ring_vaddr`, for ends that drew
    /// their ring VA from this process's arena (both `create_for_child`
    /// and `attach_from_caps` ends). Drop unmaps the ring page first,
    /// then returns the range to the arena.
    reserved_va: Option<ReservedRange>,
    /// Spawner-side peer-exit flag, shared with the per-spawn
    /// death-bridge thread. `None` for child-side ends and for
    /// parent-side ends not yet attached to a spawn (the bridge sets
    /// it after the child is constructed). The bridge flips it on
    /// every child death — clean exit included — covering the case
    /// where the peer never ran `Pipe::Drop` to mark the ring closed.
    /// `read` treats it exactly like `closed`: EOF only once a drain
    /// performed after observing the flag comes back empty. `write`
    /// returns `BrokenPipe` on observing it.
    peer_dead: Option<Arc<AtomicBool>>,
    /// Exactly-once return of the ring page's memmgr grant, shared with
    /// the spawn's death-bridge thread. `Some` only on the end that
    /// requested the grant (`create_for_child`); child-side ends map a
    /// page they do not own.
    ring_release: Option<Arc<RingRelease>>,
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
        // SAFETY: ring_vaddr points at a page mapped read-write for the
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

    /// Allocate a fresh shmem page + two notifications, map the page at a
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

        let reserved = reserve_pages(1)
            .map_err(|_| io::Error::other("seraph pipe: parent ring VA reservation failed"))?;
        let parent_va = reserved.va_start();

        // Request one page from memmgr, keeping the phys base so the grant
        // can be returned via RELEASE_MEMORY_CAPS when the pipe ends its
        // life (see `RingRelease`). want_pages=1 returns exactly one cap
        // covering one page.
        let Some((memory_cap, _pages, ring_phys)) =
            crate::sys::alloc::seraph::slab_request_pages(memmgr_ep, 1)
        else {
            unreserve_pages(reserved);
            return Err(io::Error::other(
                "seraph pipe: ring page request failed",
            ));
        };

        // Map the page read-write at parent_va via a derived mapping cap;
        // the original stays clean for the child handoff derivations.
        let map_result = syscall::cap_derive(memory_cap, syscall::RIGHTS_MAP_RW)
            .and_then(|rw| {
                let r = syscall::mem_map(rw, aspace, parent_va, 0, 1, syscall::MAP_WRITABLE);
                let _ = syscall::cap_delete(rw);
                r
            });
        if map_result.is_err() {
            let _ = syscall::cap_delete(memory_cap);
            crate::sys::alloc::seraph::slab_release_fresh(ring_phys);
            unreserve_pages(reserved);
            return Err(io::Error::other("seraph pipe: ring page map failed"));
        }

        // Initialise the ring header in shared memory before either end
        // touches it. SAFETY: parent_va is mapped writable for one page;
        // header lives at offset 0; we are the unique initialiser.
        unsafe {
            SpscHeader::init(parent_va as *mut SpscHeader, RING_CAPACITY);
        }

        // Allocator failure here is rare (memmgr unreachable / OOM); tear
        // down what we have so far before reporting.
        let data_notification = match crate::sys::alloc::seraph::object_slab_retype(120, |slab| {
            syscall::cap_create_notification(slab).ok()
        })
        .ok_or_else(|| io::Error::other("seraph pipe: cap_create_notification (data) failed"))
        {
            Ok(s) => s,
            Err(e) => {
                let _ = syscall::mem_unmap(aspace, parent_va, 1);
                let _ = syscall::cap_delete(memory_cap);
                crate::sys::alloc::seraph::slab_release_fresh(ring_phys);
                unreserve_pages(reserved);
                return Err(e);
            }
        };
        let space_notification = match crate::sys::alloc::seraph::object_slab_retype(120, |slab| {
            syscall::cap_create_notification(slab).ok()
        })
        .ok_or_else(|| io::Error::other("seraph pipe: cap_create_notification (space) failed"))
        {
            Ok(s) => s,
            Err(e) => {
                let _ = syscall::cap_delete(data_notification);
                let _ = syscall::mem_unmap(aspace, parent_va, 1);
                let _ = syscall::cap_delete(memory_cap);
                crate::sys::alloc::seraph::slab_release_fresh(ring_phys);
                unreserve_pages(reserved);
                return Err(e);
            }
        };

        // Derive handoff copies for the child. The parent's Pipe holds
        // the originals; the kernel transfers the derived slots into
        // procmgr's CSpace when they appear in CONFIGURE_PIPE's
        // cap-list, leaving the originals intact. On any error here we
        // free the originals and the parent VA before returning.
        let memory_handoff = match syscall::cap_derive(memory_cap, syscall::RIGHTS_MAP_RW) {
            Ok(s) => s,
            Err(_) => {
                let _ = syscall::cap_delete(space_notification);
                let _ = syscall::cap_delete(data_notification);
                let _ = syscall::mem_unmap(aspace, parent_va, 1);
                let _ = syscall::cap_delete(memory_cap);
                crate::sys::alloc::seraph::slab_release_fresh(ring_phys);
                unreserve_pages(reserved);
                return Err(io::Error::other(
                    "seraph pipe: cap_derive (memory handoff) failed",
                ));
            }
        };
        let data_handoff = match syscall::cap_derive(data_notification, syscall::RIGHTS_ALL) {
            Ok(s) => s,
            Err(_) => {
                let _ = syscall::cap_delete(memory_handoff);
                let _ = syscall::cap_delete(space_notification);
                let _ = syscall::cap_delete(data_notification);
                let _ = syscall::mem_unmap(aspace, parent_va, 1);
                let _ = syscall::cap_delete(memory_cap);
                crate::sys::alloc::seraph::slab_release_fresh(ring_phys);
                unreserve_pages(reserved);
                return Err(io::Error::other(
                    "seraph pipe: cap_derive (data handoff) failed",
                ));
            }
        };
        let space_handoff = match syscall::cap_derive(space_notification, syscall::RIGHTS_ALL) {
            Ok(s) => s,
            Err(_) => {
                let _ = syscall::cap_delete(data_handoff);
                let _ = syscall::cap_delete(memory_handoff);
                let _ = syscall::cap_delete(space_notification);
                let _ = syscall::cap_delete(data_notification);
                let _ = syscall::mem_unmap(aspace, parent_va, 1);
                let _ = syscall::cap_delete(memory_cap);
                crate::sys::alloc::seraph::slab_release_fresh(ring_phys);
                unreserve_pages(reserved);
                return Err(io::Error::other(
                    "seraph pipe: cap_derive (space handoff) failed",
                ));
            }
        };

        Ok((
            Pipe {
                memory_cap,
                ring_vaddr: parent_va,
                data_notification,
                space_notification,
                role: parent_role,
                aspace,
                reserved_va: Some(reserved),
                peer_dead: None,
                ring_release: Some(Arc::new(RingRelease::new(ring_phys))),
            },
            PipeCaps {
                memory: memory_handoff,
                data_notification: data_handoff,
                space_notification: space_handoff,
            },
        ))
    }

    /// Child-side attach. Maps the page received from the parent at the
    /// caller-reserved `reserved` range in `aspace`; assumes the header is
    /// already initialised by the parent. Used by `stdio::stdio_init` once
    /// per piped direction. On failure the reservation is returned to the
    /// arena; on success the `Pipe` owns it and Drop returns it.
    pub fn attach_from_caps(
        memory_cap: u32,
        data_notification: u32,
        space_notification: u32,
        role: Role,
        aspace: u32,
        reserved: ReservedRange,
    ) -> io::Result<Pipe> {
        let child_va = reserved.va_start();
        let memory_caps = [memory_cap, 0, 0, 0];
        match SharedBuffer::attach(&memory_caps, 1, aspace, child_va) {
            // Same forget-the-SharedBuffer trick: Pipe's Drop unmaps.
            Ok(sb) => core::mem::forget(sb),
            Err(_) => {
                unreserve_pages(reserved);
                return Err(io::Error::other("seraph pipe: SharedBuffer::attach failed"));
            }
        }
        Ok(Pipe {
            memory_cap,
            ring_vaddr: child_va,
            data_notification,
            space_notification,
            role,
            aspace,
            reserved_va: Some(reserved),
            peer_dead: None,
            ring_release: None,
        })
    }

    /// Attach a spawner-side abnormal-exit flag. Called by
    /// `Command::spawn` after constructing each parent-side end so the
    /// per-spawn death-bridge thread can flip the flag on child fault
    /// and have the next `read` / `write` see EOF / `BrokenPipe`.
    pub fn set_peer_dead(&mut self, flag: Arc<AtomicBool>) {
        self.peer_dead = Some(flag);
    }

    /// Arm the ring-grant release for the two-party protocol and hand the
    /// shared state to the death bridge. Called by `Command::spawn` when
    /// wiring the bridge, alongside [`set_peer_dead`][Self::set_peer_dead].
    pub fn arm_ring_release(&self) -> Option<Arc<RingRelease>> {
        self.ring_release.as_ref().map(|rr| {
            rr.arm();
            rr.clone()
        })
    }

    /// Spawn-failure path: the child is being destroyed without ever
    /// having run, but the release was already armed for the bridge,
    /// which will exit via the drop sentinel without reporting a death.
    /// Report the peer dead here instead so this end's eventual `Drop`
    /// returns the ring grant.
    pub fn mark_peer_never_ran(&self) {
        if let Some(rr) = &self.ring_release {
            if rr.on_peer_death() {
                crate::sys::alloc::seraph::slab_release_fresh(rr.phys());
            }
        }
    }

    /// Parent-side `data_notification` cap slot. Exposed for the death-bridge
    /// thread to `notification_send` on, to wake any blocked reader after
    /// `peer_dead` is flipped.
    pub fn data_notification_cap(&self) -> u32 {
        self.data_notification
    }

    /// Parent-side `space_notification` cap slot. Symmetric to
    /// `data_notification_cap`; the bridge kicks this to wake any blocked
    /// writer.
    pub fn space_notification_cap(&self) -> u32 {
        self.space_notification
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
            // Order matters: observe the EOF flags BEFORE draining the ring.
            // Each flag is Release-stored after the writer's last ring write
            // (`closed`: peer `Drop`; `peer_dead`: child death -> kernel
            // death post -> bridge), so an empty drain performed after
            // observing a set flag proves the ring is final-empty. The
            // reverse order loses bytes the peer writes between the drain
            // and the flag load.
            let eof = self.header().is_closed() || self.peer_dead();
            let mut reader = self.reader();
            let n = reader.read(buf);
            if n > 0 {
                // Wake any blocked writer that's waiting for space.
                let _ = syscall::notification_send(self.space_notification, 1);
                return Ok(n);
            }
            if eof {
                return Ok(0);
            }
            if self.data_notification == 0 {
                // No wakeup notification attached — fall back to immediate EOF
                // rather than spin (silent-drop init path).
                return Ok(0);
            }
            // Block until writer kicks the data notification, peer closes,
            // or the death bridge fires. A wait error means the notification
            // cap itself is gone (teardown raced us); surface EOF rather
            // than spin on a dead cap.
            if syscall::notification_wait(self.data_notification).is_err() {
                return Ok(0);
            }
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
                let _ = syscall::notification_send(self.data_notification, 1);
                return Ok(n);
            }
            if self.space_notification == 0 {
                // No wakeup notification — drop bytes silently to avoid spin.
                return Ok(buf.len());
            }
            // Block until reader kicks the space notification, peer closes,
            // or the death bridge fires. A wait error means the notification
            // cap itself is gone; report the pipe as broken rather than
            // spin on a dead cap.
            if syscall::notification_wait(self.space_notification).is_err() {
                return Err(io::const_error!(
                    io::ErrorKind::BrokenPipe,
                    "seraph pipe: space notification unavailable",
                ));
            }
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
        // notification kick on the *opposite-direction* notification so the peer
        // wakes from any blocking notification_wait and observes the flag.
        self.header().mark_closed();
        match self.role {
            Role::Reader =>
            {
                // Wake writer (it's waiting on space_notification).
                let _ = syscall::notification_send(self.space_notification, 1);
            }
            Role::Writer =>
            {
                // Wake reader (it's waiting on data_notification).
                let _ = syscall::notification_send(self.data_notification, 1);
            }
        }
        // Unmap the ring page from this process's aspace.
        let _ = syscall::mem_unmap(self.aspace, self.ring_vaddr, 1);
        // Release this side's cap slots. The peer's Drop releases its
        // own copies; the underlying kernel objects free when refcount
        // hits zero.
        if self.memory_cap != 0 {
            let _ = syscall::cap_delete(self.memory_cap);
        }
        if self.data_notification != 0 {
            let _ = syscall::cap_delete(self.data_notification);
        }
        if self.space_notification != 0 {
            let _ = syscall::cap_delete(self.space_notification);
        }
        if let Some(reserved) = self.reserved_va.take() {
            unreserve_pages(reserved);
        }
        // Return the ring page's memmgr grant once the child can no
        // longer touch it. With the mapping and caps above already gone,
        // this side is done; release now if the child is too.
        if let Some(rr) = &self.ring_release {
            if rr.on_parent_drop() {
                crate::sys::alloc::seraph::slab_release_fresh(rr.phys());
            }
        }
    }
}

impl fmt::Debug for Pipe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pipe")
            .field("role", &self.role)
            .field("memory_cap", &self.memory_cap)
            .field("ring_vaddr", &format_args!("{:#x}", self.ring_vaddr))
            .finish()
    }
}

/// Stub for the upstream symmetric pipe constructor. Our pipe model is
/// asymmetric (parent-side reader holds the same memory cap the child-side
/// writer maps elsewhere), so a single-process `(read, write)` pair is
/// not constructible; callers use [`Pipe::create_for_child`].
#[inline]
pub fn pipe() -> io::Result<(Pipe, Pipe)> {
    Err(io::const_error!(
        io::ErrorKind::Unsupported,
        "seraph pipe: symmetric pipe() unsupported; use create_for_child",
    ))
}
