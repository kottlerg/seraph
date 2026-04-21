// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/syscall/ipc.rs

//! IPC syscall handlers — W4.
//!
//! All handlers look up the target capability in the current thread's `CSpace`,
//! call the corresponding IPC kernel function, and enqueue/dequeue threads
//! via the scheduler as needed.
//!
//! Data words (up to `MSG_DATA_WORDS_MAX`) are read from / written to the
//! per-thread IPC buffer page registered via `SYS_IPC_BUFFER_SET`.
//!
//! Capability transfer (W4): up to `MSG_CAP_SLOTS_MAX` capabilities can be moved
//! atomically with each message. See `transfer_caps` for the protocol.

#[cfg(not(test))]
extern crate alloc;

#[cfg(not(test))]
use crate::arch::current::trap_frame::TrapFrame;
#[cfg(not(test))]
use syscall::SyscallError;

#[cfg(not(test))]
use super::{current_tcb, lookup_cap};
#[cfg(not(test))]
use crate::cap::CSpace;
#[cfg(not(test))]
use crate::cap::slot::{CapTag, Rights};
#[cfg(not(test))]
use crate::ipc::message::Message;
#[cfg(not(test))]
use syscall::{MSG_CAP_SLOTS_MAX, MSG_DATA_WORDS_MAX};

// ── IPC buffer helpers ────────────────────────────────────────────────────────

/// Read up to `count` data words from the thread's IPC buffer into `dst`.
///
/// Returns `Err(InvalidArgument)` if the buffer is not registered.
///
/// # Safety
/// `buf` must be a valid user-mode IPC buffer VA or 0. Brackets the access
/// with `user_access_begin`/`user_access_end` to satisfy SMAP (x86-64) /
/// SUM (RISC-V).
#[cfg(not(test))]
unsafe fn read_ipc_buf(
    buf: u64,
    count: usize,
    dst: &mut [u64; MSG_DATA_WORDS_MAX],
) -> Result<(), SyscallError>
{
    if buf == 0
    {
        return Err(SyscallError::InvalidArgument);
    }
    // cast_possible_truncation: Seraph targets 64-bit only; usize == u64 on all supported targets.
    #[allow(clippy::cast_possible_truncation)]
    let ptr = buf as *const u64;
    // SAFETY: buf validated non-zero and user-mapped by caller; SMAP/SUM enabled.
    unsafe {
        crate::arch::current::cpu::user_access_begin();
        for (i, item) in dst.iter_mut().enumerate().take(count)
        {
            // SAFETY: buf is page-aligned and user-mapped; count <= MSG_DATA_WORDS_MAX.
            *item = core::ptr::read_volatile(ptr.add(i));
        }
        // SAFETY: paired with user_access_begin above; clears AC flag.
        crate::arch::current::cpu::user_access_end();
    }
    Ok(())
}

/// Write up to `count` data words from `src` to the thread's IPC buffer.
///
/// Silently skips if buffer is not registered (caller may not want data).
///
/// # Safety
/// `buf` must be a valid user-mode IPC buffer VA or 0. Brackets the access
/// with `user_access_begin`/`user_access_end` to satisfy SMAP / SUM.
#[cfg(not(test))]
unsafe fn write_ipc_buf(buf: u64, count: usize, src: &[u64; MSG_DATA_WORDS_MAX])
{
    if buf == 0 || count == 0
    {
        return;
    }
    // cast_possible_truncation: Seraph targets 64-bit only; usize == u64 on all supported targets.
    #[allow(clippy::cast_possible_truncation)]
    let ptr = buf as *mut u64;
    // SAFETY: buf validated non-zero and user-mapped by caller; SMAP/SUM enabled.
    unsafe {
        crate::arch::current::cpu::user_access_begin();
        for (i, item) in src.iter().enumerate().take(count)
        {
            // SAFETY: buf is page-aligned and user-mapped; count <= MSG_DATA_WORDS_MAX.
            core::ptr::write_volatile(ptr.add(i), *item);
        }
        // SAFETY: paired with user_access_begin above; clears AC flag.
        crate::arch::current::cpu::user_access_end();
    }
}

/// Write cap transfer results to the receiver's IPC buffer.
///
/// Layout starting at word `MSG_DATA_WORDS_MAX`:
/// ```text
/// word[MSG_DATA_WORDS_MAX + 0] = cap_count as u64
/// word[MSG_DATA_WORDS_MAX + 1] = idx[0] as u64
/// word[MSG_DATA_WORDS_MAX + 2] = idx[1] as u64
/// ...
/// ```
///
/// Silently skips if `buf == 0`. Matches the layout in `shared/syscall`
/// `read_recv_caps`.
///
/// # Safety
/// `buf` must be a valid, mapped IPC buffer page VA, or 0.
#[cfg(not(test))]
unsafe fn write_cap_results(buf: u64, cap_count: usize, indices: &[u32; MSG_CAP_SLOTS_MAX])
{
    if buf == 0
    {
        return;
    }
    // Always write the cap_count word, even when 0: stale values from a prior
    // IPC round would otherwise be read by `read_recv_caps` and mismatch the
    // declared cap count, tripping `debug_assert_eq!` on the caller side.
    // cast_possible_truncation: Seraph targets 64-bit only; usize == u64 on all supported targets.
    #[allow(clippy::cast_possible_truncation)]
    let ptr = buf as *mut u64;
    // SAFETY: IPC buffer is at least 4 KiB; MSG_DATA_WORDS_MAX + 1 + MSG_CAP_SLOTS_MAX
    // words = at most 11 words = 88 bytes, well within the page. Brackets the
    // access with user_access_begin/end to satisfy SMAP (x86-64) / SUM (RISC-V).
    unsafe {
        crate::arch::current::cpu::user_access_begin();
        core::ptr::write_volatile(ptr.add(MSG_DATA_WORDS_MAX), cap_count as u64);
        for (i, &idx) in indices.iter().enumerate().take(cap_count)
        {
            core::ptr::write_volatile(ptr.add(MSG_DATA_WORDS_MAX + 1 + i), u64::from(idx));
        }
        crate::arch::current::cpu::user_access_end();
    }
}

// ── Capability transfer ───────────────────────────────────────────────────────

/// Unpack `count` slot indices from a packed u64 (4 × u16).
///
/// Matches the encoding in `shared/syscall::pack_cap_slots`.
#[cfg(not(test))]
fn unpack_cap_slots(packed: u64, count: usize) -> [u32; MSG_CAP_SLOTS_MAX]
{
    let mut out = [0u32; MSG_CAP_SLOTS_MAX];
    for (i, item) in out
        .iter_mut()
        .enumerate()
        .take(count.min(MSG_CAP_SLOTS_MAX))
    {
        *item = ((packed >> (i * 16)) & 0xFFFF) as u32;
    }
    out
}

/// Move `src_slots[..cap_count]` from `src_cspace` to `dst_cspace`.
///
/// All-or-nothing: if any slot is null/invalid or the destination is full
/// (`pre_allocate` fails), returns an error and no caps are transferred.
///
/// On success, writes the destination slot indices to `dst_indices_out` and
/// returns the number of caps transferred. The caller is responsible for
/// writing the results to the appropriate IPC buffer.
///
/// # Safety
/// `src_cspace` and `dst_cspace` must be valid live `CSpace` pointers.
///
/// # To add rollback on mid-transfer failure
/// Collect successfully-moved destination indices and call
/// `move_cap_between_cspaces` in reverse on failure. Currently the
/// pre-validation + pre-allocation pattern makes mid-transfer failure
/// unreachable in practice.
#[cfg(not(test))]
unsafe fn transfer_caps(
    src_cspace: *mut CSpace,
    src_slots: &[u32],
    dst_cspace: *mut CSpace,
    dst_indices_out: &mut [u32; MSG_CAP_SLOTS_MAX],
) -> Result<usize, SyscallError>
{
    let cap_count = src_slots.len().min(MSG_CAP_SLOTS_MAX);
    if cap_count == 0
    {
        return Ok(0);
    }

    // Pre-validate: all source slots must be non-null.
    {
        // SAFETY: src_cspace validated by caller.
        let cs = unsafe { &*src_cspace };
        for &idx in &src_slots[..cap_count]
        {
            let slot = cs.slot(idx).ok_or(SyscallError::InvalidCapability)?;
            if slot.tag == CapTag::Null
            {
                return Err(SyscallError::InvalidCapability);
            }
        }
    }

    // Pre-allocate destination slots to avoid OOM mid-transfer.
    // SAFETY: dst_cspace validated by caller.
    unsafe { (*dst_cspace).pre_allocate(cap_count) }.map_err(|_| SyscallError::OutOfMemory)?;

    // Acquire derivation lock for the batch move.
    crate::cap::DERIVATION_LOCK.write_lock();

    // Lock both CSpaces in pointer address order to prevent deadlock when two
    // threads transfer caps between the same pair of CSpaces concurrently.
    // SAFETY: Locking in deterministic order (lower address first) prevents
    // ABBA deadlock. CSpace pointers validated by caller.
    let (saved1, saved2) = unsafe {
        use core::cmp::Ordering;
        match src_cspace.cmp(&dst_cspace)
        {
            Ordering::Less =>
            {
                let s1 = (*src_cspace).lock.lock_raw();
                let s2 = (*dst_cspace).lock.lock_raw();
                (s1, s2)
            }
            Ordering::Greater =>
            {
                let s2 = (*dst_cspace).lock.lock_raw();
                let s1 = (*src_cspace).lock.lock_raw();
                (s1, s2)
            }
            Ordering::Equal =>
            {
                // src_cspace == dst_cspace: same-process IPC, lock once.
                let s = (*src_cspace).lock.lock_raw();
                (s, 0)
            }
        }
    };

    for (i, &src_idx) in src_slots[..cap_count].iter().enumerate()
    {
        // SAFETY: DERIVATION_LOCK and both CSpace locks held; pointers valid.
        dst_indices_out[i] =
            unsafe { crate::cap::move_cap_between_cspaces(src_cspace, src_idx, dst_cspace) }
                .unwrap_or_else(|_| {
                    // Pre-validation passed and pre-allocation succeeded; this branch
                    // is unreachable in correct operation. Panic in debug builds only.
                    debug_assert!(
                        false,
                        "transfer_caps: unexpected move failure after pre-validation"
                    );
                    0
                });
    }

    // Unlock in reverse order of acquisition.
    // SAFETY: saved1 and saved2 came from lock_raw calls above.
    unsafe {
        use core::cmp::Ordering;
        match src_cspace.cmp(&dst_cspace)
        {
            Ordering::Equal =>
            {
                (*src_cspace).lock.unlock_raw(saved1);
            }
            Ordering::Less =>
            {
                (*dst_cspace).lock.unlock_raw(saved2);
                (*src_cspace).lock.unlock_raw(saved1);
            }
            Ordering::Greater =>
            {
                (*src_cspace).lock.unlock_raw(saved1);
                (*dst_cspace).lock.unlock_raw(saved2);
            }
        }
    }

    crate::cap::DERIVATION_LOCK.write_unlock();

    Ok(cap_count)
}

// ── IPC syscall handlers ──────────────────────────────────────────────────────

/// `SYS_IPC_CALL` (0): synchronous call on an endpoint.
///
/// arg0 = endpoint cap index, arg1 = label, arg2 = `data_count`,
/// arg3 = `cap_count` (0-4), arg4 = packed cap slot indices (4 × u16).
///
/// If `cap_count` > 0, the endpoint cap must have `Rights::GRANT`. Capabilities
/// at the specified slots are moved from the caller's `CSpace` to the server's
/// `CSpace` atomically with the message.
///
/// Blocks caller until a server replies. On return, label and data words are
/// in the return registers and IPC buffer. Reply-direction cap indices are
/// written to the IPC buffer at word `MSG_DATA_WORDS_MAX` by the replier.
#[cfg(not(test))]
pub fn sys_ipc_call(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    // cast_possible_truncation: kernel runs on 64-bit only; value is bounded by kernel policy.
    #[allow(clippy::cast_possible_truncation)]
    let ep_idx = tf.arg(0) as u32;
    let label = tf.arg(1);
    // cast_possible_truncation: Seraph targets 64-bit only; usize == u64 on all supported targets.
    #[allow(clippy::cast_possible_truncation)]
    let data_count = (tf.arg(2) as usize).min(MSG_DATA_WORDS_MAX);
    // cast_possible_truncation: Seraph targets 64-bit only; usize == u64 on all supported targets.
    #[allow(clippy::cast_possible_truncation)]
    let cap_count = (tf.arg(3) as usize).min(MSG_CAP_SLOTS_MAX);
    let cap_packed = tf.arg(4);

    // SAFETY: current_tcb() valid from syscall context.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // SAFETY: tcb is valid.
    let cspace_ptr = unsafe { (*tcb).cspace };

    // Determine required rights: SEND always; GRANT additionally when sending caps.
    let required_rights = if cap_count > 0
    {
        Rights::SEND | Rights::GRANT
    }
    else
    {
        Rights::SEND
    };

    // SAFETY: cspace_ptr validated above.
    let slot = unsafe { lookup_cap(cspace_ptr, ep_idx, CapTag::Endpoint, required_rights) }?;
    let caller_token = slot.token;

    // Extract EndpointState pointer from the slot's object.
    // SAFETY: slot.object is a NonNull<KernelObjectHeader> at offset 0 of
    // EndpointObject; EndpointObject.state is valid.
    let ep_state = unsafe {
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?.as_ptr();
        // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
        #[allow(clippy::cast_ptr_alignment)]
        let ep_obj = obj_ptr.cast::<crate::cap::object::EndpointObject>();
        (*ep_obj).state
    };

    let mut msg = Message::new(label);
    msg.token = caller_token;
    msg.data_count = data_count;
    if data_count > 0
    {
        // SAFETY: tcb validated above; ipc_buffer is user-mapped or 0.
        let buf = unsafe { (*tcb).ipc_buffer };
        // SAFETY: buf validated by read_ipc_buf.
        unsafe { read_ipc_buf(buf, data_count, &mut msg.data) }?;
    }

    // Populate cap_slots in the message (indices in caller's CSpace).
    // The actual cap move happens in sys_ipc_recv after delivery.
    if cap_count > 0
    {
        let indices = unpack_cap_slots(cap_packed, cap_count);
        // Pre-validate source slots before blocking (all-or-nothing).
        {
            // SAFETY: cspace_ptr validated above.
            let cs = unsafe { &*cspace_ptr };
            for &idx in indices.iter().take(cap_count)
            {
                let slot = cs.slot(idx).ok_or(SyscallError::InvalidCapability)?;
                if slot.tag == CapTag::Null
                {
                    return Err(SyscallError::InvalidCapability);
                }
            }
        }
        msg.cap_slots = indices;
        msg.cap_count = cap_count;
    }

    // SAFETY: ep_state is valid; scheduler lock not held.
    let result = unsafe { crate::ipc::endpoint::endpoint_call(ep_state, tcb, &msg) };

    if let Ok(woken_server) = result
    {
        // A server was waiting; enqueue it and yield so it can run.
        // SAFETY: woken_server returned by endpoint_call; is valid TCB.
        unsafe {
            debug_assert!((*woken_server).magic == crate::sched::thread::TCB_MAGIC);
            let prio = (*woken_server).priority;
            debug_assert!((prio as usize) < crate::sched::NUM_PRIORITY_LEVELS);
            let target_cpu = crate::sched::select_target_cpu(woken_server);
            debug_assert!(target_cpu < crate::sched::MAX_CPUS);
            crate::sched::enqueue_and_wake(woken_server, target_cpu, prio);
        }
    }
    // else: No server; caller is blocked on send queue. Yield to another thread.

    // Yield CPU — the current thread is now Blocked.
    // SAFETY: scheduler initialized; called from syscall context.
    unsafe {
        crate::sched::schedule(false);
    }

    // On resume (after reply): write reply data and cap results to our IPC
    // buffer. We are now running in the caller's address space, so the VA is
    // valid. Data words and cap result indices were stored in ipc_msg by the
    // replier (sys_ipc_reply + endpoint_reply).
    // SAFETY: tcb still valid after resume; ipc_msg populated by replier.
    let reply_label = unsafe { (*tcb).ipc_msg.label };
    // SAFETY: tcb still valid; ipc_msg.data_count set by replier.
    let reply_count = unsafe { (*tcb).ipc_msg.data_count };
    // SAFETY: tcb still valid; ipc_buffer is immutable after thread creation.
    let reply_buf = unsafe { (*tcb).ipc_buffer };

    if reply_count > 0
    {
        // SAFETY: tcb validated; data field populated by replier.
        let data = unsafe { (*tcb).ipc_msg.data };
        // SAFETY: reply_buf is user-mapped in our address space.
        unsafe {
            write_ipc_buf(reply_buf, reply_count, &data);
        }
    }

    // Write cap transfer results (destination slot indices) to IPC buffer.
    // SAFETY: tcb validated; cap_count/cap_slots set by sys_ipc_reply.
    let reply_cap_count = unsafe { (*tcb).ipc_msg.cap_count };
    // SAFETY: tcb validated; cap_slots populated by sys_ipc_reply.
    let reply_cap_indices = unsafe { (*tcb).ipc_msg.cap_slots };
    // SAFETY: reply_buf is user-mapped in our address space.
    unsafe {
        write_cap_results(reply_buf, reply_cap_count, &reply_cap_indices);
    }

    tf.set_ipc_return(0, reply_label);
    Ok(0) // primary return; set_ipc_return already wrote both values
}

/// `SYS_IPC_RECV` (2): receive the next message on an endpoint.
///
/// arg0 = endpoint cap index.
///
/// Blocks server until a caller sends. On return, the message label and data
/// words are available in return registers and the server's IPC buffer.
/// If the message carried capabilities, their new slot indices in the server's
/// `CSpace` are written to the IPC buffer at word `MSG_DATA_WORDS_MAX`.
#[cfg(not(test))]
pub fn sys_ipc_recv(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    // cast_possible_truncation: kernel runs on 64-bit only; value is bounded by kernel policy.
    #[allow(clippy::cast_possible_truncation)]
    let ep_idx = tf.arg(0) as u32;

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let cspace_ptr = unsafe { (*tcb).cspace };
    // SAFETY: cspace_ptr validated above.
    let slot = unsafe { lookup_cap(cspace_ptr, ep_idx, CapTag::Endpoint, Rights::RECEIVE) }?;

    // SAFETY: slot validated; object pointer is valid Endpoint.
    let ep_state = unsafe {
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?.as_ptr();
        // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
        #[allow(clippy::cast_ptr_alignment)]
        let ep_obj = obj_ptr.cast::<crate::cap::object::EndpointObject>();
        (*ep_obj).state
    };

    // SAFETY: ep_state extracted from validated Endpoint object; scheduler lock not held.
    let result = unsafe { crate::ipc::endpoint::endpoint_recv(ep_state, tcb) };

    if let Ok((caller, msg)) = result
    {
        // A caller was waiting; deliver message immediately.
        // SAFETY: tcb validated above.
        let server_buf = unsafe { (*tcb).ipc_buffer };

        // Transfer caps from caller to server (if any).
        // On failure: all-or-nothing — return error. Caller stays blocked
        // on reply (TODO: for robustness, re-enqueue caller on send queue).
        if msg.cap_count > 0
        {
            // SAFETY: caller returned by endpoint_recv; is valid TCB.
            let caller_cspace = unsafe { (*caller).cspace };
            // SAFETY: tcb validated above.
            let server_cspace = unsafe { (*tcb).cspace };
            let mut dst_indices = [0u32; MSG_CAP_SLOTS_MAX];
            // SAFETY: CSpace pointers extracted from valid TCBs.
            let transferred = unsafe {
                transfer_caps(
                    caller_cspace,
                    &msg.cap_slots[..msg.cap_count],
                    server_cspace,
                    &mut dst_indices,
                )
            }?;
            // Write cap results to server's IPC buffer (server is current
            // thread, so its address space is active).
            // SAFETY: server_buf is user-mapped or 0.
            unsafe {
                write_cap_results(server_buf, transferred, &dst_indices);
            }
        }

        if msg.data_count > 0
        {
            // SAFETY: server_buf is user-mapped or 0.
            unsafe {
                write_ipc_buf(server_buf, msg.data_count, &msg.data);
            }
        }
        tf.set_ipc_return_with_token(0, msg.label, msg.token);
        return Ok(0);
    }
    // else: No caller; server is now Blocked on recv queue. Yield.

    // SAFETY: scheduler initialized; called from syscall context.
    unsafe {
        crate::sched::schedule(false);
    }

    // On resume (caller arrived), deliver message from ipc_msg.
    // SAFETY: tcb validated above; ipc_msg populated by endpoint_recv on wakeup.
    let msg = unsafe { (*tcb).ipc_msg };
    // SAFETY: tcb validated above; ipc_buffer is immutable.
    let server_buf = unsafe { (*tcb).ipc_buffer };

    if msg.cap_count > 0
    {
        // SAFETY: tcb validated; reply_tcb set by endpoint_recv to caller's TCB.
        let caller = unsafe { (*tcb).reply_tcb };
        // SAFETY: caller is valid TCB from reply_tcb.
        let caller_cspace = unsafe { (*caller).cspace };
        // SAFETY: tcb validated above.
        let server_cspace = unsafe { (*tcb).cspace };
        let mut dst_indices = [0u32; MSG_CAP_SLOTS_MAX];
        // On failure: deliver message data without caps (cap_count=0 in buf).
        // The caller stays blocked awaiting a reply; the server receives an
        // incomplete message but is not crashed.
        // SAFETY: CSpace pointers extracted from valid TCBs.
        if let Ok(transferred) = unsafe {
            transfer_caps(
                caller_cspace,
                &msg.cap_slots[..msg.cap_count],
                server_cspace,
                &mut dst_indices,
            )
        }
        {
            // Write cap results to server's IPC buffer (server is current
            // thread, so its address space is active).
            // SAFETY: server_buf is user-mapped or 0.
            unsafe {
                write_cap_results(server_buf, transferred, &dst_indices);
            }
        }
    }

    if msg.data_count > 0
    {
        // SAFETY: server_buf is user-mapped or 0.
        unsafe {
            write_ipc_buf(server_buf, msg.data_count, &msg.data);
        }
    }
    tf.set_ipc_return_with_token(0, msg.label, msg.token);
    Ok(0)
}

/// `SYS_IPC_REPLY` (1): reply to a blocked caller.
///
/// arg0 = label, arg1 = `data_count`,
/// arg2 = `cap_count` (0-4), arg3 = packed cap slot indices (4 × u16).
///
/// Capabilities are moved from the server's `CSpace` to the caller's `CSpace`
/// atomically with the reply. No GRANT right check: the server is trusted
/// by virtue of holding RECEIVE on the endpoint.
#[cfg(not(test))]
pub fn sys_ipc_reply(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    let label = tf.arg(0);
    // cast_possible_truncation: Seraph targets 64-bit only; usize == u64 on all supported targets.
    #[allow(clippy::cast_possible_truncation)]
    let data_count = (tf.arg(1) as usize).min(MSG_DATA_WORDS_MAX);
    // cast_possible_truncation: Seraph targets 64-bit only; usize == u64 on all supported targets.
    #[allow(clippy::cast_possible_truncation)]
    let cap_count = (tf.arg(2) as usize).min(MSG_CAP_SLOTS_MAX);
    let cap_packed = tf.arg(3);

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    let mut msg = Message::new(label);
    msg.data_count = data_count;
    if data_count > 0
    {
        // SAFETY: tcb validated above; ipc_buffer is user-mapped or 0.
        let buf = unsafe { (*tcb).ipc_buffer };
        // SAFETY: buf validated by read_ipc_buf.
        unsafe { read_ipc_buf(buf, data_count, &mut msg.data) }?;
    }

    // Populate cap_slots (indices in server's CSpace). Pre-validate before reply.
    if cap_count > 0
    {
        // SAFETY: tcb validated above.
        let server_cspace = unsafe { (*tcb).cspace };
        let indices = unpack_cap_slots(cap_packed, cap_count);
        {
            // SAFETY: server_cspace extracted from validated TCB.
            let cs = unsafe { &*server_cspace };
            for &idx in indices.iter().take(cap_count)
            {
                let slot = cs.slot(idx).ok_or(SyscallError::InvalidCapability)?;
                if slot.tag == CapTag::Null
                {
                    return Err(SyscallError::InvalidCapability);
                }
            }
        }
        msg.cap_slots = indices;
        msg.cap_count = cap_count;
    }

    // SAFETY: tcb validated above; endpoint_reply operates on reply_tcb field.
    let result = unsafe { crate::ipc::endpoint::endpoint_reply(tcb, &msg) };

    match result
    {
        Some(caller) =>
        {
            // Transfer caps from server to caller (if any).
            // Cap result indices are stored in the caller's ipc_msg so that
            // sys_ipc_call can write them to the caller's IPC buffer when the
            // caller resumes in its own address space.
            if cap_count > 0
            {
                // SAFETY: tcb validated above.
                let server_cspace = unsafe { (*tcb).cspace };
                // SAFETY: caller returned by endpoint_reply; is valid TCB.
                let caller_cspace = unsafe { (*caller).cspace };
                let mut dst_indices = [0u32; MSG_CAP_SLOTS_MAX];
                // SAFETY: CSpace pointers extracted from valid TCBs.
                let transferred = unsafe {
                    transfer_caps(
                        server_cspace,
                        &msg.cap_slots[..cap_count],
                        caller_cspace,
                        &mut dst_indices,
                    )
                }?;
                // Store cap results in caller's TCB for deferred IPC buffer write.
                // SAFETY: caller is valid TCB returned by endpoint_reply.
                unsafe {
                    (*caller).ipc_msg.cap_slots = dst_indices;
                    (*caller).ipc_msg.cap_count = transferred;
                }
            }

            // Data words are already in caller's ipc_msg (set by endpoint_reply).
            // sys_ipc_call will write them to the caller's IPC buffer on resume.

            // Re-enqueue caller (it is now Ready).
            // SAFETY: caller returned by endpoint_reply; is valid TCB.
            unsafe {
                debug_assert!((*caller).magic == crate::sched::thread::TCB_MAGIC);
                let prio = (*caller).priority;
                debug_assert!((prio as usize) < crate::sched::NUM_PRIORITY_LEVELS);
                let target_cpu = crate::sched::select_target_cpu(caller);
                debug_assert!(target_cpu < crate::sched::MAX_CPUS);
                crate::sched::enqueue_and_wake(caller, target_cpu, prio);
            }
            Ok(0)
        }
        None => Err(SyscallError::InvalidCapability),
    }
}

/// `SYS_SIGNAL_SEND` (3): OR bits into a signal object.
///
/// arg0 = signal cap index, arg1 = bits to send (must be non-zero).
#[cfg(not(test))]
pub fn sys_signal_send(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    // cast_possible_truncation: kernel runs on 64-bit only; value is bounded by kernel policy.
    #[allow(clippy::cast_possible_truncation)]
    let sig_idx = tf.arg(0) as u32;
    let bits = tf.arg(1);

    if bits == 0
    {
        return Err(SyscallError::InvalidArgument);
    }

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let cspace_ptr = unsafe { (*tcb).cspace };
    // SAFETY: cspace_ptr validated above.
    let slot = unsafe { lookup_cap(cspace_ptr, sig_idx, CapTag::Signal, Rights::SIGNAL) }?;

    // SAFETY: slot validated; object pointer is valid Signal.
    let sig_state = unsafe {
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?.as_ptr();
        // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
        #[allow(clippy::cast_ptr_alignment)]
        let sig_obj = obj_ptr.cast::<crate::cap::object::SignalObject>();
        (*sig_obj).state
    };

    // SAFETY: sig_state extracted from validated Signal object.
    let woken = unsafe { crate::ipc::signal::signal_send(sig_state, bits) };

    if let Some(waiter) = woken
    {
        // SAFETY: waiter returned by signal_send; is valid TCB.
        unsafe {
            debug_assert!(
                (*waiter).magic == crate::sched::thread::TCB_MAGIC,
                "sys_signal_send: woken waiter magic corrupt"
            );
            let prio = (*waiter).priority;
            debug_assert!(
                (prio as usize) < crate::sched::NUM_PRIORITY_LEVELS,
                "sys_signal_send: waiter priority {prio} out of range"
            );
            let target_cpu = crate::sched::select_target_cpu(waiter);
            debug_assert!(
                target_cpu < crate::sched::MAX_CPUS,
                "sys_signal_send: target_cpu {target_cpu} out of range"
            );
            crate::sched::enqueue_and_wake(waiter, target_cpu, prio);
        }
    }

    Ok(0)
}

/// `SYS_SIGNAL_WAIT` (4): block until a signal bit is set, then return the bits.
///
/// arg0 = signal cap index.
/// arg1 = `timeout_ms`. `0` blocks indefinitely (original behaviour). `> 0`
///        blocks until bits are delivered *or* `timeout_ms` milliseconds
///        have elapsed. On timeout the syscall returns `0` — unambiguous
///        because `signal_send` rejects zero-bit sends.
///
/// Returns the acquired bitmask in rax/a0 (0 = timeout).
#[cfg(not(test))]
pub fn sys_signal_wait(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    // cast_possible_truncation: kernel runs on 64-bit only; value is bounded by kernel policy.
    #[allow(clippy::cast_possible_truncation)]
    let sig_idx = tf.arg(0) as u32;
    let timeout_ms = tf.arg(1);

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let cspace_ptr = unsafe { (*tcb).cspace };
    // SAFETY: cspace_ptr validated above.
    let slot = unsafe { lookup_cap(cspace_ptr, sig_idx, CapTag::Signal, Rights::WAIT) }?;

    // SAFETY: slot validated; object pointer is valid Signal.
    let sig_state = unsafe {
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?.as_ptr();
        // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
        #[allow(clippy::cast_ptr_alignment)]
        let sig_obj = obj_ptr.cast::<crate::cap::object::SignalObject>();
        (*sig_obj).state
    };

    // SAFETY: sig_state extracted from validated Signal object.
    let result = unsafe { crate::ipc::signal::signal_wait(sig_state, tcb) };

    if let Ok(bits) = result
    {
        // Bits were already set; return immediately.
        return Ok(bits);
    }

    // No bits; thread is Blocked on the signal. For a timed wait we also
    // register in the sleep list so the timer tick wakes us if no signal
    // arrives. Arbitration between signal_send and the timer path is done
    // in `sleep_check_wakeups` (see there).
    if timeout_ms != 0
    {
        let tps = crate::arch::current::timer::ticks_per_second();
        let now = crate::arch::current::timer::current_tick();
        let deadline = now.saturating_add(timeout_ms.saturating_mul(tps) / 1000);
        // SAFETY: tcb valid; thread already Blocked above.
        unsafe {
            (*tcb).sleep_deadline = deadline;
        }
        crate::sched::sleep_list_add(tcb);
    }

    // Yield CPU.
    // SAFETY: scheduler initialized; called from syscall context.
    unsafe {
        crate::sched::schedule(false);
    }

    // On resume, either `signal_send` stored delivered bits in wakeup_value,
    // or the timer path cleared wakeup_value to 0 (timeout). Both paths
    // clear `sleep_deadline` as part of claiming the wake.
    // SAFETY: tcb still valid after resume; wakeup_value set by the waker.
    let bits = unsafe { (*tcb).wakeup_value };
    // SAFETY: tcb validated above.
    unsafe {
        (*tcb).wakeup_value = 0;
    }
    Ok(bits)
}

// ── Event Queue handlers ──────────────────────────────────────────────────────

/// `SYS_EVENT_POST` (5): append a payload word to an event queue (non-blocking).
///
/// arg0 = event queue cap index (must have POST right).
/// arg1 = payload word to enqueue.
///
/// Returns `SyscallError::QueueFull` if the queue is at capacity.
/// Returns `SyscallError::InvalidArgument` if bits == 0 is not a constraint
/// (any u64 payload including 0 is valid for event queues).
#[cfg(not(test))]
pub fn sys_event_post(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    // cast_possible_truncation: kernel runs on 64-bit only; value is bounded by kernel policy.
    #[allow(clippy::cast_possible_truncation)]
    let eq_idx = tf.arg(0) as u32;
    let payload = tf.arg(1);

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let cspace_ptr = unsafe { (*tcb).cspace };
    // SAFETY: cspace_ptr validated above.
    let slot = unsafe { lookup_cap(cspace_ptr, eq_idx, CapTag::EventQueue, Rights::POST) }?;

    // SAFETY: slot validated; object pointer is valid EventQueue.
    let eq_state = unsafe {
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?.as_ptr();
        // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
        #[allow(clippy::cast_ptr_alignment)]
        let eq_obj = obj_ptr.cast::<crate::cap::object::EventQueueObject>();
        (*eq_obj).state
    };

    // SAFETY: eq_state extracted from validated EventQueue object.
    let result = unsafe { crate::ipc::event_queue::event_queue_post(eq_state, payload) };

    match result
    {
        Ok(Some(woken)) =>
        {
            // A waiter was woken; enqueue it.
            // SAFETY: woken returned by event_queue_post; is valid TCB.
            unsafe {
                debug_assert!((*woken).magic == crate::sched::thread::TCB_MAGIC);
                let prio = (*woken).priority;
                debug_assert!((prio as usize) < crate::sched::NUM_PRIORITY_LEVELS);
                let target_cpu = crate::sched::select_target_cpu(woken);
                debug_assert!(target_cpu < crate::sched::MAX_CPUS);
                crate::sched::enqueue_and_wake(woken, target_cpu, prio);
            }
            Ok(0)
        }
        Ok(None) => Ok(0),
        Err(()) => Err(SyscallError::QueueFull),
    }
}

/// `SYS_EVENT_RECV` (6): dequeue the next entry from an event queue.
///
/// arg0 = event queue cap index (must have RECV right).
/// arg1 = non-blocking flag: `0` = block (wait until an entry is posted,
///        the pre-timeout behaviour); `1` = try once and return
///        `WouldBlock` if the queue is empty.
///
/// On success returns `0` in rax/a0 and the payload in the secondary return
/// register (rdx/a1). A timed-wait variant may be added on the same syscall
/// later; for now only block / try-once are exposed.
#[cfg(not(test))]
pub fn sys_event_recv(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    // cast_possible_truncation: kernel runs on 64-bit only; value is bounded by kernel policy.
    #[allow(clippy::cast_possible_truncation)]
    let eq_idx = tf.arg(0) as u32;
    let nonblocking = tf.arg(1) != 0;

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let cspace_ptr = unsafe { (*tcb).cspace };
    // SAFETY: cspace_ptr validated above.
    let slot = unsafe { lookup_cap(cspace_ptr, eq_idx, CapTag::EventQueue, Rights::RECV) }?;

    // SAFETY: slot validated; object pointer is valid EventQueue.
    let eq_state = unsafe {
        let obj_ptr = slot.object.ok_or(SyscallError::InvalidCapability)?.as_ptr();
        // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
        #[allow(clippy::cast_ptr_alignment)]
        let eq_obj = obj_ptr.cast::<crate::cap::object::EventQueueObject>();
        (*eq_obj).state
    };

    // SAFETY: eq_state extracted from validated EventQueue object.
    let result = unsafe { crate::ipc::event_queue::event_queue_recv(eq_state, tcb) };

    if let Ok(payload) = result
    {
        // Entry available immediately; deliver payload in secondary register.
        tf.set_ipc_return(0, payload);
        return Ok(0);
    }

    // Queue was empty; `event_queue_recv` has parked `tcb` (state = Blocked,
    // eq.waiter = tcb). In non-blocking mode we roll that back and return
    // `WouldBlock` instead of yielding.
    if nonblocking
    {
        // SAFETY: tcb parked above; eq_state still valid. Single-threaded
        // procmgr-style callers invoke this between scheduler ticks; no
        // concurrent post can race with this rollback against this eq
        // because we were just written as the sole waiter.
        unsafe {
            (*eq_state).waiter = core::ptr::null_mut();
            (*tcb).state = crate::sched::thread::ThreadState::Ready;
            (*tcb).ipc_state = crate::sched::thread::IpcThreadState::None;
            (*tcb).blocked_on_object = core::ptr::null_mut();
        }
        return Err(SyscallError::WouldBlock);
    }

    // Blocking case (arg1 == 0): yield CPU.
    // SAFETY: scheduler initialized; called from syscall context.
    unsafe {
        crate::sched::schedule(false);
    }

    // On resume, event_queue_post stored the payload in wakeup_value.
    // SAFETY: tcb still valid after resume; wakeup_value set by event_queue_post.
    let payload = unsafe { (*tcb).wakeup_value };
    // SAFETY: tcb validated above.
    unsafe {
        (*tcb).wakeup_value = 0;
    }
    tf.set_ipc_return(0, payload);
    Ok(0)
}

// ── Wait Set handlers ─────────────────────────────────────────────────────────

/// `SYS_WAIT_SET_ADD` (26): register a source in a wait set.
///
/// arg0 = wait set cap index (must have MODIFY right).
/// arg1 = source cap index (Endpoint with RECEIVE, Signal with WAIT, or
///        `EventQueue` with RECV).
/// arg2 = caller-chosen opaque u64 token (returned by `SYS_WAIT_SET_WAIT`
///        when this source fires).
///
/// Returns `SyscallError::InvalidArgument` if the wait set is full
/// or the source is already registered in a wait set.
// too_many_lines: this function performs a single logical operation (cap resolution + wait set
// registration) that requires dispatching over three source types; splitting it would
// obscure the all-or-nothing atomicity contract.
#[cfg(not(test))]
#[allow(clippy::too_many_lines)]
pub fn sys_wait_set_add(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::ipc::wait_set::WaitSetSourceTag;

    // cast_possible_truncation: kernel runs on 64-bit only; value is bounded by kernel policy.
    #[allow(clippy::cast_possible_truncation)]
    let ws_idx = tf.arg(0) as u32;
    // cast_possible_truncation: kernel runs on 64-bit only; value is bounded by kernel policy.
    #[allow(clippy::cast_possible_truncation)]
    let src_idx = tf.arg(1) as u32;
    let token = tf.arg(2);

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let cspace_ptr = unsafe { (*tcb).cspace };

    // Look up wait set cap.
    // SAFETY: cspace_ptr validated above.
    let ws_slot = unsafe { lookup_cap(cspace_ptr, ws_idx, CapTag::WaitSet, Rights::MODIFY) }?;
    // SAFETY: ws_slot validated; object pointer is valid WaitSet.
    let ws_state = unsafe {
        let obj_ptr = ws_slot
            .object
            .ok_or(SyscallError::InvalidCapability)?
            .as_ptr();
        // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
        #[allow(clippy::cast_ptr_alignment)]
        let ws_obj = obj_ptr.cast::<crate::cap::object::WaitSetObject>();
        (*ws_obj).state
    };

    // Look up source cap — accept Endpoint, Signal, or EventQueue.
    // We must accept any of the three tags, so we read the slot directly
    // instead of calling lookup_cap (which checks a single expected tag).
    // SAFETY: cspace_ptr validated above.
    let (source_ptr, source_tag) = unsafe {
        let cs = &*cspace_ptr;
        let src_slot = cs.slot(src_idx).ok_or(SyscallError::InvalidCapability)?;
        match src_slot.tag
        {
            CapTag::Endpoint =>
            {
                if !src_slot.rights.contains(Rights::RECEIVE)
                {
                    return Err(SyscallError::InsufficientRights);
                }
                let obj_ptr = src_slot
                    .object
                    .ok_or(SyscallError::InvalidCapability)?
                    .as_ptr();
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let ep_obj = obj_ptr.cast::<crate::cap::object::EndpointObject>();
                let ep_state = (*ep_obj).state.cast::<u8>();
                (ep_state, WaitSetSourceTag::Endpoint)
            }
            CapTag::Signal =>
            {
                if !src_slot.rights.contains(Rights::WAIT)
                {
                    return Err(SyscallError::InsufficientRights);
                }
                let obj_ptr = src_slot
                    .object
                    .ok_or(SyscallError::InvalidCapability)?
                    .as_ptr();
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let sig_obj = obj_ptr.cast::<crate::cap::object::SignalObject>();
                let sig_state = (*sig_obj).state.cast::<u8>();
                (sig_state, WaitSetSourceTag::Signal)
            }
            CapTag::EventQueue =>
            {
                if !src_slot.rights.contains(Rights::RECV)
                {
                    return Err(SyscallError::InsufficientRights);
                }
                let obj_ptr = src_slot
                    .object
                    .ok_or(SyscallError::InvalidCapability)?
                    .as_ptr();
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let eq_obj = obj_ptr.cast::<crate::cap::object::EventQueueObject>();
                let eq_state = (*eq_obj).state.cast::<u8>();
                (eq_state, WaitSetSourceTag::EventQueue)
            }
            _ => return Err(SyscallError::InvalidCapability),
        }
    };

    // Check the source is not already in a wait set (single wait set invariant).
    // The `wait_set` field is at the same offset for all three source types.
    // We check it by reading the field directly based on the tag.
    // SAFETY: source_ptr extracted from validated cap; tag determines object layout.
    let already_registered = unsafe {
        match source_tag
        {
            WaitSetSourceTag::Endpoint =>
            {
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let ep = source_ptr.cast::<crate::ipc::endpoint::EndpointState>();
                !(*ep).wait_set.is_null()
            }
            WaitSetSourceTag::Signal =>
            {
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let sig = source_ptr.cast::<crate::ipc::signal::SignalState>();
                !(*sig).wait_set.is_null()
            }
            WaitSetSourceTag::EventQueue =>
            {
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let eq = source_ptr.cast::<crate::ipc::event_queue::EventQueueState>();
                !(*eq).wait_set.is_null()
            }
        }
    };
    if already_registered
    {
        return Err(SyscallError::InvalidArgument);
    }

    // Register in the wait set.
    // SAFETY: ws_state, source_ptr valid; scheduler lock not held.
    let member_idx =
        unsafe { crate::ipc::wait_set::waitset_add(ws_state, source_ptr, source_tag, token) }
            .map_err(|()| SyscallError::InvalidArgument)?;

    // Write back-pointer on the source.
    // SAFETY: source_ptr extracted from validated cap; member_idx from waitset_add.
    unsafe {
        match source_tag
        {
            WaitSetSourceTag::Endpoint =>
            {
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let ep = source_ptr.cast::<crate::ipc::endpoint::EndpointState>();
                (*ep).wait_set = ws_state.cast::<u8>();
                (*ep).wait_set_member_idx = member_idx;
            }
            WaitSetSourceTag::Signal =>
            {
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let sig = source_ptr.cast::<crate::ipc::signal::SignalState>();
                (*sig).wait_set = ws_state.cast::<u8>();
                (*sig).wait_set_member_idx = member_idx;
                (*sig)
                    .has_observer
                    .store(1, core::sync::atomic::Ordering::Relaxed);
            }
            WaitSetSourceTag::EventQueue =>
            {
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let eq = source_ptr.cast::<crate::ipc::event_queue::EventQueueState>();
                (*eq).wait_set = ws_state.cast::<u8>();
                (*eq).wait_set_member_idx = member_idx;
            }
        }
    }

    Ok(0)
}

/// `SYS_WAIT_SET_REMOVE` (27): unregister a source from a wait set.
///
/// arg0 = wait set cap index (must have MODIFY right).
/// arg1 = source cap index (same cap used to add).
///
/// Clears the back-pointer on the source. Stale entries for the removed
/// member are silently skipped by subsequent `SYS_WAIT_SET_WAIT` calls.
#[cfg(not(test))]
pub fn sys_wait_set_remove(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::ipc::wait_set::WaitSetSourceTag;

    // cast_possible_truncation: kernel runs on 64-bit only; value is bounded by kernel policy.
    #[allow(clippy::cast_possible_truncation)]
    let ws_idx = tf.arg(0) as u32;
    // cast_possible_truncation: kernel runs on 64-bit only; value is bounded by kernel policy.
    #[allow(clippy::cast_possible_truncation)]
    let src_idx = tf.arg(1) as u32;

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let cspace_ptr = unsafe { (*tcb).cspace };

    // Look up wait set.
    // SAFETY: cspace_ptr validated above.
    let ws_slot = unsafe { lookup_cap(cspace_ptr, ws_idx, CapTag::WaitSet, Rights::MODIFY) }?;
    // SAFETY: ws_slot validated; object pointer is valid WaitSet.
    let ws_state = unsafe {
        let obj_ptr = ws_slot
            .object
            .ok_or(SyscallError::InvalidCapability)?
            .as_ptr();
        // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
        #[allow(clippy::cast_ptr_alignment)]
        let ws_obj = obj_ptr.cast::<crate::cap::object::WaitSetObject>();
        (*ws_obj).state
    };

    // Look up source to get its raw state pointer.
    // SAFETY: cspace_ptr validated above.
    let (source_ptr, source_tag) = unsafe {
        let cs = &*cspace_ptr;
        let src_slot = cs.slot(src_idx).ok_or(SyscallError::InvalidCapability)?;
        match src_slot.tag
        {
            CapTag::Endpoint =>
            {
                let obj_ptr = src_slot
                    .object
                    .ok_or(SyscallError::InvalidCapability)?
                    .as_ptr();
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let ep_obj = obj_ptr.cast::<crate::cap::object::EndpointObject>();
                ((*ep_obj).state.cast::<u8>(), WaitSetSourceTag::Endpoint)
            }
            CapTag::Signal =>
            {
                let obj_ptr = src_slot
                    .object
                    .ok_or(SyscallError::InvalidCapability)?
                    .as_ptr();
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let sig_obj = obj_ptr.cast::<crate::cap::object::SignalObject>();
                ((*sig_obj).state.cast::<u8>(), WaitSetSourceTag::Signal)
            }
            CapTag::EventQueue =>
            {
                let obj_ptr = src_slot
                    .object
                    .ok_or(SyscallError::InvalidCapability)?
                    .as_ptr();
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let eq_obj = obj_ptr.cast::<crate::cap::object::EventQueueObject>();
                ((*eq_obj).state.cast::<u8>(), WaitSetSourceTag::EventQueue)
            }
            _ => return Err(SyscallError::InvalidCapability),
        }
    };

    // Remove from wait set.
    // SAFETY: ws_state, source_ptr validated above.
    unsafe { crate::ipc::wait_set::waitset_remove(ws_state, source_ptr) }
        .map_err(|()| SyscallError::InvalidCapability)?;

    // Clear source back-pointer.
    // SAFETY: source_ptr extracted from validated cap.
    unsafe {
        match source_tag
        {
            WaitSetSourceTag::Endpoint =>
            {
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let ep = source_ptr.cast::<crate::ipc::endpoint::EndpointState>();
                (*ep).wait_set = core::ptr::null_mut();
                (*ep).wait_set_member_idx = 0;
            }
            WaitSetSourceTag::Signal =>
            {
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let sig = source_ptr.cast::<crate::ipc::signal::SignalState>();
                (*sig).wait_set = core::ptr::null_mut();
                (*sig).wait_set_member_idx = 0;
            }
            WaitSetSourceTag::EventQueue =>
            {
                // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
                #[allow(clippy::cast_ptr_alignment)]
                let eq = source_ptr.cast::<crate::ipc::event_queue::EventQueueState>();
                (*eq).wait_set = core::ptr::null_mut();
                (*eq).wait_set_member_idx = 0;
            }
        }
    }

    Ok(0)
}

/// `SYS_WAIT_SET_WAIT` (28): block until any registered source becomes ready.
///
/// arg0 = wait set cap index (must have WAIT right).
///
/// If a source is already ready (from a prior notification), returns immediately.
/// Otherwise blocks until any member fires. The opaque token chosen at
/// `SYS_WAIT_SET_ADD` time is returned in the secondary return register
/// (rdx on x86-64, a1 on RISC-V). The caller then reads from the identified
/// source normally.
#[cfg(not(test))]
pub fn sys_wait_set_wait(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    // cast_possible_truncation: kernel runs on 64-bit only; value is bounded by kernel policy.
    #[allow(clippy::cast_possible_truncation)]
    let ws_idx = tf.arg(0) as u32;

    // SAFETY: syscall entry ensures current_tcb() returns active thread's TCB.
    let tcb = unsafe { current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above.
    let cspace_ptr = unsafe { (*tcb).cspace };
    // SAFETY: cspace_ptr validated above.
    let ws_slot = unsafe { lookup_cap(cspace_ptr, ws_idx, CapTag::WaitSet, Rights::WAIT) }?;

    // SAFETY: ws_slot validated; object pointer is valid WaitSet.
    let ws_state = unsafe {
        let obj_ptr = ws_slot
            .object
            .ok_or(SyscallError::InvalidCapability)?
            .as_ptr();
        // cast_ptr_alignment: kernel allocator guarantees object alignment; header is at the start of the allocation.
        #[allow(clippy::cast_ptr_alignment)]
        let ws_obj = obj_ptr.cast::<crate::cap::object::WaitSetObject>();
        (*ws_obj).state
    };

    // SAFETY: ws_state valid; scheduler lock not held.
    let result = unsafe { crate::ipc::wait_set::waitset_wait(ws_state, tcb) };

    if let Ok(token) = result
    {
        // A source was already ready; return its token.
        tf.set_ipc_return(0, token);
        return Ok(0);
    }
    // else: No source ready; thread is Blocked. Yield CPU.

    // SAFETY: scheduler initialized; called from syscall context.
    unsafe {
        crate::sched::schedule(false);
    }

    // On resume, waitset_notify stored the token in wakeup_value.
    // SAFETY: tcb still valid after resume; wakeup_value set by waitset_notify.
    let token = unsafe { (*tcb).wakeup_value };
    // SAFETY: tcb validated above; clearing wakeup_value for next wait.
    unsafe {
        (*tcb).wakeup_value = 0;
    }
    tf.set_ipc_return(0, token);
    Ok(0)
}
