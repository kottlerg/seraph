// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/syscall/sysinfo.rs

//! System info and address-space query syscall handlers.
//!
//! # Adding new `SystemInfoType` variants
//! 1. Add the variant to `SystemInfoType` in `abi/syscall/src/lib.rs`.
//! 2. Add a match arm in `sys_system_info` below.
//! 3. Add a userspace wrapper in `shared/syscall/src/lib.rs` if needed.

use crate::arch::current::trap_frame::TrapFrame;
use syscall::SyscallError;

/// `SYS_SYSTEM_INFO` (43): query kernel/system information.
///
/// arg0 = `SystemInfoType` discriminant (u64).
///
/// Returns the queried value as a scalar `u64`. No buffer is required.
/// Returns `InvalidArgument` for unknown discriminants.
#[cfg(not(test))]
pub fn sys_system_info(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    // Match on the raw discriminant rather than converting to the enum —
    // keeps the handler independent of any TryFrom impl and matches the
    // pattern used by other handlers (e.g. cap create).
    match tf.arg(0)
    {
        0 =>
        // KernelVersion — packed (major << 32) | (minor << 16) | patch
        {
            Ok(syscall::KERNEL_VERSION)
        }
        1 =>
        // CpuCount
        {
            let n = crate::sched::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed);
            Ok(u64::from(n))
        }
        2 =>
        // FreeFrames
        {
            let free = crate::mm::with_frame_allocator(|a| a.free_page_count());
            Ok(free as u64)
        }
        3 =>
        // TotalFrames
        {
            let total = crate::mm::with_frame_allocator(|a| a.total_page_count());
            Ok(total as u64)
        }
        4 =>
        // PageSize
        {
            Ok(crate::mm::PAGE_SIZE as u64)
        }
        5 =>
        // BootProtocolVersion
        {
            Ok(u64::from(boot_protocol::BOOT_PROTOCOL_VERSION))
        }
        6 =>
        // ElapsedUs
        {
            Ok(crate::arch::current::timer::elapsed_us().unwrap_or(0))
        }
        _ => Err(SyscallError::InvalidArgument),
    }
}

/// `SYS_ASPACE_QUERY` (41): translate a user virtual address in an address space.
///
/// arg0 = `AddressSpace` cap slot index (must have READ right).
/// arg1 = virtual address to translate (must be 4 KiB-aligned, user range).
///
/// Returns the mapped physical address on success.
/// Returns `InvalidAddress` if the virtual address is not mapped or
/// fails the alignment/range checks.
#[cfg(not(test))]
// cast_possible_truncation: capability slot indices are u32 by ABI contract;
// tf.arg() returns u64 but the upper 32 bits are always zero for slot args.
#[allow(clippy::cast_possible_truncation)]
pub fn sys_aspace_query(tf: &mut TrapFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::AddressSpaceObject;
    use crate::cap::slot::{CapTag, Rights};

    let aspace_idx = tf.arg(0) as u32;
    let virt = tf.arg(1);

    // Virtual address must be page-aligned.
    if virt & 0xFFF != 0
    {
        return Err(SyscallError::InvalidAddress);
    }

    // Virtual address must be in the user half.
    if virt >= 0x0000_8000_0000_0000
    {
        return Err(SyscallError::InvalidAddress);
    }

    // Resolve AddressSpace cap. READ right is required to inspect mappings.
    // SAFETY: current_tcb() returns current thread; syscall context ensures it is set.
    let tcb = unsafe { super::current_tcb() };
    if tcb.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }
    // SAFETY: tcb validated non-null above; cspace field set at thread creation.
    let caller_cspace = unsafe { (*tcb).cspace };

    // SAFETY: caller_cspace is a valid CSpace pointer; lookup_cap validates slot bounds and rights.
    let aspace_slot = unsafe {
        super::lookup_cap(
            caller_cspace,
            aspace_idx,
            CapTag::AddressSpace,
            Rights::READ,
        )
    }?;
    let as_ptr = {
        let obj = aspace_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed AddressSpace; pointer is valid.
        // cast_ptr_alignment: AddressSpaceObject (8-byte) stored behind KernelObjectHeader
        // (4-byte header); Box<AddressSpaceObject> guarantees 8-byte alignment at allocation.
        #[allow(clippy::cast_ptr_alignment)]
        let as_obj = unsafe { &*(obj.as_ptr().cast::<AddressSpaceObject>()) };
        as_obj.address_space
    };
    if as_ptr.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // SAFETY: as_ptr is a valid heap-allocated AddressSpace.
    let aspace = unsafe { &*as_ptr };
    match aspace.query_page(virt)
    {
        Some((phys, _raw_pte)) => Ok(phys),
        None => Err(SyscallError::InvalidAddress),
    }
}
