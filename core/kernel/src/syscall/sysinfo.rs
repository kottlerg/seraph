// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/syscall/sysinfo.rs

//! System info and address-space query syscall handlers.
//!
//! # Adding new `SystemInfoType` variants
//! 1. Add the variant to `SystemInfoType` in `abi/syscall/src/lib.rs`.
//! 2. Add a match arm in `sys_system_info` below, and raise
//!    `SYSTEM_INFO_BOUND` when the new discriminant is at or above it.
//! 3. Add a userspace wrapper in `shared/syscall/src/lib.rs` if needed.

#[cfg(not(test))]
use super::UserFrame;
use syscall::SyscallError;

/// One past the highest `SystemInfoType` discriminant `sys_system_info`
/// answers. A discriminant at or past it is refused before the match.
const SYSTEM_INFO_BOUND: u64 = syscall::SystemInfoType::InstructionCacheSyncs as u64 + 1;

/// `SYS_SYSTEM_INFO` (43): query kernel/system information.
///
/// arg0 = `SystemInfoType` discriminant (u64).
/// arg1 = the stack class for `StackHighWater` (`syscall::STACK_CLASS_*`);
/// ignored by every other discriminant.
///
/// Returns the queried value as a scalar `u64`. No buffer is required.
/// Returns `InvalidArgument` for an unknown discriminant or an unknown
/// `StackHighWater` class, and `NotSupported` for the handoff class when the
/// kernel could not locate the handoff stack.
///
/// A discriminant at or past [`SYSTEM_INFO_BOUND`] is refused before the
/// match, and the match reads it clamped as data (`nospec::mask_index_u64`),
/// so a mispredicted refusal selects arm 0, never a jump-table entry past the
/// table (core/kernel/docs/capability-internals.md § Speculative-Execution
/// Hardening).
#[cfg(not(test))]
pub fn sys_system_info(tf: UserFrame) -> Result<u64, SyscallError>
{
    let kind = tf.arg(0);
    if kind >= SYSTEM_INFO_BOUND
    {
        return Err(SyscallError::InvalidArgument);
    }
    // Match on the raw discriminant rather than converting to the enum —
    // keeps the handler independent of any TryFrom impl.
    match crate::arch::nospec::mask_index_u64(kind, SYSTEM_INFO_BOUND)
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
        // Discriminants 2 and 3 are reserved (see `SystemInfoType`) and fall
        // through to the unknown-discriminant arm below.
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
        7 =>
        // CurrentCpu — CPU index this syscall is running on.
        //
        // Safe to read without locking: `current_cpu()` reads a per-CPU
        // register (gs/tp-based) that is fixed for the duration of a
        // kernel entry, and userspace can be migrated by the scheduler
        // only on a kernel/userspace boundary anyway.
        {
            let cpu = crate::arch::current::cpu::current_cpu();
            Ok(u64::from(cpu))
        }
        8 =>
        // UserVaTop — exclusive top of the user half; fixed per architecture
        // and boot paging mode, a value the ABI already fixes (see
        // `SystemInfoType::UserVaTop`), not a kernel address.
        {
            Ok(crate::mm::user_va_top())
        }
        9 =>
        // StackHighWater — deepest use of the stack class in arg1
        // (`crate::stack_depth::high_water`).
        {
            crate::stack_depth::high_water(tf.arg(1))
        }
        10 =>
        // ThreadRetypeBytes — the debit of one Thread retype, sized at boot
        // from the boot CPU's extended-state area.
        {
            Ok(crate::sched::thread_slot::thread_slot_bytes())
        }
        11 =>
        // LiveCSpaceCount — CSpace registry ids in use, system-wide; a count
        // the ABI fixes as a diagnostic (`SystemInfoType::LiveCSpaceCount`).
        {
            Ok(u64::from(crate::cap::live_cspace_count()))
        }
        12 =>
        // InstructionCacheSyncs — instruction-fetch synchronisations since
        // boot; a count the ABI fixes as a diagnostic
        // (`SystemInfoType::InstructionCacheSyncs`).
        {
            Ok(crate::mm::icache::sync_count())
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
pub fn sys_aspace_query(tf: UserFrame) -> Result<u64, SyscallError>
{
    use crate::cap::object::AddressSpaceObject;
    use crate::cap::slot::AsRights;

    let aspace_idx = tf.arg(0);
    let virt = tf.arg(1);

    // Virtual address must be page-aligned.
    if virt & 0xFFF != 0
    {
        return Err(SyscallError::InvalidAddress);
    }

    // Virtual address must be in the user half. The walk below reads `virt`
    // clamped as data, so a path past a mispredicted refusal walks VA 0, never
    // the kernel half of the root (core/kernel/docs/capability-internals.md
    // § Speculative-Execution Hardening).
    let user_va_top = crate::mm::user_va_top();
    if virt >= user_va_top
    {
        return Err(SyscallError::InvalidAddress);
    }
    let virt = crate::arch::nospec::mask_index_u64(virt, user_va_top);

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
    let aspace_slot = unsafe { super::lookup_cap(caller_cspace, aspace_idx, AsRights::READ) }?;
    let as_ptr = {
        let obj = aspace_slot.object.ok_or(SyscallError::InvalidCapability)?;
        // SAFETY: tag confirmed AddressSpace; pointer is valid.
        let as_obj = unsafe { &*(obj.as_ptr().cast::<AddressSpaceObject>()) };
        as_obj.address_space
    };
    if as_ptr.is_null()
    {
        return Err(SyscallError::InvalidCapability);
    }

    // SAFETY: as_ptr is a valid AddressSpace, in place in its wrapper page.
    let aspace = unsafe { &*as_ptr };
    match aspace.query_page(virt)
    {
        Some((phys, _raw_pte)) => Ok(phys),
        None => Err(SyscallError::InvalidAddress),
    }
}

#[cfg(test)]
mod tests
{
    use super::SYSTEM_INFO_BOUND;
    use syscall::SystemInfoType;

    // Defect guarded: a discriminant added at or past the dispatch bound
    // without raising it would be refused, and a bound left above the
    // discriminants would let a mispredicted refusal index past the match's
    // jump table.
    #[test]
    fn system_info_bound_is_one_past_the_highest_discriminant()
    {
        let kinds = [
            SystemInfoType::KernelVersion,
            SystemInfoType::CpuCount,
            SystemInfoType::PageSize,
            SystemInfoType::BootProtocolVersion,
            SystemInfoType::ElapsedUs,
            SystemInfoType::CurrentCpu,
            SystemInfoType::UserVaTop,
            SystemInfoType::StackHighWater,
            SystemInfoType::ThreadRetypeBytes,
            SystemInfoType::LiveCSpaceCount,
            SystemInfoType::InstructionCacheSyncs,
        ];
        let max = kinds.iter().map(|&k| k as u64).max();
        assert!(kinds.iter().all(|&k| (k as u64) < SYSTEM_INFO_BOUND));
        assert_eq!(max.map(|m| m + 1), Some(SYSTEM_INFO_BOUND));
    }
}
