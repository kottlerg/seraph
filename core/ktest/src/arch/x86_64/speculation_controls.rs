// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/speculation_controls.rs

//! Integration (x86-64): the transient-execution controls in effect on every
//! CPU are the controls the kernel selected, and the selection is the one
//! core/kernel/docs/transient-execution.md § Controls states for the inputs
//! the kernel reports.
//!
//! `SYS_SYSTEM_INFO(SpeculationControls)` reports three words: the inputs
//! (the classes the boot CPU's vulnerability table gives kernel action, its
//! two predictor behaviours, and the control bits it enumerates), the controls
//! selected from them at boot, and the controls in effect on the calling CPU,
//! read from that CPU's MSRs and from the flags the entry and exit code test.
//! The case restates the selection rule over the inputs ([`expected`]) and
//! requires the selected word to equal it, so a selection that departs from
//! the design note fails here as well as in the kernel's host tests. It then
//! pins this thread to each CPU in turn and requires the in-effect word there
//! to equal the selected one, so a CPU whose bring-up missed the per-CPU MSR
//! write (`kernel_entry_ap`) fails the case. It logs the inputs and the
//! selection, then the in-effect word: once, after every CPU's equalled the
//! selection, or the first CPU's that differs. The boot log so shows which
//! controls engaged on the machine it ran on: under QEMU
//! TCG the retpoline sequence, and on the development host under KVM
//! enhanced IBRS, `BHI_DIS_S` and `VERW` on exit, or IBRS on entry in place
//! of enhanced IBRS in a kernel built with
//! `SERAPH_FORCE_RETURN_MITIGATION=intel`. IBRS on entry is read in effect from
//! `IA32_SPEC_CTRL` inside the call, after the entry that set it.

use syscall::{speculation_controls, system_info, thread_set_affinity, thread_yield};
use syscall_abi::{
    SPECULATION_CONTROL_AUTO_IBRS, SPECULATION_CONTROL_BHB_CLEAR, SPECULATION_CONTROL_BHI_DIS_S,
    SPECULATION_CONTROL_DOITM, SPECULATION_CONTROL_EIBRS, SPECULATION_CONTROL_IBRS_ENTRY,
    SPECULATION_CONTROL_RETPOLINE, SPECULATION_CONTROL_RSB_FILL_IBPB,
    SPECULATION_CONTROL_RSB_FILL_SWITCH, SPECULATION_CONTROL_VERW_EXIT,
    SPECULATION_CONTROL_VERW_IDLE, SPECULATION_INPUT_AUTO_IBRS, SPECULATION_INPUT_BHI,
    SPECULATION_INPUT_BHI_CTRL, SPECULATION_INPUT_DOITM, SPECULATION_INPUT_IBPB_LEAVES_RSB,
    SPECULATION_INPUT_IBRS, SPECULATION_INPUT_IBRS_ALL, SPECULATION_INPUT_MDS,
    SPECULATION_INPUT_MMIO, SPECULATION_INPUT_RETBLEED, SPECULATION_INPUT_RFDS,
    SPECULATION_INPUT_RSB_ALTERNATE, SPECULATION_INPUT_SPECTRE_V2, SPECULATION_INPUT_TAA,
    SPECULATION_INPUT_TSA, SPECULATION_VIEW_IN_EFFECT, SPECULATION_VIEW_INPUTS,
    SPECULATION_VIEW_SELECTED, SystemInfoType,
};

use crate::{TestContext, TestResult};

/// Yields that may pass before a thread pinned to a CPU runs there: the first
/// yield after the pin migrates it; the bound only keeps a scheduler defect
/// from hanging the case.
const MAX_YIELDS: u32 = 64;

/// The controls core/kernel/docs/transient-execution.md § Controls selects for
/// `inputs`, restated here from the document rather than shared with the
/// kernel's `mitigation::select`.
fn expected(inputs: u64) -> u64
{
    let any = |bits: u64| inputs & bits != 0;
    let mut controls = 0;
    let spectre_v2 = any(SPECULATION_INPUT_SPECTRE_V2);
    let return_fallback = any(SPECULATION_INPUT_RETBLEED) && any(SPECULATION_INPUT_RSB_ALTERNATE);
    if any(SPECULATION_INPUT_IBRS_ALL) && (spectre_v2 || return_fallback)
    {
        controls |= SPECULATION_CONTROL_EIBRS;
    }
    else if return_fallback && any(SPECULATION_INPUT_IBRS)
    {
        controls |= SPECULATION_CONTROL_IBRS_ENTRY;
    }
    else if spectre_v2
    {
        controls |= if any(SPECULATION_INPUT_AUTO_IBRS)
        {
            SPECULATION_CONTROL_AUTO_IBRS
        }
        else
        {
            SPECULATION_CONTROL_RETPOLINE
        };
    }
    if any(SPECULATION_INPUT_BHI)
    {
        controls |= if any(SPECULATION_INPUT_BHI_CTRL)
        {
            SPECULATION_CONTROL_BHI_DIS_S
        }
        else
        {
            SPECULATION_CONTROL_BHB_CLEAR
        };
    }
    if any(SPECULATION_INPUT_MDS
        | SPECULATION_INPUT_TAA
        | SPECULATION_INPUT_MMIO
        | SPECULATION_INPUT_RFDS
        | SPECULATION_INPUT_TSA)
    {
        controls |= SPECULATION_CONTROL_VERW_EXIT;
    }
    if any(SPECULATION_INPUT_MDS | SPECULATION_INPUT_TSA)
    {
        controls |= SPECULATION_CONTROL_VERW_IDLE;
    }
    if controls & SPECULATION_CONTROL_RETPOLINE != 0 && any(SPECULATION_INPUT_RSB_ALTERNATE)
    {
        controls |= SPECULATION_CONTROL_RSB_FILL_SWITCH;
    }
    if any(SPECULATION_INPUT_IBPB_LEAVES_RSB)
    {
        controls |= SPECULATION_CONTROL_RSB_FILL_IBPB;
    }
    if any(SPECULATION_INPUT_DOITM)
    {
        controls |= SPECULATION_CONTROL_DOITM;
    }
    controls
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let inputs = speculation_controls(SPECULATION_VIEW_INPUTS)
        .map_err(|_| "integration::speculation_controls: inputs view failed")?;
    let selected = speculation_controls(SPECULATION_VIEW_SELECTED)
        .map_err(|_| "integration::speculation_controls: selected view failed")?;
    crate::log_args(format_args!(
        "ktest: speculation inputs={inputs:#x} selected={selected:#x}"
    ));
    if selected != expected(inputs)
    {
        return Err("integration::speculation_controls: selection departs from the rule");
    }
    let cpus = system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "integration::speculation_controls: system_info(CpuCount) failed")?;
    let result = every_cpu(ctx, cpus, selected);
    if result.is_ok()
    {
        crate::log_args(format_args!(
            "ktest: speculation in_effect={selected:#x} on all {cpus} CPUs"
        ));
    }
    let restore = thread_set_affinity(ctx.thread_cap, u32::MAX)
        .map_err(|_| "integration::speculation_controls: restore affinity failed");
    result?;
    restore
}

/// Pin this thread to each of the `cpus` CPUs in turn and compare the
/// controls in effect there with `selected`.
fn every_cpu(ctx: &TestContext, cpus: u64, selected: u64) -> TestResult
{
    for cpu in 0..cpus
    {
        let id = u32::try_from(cpu)
            .map_err(|_| "integration::speculation_controls: CPU index past u32")?;
        thread_set_affinity(ctx.thread_cap, id)
            .map_err(|_| "integration::speculation_controls: pin failed")?;
        let on_cpu = || system_info(SystemInfoType::CurrentCpu as u64) == Ok(cpu);
        for _ in 0..MAX_YIELDS
        {
            if on_cpu()
            {
                break;
            }
            thread_yield().map_err(|_| "integration::speculation_controls: yield failed")?;
        }
        if !on_cpu()
        {
            return Err("integration::speculation_controls: thread never ran on its CPU");
        }
        let in_effect = speculation_controls(SPECULATION_VIEW_IN_EFFECT)
            .map_err(|_| "integration::speculation_controls: in-effect view failed")?;
        if in_effect != selected
        {
            crate::log_args(format_args!(
                "ktest: speculation cpu={cpu} in_effect={in_effect:#x} selected={selected:#x}"
            ));
            return Err("integration::speculation_controls: controls in effect differ");
        }
    }
    Ok(())
}
