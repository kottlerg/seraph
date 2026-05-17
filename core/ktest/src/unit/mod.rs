// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/mod.rs

//! Tier 1 — per-syscall isolation tests.
//!
//! Each file in this module covers one logical group of related syscalls
//! (mirroring the kernel's subsystem structure). Every kernel syscall must
//! have at least one test here. Adding a new syscall means adding a section
//! to the appropriate file.
//!
//! Files:
//! - `cap.rs`      — capability creation, copy, move, insert, derive, revoke, delete
//! - `cap_info.rs` — read-only capability state inspection (`SYS_CAP_INFO`)
//! - `mm.rs`       — memory map/unmap/protect, frame split, address space query
//! - `signal.rs`   — signal send and wait
//! - `event.rs`    — event queue post and receive
//! - `wait_set.rs` — wait set add, remove, wait
//! - `ipc.rs`      — IPC call, reply, recv, buffer set
//! - `thread.rs`   — thread lifecycle, register read/write, priority, affinity
//! - `fpu.rs`      — FPU / SIMD / V extended-state isolation across preemption
//! - `hw.rs`       — MMIO, IRQ, I/O ports
//! - `sysinfo.rs`  — system info queries and debug log

pub mod cap;
pub mod cap_info;
pub mod event;
pub mod fpu;
pub mod hw;
pub mod ipc;
pub mod mm;
pub mod retype;
pub mod signal;
pub mod sysinfo;
pub mod thread;
pub mod wait_set;

use crate::TestContext;
use crate::run_test;

/// Run all Tier 1 tests in order.
///
/// To add a new test: implement a `pub fn test_name(ctx: &TestContext) -> TestResult`
/// in the appropriate submodule, then add a `run_test!` call here.
// too_many_lines: run_all is a flat dispatch table; splitting it adds no clarity.
#[allow(clippy::too_many_lines)]
pub fn run_all(ctx: &TestContext)
{
    // ── Capability syscalls ───────────────────────────────────────────────────
    run_test!("cap::create_signal", cap::create_signal(ctx));
    run_test!("cap::create_endpoint", cap::create_endpoint(ctx));
    run_test!("cap::create_event_q", cap::create_event_q(ctx));
    run_test!("cap::create_cspace", cap::create_cspace(ctx));
    run_test!("cap::create_aspace", cap::create_aspace(ctx));
    run_test!("cap::create_thread", cap::create_thread(ctx));
    run_test!("cap::create_wait_set", cap::create_wait_set(ctx));
    run_test!("cap::copy", cap::copy(ctx));
    run_test!("cap::insert", cap::insert(ctx));
    run_test!("cap::move", cap::r#move(ctx));
    run_test!("cap::derive_attenuation", cap::derive_attenuation(ctx));
    run_test!("cap::revoke_invalidates", cap::revoke_invalidates(ctx));
    run_test!("cap::delete", cap::delete(ctx));
    run_test!(
        "cap::insert_to_occupied_slot_err",
        cap::insert_to_occupied_slot_err(ctx)
    );
    run_test!(
        "cap::copy_into_non_cspace_err",
        cap::copy_into_non_cspace_err(ctx)
    );
    run_test!("cap::delete_null_slot_ok", cap::delete_null_slot_ok(ctx));
    run_test!(
        "cap::insert_out_of_bounds_err",
        cap::insert_out_of_bounds_err(ctx)
    );
    run_test!("cap::derive_zero_rights", cap::derive_zero_rights(ctx));
    run_test!("cap::revoke_null_slot_err", cap::revoke_null_slot_err(ctx));
    run_test!(
        "cap::create_event_q_zero_capacity_err",
        cap::create_event_q_zero_capacity_err(ctx)
    );
    run_test!(
        "cap::create_event_q_over_max_err",
        cap::create_event_q_over_max_err(ctx)
    );
    run_test!("cap::derive_token", cap::derive_token(ctx));
    run_test!(
        "cap::derive_token_zero_err",
        cap::derive_token_zero_err(ctx)
    );
    run_test!(
        "cap::derive_token_retoken_err",
        cap::derive_token_retoken_err(ctx)
    );
    run_test!(
        "cap::derive_inherits_token",
        cap::derive_inherits_token(ctx)
    );
    run_test!(
        "cap::derive_token_on_signal",
        cap::derive_token_on_signal(ctx)
    );

    // ── Capability inspection (SYS_CAP_INFO) ──────────────────────────────────
    run_test!(
        "cap_info::tag_rights_aspace",
        cap_info::tag_rights_aspace(ctx)
    );
    run_test!(
        "cap_info::tag_rights_frame",
        cap_info::tag_rights_frame(ctx)
    );
    run_test!(
        "cap_info::tag_rights_signal",
        cap_info::tag_rights_signal(ctx)
    );
    run_test!("cap_info::frame_fields", cap_info::frame_fields(ctx));
    run_test!(
        "cap_info::frame_caps_carry_retype_right",
        cap_info::frame_caps_carry_retype_right(ctx)
    );
    run_test!("cap_info::cspace_fields", cap_info::cspace_fields(ctx));
    run_test!(
        "cap_info::null_slot_invalid",
        cap_info::null_slot_invalid(ctx)
    );
    run_test!(
        "cap_info::tag_mismatch_invalid_arg",
        cap_info::tag_mismatch_invalid_arg(ctx)
    );
    run_test!(
        "cap_info::unknown_field_invalid_arg",
        cap_info::unknown_field_invalid_arg(ctx)
    );

    // ── Retype primitive (augment, budget exhaustion, deep PT walk) ──────────
    run_test!(
        "retype::aspace_augment_grows_budget",
        retype::aspace_augment_grows_budget(ctx)
    );
    run_test!(
        "retype::cspace_augment_grows_budget",
        retype::cspace_augment_grows_budget(ctx)
    );
    run_test!(
        "retype::pt_budget_exhaustion_returns_oom",
        retype::pt_budget_exhaustion_returns_oom(ctx)
    );
    run_test!(
        "retype::deep_pt_walk_consumes_pool",
        retype::deep_pt_walk_consumes_pool(ctx)
    );
    run_test!(
        "retype::cspace_grow_consumes_pool",
        retype::cspace_grow_consumes_pool(ctx)
    );

    // ── Memory management syscalls ────────────────────────────────────────────
    run_test!("mm::frame_split_merge", mm::frame_split_merge(ctx));
    run_test!("mm::mem_map_unmap", mm::mem_map_unmap(ctx));
    run_test!("mm::mem_protect", mm::mem_protect(ctx));
    run_test!(
        "mm::mem_protect_unmapped_err",
        mm::mem_protect_unmapped_err(ctx)
    );
    run_test!("mm::mem_unmap_idempotent", mm::mem_unmap_idempotent(ctx));
    run_test!("mm::aspace_query_mapped", mm::aspace_query_mapped(ctx));
    run_test!(
        "mm::aspace_query_unmapped_err",
        mm::aspace_query_unmapped_err(ctx)
    );
    run_test!(
        "mm::mem_map_unaligned_vaddr_err",
        mm::mem_map_unaligned_vaddr_err(ctx)
    );
    run_test!(
        "mm::mem_map_kernel_half_err",
        mm::mem_map_kernel_half_err(ctx)
    );
    run_test!(
        "mm::frame_split_at_zero_err",
        mm::frame_split_at_zero_err(ctx)
    );
    run_test!(
        "mm::mem_protect_exceeds_cap_rights_err",
        mm::mem_protect_exceeds_cap_rights_err(ctx)
    );
    run_test!("mm::mem_map_multi_page", mm::mem_map_multi_page(ctx));
    run_test!(
        "mm::mem_map_zero_pages_err",
        mm::mem_map_zero_pages_err(ctx)
    );
    run_test!(
        "mm::mem_map_offset_beyond_frame_err",
        mm::mem_map_offset_beyond_frame_err(ctx)
    );
    run_test!(
        "mm::mem_unmap_unaligned_err",
        mm::mem_unmap_unaligned_err(ctx)
    );
    run_test!("mm::mem_protect_wx_err", mm::mem_protect_wx_err(ctx));
    run_test!("mm::mem_map_wx_prot_err", mm::mem_map_wx_prot_err(ctx));
    run_test!(
        "mm::frame_split_at_end_err",
        mm::frame_split_at_end_err(ctx)
    );
    run_test!(
        "mm::init_segment_caps_aligned",
        mm::init_segment_caps_aligned(ctx)
    );

    // ── Signal syscalls ───────────────────────────────────────────────────────
    run_test!("signal::send", signal::send(ctx));
    run_test!(
        "signal::send_wait_blocking",
        signal::send_wait_blocking(ctx)
    );
    run_test!(
        "signal::send_before_wait_immediate",
        signal::send_before_wait_immediate(ctx)
    );
    run_test!(
        "signal::wait_insufficient_rights",
        signal::wait_insufficient_rights(ctx)
    );
    run_test!(
        "signal::multiple_sends_before_wait_accumulate_bits",
        signal::multiple_sends_before_wait_accumulate_bits(ctx)
    );
    run_test!(
        "signal::send_zero_bits_is_noop",
        signal::send_zero_bits_is_noop(ctx)
    );
    run_test!(
        "signal::send_insufficient_rights",
        signal::send_insufficient_rights(ctx)
    );

    // ── Event queue syscalls ──────────────────────────────────────────────────
    run_test!("event::create", event::create(ctx));
    run_test!("event::post_recv_fifo", event::post_recv_fifo(ctx));
    run_test!("event::queue_full_err", event::queue_full_err(ctx));
    run_test!(
        "event::recv_blocks_until_post",
        event::recv_blocks_until_post(ctx)
    );
    run_test!(
        "event::post_insufficient_rights",
        event::post_insufficient_rights(ctx)
    );
    run_test!(
        "event::recv_insufficient_rights",
        event::recv_insufficient_rights(ctx)
    );
    run_test!(
        "event::try_recv_empty_returns_wouldblock",
        event::try_recv_empty_returns_wouldblock(ctx)
    );
    run_test!(
        "event::recv_timeout_fires_on_empty_queue",
        event::recv_timeout_fires_on_empty_queue(ctx)
    );
    run_test!(
        "event::recv_timeout_payload_zero_wins",
        event::recv_timeout_payload_zero_wins(ctx)
    );
    run_test!(
        "event::recv_timeout_payload_nonzero_wins",
        event::recv_timeout_payload_nonzero_wins(ctx)
    );
    run_test!(
        "event::recv_timeout_zero_blocks_forever",
        event::recv_timeout_zero_blocks_forever(ctx)
    );

    // ── Wait set syscalls ─────────────────────────────────────────────────────
    run_test!(
        "wait_set::add_signal_immediate",
        wait_set::add_signal_immediate(ctx)
    );
    run_test!(
        "wait_set::add_queue_immediate",
        wait_set::add_queue_immediate(ctx)
    );
    run_test!("wait_set::blocking_wait", wait_set::blocking_wait(ctx));
    run_test!("wait_set::remove", wait_set::remove(ctx));
    run_test!(
        "wait_set::source_signal_pinned_by_member",
        wait_set::source_signal_pinned_by_member(ctx)
    );
    run_test!(
        "wait_set::source_eventqueue_pinned_by_member",
        wait_set::source_eventqueue_pinned_by_member(ctx)
    );
    run_test!(
        "wait_set::source_endpoint_pinned_by_member",
        wait_set::source_endpoint_pinned_by_member(ctx)
    );

    // ── IPC syscalls ──────────────────────────────────────────────────────────
    run_test!("ipc::call_reply_recv", ipc::call_reply_recv(ctx));
    run_test!(
        "ipc::recv_finds_queued_caller",
        ipc::recv_finds_queued_caller(ctx)
    );
    run_test!(
        "ipc::ipc_buffer_misaligned_err",
        ipc::ipc_buffer_misaligned_err(ctx)
    );
    run_test!(
        "ipc::send_insufficient_rights_err",
        ipc::send_insufficient_rights_err(ctx)
    );
    run_test!("ipc::call_with_data_words", ipc::call_with_data_words(ctx));
    run_test!(
        "ipc::call_with_cap_transfer",
        ipc::call_with_cap_transfer(ctx)
    );
    run_test!("ipc::recv_delivers_token", ipc::recv_delivers_token(ctx));
    run_test!(
        "ipc::recv_untokened_returns_zero",
        ipc::recv_untokened_returns_zero(ctx)
    );
    run_test!(
        "ipc::recv_snapshot_survives_buffer_clobber",
        ipc::recv_snapshot_survives_buffer_clobber(ctx)
    );
    run_test!(
        "ipc::reply_oom_wakes_caller_with_transfer_failed",
        ipc::reply_oom_wakes_caller_with_transfer_failed(ctx)
    );
    run_test!(
        "ipc::recv_oom_returns_cleanly",
        ipc::recv_oom_returns_cleanly(ctx)
    );

    // ── Thread syscalls ───────────────────────────────────────────────────────
    run_test!("thread::configure_start", thread::configure_start(ctx));
    run_test!("thread::yield", thread::r#yield(ctx));
    run_test!("thread::stop_read_regs", thread::stop_read_regs(ctx));
    run_test!(
        "thread::stop_again_invalid_state",
        thread::stop_again_invalid_state(ctx)
    );
    run_test!("thread::write_regs_resume", thread::write_regs_resume(ctx));
    run_test!(
        "thread::set_priority_normal",
        thread::set_priority_normal(ctx)
    );
    run_test!(
        "thread::set_priority_elevated_no_cap_err",
        thread::set_priority_elevated_no_cap_err(ctx)
    );
    run_test!(
        "thread::set_priority_elevated_with_cap",
        thread::set_priority_elevated_with_cap(ctx)
    );
    run_test!(
        "thread::set_affinity_valid",
        thread::set_affinity_valid(ctx)
    );
    run_test!(
        "thread::set_affinity_invalid_err",
        thread::set_affinity_invalid_err(ctx)
    );
    run_test!(
        "thread::configure_running_thread_err",
        thread::configure_running_thread_err(ctx)
    );
    run_test!(
        "thread::set_priority_zero_err",
        thread::set_priority_zero_err(ctx)
    );
    run_test!(
        "thread::set_priority_31_err",
        thread::set_priority_31_err(ctx)
    );
    run_test!(
        "thread::affinity_bind_cpu1",
        thread::affinity_bind_cpu1(ctx)
    );
    run_test!(
        "thread::affinity_respected",
        thread::affinity_respected(ctx)
    );
    run_test!(
        "thread::default_affinity_bsp",
        thread::default_affinity_bsp(ctx)
    );

    // ── Extended-state (FPU / SIMD / V) isolation ────────────────────────────
    run_test!("fpu::preempt_isolation", fpu::preempt_isolation(ctx));

    // ── Hardware access syscalls ──────────────────────────────────────────────
    run_test!("hw::mmio_map", hw::mmio_map(ctx));
    run_test!("hw::irq_register_ack", hw::irq_register_ack(ctx));
    run_test!("hw::ioport_bind", hw::ioport_bind(ctx));
    run_test!("hw::ioport_split", hw::ioport_split(ctx));

    // ── System info syscalls ──────────────────────────────────────────────────
    run_test!("sysinfo::kernel_version", sysinfo::kernel_version(ctx));
    run_test!("sysinfo::cpu_count", sysinfo::cpu_count(ctx));
    run_test!("sysinfo::frame_counts", sysinfo::frame_counts(ctx));
    run_test!("sysinfo::page_size", sysinfo::page_size(ctx));
    run_test!(
        "sysinfo::boot_protocol_version",
        sysinfo::boot_protocol_version(ctx)
    );
    run_test!("sysinfo::unknown_kind_err", sysinfo::unknown_kind_err(ctx));
    run_test!("sysinfo::elapsed_us", sysinfo::elapsed_us(ctx));
    run_test!("sysinfo::cpu_count_smp", sysinfo::cpu_count_smp(ctx));
}
