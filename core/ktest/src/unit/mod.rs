// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/mod.rs

//! Tier 1 — per-syscall isolation tests.
//!
//! Rule (durable):
//!
//! > **One module per kernel subsystem under test. New subsystem ⇒ new
//! > module.**
//!
//! Adding a new syscall means adding a section in the file for its
//! kernel subsystem — not a new file. New file only when a new kernel
//! subsystem is added. Files stay scoped; they don't grow unboundedly
//! because each is one surface.
//!
//! Every kernel syscall must have at least one positive-path test here
//! plus its most important negative paths (wrong rights, invalid
//! arguments, wrong object state).
//!
//! Files:
//! - `cap.rs`      — capability creation, copy, move, insert, derive, revoke, delete
//! - `cap_info.rs` — read-only capability state inspection (`SYS_CAP_INFO`)
//! - `retype.rs`   — retype primitive: aspace/cspace augment, PT budget, kernel PT pool
//! - `mm.rs`       — memory map/unmap/protect, memory split, address space query
//! - `entropy.rs`  — userspace randomness (`SYS_GETRANDOM`), incl. the user-copy
//!   fault-recovery regression (unmapped or read-only buffer ⇒ `InvalidAddress`,
//!   not panic)
//! - `notification.rs`   — notification send and wait (blocking and timeout)
//! - `event.rs`    — event queue post and receive (blocking, try, timeout)
//! - `wait_set.rs` — wait set add, remove, wait
//! - `ipc.rs`      — IPC call, reply, recv, buffer set
//! - `thread.rs`   — thread lifecycle, register read/write, priority, affinity, sleep, `bind_notification`
//! - `fpu.rs`      — FPU / SIMD / V extended-state isolation across preemption and cross-CPU migration
//! - `hw.rs`       — MMIO, IRQ, I/O ports, SBI
//! - `sysinfo.rs`  — system info queries and debug log
//! - `crypto.rs`   — shared `crypto` crate KATs (SHA-512, Ed25519 verify),
//!   run on-target so the primitives are validated on both arches (not a
//!   kernel syscall surface, but ktest is the only both-arch on-target harness)
//! - `init_layout.rs` — kernel Phase 9 ASLR draws (#39): `InitInfo` VA,
//!   init stack, and PIE image-base window membership, asserted on ktest's
//!   own layout and load base

pub mod cap;
pub mod cap_info;
pub mod crypto;
pub mod entropy;
pub mod event;
pub mod fpu;
pub mod hw;
pub mod init_layout;
pub mod ipc;
pub mod mm;
pub mod notification;
pub mod retype;
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
    run_test!("cap::create_notification", cap::create_notification(ctx));
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
    run_test!("cap::derive_badge", cap::derive_badge(ctx));
    run_test!(
        "cap::derive_badge_zero_err",
        cap::derive_badge_zero_err(ctx)
    );
    run_test!(
        "cap::derive_badge_rebadge_err",
        cap::derive_badge_rebadge_err(ctx)
    );
    run_test!(
        "cap::derive_inherits_badge",
        cap::derive_inherits_badge(ctx)
    );
    run_test!(
        "cap::derive_badge_on_notification",
        cap::derive_badge_on_notification(ctx)
    );

    // ── Capability inspection (SYS_CAP_INFO) ──────────────────────────────────
    run_test!(
        "cap_info::tag_rights_aspace",
        cap_info::tag_rights_aspace(ctx)
    );
    run_test!(
        "cap_info::tag_rights_memory",
        cap_info::tag_rights_memory(ctx)
    );
    run_test!(
        "cap_info::tag_rights_notification",
        cap_info::tag_rights_notification(ctx)
    );
    run_test!("cap_info::memory_fields", cap_info::memory_fields(ctx));
    run_test!(
        "cap_info::memory_caps_carry_retype_right",
        cap_info::memory_caps_carry_retype_right(ctx)
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
    run_test!(
        "cap_info::cspace_default_max_slots_is_pool_backed",
        cap_info::cspace_default_max_slots_is_pool_backed(ctx)
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
        "retype::region_unmap_reclaims_pt_budget",
        retype::region_unmap_reclaims_pt_budget(ctx)
    );
    run_test!(
        "retype::concurrent_regions_release_pt_budget_on_unmap",
        retype::concurrent_regions_release_pt_budget_on_unmap(ctx)
    );
    run_test!(
        "retype::cspace_grow_consumes_pool",
        retype::cspace_grow_consumes_pool(ctx)
    );
    run_test!(
        "retype::cspace_pool_exhaust_augment_then_quota",
        retype::cspace_pool_exhaust_augment_then_quota(ctx)
    );

    // ── Memory management syscalls ────────────────────────────────────────────
    run_test!("mm::memory_split_merge", mm::memory_split_merge(ctx));
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
        "mm::memory_split_at_zero_err",
        mm::memory_split_at_zero_err(ctx)
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
        "mm::mem_map_offset_beyond_memory_err",
        mm::mem_map_offset_beyond_memory_err(ctx)
    );
    run_test!(
        "mm::mem_unmap_unaligned_err",
        mm::mem_unmap_unaligned_err(ctx)
    );
    run_test!("mm::mem_protect_wx_err", mm::mem_protect_wx_err(ctx));
    run_test!("mm::mem_map_wx_prot_err", mm::mem_map_wx_prot_err(ctx));
    run_test!(
        "mm::memory_split_at_end_err",
        mm::memory_split_at_end_err(ctx)
    );
    run_test!(
        "mm::init_segment_caps_aligned",
        mm::init_segment_caps_aligned(ctx)
    );

    // ── Notification syscalls ───────────────────────────────────────────────────────
    run_test!("notification::send", notification::send(ctx));
    run_test!(
        "notification::send_wait_blocking",
        notification::send_wait_blocking(ctx)
    );
    run_test!(
        "notification::send_before_wait_immediate",
        notification::send_before_wait_immediate(ctx)
    );
    run_test!(
        "notification::wait_insufficient_rights",
        notification::wait_insufficient_rights(ctx)
    );
    run_test!(
        "notification::multiple_sends_before_wait_accumulate_bits",
        notification::multiple_sends_before_wait_accumulate_bits(ctx)
    );
    run_test!(
        "notification::send_zero_bits_is_noop",
        notification::send_zero_bits_is_noop(ctx)
    );
    run_test!(
        "notification::send_insufficient_rights",
        notification::send_insufficient_rights(ctx)
    );
    run_test!(
        "notification::wait_timeout_fires",
        notification::wait_timeout_fires(ctx)
    );
    run_test!(
        "notification::wait_timeout_returns_bits_first",
        notification::wait_timeout_returns_bits_first(ctx)
    );
    run_test!(
        "notification::wait_high_bit_roundtrip",
        notification::wait_high_bit_roundtrip(ctx)
    );
    run_test!(
        "notification::wait_high_bit_parked_wakeup",
        notification::wait_high_bit_parked_wakeup(ctx)
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
        "wait_set::add_notification_immediate",
        wait_set::add_notification_immediate(ctx)
    );
    run_test!(
        "wait_set::add_queue_immediate",
        wait_set::add_queue_immediate(ctx)
    );
    run_test!("wait_set::blocking_wait", wait_set::blocking_wait(ctx));
    run_test!("wait_set::remove", wait_set::remove(ctx));
    run_test!(
        "wait_set::source_notification_pinned_by_member",
        wait_set::source_notification_pinned_by_member(ctx)
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
    run_test!("ipc::recv_delivers_badge", ipc::recv_delivers_badge(ctx));
    run_test!(
        "ipc::recv_unbadged_returns_zero",
        ipc::recv_unbadged_returns_zero(ctx)
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
        "thread::set_priority_in_band",
        thread::set_priority_in_band(ctx)
    );
    run_test!(
        "thread::set_priority_no_cap_err",
        thread::set_priority_no_cap_err(ctx)
    );
    run_test!(
        "thread::sched_split_enforces_bands",
        thread::sched_split_enforces_bands(ctx)
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
    run_test!(
        "thread::affinity_migrate_ready_queued",
        thread::affinity_migrate_ready_queued(ctx)
    );
    run_test!(
        "thread::affinity_migrate_running",
        thread::affinity_migrate_running(ctx)
    );
    run_test!(
        "thread::load_balancer_redistributes_skewed",
        thread::load_balancer_redistributes_skewed(ctx)
    );
    run_test!(
        "thread::load_balancer_skips_pinned",
        thread::load_balancer_skips_pinned(ctx)
    );
    run_test!("thread::sleep_blocks_ms", thread::sleep_blocks_ms(ctx));
    run_test!(
        "thread::sleep_zero_is_noop",
        thread::sleep_zero_is_noop(ctx)
    );
    run_test!(
        "thread::bind_notification_fires_on_exit",
        thread::bind_notification_fires_on_exit(ctx)
    );
    run_test!(
        "thread::bind_notification_invalid_cap_err",
        thread::bind_notification_invalid_cap_err(ctx)
    );

    // ── Extended-state (FPU / SIMD / V) isolation ────────────────────────────
    run_test!("fpu::preempt_isolation", fpu::preempt_isolation(ctx));
    run_test!(
        "fpu::preempt_isolation_cross_cpu",
        fpu::preempt_isolation_cross_cpu(ctx)
    );

    // ── Hardware access syscalls ──────────────────────────────────────────────
    run_test!("hw::mmio_map", hw::mmio_map(ctx));
    run_test!("hw::mmio_split_carves", hw::mmio_split_carves(ctx));
    run_test!(
        "hw::mmio_split_wrong_tag_err",
        hw::mmio_split_wrong_tag_err(ctx)
    );
    run_test!("hw::irq_register_ack", hw::irq_register_ack(ctx));
    run_test!("hw::irq_split_carves", hw::irq_split_carves(ctx));
    run_test!(
        "hw::irq_split_wrong_tag_err",
        hw::irq_split_wrong_tag_err(ctx)
    );
    run_test!("hw::ioport_bind", hw::ioport_bind(ctx));
    run_test!("hw::ioport_split", hw::ioport_split(ctx));
    #[cfg(target_arch = "riscv64")]
    run_test!(
        "hw::sbi_call_get_spec_version",
        hw::sbi_call_get_spec_version(ctx)
    );
    #[cfg(target_arch = "x86_64")]
    run_test!(
        "hw::sbi_call_not_supported_x86_64",
        hw::sbi_call_not_supported_x86_64(ctx)
    );

    // ── System info syscalls ──────────────────────────────────────────────────
    run_test!("sysinfo::kernel_version", sysinfo::kernel_version(ctx));
    run_test!("sysinfo::cpu_count", sysinfo::cpu_count(ctx));
    run_test!("sysinfo::page_size", sysinfo::page_size(ctx));
    run_test!(
        "sysinfo::boot_protocol_version",
        sysinfo::boot_protocol_version(ctx)
    );
    run_test!("sysinfo::unknown_kind_err", sysinfo::unknown_kind_err(ctx));
    run_test!("sysinfo::elapsed_us", sysinfo::elapsed_us(ctx));
    run_test!("sysinfo::current_cpu", sysinfo::current_cpu(ctx));
    run_test!("sysinfo::cpu_count_smp", sysinfo::cpu_count_smp(ctx));

    // ── Entropy syscalls ──────────────────────────────────────────────────────
    run_test!(
        "entropy::getrandom_fills_buffer",
        entropy::getrandom_fills_buffer(ctx)
    );
    run_test!(
        "entropy::getrandom_unmapped_ptr_invalid_address",
        entropy::getrandom_unmapped_ptr_invalid_address(ctx)
    );
    run_test!(
        "entropy::getrandom_readonly_ptr_invalid_address",
        entropy::getrandom_readonly_ptr_invalid_address(ctx)
    );
    run_test!(
        "entropy::getrandom_over_max_len_invalid_arg",
        entropy::getrandom_over_max_len_invalid_arg(ctx)
    );

    // ── Init bootstrap layout (ASLR, #39) ─────────────────────────────────────
    run_test!(
        "init_layout::init_info_va_in_window",
        init_layout::init_info_va_in_window(ctx)
    );
    run_test!(
        "init_layout::sp_in_init_stack_window",
        init_layout::sp_in_init_stack_window(ctx)
    );
    run_test!(
        "init_layout::image_base_randomized",
        init_layout::image_base_randomized(ctx)
    );

    // ── Shared crypto primitives ──────────────────────────────────────────────
    run_test!("crypto::sha512_kats", crypto::sha512_kats(ctx));
    run_test!("crypto::ed25519_kats", crypto::ed25519_kats(ctx));
}
