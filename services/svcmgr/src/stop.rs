// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/stop.rs

//! The stop authority: `STOP_SERVICE` and `LIST_STOPPABLE`, served only on
//! a badge carrying `svcmgr_labels::STOP_AUTHORITY`.
//!
//! svcmgr stops a service only when the eligibility rule
//! (`svcmgr_defs::stop::stop_refusal`) allows it and an instance runs; it
//! destroys the process through the handle it holds as the service's
//! creator, so kill authority never leaves svcmgr, and routes the death
//! through the service's restart policy as `EXIT_KILLED`. A refusal is
//! logged and changes nothing. The list reports each service a stop would
//! stop with the pages its budget node and subtree hold, read through the
//! node handle svcmgr asked procmgr for at the service's create. See
//! `services/svcmgr/docs/ipc-interface.md` § Label 5: `STOP_SERVICE` and
//! § Label 6: `LIST_STOPPABLE`.

use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels};
use ipc::{svcmgr_errors, svcmgr_labels};
use svcmgr_defs::DeathTag;
use svcmgr_defs::stop::{StopFacts, core_role, stop_refusal};

use crate::restart::RestartCtx;
use crate::service::POLICY_NEVER;
use crate::{
    SvcmgrState, observed_death, read_name_from_msg, route_death, service_running, substrate_alive,
};

/// Reply `code` with no words and no caps.
fn reply(code: u64, ipc_buf: *mut u64)
{
    let msg = IpcMessage::new(code);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&msg, ipc_buf) };
}

/// Release every cap a request delivered: neither label takes one.
fn release_delivered(msg: &IpcMessage)
{
    for &cap in msg.caps()
    {
        if cap != 0
        {
            let _ = syscall::cap_delete(cap);
        }
    }
}

/// The facts the eligibility rule reads for the service in table slot
/// `idx`, from its entry, its restart recipe, and whether it is the
/// shutdown actuator. `None` when `idx` is no slot.
fn stop_facts(state: &SvcmgrState, idx: usize) -> Option<StopFacts>
{
    let svc = state.table.services.get(idx)?;
    let recipe = state.table.recipes.get(idx).and_then(Option::as_ref);
    let key = |read: fn(&crate::service::RestartRecipe) -> bool| recipe.is_some_and(read);
    let actuator = state.table.shutdown_actuator.is_some_and(|a| a.slot == idx);
    Some(StopFacts {
        launched: svc.launched,
        restart_never: svc.restart_policy == POLICY_NEVER,
        critical: svc.system_critical,
        core_role: core_role(
            key(|r| r.log_sink),
            key(|r| r.debug_authority),
            key(|r| r.stop_authority),
            key(|r| r.reserve),
            actuator,
        ),
        oom_stop: key(|r| r.oom_stop),
    })
}

/// Whether the service in slot `idx` is one a stop would stop now: the
/// eligibility rule allows it and an instance runs.
fn stoppable(state: &SvcmgrState, idx: usize) -> bool
{
    stop_facts(state, idx).is_some_and(|f| stop_refusal(&f).is_none())
        && state.table.services.get(idx).is_some_and(service_running)
}

/// Handle `STOP_SERVICE`: stop the named service when the eligibility rule
/// allows it, reply, then route its death through its restart policy.
///
/// In order: a badge without `STOP_AUTHORITY` is `UNAUTHORIZED`; a
/// malformed name `INVALID_NAME`; a name no supervised service has (an
/// unknown name, or a `restart = never` service, which has no entry), or a
/// service the rule refuses, `NOT_STOPPABLE`; an eligible service with no
/// running instance `NOT_RUNNING`, after which a death the kernel shows and
/// svcmgr has not routed is routed; and, when memmgr or procmgr is down, so
/// that the destroy would not be answered, or procmgr does not destroy,
/// `UNAVAILABLE`. Each refusal is logged and changes nothing.
///
/// Otherwise svcmgr destroys the process through its handle
/// (`procmgr_labels::DESTROY_PROCESS`), replies `SUCCESS`, so the holder
/// does not wait on the restart, and routes the death as `EXIT_KILLED`
/// ([`route_death`]): the restart policy and budget decide whether the
/// service restarts. A death post of the destroyed instance that arrives
/// later carries its instance and is dropped.
pub(crate) fn handle_stop_service(msg: &IpcMessage, state: &mut SvcmgrState, ctx: &RestartCtx)
{
    let ipc_buf = ctx.ipc_buf;
    release_delivered(msg);
    if msg.badge & svcmgr_labels::STOP_AUTHORITY == 0
    {
        reply(svcmgr_errors::UNAUTHORIZED, ipc_buf);
        return;
    }
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    let name_buf = read_name_from_msg(msg, name_len);
    let Some(name) = name_buf.as_ref().and_then(|buf| buf.get(..name_len))
    else
    {
        reply(svcmgr_errors::INVALID_NAME, ipc_buf);
        return;
    };
    let shown = core::str::from_utf8(name).unwrap_or("?");

    let Some(idx) = state
        .table
        .services
        .iter()
        .position(|svc| svc.name.as_bytes() == name)
    else
    {
        std::os::seraph::log!(
            "stop {shown} refused: not supervised (no such service, or restart = never)"
        );
        reply(svcmgr_errors::NOT_STOPPABLE, ipc_buf);
        return;
    };
    if let Some(refusal) = stop_facts(state, idx).and_then(|f| stop_refusal(&f))
    {
        std::os::seraph::log!("stop {shown} refused: {}", refusal.reason());
        reply(svcmgr_errors::NOT_STOPPABLE, ipc_buf);
        return;
    }

    let Some(svc) = state.table.services.get(idx)
    else
    {
        reply(svcmgr_errors::NOT_STOPPABLE, ipc_buf);
        return;
    };
    let tag = DeathTag::new(idx, svc.instance);
    if !service_running(svc)
    {
        std::os::seraph::log!("stop {shown} refused: not running");
        reply(svcmgr_errors::NOT_RUNNING, ipc_buf);
        // A death the kernel shows that no post has routed yet is routed
        // now, as the shutdown path does for its actuator.
        if svc.active
            && let Some(exit_reason) = observed_death(svc)
            && let Some(tag) = tag
        {
            route_death(tag, exit_reason, state, ctx);
        }
        return;
    }
    if !substrate_alive(state) || svc.process_handle == 0
    {
        std::os::seraph::log!(warn: "stop {shown} refused: procmgr cannot be called");
        reply(svcmgr_errors::UNAVAILABLE, ipc_buf);
        return;
    }

    let destroy = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let destroyed = unsafe { ipc::ipc_call(svc.process_handle, &destroy, ipc_buf) };
    if !matches!(destroyed, Ok(r) if r.label == procmgr_errors::SUCCESS)
    {
        std::os::seraph::log!(warn: "stop {shown} refused: procmgr did not destroy the process");
        reply(svcmgr_errors::UNAVAILABLE, ipc_buf);
        return;
    }
    std::os::seraph::log!("stop {shown}: stopped for a stop-authority holder");
    reply(svcmgr_errors::SUCCESS, ipc_buf);
    if let Some(tag) = tag
    {
        route_death(tag, syscall_abi::EXIT_KILLED, state, ctx);
    }
}

/// The pages the budget node `node_handle` names and its subtree hold
/// (`memmgr_labels::NODE_QUERY_USAGE`, `data[2]`), or `None` when memmgr
/// refuses the query or the call fails. The caller holds memmgr alive, since
/// the call blocks until memmgr answers.
fn node_usage(node_handle: u64, ipc_buf: *mut u64) -> Option<u64>
{
    let msg = IpcMessage::new(memmgr_labels::NODE_QUERY_USAGE);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(node_handle, &msg, ipc_buf) }.ok()?;
    (reply.label == memmgr_errors::SUCCESS).then(|| reply.word(2))
}

/// Handle `LIST_STOPPABLE`: one page of the services a stop would stop now,
/// from the slot cursor in `data[0]`, each with its subtree usage.
///
/// A badge without `STOP_AUTHORITY` is `UNAUTHORIZED`. The usage is read
/// from memmgr, so when memmgr or procmgr is down the reply is
/// `UNAVAILABLE`. Slots are examined in table order from the cursor; a
/// service is listed when [`stoppable`] and its usage is read, and one whose
/// usage memmgr does not give is logged and left out. The page ends at
/// `svcmgr_labels::LIST_STOPPABLE_PAGE` entries, the reply's `data[1]`
/// naming the slot the next call starts at, or at the table's end. Slots are
/// never reused, so a cursor names the same place for svcmgr's lifetime.
pub(crate) fn handle_list_stoppable(msg: &IpcMessage, state: &SvcmgrState, ctx: &RestartCtx)
{
    let ipc_buf = ctx.ipc_buf;
    release_delivered(msg);
    if msg.badge & svcmgr_labels::STOP_AUTHORITY == 0
    {
        reply(svcmgr_errors::UNAUTHORIZED, ipc_buf);
        return;
    }
    if !substrate_alive(state)
    {
        reply(svcmgr_errors::UNAVAILABLE, ipc_buf);
        return;
    }
    let cursor = usize::try_from(msg.word(0)).unwrap_or(usize::MAX);
    let len = state.table.services.len();
    let mut words = [0u64; syscall_abi::MSG_DATA_WORDS_MAX];
    let mut count = 0usize;
    let mut next = cursor.max(len);
    for idx in cursor..len
    {
        if count >= svcmgr_labels::LIST_STOPPABLE_PAGE
        {
            next = idx;
            break;
        }
        let Some(svc) = state.table.services.get(idx)
        else
        {
            continue;
        };
        if !stoppable(state, idx) || svc.node_handle == 0
        {
            continue;
        }
        let Some(pages) = node_usage(svc.node_handle, ipc_buf)
        else
        {
            std::os::seraph::log!(
                warn: "list stoppable: no usage for {}; left out",
                svc.name_str()
            );
            continue;
        };
        if svcmgr_labels::pack_stoppable_entry(&mut words, count, pages, svc.name.as_bytes())
        {
            count = count.saturating_add(1);
        }
    }
    let used = count
        .saturating_mul(svcmgr_labels::LIST_STOPPABLE_WORDS_PER_ENTRY)
        .saturating_add(svcmgr_labels::LIST_STOPPABLE_HEADER_WORDS);
    let [count_word, next_word, ..] = &mut words;
    *count_word = count as u64;
    *next_word = next as u64;
    let reply_msg = IpcMessage::builder(svcmgr_errors::SUCCESS)
        .words(0, words.get(..used).unwrap_or_default())
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply_msg, ipc_buf) };
}
