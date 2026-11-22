// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/stop.rs

//! The stop authority: the shared stop labels svcmgr serves as the service
//! class's stop source (`stop_labels::STOP_CANDIDATE` and
//! `stop_labels::LIST_CANDIDATES`), and `svcmgr_labels::LIST_STOP_SOURCES`,
//! all served only on a badge carrying `stop_labels::STOP_AUTHORITY`.
//!
//! svcmgr stops a service only when the eligibility rule
//! (`svcmgr_defs::stop::stop_refusal`) allows it and the instance the key
//! names runs; it destroys the process through the handle it holds as the
//! service's creator, so kill authority never leaves svcmgr, and routes the
//! death through the service's restart policy as `EXIT_KILLED`. A refusal is
//! logged and changes nothing. The list reports each service a stop would
//! stop with the pages its budget node and subtree hold, read through the
//! node handle svcmgr asked procmgr for at the service's create. The list of
//! sources hands out, per running `stop_source` service, a SEND on its
//! service endpoint badged with the stop bit. See
//! `services/svcmgr/docs/ipc-interface.md` § Stop authority.

use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels};
use ipc::{stop_labels, svcmgr_errors, svcmgr_labels};
use svcmgr_defs::DeathTag;
use svcmgr_defs::stop::{StopFacts, core_role, stop_refusal};

use crate::restart::RestartCtx;
use crate::service::POLICY_NEVER;
use crate::{
    SvcmgrState, observed_death, process_death_reason, route_death, service_running,
    substrate_alive,
};

/// Reply `code` with no words and no caps.
fn reply(code: u64, ipc_buf: *mut u64)
{
    let msg = IpcMessage::new(code);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&msg, ipc_buf) };
}

/// Release every cap a request delivered: no stop label takes one.
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
            key(|r| r.entropy_authority),
            key(|r| r.reserve),
            actuator,
            key(|r| r.stop_source.is_some()),
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

/// Handle `stop_labels::STOP_CANDIDATE`: stop the service whose key,
/// `data[0]`, names its table slot and instance (a `DeathTag` correlator),
/// reply, then route its death through its restart policy.
///
/// In order: a badge without `STOP_AUTHORITY` is `UNAUTHORIZED`; a key
/// whose slot holds no service, or a service the rule refuses, or whose
/// instance is not the one running, or that has no running instance, is
/// `NO_CANDIDATE`, after which a death the kernel shows and svcmgr has not
/// routed is routed; and, when memmgr or procmgr is down, so that the
/// destroy would not be answered, or procmgr does not destroy,
/// `UNAVAILABLE`. Each refusal is logged and changes nothing.
///
/// Otherwise svcmgr destroys the process through its handle
/// (`procmgr_labels::DESTROY_PROCESS`), replies `SUCCESS`, so the holder
/// does not wait on the restart, and routes the death as `EXIT_KILLED`
/// ([`route_death`]): the restart policy and budget decide whether the
/// service restarts. A death post of the destroyed instance that arrives
/// later carries its instance and is dropped.
pub(crate) fn handle_stop_candidate(msg: &IpcMessage, state: &mut SvcmgrState, ctx: &RestartCtx)
{
    let ipc_buf = ctx.ipc_buf;
    release_delivered(msg);
    if msg.badge & stop_labels::STOP_AUTHORITY == 0
    {
        reply(stop_labels::UNAUTHORIZED, ipc_buf);
        return;
    }
    let key = msg.word(0);
    let tag = DeathTag::from_correlator(key);
    let idx = tag.index();
    let Some(svc) = state.table.services.get(idx)
    else
    {
        std::os::seraph::log!("stop of key {key:#x} refused: no service in slot {idx}");
        reply(stop_labels::NO_CANDIDATE, ipc_buf);
        return;
    };
    if let Some(refusal) = stop_facts(state, idx).and_then(|f| stop_refusal(&f))
    {
        std::os::seraph::log!("stop {} refused: {}", svc.name_str(), refusal.reason());
        reply(stop_labels::NO_CANDIDATE, ipc_buf);
        return;
    }
    if !service_running(svc)
    {
        std::os::seraph::log!("stop {} refused: not running", svc.name_str());
        reply(stop_labels::NO_CANDIDATE, ipc_buf);
        // A death the kernel shows that no post has routed yet is routed
        // now, as the shutdown path does for its actuator.
        if svc.active
            && let Some(exit_reason) = observed_death(svc)
            && let Some(current) = DeathTag::new(idx, svc.instance)
        {
            let exit_reason = process_death_reason(state, ctx, current, exit_reason);
            route_death(current, exit_reason, state, ctx);
        }
        return;
    }
    if tag.instance != svc.instance
    {
        std::os::seraph::log!(
            "stop {} refused: instance {} is gone (instance {} runs)",
            svc.name_str(),
            tag.instance,
            svc.instance
        );
        reply(stop_labels::NO_CANDIDATE, ipc_buf);
        return;
    }
    if !substrate_alive(state) || svc.process_handle == 0
    {
        std::os::seraph::log!(warn: "stop {} refused: procmgr cannot be called", svc.name_str());
        reply(stop_labels::UNAVAILABLE, ipc_buf);
        return;
    }

    let destroy = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let destroyed = unsafe { ipc::ipc_call(svc.process_handle, &destroy, ipc_buf) };
    if !matches!(destroyed, Ok(r) if r.label == procmgr_errors::SUCCESS)
    {
        std::os::seraph::log!(
            warn: "stop {} refused: procmgr did not destroy the process",
            svc.name_str()
        );
        reply(stop_labels::UNAVAILABLE, ipc_buf);
        return;
    }
    std::os::seraph::log!(
        "stop {}: stopped for a stop-authority holder",
        svc.name_str()
    );
    reply(stop_labels::SUCCESS, ipc_buf);
    route_death(tag, syscall_abi::EXIT_KILLED, state, ctx);
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

/// The cursor a request carries in `data[0]`, as a table slot.
fn cursor_of(msg: &IpcMessage) -> usize
{
    usize::try_from(msg.word(0)).unwrap_or(usize::MAX)
}

/// Reply `SUCCESS` (`code`) with the page's `count`, the `next` cursor,
/// the entries in `words` past the header, `per_entry` words each, and
/// `caps`.
fn reply_page(
    code: u64,
    words: &mut [u64],
    count: usize,
    next: usize,
    per_entry: usize,
    caps: &[u64],
    ipc_buf: *mut u64,
) -> bool
{
    let used = count.saturating_mul(per_entry).saturating_add(2);
    if let [count_word, next_word, ..] = words
    {
        *count_word = count as u64;
        *next_word = next as u64;
    }
    let mut builder = IpcMessage::builder(code).words(0, words.get(..used).unwrap_or_default());
    for &cap in caps
    {
        builder = builder.cap(cap);
    }
    // SAFETY: ipc_buf is the registered IPC buffer.
    unsafe { ipc::ipc_reply(&builder.build(), ipc_buf) }.is_ok()
}

/// Handle `stop_labels::LIST_CANDIDATES`: one page of the services a stop
/// would stop now, from the slot cursor in `data[0]`, each with its key,
/// rank `RANK_SERVICE`, and subtree usage.
///
/// A badge without `STOP_AUTHORITY` is `UNAUTHORIZED`. The usage is read
/// from memmgr, so when memmgr or procmgr is down the reply is
/// `UNAVAILABLE`. Slots are examined in table order from the cursor; a
/// service is listed when [`stoppable`] and its usage is read, and one whose
/// usage memmgr does not give is logged and left out. The page ends at
/// `stop_labels::LIST_CANDIDATES_PAGE` entries, the reply's `data[1]`
/// naming the slot the next call starts at, or at the table's end. Slots are
/// never reused, so a cursor names the same place for svcmgr's lifetime.
pub(crate) fn handle_list_candidates(msg: &IpcMessage, state: &SvcmgrState, ctx: &RestartCtx)
{
    let ipc_buf = ctx.ipc_buf;
    release_delivered(msg);
    if msg.badge & stop_labels::STOP_AUTHORITY == 0
    {
        reply(stop_labels::UNAUTHORIZED, ipc_buf);
        return;
    }
    if !substrate_alive(state)
    {
        reply(stop_labels::UNAVAILABLE, ipc_buf);
        return;
    }
    let cursor = cursor_of(msg);
    let len = state.table.services.len();
    let mut words = [0u64; syscall_abi::MSG_DATA_WORDS_MAX];
    let mut count = 0usize;
    let mut next = cursor.max(len);
    for idx in cursor..len
    {
        if count >= stop_labels::LIST_CANDIDATES_PAGE
        {
            next = idx;
            break;
        }
        let Some(svc) = state.table.services.get(idx)
        else
        {
            continue;
        };
        let Some(tag) = DeathTag::new(idx, svc.instance)
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
                warn: "list candidates: no usage for {}; left out",
                svc.name_str()
            );
            continue;
        };
        if stop_labels::pack_candidate(
            &mut words,
            count,
            tag.correlator(),
            stop_labels::RANK_SERVICE,
            pages,
            svc.name.as_bytes(),
        )
        {
            count = count.saturating_add(1);
        }
    }
    let _ = reply_page(
        stop_labels::SUCCESS,
        &mut words,
        count,
        next,
        stop_labels::CANDIDATE_WORDS,
        &[],
        ipc_buf,
    );
}

/// Handle `svcmgr_labels::LIST_STOP_SOURCES`: one page of the running
/// services whose recipes set `stop_source`, from the slot cursor in
/// `data[0]`, each with its class and, in the cap slot of its index, a SEND
/// on its service endpoint badged with `stop_labels::STOP_AUTHORITY`.
///
/// A badge without `STOP_AUTHORITY` is `UNAUTHORIZED`. Slots are examined
/// in table order from the cursor; a source whose SEND svcmgr cannot derive
/// is logged and left out. The page ends at
/// `svcmgr_labels::LIST_STOP_SOURCES_PAGE` entries, one per cap a message
/// carries, the reply's `data[1]` naming the slot the next call starts at,
/// or at the table's end. The reply moves each SEND out of svcmgr's
/// `CSpace`; a reply that does not deliver deletes them.
pub(crate) fn handle_list_stop_sources(msg: &IpcMessage, state: &SvcmgrState, ctx: &RestartCtx)
{
    let ipc_buf = ctx.ipc_buf;
    release_delivered(msg);
    if msg.badge & stop_labels::STOP_AUTHORITY == 0
    {
        reply(svcmgr_errors::UNAUTHORIZED, ipc_buf);
        return;
    }
    let cursor = cursor_of(msg);
    let len = state.table.services.len();
    let mut words = [0u64; syscall_abi::MSG_DATA_WORDS_MAX];
    let mut caps = [0u64; svcmgr_labels::LIST_STOP_SOURCES_PAGE];
    let mut count = 0usize;
    let mut next = cursor.max(len);
    for idx in cursor..len
    {
        if count >= svcmgr_labels::LIST_STOP_SOURCES_PAGE
        {
            next = idx;
            break;
        }
        let Some(svc) = state.table.services.get(idx)
        else
        {
            continue;
        };
        let Some(class) = state
            .table
            .recipes
            .get(idx)
            .and_then(Option::as_ref)
            .and_then(|r| r.stop_source)
        else
        {
            continue;
        };
        if !service_running(svc) || svc.provided_endpoint == 0
        {
            continue;
        }
        let Ok(send) = syscall::cap_derive_badge(
            svc.provided_endpoint,
            syscall::RIGHTS_EP_SEND,
            stop_labels::STOP_AUTHORITY,
        )
        else
        {
            std::os::seraph::log!(
                warn: "list stop sources: no SEND for {}; left out",
                svc.name_str()
            );
            continue;
        };
        let Some(slot) = caps.get_mut(count)
        else
        {
            let _ = syscall::cap_delete(send);
            break;
        };
        if svcmgr_labels::pack_stop_source(&mut words, count, class.code(), svc.name.as_bytes())
        {
            *slot = send;
            count = count.saturating_add(1);
        }
        else
        {
            let _ = syscall::cap_delete(send);
        }
    }
    let sent = caps.get(..count).unwrap_or_default();
    if !reply_page(
        svcmgr_errors::SUCCESS,
        &mut words,
        count,
        next,
        svcmgr_labels::STOP_SOURCE_WORDS,
        sent,
        ipc_buf,
    )
    {
        for &cap in sent
        {
            let _ = syscall::cap_delete(cap);
        }
    }
}
