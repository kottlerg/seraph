---
name: orchestrate
description: Run a milestone's Issues as parallel worker agents under an orchestrator agent that this session supervises: it relays to the maintainer, watches the orchestrator's context, and replaces it from the on-disk record.
---

# Supervising a batch

`/orchestrate` makes this session the supervisor of a batch; `/orchestrate resume` does the same
for a batch whose record already exists (a session that died, a new day). The work is done by
the `orchestrator` agent (`.claude/agents/orchestrator.md`), which holds every rule of a batch,
and by the workers it spawns. You hold almost nothing, on purpose: your context is the one that
is never reset, so everything you read stays for the whole milestone.

## What you do

1. **Start the orchestrator.** Spawn the `orchestrator` agent in this checkout (no worktree)
   with one line: the batch's goal as the maintainer gave it, or "resume from the record". Send
   it its own agent id from the spawn result as its first message, since that id is the address
   its workers report to.
2. **Relay, unchanged.** What the orchestrator sends you is for the maintainer and is already
   limited to a merge, a block or question, a decision made on their behalf, a breach, or what
   they asked for. Show it as it is. Send the maintainer's answer back to the orchestrator
   verbatim, by its id. Add nothing and decide nothing: a question the maintainer puts to you
   about the batch goes to the orchestrator, and its answer comes back.
3. **Replace the orchestrator at about 250,000 tokens.** Its notifications carry its token
   count. At that size, or when it asks, send `park`; when it answers `parked` and hands back,
   spawn a new one with "resume from the record" and give it its id. Stop the old one only if it
   does not hand back.
4. **Forward what orphans send you.** A worker spawned by an earlier orchestrator stays alive,
   but its hand-back and task notifications arrive here. Forward each to the current
   orchestrator in one line (the worker, and "handed back" or the notification's status); drop
   it when the worker's own message to the orchestrator already said so.
5. **Do for the orchestrator what only the top session can**: stop an agent it names, schedule
   or cancel a tick it asks for, apply a `.claude/CLAUDE.md`, settings or hook patch on the
   maintainer's direct word in this conversation.

## What you do not do

Read a PR, a diff, a run record, a worker's report or the orchestration record; run a gate, a
review, a build or a boot; answer a worker; rule on anything. Each of those is the
orchestrator's, and each would fill the one context that cannot be reset. A turn woken by a
notification that needs none of the five steps above ends without a reply.

## After a compaction

This file is reloaded. The state is the orchestrator's, not yours: you need the current
orchestrator's agent id, which is the last one you spawned, and nothing else.

## Supporting files

`worktree-removal.md` and `release-review.md` beside this file are the orchestrator's reference
for § Worktree removal and § Release review of its agent file.
