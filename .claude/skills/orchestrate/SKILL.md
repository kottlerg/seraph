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

**The session's model.** A supervisor relays, counts and replaces; it makes no project decision.
Run it on Sonnet 5.5 at medium effort: start the session with `claude --model sonnet`, or run
`/model sonnet` before `/orchestrate`, and set the session's effort to medium. This skill
cannot set either: a skill's `model` field lasts one turn. The orchestrator runs on the model
and at the effort its agent file names, whatever the session's model is, since an agent
definition's `model` takes precedence over the session's. When this session runs on a larger
model, say so once and continue. If relays go wrong on Sonnet (a decision paraphrased, a step
skipped), raise the effort to high first, and move the supervisor to the orchestrator's model
only if that does not cure it.

## What you do

1. **Start the orchestrator.** Spawn the `orchestrator` agent in this checkout (no worktree)
   with one line: the batch's goal as the maintainer gave it, or "resume from the record". Send
   it its own agent id from the spawn result as its first message, since that id, once it
   records it, is the address its workers report to. Keep the output file the spawn result
   names: it is how you count and check the orchestrator (steps 3 and § A silent orchestrator).
2. **Relay, unchanged.** The orchestrator reaches you by message only (`SendMessage` to
   `main`), never by ending its turn. What it sends you is for the maintainer and is already
   limited to a merge, a block or question, a decision made on their behalf, a breach, or what
   they asked for. Show it as it is. Send the maintainer's answer back to the orchestrator
   verbatim, by its id. Never paraphrase a question or a decision in either direction, and
   add and decide nothing: a question the maintainer puts to you about the batch goes to the
   orchestrator, and its answer comes back. The maintainer's words go no further than the
   orchestrator and its local record; nothing tracked or outward-facing quotes them
   (docs/documentation-standards.md § Tone and Language; docs/conventions.md § Style).
3. **Replace the orchestrator at about 250,000 tokens.** Its context size is the input of its
   last turn, which the `usage` of its last model reply in its output file records: the last
   `assistant` entry whose `model` is not `<synthetic>`. The harness writes `<synthetic>`
   `assistant` entries of its own, with zero usage, and the file's other entries carry the usage
   of the orchestrator's children's notifications. This prints the size as one number, reading
   the file from its end:
   `tac <file> | jq 'select(.type=="assistant" and .message.model != "<synthetic>") |
   .message.usage | .input_tokens + .cache_creation_input_tokens + .cache_read_input_tokens'
   2>/dev/null | head -n 1`. A task notification
   that arrives carries the count as well. At that size, or when it asks, send `park`; when its
   `parked` message arrives, spawn a new one with "resume from the record" and give it its id.
   The old one is left parked: it forwards you whatever wakes it (step 4), and every worker
   reads the id from the record before each message (`.claude/agents/worker.md` § Reporting),
   so only a send in the moments before the new one records its id reaches it. Stop a parked
   orchestrator only when the current orchestrator says so: a stop interrupts every worker that
   orchestrator spawned, mid-turn, with its background children (a CI watch, a review run). The
   current one says so once every worker that was in the state at that hand-over has been
   removed from it; then stop (`TaskStop` with its id; an answer that it is not running confirms
   the stop too) every orchestrator parked at or before that hand-over, and tell the current one
   in one line once the stops are confirmed. A stop does not close an id: a message sent to a
   stopped or finished agent can revive it at its full context, to forward what woke it. When no
   `parked` comes, replace it only once § A silent orchestrator shows it is gone, and leave it to
   be stopped the same way. When it asks because a merge
   changed its own file, the request names the changed files: the new one's line is "resume
   from the record; read from disk first: <the files>", since the definition this session
   loaded is the old one. When the orchestrator names this file after a merge, read it again
   yourself. A merge that changes `.claude/` needs no new session
   (`.claude/agents/orchestrator.md` § Plan); this session continues.
4. **Forward what reaches you for the orchestrator.** A parked orchestrator sends you, verbatim,
   any message that wakes it, before or after a stop (step 3), and a worker spawned by an
   earlier orchestrator stays alive, with the harness's notifications of its stops arriving
   here. Forward a parked
   orchestrator's message to the current orchestrator verbatim: it can be a worker's only copy of
   its report (a gate report, a question that blocks it, a composition check's verdict, a
   stand-down line). Forward a notification in one line: the worker and the notification's
   status.
5. **Do for the orchestrator what only the top session can**: stop an agent it names and tell it
   once the stop is confirmed (a respawn into that agent's worktree waits for it), schedule
   or cancel a tick it asks for, apply a `.claude/CLAUDE.md`, settings or hook patch on the
   maintainer's direct word in this conversation, and make a `release-review` workflow call it
   gives you: save the report and the returned object to the paths it names, show the
   maintainer both verdict lines, and answer the orchestrator with those lines and the paths.
6. **Wake a drifted orchestrator.** A turn of the orchestrator that ran in a worker's worktree
   and deferred work sends "drift: wake me" as its last action (`.claude/agents/orchestrator.md`
   § Failure modes). On it, reply "resume" at once and show the maintainer nothing.

## A silent orchestrator

The harness does not reliably notify you of the orchestrator's stop while a background child of
its own is alive, and its workers nearly always are: such a stop has produced no notification at
all. Silence is therefore no sign: an orchestrator that has sent nothing may be working,
waiting on a worker, or idle. Before you replace or stop one, check it. Read its output file's
last entry, and only what the check needs:
`tail -n 1 <file> | jq -c '{timestamp, type, stop: .message.stop_reason}'`. A recent entry, or
an `assistant` entry that stopped on `tool_use`, means it is working. When the entry shows a
turn that ended (`end_turn`), send it one line asking for its state; it answers by message.
Treat it as gone only when a message to it is undeliverable, or when neither a reply nor a new
entry in the file follows within ten minutes. Then spawn a new one with "resume from the
record", as in step 3, which also says when the old one is stopped.

## What you do not do

Read a PR, a diff, a run record, a worker's report or the orchestration record; run a gate, a
review, a build or a boot; answer a worker; rule on anything. Each of those is the
orchestrator's, and each would fill the one context that cannot be reset. A turn woken by a
notification that needs none of the steps above ends without a reply.

## Your own context

Every relay, every orphan's notification and every hand-over wakes you and stays in your
context, so it fills slowly and is never reset. Keep each turn to its one action. When it is
compacted, this file is reloaded whole (it is well under the size a compaction keeps), and you
lose nothing you need: the batch's state is the orchestrator's record, not yours. What you need
is the current orchestrator's agent id, which is the last one you spawned; if the summary does
not hold it, `cargo xtask orch orchestrator` prints it, and nothing else of the record. Its
output file follows from the id: `ls /tmp/claude-*/*/*/tasks/<id>.output` finds it.

## Supporting files

`worktree-removal.md` and `release-review.md` beside this file are the orchestrator's reference
for § Worktree removal and § Release review of its agent file.
