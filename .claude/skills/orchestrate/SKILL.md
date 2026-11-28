---
name: orchestrate
description: Run a milestone's Issues as parallel worker agents under an orchestrator agent that this session supervises: it relays to the maintainer, watches the orchestrator's context, and replaces it from the on-disk record.
---

# Supervising a batch

`/orchestrate` makes this session the supervisor of a batch; `/orchestrate resume` does the same
for a batch whose record already exists (a session that died, a new day). The work is done by the
`orchestrator` agent (`.claude/agents/orchestrator.md`), which holds every rule of a batch, and by
the workers you spawn at its request. You hold almost nothing, on purpose: your context is the one
that is never reset, so everything you read stays for the whole milestone.

**The session's model.** A supervisor relays, counts and replaces; it makes no project decision.
Run it on Sonnet 5.5 at medium effort: start the session with `claude --model sonnet`, or run
`/model sonnet` before `/orchestrate`, and set the session's effort to medium. This skill
cannot set either: a skill's `model` field lasts one turn, and the session's model and effort
are the maintainer's to set. The orchestrator runs on the model and at the effort its agent file
names, whatever the session's model is, since an agent definition's `model` takes precedence
over the session's. When this session runs on a larger model, say so once and continue.

## What you do

1. **Start the orchestrator.** Spawn the `orchestrator` agent in this checkout (no worktree)
   with one line: the batch's goal as the maintainer gave it, or "resume from the record". Send
   it its own agent id from the spawn result as its first message, since that id, once it
   records it, is the address its workers report to. Keep the output file the spawn result
   names: it is how you count and check the orchestrator (steps 3 and § A silent orchestrator).
2. **Relay, unchanged.** The orchestrator reaches you by message only (`SendMessage` to
   `main`), never by ending its turn. What it sends you is for the maintainer and is already
   limited to a merge, a block or question, a decision made on their behalf, a breach, or what
   they asked for. Each direction has a fixed form, so that a departure from it shows:
   - **To the maintainer.** Show the orchestrator's message whole, in a quote block, under a
     one-line header that says only that it is from the orchestrator (`From the orchestrator:`).
     Keep its own structure: do not summarize, reorder, reformat or annotate it.
   - **To the orchestrator.** A message of the maintainer for the orchestrator (an answer, an
     instruction, a question about the batch) goes to it by its id as their words alone, in the
     form `Maintainer, verbatim: "<exact text>"`, and nothing else in that message. When the
     words answer a question, one line before them may name which, quoted from what you showed
     and never restated: `Answers: "<the question as shown>"`. The orchestrator's answer to a
     question of theirs comes back to them as above.
   - **Nothing of your own in a relay.** A remark, a question or a recommendation of yours, for
     either side, is added to no relay. Put it to the maintainer first, as your own and apart
     from any relayed text; it reaches the orchestrator only as the maintainer's words, if they
     then say it. The messages the other steps and § A silent orchestrator have you send the
     orchestrator (its id, `park`, a spawn answer, a confirmed stop, `resume`, a request for its
     state among them) are no relay and go to it directly.

   Never paraphrase in either direction, and decide nothing. The maintainer's words go no
   further than the orchestrator and its local record; nothing tracked or outward-facing quotes
   them (docs/documentation-standards.md § Tone and Language; docs/conventions.md § Style).
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
   `parked` message arrives, spawn a new one with "resume from the record" and give it its id. The
   old one parks with no agent of its own running and ends its turn, so its task is complete: there
   is nothing to stop, and you stop no parked orchestrator. A message that still reaches it (a
   worker that read the record before the new one recorded its id) wakes it, and it sends you the
   message verbatim (step 4). When no `parked` comes, replace it as § A silent orchestrator says.
   When it asks because a merge changed its own file, the request names the changed files: the new
   one's line is "resume from the record; read from disk first: <the files>", since the definition
   this session loaded is the old one. When the orchestrator names this file after a merge, read it
   again yourself. A merge that changes `.claude/` needs no new session
   (`.claude/agents/orchestrator.md` § Plan); this session continues.
4. **Forward what reaches you for the orchestrator.** Forward a message a parked orchestrator
   sends you to the current orchestrator verbatim: it can be a worker's only copy of its report
   (a gate report, a question that blocks it, a composition check's verdict, a stand-down line).
   The harness's notifications of a worker's stops come to you for the whole batch, since you
   spawned it (step 5). A worker reports by message to the orchestrator, so end such a turn
   without a reply and forward nothing, except a notification that the worker's session ended
   without a hand-back or failed: forward that in one line, the worker and the notification's
   status.
5. **Spawn each worker the orchestrator asks for.** Every worker is yours, never the
   orchestrator's: the harness stops an agent together with every running agent it spawned, and
   has no stop that spares them, so a worker spawned by an orchestrator could be interrupted by
   anything done to that orchestrator. The orchestrator writes the worker's whole prompt to a
   scratchpad file and records the worker, then sends you one line:
   `spawn <name>: prompt <path>; model <m>; effort <e>; worktree: new`, or
   `worktree: <existing path>` for a respawn into its predecessor's worktree.
   - Make one `Agent` call: `subagent_type` `worker`, that model and effort, `isolation`
     `worktree` for `new` and none for an existing path, and as the prompt only the line
     "Read <path> and follow it as your prompt." The result echoes the prompt back, and a
     one-line prompt keeps that echo out of your context. Read nothing of the file.
   - Answer the orchestrator with one line, `<name>: <agent id>`. Keep and relay nothing else of
     the result.
   - A respawn into a predecessor's worktree comes only after you have ended the predecessor's
     task and confirmed it (step 6), except for a worker of an earlier session, which ended with
     that session; the spawn line then names that worktree.
6. **Do for the orchestrator what only the top session can**: stop an agent it names and tell it
   once the stop is confirmed (a respawn into that agent's worktree waits for it), schedule
   or cancel a tick it asks for, and make a `release-review` workflow call it
   gives you: save the report and the returned object to the paths it names, show the
   maintainer both verdict lines, and answer the orchestrator with those lines and the paths.
7. **Wake a drifted orchestrator.** A turn of the orchestrator that ran in a worker's worktree
   and deferred work sends "drift: wake me" as its last action (`.claude/agents/orchestrator.md`
   § Failure modes). On it, reply "resume" at once and show the maintainer nothing.

## A silent orchestrator

The harness does not reliably notify you of the orchestrator's stop while a background child of its
own is alive (an `Explore` or `scribe` it started, a background command): such a stop has produced
no notification at all. Silence is therefore no sign: an orchestrator that has sent nothing may be
working, waiting on a worker, or idle. Before you replace or stop one, check it. Read its output
file's last entry, and only what the check needs:
`tail -n 1 <file> | jq -c '{timestamp, type, stop: .message.stop_reason}'`. A recent entry, or an
`assistant` entry that stopped on `tool_use`, means it is working. When the entry shows a turn that
ended (`end_turn`), send it one line asking for its state; it answers by message. Treat it as gone
only when a message to it is undeliverable, or when neither a reply nor a new entry in the file
follows within ten minutes. Then stop it, but only once no agent it spawned is running, since the
stop would end that agent too. The meta files of the agents it spawned sit beside its transcript;
this lists those of the ones still running:

```sh
d=$(dirname "$(readlink <file>)")
grep -l '"parentAgentId":"<id>"' "$d"/*.meta.json | xargs -r grep -L '"finished":true' || true
```

Then spawn a new one with "resume from the record", as in step 3.

## What you do not do

Read a PR, a diff, a run record, a worker's report or the orchestration record; run a gate, a
review, a build or a boot; answer a worker; rule on anything. Each of those is the
orchestrator's, and each would fill the one context that cannot be reset. A turn woken by a
notification that needs none of the steps above ends without a reply.

## Your own context

Every relay, every spawn, every worker's notification and every hand-over wakes you and stays in
your context, so it fills slowly and is never reset. Keep each turn to its one action. When it is
compacted, this file is reloaded whole (it is well under the size a compaction keeps), and you lose
nothing you need: the batch's state is the orchestrator's record, not yours. What you need is the
current orchestrator's agent id, which is the last orchestrator you spawned; if the summary does not
hold it, `cargo xtask orch orchestrator` prints it, and nothing else of the record. Its output file
follows from the id: `ls /tmp/claude-*/*/*/tasks/<id>.output` finds it.

## Supporting files

`worktree-removal.md` and `release-review.md` beside this file are the orchestrator's reference
for § Worktree removal and § Release review of its agent file.
