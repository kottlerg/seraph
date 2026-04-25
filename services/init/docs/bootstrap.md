# init Bootstrap Stages

Placeholder: authoritative enumeration of the stages init follows between
kernel handoff and `sys_thread_exit`. Content to be written during the
init-review cycle.

---

## Status

This document exists so that top-level summaries (notably
[`docs/bootstrap.md`](../../../docs/bootstrap.md)) can link an authoritative
component-scope target for init's bootstrap sequence. The actual enumeration
of stages — starting procmgr via raw syscalls, requesting early-service
startup, delegating capabilities, registering services with svcmgr, exiting —
will be filled in when the init-review round runs. Until then,
[`init/README.md`](../README.md) carries the role-level description.

Tracked in the repo-local `TODO.md` under "init docs restructure".

---

## Summarized By

[docs/bootstrap.md](../../../docs/bootstrap.md)
