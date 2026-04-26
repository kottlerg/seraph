# init Bootstrap Stages

Placeholder: authoritative enumeration of the stages init follows between
kernel handoff and `sys_thread_exit`. Content to be written during the
init-review cycle.

---

## Status

This document exists so that top-level summaries (notably
[`docs/bootstrap.md`](../../../docs/bootstrap.md)) can link an authoritative
component-scope target for init's bootstrap sequence. The actual enumeration
of stages — starting memmgr and procmgr via raw syscalls, requesting
early-service startup, delegating capabilities, registering services with
svcmgr, exiting — will be filled in when the init-review round runs. Until
then, [`init/README.md`](../README.md) carries the role-level description and
[`docs/process-lifecycle.md`](../../../docs/process-lifecycle.md) is the
authoritative system-scope description of the userspace boot order.

---

## Summarized By

[docs/bootstrap.md](../../../docs/bootstrap.md), [docs/process-lifecycle.md](../../../docs/process-lifecycle.md)
