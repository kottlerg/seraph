# Restart Protocol

Restart protocol details: crash detection via thread death notifications,
restart sequencing, capability re-delegation, and criticality handling.

---

## Death Detection

svcmgr uses the kernel's `SYS_THREAD_BIND_NOTIFICATION` syscall to bind an
EventQueue to each monitored service's thread. When the thread exits — either
cleanly via `SYS_THREAD_EXIT` or due to an unhandled fault (GPF, page fault,
etc.) — the kernel posts the exit reason to the bound EventQueue.

svcmgr multiplexes all EventQueues (plus its own service endpoint for
registration IPC) into a single WaitSet. The monitor loop blocks on
`SYS_WAIT_SET_WAIT` and dispatches based on the returned token.

Exit reason encoding:

| Value | Meaning |
|-------|---------|
| 0 | Clean exit (thread called `SYS_THREAD_EXIT`) |
| 1–255 | Fault: exception vector + 1 (x86-64) or scause + 1 (RISC-V) |

---

## Criticality Check

On detecting a service death, svcmgr first checks the service's criticality:

- **Fatal**: The service is essential and cannot be safely restarted. svcmgr
  logs the crash with the service name and exit reason, then halts the system.
  Graceful shutdown (notifying other services, flushing state) is deferred to
  a future implementation.

- **Normal**: The service can be restarted. svcmgr proceeds to the restart
  policy check.

---

## Restart Policy Check

For Normal-criticality services, svcmgr checks the restart policy:

- **Always**: Restart unconditionally.
- **OnFailure**: Restart only if exit_reason != 0 (the thread faulted). If the
  thread exited cleanly (exit_reason == 0), do not restart.
- **Never**: Do not restart. Log the event and mark the service as inactive.

---

## Restart Sequencing

When a restart is permitted:

1. **Check restart count.** If the service has been restarted 5 times (the
   maximum), mark it as **degraded** and do not restart. Log a warning.

2. **Create new process.** Send `CREATE_PROCESS` to procmgr with the stored
   module Frame capability. For VFS-loaded services, send
   `CREATE_PROCESS_FROM_VFS` with the stored path (deferred — not needed for
   the initial implementation).

3. **Inject capabilities.** Using the child CSpace cap returned by procmgr,
   inject the stored restart recipe caps (e.g., log endpoint) into the new
   process's CSpace. Write corresponding CapDescriptors into the ProcessInfo
   page.

4. **Start process.** Send `START_PROCESS` to procmgr.

5. **Rebind death notification.** Create a new EventQueue, bind it to the new
   thread via `SYS_THREAD_BIND_NOTIFICATION`, and replace the old EventQueue
   in the WaitSet.

6. **Increment restart count.** Update the service entry.

---

## Restart Recipe

Each registered service stores a restart recipe: the set of capabilities and
metadata needed to recreate the service. Init transfers these during
`REGISTER_SERVICE`.

For the initial implementation, the recipe consists of:

- Module Frame capability (for `CREATE_PROCESS`)
- Log endpoint Send capability (injected into child CSpace)

Future services may require additional caps (procmgr endpoint, device
endpoints, etc.), which can be added to the recipe as needed. The IPC cap
slot limit (4 per message) bounds the recipe size for a single registration
message; multi-message registration can be added if needed.

---

## Supervision Hierarchy

svcmgr only supervises top-level services registered by init:

| Service | Criticality | Restart Policy |
|---------|-------------|---------------|
| procmgr | Fatal | Never |
| devmgr | Fatal | Never |
| vfsd | Fatal | Never |
| crasher (test) | Normal | Always |

Device drivers (virtio-blk, etc.) are supervised by devmgr. Filesystem
drivers (fatfs, etc.) are supervised by vfsd. All supervisors use the same
kernel primitive (`SYS_THREAD_BIND_NOTIFICATION` + EventQueue).

---

## procmgr Fallback

If procmgr itself crashes, svcmgr cannot use procmgr IPC to restart it.
svcmgr holds raw kernel capabilities (AddressSpace, CSpace, Thread creation
syscalls) as a fallback to reconstruct procmgr from its boot module.

This fallback is deferred to a future implementation. For now, procmgr is
registered as Fatal — its crash halts the system.

---

## Summarized By

[svcmgr/README.md](../README.md)
