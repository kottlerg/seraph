# Checkpoint and Restore

The cooperative protocol by which a process is captured at a point it chooses and restored, within
one boot, as a new process created from its signed image.

---

## Implementation Status

Partly implemented. The quiesce point and the checkpoint are implemented: the runtime's `quiesce`
and `take` ([runtime/ruststd/README.md](../runtime/ruststd/README.md#checkpoint) § Checkpoint),
procmgr's `QUIESCE` and `CHECKPOINT` labels ([procmgr IPC
Interface](../services/procmgr/docs/ipc-interface.md) § Label 34: `QUIESCE`, § Label 35:
`CHECKPOINT`), the snapshot layout's checkpoint section (§ Snapshot object layout there), and
memmgr's `OBJECT_READ`, `FILL_REGION` and `MARK_CHECKPOINT` labels and its checkpoint mark ([memmgr
IPC Interface](../services/memmgr/docs/ipc-interface.md) § Label 35 to § Label 37), which
`CHECKPOINT` sets on a complete capture. Design intent, which no code implements yet: procmgr's
restore creation, `ProcessInfo`'s restore word, and the runtime's resume record and restore entry.
Until the resume record exists, the restore stack pointer `quiesce` gives is an address in its own
frame rather than below a resume record. The live capture this protocol builds on is implemented:
procmgr's debug-authority `SNAPSHOT` and the snapshot object layout ([procmgr IPC
Interface](../services/procmgr/docs/ipc-interface.md) § Label 33: `SNAPSHOT`, § Snapshot object
layout), and the kernel's address-space hold
([core/kernel/docs/syscalls.md](../core/kernel/docs/syscalls.md) § `SYS_ASPACE_HOLD` (71)).

---

## Scope

This document is authoritative for:

- the quiesce point: where a process consents to a capture it can be restored from, and what its
  runtime requires of it there;
- the checkpoint: the capture of a quiesced process for its controller;
- the restore creation: what procmgr restores, what it does not, and the binding of a restore to
  the signed image;
- the restore entry and the rebinding of every handle from the new `ProcessInfo`;
- the rollback notice the restored process receives;
- the bound of a snapshot to one boot.

The wire forms of the labels are in the owning components' interface documents once implemented;
the capture's mechanism, which a checkpoint shares, is procmgr's
([procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md) § Label 33: `SNAPSHOT`), and
the memory objects a snapshot is sealed into are memmgr's
([services/memmgr/docs/memory-pool.md](../services/memmgr/docs/memory-pool.md#memory-objects)
§ Memory objects).

---

## Principles

- **No capability state is captured or restored.** A snapshot holds bytes and the arguments of the
  process's memmgr regions, never a capability, a badge, or a mapping made from a capability.
  Restoring capabilities would make the restorer a universal minter of badges, restore authority
  past its revocation, replay single-use authority, and persist authority at rest. A mapping made
  from a Memory capability, a memory-object handle or an Mmio capability is that capability's
  state, and goes with it.
- **A restore is an ordinary creation.** The restored process is created by procmgr from a signed
  object that verifies under its name, as every process is
  ([docs/signing.md](signing.md) § Verifier Discipline), with a new address space, `CSpace`,
  main thread, memmgr record, budget node and process badge, and the capabilities its creator
  gives it. No executable page of a restored process comes from a snapshot.
- **Consent.** A process is captured for a restore only at a quiesce point it entered itself. A
  process that never quiesces cannot be checkpointed, and a snapshot taken without its consent (a
  debugger's `SNAPSHOT`) cannot be restored. Consent is carried by memmgr's checkpoint mark on the
  object (§ Checkpoint), which only procmgr sets, on its own complete capture of a quiesce point,
  through an account memmgr has verified is its own. It is never a value in the snapshot: whoever
  seals an object supplies every byte of it, a checkpoint flag or a completion bit included, while
  the mark is memmgr's state beside the object's bytes.
- **The process restores itself.** The kernel restores no register state: procmgr starts the new
  main thread at the image's entry, and the runtime resumes the quiesced context from the memory
  the restore holds.

---

## Parties

- **The process**, through its runtime (`std::os::seraph`,
  [runtime/ruststd/README.md](../runtime/ruststd/README.md)), which enters and leaves the quiesce
  point and runs the restore entry.
- **The controller**, any holder of the process's process handle (its creator, or a process the
  creator passed the handle to), which asks for the checkpoint, presents the memmgr account it is
  charged to, and holds the snapshot's object handle.
- **The restorer**, any process that holds the object handle and may create the image, which
  restores by a create request carrying the handle. The controller and the restorer are usually
  one process.
- **procmgr**, which records the quiesce point, captures, and creates the restored process.
- **memmgr**, which holds the snapshot object, marks a checkpoint's object for procmgr, and makes
  the restored process's regions.

---

## Quiesce point

The process quiesces by a call into its runtime, `std::os::seraph::checkpoint::quiesce(timeout)`,
on its main thread. The runtime refuses the call, capturing nothing, unless every condition below
holds, since a restore can reproduce none of what they exclude:

- the caller is the main thread, and no other thread the application spawned is alive;
- the process is demand-paged (`ProcessInfo.pager_endpoint_cap` nonzero), so its memory is held
  in memmgr regions a restore can replay;
- no `std::fs::File` is open, no `std::process::Child` is held, and no pipe other than stdio is
  open, so no server holds a request or a mapping of the process's that a restore would orphan.

The runtime's own threads (the fs release handler, a child's death bridge) are idle at their wait
when these hold, and hold no lock of the runtime's; the restore discards them.

At the call the runtime saves the caller's callee-saved registers, its stack pointer and its return
address in a resume record in its own memory, creates a Notification for this call, and sends
procmgr `QUIESCE` on its own procmgr cap with the **restore stack pointer**, a stack address below
the resume record's stack pointer, and a Notify-only derivation of that Notification. procmgr
refuses `QUIESCE` from a process it cannot restore: one created pinned (`CREATE_PINNED`), phys-class
(`CREATE_PHYS_ACCESS`), or with a DMA hold (`CREATE_DMA_HOLD`); a driver never quiesces. Otherwise
it records the quiesce point in the process's entry, the restore stack pointer and the Notification
with it, and replies. The thread then waits on its Notification for at most `timeout`, and writes no
memory but its stack below the resume record's stack pointer.

procmgr signals the Notification only once a complete, marked checkpoint of the point has been
delivered to its controller (§ Checkpoint). A capture that fails signals nothing and leaves the
process at its point, so its controller can take the checkpoint again. The process leaves the
quiesce point when the Notification is signalled, or when the wait times out: the runtime sends
`QUIESCE` again with no stack pointer, which ends the point, procmgr deletes its Notification, and
only after that reply does the thread return or write any other memory. The runtime then reads the
Notification once more without waiting, and deletes it. `quiesce` returns `Captured` when the
Notification was signalled: its controller then holds a complete checkpoint of the point. It returns
`NotCaptured` otherwise, which says only that no checkpoint was delivered before the point ended: a
capture whose hold began before the end may still deliver one (§ Checkpoint). A process's death ends
its quiesce point.

The application chooses the point: at the call, its own state is what it accepts to resume from,
after any number of restores, in a world that has moved on (§ Rollback notice).

---

## Checkpoint

The controller sends procmgr `CHECKPOINT` on the process handle with a memmgr SEND, the
**account**, as `SNAPSHOT` takes one. procmgr refuses it with `NOT_QUIESCED` unless the process
is at a quiesce point. Otherwise it captures the process as `SNAPSHOT` does
([procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md) § Label 33: `SNAPSHOT`): it
holds the address space, captures every region and listed page into frames requested on the
account, releases the space, and seals the copy on the account into one memory object. The
process's consent replaces the debug authority, so a process that declared itself undebuggable
(`DECLARE_NO_DEBUG`) can be checkpointed: its quiesce is its consent.

Under the hold procmgr checks, under its table lock, that the quiesce point it found is still
recorded, and derives a copy of the point's Notification for the capture, as `SNAPSHOT` derives
the caps it uses under that lock. A process that ended the point before the hold may have written
its memory since, and the checkpoint is refused `NOT_QUIESCED`. One that ends it after the hold
began was held in its `QUIESCE` call and wrote nothing, so the capture goes on; it signals through
its own copy of the Notification, never through a slot the point's end freed.

The layout carries, beside what a `SNAPSHOT` layout holds, a **checkpoint section**: the restore
stack pointer; the process's bootstrap layout (its `ProcessInfo` address, its argv and env header,
the main thread's IPC buffer, stack top and TLS base); the image's identity (the verified body's
SHA-512 and length) whether or not procmgr shares an image object with it; and the process's
declarations that hold no capability (`DECLARE_NO_DEBUG`, `DECLARE_NO_CORE`, and whether its image
is private). The header marks such a layout as a checkpoint.

When the capture is complete, procmgr sends memmgr `MARK_CHECKPOINT` (below) on its own memmgr cap,
with the object handle and a copy of the account. memmgr marks the object only when the account is
a SEND on its own endpoint that names a process record, which it reads from the cap's badge
(`SYS_ENDPOINT_BADGE`) as it reads every handle a client hands it. An account memmgr has verified
is its own leaves no server between procmgr and memmgr: the frames came from memmgr's grants to
procmgr alone, memmgr's seal found no other capability or mapping reaching them, and the handle
came in memmgr's own reply. The marked object is then the copy procmgr wrote, whoever presented
the account. An account that is not memmgr's is refused the mark, and the checkpoint is refused
`NOT_RESTORABLE` as a failed one.

procmgr then replies to the controller with the object handle and `SNAPSHOT_COMPLETE`, and signals
the process through its copy of the Notification only once that reply is delivered, then deletes
the copy. A reply procmgr cannot deliver releases the object, as `SNAPSHOT`'s does, and signals
nothing. An incomplete capture is a failed checkpoint: procmgr marks nothing and signals nothing,
and the reply carries the handle without `SNAPSHOT_COMPLETE`, as `SNAPSHOT`'s does. After a failed
checkpoint, and a checkpoint refused after the hold (a refused allocation), the process stays at
its point for the controller to take it again.

The object handle is the authority to read every byte the process held at its quiesce point, its
secrets included: a process quiesces only for a controller it trusts with its memory. The snapshot
is charged in full to the account, and its frames are freed once its handle state is released and
no region attaches it.

---

## Restore creation

The restorer sends `CREATE_PROCESS` or `CREATE_FROM_FILE` with `CREATE_RESTORE` and the snapshot's
object handle as a cap of its own. procmgr verifies the signed object under the name, as every
create does, and reads the snapshot's layout from the object (`OBJECT_READ`, below). It refuses the
create with `NOT_RESTORABLE`, having created nothing, unless:

- memmgr reports the object marked as a checkpoint: only procmgr marks an object, only its own
  complete capture of a quiesce point through an account memmgr verified, so the layout and every
  byte are procmgr's capture and the process consented. An object another process sealed, a
  debugger's `SNAPSHOT`, and a copy of either sealed again carry no mark;
- the verified body's SHA-512 and length are the checkpoint's: the restore binds to the bytes the
  process ran, whatever name the restorer gives them;
- every executable run lies in the image's executable segments at the snapshot's load bias, so no
  executable byte comes from the snapshot.

The restored process is then created as any other, with three differences:

- **Layout.** procmgr places the image at the snapshot's load bias, and the `ProcessInfo` page, the
  argv and env region after it, the main thread's IPC buffer, stack and TLS block at the
  checkpoint's addresses, instead of drawing them, since the restored memory holds pointers into
  each. Every clone of a snapshot therefore has the layout of the process it was taken from.
- **Memory.** The image is loaded from the verified body as at any create: its text and read-only
  data attached shared, or loaded private when the checkpoint records a private image. Its writable
  segments, the main thread's committed stack pages and its TLS block take the snapshot's bytes
  instead of the image's. The argv and env region takes the checkpoint's argv and env from the
  snapshot's bytes, and the new `ProcessInfo` the checkpoint's argv and env header, so the `'static`
  slices the runtime and `std::env::args()` hold into the region read the same bytes after the
  restore. A restore create carries no argv or env of its own: procmgr refuses one with
  `CREATE_ARGV_ENV` as `INVALID_ARGUMENT`. Every region of the snapshot is made again on the new
  process's memmgr record, by the arguments its entry holds (`REGISTER_REGION`, or `ATTACH_OBJECT`
  of the zero object), and each of its pages the snapshot holds bytes of is backed with a copy of
  them (`FILL_REGION`, below); a zero run stays unbacked. A region of the image is the new image
  attachment, and a copy of an image page the process held (a debugger's breakpoint) is not
  restored. Nothing else is restored: a region attaching another memory object, and every run
  outside the regions but those above (grants, shared memory, device memory, a `File`'s pages), was
  mapped from a capability.
- **Entry.** procmgr starts the main thread at the image's entry with the checkpoint's restore stack
  pointer, the TLS base of the checkpoint's TLS block, and the new `ProcessInfo` page, whose restore
  word is set. It applies the checkpoint's declarations to the new entry before the start.

Every page the restore backs is the new process's own, charged to its budget node as its faults
would be, admitted as `REGISTER_REGION` and a fault admit them; a refusal fails the create with
`OUT_OF_MEMORY` as any failed allocation does. The restored process shares no frame with the
snapshot or with another restore of it, and the snapshot can be released once the create replies.

memmgr serves the checkpoint and the restore with three labels:

- **`MARK_CHECKPOINT`**, procmgr-only, marks the object whose handle it carries as a checkpoint,
  when the account it carries is memmgr's own (§ Checkpoint). memmgr knows the caller is procmgr as
  for its other procmgr-only labels: the request arrives on the cap init transfers to procmgr at
  its bootstrap round, which memmgr identifies by badge, and any other badge is refused
  `UNAUTHORIZED` ([memmgr IPC Interface](../services/memmgr/docs/ipc-interface.md) § Badge
  Discipline). memmgr keeps the mark with the object for its life; no other label sets or clears it.
- **`OBJECT_READ`**, open to any process, copies pages of a memory object into Memory caps the
  caller presents, over the object's handle, and its reply says whether the object carries the
  checkpoint mark. procmgr, which has no pager and so cannot attach an object, reads the mark, the
  layout and the bytes of the argv and env region, the writable segments, the stack and the TLS
  block with it.
- **`FILL_REGION`**, open to any process for its own memory, backs pages of the caller's own region
  that no fault has backed with copies of a memory object's pages, over the object's handle, as a
  write fault would back them. procmgr sends it, and `REGISTER_REGION`, on the new process's memmgr
  SEND, so memmgr attributes and charges each to that process, as it does the image's attachment.

---

## Restore entry and handle rebinding

The runtime's `_start` reads the restore word of `ProcessInfo`. With it set, `_start` runs below
the restore stack pointer, on the restored stack, and rebinds before it resumes:

- it registers the new IPC buffer and rebuilds `StartupInfo` from the new `ProcessInfo`, so every
  cap the runtime reaches through it names the new process's slot;
- it drops every runtime state that names a capability of the captured process without using the
  capability: the object slab, the `CSpace` slot reserve, the memory-pressure registration, the
  stdio rings and their page reservations, the main thread's `Parker` Notification, the fs release
  handler and the thread reaper's queues, and releases the regions it holds for the threads it
  discards; then takes each anew from the new process's caps, as a fresh `_start` does;
- it keeps the heap, the page-reservation arena and every memmgr region, which the restore holds as
  captured;
- it draws the main thread's `HashMap` key seed again, so maps the clones of one snapshot create
  take distinct keys.

It then resumes the resume record: `quiesce` returns `Restored` with the rollback notice, on the
main thread of the new process. A `ProcessInfo` capability slot the application read before its
quiesce point names nothing it can rely on; it reads the new ones through
`std::os::seraph::startup_info()`. Its argv and env are the original's, at the same addresses.

---

## Rollback notice

`Restored` tells the application that it runs in a new process resumed from an earlier state:

- every capability it held before its quiesce point, and every slot number it kept, is gone; it
  acquires what it needs again from `ProcessInfo`, the service registry, or its creator;
- every request it made before the point, and every reply it owed, is void: a server's in-flight
  reply to the original never reaches the restore;
- the same snapshot may have been restored any number of times, and the original may still run:
  state that must not repeat (a nonce, a counter, a key stream, a generator's state) is derived
  again before use;
- time moved on: the notice carries the monotonic time of the quiesce point, and the clock reads
  on from the time of the restore.

---

## One boot

A snapshot is a memmgr memory object, which exists only in this boot's RAM and only while its
handle state stands or a region attaches it. A restore is therefore within one boot, from a
snapshot taken in it. A snapshot persisted across boots needs keys sealed to the platform's
measured state, to keep its bytes confidential and bound to the image and the boot policy at rest;
until such keys exist no snapshot is written to storage.

The checkpoint mark (§ Checkpoint) holds within one boot only: it is memmgr's state in this boot's
RAM, and no bytes of the object carry it. A snapshot that outlives a boot will need its
provenance authenticated under the sealed keys, by a tag over its bytes that only the measured
system can make, which the mark does not replace.

---

## Refusals

| Error | Where | Meaning |
|---|---|---|
| `NOT_RESTORABLE` | `QUIESCE` | The process is pinned, phys-class or DMA-held |
| `NOT_QUIESCED` | `CHECKPOINT` | The process is not at a quiesce point, or left it before the hold |
| `NOT_RESTORABLE` | `CHECKPOINT` | The account is no memmgr account, so memmgr refused the mark |
| `NOT_RESTORABLE` | `CREATE_RESTORE` | The object carries no checkpoint mark, or is not a checkpoint of the verified body |
| `INVALID_ARGUMENT` | `CREATE_RESTORE` | The create carries argv and env (`CREATE_ARGV_ENV`) |

A `CHECKPOINT` is refused as a `SNAPSHOT` is for a missing account, an ended target, a held space
and a refused allocation, and a restore creation as any create is.

---

## Limits

- A process that does not cooperate cannot be restored, nor can a driver, a pinned process, or
  the requests a server held for the original.
- A process restores as one thread, its main thread: the application's other threads end before
  its quiesce point.
- A restore copies every backed page of the snapshot, at about the cost of the capture's copy, and
  needs those pages free at once.
- The clones of one snapshot share its load bias and bootstrap layout with the original.
- A snapshot lives for one boot.

---

## Summarized By

[Process Lifecycle](process-lifecycle.md)
