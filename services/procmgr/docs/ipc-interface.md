# procmgr IPC Interface

IPC interface specification for procmgr: message labels, capability transfer
semantics, and error conditions for process lifecycle operations.

---

## Endpoint

procmgr listens on a single IPC endpoint. Init holds the Send-side capability
and passes it (or a derived copy) to any service that needs to create processes.
procmgr holds the Receive-side capability.

---

## Messages

All requests use `SYS_IPC_CALL` (synchronous call/reply). The low 16 bits of the
message label (`label & 0xFFFF`) select the operation; the create labels carry
further fields in the upper bits. Data words and capability slots carry
arguments. The reply label is `procmgr_errors::SUCCESS` (0) or an error code.
Label numbers, error codes, and query states are defined in
[`procmgr_labels`](../../../shared/ipc/src/procmgr_labels.rs),
[`procmgr_errors`](../../../shared/ipc/src/procmgr_errors.rs), and
[`procmgr_process_state`](../../../shared/ipc/src/procmgr_process_state.rs). `START_PROCESS`,
`DESTROY_PROCESS`, `QUERY_PROCESS`, `CONFIGURE_PIPE`, `CONFIGURE_NAMESPACE`, `BIND_DEATH_OBSERVER`,
`LIST_CHILDREN` and `DESTROY_CHILD` are sent on a **process handle** (the badged endpoint a create
call returns), and `RELEASE_HOLD` on a **release token** (the third cap a `CREATE_DMA_HOLD` create
returns); procmgr identifies the target process by the badge `ipc_recv` delivers. A process handle
is badged with the child's process badge and `procmgr_labels::PROCESS_HANDLE_TAG` (bit 59, a bit of
`ipc::VERB_BIT_MASK`, which no process badge carries), which tells it from the child's own procmgr
cap (`ProcessInfo.procmgr_endpoint_cap`), badged with the process badge alone. procmgr clears the
tag before it serves a request, so a handle names its child to every label, and refuses
`DECLARE_NO_DEBUG`, `DECLARE_NO_CORE`, `REGISTER_THREAD`, `REGISTER_END_QUEUE` and `READ_VERIFIED`,
which name their sender, on a badge carrying it with `INVALID_BADGE`, deleting the caps the request
carried: only the process itself sends them (§ Label 21, § Label 22, § Label 26, § Label 29, § Label
31). `BIND_DEATH_OBSERVER`, `LIST_CHILDREN` and `DESTROY_CHILD` are served on a process handle only,
and refused on any other cap with `UNAUTHORIZED` (§ Label 25, § Process Tree).
Labels 14–18 are specified in § `REGISTER_DEATH_EQ`, § `REGISTER_INIT_TEARDOWN`, §
`INIT_TEARDOWN_DONE`, § `QUERY_INIT_REAP`, and § `QUERY_LIVE_PROCESSES` below, labels 19–24 and 26
in § Crash Endpoint and Debug Authority, label 25 in § Label 25: `BIND_DEATH_OBSERVER`, labels
27–29 in § Process Tree, label 30 in § Label 30: `MAKE_RESIDENT`, label 31 in § Label 31:
`READ_VERIFIED`, and label 32 in § Label 32: `MAKE_PRIVATE`.
Labels 4–7 and 10 are unassigned; procmgr replies `UNKNOWN_OPCODE` (`0xFFFF`) to them and to any
other unknown opcode, and deletes the caps such a request carried (see § Capability Transfer).

Memory-cap allocation is owned by memmgr, not procmgr, per
[docs/process-lifecycle.md](../../../docs/process-lifecycle.md)
§ Authority Boundaries Between memmgr and procmgr.
See
[`services/memmgr/docs/ipc-interface.md`](../../memmgr/docs/ipc-interface.md)
for `REQUEST_MEMORY_CAPS` and related labels.

### Image Verification

Both create labels load a signed object (an ELF image followed by its trailer,
[docs/signing.md](../../../docs/signing.md) § Signed Object Format) and name it, and procmgr
creates the child only from an object that verifies under that name
([docs/signing.md](../../../docs/signing.md) § Verifier Discipline, § Signature Policy in procmgr).

- **Length and name.** Data word 0 is the object's exact length in bytes, nonzero, since a Memory
  cap covers whole pages and the trailer is found from the object's end. After every other data
  word (the argv/env header and the memory max, each when its flag is set) comes the name block,
  at word `procmgr_labels::create_name_word(label)`: the name's length in bytes, 1 to
  `procmgr_labels::CREATE_NAME_MAX` (256), then its bytes packed little-endian, eight to a word
  (`procmgr_labels::with_create_name` writes it). The name is in the canonical form of
  [docs/signing.md](../../../docs/signing.md) § Signed Attributes: an install path for a file, a
  bundle entry name for a boot module. A request without a name block, with a name that is not
  canonical, or with a zero length is refused with `INVALID_ARGUMENT` before procmgr acquires
  anything for the child.
- **One copy.** Once the child is registered with memmgr and its argv and env are copied, procmgr
  reads the object once, `[0, length)`, into frames it requests on the child's memmgr account
  and maps only in its own address space: a Memory cap's pages whole (`CREATE_PROCESS`), or a
  file's cache pages one `FS_READ_MEMORY` at a time (`CREATE_FROM_FILE`). The cap's holder and
  the file's server can still write their pages; they cannot write the copy. The child's budget
  therefore bounds an object's size, and its node must have room for the copy beside the child's
  own pages while it is created.
- **Verify, then parse.** procmgr verifies the copy against the trust store the bootloader handed
  it, expecting the requested name, this build's architecture, and a role in the creator's
  signature policy, and parses and loads only the body the verifier returned. A refusal replies
  `SIGNATURE_REFUSED` (18) and logs one warning naming the name and the verifier's reason; the
  create releases everything it took, as any failed create does. A child takes its creator's
  policy, narrowed to programs when its own object's role set holds program.
- **Release.** The copy's frames return to memmgr (`RELEASE_MEMORY_CAPS`) once the segments are
  copied into the child's own frames, whether the create succeeds or fails.

### Label 1: `CREATE_PROCESS`

Create a new process from a signed object in a Memory cap, a boot module's. The process is
created in a **suspended** state — the thread is not started. Between create and
`START_PROCESS` the caller configures the child through the returned process
handle (`CONFIGURE_PIPE`, `CONFIGURE_NAMESPACE`).

**Request:**

| Field | Value |
|---|---|
| label bits `[0..16]` | 1 |
| label bits `[16..36]` | Create flags and scheduling fields (see **Pinned flag**, **Death relay**, **Containment**, **Scheduling fields**, **argv and env**, **Physical-address flag**, and **Memory max and reserve** below) |
| label bits `[36..64]` | Reserved, zero |
| data[0] | The object's exact length in bytes, at byte 0 of cap[0] (§ Image Verification) |
| data[1..5] | When `CREATE_ARGV_ENV` is set: the `ArgvEnvHeader`, `args_bytes`, `args_count`, `env_bytes`, `env_count`, one `u64` each |
| data[1], or data[5] with `CREATE_ARGV_ENV` | When `CREATE_MEMORY_MAX` is set: the child's memory max in pages (**Memory max and reserve** below) |
| the words after them | The name block: the name the object is signed under (§ Image Verification) |
| cap[0] | Memory capability holding the signed object |
| cap[1] | Optional creator endpoint, copied into the child's `ProcessInfo.creator_endpoint_cap` |
| the cap before the argv/env cap, or before the relay without one, or last without either | When `CREATE_CHARGE_NODE` is set: the node handle the child is charged to (**Memory max and reserve** below) |
| next-to-last cap, or last without a relay | When `CREATE_ARGV_ENV` is set: Memory cap holding the argv and env blobs |
| last cap | When `CREATE_DEATH_RELAY` is set: POST-only `EventQueue` cap (**Death relay** below) |

procmgr maps the module's Memory cap read-only, copies the object out and verifies it
(§ Image Verification), parses the verified ELF, creates the child's address space,
CSpace, and thread, maps LOAD segments, and populates the `ProcessInfo`
handover page, with the child's argv and env in the pages after it (see
**argv and env** below). procmgr deletes its copies of cap[0], cap[1], and
the argv/env cap whether creation succeeds or fails, and the charge node's handle when memmgr did
not take it (**Memory max and reserve** below), and deletes any cap the
layout does not name; the death-relay cap it keeps or deletes as **Death
relay** below says. A
failed creation releases everything procmgr acquired for the child, including
the child's memmgr record: procmgr sends memmgr `PROCESS_DIED` for it, so the
pages already allocated to the child return to memmgr's pool.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | The max in pages the child's budget node took, `u64::MAX` for none (**Memory max and reserve** below) |
| cap[0] | Process handle (a SEND on procmgr's endpoint badged with the child's process badge and `procmgr_labels::PROCESS_HANDLE_TAG`; § Messages) |
| cap[1] | Child `Thread` capability (Control, Observe, and Upcall rights, `RIGHTS_THREAD`) |
| cap[2] | With `CREATE_DMA_HOLD` only: the release token (a SEND on procmgr's endpoint badged with the child's process badge and `procmgr_labels::HOLD_RELEASE_AUTHORITY`; **DMA hold flag** below) |
| last cap | With `CREATE_NODE_HANDLE` only: a node handle to the child's budget node (**Memory max and reserve** below) |

The process handle is a badged endpoint capability. The caller uses it for the
per-process operations — the badge identifies the process without a forgeable
PID. The `Thread` cap allows the caller to bind death notifications or
stop/configure the thread.

The reply's cap transfer is all-or-nothing
([docs/ipc-design.md](../../../docs/ipc-design.md#message-format) § Message Format). When the
caller's `CSpace` cannot take every cap (or the caller is gone), the caller
resumes with `IPC_REPLY_TRANSFER_FAILED` and no caps. procmgr then deletes the
caps and destroys the suspended child as `DESTROY_PROCESS` does, since no one
holds a handle to it.

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `INVALID_ELF` | The verified body's ELF validation or relocation failed (the TLS block's checks aside, see `OUT_OF_MEMORY`) |
| 2 | `OUT_OF_MEMORY` | procmgr's own `CSpace` is short of its headroom and its top-up was refused ([README.md](../README.md) § CSpace headroom), or memory-cap, kernel-object, or badge allocation failed, the copy of the object among them (a max too small for the child among its causes), the main thread's TLS block could not be built, the stack or IPC-buffer pages could not be mapped, or, with `CREATE_DMA_HOLD`, the room for the child's held reclaim or the derivation of its release token (the child, never started, is destroyed and its pages returned) |
| 7 | `INVALID_ARGUMENT` | No module capability, the length is zero or past the cap's pages, no name block or a name not in the canonical form (§ Image Verification), `CREATE_DEATH_RELAY` or `CREATE_CHARGE_NODE` set without a cap of its own (**Death relay** below), reserved label bits `[36..64]` set, the scheduling fields violate the resolution rules below (band above the creator's ceiling, or priority above the resolved band), the argv and env violate the rules of **argv and env** below, `CREATE_PHYS_ACCESS` comes from a creator that is not phys-class (**Physical-address flag** below), or the request's badge names no live process or one a destroy has begun on (§ Process Tree), as when the creator's destroy begins before the child is recorded or before procmgr's reply delivers it, or a destroy marked the child itself (`DESTROY_CHILD`, or a destroy of a subtree it is in) before procmgr's reply delivered it (§ Process Tree), `CREATE_MEMORY_MAX` comes without its data word, or `CREATE_RESERVE` comes from a creator outside the system reserve or with `CREATE_CHARGE_NODE` (**Memory max and reserve** below) |
| 11 | `MAP_FAILED` | The module cap, a copy frame or a segment could not be mapped |
| 12 | `INSUFFICIENT_RIGHTS` | The module cap lacks the map right, or a rights derivation failed during segment load |
| 14 | `ARGV_ENV_STILL_MAPPED` | A copy window of the argv and env would not unmap; the caller withholds its argv/env run (**argv and env** below) |
| 18 | `SIGNATURE_REFUSED` | The object does not verify under the name, in a role of the creator's signature policy, for this architecture (§ Image Verification) |

**argv and env.** The label's bit 29 (`CREATE_ARGV_ENV`, in the window shared with
`CREATE_FROM_FILE`) marks a request that carries the child's argv and env in a Memory cap the caller
sizes and funds: one run holding the argv blob at byte 0 and the env blob directly after it, each a
concatenation of NUL-terminated UTF-8 strings (env entries `KEY=VALUE`), with the
`ipc::procmgr_labels::ArgvEnvHeader` of the two blobs' byte lengths and string counts in four data
words. The cap is the last one before the death relay (**Death relay** below), or the last cap
without one, so the creator endpoint stays at cap[1]. Without the flag the child gets no argv and no
env, and the request carries neither the header nor the cap. procmgr refuses the request with
`INVALID_ARGUMENT`, before it acquires anything for the child, when the flag is set without a cap of
its own, a header word was not delivered, the cap is not a Memory cap, or the blobs reach past the
cap or together exceed `process_abi::ARGV_ENV_MAX_BYTES`. Otherwise, once it has registered the
child with memmgr and before it creates anything else, procmgr copies the blobs into fresh pages on
the child's account, through two windows of `ARGV_ENV_COPY_WINDOW_PAGES` (64) pages re-mapped for
each chunk, so its own page-table cost per create stays that of two 256 KiB spans whatever the
blobs' size. That copy also refuses the create with `INVALID_ARGUMENT` when the caller's cap cannot
be mapped (it lacks the map right, or the kernel refuses its pages for a reason other than procmgr's
memory), and when, on the copy, a blob's NULs disagree with its count or a nonempty blob does not
end in a NUL; a caller that rewrites its pages meanwhile changes only the copy that is checked. A
shortfall of procmgr's or the child's memory replies `OUT_OF_MEMORY`. Should procmgr fail to unmap a
copy window, which may then still map the caller's pages read-only and the child's writable, it
replies `ARGV_ENV_STILL_MAPPED` (14), keeps the window's VA reserved, and withholds the child's
memmgr record (sends no `PROCESS_DIED` for it); the caller MUST then withhold its run too (not
return it to memmgr), so memmgr re-grants no frame procmgr may still map. `ArgvEnvCap::settle` does
so. procmgr maps the copy read-only directly after the child's `ProcessInfo` page, where
`ProcessInfo`'s `args_offset` and `env_offset` locate it
([abi/process-abi/README.md](../../../abi/process-abi/README.md) § argv / env region), funding the
child's page tables for a region past one last-level table's span (512 pages) from the child's
account. procmgr deletes its copy of the cap before it replies, so the caller can return the run to
memmgr as soon as the call returns. `std::os::seraph::process::ArgvEnvCap` builds the cap and the
header for a std-built sender.

**Pinned flag.** Demand paging is the default: at finalize procmgr binds every child's main thread
fault handler to memmgr (the system pager) via `SYS_THREAD_SET_FAULT_HANDLER`, for the
virtual-memory class (`FAULT_CLASS_VM`; the exception class is bound to the crash endpoint, as
§ Crash Endpoint and Debug Authority says, and the upcall class stays unbound), delegates the
child `AddressSpace` to memmgr via `memmgr_labels::DELEGATE_ASPACE`,
and then sets `ProcessInfo.pager_endpoint_cap` (the child's badged memmgr cap, whose derivation
badge the kernel stamps on each fault) and `pager_badge` (that badge), which tell the runtime the
process is demand-paged; the runtime copies the spawning thread's bindings, this one among them,
onto each thread it
spawns (`SYS_THREAD_INHERIT_FAULT_HANDLER`). The
child then backs reserved regions lazily via
`std::os::seraph::register_demand_paged`. The label's bit 16 (`CREATE_PINNED`,
in the `[16..31]` window shared with `CREATE_FROM_FILE`) opts out: the
child is left eager-mapped with no pager. Set it only for a process that cannot
depend on the fault path — a DMA driver, or the shutdown actuator, which svcmgr
creates pinned. init, memmgr, and procmgr are pre-pager
and never routed through this path, so they are pinned by construction. See
[docs/fault-handling.md](../../../docs/fault-handling.md). The binding is
best-effort: a failure degrades to "no pager" (faults kill), never blocking
creation. procmgr writes `pager_endpoint_cap` and `pager_badge` only after the
delegation and the main thread's binding have both taken effect, so the page never
names a pager the child does not have; a child whose binding failed, or whose page
procmgr could not map to advertise it, reads zero and keeps its memory eager.

**Death relay.** The label's bit 17 (`CREATE_DEATH_RELAY`, in the window shared with
`CREATE_FROM_FILE`) marks a request whose last cap is a POST-only `EventQueue` cap, the relay. It is
the last cap, so the creator-endpoint slot stays at cap[1], and a cap of its own, as the argv/env
cap is: a request needs one cap past cap[0] for each of `CREATE_DEATH_RELAY`, `CREATE_ARGV_ENV` and
`CREATE_CHARGE_NODE` it sets, and one that sets more than its caps can supply is refused with
`INVALID_ARGUMENT`. procmgr keeps the relay in the child's entry for the child's life and posts the
child's end to it once, as the entry `(reason, 0)`, whoever ends the child: at the reap of a child
that exited or took a terminal fault in any of its threads, the exit reason or the fault class
procmgr reaped it by, and at the teardown of a destroyed child, a subtree's or a containment's
included (§ Process Tree), the reason § Label 9 states for a destroyed process, `EXIT_KILLED` unless
the child had exited or faulted already. Each is the reason `QUERY_PROCESS` then reports. procmgr
posts after the teardown and memmgr's reclaim, then deletes its copy. The post is procmgr's, not a
kernel binding: one party posts, once, whatever number of the child's threads exit or fault before
the teardown, and the relay takes none of its queue's observer nodes. The relay reports the ends of
its creator's own children only: when the creator ends and the child is re-parented, procmgr deletes
the relay unposted. A failed creation deletes it unposted, one a destroy marked included: until
procmgr's reply delivers the child's handle, the create owns the child's entry, and a destroy that
marks the child leaves it to the create, which is then refused with `INVALID_ARGUMENT`
(§ Process Tree).

**Containment.** The label's bit 35 (`CREATE_CONTAIN`, in the window shared with
`CREATE_FROM_FILE`) creates the child contained: when it ends, by an exit, a fault or a destroy,
procmgr destroys what is left of its subtree instead of re-parenting its children (§ Process Tree).

**DMA hold flag.** The label's bit 28 (`CREATE_DMA_HOLD`, in the window shared
with `CREATE_FROM_FILE`) holds back the child's memory reclaim. Once the child
has been started, its teardown, however it comes (its death, a death resync, or
`DESTROY_PROCESS`), revokes and deletes its kernel objects as for any child but
does not send memmgr `PROCESS_DIED`: procmgr parks the child's memmgr record
until the creator sends `RELEASE_HOLD` (§ Label 3) on the child's release
token, and until then memmgr keeps the child's frames on that record, out of
its free pool. Set it for a driver whose device may DMA into its frames after
it dies: the creator releases the hold once it has confirmed the device's DMA
stopped, and never when it cannot, which leaves the frames quarantined for the
rest of the boot
([docs/device-management.md](../../../docs/device-management.md#dma-safe-teardown)
§ DMA-Safe Teardown). The release token is the create reply's cap[2], a SEND
badged with the child's process badge and `procmgr_labels::HOLD_RELEASE_AUTHORITY`,
a verb bit no process badge carries; procmgr mints it only here, so only the
creator, or a process the creator hands it to, can release the hold. On any
label but `RELEASE_HOLD` the token names no process: procmgr answers it as for
a badge no process holds. A child destroyed before `START_PROCESS` never ran,
so it touched no device, and its teardown sends `PROCESS_DIED` at once.
procmgr reserves the room the child's parked record takes before it replies to
the create, so no teardown frees a held child's pages for want of a record;
when it cannot, or cannot derive the token, the create fails with
`OUT_OF_MEMORY`.

**Physical-address flag.** The label's bit 30 (`CREATE_PHYS_ACCESS`, in the window shared with
`CREATE_FROM_FILE`) creates the child phys-class: procmgr registers it with memmgr with
`REGISTER_PHYS_CLASS`, so memmgr's grants to it keep `RIGHTS_MEM_PHYS` and the child can read
the physical bases of the Memory caps it holds
([services/memmgr/docs/ipc-interface.md](../../memmgr/docs/ipc-interface.md) § Label 3).
procmgr retypes every child's address space, a phys-class child's included, through a
derivation of its slab without `RIGHTS_MEM_PHYS`, so no child's address space carries
`RIGHTS_AS_READ` and procmgr, which keeps it for the child's life, cannot translate its pages;
devmgr, the phys-class child every boot creates, checks its own at startup
([services/devmgr/docs/responsibilities.md](../../devmgr/docs/responsibilities.md)
§ Capabilities Received). procmgr honours `CREATE_PHYS_ACCESS` only from a creator that is
phys-class itself: an un-badged one (badge 0: init, or svcmgr's mint source) or one whose memmgr
badge carries `memmgr_labels::PHYS_CLASS_BADGE_BIT`; from any other it replies
`INVALID_ARGUMENT` before any resource is acquired. init sets it for devmgr and devmgr for the
IOMMU driver, the processes
[docs/device-management.md](../../../docs/device-management.md#dma-authorisation) § DMA
Authorisation names; every other process, every device driver included, is created without it.

**Memory max and reserve.** procmgr registers each child with memmgr under a budget node
([services/memmgr/docs/memory-pool.md](../../memmgr/docs/memory-pool.md#distribution-policy)
§ Distribution policy; [services/memmgr/docs/ipc-interface.md](../../memmgr/docs/ipc-interface.md)
§ Label 3), to which memmgr charges every page the child holds: the pages procmgr allocates on the
child's account while it creates it, and the child's own grants, demand chunks and page-table
donations. The creator is the process the request's badge names, and the child's node sits under
the creator's node, so a max on the creator's node bounds its children too. A child of the
un-badged creator (badge 0: init, or svcmgr's mint source) is a top-level node. procmgr refuses a
request whose badge names no live process (a reaped process's own cap or handle, or a cap whose
badge carries a verb bit, such as a release token) with `INVALID_ARGUMENT` before any resource is
acquired: its child would sit under no creator's node.

The label's bit 31 (`CREATE_MEMORY_MAX`) carries a max in pages in the data word after the fixed
ones: data[1] of either create label, four words later with `CREATE_ARGV_ENV`. A request that sets
it without delivering that word is refused with `INVALID_ARGUMENT` before any resource is acquired.
procmgr passes the max to memmgr, which clamps it to what the creator's node and every ancestor have
left, and the reply's data[0] carries the max the node took. Without the flag, or with a max of
`u64::MAX`, the node has no max of its own, only its ancestors and the system reserve limit it, and
data[0] is `u64::MAX`. A max too small for the pages procmgr allocates on the child's account fails
the create with `OUT_OF_MEMORY`, as any failed allocation does. Once the child runs, a grant past
the max fails with `memmgr_errors::LIMIT`, and a demand fault past it is declined with code 10,
which the kernel forwards to the faulting thread's exception handler
([services/memmgr/docs/ipc-interface.md](../../memmgr/docs/ipc-interface.md)
§ Kernel-origin fault message).

The label's bit 32 (`CREATE_RESERVE`) makes the child's node a system-reserve node, which may take
the free pages memmgr keeps in reserve. procmgr honours it only from a creator whose own node is a
reserve node, and from any other replies `INVALID_ARGUMENT` before any resource is acquired, as for
`CREATE_PHYS_ACCESS`; it refuses the flag with `CREATE_CHARGE_NODE` in the same way, from any
creator, since a handle may name a sub-node, which is never in the reserve. A child of the
un-badged creator that is not charged to a node handle is a reserve node with or without the flag,
so init's children are, and procmgr records each child's membership for the check on its own
creates. procmgr trusts the un-badged creator as it does for `CREATE_PHYS_ACCESS`: svcmgr never
creates on its mint source, and a create there would make a top-level reserve node with no max,
which is what svcmgr's own node is. svctest's test phases set both flags, `CREATE_RESERVE` only to
see procmgr refuse it; in the default image no process has a max of its own, and no default
per-process max exists. svcmgr sets
`CREATE_RESERVE` for a service whose recipe sets `reserve = yes`, oomd's, sessiond's, crashd's,
logd's and swapd's in the default image, and starts every other service outside the reserve
([services/svcmgr/docs/service-definitions.md](../../svcmgr/docs/service-definitions.md)
§ `reserve`). devmgr, a reserve node, sets it for each driver of the `block` device class and for
the IOMMU driver, the storage path swapd calls
([docs/driver-binding.md](../../../docs/driver-binding.md) § Driver Declarations).

The label's bit 33 (`CREATE_NODE_HANDLE`) asks for a node handle to the child's budget node, the
reply's last cap. procmgr registers the child with memmgr's `REGISTER_NODE_HANDLE` and passes on
the handle memmgr returns; without the flag it asks for none, and deletes any handle a reply
carries unasked. The handle lets the creator set the child's max while it runs, make sub-nodes
under it, read its usage and register for its limit event
([services/memmgr/docs/ipc-interface.md](../../memmgr/docs/ipc-interface.md) § Node Handles). Its
handle state belongs to the child's memmgr record, so the handle is refused once the child is
gone, and a failed create, which deletes every cap procmgr holds for the child, leaves none
behind. The child itself receives no handle to its own node.

The label's bit 34 (`CREATE_CHARGE_NODE`) charges the child to the node of a node handle the
creator holds: the request carries a copy of the handle as a cap of its own, after any extra caps
and before the argv/env cap and the relay, and the child's node is made under the handle's node in
place of the creator's, clamped as above to what that node and every ancestor have left. The
child's node is outside the reserve: procmgr refuses `CREATE_RESERVE` with the flag, and a charged
child of the un-badged creator is no reserve node. Two
children charged to one sub-node share its budget. procmgr passes the handle to memmgr with
`REGISTER_CHARGE_NODE`
([services/memmgr/docs/ipc-interface.md](../../memmgr/docs/ipc-interface.md) § Label 3), which
refuses a cap that is no live node handle, and procmgr then fails the create as it does for any
refused registration. procmgr deletes its copy on every path: memmgr
takes it with the registration, and a request refused before it is deleted with the request's other
caps. A message carries at most `MSG_CAP_SLOTS_MAX` (4) caps, so a create that sets the flag
carries at most two of the creator endpoint, the argv/env cap and the relay.

**Scheduling fields.** Bits `[18..23]` (`CREATE_PRIORITY`) and `[23..28]`
(`CREATE_BAND_MAX`) of the label window — shared by `CREATE_PROCESS` and
`CREATE_FROM_FILE` — carry the child's scheduling placement; bits `[35..64]`
remain reserved and MUST be zero (`INVALID_ARGUMENT` otherwise, which keeps a
future field addition provably additive). Resolution, against the **creator's
band ceiling** (badge 0 = init, ceiling `sched_policy::BASELINE_PRIORITY_MAX`;
a badged caller's ceiling is its own minted `band_max`; a badge that names no
live process is refused, as **Memory max and reserve** above says):

| Field | 0 (unspecified) | Nonzero |
|---|---|---|
| `CREATE_BAND_MAX` | copy of the creator's band | `[1, band_max]`; must be ≤ the creator's ceiling |
| `CREATE_PRIORITY` | `DEFAULT_SPAWN_PRIORITY` clamped to the band | must be ≤ the resolved `band_max` (so the child's own band always covers its starting level) |

Violations reply `INVALID_ARGUMENT` before any resource is acquired. On
success procmgr creates the child's initial thread at the resolved priority
(via its own baseline `SchedControl`), mints the child's band — a plain
`cap_copy` of the baseline for a full-width band, copy-then-`SYS_SCHED_SPLIT`
for a narrowed one — into `ProcessInfo.sched_control_cap`, and records the
resolved priority in `ProcessInfo.initial_priority` so the runtime spawns
further threads at the same level by default, unless
`std::os::seraph::thread::BuilderExt::spawn_at_priority` places one
elsewhere in the band.

### Label 2: `START_PROCESS`

Start a previously created (suspended) process. The caller must have
completed any `CONFIGURE_PIPE` and `CONFIGURE_NAMESPACE` calls before calling
this operation. procmgr copies the namespace caps installed by
`CONFIGURE_NAMESPACE` into the child's CSpace and `ProcessInfo`, configures the
thread, and starts it.

**Request:**

| Field | Value |
|---|---|
| endpoint | Process handle (badged endpoint from the create reply's cap[0]) |
| label | 2 |

No data words are required — the process is identified by the badge
embedded in the endpoint capability.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 2 | `OUT_OF_MEMORY` | Installing the namespace caps in the child failed |
| 3 | `THREAD_CONFIGURE_FAILED` | `thread_configure_with_tls` failed |
| 4 | `INVALID_BADGE` | No process with the given badge exists |
| 5 | `ALREADY_STARTED` | Process was already started |
| 6 | `THREAD_START_FAILED` | `thread_start` failed with an error other than `Interrupted`, which procmgr retries |

### Label 3: `RELEASE_HOLD`

Release the held memory reclaim of a torn-down child created with
`CREATE_DMA_HOLD` (§ Label 1, **DMA hold flag**). Sent on the child's release
token, the create reply's cap[2], with no data words or caps. procmgr sends
memmgr `PROCESS_DIED` for the child's memmgr badge, deletes its copy of the
child's badged memmgr SEND, and drops the held record, so memmgr returns the
child's frames to its free pool.

procmgr serves the label only when the sender's badge carries
`procmgr_labels::HOLD_RELEASE_AUTHORITY`, and looks the child up by the badge
with every verb bit (`ipc::VERB_BIT_MASK`) cleared. Any other sender carrying
the child's badge, its process handle and the child's own procmgr cap included,
however the child granted a copy onward before it died, is refused
`UNAUTHORIZED` and the hold stays. Like every badge-gated label, the token can
be minted by a holder of an un-badged SEND on procmgr's endpoint, which only
init and svcmgr hold (§ `REGISTER_INIT_TEARDOWN`).

procmgr replies to a `DESTROY_PROCESS` only once the child is torn down and its
record parked, by whichever of its threads tore the child down, since a
teardown takes the child's entry and parks its record in one hold of the table
lock ([README.md](../README.md) § Concurrency). So a release the creator sends
after the destroy's reply finds the record parked, whether or not procmgr had
reaped the child already. A release that
finds no held record changes nothing: the child is live, was never started or
never held, or was released already. procmgr never hands a held record's badge
to a new child.

**Reply:**

| Field | Value |
|---|---|
| label | 0 (success): the held reclaim was sent; or a nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `INVALID_BADGE` | procmgr holds no reclaim for the token's child |
| 13 | `UNAUTHORIZED` | The sender's badge lacks `HOLD_RELEASE_AUTHORITY`: it is not a release token; any hold stays |

### Label 8: `DESTROY_PROCESS`

Destroy a process together with every process below it (§ Process Tree). Sent on the process handle
with no data words or caps. procmgr marks the subtree first, in one hold of its table lock, and
from then on refuses a create from any process of it. For each process of the subtree it then
removes the process entry, revokes and deletes the process's `Thread`, `CSpace`, `AddressSpace`,
`ProcessInfo` Memory cap, and TLS Memory cap, deletes any namespace caps never consumed by
`START_PROCESS`, sends memmgr `PROCESS_DIED` for its memmgr badge, unless it was created with
`CREATE_DMA_HOLD` and started, whose reclaim waits for `RELEASE_HOLD` (§ Label 3), and posts its
end to its death relay (§ Label 1, **Death relay**) and its end queue (§ Label 29). A process
that has already ended, by an exit of its main thread, or by a terminal fault or a
`sys_aspace_exit` of any of its threads, and that procmgr has not reaped yet, is reaped instead,
in the same hold of the table lock, with
the reason it ended with: its children are re-parented, or destroyed when it was created contained,
as at its reap (§ Process Tree), so whether the destroy or the reaper comes first changes nothing.

**Reply:** label 0 (success), always, once the subtree is torn down, apart from a child whose
create procmgr has not answered yet, which that create tears down when procmgr refuses it
(§ Process Tree). An unknown or already-destroyed badge is a no-op.

### Label 9: `QUERY_PROCESS`

Query a process's state without blocking on a death event. Sent on the process
handle with no data words or caps.

**Reply:**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | State: 0 `ALIVE`, 1 `CREATED` (not yet started), 2 `UNKNOWN` (no entry; reaped or destroyed more than `RECENT_EXIT_RETENTION_NS` ago, dropped early under heap exhaustion, or never valid), 3 `EXITED` |
| data[1] | Kernel-encoded exit reason when `data[0]` is `EXITED`; 0 otherwise |

A live entry whose main thread the kernel reports as exited, or any of whose
threads ended its address space (its recorded end), answers
`EXITED` before procmgr reaps it, with the main thread's reason or else the
end's. After the reap, or after a `DESTROY_PROCESS` teardown, the
badge answers `EXITED` for `RECENT_EXIT_RETENTION_NS` (30 s) of monotonic time,
however many other processes die in the window, while procmgr's heap can hold
their records, and `UNKNOWN` after that. Retention is best-effort: when the heap
cannot hold a new record, the oldest record makes room (or, with none held, the
new one is dropped), so such a badge can answer `UNKNOWN` early. A destroyed
process's reason is the one the kernel retained if its main thread had already
exited, or else its address space's first terminal end's, else `EXIT_KILLED`.

### Label 11: `CONFIGURE_PIPE`

Install one direction's shmem-backed stdio pipe on a created, not yet started
child. Sent on the process handle.

**Request:**

| Field | Value |
|---|---|
| label | 11 |
| data[0] | Direction: 0 `PIPE_DIR_STDIN`, 1 `PIPE_DIR_STDOUT`, 2 `PIPE_DIR_STDERR` |
| data[1] | Ring byte capacity (informational; the spawner has already initialised the `SpscHeader`) |
| cap[0] | Memory capability for the shmem ring page |
| cap[1] | Data-available notification capability |
| cap[2] | Space-available notification capability |

procmgr copies each cap into the child's CSpace and writes the slots into the
direction's `<dir>_memory_cap`, `<dir>_data_notification_cap`, and
`<dir>_space_notification_cap` fields of the child's `ProcessInfo`, then deletes
its own copies. It deletes every cap the request carried on success and on
every failure, including caps past cap[2]. Every check precedes the copies, and
a copy that fails revokes the copies already made, so a refused call installs
nothing in the child. A spawner calls this once per piped direction. A second
call for a direction already configured is refused, since procmgr cannot remove
the earlier triple from the child's CSpace.

**Error codes:** 2 `OUT_OF_MEMORY` (mapping or `cap_copy` failed), 4
`INVALID_BADGE`, 5 `ALREADY_STARTED`, 7 `INVALID_ARGUMENT` (fewer than three
caps, a zero cap, an unknown direction, or a direction already configured).

### Label 12: `CONFIGURE_NAMESPACE`

Install the namespace caps a created, not yet started child receives. Sent on
the process handle. procmgr holds no namespace cap of its own; this call is the
only path that installs `ProcessInfo.system_root_cap` and
`ProcessInfo.current_dir_cap`, and without it both stay zero.

**Request:**

| Field | Value |
|---|---|
| label | 12 |
| cap[0] | Root namespace cap for the child (mandatory) |
| cap[1] | Current-directory cap for the child (optional; absent leaves `current_dir_cap` zero) |

procmgr stores the caps, deletes any previously installed pair, and copies
them into the child's CSpace at `START_PROCESS`. It does not validate cap shape.
procmgr consumes the transferred caps on success and failure alike, and deletes
any cap past cap[1].

**Error codes:** 4 `INVALID_BADGE`, 5 `ALREADY_STARTED`, 7 `INVALID_ARGUMENT`
(no cap in cap[0]).

### Label 13: `CREATE_FROM_FILE`

Create a suspended process from an ELF binary the caller has already resolved:
the caller walks its own namespace cap to the binary node and transfers the
resulting file cap. procmgr opens it (`FS_OPEN`), copies the signed object out with
`FS_READ_MEMORY` against its own open and verifies it (§ Image Verification), and never holds a
namespace cap of its own. Loading, the
**Pinned flag**, the **Death relay**, **Containment**, **Memory max and reserve**, the **Scheduling
fields**, and **argv and env** are as for `CREATE_PROCESS`.

**Request:**

| Field | Value |
|---|---|
| label bits `[0..16]` | 13 |
| label bits `[16..36]` | As for `CREATE_PROCESS` |
| label bits `[36..64]` | Reserved, zero |
| data[0] | `file_size` in bytes, from the caller's `NS_LOOKUP` size hint: the signed object's length (§ Image Verification) |
| data[1..5] | When `CREATE_ARGV_ENV` is set: the `ArgvEnvHeader`, as for `CREATE_PROCESS` |
| data[1], or data[5] with `CREATE_ARGV_ENV` | When `CREATE_MEMORY_MAX` is set: the child's memory max in pages, as for `CREATE_PROCESS` |
| the words after them | The name block: the file's install path (§ Image Verification) |
| cap[0] | File cap for the binary |
| cap[1] | Optional creator endpoint, copied into the child's `ProcessInfo.creator_endpoint_cap` |
| the cap before the argv/env cap, or before the relay without one, or last without either | When `CREATE_CHARGE_NODE` is set: the charge node's handle, as for `CREATE_PROCESS` |
| next-to-last cap, or last without a relay | When `CREATE_ARGV_ENV` is set: the argv/env Memory cap, as for `CREATE_PROCESS` |
| last cap | When `CREATE_DEATH_RELAY` is set: the death-relay cap, as for `CREATE_PROCESS` |

procmgr deletes the file cap once it has opened it, `FS_CLOSE`s and deletes its open once the object
is copied, whether the copy succeeds or fails, and deletes its copies of the creator endpoint, the
argv/env cap and the charge node's handle memmgr did not take, and any cap the layout does not name;
a request refused before the open deletes the file cap unopened. The death-relay cap is kept or
deleted as for `CREATE_PROCESS` (§ Label 1, **Death relay**), the file cap standing in for cap[0].

The file cap's server is the caller's to choose, so procmgr bounds each call it makes on the file
cap and on its open (`FS_OPEN`, `FS_READ_MEMORY`, `FS_RELEASE_MEMORY`, `FS_CLOSE`) at
`FILE_CAP_CALL_TIMEOUT_MS` (10 s): an `FS_OPEN` or a read the server has not answered by then fails
the create with `IO_ERROR`, as a refused one does, and an unanswered release or close is given up
as a failed one is. procmgr makes no further read of the file once one has failed or gone
unanswered, so a server that stops answering costs the create one such wait on its reads.

**Reply (success):** as for `CREATE_PROCESS` (data[0] the max the child's
budget node took, cap[0] process handle, cap[1] child `Thread` cap, and, with
`CREATE_DMA_HOLD`, cap[2] the release token),
including the destruction of a child whose reply caps cannot be delivered. A
failed creation releases what procmgr acquired for the child, its memmgr record
included, as for `CREATE_PROCESS`.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `INVALID_ELF` | The verified body's ELF validation or relocation failed (the TLS block's checks aside, see `OUT_OF_MEMORY`) |
| 2 | `OUT_OF_MEMORY` | procmgr's own `CSpace` is short of its headroom and its top-up was refused ([README.md](../README.md) § CSpace headroom), or memory-cap, kernel-object, or badge allocation failed, the copy of the object among them (a max too small for the child among its causes), the main thread's TLS block could not be built (an oversized or overaligned `PT_TLS`, or a mapping), the stack or IPC-buffer pages could not be mapped, or, with `CREATE_DMA_HOLD`, the room for the child's held reclaim or the derivation of its release token (the child, never started, is destroyed and its pages returned) |
| 7 | `INVALID_ARGUMENT` | No file cap, `file_size` zero, no name block or a name not in the canonical form (§ Image Verification), `CREATE_DEATH_RELAY`, `CREATE_ARGV_ENV` or `CREATE_CHARGE_NODE` set without a cap of its own, reserved label bits `[36..64]` set, `CREATE_PHYS_ACCESS` from a creator that is not phys-class (Label 1's **Physical-address flag**), a badge that names no live process or one a destroy has begun on before the reply delivers the child, a destroy that marked the child itself before the reply delivered it (§ Process Tree), `CREATE_MEMORY_MAX` without its data word, or `CREATE_RESERVE` from a creator outside the system reserve or with `CREATE_CHARGE_NODE` (Label 1's **Memory max and reserve**), the scheduling fields violate the resolution rules (band above the creator's ceiling, or priority above the resolved band), or the argv and env violate the rules of **argv and env** (§ Label 1) |
| 10 | `IO_ERROR` | The `FS_OPEN` of the file cap failed or went unanswered for `FILE_CAP_CALL_TIMEOUT_MS`, or the object's bytes did not all arrive: an `FS_READ_MEMORY` against procmgr's open failed, went unanswered for that long or returned zero bytes before `file_size`, its cache page could not be mapped, or its reply named a range past that page |
| 11 | `MAP_FAILED` | A copy frame or a segment could not be mapped |
| 12 | `INSUFFICIENT_RIGHTS` | Rights derivation failed during segment load |
| 14 | `ARGV_ENV_STILL_MAPPED` | As for `CREATE_PROCESS` (§ Label 1, **argv and env**) |
| 18 | `SIGNATURE_REFUSED` | As for `CREATE_PROCESS` (§ Image Verification) |

### Label 25: `BIND_DEATH_OBSERVER`

Bind the caller's event queue as a terminal-end death observer on the address space of the child a
process handle names, so the creator sees the first terminal fault or exit in any of the child's
threads, not only in the main thread its `Thread` cap observes. procmgr keeps the address space's
`Control` right, which binding such an observer needs
([docs/capability-model.md](../../../docs/capability-model.md#address-space) § Address Space), and
makes the bind on the creator's behalf. A creator may send it any number of times while the child
lives, before or after `START_PROCESS`, each with its own queue and correlator. devmgr uses it for
each driver it spawns, and svcmgr for each service it launches or restarts and for devmgr and vfsd,
whose process handles init endows.

**Request:**

| Field | Value |
|---|---|
| sent on | the child's process handle |
| data[0] | correlator: the word every post of this observer carries beside the exit reason |
| cap[0] | a cap on the observing `EventQueue` carrying `POST` |

procmgr binds the queue with `aspace_bind_notification` and deletes its copy of the cap on every
outcome, as it deletes any further cap. Once bound, the first terminal end of any thread of the
child, a fault or a `sys_aspace_exit`, posts the death entry `(exit reason, correlator)` to the
queue, once: a later end posts nothing ([syscalls.md](../../../core/kernel/docs/syscalls.md) §
`SYS_ASPACE_BIND_NOTIFICATION` (53)). A child that has already ended posts its retained reason at
once, so a bind that follows the end loses nothing. The binding takes one death-observer node of the
queue's pool until the child's address space is torn down (none when the bind follows the end). Only
a terminal end posts: `sys_thread_exit` posts only to the exiting thread's observers, and a teardown
(`DESTROY_PROCESS`, or procmgr's reap) posts to neither
([docs/process-lifecycle.md](../../../docs/process-lifecycle.md#exit-reason) § Exit reason). A fault
or `sys_aspace_exit` of the main thread that is its address space's first terminal end posts both to
this observer and to the main thread's observers; a later one posts only to the main thread's
observers.

**Reply:** label 0 (success), or an error code.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 2 | `OUT_OF_MEMORY` | The queue has no free death-observer node |
| 4 | `INVALID_BADGE` | The handle names no live process: it was torn down, or never created |
| 7 | `INVALID_ARGUMENT` | No cap, or a cap that is not an `EventQueue` cap carrying `POST` |
| 13 | `UNAUTHORIZED` | Not sent on a process handle: the child's own procmgr cap, or any other badge |

---

## Process Tree

procmgr records each process's **parent**: the process whose request created it, named by the
badge of the procmgr cap the create came on (the creator's own cap or the creator's handle on
it), or none for a child of the un-badged creator (init, or svcmgr's mint source). A create
reserves its child's badge with the creator recorded beside it, and the child's entry takes the
parent from that reservation when it is recorded. Every recorded parent names a live process. The
parent link is the session model's process tree
([docs/session-supervision.md](../../../docs/session-supervision.md#procmgr-mechanism)
§ procmgr Mechanism): a supervisor that destroys a process destroys everything it started.

- **Re-parenting.** When a process ends, by an exit or a terminal fault, each of its children, and
  each create it has in progress, takes the dead process's parent as its parent, which by the
  invariant is its nearest live ancestor, or none. A re-parented child loses its death relay
  (§ Label 1, **Death relay**). A child's memmgr budget node stays where it was made, so its pages
  still count in every ancestor's subtree usage.
- **Containment.** When a process created with `CREATE_CONTAIN` ends, by an exit, a fault or a
  destroy, procmgr destroys what is left of its subtree instead of re-parenting its children, as
  it does when the process's new parent is itself being destroyed. Re-parenting therefore never
  moves a process out of the subtree of a live contained ancestor.
- **Subtree destroy.** `DESTROY_PROCESS` (§ Label 8) and `DESTROY_CHILD` (§ Label 28) mark the
  process and every process below it, and every create one of them has in progress, in one hold of
  procmgr's table lock, then tear each marked process down, one per hold. From the mark on, procmgr
  refuses a create from a marked process with `INVALID_ARGUMENT`, as from a badge that names no live
  process, and a marked create's child is destroyed when it is built, its create refused the same
  way, so no process escapes the destroy by creating a child during it. A child built but whose
  create procmgr has not answered yet is its create's until the reply delivers its handle: procmgr
  makes that reply under its table lock, so a destroy marks the child either before it, when the
  create is refused the same way and the child destroyed without posting to the creator's relay, or
  after it, when the destroy tears the child down as any other. The destroy's reply can thus precede
  the teardown of a child no one had yet received, which never ran. `LIST_CHILDREN` lists no marked
  process, and `START_PROCESS` refuses one with `INVALID_BADGE`. Each destroyed process posts its
  end to its relay and end queue. A destroy of a process that has already ended, before procmgr
  reaped it, is that end's reap (§ Label 8).

### Label 27: `LIST_CHILDREN`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::LIST_CHILDREN` (27) |
| sent on | the process's handle; any other cap is refused with `UNAUTHORIZED` |
| `data[0]` | `0` to start the walk, `1` to resume after the badge in `data[1]` |
| `data[1]` | The cursor badge when `data[0]` is `1` |
| caps | none; procmgr deletes any cap the message carried |

Reply `SUCCESS` with `data[0]` = the page's count, then, for each child of the process above the
cursor in ascending badge order, `LIST_CHILDREN_WORDS_PER_ENTRY` (11) words: a `LIST_PROCESSES`
entry (its badge and its name, § Label 23), then the pages charged to its memmgr budget node and
every node below it (`procmgr_labels::pack_child_entry`, `unpack_child_entry`). A child is a
process whose parent the process is, by creation or by re-parenting, and no destroy has marked. A
page holds at most `LIST_CHILDREN_PAGE` (`(MSG_DATA_WORDS_MAX - 1) / 11` = 5) entries; a page
shorter than that ends the walk, as for `LIST_PROCESSES`. procmgr reads each child's subtree pages
after it releases its table lock, as `data[2]` of a memmgr `QUERY_MEMORY_USAGE` over a copy of
the memmgr SEND it holds for the child, which carries the child's memmgr badge
([memmgr IPC Interface](../../memmgr/docs/ipc-interface.md)); a child memmgr no longer knows, or a
failed query, reports `0`. Refusals: `INVALID_BADGE` when the handle names no live process;
`INVALID_ARGUMENT` for a `data[0]` other than 0 or 1.

### Label 28: `DESTROY_CHILD`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::DESTROY_CHILD` (28) |
| sent on | the parent's handle; any other cap is refused with `UNAUTHORIZED` |
| `data[0]` | The badge of one child of the process, as `LIST_CHILDREN` lists it |
| caps | none; procmgr deletes any cap the message carried |

Destroy the named child together with every process below it, as `DESTROY_PROCESS` destroys a
process (§ Label 8), a child that has already ended included. The check that the badge names a child
and the mark of its subtree are one hold of the table lock, so a re-parenting cannot move the child
out from under the check. The handle is the authority: its holder may already destroy the parent
with every process below it, and the badge only names one of its children. Replies `SUCCESS` once
the subtree is torn down, as `DESTROY_PROCESS` does; `INVALID_BADGE` when `data[0]` names no live
child of the process, a grandchild or a child a destroy has marked among them.

### Label 29: `REGISTER_END_QUEUE`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::REGISTER_END_QUEUE` (29) |
| caller's cap badge | The sender's own process badge (its `ProcessInfo.procmgr_endpoint_cap`); a process handle is refused (§ Messages) |
| `data[0]` | The correlator every post to the queue carries |
| cap[0] | A cap on an `EventQueue` carrying `POST`, the end queue |

The sender registers an end queue on itself. procmgr posts the process's end to it once, as the
entry `(reason, correlator)`, with the reason and at the point it posts to a death relay
(§ Label 1, **Death relay**): the exit reason or fault class at the reap, or the destroyed
process's reason after a destroy, whoever caused it. procmgr learns of every end, since it reaps
each process through its own death observers and makes each destroy, so the holder of the queue's
receive right learns of the end whoever caused it. A process registers one queue for its life:
procmgr refuses a second with `END_QUEUE_PRESENT`, so no process replaces the queue another
holder watches its end through. procmgr does not check the cap's type or rights: a cap that is no
`POST` cap on an event queue is kept as the queue, and the post to it fails. procmgr deletes caps
past cap[0], the queue of a refused request, and its copy of the queue once it has posted.
Replies `SUCCESS`; `INVALID_ARGUMENT` without a cap; `INVALID_BADGE` when the badge names no live
process or the request came on a process handle; `END_QUEUE_PRESENT` (19) when the process
registered a queue before. Telling another holder of one's own end confers no authority over
anything.

---

## Capability Transfer

Capability transfer uses the IPC message's cap slot array (up to 4 caps per
message). On `CREATE_PROCESS`, the caller's Memory cap is moved into procmgr's
CSpace atomically with the message delivery (as is the argv/env Memory cap of
either create label), per
[docs/ipc-design.md](../../../docs/ipc-design.md#capability-semantics-in-ipc)
§ Capability Semantics in IPC.
procmgr consumes the cap during
process creation and does not return it.

Every cap a request transfers lands in procmgr's CSpace, whether or not the
request's layout names it. procmgr deletes the caps a layout does not name
(caps past the last named position, and every cap of a label that names none:
`START_PROCESS`, `RELEASE_HOLD`, `DESTROY_PROCESS`, `QUERY_PROCESS`, `LIST_CHILDREN`,
`DESTROY_CHILD`, `INIT_TEARDOWN_DONE`, and unknown opcodes), and every cap of a refused request, a
refused `REGISTER_THREAD`'s thread cap among them, except the init-reap
refusals of an un-badged sender that keep caps init may still be running on
(§ `REGISTER_INIT_TEARDOWN`). A padded or refused request from any badged sender
therefore cannot grow procmgr's CSpace. Replies to the calls procmgr makes on a
caller-supplied file cap are treated the same way: procmgr deletes every reply
cap it does not use.

On a create reply, procmgr transfers a badged process handle endpoint (for
subsequent per-process operations), a derived copy of the child's `Thread`
capability (Control, Observe, and Upcall rights, `RIGHTS_THREAD`), and, for a
`CREATE_DMA_HOLD` child, its release token to the caller. procmgr retains the
original caps for process lifecycle management, and hands out no cap on the
child's address space: a creator observes the child's end through its death relay (§ Label 1,
**Death relay**), and its first terminal end through `BIND_DEATH_OBSERVER` (§ Label 25).

---

## REGISTER_DEATH_EQ — install logd's death queue

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::REGISTER_DEATH_EQ` (14) |
| caller's cap badge | MUST equal `procmgr_labels::DEATH_EQ_AUTHORITY` (`1 << 62`); svcmgr mints this badged `SEND\|GRANT` cap for real-logd on each launch, from the badge-0 `SEND\|GRANT` procmgr source init hands it at the handover (see the [svcmgr IPC interface](../../svcmgr/docs/ipc-interface.md)) |
| `caps[0]` | `EventQueue` cap with `POST` right; it needs no death-observer nodes, since nothing binds it |

Procmgr stores the cap in
[`process::LOGD_DEATH_EQ`](../src/process.rs), in place of the cap an earlier registration
stored, which it deletes. From that moment onward,
every teardown procmgr runs (`teardown_entry`: the reap of a death event, the
death resync, and `DESTROY_PROCESS`) posts the two-word death entry
`(exit_reason, process badge)` to it with `SYS_EVENT_POST`, the full `u64`
badge in the correlator word (`syscall::DeathEvent`), after the process's
objects are torn down. procmgr, not the kernel, is the source of logd's death
events: a worker thread's terminal fault that tears down its process reaches
logd too, and `DESTROY_PROCESS` posts the reason the kernel retained if the
process's main thread had already exited, else `EXIT_KILLED`. A process torn down
before the registration posts nothing. A post the full queue refuses
(`QueueFull`) is dropped, as the kernel drops a post to a full queue; logd's
full-drain resync recovers it.

Reply: `procmgr_errors::SUCCESS` once stored, `UNAUTHORIZED` if the
caller lacks `DEATH_EQ_AUTHORITY`, `INVALID_ARGUMENT` if no cap was
transferred. Each registration replaces the last, so a restarted logd's queue
takes every death after its registration, and the dead instance's queue no
more. The authority admits no other registrant: a badge is set once, so only
a holder of an un-badged source on procmgr's endpoint can mint it
([docs/capability-model.md](../../../docs/capability-model.md) § Kernel
guarantees), and svcmgr mints it for each logd launch alone. A forward holds
the queue's lock across its post, and a registration swaps the cap under the
same lock, so no post reaches a cap the registration then deletes
([README](../README.md) § Concurrency). procmgr writes no log line serving the
request: logd waits on the reply before its receive workers take the log
endpoint. procmgr deletes every cap a refused request carried, and any cap
past `caps[0]`.

logd derives a `POST`-only copy from its `RECV+POST` event queue
before sending — the kernel's cap-transfer moves the sent cap into
procmgr's CSpace (per
[docs/capability-model.md](../../../docs/capability-model.md#transfer) § Transfer),
so logd must retain `RECV` on its own copy to
keep `wait_set_add` and `event_try_recv` working.

---

## QUERY_LIVE_PROCESSES — list live process badges

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::QUERY_LIVE_PROCESSES` (18) |
| caller's cap badge | MUST equal `procmgr_labels::DEATH_EQ_AUTHORITY`, as for `REGISTER_DEATH_EQ`; a badge names a process handle, so the list is not public |
| `data[0]` | `0` to start the walk, `1` to resume after the badge in `data[1]` |
| `data[1]` | The cursor badge when `data[0]` is `1` |
| caps | none; procmgr deletes any cap the message carried |

Reply `SUCCESS` with `data[0]` = the page's count and `data[1..=count]` = the
badges of live processes above the cursor, ascending, at most
`LIVE_PROCESSES_PAGE` (`MSG_DATA_WORDS_MAX - 1` = 63). A page shorter than that
ends the walk; a full page is followed by a call resuming after its last badge.
A process that stays live across the whole walk is listed exactly once,
whatever spawns and deaths happen between pages. `UNAUTHORIZED` for any other
badge; `INVALID_ARGUMENT` for a `data[0]` other than 0 or 1.

Real-logd walks it to resync its slots after its death queue may have dropped a
post (see [logd IPC interface](../../logd/docs/ipc-interface.md) § Death-queue
resync), from a helper thread rather than its main thread.

---

## REGISTER_INIT_TEARDOWN — init reap handoff

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::REGISTER_INIT_TEARDOWN` (15) |
| `data[0]` | `1` on the first round (carrying kernel-object caps); `0` on subsequent donation rounds |
| `caps[0..]` | Round 1: 4 kernel-object caps (`AddressSpace`, `CSpace`, main `Thread`, init-logd `Thread`) — MOVED out of init's CSpace via IPC cap-transfer. Subsequent rounds: 1-4 reclaimable Memory caps per round (every reclaimable Memory cap init solely owns; the set is in [docs/process-lifecycle.md](../../../docs/process-lifecycle.md#init-reap) § Init reap). |

**Gate.** Labels 15 and 16 are accepted only on an un-badged cap
(`req.badge == 0`). Init holds one; the only other badge-0 holder is svcmgr,
whose `procmgr_death_auth_source` is a mint source for real-logd's
`DEATH_EQ_AUTHORITY` cap and a debug-authority holder's `DEBUG_AUTHORITY` cap (see the
[svcmgr IPC interface](../../svcmgr/docs/ipc-interface.md)), a trusted minter.
Every other process holds only SENDs on procmgr badged with a process badge (or
a badge svcmgr mints from its source), so none of them can stage a handoff or
hand procmgr caps to forward to memmgr's `DONATE_MEMORY_CAPS`. The handoff is
one-shot: once the reap has run, every further round and `INIT_TEARDOWN_DONE`
is refused. The gate is badge 0 rather than a verb bit
([docs/capability-model.md](../../../docs/capability-model.md) § Verb-bit
authority pattern) because the handoff's sender is init itself, which holds
procmgr's un-badged endpoint from before any badge is minted; a verb bit would
only add a badged cap for init to derive and for svcmgr's mint source to be
able to forge.

On the first round procmgr stores the kernel-object caps and binds a death
observer from its death queues (§ Process table and death queues of the
[README](../README.md#process-table-and-death-queues)) on both init threads
under the same correlator:
`deaths.bind_thread(main_thread, procmgr_labels::INIT_REAP_CORRELATOR)`
and the same call on `logd_thread`, expecting two deaths; the reap runs on the
second death. Either bind failing rejects the round with `INVALID_ARGUMENT`.
Subsequent rounds append to the donation Memory cap list. `INIT_TEARDOWN_DONE`
(label 16, no caps, no data words) closes the stream and arms the state machine.

Reply: `procmgr_errors::SUCCESS` on accept; `UNAUTHORIZED` from a badged sender;
`INVALID_ARGUMENT` when a first round arrives while a handoff is open or after
the reap, a first round carries other than 4 caps, either death-EQ bind fails,
or a donation round arrives before the first round or after the reap. procmgr
deletes the caps of a badged sender's round, and of any round refused after the
reap. The caps of an un-badged round refused before the reap stay in procmgr's
CSpace: they may be init's live `AddressSpace` or Memory
caps, which procmgr cannot delete while init's threads run on them or its
address space maps them.

## INIT_TEARDOWN_DONE — end-of-stream notification

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::INIT_TEARDOWN_DONE` (16) |
| caps | none |

Procmgr replies `SUCCESS` then arms the state machine, `UNAUTHORIZED` from a
badged sender, or `INVALID_ARGUMENT` when no handoff is open (none yet, or the
reap ran) or the state machine is already armed; it deletes any cap the message
carried. Init proceeds to `sys_thread_exit` immediately (per
[services/init/docs/bootstrap.md](../../init/docs/bootstrap.md#handover) § Handover).
Each death-EQ event with
`INIT_REAP_CORRELATOR` (reserved `u64::MAX`) calls
[`init_reap::run_reap`](../src/init_reap.rs), which counts the death and, on the
second, executes the six-step teardown (Threads → AddressSpace →
DONATE_MEMORY_CAPS → revoke and delete procmgr's CSpace capability, the last
reference to init's CSpace, which frees it and releases the caps init still holds →
log), whether or not `INIT_TEARDOWN_DONE` has armed the reap: a threadless init can
send no further round.
init-logd normally exits last, once real-logd's `HANDOVER_RELEASE` releases it;
procmgr never force-stops it. If the handover never completes, init-logd serves on
and init's caps stay held until shutdown — a benign hold, not a wedge (see the
[logd handover protocol](../../logd/docs/handover-protocol.md) § Failure modes).
The system-scope reap model is in
[docs/process-lifecycle.md](../../../docs/process-lifecycle.md) § Init reap.

## QUERY_INIT_REAP — init reap outcome

Wire format:

| Field | Meaning |
|---|---|
| label | `procmgr_labels::QUERY_INIT_REAP` (17) |
| caps | none |

Accepted on any procmgr cap, badged or not: it returns two words and changes no
state. Procmgr deletes any cap the message carried. Reply `SUCCESS` with:

| Field | Meaning |
|---|---|
| `data[0]` | `1` once the reap has run, `0` before |
| `data[1]` | The release probe's outcome: `INIT_REAP_PROBE_UNCHECKED` (0) before the reap, or when procmgr could not place the probe; `INIT_REAP_PROBE_RELEASED` (1) when deleting procmgr's CSpace capability freed init's CSpace; `INIT_REAP_PROBE_HELD` (2) when it did not |

The probe is an Endpoint procmgr retypes from a one-page memmgr grant and moves
into init's CSpace through its CSpace capability after the donation step and
before the revoke and delete. Freeing init's CSpace releases the endpoint, whose
bytes return to the grant, and nothing else retypes from or returns bytes to the
grant. procmgr reads the grant's `available_bytes` before the move and again after
the revoke and delete, re-reading with a yield between reads for up to 500 ms of
wall-clock time (a concurrent syscall pin on init's CSpace defers its free to the
pin's release, and a time bound outlasts a loaded scheduler that stretches each
yield). It
reports `RELEASED` once the value rose, and returns the page to memmgr
(`RELEASE_MEMORY_CAPS`); otherwise it reports `HELD` and keeps the page, which the
endpoint still backs. svctest's `init_cspace_released` phase asserts `RELEASED`.

Two callers read it. svctest's `init_cspace_released` phase reads both words. svcmgr calls it on
every restart of the log sink and relies on `data[0] = 1` being reported only after the reap has
run, which procmgr runs only once both init threads, init-logd among them, have exited; until then
svcmgr mints the restarted logd the handover SEND.

---

## Crash Endpoint and Debug Authority

procmgr creates one **crash endpoint** at startup, before any process, and holds it for its life.
At finalize it binds every child's main-thread exception class (`FAULT_CLASS_EXCEPTION`) to a SEND
on it badged with the child's process badge, whether or not the child is pinned; the runtime copies
the binding onto every thread the child spawns, and procmgr binds each thread that registers
(Label 22) again under a **crash badge** of the thread's own, so a fault message's badge names the
faulting thread: the process badge its main thread, or a thread that never registered and kept its
spawner's binding; a crash badge, which carries bit 63 (a bit of `ipc::VERB_BIT_MASK`, which no
process badge carries) and is unique for procmgr's life, the registered thread procmgr bound under
it. memmgr forwards each page fault it cannot back to
the same class (`FAULT_REPLY_FORWARD`), so the endpoint receives every fault that would kill a
procmgr-created process that has not declared itself undebuggable (Label 21), except a page fault of
a child created `CREATE_PINNED` or whose pager binding failed, which no pager forwards
([docs/fault-handling.md](../../../docs/fault-handling.md) § Crash Reports). A fault of a
restartable syscall's user copy, which the process survives, does not reach it either: the forward
of one is a decline. A failure to create the endpoint, or to bind a child, is logged and leaves the
class unbound; it never fails a creation.

While no crash service is registered, a procmgr thread of its own, the **decliner**, receives on
the endpoint and declines each fault with `FAULT_REPLY_KILL`, carrying the forwarder's reason for a
forwarded page fault (data word 4) and no reason for an exception: the fault takes the outcome it
has with no handler bound, and the kernel's decline line for a forwarded fault is the one the
pager's own decline printed. The decliner shares nothing with procmgr's request workers but a wake
notification, so a receive on the endpoint never waits behind a request.

Labels 19–21, 23, 24, 30 and 32 are the **debug authority**, label 22 the **thread registry** it
reads, and label 26 the **core-path declaration** its `ATTACH_PROCESS` reply reports.
`REGISTER_CRASH_SERVICE`, `ATTACH_PROCESS`, `LIST_PROCESSES`, `DETACH_PROCESS`, `MAKE_RESIDENT` and
`MAKE_PRIVATE` are served only on a badge carrying `procmgr_labels::DEBUG_AUTHORITY`, which svcmgr
mints, from the un-badged procmgr source init endows it, for a service whose definition sets
`debug_authority = yes` ([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md)); no
other path mints it, so an image that stages no such service has no attach path. The crash service
([services/crashd/README.md](../../crashd/README.md)) and the GDB stub
([services/gdbstub/README.md](../../gdbstub/README.md)) are its consumers.

### Label 19: `REGISTER_CRASH_SERVICE`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::REGISTER_CRASH_SERVICE` (19) |
| caller's cap badge | MUST carry `DEBUG_AUTHORITY` |
| `caps[0]` | A Thread cap of the service's main thread (any rights); further caps are deleted |

procmgr parks the decliner, keeps the thread cap, and replies `SUCCESS` with one cap, `RECV` on the
crash endpoint. The park is a message on the endpoint itself: the request worker serving the
registration calls the endpoint, un-badged and with a label no fault carries, and the decliner,
which receives it only after every fault queued ahead of it and declines those, answers it and waits
on its wake notification. The service then receives every fault on the endpoint. procmgr checks the
kept cap on every pass of its reaper, which the service's own death wakes, before it serves any
request, and after the teardown of a `DESTROY_PROCESS`, which posts no death ([README](../README.md)
§ Concurrency): once the cap is gone (procmgr's teardown of the service revokes every cap derived
from its main thread) or its thread has exited, procmgr deletes the cap and signals the decliner,
which receives again, declining the faults already queued. Replies: `UNAUTHORIZED` without the
authority; `INVALID_ARGUMENT` without a thread cap, or when procmgr has no crash endpoint;
`CRASH_SERVICE_PRESENT` while a registered service lives; `OUT_OF_MEMORY` when the `RECV` cap cannot
be derived or the park fails. A refused request's caps are deleted. A `SUCCESS` reply that cannot
deliver the `RECV` cap (the caller's `CSpace` cannot take it, or the caller is gone) registers
nothing: procmgr deletes the `RECV` cap and the kept thread cap and signals the decliner, as at the
take-back. svctest's `crash_endpoint` phase drives the registration, the refusal of a second one,
the handover, the take-back, and a registration after it.

### Label 20: `ATTACH_PROCESS`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::ATTACH_PROCESS` (20) |
| caller's cap badge | MUST carry `DEBUG_AUTHORITY` |
| `data[0]` | The target: its process badge, or a thread's crash badge as a fault message on the crash endpoint carries it |
| `data[1]` | The index of the first thread to return |
| `caps[0]` | Optional: the **debugger watch**, a Thread cap of the caller's own main thread, of any rights; further caps are deleted |

Reply `SUCCESS` with:

| Field | Meaning |
|---|---|
| `data[0]` | The number of threads in the target's list: its main thread, then each thread it registered (Label 22) that procmgr still holds |
| `data[1]` | The image's load bias |
| `data[2]`, `data[3]` | The biased start and end (exclusive) of the image's executable segments; both `0` for an image with none |
| `data[4]` | The address of the target's `ProcessInfo` page |
| `data[5]` | The target's process badge (`ATTACH_WORD_PROCESS_BADGE`) |
| `data[6]` | The list index of the thread `data[0]` names (`ATTACH_WORD_NAMED_THREAD`): `0`, the main thread, for a process badge; the registered thread bound under a crash badge; `ATTACH_NO_THREAD` (`u64::MAX`) when that thread is no longer listed |
| `data[7]` | The target's declarations and placement (`ATTACH_WORD_FLAGS`): `ATTACH_FLAG_NO_CORE` (bit 0) once it sent `DECLARE_NO_CORE` (Label 26); `ATTACH_FLAG_RESERVE` (bit 1) when its budget node is a system-reserve node (Label 1, **Memory max and reserve**); other bits `0` |
| caps | The Thread caps of threads `data[1]..`, each with `OBSERVE`, `CONTROL`, and `UPCALL`, at most `ATTACH_THREADS_PAGE` (`MSG_CAP_SLOTS_MAX`, 4); none past the count |

The list is the main thread at index 0, then the registered threads in registration order. Before
it replies, procmgr drops from the target's registry each thread that has exited or whose cap the
runtime revoked (its reclaim of a joined or reaped thread does), so no thread that exited before
the request is listed; a thread blocked on a fault has not exited and stays listed. A thread whose
cap the runtime revokes between that sweep and the derivation of the reply's caps is swept out and
the page derived again, in at most four derivations in all. The list can change between two calls
of a paged walk, as threads register and exit; the named thread's index is the one in the reply
that carries it, and a caller that needs that thread's cap from a later page reads `data[6]` of
that page's reply too. The caps are derivations of procmgr's own; procmgr's teardown of the target,
and the runtime's reclaim of a registered thread, revoke them. A debugger that binds a listed
thread's exception or upcall class MUST bind it under a badge carrying
`procmgr_labels::DEBUGGER_BADGE_TAG` (bit 62) with bit 63 clear: the **debugger tag**, by which
procmgr tells a debugger's binding from its own crash bindings (the process badge `data[5]` returns,
and the crash badges, bit 63) and from a handler the target bound itself (§ Label 22, § Label 24).

A debugger that rebinds the target's threads sends the watch with its first request. When the attach
succeeds, procmgr keeps the watch as the target's debugger, replacing, and deleting, the one an
earlier attach left; a watch that is not a Thread cap, or that a refused attach carried, is deleted.
procmgr holds the watch before it sends the reply, so a debugger that binds the target's threads and
dies as soon as it has its reply is found gone by the next check below. An attach whose reply cannot
deliver its caps (the caller's `CSpace` cannot take them, or the caller is gone) has not succeeded:
procmgr deletes the caps derived for it and the watch, and keeps the earlier one.
procmgr reads the watched thread's state on every pass of its reaper, which a process's death
wakes, before it serves any request, and after every `DESTROY_PROCESS`: once the thread has exited,
or its cap went with its process's teardown, procmgr logs `debugger gone; crash bindings restored`
and restores the target's crash bindings as `DETACH_PROCESS` does
(Label 24). So a debugger that dies attached leaves no thread of its target bound to an endpoint no
one receives on: a fault the target takes meanwhile waits there, and the restore delivers it again
to the crash endpoint ([docs/fault-handling.md](../../../docs/fault-handling.md) § Delivery, Resume,
and Kill, Rebind), and an upcall the debugger posted is dropped and its thread resumes. A thread the
target spawned while the debugger's binding was on its spawner copies that binding: when it
registers after the restore, procmgr binds it back then, and when its registration is refused at the
registry's bound or for procmgr's heap, at the refusal, under the process badge (§ Label 22). A
thread whose registration never reached procmgr, its cap derivation or its IPC buffer having
failed, the kernel having cancelled its call before procmgr received it, or its runtime having
stopped registering after a `NOT_ATTACHABLE` refusal, keeps the binding it copied, which procmgr
cannot reach. The target's `DECLARE_NO_DEBUG` deletes the watch (§ Label 21). The restore cannot
undo the dead debugger's own changes to the target, a breakpoint it planted among them. procmgr
only reads the watched thread's state, which takes no right.

`data[5]` to `data[7]`, the crash-badge form of `data[0]`, and the watch extend the reply and the
target's domain without changing what an earlier request means: a request that carries no cap is
answered as before, a request naming a process badge means what it meant, and a caller that
reads only `data[0]` to `data[4]` and pages from index 0 sees the main thread first, as before,
with the registered threads after it. Refusals, in order: `UNAUTHORIZED` without the authority;
`INVALID_BADGE` when no live process carries the badge, or no registered thread of a live process
the crash badge, which covers init, memmgr, and procmgr, none of which procmgr created;
`NOT_ATTACHABLE` when the target declared itself undebuggable (Label 21); `OUT_OF_MEMORY` when the
cap of a thread still listed cannot be derived, or threads keep going through four derivations of
the page, the caps already derived for the reply then deleted. The refusal order is
`process_table::attach_target`.

### Label 21: `DECLARE_NO_DEBUG`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::DECLARE_NO_DEBUG` (21) |
| caller's cap badge | The sender's own process badge (its `ProcessInfo.procmgr_endpoint_cap`); a process handle is refused (§ Messages) |
| caps | none; procmgr deletes any cap the message carried |

The sender declares itself undebuggable: procmgr marks it; deletes the debugger watch an attach left
(Label 20), so no debugger's death binds it back; unbinds the exception class of its main thread and
of every thread it registered (Label 22) wherever procmgr bound it (under the process badge or a
crash badge) or a debugger did (under the debugger tag, Label 20), and the upcall class wherever a
debugger bound it, leaving a handler the process bound itself; releases the registered threads; and
refuses `ATTACH_PROCESS` and `REGISTER_THREAD` on it from then on. A debugger attached at the
declaration loses its bindings on the threads procmgr holds, the watch, and the registered threads'
caps its attach was given, which procmgr revokes. The main thread's cap it was given keeps its
rights, since procmgr cannot revoke it without revoking the creator's: such a debugger can still
stop that thread and bind its classes, and nothing binds back what it binds after the declaration.
A process sends it before it spawns a thread: a thread spawned before that copies its spawner's
binding, and the declaration reaches it only once it is registered. One whose registration reaches
procmgr after the declaration is unbound then (Label 22). One procmgr does not hold at the
declaration, its runtime having sent no registration, or its registration having been refused at
the registry's bound or for procmgr's heap, keeps a binding: the one it copied, or procmgr's under
the process badge when that was a debugger's (Label 22).
The senders are the processes a stop of which would hold a debug-authority holder, which waits on
them for its own progress: the debug port's virtio-console driver, through which the GDB stub
reaches its host for every packet, and every debug-authority holder, so none attaches to itself.
logd does not declare: every log call to it is bounded, so a holder that stops it waits on its own
log output for at most that bound. Nor do the serial and framebuffer drivers: no thread of logd's
but a sink's own writer waits on either for longer than `SINK_STALL_MS`
([logd IPC interface](../../logd/docs/ipc-interface.md#output-sinks) § Output sinks). Replies
`SUCCESS`, or `INVALID_BADGE` when the badge names no live process or the request came on a
process handle.

Any process may declare itself, on its own cap alone: the badge names the sender, and the process
handle its creator holds carries `procmgr_labels::PROCESS_HANDLE_TAG`, on which procmgr refuses the
request (§ Messages), so a declaration affects the declarer and no other process, apart from
another process's thread the declarer registered (Label 22), whose crash or debugger binding is
unbound with the declarer's own since procmgr tells a binding by its badge alone; and it removes no
authority a debug-authority holder needs over another. It is one-way: nothing makes a declared
process debuggable again for its life. No restore of another process's crash bindings (Label 24)
binds a thread of a declared process back to the crash endpoint, whichever registry lists it,
unless that registry's process registered it as its own, as procmgr can take it to be (Label 22). A
process that holds a cap of a declared process's thread, as its creator holds the main thread's, can
still register that thread in its own registry (Label 22), and so list it to a debugger attached to
that process, which gains on it the `CONTROL` the cap's holder already has.
Until it declares, a process is bound and attachable like any other: a fault of one of those
drivers between its creation and its declaration, which each sends before its bootstrap, reaches
the crash service, whose log output then waits on the faulting process until the crash service's
watchdog bound ([crashd Operation](../../crashd/docs/operation.md) § Bounds) declines
the fault.

### Label 22: `REGISTER_THREAD`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::REGISTER_THREAD` (22) |
| caller's cap badge | The sender's own process badge (its `ProcessInfo.procmgr_endpoint_cap`); a process handle is refused (§ Messages) |
| `caps[0]` | A Thread cap with `OBSERVE`, `CONTROL`, and `UPCALL` (`RIGHTS_THREAD`); further caps are deleted |

The sender hands procmgr a cap of one of its threads, which procmgr keeps in the process's registry
until the thread exits, the cap is revoked, or the process is torn down; `ATTACH_PROCESS` lists it.
The runtime sends it from each thread it spawns, before the thread runs its code, with a copy of
the thread's own cap ([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Thread
registration). When the thread's exception class is bound under the sender's process badge or under
a crash badge, any badge with bit 63 set, as a thread that copied its spawner's bindings is
(whether or not that spawner is still registered), procmgr binds it again under a fresh crash
badge. So it does when the class is bound under the debugger tag (Label 20) while the process has
no debugger watch: the thread copied a debugger's binding from its spawner, and that debugger has
since detached or died; procmgr then also unbinds the upcall class a debugger bound on it. A
debugger's binding while a watch is held, a binding of another handler, or none, is left, and the
thread is then listed without a crash badge. procmgr reads the binding's badge, which
`SYS_THREAD_GET_FAULT_HANDLER` returns, not its endpoint, so it tells its own binding and a
debugger's by the badge alone: a debugger binds under the debugger tag (Label 20), and a handler a
process binds on its own threads under a badge that carries neither bit 62 nor bit 63, or procmgr
takes it for a debugger's or its own.

Before it adds the thread, procmgr drops from the registry the threads that have exited or whose cap
was revoked, when the registry has reached the count its last sweep set (64 at first, then twice
what the sweep kept, at least 64), or the bound when that count lies past it, and at least half as
many registrations as it holds, refused ones included, came since the last sweep. A sweep therefore
comes after at least half as many requests as threads it reads, so the sweeps cost at most two
thread-state reads per request on average, and threads that are gone hold the bound for at most
half a registry's worth of requests.

The registry holds at most `procmgr_labels::REGISTERED_THREADS_MAX` (16384) threads per process
([docs/limits.md](../../../docs/limits.md) § Shared IPC and protocol crates); past it a thread runs
unregistered, so no spawn fails for the bound. A thread refused there, for procmgr's heap, or while
procmgr's own `CSpace` is short of its headroom, that carries a binding under the debugger tag, a
watched debugger's included, is bound back to the crash endpoint under the process badge at the
refusal, with a debugger's upcall binding unbound, since no attach lists an unregistered thread and
no restore reaches it. procmgr does not compare a
registration against the threads it holds: a thread registered twice takes two entries, both
counting toward the bound, and the runtime registers each thread once: it does not repeat a call
that failed, since the kernel can cancel a call with `Interrupted` after procmgr received it and
carried it out, so the runtime cannot tell such a thread registered or not
([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Thread registration).

procmgr does not check that the thread runs in the sender's address space, which no kernel query
gives: a sender can register only a thread it holds `CONTROL` on, which already lets it read and
change that thread. It records with each thread whose it is, as the binding shows before procmgr
rebinds it, and a restore binds the thread back by that record alone (Label 24). The sender's own,
as far as procmgr can tell: its process badge, the debugger tag, a crash badge no live registry
lists, or a crash badge its own registry lists on a thread recorded as its own, so the record
carries through a thread that copied a binding procmgr gave. Another live process's: that process's
badge, which procmgr leaves on the thread (that process's main thread, or a thread that copied it
and has not registered yet), and under which no restore binds it, since any process can bind a
thread of its own under that badge value on an endpoint of its own (Label 24). Unknown: a crash
badge another live registry lists, or the sender's lists on a thread not recorded as its own,
another handler's badge, or none. A thread bound under a crash badge is rebound into the sender's
registry whoever listed it: its faults then reach the crash service under a crash badge the sender's
process holds, and are reported against the sender's image; the other process's `DECLARE_NO_DEBUG`
still unbinds it while that process's registry holds it, since the declaration unbinds any crash
badge (Label 21), and no restore of the sender's binds it back unless it is recorded as the sender's
own. One bound under the debugger tag while the sender has no debugger watch is rebound into the
sender's registry too, whichever process's debugger bound it, since procmgr cannot tell; the
sender's declaration (Label 21) and restore (Label 24) likewise treat a debugger's binding on such a
thread as one on the sender's own, and procmgr records the thread as the sender's, as it does one
under a crash badge no live registry lists, so a restore of the sender's binds it back to the crash
endpoint even once its own process has declared itself undebuggable (Label 21). Such a cap comes
from the other process itself, from a debug-authority holder's attach, or, for the other process's
main thread alone, from its creation (`CREATE_PROCESS` and `CREATE_FROM_FILE` give the creator that
cap), whose binding is its process badge, which procmgr does not rebind and records as that
process's, none once that process has declared itself undebuggable, the debugger tag while a
debugger attached to that process holds it, a crash badge another registry put on it, or any binding
the cap's holder sets with its `CONTROL`. So no process gains this over a spawned thread it was not
given. No restore of the creator's binds a declared child's main thread back (Label 24) unless one
of the creator's registrations of it recorded it as the creator's own, since procmgr records each
registration by the binding it then shows: the creator's process badge, the debugger tag, a crash
badge no live registry lists, or a crash badge the creator's registry lists on a thread recorded as
its own. The creator can bring any of these about itself before it registers the thread: by binding
it to its own procmgr cap, or under a badge that carries the debugger tag, or by copying onto it the
binding of one of its own registered threads (`SYS_THREAD_INHERIT_FAULT_HANDLER`). That gives it
nothing over the thread its `CONTROL` does not already give, since that cap lets it bind the
thread's exception class to a handler of its own. A restore of the creator's leaves the child's main
thread unbound when the creator's registration found it under the child's badge and a debugger then
bound it (Label 24).

Replies `SUCCESS`; refusals, in order: `INVALID_BADGE` when the badge names no live process, or the
request came on a process handle (§ Messages);
`NOT_ATTACHABLE` when the process declared itself undebuggable (Label 21), after procmgr unbinds
the thread as the declaration unbinds the declarer's threads, and on which the runtime sends no
further registration; `INVALID_ARGUMENT` without a Thread cap carrying `RIGHTS_THREAD`;
`THREAD_LIMIT` at the bound, after any sweep due; `OUT_OF_MEMORY` when procmgr's heap cannot hold
the entry, or when procmgr's own `CSpace` is short of its headroom and its top-up was refused
([README.md](../README.md) § CSpace headroom). A refused request's caps are deleted.

### Label 23: `LIST_PROCESSES`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::LIST_PROCESSES` (23) |
| caller's cap badge | MUST carry `DEBUG_AUTHORITY` |
| `data[0]` | `0` to start the walk, `1` to resume after the badge in `data[1]` |
| `data[1]` | The cursor badge when `data[0]` is `1` |
| caps | none; procmgr deletes any cap the message carried |

Reply `SUCCESS` with `data[0]` = the page's count, then, for each live process above the cursor in
ascending badge order, `LIST_PROCESSES_WORDS_PER_ENTRY` (10) words: its process badge, its name's
length in bytes, and the name in eight words, little-endian and zero-padded
(`procmgr_labels::pack_list_entry`, `unpack_list_entry`). A page holds at most
`LIST_PROCESSES_PAGE` (`(MSG_DATA_WORDS_MAX - 1) / 10` = 6) entries; a page shorter than that ends
the walk, and a full page is followed by a call resuming after its last badge. A process that stays
live across the whole walk is listed exactly once, as for `QUERY_LIVE_PROCESSES`; a cursor whose
process died resumes at the next badge above it.

A process's name is the first string of the argv its creator passed (`CREATE_ARGV_ENV`), up to
its NUL, truncated to `svcmgr_labels::NAME_MAX` (64) bytes, or empty for a process created
without argv. For a service it is the first word of its recipe's `argv`; devmgr, vfsd and svcmgr,
which init creates, carry their service name. procmgr records it at
creation and never changes it. It is a label the creator chose, not an identity: two processes can
share one, and a debugger that looks a process up by name takes the first match in badge order.
The walk lists every live process procmgr created, those that declared themselves undebuggable
(Label 21) among them, which then refuse the attach. Refusals: `UNAUTHORIZED` without the
authority; `INVALID_ARGUMENT` for a `data[0]` other than 0 or 1. The GDB stub walks it to find the
process its host names ([services/gdbstub/README.md](../../gdbstub/README.md)).

### Label 24: `DETACH_PROCESS`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::DETACH_PROCESS` (24) |
| caller's cap badge | MUST carry `DEBUG_AUTHORITY` |
| `data[0]` | The target's process badge |
| caps | none; procmgr deletes any cap the message carried |

procmgr hands the target's crash bindings back after a debugger's attach. It binds the main thread
to the crash endpoint again under the process badge when its exception class is bound under the
debugger tag (Label 20), is unbound, or is bound by procmgr under another badge. A registered thread
(Label 22) it restores by whose thread it recorded at the registration
(`process_table::ProcessTable::restore_action`):

- The target's own, by the main thread's rule: when its class is bound under the debugger tag, is
  unbound, or is bound by procmgr under a badge other than the thread's crash badge, it binds again
  under that crash badge, minting one for a thread that has none (one that registered while the
  debugger's binding was on it, which a registration leaves).
- Any other, another process's left under that process's badge at the registration among them:
  never bound to the crash endpoint, and a debugger's binding on it is unbound. procmgr reads a
  binding's badge, not its endpoint, and any process can bind a thread of its own under any badge
  value on an endpoint of its own, so no restore binds a thread under a badge its registration
  showed, which would report that thread's faults against the process the badge names
  ([docs/fault-handling.md](../../../docs/fault-handling.md) § Security). Such a thread may be a
  declared process's, one that a third registry rebound before the target registered it among
  them, so no restore binds a thread procmgr did not record as the target's own back for a declared
  process. Another process's thread that procmgr left under that process's badge, as the target's
  registration of its child's main thread leaves it, and whose binding a debugger then replaced, is
  therefore left unbound, and its faults are unhandled from then on.

A thread bound to any other handler is left: one the target bound itself, or another process's
thread bound under that process's own badge. Since procmgr tells whose a thread is by its binding at
the registration, another process's thread that then carried the target's process badge, the
debugger tag, or a crash badge no live registry lists, directly or through the target's own earlier
record of it, is restored as the target's own (Label 22). procmgr also unbinds each listed thread's
upcall class that is bound under the debugger tag, and deletes the debugger watch the attach left
(Label 20). A thread whose bind fails keeps the binding it has, as does each thread that needs a
fresh crash badge when procmgr's heap cannot hold them, which procmgr logs; a failure to bind the
main thread is logged. procmgr rebinds over the debugger's binding, so no thread it binds back is
unbound meanwhile, and a fault in flight under the debugger's binding is delivered again to the
crash endpoint; on a thread whose debugger's binding it unbinds instead, such a fault is unhandled;
an upcall pending under the debugger's binding is dropped and its thread resumes (§ Delivery,
Resume, and Kill, Rebind, and § Asynchronous Upcalls, in
[docs/fault-handling.md](../../../docs/fault-handling.md)). A debugger holds no SEND on the crash
endpoint, so it cannot restore those bindings itself: it writes back the text it changed and resumes
the threads it held, then sends this, and then unbinds any other class it bound. procmgr restores
the bindings the same way, unasked, when the watched debugger thread has exited. A declared process
(Label 21) is never bound back: the declaration deleted its watch, and this request refuses it.

procmgr restores its own crash bindings, not what the attach found: a handler the target bound on
a thread's exception class itself, which the debugger's bind replaced, is not bound back. The main
thread, and a registered thread recorded as the target's own (Label 22), the target having bound
its handler after the registration, are bound to the crash endpoint instead, and their faults reach
it from then on. A registered thread that carried the target's handler when the target registered it
is recorded unknown, so the debugger's binding on it is unbound, and its faults are unhandled from
then on (§ Reply in [docs/fault-handling.md](../../../docs/fault-handling.md)). procmgr binds no
other class, so the target's own handler of another class the debugger bound over is not bound back
either.

Replies `SUCCESS`; refusals, in order: `UNAUTHORIZED` without the authority; `INVALID_BADGE` when
no live process carries the badge (a thread's crash badge names no process here); `NOT_ATTACHABLE`
when the target declared itself undebuggable (Label 21). The refusal order is
`process_table::detach_target`. svctest's `crash_endpoint` phase drives a `LIST_PROCESSES` walk to
a process it attached to, this request's restore of a registered thread whose exception and upcall
classes it rebound, and the same restore once an attach's watch thread exits.

### Label 26: `DECLARE_NO_CORE`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::DECLARE_NO_CORE` (26) |
| caller's cap badge | The sender's own process badge (its `ProcessInfo.procmgr_endpoint_cap`); a process handle is refused (§ Messages) |
| caps | none; procmgr deletes any cap the message carried |

The sender declares itself on the **core path**, the processes a core dump waits on: the crash
service writes a core to `/crash` through vfsd, the filesystem driver of the root partition, the
block driver beneath it, devmgr, which maps each transfer's buffer on its DMA endpoint, and the
IOMMU driver devmgr installs those mappings through, and logs the dump's outcome through logd, which
every process's log output waits on too ([crashd Operation](../../crashd/docs/operation.md) § Core
Dump). A dump stops every thread of its process but the faulting one, so a core of one of them would
wait on the process it describes. procmgr marks the sender, and every `ATTACH_PROCESS` reply for it
from then on carries `ATTACH_FLAG_NO_CORE` in `data[7]` (Label 20); the crash service writes no core
of a process whose reply carries it, and still reports the fault in the log. The mark changes
nothing else: the process stays attachable and bound to the crash endpoint. It is one-way for the
process's life. A repeat is answered as the first. Replies `SUCCESS`, or `INVALID_BADGE` when the
badge names no live process or the request came on a process handle.

The duty falls on every process a dump can wait on: vfsd, each filesystem driver, each block driver,
devmgr, and each IOMMU driver, which each send the declaration at startup, before they serve a
request, and logd, which sends it before it spawns a thread. A new storage or IOMMU driver sends it
too, as the driver-authoring rules require ([Driver Model](../../drivers/docs/driver-model.md) §
Adding a Driver). A process that faults before its declaration reaches procmgr is dumped like any
other, and its dump's wait on it ends at the crash service's dump bound ([crashd
Operation](../../crashd/docs/operation.md) § Bounds), as does the wait of a dump that blocks on a
process that never declared. A process can declare itself only, so the declaration removes no core
of another process. Its mark leaves out a core of the declarer alone, which holds nothing of another
process.

### Label 30: `MAKE_RESIDENT`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::MAKE_RESIDENT` (30) |
| caller's cap badge | MUST carry `DEBUG_AUTHORITY` |
| `data[0]` | The target's process badge |
| `data[1]` | The first address of the range |
| `data[2]` | The range's length in bytes, nonzero |
| caps | none; procmgr deletes any cap the message carried |

`SYS_THREAD_READ_MEM` fails with `InvalidAddress` on a page that is not present and does not ask the
pager ([core/kernel/docs/syscalls.md](../../../core/kernel/docs/syscalls.md) §
`SYS_THREAD_READ_MEM`), and memmgr evicts cold pages of a demand-paged process into its compressed
store under memory pressure
([services/memmgr/docs/memory-pool.md](../../memmgr/docs/memory-pool.md#eviction) § Eviction). A
debugger that gets that failure on a page asks for its range here and retries: procmgr finds the
target under the table lock and, after it, sends memmgr its `MAKE_RESIDENT` with the target's memmgr
badge ([services/memmgr/docs/ipc-interface.md](../../memmgr/docs/ipc-interface.md) § Label 21).
memmgr restores the evicted chunks the range meets, a bounded number per request; a page no fault
has backed stays not present, so the retry fails again on it. A chunk on disk memmgr asks the swap
service to restore, and replies pending at it; a lost chunk, or one on disk with no swap service to
ask, it passes over, and the retry fails on its pages too
([services/memmgr/docs/memory-pool.md](../../memmgr/docs/memory-pool.md#disk-tier) § Disk tier). A
process that declared itself undebuggable (Label 21) is served too: the request reads and writes
nothing of the target, and only does what the target's own next touch of the pages would.

Replies `SUCCESS` with `data[0]` the address memmgr stopped at, memmgr's reply word: the range's end
when the whole range is done, else the address the caller asks again from, with the rest of the
range; `data[1]`, memmgr's word 1: `memmgr_labels::RESIDENT_PENDING` when that address is a
chunk on disk the swap service was asked to restore, else `0`; and `data[2]`, memmgr's word 2,
where its walk stopped. `ipc::make_resident` asks until it is done, pausing
`ipc::PENDING_PAUSE_MS` (2 ms) before each request after a pending reply; after
`ipc::PENDING_TRIES` (500) pauses in all, about a second, it asks on from `data[2]` with no pause,
the chunks on disk it passes over staying not present, and returns `false`. Refusals, in order:
`UNAUTHORIZED` without the authority; `INVALID_BADGE` when no live process carries the badge;
then memmgr's: `INVALID_ARGUMENT` for a zero length or a range past the address space, and
`OUT_OF_MEMORY` when memmgr could not restore a chunk of the range or the call to it failed.
svctest's `memmgr_swap` phase reads a page of an evicted chunk this way.

### Label 31: `READ_VERIFIED`

Read a signed data file for the sender and give it the verified body read-only
([docs/signing.md](../../../docs/signing.md) § Verifier Discipline): the request a process makes
before it parses a file it reads from the root filesystem as trusted input. Its client is
`std::os::seraph::read_verified`.

| Field | Meaning |
|---|---|
| label | `procmgr_labels::READ_VERIFIED` (31) |
| caller's cap | The sender's own procmgr cap (`ProcessInfo.procmgr_endpoint_cap`) |
| `data[0]` | The file's length in bytes, from the caller's `NS_LOOKUP` size hint: 1 to `procmgr_labels::READ_VERIFIED_MAX` (32 KiB) |
| from `data[1]` | The name block (`procmgr_labels::READ_VERIFIED_NAME_WORD`): the install path the file must be signed under, in the canonical form of § Image Verification |
| cap[0] | File cap for the file |

procmgr serves it as follows:

1. **Checks.** A request with no file cap, a length of zero or past `READ_VERIFIED_MAX`, or no name
   block or a name that is not a canonical install path is refused with `INVALID_ARGUMENT` before
   procmgr opens the file. A request sent on a process handle, which names another process, is
   refused with `INVALID_BADGE` (§ Messages), as is one whose badge names no live process. Every cap
   past cap[0] is deleted at once.
2. **The account.** Under the table lock procmgr derives a copy of the sender's memmgr SEND from its
   table entry, so the copy is charged to the sender: its budget bounds it, and a teardown of the
   sender that deletes the entry's slot meanwhile cannot hand the request another cap. A sender
   procmgr registered with no memmgr SEND is refused with `OUT_OF_MEMORY`.
3. **One copy.** With no lock held, procmgr opens the file (`FS_OPEN`), reads it once, `[0,
   length)`, one `FS_READ_MEMORY` at a time, into one run of frames it requests on the sender's
   account (`REQUIRE_CONTIGUOUS`) and maps in its own address space alone, and closes it, as
   `CREATE_FROM_FILE` reads an image (§ Label 13, its bounds on every call on the file cap
   included). The file cap is deleted on every path.
4. **Verify.** procmgr verifies the copy against the trust store in the data role alone, under the
   requested name, for this build's architecture. A refusal replies `SIGNATURE_REFUSED` and logs one
   warning naming the name and the verifier's reason, as an image's does; the run returns to the
   sender's account.
5. **Hand over.** procmgr derives a Memory cap on the run carrying `RIGHTS_MEM_MAP` alone, unmaps
   the run from its own address space and deletes its own cap, so no process but memmgr holds a cap
   that can write it, and replies with the derived cap. A reply the sender cannot take (it is gone,
   or its `CSpace` is full) leaves the cap with procmgr, which deletes it and releases the run to
   the sender's account.

**Reply (success):** `data[0]` the verified body's length, the body being the run's first
`data[0]` bytes; `data[1]` the run's region id on the sender's account; `data[2]` its pages;
cap[0] the map-only Memory cap. The sender maps it read-only and parses only the body. When it is
done it unmaps the run, deletes the cap and names the region to memmgr's `RELEASE_MEMORY_CAPS` on
its own memmgr cap; its death releases the run with its record.

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 2 | `OUT_OF_MEMORY` | The run could not be had on the sender's account (a max too small for it among the causes), the sender has no memmgr SEND, or the map-only cap could not be derived |
| 4 | `INVALID_BADGE` | Sent on a process handle, or no live process carries the badge |
| 7 | `INVALID_ARGUMENT` | No file cap, a length of zero or past `READ_VERIFIED_MAX`, or no name block or a name not in the canonical form |
| 10 | `IO_ERROR` | As for `CREATE_FROM_FILE` (§ Label 13) |
| 11 | `MAP_FAILED` | The run could not be mapped in procmgr, or its mapping would not come down |
| 18 | `SIGNATURE_REFUSED` | The copy does not verify in the data role under the name |

svctest's `procmgr_read_verified` phase reads its data-role fixture back and checks the copy's
charge, and the refusal of the fixture under another name, of a copy with a flipped byte, of an
unsigned file, of a file past the bound and of a zero length.

### Label 32: `MAKE_PRIVATE`

| Field | Meaning |
|---|---|
| label | `procmgr_labels::MAKE_PRIVATE` (32) |
| caller's cap badge | MUST carry `DEBUG_AUTHORITY` |
| `data[0]` | The target's process badge |
| `data[1]` | The first address of the range |
| `data[2]` | The range's length in bytes, nonzero |
| caps | none; procmgr deletes any cap the message carried |

A text write of `SYS_THREAD_WRITE_MEM` fails with `InvalidState` on a read-only page whose frame
another leaf maps too ([docs/fault-handling.md](../../../docs/fault-handling.md) § Debugging), as
every page of a memory-object attachment that still maps its object's frame does: memmgr keeps its
own view of every object frame, so a process cannot patch text others map
([services/memmgr/docs/memory-pool.md](../../memmgr/docs/memory-pool.md#memory-objects) § Memory
objects). A debugger that gets that failure asks for the page's range here and writes again: procmgr
finds the target under the table lock and, after it, sends memmgr its `MAKE_PRIVATE` with the
target's memmgr badge ([services/memmgr/docs/ipc-interface.md](../../memmgr/docs/ipc-interface.md) §
Label 30), which gives each such page of the range a copy of its own, a bounded number per request;
the write then patches the target alone. A page outside every attachment, or with a copy already, is
passed over.

Replies `SUCCESS` with `data[0]` the address memmgr stopped at, memmgr's reply word: the range's end
when the whole range is done, else the address the caller asks again from, with the rest of the
range. `ipc::make_private` asks until it is done. Refusals, in order: `UNAUTHORIZED` without the
authority; `INVALID_BADGE` when no live process carries the badge; `NOT_ATTACHABLE` for a process
that declared itself undebuggable (Label 21), whose memory no debugger may write, so a copy would
only cost it pages; then memmgr's: `INVALID_ARGUMENT` for a zero length or a range past the address
space, and `OUT_OF_MEMORY` when memmgr could not make a copy or the call to it failed.
svctest's `memmgr_memory_object_text` phase makes a child's executable attachment private this way
before it writes a breakpoint into it, and checks the refusals without the authority and for
svctest itself.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-design.md](../../../docs/ipc-design.md) | IPC message format, cap transfer protocol |
| [docs/process-lifecycle.md](../../../docs/process-lifecycle.md) | System-scope creation order; procmgr's role and authority boundary with memmgr |
| [abi/process-abi](../../../abi/process-abi/README.md) | ProcessInfo handover struct |
| [abi/syscall](../../../abi/syscall/README.md) | Syscall numbers and register conventions |
| [services/memmgr/docs/ipc-interface.md](../../memmgr/docs/ipc-interface.md) | Memory-cap allocation IPC |

---

## Summarized By

[Kernel Cross-Boundary Disclosure Inventory](../../../core/kernel/docs/cross-boundary-disclosure.md),
[Scheduler Internals](../../../core/kernel/docs/scheduler.md),
[Capability Model](../../../docs/capability-model.md),
[Device Management](../../../docs/device-management.md),
[Fault Handling](../../../docs/fault-handling.md),
[Namespace Model](../../../docs/namespace-model.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[Session Supervision](../../../docs/session-supervision.md),
[runtime/ruststd/README.md](../../../runtime/ruststd/README.md),
[crashd Operation](../../crashd/docs/operation.md),
[devmgr Responsibilities and Capabilities](../../devmgr/docs/responsibilities.md),
[Driver Model](../../drivers/docs/driver-model.md),
[services/drivers/virtio/console/README.md](../../drivers/virtio/console/README.md),
[services/gdbstub/README.md](../../gdbstub/README.md),
[init Bootstrap Stages](../../init/docs/bootstrap.md),
[services/logd/README.md](../../logd/README.md),
[logd IPC interface](../../logd/docs/ipc-interface.md),
[memmgr IPC Interface](../../memmgr/docs/ipc-interface.md),
[services/procmgr/README.md](../README.md),
[Restart Protocol](../../svcmgr/docs/restart-protocol.md),
[`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md),
[Synthetic Root and Namespace Composition](../../vfsd/docs/namespace-composition.md)
