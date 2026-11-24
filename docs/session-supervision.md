# Session Supervision

System-wide model of a session as a supervision unit: which process holds stop authority over the
programs a user starts, what procmgr records so that a supervisor stops a program together with
everything it started, how a session's memory is attributed, and how oomd finds and orders what
it may stop.

---

## Scope

This document is authoritative for:

- What a session, its leader and its jobs are.
- sessiond: what it supervises, the interfaces that are its clients, and its relationship to
  usermgr.
- What procmgr records and guarantees so that a supervisor stops a process together with every
  process it started.
- How a session's memory is attributed.
- Stop sources: how oomd learns of them and of their class, what each serves, and the order in
  which oomd stops.
- The session kinds, and for each what is built and what is design intent.

The supervision of services is specified in [Supervision](supervision.md). Each component's own
mechanism (procmgr's labels and their wire format, svcmgr's recipe keys, memmgr's budget nodes,
oomd's ladder) is specified in that component's documents once built. The authority model of
users is `docs/identity-and-authority.md`'s (design intent; not yet written, #152), and the
cap-native coordination of a session's members (signals, a foreground job, suspend and resume) is
`docs/coordination-model.md`'s (design intent; not yet written, #150).

---

## Implementation Status

§ Today, § Sessions, § sessiond, § procmgr Mechanism, § Attribution, § Stop Sources, and the
Terminal kind of § Session Kinds state the system as built, but for the parts below, which state
design intent, not yet implemented, each under the Issue that builds it:

| Part | Issue |
|---|---|
| Sessions over a PTY, several terminals, hangup (§ Session Kinds) | #1235 |
| Remote login through sessiond (§ Session Kinds) | #1236 |
| Per-user sessions: usermgr's token, per-account nodes (§ sessiond and usermgr) | #1238 |
| Graphical sessions (§ Session Kinds) | #1239 |

---

## Today

The system runs userless, and the terminal is the only interface through which a user starts a
program:

- sessiond runs in operator mode ([services/sessiond/README.md](../services/sessiond/README.md)).
  The terminal opens an operator session through its `sessiond.operator` seed, and sessiond
  creates the leader, the shell its recipe names, contained and charged to the session's node.
  The terminal holds no process handle and no namespace; svcmgr supervises it
  (`restart = on_failure`), and when the leader ends it opens a new session
  ([programs/terminal/README.md](../programs/terminal/README.md)).
- The shell starts each external command with std `Command`: a job of the session, whose process
  handle the shell holds as its creator ([programs/shell/README.md](../programs/shell/README.md)).
- sessiond is the one stop source of the program class in the default image. oomd, the holder of
  svcmgr's stop authority, stops a session's job, then a whole session, before any service that
  opted in, when memory stays critical ([services/oomd/README.md](../services/oomd/README.md)).
  The `stopsrc` test fixture is a second source of the class, staged in the svctest boot
  ([service-modes § stopsrc](../services/fixtures/service-modes/README.md#stopsrc)).

---

## Sessions

A session is the set of processes started for one use of the system through one interface: its
leader and every process the leader starts, transitively. The leader is the session's first
process, which sessiond creates: a shell, or a desktop shell in a graphical session. A job is a
child of the leader together with every process below it. An interface is a service through
which a user reaches the system and which asks sessiond for sessions: the terminal; later a remote
login service and a graphical greeter.

A session is a supervision unit, not a system-wide name. No kernel object and no procmgr record
represents it, no process can ask which session it belongs to, and no identifier of a session
confers authority. It exists as sessiond's record: the leader's process handle and thread cap, the
handle of the session's budget node, and the caps the interface handed over. The coordination of a
session's members (#150) is a separate mechanism: a coordination endpoint is held by the members,
and a member can drop it, so it carries signals and never a stop.

---

## sessiond

sessiond is a system service svcmgr launches from its recipe. It supervises every session: it
creates each leader, holds its handle, observes its death, and ends the session. Kill authority
over a session's programs, and the path from a user's authority to processes, stay in sessiond and
out of every interface.

- **Recipe.** `restart = on_failure`, `critical = no`, `reserve = yes` and
  `stop_source = program` (§ Stop Sources;
  [`.svc` Service Definitions § `stop_source`](../services/svcmgr/docs/service-definitions.md#stop_source)).
  The last two are core roles, so svcmgr never offers sessiond to oomd. A reserve service, it
  touches what it uses at start and allocates nothing on its list and stop paths, so it answers
  oomd while the free pool is spent. svcmgr creates every `stop_source` service contained
  (§ Stop Sources): sessiond's death ends every session, and no session outlives its supervisor.
- **Opening a session.** An interface asks sessiond to open a session and hands it the caps the
  leader's standard streams take (the terminal's pipe caps; later a PTY's subordinate end, or a
  compositor's client caps), a POST cap on an event queue of the interface's own, and the session's
  authority (§ sessiond and usermgr). sessiond makes the session's budget node (§ Attribution),
  creates the leader contained, charged to that node, with the interface's queue as its death
  relay, and starts it. The exchange and its wire format are
  [sessiond IPC Interface](../services/sessiond/docs/ipc-interface.md)'s. sessiond opens no session
  while memmgr's pressure level reads `CRITICAL`: a session opened then is a fresh candidate oomd
  stops before any service, so an interface that reopened its stopped session would undo the
  stop. The interface waits for the level to change and asks again.
- **Who may open.** Opening an operator session is itself an authority: a seed-only name sessiond
  provides, which svcmgr seeds only to the interfaces whose recipes name it, the terminal in the
  default image. A user session needs no authority beyond the usermgr token the open carries.
- **Session end.** A session ends when its leader ends (an exit, a fault, a stop), when its
  interface dies, or when sessiond is told to stop it. The leader is contained, so procmgr
  destroys what is left of its subtree; sessiond drops its record and releases the session's node.
  The interface learns of the end from the leader's death relay, which the leader's end reaches
  once (§ procmgr Mechanism), and opens a new session if it wants one. The terminal does.
- **Interface death.** An interface registers an end queue on itself with procmgr (§ procmgr
  Mechanism) and hands sessiond only that queue's receive right. procmgr posts the interface's end
  to it whatever ends it: an exit, a fault, or a destroy, svcmgr's stop of an opted-in service
  included, which a death observer bound on the interface's own threads would not see, since a
  teardown posts no death event
  ([Process Lifecycle § Exit reason](process-lifecycle.md#exit-reason)). sessiond stops that
  interface's sessions when the entry arrives, so no session outlives its interface, and an
  interface can be a supervised, restartable service: the terminal's recipe sets
  `restart = on_failure`.
- **sessiond's death.** procmgr destroys every session with it. Each interface receives its
  leader's end through the relay and opens a new session once svcmgr has restarted sessiond. Every
  session is lost; that is the cost of keeping no process past the supervisor that can stop it.

---

## sessiond and usermgr

The system runs userless today, and userless operator sessions are the only sessions sessiond
opens under #1233. An operator session's leader receives sessiond's own recipe namespace, the
system root in the default image, which is the authority #152's userless mode gives the operator.

In the single-user and multi-user modes of #152, usermgr and sessiond divide the work. usermgr
authenticates a user through an interface and issues the session's authority to that interface
as a token. The interface passes the token to sessiond with the open, and sessiond, the one
process usermgr derives a user's capabilities for, redeems it and creates the leader with those
capabilities. No interface holds a user's capabilities or the path that derives them, and usermgr
creates no process. sessiond places an account's sessions under one budget node per account, above
the session nodes (§ Attribution). A per-user manager, where an image runs one, is a program inside
a session and is stopped like any other. The token's form, the capabilities it yields and the
account record are `docs/identity-and-authority.md`'s (#152).

---

## procmgr Mechanism

What procmgr records and guarantees. The labels and their wire format are
[procmgr's IPC Interface § Process Tree](../services/procmgr/docs/ipc-interface.md#process-tree)'s.

- **Parent link.** procmgr records each process's parent: the process whose request created it,
  or none for a child of the un-badged creator (init, or svcmgr's mint source).
- **Re-parenting.** When a process ends, each of its live children takes the dead process's
  nearest live ancestor as its parent, or none when no ancestor lives. A child's budget node stays
  where it was made, so its pages still count in every ancestor's subtree usage.
- **Containment.** A create flag marks the child contained: when it ends, procmgr destroys what is
  left of its subtree instead of re-parenting its children. Re-parenting therefore never moves a
  process out of the subtree of a live contained ancestor.
- **Subtree destroy.** `DESTROY_PROCESS` destroys the process together with every process below
  it. Once a destroy begins, procmgr refuses a create from any process of that subtree, so none
  escapes it by starting a child during the teardown. A supervisor stopping a service or a program
  thereby stops everything it started. A destroy of a process that has already ended, before
  procmgr reaped it, is that end's reap, so its children are re-parented whichever comes first.
- **Children.** On a process handle, procmgr lists the process's children, each with its badge,
  its name and the pages of its subtree, and destroys one child, named by its badge, with its
  subtree. procmgr reads a child's subtree pages from memmgr with `QUERY_MEMORY_USAGE` over the
  memmgr SEND it holds for that child, which carries the child's memmgr badge, so memmgr needs no
  new label. The handle is the authority: its holder may already destroy the process with every
  process below it, and the badge only names one of its children.
- **End post.** procmgr keeps the death relay a create request carries (`CREATE_DEATH_RELAY`) for
  the child's life and posts the child's end to it once, whoever ends the child: a terminal fault in
  any thread as the fault class, and an exit as the exit reason, at the reap; a destroy, a
  containment's included, as `EXIT_KILLED` after the teardown, or as the exit or fault a process
  that ended before its destroy was reaped took. procmgr posts it rather than binding the relay to
  the child's address space, so the post is one whatever number of the child's threads end, and a
  re-parent can take the relay away. A creator thereby learns of a destroy it did not make (the
  shell, waiting on a job sessiond stopped), and an interface whose queue is a leader's relay learns
  that its session ended. procmgr deletes its copy of the relay once it has posted, and when the
  child is re-parented. A create procmgr refuses posts nothing, one a destroy reached between the
  child's insert and procmgr's reply included: until that reply delivers the child, the create, not
  the destroy, tears the child down, and procmgr deletes the relay unposted.
- **End queue.** A process may register one end queue on itself, through the procmgr SEND it
  holds, which names it. procmgr posts the process's end to it once, as to a death relay: the
  fault class or the exit reason at the reap, or the destroyed process's reason after a destroy.
  procmgr learns of every end, since it reaps each process through its own observer and makes each
  destroy, so the holder of the queue's receive right learns of the end whoever caused it. Telling
  another holder of one's own end confers no authority over anything.

---

## Attribution

sessiond makes each session's budget node with `CREATE_SUB_NODE` under its own node, holds the
node's handle, and charges the leader to it with `CREATE_CHARGE_NODE`
([memmgr IPC Interface § Node Handles](../services/memmgr/docs/ipc-interface.md#node-handles)).
Every process of the session is charged within that node's subtree, so a program's pages count in
its job, its session and sessiond, and never in an interface's subtree: svcmgr's stop list
never names an interface for a program's memory, and never names sessiond, which holds core roles.
sessiond makes every session node without `SUB_NODE_RESERVE`, and a node under one outside the
reserve cannot be a reserve node, so no process of a session takes the pages memmgr keeps in
reserve ([services/memmgr/docs/memory-pool.md](../services/memmgr/docs/memory-pool.md)
§ Distribution policy, **System reserve**).

A session's usage is its node's subtree pages, which sessiond reads with `NODE_QUERY_USAGE`; a
job's is the subtree pages procmgr's child list reports. In the single-user and multi-user modes
sessiond makes one node per account and each of that account's session nodes under it with
`NODE_CREATE`. State a server holds on a session's behalf (an interface's buffers, a compositor's
surfaces) is charged to the session's node once a server charges per-client state to its client
(#1100).

---

## Stop Sources

A stop source is a service that holds kill authority over a set of processes and offers oomd the
stop of them. svcmgr is the source of the service class, through the stop authority it already
serves. Every other source is a service whose recipe sets `stop_source = <class>`; `program` is
the one class, and sessiond its one source.

- **Discovery.** oomd asks svcmgr for the sources, on its stop authority. For each running service
  whose recipe sets the key, svcmgr returns a SEND derived from the original of that service's
  endpoint, which it holds for the service's life
  ([Supervision § Restart Authority](supervision.md#restart-authority)), badged with the stop
  verb bit, and the class the recipe names. oomd keeps no source between acts: it asks for the list
  at each act, so a source that started, restarted or ended since is found as it is, and deletes
  the SENDs it received once the act is done. The endpoint persists across the source's restarts,
  so a SEND that is still held reaches the next instance. A message carries at most
  `MSG_CAP_SLOTS_MAX` caps, so the list is paged.
- **Class.** A source's class is read from its recipe, never from the source: a source that
  declared its own class could claim the service class and delay its own stop. The key is a core
  role, and svcmgr creates every `stop_source` service contained (§ procmgr Mechanism), so no
  process a source started outlives it and each instance starts with no candidate. A source is
  reached on its service endpoint, so the `.svc` parser rejects the key on a recipe without
  `provides`; on one with a bare `provides` entry, whose unbadged SEND any holder could badge with
  the stop bit; and with `restart = never`, since svcmgr lists only a source it supervises.
- **Protocol.** Every source serves the same two labels, from one shared label module: a paged list
  of its candidates, each with a key, a rank, a name and the pages of its subtree; and the stop of
  one candidate, named by its key. A key names one candidate and no other across the source's
  instances, since the endpoint persists across its restarts and a stopper can hold a listed key
  past one: each instance draws its keys from a value of its own, so a key an earlier instance
  handed out names a candidate of a later one with a probability of at most about 2^-31; the stop of
  a candidate that is gone is refused and changes nothing. The source stops through the handles it
  holds, and oomd holds no process handle. svcmgr serves the shared labels for the service class, a
  service's key naming its table slot and instance.
- **sessiond's candidates.** Each job, ranked job, with the subtree pages procmgr's child list
  gives; and each session, ranked session, with its node's subtree pages. The stop of a job
  destroys that child of the leader with its subtree, and the shell, its creator, sees it end
  through its death relay. The stop of a session destroys the leader, which ends the session.
- **Order.** oomd stops one candidate per cooldown, as #1098 sets: first the program class's jobs,
  then its whole sessions, then the service class's services. Within each, the candidate with the
  most subtree pages goes first, ties to the earlier source and then the earlier entry. A rank
  orders candidates within the class its source has, never across classes. Programs are stoppable
  by default; services stay opt-in under svcmgr's rule. oomd bounds each call to a source and
  passes over a source that does not answer, so a wedged source does not stall the ladder.
- **Growth.** A new kind of session is a new client of sessiond and changes no other component. A
  new source is one recipe key, and changes no oomd code.

---

## Session Kinds

| Kind | Interface | Leader | Authority at the open | Issue |
|---|---|---|---|---|
| Terminal | terminal | shell | operator | #1233 |
| Several terminals, over a PTY | one terminal instance per TTY | shell | operator; a usermgr token with #1238 | #1235 |
| Remote login | rshd | shell | operator where the image seeds it; a usermgr token with #1238 | #1236 |
| Per-user | terminal, rshd or greeter | shell or desktop shell | a usermgr token | #1238 |
| Graphical | greeter | desktop shell | a usermgr token, or operator in a userless image | #1239 |

- **Terminal.** Built: the terminal opens an operator session through sessiond with its pipe
  caps, and the session's programs are stoppable before any service. The terminal holds no
  process handle, and needs no namespace of its own to start the shell.
- **Several terminals, over a PTY.** Design intent (#1235): the standard streams are a PTY's
  subordinate end; each terminal instance opens its own session (D21 of #152); the hangup policy,
  which ends a session when its PTY's controlling end closes, is sessiond's.
- **Remote login.** Design intent (#1236): rshd is a client only. It holds no process handle
  and no derivation path, and its death ends only its own sessions. Whether a remote peer may open
  an operator session in the userless mode is the image's choice, made by seeding rshd with the
  operator name or not.
- **Per-user.** Design intent (#1238): every interface authenticates through usermgr and opens
  the session with the token, as § sessiond and usermgr says; an account's sessions share its
  budget node.
- **Graphical.** Design intent (#1239): the greeter is the interface. It authenticates through
  usermgr and opens a session whose leader is the desktop shell, handing over the compositor's
  client caps for that session; the programs the desktop shell starts are the session's jobs. The
  compositor is a display broker and holds no process handle.

---

## Alternatives Not Taken

- **The launching interface as supervisor.** Kill authority and the derivation of a user's
  capabilities would sit in network-facing and display-facing processes, and a graphical session
  has no trusted launcher: the compositor is a broker and the desktop shell is inside the session.
- **The shell or leader as supervisor.** A user can replace it, so oomd could not trust its list.
- **A per-user manager as holder.** None exists in the userless mode.
- **svcmgr supervising sessions.** Login-driven creation and the derivation of user authority would
  enter the core set, which cannot restart.
- **A stop through a budget node, or a process handle held by oomd.** Either couples memory control
  to kill authority (#1097, #1098).
- **A kill by class or name, or a kernel session object.** Ambient authority (#150).
- **Coordination endpoints carrying the stop.** Membership is the holding of a cap, which a member
  can drop.
- **Orphans left unparented, or every end destroying its subtree.** The first puts orphans beyond
  every supervisor; the second ends a helper a program starts to outlive itself. Re-parenting, with
  containment where a supervisor needs it, keeps both.

---

## Open Questions

None. An interface returns a ring page whose peer it did not create once the leader's death relay
has been read, since procmgr posts the relay only after it has torn the leader down, or at once
when sessiond refused the open, as ruststd's `std::os::seraph::process::SessionStdio` does
([runtime/ruststd/README.md](../runtime/ruststd/README.md)).

---

## Summarized By

[Supervision](supervision.md)
