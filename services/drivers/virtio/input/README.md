# virtio/input

VirtIO input (keyboard) device driver. Decodes `virtio-input` `EV_KEY` events
into a keysym stream and serves it over a blocking-read IPC interface. This is
the virtio-input *backend* for keyboard input; future USB-HID / PS-2 keyboards
are sibling drivers that decode their own raw codes into the same keysym ABI
and register the same devmgr slot, so consumers are transport-agnostic.

---

## Source Layout

```
virtio/input/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs                # Driver entry, PCI bring-up, IPC service loop
    ├── input.rs              # Event virtqueue receive-buffer ring + event struct
    └── decode.rs             # Keycode → keysym tables + modifier-state FSM
```

---

## Endpoint

Devmgr enumerates the virtio-input PCI device, carves its per-device
capabilities (BAR MMIO, IRQ), and spawns this driver from the rootfs
(`/services/drivers/virtio-input`) — it is not bootstrap-essential, so it loads
lazily through devmgr's `SET_DRIVERS_DIR` subtree cap, like the RTC drivers.
Devmgr owns the service endpoint and mints clients an
`input_labels::READ_AUTHORITY`-badged SEND cap via
`devmgr_labels::QUERY_INPUT_DEVICE`.

One device, one client for v0.1.0; multi-device fan-out is out of scope.

---

## Messages

Synchronous call/reply (`SYS_IPC_CALL`). Labels and the keysym ABI live in
`shared/ipc::input_labels`, `shared/ipc::input_errors`, and
`shared/ipc::keysym`.

### Label 1: `INPUT_READ_EVENTS`

Read a batch of pending keyboard events. **Blocking**: the driver does not
reply until at least one event is available.

**Request:** empty body (caller's badge carries `READ_AUTHORITY`).

**Reply (`SUCCESS`):**

| Field | Value |
|---|---|
| word[0] | event count `n` (`1..=INPUT_MAX_EVENTS_PER_READ`) |
| word[1 + i] | event `i`, packed by `keysym::pack_event` |

Each packed event carries `keysym` (bits 0-31), the `modifiers` mask (bits
32-62), and `pressed` (bit 63). Consumers decode with `keysym::unpack_event`.

### Keysym model

Keysyms follow X11 numbering: a printable Latin-1 keysym *is* its Unicode
codepoint (`a` = 0x61, `A` = 0x41); named keys (Enter, Backspace, Tab, Escape,
arrows, …) use the `0xFF00`+ function range. The driver resolves Shift and Caps
Lock into the emitted keysym and reports the full modifier mask (Shift, Caps,
Ctrl, Alt) so a terminal can form Ctrl/Alt combinations — the driver does not
cook bytes or encode terminal/line-discipline policy. US layout only.

---

## DMA Discipline

The driver owns one DMA page of 8-byte event buffers posted to the eventq
(virtqueue 0) as device-writable descriptors. The device fills one event per
buffer as keys arrive and raises an interrupt; the driver drains the used ring,
decodes, and re-posts each buffer. A descriptor-head → buffer-slot map locates
the filled buffer on completion. The IRQ wait carries a bounded timeout and
re-drains each tick, tolerating the occasional lost PLIC interrupt on QEMU virt
RISC-V (the same mitigation virtio-blk uses).

---

## Out of Scope (v0.1.0)

Configurable key-repeat, keyboard-layout switching, the statusq (LED feedback —
Caps Lock LED does not light), pointer/mouse/touch events, and multi-device
fan-out. Each is a separate effort if filed.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/drivers/docs/driver-model.md](../../docs/driver-model.md) | Driver lifecycle and capability delegation |
| [services/drivers/docs/virtio-architecture.md](../../docs/virtio-architecture.md) | VirtIO transport abstraction, virtqueue internals |
| [docs/device-management.md](../../../../docs/device-management.md) | Driver lifecycle, on-disk loading, DMA safety |
| [docs/ipc-design.md](../../../../docs/ipc-design.md) | IPC semantics, endpoints, message format |
| [docs/capability-model.md](../../../../docs/capability-model.md) | Capability types, rights, delegation, badges |
