# framebuffer

Userspace framebuffer device driver. Owns the bootloader-discovered GOP
linear-framebuffer MMIO end-to-end and exposes a single byte-write IPC; bytes
are rendered as text through the embedded 9×20 bitmap font (`shared/font`).
The kernel framebuffer renderer (`core/kernel/src/framebuffer.rs`) remains
the early-boot / panic console fallback — see
[docs/console-model.md](../../../docs/console-model.md).

---

## Source Layout

```
framebuffer/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs                  # Driver entry, bootstrap, write service loop
    ├── render.rs                # FramebufferWriter (cursor + glyph blit + scroll)
    └── arch/
        ├── mod.rs               # #[cfg(target_arch)] dispatch
        ├── x86_64/mod.rs        # reserve VA + mmio_map the linear framebuffer
        └── riscv64/mod.rs       # reserve VA + mmio_map the linear framebuffer
```

---

## Endpoint

Devmgr discovers the framebuffer via the bootloader-synthesised aperture
seed for `[physical_base, physical_base + stride * height)` plus the
`BootInfo.framebuffer` geometry propagated through `InitInfo.framebuffer`
(`abi/init-protocol`'s v8 addition). The framebuffer's authoritative
identity dies with UEFI `ExitBootServices` (only GOP knows it pre-exit),
so the bootloader is the only entity that can carry this information to
userspace.

Devmgr spawns the driver via the `simple-device` path with a round-2
tokened SEND on its registry endpoint so the driver can fetch its
geometry via `QUERY_DEVICE_INFO` (generic kind/version/bytes payload
schema, shared with virtio).

Clients obtain a write cap through devmgr, not svcmgr: a framebuffer is a
device, not a service. Devmgr answers
[`devmgr_labels::QUERY_FRAMEBUFFER_DEVICE`] by minting a
[`fb_labels::WRITE_AUTHORITY`]-tokened `SEND_GRANT` cap on the driver's
service endpoint, mirroring the `QUERY_SERIAL_DEVICE` flow. The caller's
devmgr-registry token must carry `REGISTRY_QUERY_AUTHORITY`.

---

## Messages

One synchronous operation. Labels are defined in `shared/ipc::fb_labels`;
error codes in `shared/ipc::fb_errors`.

### Label 1: `FB_WRITE_BYTES`

Write a run of bytes to the framebuffer. The label carries the payload
byte length in its high bits, mirroring `serial_labels::SERIAL_WRITE_BYTES`
and `stream_labels::STREAM_BYTES`; the bytes are packed into the data
words. The driver renders each printable byte as a 9×20 glyph at the
cursor, handles `\n` / `\r`, and scrolls when the last row is filled, then
replies empty.

**Request:**

| Field | Value |
|---|---|
| label | `1 \| (byte_len << 16)` — opcode in bits 0-15, payload byte length in bits 16-31 (`0..=512`) |
| data[0..] | `byte_len` payload bytes, packed contiguously (`.bytes(0, …)`) |

**Reply:**

| Field | Value |
|---|---|
| label | `0` (`SUCCESS`) or `2` (`UNKNOWN_OPCODE`) |

---

## Planned future surface

Not implemented; named so the intended shape is visible. No wire tables
until implemented.

- `FB_CLEAR` — clear the framebuffer to a caller-supplied colour.
- `FB_SET_CURSOR` — move the text cursor to a (col, row) cell.
- `FB_BLIT_RECT` — blit a caller-supplied pixel buffer into a rectangle.
- `FB_REGISTER_RESIZE_NOTIFY` — register a signal cap kicked on geometry change.
- `FB_SET_PALETTE` — set the foreground/background colour palette.

Multi-head dispatch (v1 binds the single bootloader-handed framebuffer)
and mode-set are deferred to a follow-up issue when a real consumer
(terminal, shell, compositor) needs them.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/console-model.md](../../../docs/console-model.md) | Console output phase ownership; where this driver sits |
| [services/drivers/docs/driver-model.md](../docs/driver-model.md) | Driver lifecycle and capability delegation |
| [docs/device-management.md](../../../docs/device-management.md) | Driver discovery, spawning, security boundary |
| [docs/ipc-design.md](../../../docs/ipc-design.md) | IPC semantics, endpoints, message format |
| [docs/capability-model.md](../../../docs/capability-model.md) | Capability types, rights, delegation, tokens |

---

## Summarized By

[docs/console-model.md](../../../docs/console-model.md)
