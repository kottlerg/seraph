# framebuffer

Userspace framebuffer device driver. Owns the bootloader-discovered GOP
linear-framebuffer MMIO end-to-end and exposes a single byte-write IPC.
Payload bytes are interpreted as UTF-8: the driver carries a `text::Utf8Decoder`
across calls (so a multi-byte sequence may straddle two payloads), then
resolves each codepoint via CP437 reverse → font-extension → ASCII-fallback
→ `U+FFFD`, blitting one or more 9×20 glyphs from `shared/font`. The kernel
framebuffer renderer (`core/kernel/src/framebuffer.rs`) remains the early-
boot / panic console fallback — see
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
        ├── x86_64/mod.rs        # reserve VA + fund PT budget + mmio_map the linear framebuffer
        └── riscv64/mod.rs       # reserve VA + fund PT budget + mmio_map the linear framebuffer
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
badged SEND on its registry endpoint so the driver can fetch its
geometry via `QUERY_DEVICE_INFO` (generic kind/version/bytes payload
schema, shared with virtio).

Clients obtain a write cap through devmgr, not svcmgr: a framebuffer is a
device, not a service. Devmgr answers
[`devmgr_labels::QUERY_FRAMEBUFFER_DEVICE`] by minting a
[`fb_labels::WRITE_AUTHORITY`]-badged `SEND_GRANT` cap on the driver's
service endpoint, mirroring the `QUERY_SERIAL_DEVICE` flow. The caller's
devmgr-registry badge must carry `REGISTRY_QUERY_AUTHORITY`.

---

## Messages

One synchronous operation. Labels are defined in `shared/ipc::fb_labels`;
error codes in `shared/ipc::fb_errors`.

### Label 1: `FB_WRITE_BYTES`

Write a run of UTF-8 bytes to the framebuffer. The label carries the
payload byte length in its high bits, mirroring
`serial_labels::SERIAL_WRITE_BYTES` and `stream_labels::STREAM_BYTES`;
the bytes are packed into the data words.

The driver feeds each byte to its `text::Utf8Decoder`:

* `\n` advances to the start of the next line (scrolling if at the
  bottom); `\r` returns the cursor to column 0. Both bypass the decoder.
* Other bytes drive the decoder; on a completed codepoint the driver
  calls `text::render_codepoint`, which dispatches in order:
  CP437 reverse (`font::FONT_9X20`) → font-extension table
  (`font::FONT_9X20_EXT`) → ASCII fallback (multi-byte substitutes such
  as `©` → `(C)`) → `U+FFFD` replacement glyph (slot 0 of the extension
  table).
* Invalid UTF-8 emits one `U+FFFD` glyph and resets the decoder.

A multi-byte sequence may straddle two `FB_WRITE_BYTES` calls; partial
state is held in the driver's decoder until the sequence completes.
There is one decoder per driver process, alongside the single cursor.

**Request:**

| Field | Value |
|---|---|
| label | `1 \| (byte_len << 16)` — opcode in bits 0-15, payload byte length in bits 16-31 (`0..=512`) |
| data[0..] | `byte_len` payload bytes (UTF-8), packed contiguously (`.bytes(0, …)`) |

**Reply:**

| Field | Value |
|---|---|
| label | `0` (`SUCCESS`) or `2` (`UNKNOWN_OPCODE`) |

The driver's UTF-8 / font output is exercised by `programs/fb-charset`,
a small demo program launched once per default boot by svcmgr via
`/config/svcmgr/services/fb-charset.svc` (`seed = devmgr.registry`).
It prints a representative sample of every glyph class and exits.

---

## Planned future surface

Not implemented; named so the intended shape is visible. No wire tables
until implemented.

- `FB_CLEAR` — clear the framebuffer to a caller-supplied colour.
- `FB_SET_CURSOR` — move the text cursor to a (col, row) cell.
- `FB_BLIT_RECT` — blit a caller-supplied pixel buffer into a rectangle.
- `FB_REGISTER_RESIZE_NOTIFY` — register a notification cap kicked on geometry change.
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
| [docs/capability-model.md](../../../docs/capability-model.md) | Capability types, rights, delegation, badges |

---

## Summarized By

[docs/console-model.md](../../../docs/console-model.md)
