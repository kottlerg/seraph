# hwrng-protocol

The wire protocol of the `hwrng` device class: the one label a hardware random-number generator
driver serves, its verb bit, its error codes, and the codec of its reply. A driver of the class and
every consumer of the class compile against this crate. `no_std`; host unit tests cover the codec.

---

## Authority

This crate is authoritative for the **wire format** of the `hwrng` class: the label, the request
and reply layouts, the reply bound, the error codes, and the verb bit. The class model (class
files, verb masks, `QUERY_DEVICE` through a class SEND) is specified in
[docs/driver-binding.md](../../docs/driver-binding.md) § Device Classes; the class file is
`rootfs/config/devmgr/classes/hwrng.class`.

---

## Reaching a driver

svcmgr publishes the class SEND seed-only as `devmgr.class.hwrng`. A consumer seeded with it asks
devmgr for a driver of the class with `devmgr_labels::QUERY_DEVICE` (or waits for one with
`WATCH_CLASS`), and devmgr answers with a SEND on that driver's service endpoint, badged with the
class file's verb bits: `READ_AUTHORITY` (bit 63).

---

## Label 1: `READ`

| | Layout |
|---|---|
| Request | `data[0]` = `n`, the most bytes the caller takes; no data word asks for 0. No cap: the driver deletes any a request carries. |
| Reply `SUCCESS` (0) | `data[0]` = `k` ≤ `min(n, MAX_READ_BYTES)`; the `k` bytes from `data[1]`, packed little-endian, the last word zero-padded |
| Reply `UNKNOWN_OPCODE` (1) | the label is not `READ`; no data |
| Reply `UNAUTHORIZED` (2) | the caller's badge lacks `READ_AUTHORITY`; no data |
| Reply `NOT_READY` (3) | the device produced no bytes within the driver's wait bound; no data, and the caller asks again later |

`MAX_READ_BYTES` is 504: every data word of a message (`MSG_DATA_WORDS_MAX`, 64) but the count
word, eight bytes each. `k` is 0 for `n` = 0 and may be below `n` when the device produced
fewer bytes. `encode_reply` writes a reply's words and `decode_reply` reads them; the decoder
refuses a count past the caller's buffer, past `MAX_READ_BYTES`, or past the words delivered, since
the reply is another process's.

The protocol says nothing of the quality of the bytes. A consumer mixes them into a pool that
credits them with no entropy, as the kernel's contribution path does
([core/kernel/docs/entropy.md](../../core/kernel/docs/entropy.md)).

`HWRNG_LABELS_VERSION` is marker-only: no request carries it, and `PROCESS_ABI_VERSION` covers
the driver and its consumers, which build together. It is bumped on any breaking change, per
[docs/conventions.md](../../docs/conventions.md) § ABI / wire-protocol versions.

---

## Summarized By

None
