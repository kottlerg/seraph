# shared/boot-policy

The boot-time policy: the parser of the `/config/boot/policy.conf` bundle entry, which holds the
settings by which a system's signed configuration makes hardware a boot requirement
([docs/signing.md](../../docs/signing.md#configuration) § Configuration).

---

## Source Layout

```
boot-policy/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs              # DmaConfinement, Policy, Error, parse, parse_module
```

`no_std`, no allocation. Host-tested (`cargo xtask test`).

---

## Format

The policy is text in the `key = value` line grammar of
[`svc-grammar`](../svc-grammar/README.md): a blank line, and one whose first character is `#`, is
skipped, and the key and the value are each trimmed. A key appears at most once, and a key the
policy does not set takes its default.

| Key | Values | Default | Consumer |
|---|---|---|---|
| `dma-confinement` | `required`, `opportunistic` | `opportunistic` | devmgr ([docs/device-management.md](../../docs/device-management.md#dma-safety-model) § DMA Safety Model) |

A policy is accepted whole or not at all: a body that is not UTF-8, a line with no `=`, an
unknown key, a value its key does not take, and a key set twice each refuse it, naming the line.
A consumer handed no policy, or one that does not parse, applies `Policy::FAIL_CLOSED`, every
requirement on. The policy sets no bound of its own: the parser allocates nothing, and the file
is one bundle entry, bounded as every entry is
([docs/limits.md](../../docs/limits.md#bootloader-and-boot-abis) § Bootloader and boot ABIs).

The committed policy, `rootfs/config/boot/policy.conf`, writes every key out at its default.

---

## Relevant Design Documents

| Document | Relevance |
|---|---|
| [docs/signing.md](../../docs/signing.md) | § Configuration: the policy file, its role, and its refusals |
| [docs/device-management.md](../../docs/device-management.md) | § DMA Safety Model: the `dma-confinement` setting |

---

## Consumers

| Consumer | Use |
|---|---|
| [devmgr](../../services/devmgr/README.md) | `parse_module` of the policy boot module init forwards it, before the first driver starts |
| [xtask](../../xtask/README.md) | `parse` of the policy a pack installs; a pack refuses a policy it does not accept |

---

## Summarized By

None
