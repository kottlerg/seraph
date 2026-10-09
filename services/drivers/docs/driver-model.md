# Driver Model

Driver lifecycle specification: device discovery, driver binding, per-device
capability delegation, service-endpoint delivery, and driver teardown.

---

## Adding a Driver

1. A driver lives in a subdirectory of `services/drivers/`, grouped by bus or device family
   where appropriate (e.g. `virtio/`).
2. A driver is a std binary crate (ruststd) built for the std-userspace Seraph target; see
   [docs/build-system.md](../../../docs/build-system.md#custom-targets) § Custom Targets.
3. A driver receives its device capabilities from [devmgr](../../devmgr/README.md) at spawn.
   It MUST NOT assume any capabilities beyond what devmgr delegates.
4. A driver serves client requests on the service endpoint devmgr creates and delivers in its
   bootstrap round; devmgr keeps the endpoint and mints client SEND caps from its device
   registry (`QUERY_*_DEVICE`); see
   [services/devmgr/docs/responsibilities.md](../../devmgr/docs/responsibilities.md#responsibilities)
   § Responsibilities.
5. A driver SHOULD use shared library crates (e.g. `services/drivers/virtio/core/`) where
   applicable rather than duplicating transport logic.

---

## Summarized By

[services/drivers/README.md](../README.md)
