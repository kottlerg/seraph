# rootfs

Static source files mirrored into the sysroot during `cargo xtask build`. Every
file's path under `rootfs/` becomes its path under `sysroot/`; no rename or
remap table is involved. The mirror is authoritative over the subtrees it owns
(`config/`, `data/`): a file deleted from `rootfs/` is removed from the sysroot
(and the disk image) on the next `cargo xtask build` or `mkdisk`. Build-installed
binaries and the synthesised `data/svctest/` fixtures live in the sysroot but
outside `rootfs/`, and are never pruned.

This directory holds the non-binary parts of the runtime image: boot
configuration, system configuration, and pre-populated data files for
services and tests. Compiled binaries are installed by the build pipeline
directly to their sysroot destinations, not via this tree.

## Tree

```
rootfs/
  config/
    svcmgr/
      services/       # `.svc` recipes svcmgr scans at handover
        *.svc
      tests/          # Opt-in test-harness recipes; staged by hand
        *.svc
  data/
    test.txt          # Marker fixture for svctest fs / namespace phases
```

xtask synthesises additional data fixtures at build time directly into
the sysroot at `sysroot/data/svctest/{large.bin, bench.bin}`; they are
not stored under `rootfs/` since they are deterministic build artifacts.

The bootloader's `bootstrap.bundle` (which now carries every userspace
binary the system needs to boot) is composed by `cargo xtask build`
and written to `sysroot/esp/EFI/seraph/bootstrap.bundle`; it has no
hand-authored counterpart under `rootfs/`. There is no `boot.conf`
(replaced by hardcoded ESP paths in the bootloader) and no
`mounts.conf` (replaced by GPT-type-GUID-driven mount discovery in
vfsd, plus automatic `/esp` mount).

To add a new static file, place it under the path it should occupy in the
sysroot; the build picks it up automatically. Removing a file here removes it
from the sysroot on the next build. `README.md` files are the only excluded
names.

For the sysroot layout this tree contributes to, see
[`docs/build-system.md`](../docs/build-system.md). The implementation that
performs the mirror is
[`xtask/src/sysroot.rs`](../xtask/src/sysroot.rs)'s `install_rootfs`.

---

## Summarized By

[../docs/build-system.md](../docs/build-system.md)
