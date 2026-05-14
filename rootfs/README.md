# rootfs

Static source files mirrored into the sysroot during `cargo xtask build`. Every
file's path under `rootfs/` becomes its path under `sysroot/`; no rename or
remap table is involved.

This directory holds the non-binary parts of the runtime image: boot
configuration, system configuration, and pre-populated data files for
services and tests. Compiled binaries are installed by the build pipeline
directly to their sysroot destinations, not via this tree.

## Tree

```
rootfs/
  config/
    mounts.conf       # vfsd mount table consumed at runtime
  esp/
    EFI/
      seraph/
        boot.conf     # Bootloader config; selects init mode (init=ktest, …)
  srv/
    test.txt          # Sample service-data file
  usertest/
    large.bin         # Data file consumed by the usertest harness
```

To add a new static file, place it under the path it should occupy in the
sysroot. The build will pick it up automatically — `README.md` files are the
only excluded names.

For the sysroot layout this tree contributes to, see
[`docs/build-system.md`](../docs/build-system.md). The implementation that
performs the mirror is
[`xtask/src/sysroot.rs`](../xtask/src/sysroot.rs)'s `install_rootfs`.

---

## Summarized By

[../docs/build-system.md](../docs/build-system.md)
