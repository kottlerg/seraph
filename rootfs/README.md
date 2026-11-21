# rootfs

Static source files mirrored into the sysroot during `cargo xtask build`. Every
file's path under `rootfs/` becomes its path under `sysroot/`; no rename or
remap table is involved. The mirror is authoritative over the subtrees it owns
(`config/`, `data/`): a file deleted from `rootfs/` is removed from the sysroot
(and the disk image) on the next `cargo xtask build` or `mkdisk`. Build-installed
binaries and the synthesised `data/svctest/` fixtures live in the sysroot but
outside `rootfs/`, and are never pruned.

This directory holds the non-binary parts of the runtime image: system
configuration (svcmgr `.svc` recipes) and pre-populated data files for
services and tests. Compiled binaries are installed by the build pipeline
directly to their sysroot destinations, not via this tree (see
[`docs/build-system.md`](../docs/build-system.md)).

---

## Source Layout

```
rootfs/
  config/
    bundle/           # The bundle lists: per harness, and per architecture where
      *.list          #   they differ, the installed files the bootstrap bundle copies
    svcmgr/
      services/       # `.svc` recipes svcmgr reads at handover, through the
                      #   signed index each pack writes
        *.svc
      tests/          # Opt-in test-harness recipes; staged by hand
        *.svc
      debug/          # The GDB stub's recipe template; staged by xtask (run
        gdbstub.svc   #   --debug-target, `debug-port` case), naming its target
  data/
    test.txt          # Marker fixture for svctest fs / namespace phases
    crasher-boot/
      die-early       # Token the crasher boot-fault fixture removes before it dies
```

xtask synthesises additional data fixtures at build time directly into
the sysroot at `sysroot/data/svctest/{large.bin, bench.bin}` and
`sysroot/data/svctest/signed/verified.dat`, the data-role fixture of
procmgr's verified read, which every pack signs
([docs/signing.md](../docs/signing.md) § Signing); they are not stored
under `rootfs/` since they are deterministic build artifacts.
It also creates `sysroot/crash/` empty, which git cannot carry here: the
directory crashd writes cores to
([services/crashd/docs/core-format.md](../services/crashd/docs/core-format.md)).
The build never prunes it, so cores written to a disk image survive until
the image is rebuilt.

The bootloader's `bootstrap.bundle` (init plus every boot module) is
composed by every pack of the disk image and written to
`sysroot/esp/EFI/seraph/bootstrap.bundle` (see
[`docs/build-system.md`](../docs/build-system.md#build-output-the-sysroot)).
Its entries are byte copies of the installed files that the harness's list
under `config/bundle/` names, each by its install path: `init.x86_64.list`
and `init.riscv64.list` for the init harness, `ktest.list` for ktest. A
list holds one `init <path>` line, naming the object of the bundle's `init`
slot, and one install path per line for every other entry; `#` starts a
comment. A harness has one list for every architecture or one per
architecture, never both. Adding a boot module is a line in its harness's
list ([docs/boot-media.md](../docs/boot-media.md) § The Bootstrap Closure
says what belongs there). The bootloader reads
hardcoded ESP paths (see [`core/boot/README.md`](../core/boot/README.md)),
and vfsd discovers mounts by GPT role GUID and auto-mounts `/esp` (see
[`docs/storage.md`](../docs/storage.md#gpt-role-guid-discovery)); neither
needs a file under `rootfs/`.

To add a new static file, place it under the path it should occupy in the
sysroot; the build picks it up automatically. Removing a file here removes it
from the sysroot on the next build. `README.md` files are the only excluded
names. To refresh the sysroot and disk image after editing this tree without
a full build, use
[`cargo xtask mkdisk`](../xtask/README.md#cargo-xtask-mkdisk).

For the sysroot layout this tree contributes to, see
[`docs/build-system.md`](../docs/build-system.md). The implementation that
performs the mirror is
[`xtask/src/sysroot.rs`](../xtask/src/sysroot.rs)'s `install_rootfs`.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/build-system.md](../docs/build-system.md) | Sysroot layout and the `cargo xtask build` mirror |
| [xtask/README.md](../xtask/README.md#cargo-xtask-mkdisk) | `cargo xtask mkdisk` re-mirror and `--repack-only` |
| [docs/storage.md](../docs/storage.md) | GPT role-GUID mount discovery and `/esp` auto-mount |
| [services/svcmgr/docs/service-definitions.md](../services/svcmgr/docs/service-definitions.md) | The `.svc` recipe format under `config/svcmgr/` |
| [docs/testing.md](../docs/testing.md) | Opt-in harness recipes under `config/svcmgr/tests/` |

---

## Summarized By

[Build System](../docs/build-system.md),
[programs/fsbench/README.md](../programs/fsbench/README.md), [xtask/README.md](../xtask/README.md)
