# shared/storage-statement

The storage statement: the format, parser and writer of `/config/vfsd/storage.conf`, the signed
file by which a disk other than the boot disk takes a storage role
([docs/storage.md](../../docs/storage.md#gpt-role-guid-discovery) § GPT Role-GUID Discovery).

---

## Source Layout

```
storage-statement/
├── Cargo.toml
├── README.md
├── fuzz/
│   └── storage-statement/
│       ├── regressions/    # inputs of defects the fuzzer found, replayed by `cargo xtask test`
│       └── seeds/          # checked-in inputs, replayed by `cargo xtask test`
└── src/
    ├── lib.rs              # PATH, Role, Disk, PciLocation, Named, Statement, Error, parse,
    │                       # parse_guid, format_guid
    └── property.rs         # storage_statement_holds, the parser's contract over any input
```

`no_std` with `alloc`. Host-tested (`cargo xtask test`), fuzzed (target `storage-statement`,
[docs/testing.md](../../docs/testing.md#fuzzing) § Fuzzing), and proved by the Kani harnesses of
its `proofs` module ([docs/testing.md](../../docs/testing.md#bounded-verification) § Bounded
verification).

---

## Format

The statement is UTF-8 text of lines each ending in `\n`. An empty line, and one whose first byte
is `#`, is skipped. Every other line names one partition for one role: the role's keyword, the
mount path when the role takes one, the disk the partition must be on, and the partition's unique
GUID, joined by single spaces. The GUID is in its canonical text form, `8-4-4-4-12` hex digits in
either case, read into GPT on-disk byte order.

| Keyword | Line | Number | Type GUID the partition must carry |
|---|---|---|---|
| `data` | `data <mount path> <disk> <GUID>` | any, at distinct paths | `SERAPH_DATA` |
| `swap` | `swap <disk> <GUID>` | at most one | `SERAPH_SWAP` |

The disk (`Disk`) is `boot`, the boot disk wherever vfsd finds it, or `pci:SSSS:BB:DD.F`, the PCI
location devmgr reports for a disk: the segment in four hex digits, the bus and the device in two
each, the device at most `1f`, and the function a digit from 0 to 7, in either case and written in
lowercase. They are the digits vfsd logs for each disk it holds after `PCI `. vfsd gives the role
only to the partition on that disk
([docs/storage.md](../../docs/storage.md#gpt-role-guid-discovery)).

A mount path is absolute, not `/`, at most `MAX_PATH_LEN` (255) bytes, and each of its
components is one or more of `A-Z a-z 0-9 . _ -` and neither `.` nor `..`. A later role is one
more row of `Role`, its keyword and its type GUID; the mechanism stays as it is.

A statement is accepted whole or not at all: a line with an unknown keyword, a field missing,
extra or empty, a path, a disk or a GUID not in its form, a mount path or a partition (a disk and
a GUID) named twice, a role that takes one partition named twice, a last line with no `\n`, and
an allocation that fails each refuse it, naming the line. One GUID named on two disks names two
partitions. vfsd reads a refused statement as naming nothing, so every role then
resolves on the boot disk.

---

## Relevant Design Documents

| Document | Relevance |
|---|---|
| [docs/storage.md](../../docs/storage.md) | § GPT Role-GUID Discovery: how a named role resolves |
| [docs/signing.md](../../docs/signing.md) | § Configuration: the file's role and install path |
| [docs/threat-model.md](../../docs/threat-model.md) | § Disk Images: what the statement defends and its gaps |

---

## Consumers

| Consumer | Use |
|---|---|
| [vfsd](../../services/vfsd/README.md) | `parse` of the statement it reads through procmgr's verified read after the root self-mount |
| [xtask](../../xtask/README.md) | `Statement::render` of the statement `mkdisk --split-data` stages for the location its boot places the data disk, checked with `parse` |

---

## Summarized By

None
