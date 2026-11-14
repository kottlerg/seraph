# Intel Affected Processor List

Records the provenance, the licence and the update procedure of the vendored copy of Intel's
machine-readable affected-processor list. The x86-64 transient-execution table is derived from
this list ([transient-execution.md](../../docs/transient-execution.md)).

---

## Source

| Item | Value |
|---|---|
| Upstream | [github.com/intel/Intel-affected-processor-list](https://github.com/intel/Intel-affected-processor-list) |
| Commit | `3bc9bd4f7c0286eb2c20dca719742ca0fbde88c5` |
| `Intel_affected_processor_list.csv` SHA-256 | `973cca30ee07bd7c3e3a18116a3ce2ec496d898027f2e3bbe2761e55080825c3` |
| `LICENSE` (upstream `license.md`) SHA-256 | `c737b0e42306e7524c7228d47b23cb02f4d643db3759bc1326445b761b7f17c7` |
| Licence | 0BSD, as `LICENSE` states |

The list is the machine-readable form of Intel's consolidated table of affected processors
(Intel, "Affected Processors: Transient Execution Attacks & Related Security Issues by CPU").
Upstream states that processors past their End of Servicing Lifetime may not be listed. The
derivation treats such a processor, like any other model the list does not hold, as affected by
every class the list covers ([transient-execution.md](../../docs/transient-execution.md)
§ Intel).

Both files are byte-for-byte copies of the upstream files at the commit above. The upstream
`license.md` is kept as `LICENSE`. Neither file carries a Seraph header, and neither is edited
in this tree.

---

## Update procedure

1. Copy `Intel_affected_processor_list.csv` and `license.md` (as `LICENSE`) from the upstream
   commit, unmodified.
2. Record the commit and both SHA-256 digests in § Source.
3. Run `cargo xtask test`. The test `vendored_list_is_well_formed` in
   `core/kernel/src/arch/x86_64/vulnerability.rs` fails when a row's column count differs from
   the header's, when a class's column holds a status the derivation does not map, or when a
   class loses its column. A new column for a class the table does not report is ignored until
   [transient-execution.md](../../docs/transient-execution.md) admits the class.
4. Review every changed row against
   [transient-execution.md](../../docs/transient-execution.md) § Intel, and update the host test
   vectors whose rows changed.

---

## Summarized By

[Transient Execution](../../docs/transient-execution.md)
