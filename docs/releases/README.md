# Release Notes

Catalogue, naming, and source-of-truth discipline for per-tag release notes
published via the project's release workflow.

---

## Directory Contents

| File | Role |
|---|---|
| `README.md` | This document. |
| `TEMPLATE.md` | Skeleton from which new release notes files are copied. |
| `v<X>.<Y>.<Z>.md` | Release notes for tag `v<X>.<Y>.<Z>`. One file per tag. |

## Naming

- Each release notes file MUST be named `<tag>.md` where `<tag>` is the
  literal git tag (e.g., `v0.1.0.md` for tag `v0.1.0`).
- One file per tag. Files MUST NOT be combined or split.

## Source of Truth

`docs/releases/<tag>.md` at the tagged commit is the canonical text of that
tag's release notes.

- The notes file MUST exist at the tagged commit. The release workflow reads
  it via `gh release create --notes-file` and aborts the publish step if the
  file is missing.
- New release notes MUST be authored by copying `TEMPLATE.md` and filling
  every section. Non-template structure introduces inconsistency across
  releases.
- The notes file MUST be committed before the tag is pushed; the tag MUST
  point at a commit that contains the file.

## Workflow Integration

The release workflow at `.github/workflows/release.yml` is the sole
mechanism for creating GitHub Releases. It triggers on tag push matching
`v*.*.*`, builds release-profile disk images for every supported
architecture, and creates a draft Release whose body is the contents of
`docs/releases/<tag>.md`.

The draft is published manually by the maintainer after verifying the
burn-in workflow at `.github/workflows/burnin.yml` completed successfully
on the same tag.

## Post-Publish Edits

A published Release remains editable. The underlying tag and Release URL
are immutable; the title, body, and asset list are mutable.

- Body edits MUST update `docs/releases/<tag>.md` first, then resync the
  GitHub Release via:
  ```sh
  gh release edit <tag> --notes-file docs/releases/<tag>.md
  ```
- The github.com UI MUST NOT be used to edit a published Release body;
  doing so creates drift between the file and the rendered body.
- Asset replacement uses `gh release upload <tag> <file> --clobber`.
  Asset URLs are stable across replacement.
- The tag itself MUST NOT be moved or recreated after a Release is
  published. A tag move breaks every downstream consumer that resolved the
  tag to a commit.

---

## Summarized By

[README.md](../../README.md)
