# Documentation Standards

This document is the authoritative standard for all documentation in the Seraph project.
It governs document structure, authority relationships, linking, and maintenance discipline.

---

## Document Hierarchy

Four documentation scopes exist:

| Scope | Location | Role |
|---|---|---|
| System | `docs/*.md` | Authoritative for system-wide behavior and invariants |
| Component | `<component>/README.md` | Authoritative for that component's scope and structure |
| Design-authority | `<component>/docs/*.md` | Authoritative for component-internal design decisions |
| Routing | Root `README.md` | Routes to authoritative documents; may summarize their content; carries no original behavior |

- Every component MUST have a `README.md`.
- A component MAY have a `docs/` directory.
- If a component has no `docs/` directory, its `README.md` is the sole authoritative
  document for that component.
- A component README carries original authoritative content only if the component has
  no `docs/` subdirectory. If a `docs/` subdirectory exists, the README contains only
  summaries of its `docs/*.md` files and the system-scope documents it depends on;
  every such summary MUST link the authoritative source.
- The root README routes to `docs/*.md` via its link list and MAY contain
  summaries of content owned by `docs/*.md` or by top-level non-component
  targets (for example `xtask/README.md`). Every summary MUST link its
  authoritative source. Summaries MUST NOT introduce normative or
  behavior-bearing content not present in the authoritative source.

---

## Authority and Duplication

- An **authoritative** document is the primary specification for the content it contains.
- A **summary** condenses content owned by an authoritative document.
- Higher-level documents MAY summarize lower-level documents.
- Higher-level documents MUST NOT specify or restate behavior owned by an authoritative
  lower-level document.
- A summary MUST link to the authoritative document it summarizes.

---

## Backlinks and Change Propagation

Every authoritative document MUST include a `## Summarized By` section at the end of the
document (after a `---` separator) listing every document that contains a summary of its
content, regardless of hierarchical relationship. Structural parent READMEs are not
implicitly exempt; if a parent README summarizes a child doc, the parent MUST appear in
the child's `## Summarized By` list.

```markdown
---

## Summarized By

[Title](relative/path.md), [Title](relative/path.md)
```

If no non-structural document summarizes this document:

```markdown
---

## Summarized By

None
```

### Change propagation procedure

When implementation changes invalidate documentation:

1. Update the most specific authoritative document first.
2. Identify all upstream summaries via the `## Summarized By` section.
3. Review and update each identified summary if necessary.

This procedure is mandatory. Skipping it allows silent conceptual drift.

---

## Documentation and Code Comments

Documentation defines behavior and invariants at the system or component level.
Code comments explain local intent, constraints, or non-obvious rationale.

- Comments MUST NOT duplicate documentation content.
- Where a comment depends on a documented invariant, it MUST reference the relevant document
  rather than restate the invariant inline.

Detailed comment conventions are in [coding-standards.md](coding-standards.md).

---

## Tone and Language

- Use normative language where the rule admits no discretion: MUST, MUST NOT, SHOULD, MAY
  (RFC 2119 semantics).
- Write declaratively and concisely. Omit narrative, motivational, and conversational prose.
- Avoid examples unless an example is the only means of defining a structural rule.

---

## Discoverability and Linking

No document may be orphaned. Every document MUST be reachable by following links from the
root `README.md` through this hierarchy:

```
Root README.md
  └─► docs/*.md
  └─► <component>/README.md
        └─► <component>/docs/*.md
```

### Root README.md

- MUST describe the project structure and purpose of each top-level directory.
- MUST link to every document in `docs/`.
- SHOULD NOT list or link to individual component `README.md` files.
- MUST NOT contain original normative or behavior-bearing content. Project-level
  framing (goals, positioning) lives in `docs/architecture.md`.

### Component README.md

- MUST describe the component's internal structure.
- MUST link to all documents in its `docs/` directory, if present.
- MUST link to any system-level documents it directly summarizes.
- MUST NOT restate authoritative content owned by its own `docs/*.md` files. If it
  mentions that content, it MUST link the authoritative source and contain only
  summary-form prose.

---

## Required Structure

Mandatory sections for all authoritative documents (additional sections permitted):

```markdown
# Title

<One-sentence purpose statement.>

---

## <Content sections>

---

## Summarized By

[Title](path), … | None
```

Component README.md files follow the same pattern with two required content sections:
**Source Layout** (directory/file tree) and **Relevant Design Documents** (table linking
to system-level documents this component summarizes or depends on).

---

## Summarized By

None
