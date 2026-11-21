// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/lint_docs/cells.rs

//! The `md-test-cells` rule: the documents that state the case registry
//! (`commands::test::cases`) state it as it is, so a case added to the
//! registry, moved to another cell, or given another architecture fails the
//! lint until they do.
//!
//! xtask/README.md § `cargo xtask test` restates the registry in its Cases
//! table, row for row, and gives each case a ``#### The `<case>` case``
//! section; docs/testing.md § Gating gives each a heading naming
//! ``(`<case>` case)``; and the cell table of docs/testing.md § Coverage
//! tiers lists each case in the cell that runs it, on the architectures it
//! runs on.

use std::collections::BTreeSet;

use super::{COVERAGE_DOC, COVERAGE_HEADING, Diagnostic, SourceFile, one_based};
use crate::arch::Arch;
use crate::argparse::ValueEnum as _;
use crate::cli::{TestCase, Tester};
use crate::commands::test::cases::{self, Case, Cell};

const RULE: &str = "md-test-cells";

/// The command reference and the heading of its Cases table.
const README: &str = "xtask/README.md";
const CASES_HEADING: &str = "#### Cases";

/// The heading of the section of docs/testing.md that describes each case.
const GATING_HEADING: &str = "## Gating";

/// The first header cell of the cell table of docs/testing.md § Coverage tiers.
const CELL_COLUMN: &str = "Cell";

/// The architectures, as the documents write them.
const ARCHES: [Arch; 2] = [Arch::X86_64, Arch::Riscv64];

/// A Markdown table: the 1-based line of its header, its header cells, and
/// each row's cells with the row's 1-based line.
struct Table
{
    line: usize,
    header: Vec<String>,
    rows: Vec<(usize, Vec<String>)>,
}

impl Table
{
    /// The index of the column headed `name`.
    fn column(&self, name: &str) -> Option<usize>
    {
        self.header.iter().position(|cell| cell == name)
    }
}

/// The cells of the table row `line`.
fn row_cells(line: &str) -> Vec<String>
{
    let inner = line.trim();
    let inner = inner.strip_prefix('|').unwrap_or(inner);
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    inner
        .split('|')
        .map(|cell| cell.trim().to_owned())
        .collect()
}

/// The prose lines of the section `heading` opens in `text` (zero-based
/// index, line), up to the next heading of its level or above, the lines of
/// fenced code blocks left out; `None` when no prose line is `heading`.
fn section<'a>(text: &'a str, heading: &str) -> Option<Vec<(usize, &'a str)>>
{
    let level = heading.chars().take_while(|&c| c == '#').count();
    // A heading is prose: a `#` line in a fenced code block is not one.
    let mut lines = super::prose_lines(text);
    lines.find(|(_, line)| line.trim_end() == heading)?;
    Some(
        lines
            .take_while(|(_, line)| {
                let hashes = line.chars().take_while(|&c| c == '#').count();
                !(hashes > 0 && hashes <= level && line.chars().nth(hashes) == Some(' '))
            })
            .collect(),
    )
}

/// The tables of `lines`, in order.
fn tables(lines: &[(usize, &str)]) -> Vec<Table>
{
    let mut out: Vec<Table> = Vec::new();
    // The index of the last row seen: a table's rows are consecutive lines.
    let mut previous_row: Option<usize> = None;
    for &(idx, line) in lines
    {
        let row = line.trim_start().starts_with('|');
        if row && previous_row.is_none_or(|previous| previous.saturating_add(1) != idx)
        {
            out.push(Table {
                line: one_based(idx),
                header: row_cells(line),
                rows: Vec::new(),
            });
        }
        else if row && let Some(table) = out.last_mut()
        {
            let cells = row_cells(line);
            let separator = cells
                .iter()
                .all(|cell| !cell.is_empty() && cell.chars().all(|c| matches!(c, '-' | ':')));
            if !separator
            {
                table.rows.push((one_based(idx), cells));
            }
        }
        previous_row = row.then_some(idx);
    }
    out
}

/// The code spans of `cell`, each with the text that follows it up to the
/// next span.
fn spans(cell: &str) -> Vec<(&str, &str)>
{
    let pieces: Vec<&str> = cell.split('`').collect();
    pieces
        .iter()
        .enumerate()
        .skip(1)
        .step_by(2)
        .map(|(i, span)| {
            (
                *span,
                pieces.get(i.saturating_add(1)).copied().unwrap_or(""),
            )
        })
        .collect()
}

/// The architectures `text` names.
fn arches_in(text: &str) -> BTreeSet<String>
{
    ARCHES
        .iter()
        .map(ToString::to_string)
        .filter(|arch| text.contains(arch.as_str()))
        .collect()
}

/// The architectures the case `entry` runs on.
fn case_arches(entry: &Case) -> BTreeSet<String>
{
    entry
        .arches
        .iter()
        .map(|(arch, _)| arch.to_string())
        .collect()
}

/// The registered case named `name`.
fn case_named(name: &str) -> Option<TestCase>
{
    TestCase::VARIANTS
        .iter()
        .copied()
        .find(|case| case.name() == name)
}

/// The cells of a case's row in the Cases table of xtask/README.md: case,
/// architectures with their boots, bundle, cell, case options.
fn readme_row(name: TestCase, entry: &Case) -> [String; 5]
{
    let arches: Vec<String> = entry
        .arches
        .iter()
        .map(|(arch, boots)| format!("{arch} ({boots})"))
        .collect();
    let cell = match entry.cell
    {
        Cell::Ci(tester) => tester.name(),
        Cell::Host => "host run".to_owned(),
    };
    let options = if entry.options.is_empty()
    {
        "none".to_owned()
    }
    else
    {
        let flags: Vec<String> = entry
            .options
            .iter()
            .map(|option| format!("`{}`", option.flag()))
            .collect();
        flags.join(", ")
    };
    [
        format!("`{}`", name.name()),
        arches.join(", "),
        entry.bundle.name(),
        cell,
        options,
    ]
}

/// The Cases table of xtask/README.md equals the registry, row for row, and
/// every case has its section there.
fn check_readme(doc: &SourceFile) -> Vec<Diagnostic>
{
    let mut diags = Vec::new();
    let Some(lines) = section(&doc.text, CASES_HEADING)
    else
    {
        return vec![Diagnostic::new(
            RULE,
            README,
            1,
            format!("no `{CASES_HEADING}` section states the case registry"),
        )];
    };
    let Some(table) = tables(&lines).into_iter().next()
    else
    {
        return vec![Diagnostic::new(
            RULE,
            README,
            lines.first().map_or(1, |&(idx, _)| one_based(idx)),
            format!("`{CASES_HEADING}` holds no table of the case registry"),
        )];
    };
    let mut seen = BTreeSet::new();
    for (line, cells) in &table.rows
    {
        let first = cells.first().map_or("", String::as_str);
        let Some(name) = case_named(first.trim_matches('`'))
        else
        {
            diags.push(Diagnostic::new(
                RULE,
                README,
                *line,
                format!("the row `{first}` names no case of the registry"),
            ));
            continue;
        };
        if !seen.insert(name.name())
        {
            diags.push(Diagnostic::new(
                RULE,
                README,
                *line,
                format!("the {} case has a second row", name.name()),
            ));
            continue;
        }
        let expected = readme_row(name, &cases::case(name));
        if cells.as_slice() != expected.as_slice()
        {
            diags.push(Diagnostic::new(
                RULE,
                README,
                *line,
                format!(
                    "the row states `| {} |`, and the registry `| {} |`",
                    cells.join(" | "),
                    expected.join(" | ")
                ),
            ));
        }
    }
    for &name in TestCase::VARIANTS
    {
        if !seen.contains(&name.name())
        {
            diags.push(Diagnostic::new(
                RULE,
                README,
                table.line,
                format!("the {} case of the registry has no row", name.name()),
            ));
        }
        let heading = format!("#### The `{}` case", name.name());
        if !doc.text.lines().any(|line| line.trim_end() == heading)
        {
            diags.push(Diagnostic::new(
                RULE,
                README,
                table.line,
                format!("the {} case has no `{heading}` section", name.name()),
            ));
        }
    }
    diags
}

/// Every case has a heading in docs/testing.md § Gating.
fn check_gating(doc: &SourceFile) -> Vec<Diagnostic>
{
    let Some(lines) = section(&doc.text, GATING_HEADING)
    else
    {
        return vec![Diagnostic::new(
            RULE,
            COVERAGE_DOC,
            1,
            format!("no `{GATING_HEADING}` section describes the cases"),
        )];
    };
    let at = lines.first().map_or(1, |&(idx, _)| idx);
    let at = one_based(at.saturating_sub(1));
    TestCase::VARIANTS
        .iter()
        .filter(|name| {
            let named = format!("(`{}` case)", name.name());
            !lines
                .iter()
                .any(|(_, line)| line.starts_with('#') && line.contains(named.as_str()))
        })
        .map(|name| {
            Diagnostic::new(
                RULE,
                COVERAGE_DOC,
                at,
                format!(
                    "no heading of `{GATING_HEADING}` names the {} case as \"(`{}` case)\"",
                    name.name(),
                    name.name()
                ),
            )
        })
        .collect()
}

/// One case a row of the cell table lists: the row's line, the cell's
/// name, the architectures it lists the case on, and how many cases the row
/// lists.
struct Listing
{
    line: usize,
    cell: String,
    arches: BTreeSet<String>,
    row_cases: usize,
}

/// The cell table of docs/testing.md § Coverage tiers lists each case once,
/// in the row of the cell the registry gives it, on its architectures: a CI
/// case in its tester's row, a host-run case in a row of its own.
fn check_cell_table(doc: &SourceFile) -> Vec<Diagnostic>
{
    let missing =
        |line: usize, what: &str| vec![Diagnostic::new(RULE, COVERAGE_DOC, line, what.to_owned())];
    let Some(lines) = section(&doc.text, COVERAGE_HEADING)
    else
    {
        return missing(1, "no `## Coverage tiers` section holds the cell table");
    };
    let Some(table) = tables(&lines)
        .into_iter()
        .find(|table| table.header.first().is_some_and(|cell| cell == CELL_COLUMN))
    else
    {
        return missing(
            lines.first().map_or(1, |&(idx, _)| one_based(idx)),
            "§ Coverage tiers holds no cell table (a table whose first column is `Cell`)",
        );
    };
    let (Some(arch_col), Some(cases_col)) = (table.column("Architectures"), table.column("Cases"))
    else
    {
        return missing(
            table.line,
            "the cell table has no `Architectures` or no `Cases` column",
        );
    };
    let mut diags = Vec::new();
    let listings = listings(&table, arch_col, cases_col, &mut diags);
    for &name in TestCase::VARIANTS
    {
        diags.extend(check_placement(name, &listings, table.line));
    }
    diags
}

/// The cases the rows of the cell `table` list, each with its listing; a
/// span naming no case is reported to `diags`.
fn listings(
    table: &Table,
    arch_col: usize,
    cases_col: usize,
    diags: &mut Vec<Diagnostic>,
) -> Vec<(TestCase, Listing)>
{
    let mut listings: Vec<(TestCase, Listing)> = Vec::new();
    for (line, cells) in &table.rows
    {
        let cell_name = cells
            .first()
            .and_then(|cell| spans(cell).first().map(|(span, _)| (*span).to_owned()))
            .unwrap_or_else(|| cells.first().cloned().unwrap_or_default());
        let row_arches = arches_in(cells.get(arch_col).map_or("", String::as_str));
        let listed = spans(cells.get(cases_col).map_or("", String::as_str));
        for (span, after) in &listed
        {
            let Some(name) = case_named(span)
            else
            {
                diags.push(Diagnostic::new(
                    RULE,
                    COVERAGE_DOC,
                    *line,
                    format!("`{span}` names no case of the registry"),
                ));
                continue;
            };
            let qualifier = after
                .trim_start()
                .strip_prefix('(')
                .and_then(|rest| rest.split_once(')'))
                .map(|(inside, _)| arches_in(inside))
                .filter(|arches| !arches.is_empty());
            listings.push((
                name,
                Listing {
                    line: *line,
                    cell: cell_name.clone(),
                    arches: qualifier.unwrap_or_else(|| row_arches.clone()),
                    row_cases: listed.len(),
                },
            ));
        }
    }
    listings
}

/// The case `name` is listed once in `listings` (the cell table, its header at
/// `table_line`), in the cell the registry gives it, on its architectures.
fn check_placement(
    name: TestCase,
    listings: &[(TestCase, Listing)],
    table_line: usize,
) -> Vec<Diagnostic>
{
    let testers: Vec<String> = Tester::VARIANTS
        .iter()
        .map(|tester| tester.name())
        .collect();
    let mut diags = Vec::new();
    let entry = cases::case(name);
    let arches = case_arches(&entry);
    let found: Vec<&Listing> = listings
        .iter()
        .filter(|(listed, _)| *listed == name)
        .map(|(_, listing)| listing)
        .collect();
    let [listing] = found.as_slice()
    else
    {
        let at = found.get(1).map_or(table_line, |listing| listing.line);
        diags.push(Diagnostic::new(
            RULE,
            COVERAGE_DOC,
            at,
            format!(
                "the cell table lists the {} case {} times, and the registry gives it one cell",
                name.name(),
                found.len()
            ),
        ));
        return diags;
    };
    let wrong_cell =
        match entry.cell
        {
            Cell::Ci(tester) => (listing.cell != tester.name())
                .then(|| format!("the CI cells of `{}`", tester.name())),
            Cell::Host => (testers.contains(&listing.cell) || listing.row_cases != 1)
                .then(|| "a host-run cell of its own".to_owned()),
        };
    if let Some(cell) = wrong_cell
    {
        diags.push(Diagnostic::new(
            RULE,
            COVERAGE_DOC,
            listing.line,
            format!(
                "the cell table lists the {} case in the `{}` row, and the registry runs it in {cell}",
                name.name(),
                listing.cell
            ),
        ));
    }
    if listing.arches != arches
    {
        let shown = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(", ");
        diags.push(Diagnostic::new(
            RULE,
            COVERAGE_DOC,
            listing.line,
            format!(
                "the cell table lists the {} case on {}, and the registry runs it on {}",
                name.name(),
                shown(&listing.arches),
                shown(&arches)
            ),
        ));
    }
    diags
}

/// The documents that state the case registry state it as it is.
pub(super) fn check(markdown: &[&SourceFile]) -> Vec<Diagnostic>
{
    let mut diags = Vec::new();
    for (path, check) in [
        (README, check_readme as fn(&SourceFile) -> Vec<Diagnostic>),
        (COVERAGE_DOC, |doc: &SourceFile| {
            let mut diags = check_gating(doc);
            diags.extend(check_cell_table(doc));
            diags
        }),
    ]
    {
        match markdown.iter().find(|file| file.path == path)
        {
            Some(doc) => diags.extend(check(doc)),
            None => diags.push(Diagnostic::new(RULE, path, 1, "not a tracked document")),
        }
    }
    diags
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn doc(path: &str, text: &str) -> SourceFile
    {
        SourceFile {
            path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    /// The tracked documents, read once.
    fn tracked(path: &str) -> String
    {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        std::fs::read_to_string(root.join(path)).unwrap()
    }

    fn messages(readme: &str, testing: &str) -> Vec<String>
    {
        let readme = doc(README, readme);
        let testing = doc(COVERAGE_DOC, testing);
        check(&[&readme, &testing])
            .into_iter()
            .map(|d| d.message)
            .collect()
    }

    // Defect caught: the rule refusing the documents as the tree holds them,
    // which would fail every CI run.
    // Defect caught: a `#` comment in a fenced block read as a heading, which
    // ended the section before its own tables and headings.
    #[test]
    fn a_comment_in_a_fenced_block_does_not_end_a_section()
    {
        let text = "## Gating\n\n```sh\n# a comment\n```\n\n| A |\n|---|\n| x |\n\n## Next\n";
        let lines = section(text, "## Gating").unwrap_or_default();
        let rows: Vec<usize> = tables(&lines)
            .iter()
            .map(|table| table.rows.len())
            .collect();
        assert_eq!(rows, vec![1]);
    }

    #[test]
    fn the_tracked_documents_state_the_registry()
    {
        let found = messages(&tracked(README), &tracked(COVERAGE_DOC));
        assert!(found.is_empty(), "{found:?}");
    }

    // Defect caught: a case added to the registry, or a row changed, that the
    // README's Cases table does not follow.
    #[test]
    fn a_cases_table_row_that_differs_from_the_registry_is_reported()
    {
        let readme = tracked(README);
        let testing = tracked(COVERAGE_DOC);
        let row = readme
            .lines()
            .find(|line| line.starts_with("| `kaslr` |"))
            .unwrap();
        let found = messages(&readme.replace(&format!("{row}\n"), ""), &testing);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("kaslr case of the registry has no row"));
        let found = messages(
            &readme.replace(row, &row.replace("ktest |", "init |")),
            &testing,
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("the registry `| `kaslr` |"), "{found:?}");
        let found = messages(&readme.replace(row, &format!("{row}\n{row}")), &testing);
        assert!(found.iter().any(|m| m.contains("second row")), "{found:?}");
        let stray = "| `rollbak` | x86_64 (1) | init | usertest | none |";
        let found = messages(&readme.replace(row, &format!("{row}\n{stray}")), &testing);
        assert!(
            found.iter().any(|m| m.contains("names no case")),
            "{found:?}"
        );
    }

    // Defect caught: a case without its README section or its Gating heading.
    #[test]
    fn a_case_without_its_section_or_gating_heading_is_reported()
    {
        let readme = tracked(README);
        let testing = tracked(COVERAGE_DOC);
        let found = messages(&readme.replace("#### The `tpm` case", "#### TPM"), &testing);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("tpm case has no"), "{found:?}");
        let found = messages(&readme, &testing.replace("(`wedge` case)", "(wedge)"));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("wedge case"), "{found:?}");
    }

    // Defect caught: the cell table missing a case, listing it in a cell
    // that does not run it, or on architectures it does not run on.
    #[test]
    fn a_cell_table_that_places_a_case_otherwise_than_the_registry_is_reported()
    {
        let readme = tracked(README);
        let testing = tracked(COVERAGE_DOC);
        let usertest = testing
            .lines()
            .find(|line| line.starts_with("| `usertest` | Canonical |"))
            .unwrap();
        for (changed, expected) in [
            (
                usertest.replace("`vmgenid` (x86_64), ", ""),
                "vmgenid case 0 times",
            ),
            (
                usertest.replace("`vmgenid` (x86_64)", "`vmgenid`"),
                "vmgenid case on riscv64",
            ),
            (
                usertest.replace("`shutdown`", "`shutdown`, `kaslr`"),
                "kaslr case 2 times",
            ),
            (
                usertest.replace("`terminal`", "`terminal`, `termnal`"),
                "`termnal` names no case",
            ),
        ]
        {
            let found = messages(&readme, &testing.replace(usertest, &changed));
            assert_eq!(found.len(), 1, "{expected}: {found:?}");
            assert!(found[0].contains(expected), "{expected}: {found:?}");
        }
        let tpm = testing
            .lines()
            .find(|line| line.starts_with("| tpm |"))
            .unwrap();
        let found = messages(
            &readme,
            &testing.replace(tpm, &tpm.replace("`tpm` |", "`tpm`, `cet` |")),
        );
        assert!(
            found
                .iter()
                .any(|m| m.contains("a host-run cell of its own")),
            "{found:?}"
        );
        let found = messages(&readme, &testing.replace("| Cell |", "| Row |"));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("no cell table"), "{found:?}");
    }
}
