// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/lint_docs/restore.rs

//! The `src-restore-class` rule: every static of the runtime carries its
//! restore class, and every static a restore rebinds is rebound by the
//! restore entry (runtime/ruststd/README.md § Restore classes).
//!
//! The rule reads the Rust sources under [`CRATES`]. Each `static` item,
//! a `thread_local!` one among them, carries a `// restore: <class>` line
//! among the comment and attribute lines directly above it, the class one of
//! [`CLASSES`]. A function marked `// restore: reset` the same way is a
//! reset, and the one marked `// restore: entry` is the restore entry: each
//! `rebound` static is named in the body of a reset of its own file, or of
//! the entry when the entry is in that file, and each reset is named in the
//! entry's body. A `#[cfg(test)]` module is not read.

use std::collections::BTreeMap;

use super::{Diagnostic, SourceFile, has_ext, one_based};

const RULE: &str = "src-restore-class";

/// The source directories the rule reads: the runtime and the shared crates
/// it links whose statics outlive a restore.
pub(super) const CRATES: [&str; 3] = [
    "runtime/ruststd/src/",
    "shared/log/src/",
    "shared/registry-client/src/",
];

/// The class of a static a restore leaves as the checkpoint holds it.
const NONE: &str = "none";
/// The class of a static whose value names the checkpointed process's
/// capabilities or state, which a reset gives the new process's.
const REBOUND: &str = "rebound";
/// The classes a static may carry.
pub(super) const CLASSES: [&str; 2] = [NONE, REBOUND];

/// The marker of a reset function and of the restore entry.
const RESET: &str = "reset";
const ENTRY: &str = "entry";

/// The marker every class and function mark starts with.
const MARK: &str = "// restore:";

/// A function a mark names: its name, its file, the 1-based line of its
/// `fn` and its body's text.
struct Marked<'a>
{
    name: String,
    path: &'a str,
    line: usize,
    body: String,
}

/// A `rebound` static: its name, its file and its 1-based line.
struct Rebound<'a>
{
    name: String,
    path: &'a str,
    line: usize,
}

/// The rule over `sources`, the tracked source files.
pub(super) fn check(sources: &[&SourceFile]) -> Vec<Diagnostic>
{
    let mut diags = Vec::new();
    let mut rebound = Vec::new();
    let mut resets = Vec::new();
    let mut entries = Vec::new();
    for file in sources
        .iter()
        .filter(|f| has_ext(&f.path, "rs") && CRATES.iter().any(|c| f.path.starts_with(c)))
    {
        scan(file, &mut diags, &mut rebound, &mut resets, &mut entries);
    }
    let entry = match entries.as_slice()
    {
        [entry] => Some(entry),
        [] =>
        {
            if !rebound.is_empty() || !resets.is_empty()
            {
                let path = CRATES[0];
                diags.push(Diagnostic::new(
                    RULE,
                    path,
                    1,
                    "no function is marked `// restore: entry`",
                ));
            }
            None
        }
        [_, more @ ..] =>
        {
            for m in more
            {
                diags.push(Diagnostic::new(
                    RULE,
                    m.path,
                    m.line,
                    format!("`{}` is a second restore entry", m.name),
                ));
            }
            None
        }
    };
    let mut names: BTreeMap<&str, &Marked<'_>> = BTreeMap::new();
    for reset in &resets
    {
        if let Some(first) = names.insert(&reset.name, reset)
        {
            diags.push(Diagnostic::new(
                RULE,
                reset.path,
                reset.line,
                format!(
                    "the reset `{}` shares its name with the one at {}:{}",
                    reset.name, first.path, first.line
                ),
            ));
        }
        if let Some(entry) = entry
            && !names_word(&entry.body, &reset.name)
        {
            diags.push(Diagnostic::new(
                RULE,
                reset.path,
                reset.line,
                format!(
                    "the restore entry `{}` does not call the reset `{}`",
                    entry.name, reset.name
                ),
            ));
        }
    }
    for r in &rebound
    {
        let reset_by = resets
            .iter()
            .chain(entry)
            .any(|m| m.path == r.path && names_word(&m.body, &r.name));
        if !reset_by
        {
            diags.push(Diagnostic::new(
                RULE,
                r.path,
                r.line,
                format!(
                    "the `rebound` static `{}` is named by no reset of its file",
                    r.name
                ),
            ));
        }
    }
    diags
}

/// Read one file's statics and marked functions.
fn scan<'a>(
    file: &'a SourceFile,
    diags: &mut Vec<Diagnostic>,
    rebound: &mut Vec<Rebound<'a>>,
    resets: &mut Vec<Marked<'a>>,
    entries: &mut Vec<Marked<'a>>,
)
{
    let lines: Vec<&str> = file.text.lines().collect();
    let mut i = 0;
    while let Some(&line) = lines.get(i)
    {
        if line.trim() == "#[cfg(test)]"
            && lines
                .get(i.saturating_add(1))
                .is_some_and(|next| item_after_vis(next.trim()).starts_with("mod "))
        {
            i = block_end(&lines, i.saturating_add(1)).saturating_add(1);
            continue;
        }
        if let Some(name) = static_name(line)
        {
            match mark_above(&lines, i)
            {
                None => diags.push(Diagnostic::new(
                    RULE,
                    &file.path,
                    one_based(i),
                    format!("the static `{name}` carries no `{MARK} <class>` line"),
                )),
                Some(class) if class == REBOUND => rebound.push(Rebound {
                    name: name.to_owned(),
                    path: &file.path,
                    line: one_based(i),
                }),
                Some(class) if class == NONE =>
                {}
                Some(class) => diags.push(Diagnostic::new(
                    RULE,
                    &file.path,
                    one_based(i),
                    format!(
                        "the static `{name}` carries the class `{class}`, not one of {}",
                        CLASSES.join(", ")
                    ),
                )),
            }
        }
        else if let Some(name) = fn_name(line)
        {
            let kind = mark_above(&lines, i);
            if let Some(kind) = kind.filter(|k| *k == RESET || *k == ENTRY)
            {
                let end = block_end(&lines, i);
                let marked = Marked {
                    name: name.to_owned(),
                    path: &file.path,
                    line: one_based(i),
                    body: lines.get(i..=end).unwrap_or_default().join("\n"),
                };
                if kind == RESET
                {
                    resets.push(marked);
                }
                else
                {
                    entries.push(marked);
                }
            }
        }
        i = i.saturating_add(1);
    }
}

/// `s` without a leading visibility (`pub`, `pub(crate)`, `pub(super)` and
/// the like).
fn item_after_vis(s: &str) -> &str
{
    let Some(rest) = s.strip_prefix("pub")
    else
    {
        return s;
    };
    let rest = match rest.strip_prefix('(')
    {
        Some(inner) => inner.split_once(')').map_or(rest, |(_, after)| after),
        None => rest,
    };
    if rest.starts_with(char::is_whitespace)
    {
        rest.trim_start()
    }
    else
    {
        s
    }
}

/// The name of the static item `line` opens, if it opens one.
fn static_name(line: &str) -> Option<&str>
{
    let rest = item_after_vis(line.trim()).strip_prefix("static ")?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("mut ").unwrap_or(rest).trim_start();
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let (name, after) = rest.split_at(end);
    (!name.is_empty() && after.trim_start().starts_with(':')).then_some(name)
}

/// The name of the function `line` opens, if it opens one.
fn fn_name(line: &str) -> Option<&str>
{
    let mut rest = item_after_vis(line.trim());
    for qualifier in ["const ", "unsafe ", "extern \"C\" ", "extern \"Rust\" "]
    {
        rest = rest.strip_prefix(qualifier).unwrap_or(rest);
    }
    let rest = rest.strip_prefix("fn ")?;
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let name = rest.get(..end)?;
    (!name.is_empty()).then_some(name)
}

/// The word of the `// restore:` line among the comment and attribute lines
/// directly above line `at`, an attribute written over several lines
/// among them.
fn mark_above<'l>(lines: &[&'l str], at: usize) -> Option<&'l str>
{
    let mut in_attribute = false;
    for line in lines
        .get(..at)
        .unwrap_or_default()
        .iter()
        .rev()
        .map(|l| l.trim())
    {
        if in_attribute
        {
            in_attribute = !line.starts_with("#[");
            continue;
        }
        if let Some(word) = line.strip_prefix(MARK)
        {
            return Some(word.trim());
        }
        if line.starts_with("//") || line.starts_with("#[")
        {
            continue;
        }
        if line.ends_with(']')
        {
            in_attribute = true;
            continue;
        }
        return None;
    }
    None
}

/// The index of the line that closes the block opened at or after line
/// `at`, by counting braces outside `//` comments; the last line when it
/// never closes.
fn block_end(lines: &[&str], at: usize) -> usize
{
    let mut depth = 0usize;
    let mut opened = false;
    for (i, line) in lines.iter().enumerate().skip(at)
    {
        let code = line.split_once("//").map_or(*line, |(code, _)| code);
        for c in code.chars()
        {
            match c
            {
                '{' =>
                {
                    depth = depth.saturating_add(1);
                    opened = true;
                }
                '}' => depth = depth.saturating_sub(1),
                _ =>
                {}
            }
        }
        if opened && depth == 0
        {
            return i;
        }
        if !opened && code.trim_end().ends_with(';')
        {
            return i;
        }
    }
    lines.len().saturating_sub(1)
}

/// Whether `text` holds `word` as a whole word.
fn names_word(text: &str, word: &str) -> bool
{
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word).any(|(at, _)| {
        let before = text.get(..at).and_then(|s| s.chars().next_back());
        let after = text
            .get(at.saturating_add(word.len())..)
            .and_then(|s| s.chars().next());
        !before.is_some_and(is_word) && !after.is_some_and(is_word)
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn src(path: &str, text: &str) -> SourceFile
    {
        SourceFile {
            path: path.into(),
            text: text.into(),
        }
    }

    fn messages(files: &[SourceFile]) -> Vec<(String, usize, String)>
    {
        let refs: Vec<&SourceFile> = files.iter().collect();
        check(&refs)
            .into_iter()
            .map(|d| (d.path, d.line, d.message))
            .collect()
    }

    const CLASSED: &str = "\
// restore: none
static KEPT: u8 = 0;

/// Rebound below.
// restore: rebound
#[expect(dead_code, reason = \"fixture\")]
pub(crate) static mut CAP: u64 = 0;

thread_local! {
    // restore: rebound
    static KEYS: Cell<u64> = const { Cell::new(0) };
}

static UNCLASSED: u8 = 0;

// restore: rebound
static FORGOTTEN: u64 = 0;

// restore: kept
static UNKNOWN: u8 = 0;

fn takes(_: &'static str) {}

// restore: reset
#[expect(
    clippy::too_many_arguments,
    reason = \"fixture\"
)]
pub(crate) fn rebind()
{
    unsafe { CAP = 1 };
    KEYS.with(|k| k.set(1));
}

#[cfg(test)]
mod tests
{
    static IN_TEST: u8 = 0;
}
";

    const ENTRY_FILE: &str = "\
// restore: entry
fn restore_entry() -> !
{
    crate::sys::rebind();
    loop {}
}
";

    #[test]
    fn a_static_of_each_class_and_each_fault_is_judged()
    {
        let files = [
            src("runtime/ruststd/src/sys/a.rs", CLASSED),
            src("runtime/ruststd/src/os/seraph.rs", ENTRY_FILE),
            src("services/other/src/main.rs", "static OUTSIDE: u8 = 0;\n"),
        ];
        let got = messages(&files);
        let at = |line: usize| got.iter().filter(|(_, l, _)| *l == line).count();
        assert_eq!(at(2), 0, "a none static: {got:?}");
        assert_eq!(at(7), 0, "a rebound static its reset names: {got:?}");
        assert_eq!(at(11), 0, "a rebound thread_local its reset names: {got:?}");
        assert!(
            got.iter()
                .any(|(_, l, m)| *l == 14 && m.contains("UNCLASSED") && m.contains("no")),
            "a static without a class: {got:?}"
        );
        assert!(
            got.iter()
                .any(|(_, l, m)| *l == 17 && m.contains("FORGOTTEN") && m.contains("no reset")),
            "a rebound static missing from the reset: {got:?}"
        );
        assert!(
            got.iter().any(|(_, l, m)| *l == 20 && m.contains("kept")),
            "an unknown class: {got:?}"
        );
        assert_eq!(
            got.len(),
            3,
            "nothing else, the test module and other crates unread: {got:?}"
        );
    }

    #[test]
    fn a_reset_the_entry_does_not_call_is_reported()
    {
        let files = [
            src(
                "shared/log/src/lib.rs",
                "// restore: rebound\nstatic CAP: u64 = 0;\n\n// restore: reset\npub fn rebind_log()\n{\n    let _ = CAP;\n}\n",
            ),
            src("runtime/ruststd/src/os/seraph.rs", ENTRY_FILE),
        ];
        let got = messages(&files);
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(
            got.iter()
                .any(|(_, l, m)| *l == 5 && m.contains("rebind_log")),
            "{got:?}"
        );
    }

    #[test]
    fn the_entry_resets_the_statics_of_its_own_file()
    {
        let files = [src(
            "runtime/ruststd/src/os/seraph.rs",
            "// restore: rebound\nstatic INFO: u64 = 0;\n\n// restore: entry\nfn restore_entry()\n{\n    let _ = INFO;\n}\n",
        )];
        assert_eq!(messages(&files), Vec::new());
    }

    #[test]
    fn the_word_test_takes_whole_words()
    {
        assert!(names_word("a CAP b", "CAP"));
        assert!(!names_word("a CAPS b", "CAP"));
        assert!(!names_word("MY_CAP", "CAP"));
        assert_eq!(
            static_name("    pub(crate) static mut X_Y: u8 = 0;"),
            Some("X_Y")
        );
        assert_eq!(static_name("fn f(s: &'static str)"), None);
        assert_eq!(
            fn_name("pub(crate) unsafe fn rebind_alloc(a: u64)"),
            Some("rebind_alloc")
        );
    }
}
