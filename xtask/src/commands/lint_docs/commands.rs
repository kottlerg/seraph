// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/lint_docs/commands.rs

//! The `xtask-commands` rule: every `cargo xtask` command line a document, a
//! workflow or an assistant file writes resolves against the command table
//! (`Cli::command`), which is the one source of the command names.
//!
//! A command line is the text after `cargo xtask` up to the end of its code
//! span, of its line (a trailing backslash continues it on the next line of a
//! fenced block or a workflow), a shell separator, a redirection, or a
//! comment. Its literal words resolve, level by level, to a command and its
//! sub-commands, the first positional that takes a fixed set of values (the
//! case of `test`) must name one of them, and each `--option` on it must be an
//! option of the command it resolved to. A placeholder (`<N>`, `A`, `${...}`)
//! where a sub-command stands ends the resolution of sub-commands, and the
//! options after it are then checked against that command and every command
//! below it.

use super::{CodeSpans, Diagnostic, SourceFile, has_ext, is_markdown, marked_lines, one_based};
use crate::argparse::Command;
use crate::cli::Cli;

const RULE: &str = "xtask-commands";

/// What precedes a command line.
const INVOCATION: &str = "cargo xtask";

/// How a file the rule reads writes a command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope
{
    /// Markdown: in a code span, or on a line of a fenced block.
    Markdown,
    /// A workflow or a shell script: on any line, quotes delimiting one word.
    Shell,
    /// A script or a settings file: on any line, inside a string that a quote
    /// ends.
    Script,
}

/// Whether the rule reads `path`, and how: every tracked Markdown document
/// but the per-tag release notes (`docs/releases/v*.md`, records of the
/// commands of their release), and every workflow, script and settings file
/// under `.github/` and `.claude/`.
fn scope(path: &str) -> Option<Scope>
{
    if is_markdown(path)
    {
        return (!path.starts_with("docs/releases/v")).then_some(Scope::Markdown);
    }
    if !(path.starts_with(".github/") || path.starts_with(".claude/"))
    {
        return None;
    }
    if ["yml", "yaml", "sh"].iter().any(|ext| has_ext(path, ext))
    {
        Some(Scope::Shell)
    }
    else if ["js", "json"].iter().any(|ext| has_ext(path, ext))
    {
        Some(Scope::Script)
    }
    else
    {
        None
    }
}

/// Whether `run` must read `path` for this rule, beyond the Markdown and the
/// sources it reads for the others.
pub(super) fn reads(path: &str) -> bool
{
    scope(path).is_some()
}

/// What a quote does to a command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Quotes
{
    /// It delimits one word, as a shell reads it.
    Delimit,
    /// It ends the command line: the string holding the line ends there.
    End,
}

/// One word of a command line.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token
{
    Word(String),
    /// A quoted word: a value, never a name.
    Quoted,
}

/// The words of the command line at the start of `text`, a quote read as
/// `quotes` says.
fn tokens(text: &str, quotes: Quotes) -> Vec<Token>
{
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    loop
    {
        while chars.get(i).is_some_and(|c| c.is_whitespace())
        {
            i = i.saturating_add(1);
        }
        let Some(&c) = chars.get(i)
        else
        {
            break;
        };
        if c == '`'
        {
            break;
        }
        if c == '"' || c == '\''
        {
            if quotes == Quotes::End
            {
                break;
            }
            let rest = chars.get(i.saturating_add(1)..).unwrap_or_default();
            let Some(len) = rest.iter().position(|&x| x == c)
            else
            {
                break;
            };
            out.push(Token::Quoted);
            i = i.saturating_add(len).saturating_add(2);
            continue;
        }
        let start = i;
        while chars
            .get(i)
            .is_some_and(|&x| !x.is_whitespace() && !matches!(x, '`' | '"' | '\''))
        {
            i = i.saturating_add(1);
        }
        let mut word: String = chars.get(start..i).unwrap_or_default().iter().collect();
        // A workflow expression is one word, whatever its spaces.
        if word.starts_with("${{")
        {
            while !word.ends_with("}}") && i < chars.len()
            {
                word.push(chars.get(i).copied().unwrap_or(' '));
                i = i.saturating_add(1);
            }
            out.push(Token::Quoted);
            continue;
        }
        if word == "\\"
        {
            continue;
        }
        if matches!(word.as_str(), "|" | "||" | "&&" | "&" | ";")
            || word.starts_with('#')
            || word.starts_with('>')
            || word.starts_with("1>")
            || word.starts_with("2>")
        {
            break;
        }
        if let Some(last) = word.strip_suffix(';').or_else(|| word.strip_suffix(')'))
        {
            if !last.is_empty()
            {
                out.push(Token::Word(last.to_owned()));
            }
            break;
        }
        out.push(Token::Word(word));
    }
    out
}

/// Whether `word` is written as a name (a command, a sub-command, a value of
/// a fixed set, an option without its dashes) rather than a placeholder.
fn is_name(word: &str) -> bool
{
    let mut chars = word.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Whether `cmd` or any command under it takes `--name`, and with it a
/// value.
fn option_below(cmd: &Command, name: &str) -> Option<bool>
{
    cmd.long_takes_value(name).or_else(|| {
        cmd.children()
            .iter()
            .find_map(|sub| option_below(sub, name))
    })
}

/// What is wrong with the command line `words` against the command table
/// `table`: each word that names no command, case or option.
fn resolve(table: &Command, words: &[Token]) -> Vec<String>
{
    let mut problems = Vec::new();
    let mut at = table;
    // Whether `at` is the command the line names, not one above a placeholder.
    let mut exact = true;
    let mut positional_seen = false;
    let mut iter = words.iter();
    while let Some(token) = iter.next()
    {
        let Token::Word(word) = token
        else
        {
            if !at.children().is_empty()
            {
                exact = false;
            }
            positional_seen = true;
            continue;
        };
        let bare = word.trim_start_matches('[');
        if let Some(body) = bare.strip_prefix("--")
        {
            let (body, attached) = body
                .split_once('=')
                .map_or((body, false), |(name, _)| (name, true));
            let name = body.trim_end_matches([',', '.', ':', ']', ')']);
            if name.is_empty()
            {
                break;
            }
            if !is_name(name)
            {
                continue;
            }
            match if exact
            {
                at.long_takes_value(name)
            }
            else
            {
                option_below(at, name)
            }
            {
                None => problems.push(format!(
                    "`--{name}` is not an option of `cargo {}`",
                    at.path()
                )),
                Some(true) if !attached =>
                {
                    iter.next();
                }
                Some(_) =>
                {}
            }
            continue;
        }
        if bare.starts_with('-')
        {
            continue;
        }
        let literal = is_name(word);
        if exact && !at.children().is_empty()
        {
            if !literal
            {
                exact = false;
                continue;
            }
            if word == "help"
            {
                break;
            }
            if let Some(sub) = at.child(word)
            {
                at = sub;
                continue;
            }
            problems.push(format!(
                "`{word}` is not a command of `cargo {}`",
                at.path()
            ));
            break;
        }
        if exact && !positional_seen
        {
            positional_seen = true;
            if let Some((value_name, values)) = at.first_positional_values()
                && literal
                && !values.contains(&word.as_str())
            {
                problems.push(format!(
                    "`{word}` is not a {value_name} of `cargo {}`",
                    at.path()
                ));
            }
        }
    }
    problems
}

/// The problems of every command line in `text` (a span's content or a
/// line), each prefixed with the command line as written.
fn check_text(table: &Command, text: &str, quotes: Quotes) -> Vec<String>
{
    let mut problems = Vec::new();
    let mut from = 0usize;
    while let Some(found) = text.get(from..).and_then(|rest| rest.find(INVOCATION))
    {
        let start = from.saturating_add(found).saturating_add(INVOCATION.len());
        from = start;
        let rest = text.get(start..).unwrap_or_default();
        if !(rest.is_empty() || rest.starts_with(char::is_whitespace))
        {
            continue;
        }
        let words = tokens(rest, quotes);
        problems.extend(resolve(table, &words));
    }
    problems
}

/// The lines of `lines` (zero-based index, text), each joined with the lines
/// its trailing backslash continues it on, with the index of its first line.
fn logical_lines<'a>(lines: impl Iterator<Item = (usize, &'a str)>) -> Vec<(usize, String)>
{
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut continued = false;
    for (idx, line) in lines
    {
        match out.last_mut()
        {
            Some((_, text)) if continued =>
            {
                text.push(' ');
                text.push_str(line);
            }
            _ => out.push((idx, line.to_owned())),
        }
        continued = line.trim_end().ends_with('\\');
        if let Some((_, text)) = out.last_mut()
            && continued
        {
            let kept = text.trim_end().trim_end_matches('\\').len();
            text.truncate(kept);
        }
    }
    out
}

/// The command lines of `file` read as `scope` says: (1-based line, text,
/// what a quote does in it).
fn command_texts(file: &SourceFile, scope: Scope) -> Vec<(usize, String, Quotes)>
{
    let mut out = Vec::new();
    match scope
    {
        Scope::Markdown =>
        {
            let mut spans = CodeSpans::default();
            let mut fenced: Vec<(usize, &str)> = Vec::new();
            for (idx, line, prose) in marked_lines(&file.text)
            {
                if prose
                {
                    for (start, content) in spans.read(one_based(idx), line)
                    {
                        out.push((start, content, Quotes::Delimit));
                    }
                }
                else
                {
                    spans = CodeSpans::default();
                    fenced.push((idx, line));
                }
            }
            out.extend(
                logical_lines(fenced.into_iter())
                    .into_iter()
                    .map(|(idx, text)| (one_based(idx), text, Quotes::Delimit)),
            );
        }
        Scope::Shell | Scope::Script =>
        {
            let quotes = if scope == Scope::Script
            {
                Quotes::End
            }
            else
            {
                Quotes::Delimit
            };
            out.extend(
                logical_lines(file.text.lines().enumerate())
                    .into_iter()
                    .map(|(idx, text)| (one_based(idx), text, quotes)),
            );
        }
    }
    out
}

/// Every command line the rule's files write names a command, its
/// sub-commands and options, and a case, that the command table has.
pub(super) fn check(files: &[&SourceFile]) -> Vec<Diagnostic>
{
    let table = Cli::command();
    let mut diags = Vec::new();
    for file in files
    {
        let Some(scope) = scope(&file.path)
        else
        {
            continue;
        };
        for (line, text, quotes) in command_texts(file, scope)
        {
            for problem in check_text(&table, &text, quotes)
            {
                diags.push(Diagnostic::new(RULE, &file.path, line, problem));
            }
        }
    }
    diags.sort_by(|a, b| (&a.path, a.line).cmp(&(&b.path, b.line)));
    diags
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn problems(line: &str) -> Vec<String>
    {
        check_text(&Cli::command(), line, Quotes::Delimit)
    }

    fn reported(path: &str, text: &str) -> Vec<(usize, String)>
    {
        let file = SourceFile {
            path: path.to_owned(),
            text: text.to_owned(),
        };
        check(&[&file])
            .into_iter()
            .map(|d| (d.line, d.message))
            .collect()
    }

    // Defect caught: a document naming a command, sub-command, case or
    // option the command table does not have passes the lint.
    #[test]
    fn a_name_the_command_table_lacks_is_reported()
    {
        for (line, word) in [
            (
                "cargo xtask run-parallel --runs 3",
                "`run-parallel` is not a command of",
            ),
            (
                "cargo xtask test-kaslr --arch x86_64",
                "`test-kaslr` is not a command",
            ),
            (
                "cargo xtask review-check 12",
                "`review-check` is not a command",
            ),
            (
                "cargo xtask test kasler",
                "`kasler` is not a CASE of `cargo xtask test`",
            ),
            (
                "cargo xtask run --parallel-boots 4",
                "`--parallel-boots` is not an option of `cargo xtask run`",
            ),
            (
                "cargo xtask orch grant sett",
                "`sett` is not a command of `cargo xtask orch grant`",
            ),
            (
                "cargo xtask mkdisk --no-kaslr",
                "`--no-kaslr` is not an option",
            ),
            (
                "cargo xtask orch <sub> --no-such-option",
                "`--no-such-option` is not an option",
            ),
        ]
        {
            let found = problems(line);
            assert_eq!(found.len(), 1, "{line}: {found:?}");
            assert!(found[0].contains(word), "{line}: {found:?}");
        }
    }

    // Defect caught: a command line the table accepts reported, which would
    // make the rule refuse correct documents.
    #[test]
    fn a_line_the_command_table_accepts_passes()
    {
        for line in [
            "cargo xtask run --runs 3 --arch riscv64 --save-logs",
            "cargo xtask run --arch=x86_64 --help",
            "cargo xtask test kaslr --riscv-mmu sv57",
            "cargo xtask test --cell usertest --arch x86_64 --release",
            "cargo xtask test <CASE> [--arch x86_64|riscv64] [--cpus N] [case options]",
            "cargo xtask test ${{ matrix.case }} --arch ${{ matrix.arch }}",
            "cargo xtask orch worker W1 --status 'a line --not-an-option'",
            "cargo xtask review-ledger 12 --check",
            "cargo xtask",
            "cargo xtask help run",
            "cargo xtask <command> --help",
            "cargo xtask build && foo --bar",
            "cargo xtask build | tee --x",
            "cargo xtask build # --nope",
            "cargo xtask build 2>&1 --nope",
            "x=$(cargo xtask orch orchestrator) --nope",
        ]
        {
            assert_eq!(problems(line), Vec::<String>::new(), "{line}");
        }
    }

    // Defect caught: a value of an option read as the case (`usertest` is a
    // tester, not a case), or every case missed after another option.
    #[test]
    fn an_option_s_value_is_not_read_as_a_case()
    {
        assert_eq!(
            problems("cargo xtask test --cell usertest"),
            Vec::<String>::new()
        );
        assert_eq!(problems("cargo xtask test --arch x86_64 kasler").len(), 1);
    }

    // Defect caught: Markdown prose read as a command line, a code span or a
    // fenced continuation line left unread, or a past release's notes held to
    // today's table.
    #[test]
    fn markdown_is_read_in_code_spans_and_fenced_blocks_only()
    {
        let text = "Prose cargo xtask run-parallel is not read.\n\
                    Run `cargo xtask run-parallel` first.\n\
                    \n\
                    ```sh\n\
                    cargo xtask run --runs 2 \\\n    --nope\n\
                    ```\n\
                    A span over a line `cargo xtask\n\
                    test-wedge` end.\n";
        let found = reported("docs/x.md", text);
        let lines: Vec<usize> = found.iter().map(|(line, _)| *line).collect();
        assert_eq!(lines, [2, 5, 8], "{found:?}");
        assert_eq!(reported("docs/releases/v0.1.0.md", text), []);
        assert_eq!(reported("docs/releases/TEMPLATE.md", text).len(), 3);
    }

    // Defect caught: a workflow's or a script's command line left unread, or
    // the text after a script's closing quote read as part of it.
    #[test]
    fn workflows_and_scripts_are_read_on_every_line()
    {
        let yml = "      - run: cargo xtask test-reboot --arch x86_64\n";
        assert_eq!(reported(".github/workflows/x.yml", yml).len(), 1);
        let json = "{ \"command\": \"cargo xtask hook bash\", \"flag\": \"--nope\" }\n";
        assert_eq!(reported(".claude/settings.json", json), []);
        let js = "const cmd = `cargo xtask review-ledger ${pr} --nope`;\n";
        assert_eq!(reported(".claude/workflows/x.js", js).len(), 1);
        assert_eq!(
            reported("xtask/src/x.rs", "// cargo xtask run-parallel\n"),
            []
        );
    }
}
