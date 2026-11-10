// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/tasklist.rs

//! GitHub task-list items (`- [ ]`, `- [x]`), as the pull-request and Issue
//! checks read them from a body.

/// The state of a task-list item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskItem
{
    Open,
    Ticked,
}

/// The text after a list marker, if `line` opens a list item: a bullet
/// (`-`, `*`, `+`) or an ordered marker (digits, then `.` or `)`), each
/// followed by a space, after any indentation.
fn after_marker(line: &str) -> Option<&str>
{
    let rest = line.trim_start();
    if let Some(rest) = ["- ", "* ", "+ "]
        .iter()
        .find_map(|marker| rest.strip_prefix(marker))
    {
        return Some(rest);
    }
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    if digits == 0
    {
        return None;
    }
    let rest = &rest[digits..];
    rest.strip_prefix(". ").or_else(|| rest.strip_prefix(") "))
}

/// The task-list item `line` holds, if it is one: a list marker, then `[ ]`,
/// `[x]`, or `[X]`. These are the forms GitHub renders as a checkbox.
pub fn task_item(line: &str) -> Option<TaskItem>
{
    let rest = after_marker(line)?;
    if rest.starts_with("[ ]")
    {
        Some(TaskItem::Open)
    }
    else if rest.starts_with("[x]") || rest.starts_with("[X]")
    {
        Some(TaskItem::Ticked)
    }
    else
    {
        None
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_task_item_is_a_list_marker_followed_by_a_box()
    {
        assert_eq!(task_item("- [ ] open"), Some(TaskItem::Open));
        assert_eq!(task_item("  * [ ] nested"), Some(TaskItem::Open));
        assert_eq!(task_item("+ [ ] plus"), Some(TaskItem::Open));
        assert_eq!(task_item("1. [ ] ordered"), Some(TaskItem::Open));
        assert_eq!(task_item("12) [x] ordered"), Some(TaskItem::Ticked));
        assert_eq!(task_item("- [x] done"), Some(TaskItem::Ticked));
        assert_eq!(task_item("* [X] done"), Some(TaskItem::Ticked));
    }

    #[test]
    fn a_line_without_a_marker_or_a_box_is_not_a_task_item()
    {
        assert_eq!(task_item("- plain item"), None);
        assert_eq!(task_item("[ ] no marker"), None);
        assert_eq!(task_item("-[ ] no space"), None);
        assert_eq!(task_item("1.[ ] no space"), None);
        assert_eq!(task_item("1 [ ] no delimiter"), None);
        assert_eq!(task_item(". [ ] no digits"), None);
    }
}
