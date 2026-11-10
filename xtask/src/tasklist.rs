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

/// The task-list item `line` holds, if it is one: a `-` or `*` list marker,
/// then `[ ]`, `[x]`, or `[X]`, after any indentation.
pub fn task_item(line: &str) -> Option<TaskItem>
{
    let rest = line.trim_start();
    let rest = rest
        .strip_prefix("- ")
        .or_else(|| rest.strip_prefix("* "))?;
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
        assert_eq!(task_item("- [x] done"), Some(TaskItem::Ticked));
        assert_eq!(task_item("* [X] done"), Some(TaskItem::Ticked));
        assert_eq!(task_item("- plain item"), None);
        assert_eq!(task_item("[ ] no marker"), None);
        assert_eq!(task_item("-[ ] no space"), None);
    }
}
