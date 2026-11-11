// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/orch.rs

//! `orch`: the on-disk state of an orchestration batch.
//!
//! An orchestrator is replaced during a batch, and its replacement starts
//! from what is on disk (`.claude/agents/orchestrator.md` § Hand-over). This
//! command keeps that state in `target/xtask/orchestration/state.json`,
//! which nothing else writes: the orchestrator's id, the exclusive grant and
//! its queue, each worker, the merge order, the questions the maintainer has
//! open, and the rulings in force. Every change also appends one timestamped
//! line to the batch's log beside it, so the log is a by-product of the
//! changes. `orch state` prints the state as text short enough for a hook to
//! put into a session's context. The exclusive grant is also written to the
//! host lock (`crate::host_lock`), which refuses every boot not under it.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};

use crate::cli::{
    OrchArgs, OrchCommand, OrchGrantCommand, OrchQuestionCommand, OrchRulingCommand, OrchWorkerArgs,
};
use crate::context::Context as BuildContext;
use crate::host_lock;
use crate::util::step;

const STATE_FILE: &str = "state.json";
const LOCK_FILE: &str = "state.lock";

/// The longest one-line field the state stores. The state is printed into a
/// session's context, so every field is one bounded line.
const LINE_MAX: usize = 300;

/// The size `orch state` stays under: what a hook may add to a session's
/// context before the harness replaces it with a file path.
const STATE_TEXT_MAX: usize = 10_000;

/// How long a change waits for another writer's lock before it fails.
const LOCK_WAIT: Duration = Duration::from_secs(5);

/// The phases of a worker, in the order a PR passes through them.
const PHASES: &[&str] = &[
    "planning", "coding", "review", "gate", "merged", "retired", "dead",
];

/// The fields of a worker that `orch worker` sets, each one line of text.
const WORKER_FIELDS: &[&str] = &[
    "id", "model", "effort", "scope", "branch", "worktree", "pr", "phase", "status",
];

/// One change to the state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Change
{
    /// The current orchestrator's agent id.
    Orchestrator(String),
    /// Set the given fields of a worker, creating it when it is new.
    Worker
    {
        name: String,
        fields: Vec<(&'static str, String)>,
    },
    /// Remove a worker.
    WorkerRemove(String),
    /// Give the exclusive grant to `holder` for `commands`.
    GrantSet
    {
        holder: String, commands: String
    },
    /// End the exclusive grant.
    GrantClear,
    /// Queue a request for the exclusive grant.
    Queue
    {
        holder: String, commands: String
    },
    /// Drop `holder`'s queued request.
    Unqueue(String),
    /// Replace the merge order.
    Order(Vec<String>),
    /// Record a question the maintainer has open.
    QuestionAdd
    {
        id: String,
        text: String,
        file: Option<String>,
    },
    /// Close a question.
    QuestionClose(String),
    /// Record a ruling in force for the batch.
    RulingAdd(String),
    /// Drop the ruling with this number, as `orch state` prints it.
    RulingDrop(usize),
}

// ── Time ──────────────────────────────────────────────────────────────────────

/// The UTC date of `secs` seconds after the Unix epoch, as `YYYY-MM-DD`.
fn date(secs: u64) -> String
{
    // Days-to-civil conversion over the proleptic Gregorian calendar, with
    // the year starting in March so that a leap day ends it.
    let days = secs / 86_400 + 719_468;
    let era = days / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10
    {
        month_from_march + 3
    }
    else
    {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// The UTC time of `secs` seconds after the Unix epoch, as
/// `YYYY-MM-DDTHH:MMZ`.
fn timestamp(secs: u64) -> String
{
    let of_day = secs % 86_400;
    format!(
        "{}T{:02}:{:02}Z",
        date(secs),
        of_day / 3_600,
        of_day % 3_600 / 60
    )
}

fn now_secs() -> Result<u64>
{
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("the system clock is before 1970")?
        .as_secs())
}

// ── The state ─────────────────────────────────────────────────────────────────

/// `text` as one stored line: trimmed, not empty, without a line break, and
/// at most `LINE_MAX` characters.
fn one_line(what: &str, text: &str) -> Result<String>
{
    let text = text.trim();
    if text.is_empty()
    {
        bail!("{what} is empty");
    }
    if text.contains(['\n', '\r'])
    {
        bail!("{what} spans lines; the state holds one line per field");
    }
    let length = text.chars().count();
    if length > LINE_MAX
    {
        bail!(
            "{what} is {length} characters; the limit is {LINE_MAX} (put the detail in a file \
             and name its path)"
        );
    }
    Ok(text.to_owned())
}

/// The state of a batch that has just started.
fn new_state(goal: &str, log: &str) -> Result<Value>
{
    Ok(json!({
        "goal": one_line("the goal", goal)?,
        "log": log,
        "orchestrator": null,
        "grant": null,
        "queue": [],
        "workers": {},
        "order": [],
        "questions": [],
        "rulings": [],
    }))
}

fn object_mut<'a>(state: &'a mut Value, key: &str) -> Result<&'a mut Map<String, Value>>
{
    state
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("the state has no `{key}` object"))
}

fn list_mut<'a>(state: &'a mut Value, key: &str) -> Result<&'a mut Vec<Value>>
{
    state
        .get_mut(key)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("the state has no `{key}` list"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str
{
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Apply `change` to `state` at time `now` and return the line that records
/// it in the log.
fn apply(state: &mut Value, change: &Change, now: &str) -> Result<String>
{
    match change
    {
        Change::Orchestrator(id) =>
        {
            let id = one_line("the orchestrator's id", id)?;
            state["orchestrator"] = json!(id);
            Ok(format!("orchestrator is {id}"))
        }
        Change::Worker { name, fields } => apply_worker(state, name, fields, now),
        Change::WorkerRemove(name) => worker_remove(state, name),
        Change::GrantSet { holder, commands } => grant_set(state, holder, commands, now),
        Change::GrantClear => grant_clear(state),
        Change::Queue { holder, commands } => queue_add(state, holder, commands),
        Change::Unqueue(holder) =>
        {
            if !remove_entry(state, "queue", "holder", holder)?
            {
                bail!("{holder} has no queued grant request");
            }
            Ok(format!("grant request of {holder} dropped"))
        }
        Change::Order(items) => order_set(state, items),
        Change::QuestionAdd {
            id,
            text: question,
            file,
        } => question_add(state, id, question, file.as_deref(), now),
        Change::QuestionClose(id) =>
        {
            if !remove_entry(state, "questions", "id", id)?
            {
                bail!("no open question has the id {id}");
            }
            Ok(format!("question {id} closed"))
        }
        Change::RulingAdd(ruling) =>
        {
            let ruling = one_line("the ruling", ruling)?;
            list_mut(state, "rulings")?.push(json!(ruling));
            Ok(format!("ruling: {ruling}"))
        }
        Change::RulingDrop(number) => ruling_drop(state, *number),
    }
}

fn worker_remove(state: &mut Value, name: &str) -> Result<String>
{
    if object_mut(state, "workers")?.remove(name).is_none()
    {
        bail!("no worker named {name}");
    }
    Ok(format!("worker {name} removed"))
}

fn grant_clear(state: &mut Value) -> Result<String>
{
    let holder = state
        .get("grant")
        .filter(|grant| !grant.is_null())
        .map(|grant| text(grant, "holder").to_owned())
        .ok_or_else(|| anyhow!("no exclusive grant is outstanding"))?;
    state["grant"] = Value::Null;
    Ok(format!("grant of {holder} ended"))
}

/// Queue `holder`'s request, in place of an earlier one of the same holder.
fn queue_add(state: &mut Value, holder: &str, commands: &str) -> Result<String>
{
    let holder = one_line("the request's holder", holder)?;
    let commands = one_line("the request's commands", commands)?;
    let queue = list_mut(state, "queue")?;
    queue.retain(|entry| text(entry, "holder") != holder);
    queue.push(json!({ "holder": holder, "commands": commands }));
    Ok(format!("grant request queued for {holder}: {commands}"))
}

fn order_set(state: &mut Value, items: &[String]) -> Result<String>
{
    let items = items
        .iter()
        .map(|item| one_line("a merge-order entry", item))
        .collect::<Result<Vec<_>>>()?;
    let line = format!("merge order: {}", join_or_none(&items));
    state["order"] = json!(items);
    Ok(line)
}

fn ruling_drop(state: &mut Value, number: usize) -> Result<String>
{
    let rulings = list_mut(state, "rulings")?;
    if number == 0 || number > rulings.len()
    {
        bail!("no ruling has the number {number}");
    }
    let dropped = rulings.remove(number - 1);
    Ok(format!(
        "ruling dropped: {}",
        dropped.as_str().unwrap_or_default()
    ))
}

/// Remove the entries of the list `key` whose `field` is `value`, and say
/// whether there was one.
fn remove_entry(state: &mut Value, key: &str, field: &str, value: &str) -> Result<bool>
{
    let list = list_mut(state, key)?;
    let before = list.len();
    list.retain(|entry| text(entry, field) != value);
    Ok(list.len() < before)
}

fn grant_set(state: &mut Value, holder: &str, commands: &str, now: &str) -> Result<String>
{
    let holder = one_line("the grant's holder", holder)?;
    let commands = one_line("the grant's commands", commands)?;
    if let Some(grant) = state.get("grant").filter(|grant| !grant.is_null())
    {
        bail!(
            "{} holds the exclusive grant; clear it before granting again",
            text(grant, "holder")
        );
    }
    list_mut(state, "queue")?.retain(|entry| text(entry, "holder") != holder);
    state["grant"] = json!({ "holder": holder, "commands": commands, "since": now });
    Ok(format!("grant to {holder}: {commands}"))
}

fn question_add(
    state: &mut Value,
    id: &str,
    question: &str,
    file: Option<&str>,
    now: &str,
) -> Result<String>
{
    let id = one_line("the question's id", id)?;
    let question = one_line("the question", question)?;
    let file = file
        .map(|file| one_line("the question's file", file))
        .transpose()?;
    let questions = list_mut(state, "questions")?;
    if questions.iter().any(|entry| text(entry, "id") == id)
    {
        bail!("a question with the id {id} is already open");
    }
    questions.push(json!({ "id": id, "asked": now, "text": question, "file": file }));
    Ok(format!("question {id} open: {question}"))
}

/// The fields of a worker change, each checked: one line, and a phase that
/// is one of `PHASES`.
fn worker_fields(fields: &[(&'static str, String)]) -> Result<Vec<(&'static str, String)>>
{
    let mut set = Vec::new();
    for (field, value) in fields
    {
        let value = one_line(&format!("the worker's {field}"), value)?;
        if *field == "phase" && !PHASES.contains(&value.as_str())
        {
            bail!(
                "unknown phase `{value}`; the phases are {}",
                PHASES.join(", ")
            );
        }
        set.push((*field, value));
    }
    Ok(set)
}

fn apply_worker(
    state: &mut Value,
    name: &str,
    fields: &[(&'static str, String)],
    now: &str,
) -> Result<String>
{
    let name = one_line("the worker's name", name)?;
    let set = worker_fields(fields)?;
    let workers = object_mut(state, "workers")?;
    let created = !workers.contains_key(&name);
    if created && set.is_empty()
    {
        bail!("no worker named {name}; give at least one field to create it");
    }
    let worker = workers
        .entry(name.clone())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| anyhow!("the state's entry for {name} is not an object"))?;
    for (field, value) in &set
    {
        worker.insert((*field).to_owned(), json!(value));
    }
    // The time beside a worker's last report is the time of that report, so
    // a change to another field leaves it alone.
    if set.iter().any(|(field, _)| *field == "status")
    {
        worker.insert("status_at".to_owned(), json!(now));
    }
    let described: Vec<String> = set
        .iter()
        .map(|(field, value)| format!("{field}={value}"))
        .collect();
    Ok(format!(
        "worker {name}{}: {}",
        if created { " added" } else { "" },
        described.join("; ")
    ))
}

fn join_or_none(items: &[String]) -> String
{
    if items.is_empty()
    {
        "none".to_owned()
    }
    else
    {
        items.join(", ")
    }
}

// ── Rendering ─────────────────────────────────────────────────────────────────

/// Append `text` and a line break to `out`.
fn push_line(out: &mut String, text: &str)
{
    out.push_str(text);
    out.push('\n');
}

/// The state as the text `orch state` prints.
fn render(state: &Value) -> String
{
    let mut out = String::new();
    push_line(&mut out, "ORCHESTRATION STATE");
    push_line(&mut out, &format!("goal: {}", text(state, "goal")));
    push_line(&mut out, &format!("log: {}", text(state, "log")));
    let orchestrator = state.get("orchestrator").and_then(Value::as_str);
    push_line(
        &mut out,
        &format!("orchestrator: {}", orchestrator.unwrap_or("none")),
    );
    render_grant(state, &mut out);
    render_workers(state, &mut out);
    let order: Vec<String> = entries(state, "order")
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    push_line(&mut out, &format!("merge order: {}", join_or_none(&order)));
    render_questions(state, &mut out);
    push_line(&mut out, "rulings:");
    for (index, ruling) in entries(state, "rulings").enumerate()
    {
        let ruling = ruling.as_str().unwrap_or_default();
        push_line(&mut out, &format!("  {}. {ruling}", index + 1));
    }
    out
}

/// The exclusive grant and the requests queued behind it.
fn render_grant(state: &Value, out: &mut String)
{
    match state.get("grant").filter(|grant| !grant.is_null())
    {
        Some(grant) => push_line(
            out,
            &format!(
                "grant: {} since {}: {}",
                text(grant, "holder"),
                text(grant, "since"),
                text(grant, "commands")
            ),
        ),
        None => push_line(out, "grant: none"),
    }
    for entry in entries(state, "queue")
    {
        push_line(
            out,
            &format!(
                "  queued: {}: {}",
                text(entry, "holder"),
                text(entry, "commands")
            ),
        );
    }
}

/// Each worker: its phase and fields on one line, and its last report, with
/// the time that report was recorded, on the next.
fn render_workers(state: &Value, out: &mut String)
{
    push_line(out, "workers:");
    let workers = state.get("workers").and_then(Value::as_object);
    for (name, worker) in workers.into_iter().flatten()
    {
        let mut head = vec![format!("  {name} [{}]", or_dash(text(worker, "phase")))];
        for field in ["pr", "scope", "branch", "id", "model", "effort", "worktree"]
        {
            let value = text(worker, field);
            if !value.is_empty()
            {
                head.push(format!("{field}={value}"));
            }
        }
        push_line(out, &head.join(" "));
        let status = text(worker, "status");
        if !status.is_empty()
        {
            push_line(
                out,
                &format!("    last ({}): {status}", text(worker, "status_at")),
            );
        }
    }
}

/// The questions the maintainer has open.
fn render_questions(state: &Value, out: &mut String)
{
    push_line(out, "open questions:");
    for question in entries(state, "questions")
    {
        let file = question
            .get("file")
            .and_then(Value::as_str)
            .map_or_default(|file| format!(" [{file}]"));
        push_line(
            out,
            &format!(
                "  {} (asked {}): {}{file}",
                text(question, "id"),
                text(question, "asked"),
                text(question, "text")
            ),
        );
    }
}

fn entries<'a>(state: &'a Value, key: &str) -> impl Iterator<Item = &'a Value>
{
    state
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn or_dash(text: &str) -> &str
{
    if text.is_empty() { "-" } else { text }
}

// ── Files ─────────────────────────────────────────────────────────────────────

/// The directory that holds a batch's state and log.
fn state_dir(ctx: &BuildContext) -> PathBuf
{
    ctx.target_dir.join("xtask").join("orchestration")
}

/// The lock that makes a change to the state exclusive: a file created for
/// the length of the change and removed when the guard drops.
struct Lock(PathBuf);

impl Lock
{
    fn acquire(dir: &Path) -> Result<Self>
    {
        Self::acquire_within(dir, LOCK_WAIT)
    }

    /// Take the lock, waiting at most `wait` for another writer to release it.
    fn acquire_within(dir: &Path, wait: Duration) -> Result<Self>
    {
        let path = dir.join(LOCK_FILE);
        let started = Instant::now();
        loop
        {
            match OpenOptions::new().write(true).create_new(true).open(&path)
            {
                Ok(_) => return Ok(Lock(path)),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    if started.elapsed() >= wait
                    {
                        bail!(
                            "{} exists: another change is in progress, or one died; remove the \
                             file if no `cargo xtask orch` command is running",
                            path.display()
                        );
                    }
                    sleep(Duration::from_millis(50));
                }
                Err(err) =>
                {
                    return Err(err).with_context(|| format!("creating {}", path.display()));
                }
            }
        }
    }
}

impl Drop for Lock
{
    fn drop(&mut self)
    {
        let _ = fs::remove_file(&self.0);
    }
}

fn load(dir: &Path) -> Result<Value>
{
    let path = dir.join(STATE_FILE);
    let raw = fs::read_to_string(&path).with_context(|| {
        format!(
            "reading {} (start a batch with `cargo xtask orch start`)",
            path.display()
        )
    })?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

/// Write the state through a temporary file, so a reader never sees half of
/// it.
fn save(dir: &Path, state: &Value) -> Result<()>
{
    let path = dir.join(STATE_FILE);
    let temporary = dir.join(format!("{STATE_FILE}.tmp"));
    let mut raw = serde_json::to_string_pretty(state).context("encoding the state")?;
    raw.push('\n');
    fs::write(&temporary, raw).with_context(|| format!("writing {}", temporary.display()))?;
    fs::rename(&temporary, &path).with_context(|| format!("replacing {}", path.display()))
}

fn append_log(dir: &Path, state: &Value, now: &str, line: &str) -> Result<()>
{
    let name = text(state, "log");
    if name.is_empty()
    {
        bail!("the state names no log file");
    }
    let path = dir.join(name);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    writeln!(file, "- {now} {line}").with_context(|| format!("appending to {}", path.display()))
}

/// Start a batch in `dir` at `secs`: a fresh state and the first line of its
/// log. Refuses while a state exists, since it may hold live workers.
fn start(dir: &Path, goal: &str, secs: u64) -> Result<()>
{
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let _lock = Lock::acquire(dir)?;
    if dir.join(STATE_FILE).exists()
    {
        bail!(
            "{} exists: a batch is in progress; end it with `cargo xtask orch end` first",
            dir.join(STATE_FILE).display()
        );
    }
    let state = new_state(goal, &format!("{}.md", date(secs)))?;
    save(dir, &state)?;
    append_log(
        dir,
        &state,
        &timestamp(secs),
        &format!("batch started: {}", text(&state, "goal")),
    )
}

/// Refuse, naming the command that starts one, when `dir` holds no batch.
fn require_batch(dir: &Path) -> Result<()>
{
    let path = dir.join(STATE_FILE);
    if !path.exists()
    {
        bail!(
            "{} does not exist: start a batch with `cargo xtask orch start`",
            path.display()
        );
    }
    Ok(())
}

/// Apply `change` to the state in `dir` at `secs`, and record it in the log.
fn change(dir: &Path, change: &Change, secs: u64) -> Result<String>
{
    require_batch(dir)?;
    let _lock = Lock::acquire(dir)?;
    let mut state = load(dir)?;
    let now = timestamp(secs);
    let line = apply(&mut state, change, &now)?;
    save(dir, &state)?;
    append_log(dir, &state, &now, &line)?;
    Ok(line)
}

/// Append `line` to the log of the batch in `dir`.
fn log(dir: &Path, line: &str, secs: u64) -> Result<()>
{
    let line = one_line("the log line", line)?;
    require_batch(dir)?;
    let _lock = Lock::acquire(dir)?;
    let state = load(dir)?;
    append_log(dir, &state, &timestamp(secs), &line)
}

/// End the batch in `dir`: keep its state beside the log under the log's
/// name, so the next `orch start` begins clean.
fn end(dir: &Path, secs: u64) -> Result<PathBuf>
{
    require_batch(dir)?;
    let _lock = Lock::acquire(dir)?;
    let state = load(dir)?;
    append_log(dir, &state, &timestamp(secs), "batch ended")?;
    let stem = text(&state, "log").trim_end_matches(".md");
    // A second batch that starts on the same UTC day appends to the same log,
    // and its ended state takes the next free name beside the first one's.
    let kept = (1..1_000_u32)
        .map(|number| match number
        {
            1 => dir.join(format!("{stem}.state.json")),
            _ => dir.join(format!("{stem}-{number}.state.json")),
        })
        .find(|path| !path.exists())
        .ok_or_else(|| anyhow!("no free name for the ended batch's state"))?;
    fs::rename(dir.join(STATE_FILE), &kept)
        .with_context(|| format!("moving the state to {}", kept.display()))?;
    Ok(kept)
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// The change an `orch worker` invocation asks for.
fn worker_change(args: &OrchWorkerArgs) -> Result<Change>
{
    if args.remove
    {
        return Ok(Change::WorkerRemove(args.name.clone()));
    }
    let values = [
        &args.id,
        &args.model,
        &args.effort,
        &args.scope,
        &args.branch,
        &args.worktree,
        &args.pr,
        &args.phase,
        &args.status,
    ];
    let fields: Vec<(&'static str, String)> = WORKER_FIELDS
        .iter()
        .zip(values)
        .filter_map(|(field, value)| value.clone().map(|value| (*field, value)))
        .collect();
    if fields.is_empty()
    {
        bail!("give at least one field to set, or `--remove`");
    }
    Ok(Change::Worker {
        name: args.name.clone(),
        fields,
    })
}

/// The change to the state that `command` asks for. A command that reads the
/// state, or that starts, logs to or ends the batch, asks for none.
fn state_change(command: &OrchCommand) -> Result<Change>
{
    Ok(match command
    {
        OrchCommand::Orchestrator { id: Some(id) } => Change::Orchestrator(id.clone()),
        OrchCommand::Worker(worker) => worker_change(worker)?,
        OrchCommand::Grant { command } => match command
        {
            OrchGrantCommand::Set { holder, commands } => Change::GrantSet {
                holder: holder.clone(),
                commands: commands.join(" "),
            },
            OrchGrantCommand::Clear => Change::GrantClear,
            OrchGrantCommand::Queue { holder, commands } => Change::Queue {
                holder: holder.clone(),
                commands: commands.join(" "),
            },
            OrchGrantCommand::Unqueue { holder } => Change::Unqueue(holder.clone()),
        },
        OrchCommand::Order { items } => Change::Order(items.clone()),
        OrchCommand::Question { command } => match command
        {
            OrchQuestionCommand::Add { id, text, file } => Change::QuestionAdd {
                id: id.clone(),
                text: text.join(" "),
                file: file.clone(),
            },
            OrchQuestionCommand::Close { id } => Change::QuestionClose(id.clone()),
        },
        OrchCommand::Ruling { command } => match command
        {
            OrchRulingCommand::Add { text } => Change::RulingAdd(text.join(" ")),
            OrchRulingCommand::Drop { number } => Change::RulingDrop(*number),
        },
        OrchCommand::Start { .. }
        | OrchCommand::State { .. }
        | OrchCommand::Log { .. }
        | OrchCommand::End
        | OrchCommand::Orchestrator { id: None } => bail!("the command changes no state"),
    })
}

/// The current orchestrator's agent id, as the state holds it.
fn orchestrator_id(state: &Value) -> Result<String>
{
    state
        .get("orchestrator")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("the state names no orchestrator"))
}

/// Print the state in `dir` as the JSON it is stored as.
fn print_state_json(dir: &Path) -> Result<()>
{
    let state = load(dir)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&state).context("encoding the state")?
    );
    Ok(())
}

/// Print the state in `dir` as the text a session reads, with a warning on
/// stderr when it has grown past `STATE_TEXT_MAX`.
fn print_state_text(dir: &Path) -> Result<()>
{
    let rendered = render(&load(dir)?);
    print!("{rendered}");
    if let Some(warning) = size_warning(&rendered)
    {
        eprintln!("{warning}");
    }
    Ok(())
}

/// The warning for a rendered state longer than `STATE_TEXT_MAX`, if it is.
fn size_warning(rendered: &str) -> Option<String>
{
    (rendered.len() > STATE_TEXT_MAX).then(|| {
        format!(
            "warning: the state is {} bytes, over the {STATE_TEXT_MAX} this command keeps to; \
             remove finished workers (`orch worker <name> --remove`) and close settled questions",
            rendered.len()
        )
    })
}

/// Entry point for `cargo xtask orch`.
pub fn run(ctx: &BuildContext, args: &OrchArgs) -> Result<()>
{
    let dir = state_dir(ctx);
    let secs = now_secs()?;
    match &args.command
    {
        OrchCommand::Start { goal } =>
        {
            start(&dir, goal, secs)?;
            step(&format!("Started a batch in {}", dir.display()));
        }
        OrchCommand::State { json: true } => print_state_json(&dir)?,
        OrchCommand::State { json: false } => print_state_text(&dir)?,
        OrchCommand::Log { line } => log(&dir, &line.join(" "), secs)?,
        OrchCommand::End =>
        {
            let kept = end(&dir, secs)?;
            // A grant the batch left outstanding would refuse every boot.
            host_lock::clear_grant(&host_lock::lock_dir(ctx))?;
            step(&format!("Ended the batch; its state is {}", kept.display()));
        }
        OrchCommand::Orchestrator { id: None } => println!("{}", orchestrator_id(&load(&dir)?)?),
        command =>
        {
            let change_asked = state_change(command)?;
            let line = change(&dir, &change_asked, secs)?;
            apply_to_host(ctx, &change_asked)?;
            println!("{line}");
        }
    }
    Ok(())
}

/// Carry a change of the exclusive grant to the host lock, whose boots it
/// admits (`crate::host_lock`): `grant set` records the holder there, and
/// `grant clear` removes it.
fn apply_to_host(ctx: &BuildContext, change: &Change) -> Result<()>
{
    match change
    {
        Change::GrantSet { holder, commands } =>
        {
            let holder = one_line("the grant's holder", holder)?;
            host_lock::write_grant(&host_lock::lock_dir(ctx), &holder, commands)
        }
        Change::GrantClear => host_lock::clear_grant(&host_lock::lock_dir(ctx)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const NOW: &str = "2026-11-10T14:39Z";

    fn fresh() -> Value
    {
        new_state("close out the milestone", "2026-11-10.md").expect("a valid goal")
    }

    fn worker(name: &str, fields: &[(&'static str, &str)]) -> Change
    {
        Change::Worker {
            name: name.to_owned(),
            fields: fields
                .iter()
                .map(|(field, value)| (*field, (*value).to_owned()))
                .collect(),
        }
    }

    fn scratch(tag: &str) -> PathBuf
    {
        let dir = std::env::temp_dir().join(format!("seraph-orch-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_timestamp_is_the_utc_civil_time()
    {
        assert_eq!(timestamp(0), "1970-01-01T00:00Z");
        assert_eq!(timestamp(951_868_800), "2000-03-01T00:00Z");
        assert_eq!(timestamp(1_709_209_800), "2024-02-29T12:30Z");
        assert_eq!(date(1_709_251_199), "2024-02-29");
        assert_eq!(date(1_709_251_200), "2024-03-01");
        assert_eq!(date(1_735_689_599), "2024-12-31");
    }

    #[test]
    fn a_field_is_one_bounded_line()
    {
        assert_eq!(one_line("x", "  a b  ").unwrap(), "a b");
        assert!(one_line("x", "   ").is_err());
        assert!(one_line("x", "a\nb").is_err());
        assert!(one_line("x", &"a".repeat(LINE_MAX)).is_ok());
        assert!(one_line("x", &"a".repeat(LINE_MAX + 1)).is_err());
    }

    #[test]
    fn a_worker_keeps_the_fields_a_later_change_does_not_name()
    {
        let mut state = fresh();
        let line = apply(
            &mut state,
            &worker(
                "W1",
                &[("id", "a1"), ("branch", "fix/x"), ("phase", "coding")],
            ),
            NOW,
        )
        .unwrap();
        assert_eq!(line, "worker W1 added: id=a1; branch=fix/x; phase=coding");
        apply(
            &mut state,
            &worker("W1", &[("phase", "review"), ("pr", "852")]),
            "2026-11-10T15:00Z",
        )
        .unwrap();
        let w1 = &state["workers"]["W1"];
        assert_eq!(text(w1, "id"), "a1");
        assert_eq!(text(w1, "branch"), "fix/x");
        assert_eq!(text(w1, "phase"), "review");
        assert_eq!(text(w1, "pr"), "852");
    }

    #[test]
    fn a_report_keeps_its_own_time_across_other_changes()
    {
        let mut state = fresh();
        apply(&mut state, &worker("W1", &[("phase", "coding")]), NOW).unwrap();
        assert!(state["workers"]["W1"].get("status_at").is_none());
        apply(
            &mut state,
            &worker("W1", &[("status", "CI green")]),
            "2026-11-10T15:00Z",
        )
        .unwrap();
        apply(
            &mut state,
            &worker("W1", &[("phase", "gate")]),
            "2026-11-10T16:00Z",
        )
        .unwrap();
        assert_eq!(
            text(&state["workers"]["W1"], "status_at"),
            "2026-11-10T15:00Z"
        );
        assert!(render(&state).contains("    last (2026-11-10T15:00Z): CI green"));
    }

    #[test]
    fn a_worker_change_is_checked()
    {
        let mut state = fresh();
        assert!(apply(&mut state, &worker("W1", &[("phase", "napping")]), NOW).is_err());
        assert!(apply(&mut state, &worker("W1", &[]), NOW).is_err());
        assert!(apply(&mut state, &Change::WorkerRemove("W1".to_owned()), NOW).is_err());
        apply(&mut state, &worker("W1", &[("phase", "gate")]), NOW).unwrap();
        apply(&mut state, &Change::WorkerRemove("W1".to_owned()), NOW).unwrap();
        assert!(state["workers"].as_object().unwrap().is_empty());
    }

    #[test]
    fn one_grant_is_outstanding_at_a_time()
    {
        let mut state = fresh();
        let grant = |holder: &str| Change::GrantSet {
            holder: holder.to_owned(),
            commands: "run-parallel --smp 8".to_owned(),
        };
        let queue = |holder: &str| Change::Queue {
            holder: holder.to_owned(),
            commands: "boundary set".to_owned(),
        };
        assert!(apply(&mut state, &Change::GrantClear, NOW).is_err());
        apply(&mut state, &queue("W1"), NOW).unwrap();
        apply(&mut state, &queue("W2"), NOW).unwrap();
        apply(&mut state, &grant("W1"), NOW).unwrap();
        assert_eq!(text(&state["grant"], "since"), NOW);
        // Granting takes the holder out of the queue.
        assert_eq!(state["queue"].as_array().unwrap().len(), 1);
        assert!(apply(&mut state, &grant("W2"), NOW).is_err());
        apply(&mut state, &Change::GrantClear, NOW).unwrap();
        apply(&mut state, &grant("W2"), NOW).unwrap();
        assert!(state["queue"].as_array().unwrap().is_empty());
        assert!(apply(&mut state, &Change::Unqueue("W2".to_owned()), NOW).is_err());
    }

    #[test]
    fn a_question_is_open_once_and_closes_by_its_id()
    {
        let mut state = fresh();
        let ask = |id: &str| Change::QuestionAdd {
            id: id.to_owned(),
            text: "merge on a passing gate?".to_owned(),
            file: Some("scratch/q.md".to_owned()),
        };
        apply(&mut state, &ask("Q1"), NOW).unwrap();
        assert!(apply(&mut state, &ask("Q1"), NOW).is_err());
        assert!(apply(&mut state, &Change::QuestionClose("Q2".to_owned()), NOW).is_err());
        apply(&mut state, &Change::QuestionClose("Q1".to_owned()), NOW).unwrap();
        assert!(state["questions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn a_ruling_is_dropped_by_its_number()
    {
        let mut state = fresh();
        apply(&mut state, &Change::RulingAdd("first".to_owned()), NOW).unwrap();
        apply(&mut state, &Change::RulingAdd("second".to_owned()), NOW).unwrap();
        assert!(apply(&mut state, &Change::RulingDrop(0), NOW).is_err());
        assert!(apply(&mut state, &Change::RulingDrop(3), NOW).is_err());
        let line = apply(&mut state, &Change::RulingDrop(1), NOW).unwrap();
        assert_eq!(line, "ruling dropped: first");
        assert_eq!(state["rulings"], json!(["second"]));
    }

    #[test]
    fn a_holder_has_one_queued_request()
    {
        let mut state = fresh();
        let queue = |commands: &str| Change::Queue {
            holder: "W1".to_owned(),
            commands: commands.to_owned(),
        };
        apply(&mut state, &queue("boundary set"), NOW).unwrap();
        apply(&mut state, &queue("timing run"), NOW).unwrap();
        assert_eq!(
            state["queue"],
            json!([{ "holder": "W1", "commands": "timing run" }])
        );
    }

    #[test]
    fn a_queued_request_is_dropped_by_its_holder()
    {
        let mut state = fresh();
        let queue = |holder: &str| Change::Queue {
            holder: holder.to_owned(),
            commands: "boundary set".to_owned(),
        };
        apply(&mut state, &queue("W1"), NOW).unwrap();
        apply(&mut state, &queue("W2"), NOW).unwrap();
        let line = apply(&mut state, &Change::Unqueue("W1".to_owned()), NOW).unwrap();
        assert_eq!(line, "grant request of W1 dropped");
        assert_eq!(
            state["queue"],
            json!([{ "holder": "W2", "commands": "boundary set" }])
        );
    }

    #[test]
    fn the_merge_order_is_replaced_whole()
    {
        let mut state = fresh();
        let order =
            |items: &[&str]| Change::Order(items.iter().map(|item| (*item).to_owned()).collect());
        let line = apply(&mut state, &order(&["#852", "#853"]), NOW).unwrap();
        assert_eq!(line, "merge order: #852, #853");
        apply(&mut state, &order(&["#854"]), NOW).unwrap();
        assert_eq!(state["order"], json!(["#854"]));
        let line = apply(&mut state, &order(&[]), NOW).unwrap();
        assert_eq!(line, "merge order: none");
        assert_eq!(state["order"], json!([]));
    }

    #[test]
    fn a_merge_order_entry_is_one_line()
    {
        let mut state = fresh();
        apply(&mut state, &Change::Order(vec!["#852".to_owned()]), NOW).unwrap();
        let refused = Change::Order(vec!["#853".to_owned(), "  ".to_owned()]);
        assert!(apply(&mut state, &refused, NOW).is_err());
        assert_eq!(state["order"], json!(["#852"]));
    }

    #[test]
    fn the_rendered_state_names_everything_a_new_orchestrator_needs()
    {
        let mut state = fresh();
        let changes = [
            Change::Orchestrator("a0c1".to_owned()),
            worker(
                "W1",
                &[
                    ("id", "a1"),
                    ("pr", "852"),
                    ("phase", "review"),
                    ("worktree", ".claude/worktrees/agent-a1"),
                    ("status", "delta review running"),
                ],
            ),
            Change::GrantSet {
                holder: "W1".to_owned(),
                commands: "boundary set".to_owned(),
            },
            Change::Queue {
                holder: "W2".to_owned(),
                commands: "timing run".to_owned(),
            },
            Change::Order(vec!["#852".to_owned(), "#853".to_owned()]),
            Change::QuestionAdd {
                id: "Q1".to_owned(),
                text: "which window?".to_owned(),
                file: None,
            },
            Change::RulingAdd("merge on a passing gate".to_owned()),
        ];
        for change in &changes
        {
            apply(&mut state, change, NOW).unwrap();
        }
        let rendered = render(&state);
        for expected in [
            "goal: close out the milestone",
            "log: 2026-11-10.md",
            "orchestrator: a0c1",
            "grant: W1 since 2026-11-10T14:39Z: boundary set",
            "  queued: W2: timing run",
            "  W1 [review] pr=852 id=a1 worktree=.claude/worktrees/agent-a1",
            "    last (2026-11-10T14:39Z): delta review running",
            "merge order: #852, #853",
            "  Q1 (asked 2026-11-10T14:39Z): which window?",
            "  1. merge on a passing gate",
        ]
        {
            assert!(
                rendered.contains(expected),
                "missing `{expected}` in:\n{rendered}"
            );
        }
        let empty = render(&fresh());
        assert!(empty.contains("orchestrator: none"));
        assert!(empty.contains("grant: none"));
        assert!(empty.contains("merge order: none"));
    }

    #[test]
    fn a_batch_of_six_workers_renders_under_the_hook_limit()
    {
        let mut state = fresh();
        let long = "x".repeat(LINE_MAX);
        for index in 0..6
        {
            let fields: Vec<(&'static str, &str)> = WORKER_FIELDS
                .iter()
                .map(|field| {
                    (
                        *field,
                        if *field == "phase"
                        {
                            "review"
                        }
                        else
                        {
                            &long[..120]
                        },
                    )
                })
                .collect();
            apply(&mut state, &worker(&format!("W{index}"), &fields), NOW).unwrap();
        }
        for index in 0..4
        {
            apply(
                &mut state,
                &Change::RulingAdd(format!("{index} {}", &long[..200])),
                NOW,
            )
            .unwrap();
        }
        assert!(render(&state).len() < STATE_TEXT_MAX);
    }

    /// 2026-11-10T14:39:00Z.
    const SECS: u64 = 1_794_321_540;

    #[test]
    fn a_change_before_start_names_the_start_command()
    {
        let dir = scratch("unstarted");
        let refused = change(&dir, &Change::GrantClear, SECS).unwrap_err();
        assert!(refused.to_string().contains("cargo xtask orch start"));
        assert!(log(&dir, "an event", SECS).is_err());
        assert!(end(&dir, SECS).is_err());
        assert!(!dir.exists());
    }

    #[test]
    fn start_refuses_over_a_batch_in_progress()
    {
        let dir = scratch("restart");
        start(&dir, "close out the milestone", SECS).unwrap();
        assert!(start(&dir, "again", SECS).is_err());
        assert_eq!(
            text(&load(&dir).unwrap(), "goal"),
            "close out the milestone"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn changes_reach_the_state_file_and_the_log()
    {
        let dir = scratch("files");
        start(&dir, "close out the milestone", SECS).unwrap();
        change(&dir, &Change::Orchestrator("a0c1".to_owned()), SECS).unwrap();
        log(&dir, "W1 handed back", SECS + 60).unwrap();

        let state = load(&dir).unwrap();
        assert_eq!(text(&state, "orchestrator"), "a0c1");
        assert!(!dir.join(LOCK_FILE).exists());
        let written = fs::read_to_string(dir.join("2026-11-10.md")).unwrap();
        assert_eq!(
            written,
            "- 2026-11-10T14:39Z batch started: close out the milestone\n\
             - 2026-11-10T14:39Z orchestrator is a0c1\n\
             - 2026-11-10T14:40Z W1 handed back\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_ended_batch_keeps_its_state_under_a_free_name()
    {
        let dir = scratch("end");
        start(&dir, "close out the milestone", SECS).unwrap();
        let kept = end(&dir, SECS + 120).unwrap();
        assert_eq!(kept, dir.join("2026-11-10.state.json"));
        assert!(!dir.join(STATE_FILE).exists());
        start(&dir, "the next batch", SECS + 180).unwrap();
        let second = end(&dir, SECS + 240).unwrap();
        assert_eq!(second, dir.join("2026-11-10-2.state.json"));
        assert!(kept.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_state_that_does_not_parse_is_reported()
    {
        let dir = scratch("garbled");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(STATE_FILE), "{ not json").unwrap();
        let refused = load(&dir).unwrap_err();
        assert!(refused.to_string().contains("parsing"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_state_without_a_log_name_refuses_a_log_line()
    {
        let dir = scratch("nolog");
        fs::create_dir_all(&dir).unwrap();
        assert!(append_log(&dir, &json!({ "log": "" }), NOW, "an event").is_err());
        assert!(fs::read_dir(&dir).unwrap().next().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_held_lock_refuses_a_second_writer_and_is_released_on_drop()
    {
        let dir = scratch("lock");
        fs::create_dir_all(&dir).unwrap();
        let held = Lock::acquire_within(&dir, Duration::ZERO).unwrap();
        assert!(Lock::acquire_within(&dir, Duration::ZERO).is_err());
        drop(held);
        assert!(!dir.join(LOCK_FILE).exists());
        assert!(Lock::acquire_within(&dir, Duration::ZERO).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    fn worker_args(name: &str) -> OrchWorkerArgs
    {
        OrchWorkerArgs {
            name: name.to_owned(),
            remove: false,
            id: None,
            model: None,
            effort: None,
            scope: None,
            branch: None,
            worktree: None,
            pr: None,
            phase: None,
            status: None,
        }
    }

    #[test]
    fn worker_arguments_become_the_fields_they_name()
    {
        let args = OrchWorkerArgs {
            id: Some("the id".to_owned()),
            model: Some("the model".to_owned()),
            effort: Some("the effort".to_owned()),
            scope: Some("the scope".to_owned()),
            branch: Some("the branch".to_owned()),
            worktree: Some("the worktree".to_owned()),
            pr: Some("the pr".to_owned()),
            phase: Some("the phase".to_owned()),
            status: Some("the status".to_owned()),
            ..worker_args("W1")
        };
        let Change::Worker { name, fields } = worker_change(&args).unwrap()
        else
        {
            panic!("not a worker change");
        };
        assert_eq!(name, "W1");
        assert_eq!(fields.len(), WORKER_FIELDS.len());
        for (field, value) in fields
        {
            assert_eq!(value, format!("the {field}"));
        }
    }

    #[test]
    fn worker_arguments_set_only_the_fields_given()
    {
        let args = OrchWorkerArgs {
            pr: Some("854".to_owned()),
            ..worker_args("W1")
        };
        assert_eq!(
            worker_change(&args).unwrap(),
            worker("W1", &[("pr", "854")])
        );
    }

    #[test]
    fn worker_arguments_without_a_field_are_refused()
    {
        assert!(worker_change(&worker_args("W1")).is_err());
    }

    #[test]
    fn the_remove_flag_removes_the_worker()
    {
        let args = OrchWorkerArgs {
            remove: true,
            ..worker_args("W1")
        };
        assert_eq!(
            worker_change(&args).unwrap(),
            Change::WorkerRemove("W1".to_owned())
        );
    }

    #[test]
    fn a_command_that_changes_the_state_names_its_change()
    {
        let command = OrchCommand::Order {
            items: vec!["#852".to_owned()],
        };
        assert_eq!(
            state_change(&command).unwrap(),
            Change::Order(vec!["#852".to_owned()])
        );
        let command = OrchCommand::Grant {
            command: OrchGrantCommand::Set {
                holder: "W1".to_owned(),
                commands: vec![
                    "run-parallel".to_owned(),
                    "--smp".to_owned(),
                    "8".to_owned(),
                ],
            },
        };
        assert_eq!(
            state_change(&command).unwrap(),
            Change::GrantSet {
                holder: "W1".to_owned(),
                commands: "run-parallel --smp 8".to_owned(),
            }
        );
    }

    #[test]
    fn a_command_that_changes_nothing_names_no_change()
    {
        assert!(state_change(&OrchCommand::End).is_err());
        assert!(state_change(&OrchCommand::Orchestrator { id: None }).is_err());
    }

    #[test]
    fn a_state_over_the_limit_draws_the_warning()
    {
        assert_eq!(size_warning(&"x".repeat(STATE_TEXT_MAX)), None);
        let warning = size_warning(&"x".repeat(STATE_TEXT_MAX + 1)).expect("a warning");
        assert!(warning.contains(&format!("{} bytes", STATE_TEXT_MAX + 1)));
        assert!(warning.contains("--remove"));
    }

    #[test]
    fn the_orchestrator_id_is_read_back()
    {
        let mut state = fresh();
        assert!(orchestrator_id(&state).is_err());
        apply(&mut state, &Change::Orchestrator("a0c1".to_owned()), NOW).unwrap();
        assert_eq!(orchestrator_id(&state).unwrap(), "a0c1");
    }
}
