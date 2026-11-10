// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// .claude/workflows/release-review.js

// Sharded adversarial review and audit of a release candidate.
//
// The pre-merge review of every pull request read each PR's own lines; this
// workflow reviews what none of them saw, the composition of the merged PRs
// between the previous release tag and the candidate head
// (docs/conventions.md § Release Production says when it runs and where its
// findings go). Scope (one agent) lists the range, its first-parent units (one
// per merged PR), each unit's files, and the saved review records. Review runs
// one `pr-reviewer` per shard of the files two or more units touched (no other
// file is reviewed line by line) and whole-range lenses, in parallel. Verify
// puts every finding that can block, and every Critical and Should finding, to
// two independent refuters as soon as its reviewer completes. Audit runs the
// `release-auditor` once the findings are judged, with the known-issue
// candidates (the blocking-track findings an open Issue names, of this run and,
// while their Issue is open, of the release's earlier runs), so the notes it
// checks and the notes this run drafts take the same list. Synthesize renders
// one report and, when the verdict is `RELEASE READY`, drafts the release
// notes from docs/releases/TEMPLATE.md. The script computes the verdict line
// itself: `RELEASE BLOCKED` when a reviewer failed, a finding on the blocking track
// (class correctness, safety, or contract, or a MUST violation anchored
// outside Markdown) survives verification with no open Issue naming its work,
// or the audit fails; `RELEASE READY` otherwise. A blocking-class finding an
// open Issue names is a known-issue candidate, not a blocker; every other
// surviving finding is recorded on an Issue.
//
// The ledger is the union of the saved run records of the range's PRs
// (`target/xtask/review/pr<N>/*-*.json`) and of this release's earlier runs
// (`target/xtask/review/release-v<X.Y.Z>/*-*.json`); reviewers read it with
// `jq`, and a finding an entry states at a hunk unchanged since the run the
// entry names, when that run resolves in the clone, is listed, not counted.
//
// args: { mode: 'scope' | 'full' | 'delta', from: string, version: string,
//         since?: string, host_runs?: string }
//   from         the previous release tag (or any commit) the range starts at.
//   version      the target version `X.Y.Z`; `vX.Y.Z` must be the current
//                milestone (docs/conventions.md § Milestones).
//   mode 'full'  reviews the whole range `from..HEAD`.
//   mode 'delta' reviews what changed between `since` (the head the last run
//                reviewed) and the head: the multi-PR files the delta changed,
//                the lenses over the delta, the fixes claimed since then, and a
//                correctness-only regression lens over the delta. It also puts
//                every finding the run at `since` left standing (its record's
//                `findings`, contested ones aside) to the refuters again, so
//                one no fix removed still blocks; it aborts when no saved
//                record of this release reviewed `since`.
//   mode 'scope' stops after Scope and returns the agent plan and sample
//                prompts (one agent); with `since` it scopes as delta would.
//   host_runs    path of the release host-run report; the audit requires it
//                once the head carries the version bump.
//
// Every stage takes the diff from the local tree (`git diff`), never from
// `gh pr diff` or the `files` field of `gh pr view`, which GitHub caps. The
// script checks every returned file list against the count the scope agent
// reads from the same local diff, and aborts rather than review a partial list.

export const meta = {
    name: 'release-review',
    description: 'Sharded review and audit of a release candidate; drafts the release notes',
    whenToUse:
        'Once the milestone is ready to close, per docs/conventions.md § Release Production',
    phases: [
        { title: 'Scope', detail: 'list the range, its PRs and files, and the saved records' },
        { title: 'Review', detail: 'multi-PR file shards and whole-range lenses' },
        {
            title: 'Verify',
            detail: 'two independent refuters per finding that can block, or is Critical or Should',
        },
        { title: 'Audit', detail: 'release-auditor, given the known-issue candidates' },
        { title: 'Synthesize', detail: 'report and notes draft; verdict computed by the script' },
    ],
}

// ─── Arguments ───

const MODES = ['full', 'delta', 'scope']
const text_arg = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null)
const MODE = args && MODES.includes(args.mode) ? args.mode : null
const FROM = args ? text_arg(args.from) : null
const VERSION = args ? text_arg(args.version) : null
const SINCE = args ? text_arg(args.since) : null
const HOST_RUNS = args ? text_arg(args.host_runs) : null
const DELTA = SINCE !== null

if (MODE === null) return { error: "args.mode must be 'full', 'delta', or 'scope'" }
if (FROM === null) return { error: 'args.from must name the previous release tag' }
if (VERSION === null || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(VERSION)) {
    return { error: 'args.version must be the target version X.Y.Z' }
}
if (MODE === 'delta' && !DELTA) {
    return { error: "args.since (the head the last run reviewed) is required in 'delta' mode" }
}
if (MODE === 'full' && DELTA) {
    return { error: "args.since is only meaningful with mode 'delta' or 'scope'" }
}

const TAG = 'v' + VERSION
const RECORD_DIR = 'target/xtask/review/release-' + TAG

// ─── Tunables ───

const MAX_SHARD_FILES = 6 // files per shard reviewer
const MAX_SHARD_LINES = 500 // changed lines per shard reviewer
const MAX_LENS_DOCS = 8 // documents per design-docs lens agent
const DEDUP_LINE_SLACK = 3 // lines apart at which same file, class, bucket, and flag are one
const VERIFY_LENSES = ['reality', 'authority']
const BLOCKING_CLASSES = ['correctness', 'safety', 'contract']
const OTHER_CLASSES = ['standards', 'doc-drift', 'coverage', 'style']
// The blocking track (docs/conventions.md § Branch and PR Workflow): a finding
// of a blocking class, or a MUST violation of a standard, of whatever class,
// anchored outside Markdown.
const blocks = (f) =>
    BLOCKING_CLASSES.includes(f.class) || (f.must_violation && !f.file.endsWith('.md'))
// The findings docs/conventions.md § Release Production says the release
// review verifies.
const verifiable = (f) => blocks(f) || f.bucket !== 'nit'
// The sections release-auditor's Output lists; the audit must return each.
const AUDIT_SECTION_NAMES = [
    'milestone state', 'version', 'release notes', 'known issues', 'host runs',
]
// A generated file: no reviewer reads it for composition.
const SKIPPED_FILES = ['Cargo.lock']
// Read-only agent types. The investigator's brief pins a cheaper model for the
// bounded jobs (scope, refute, render, draft); the reviewers run on the model
// pr-reviewer.md pins.
const INVESTIGATOR = 'release-verifier'
const REVIEWER = 'pr-reviewer'
const AUDITOR = 'release-auditor'

// ─── Schemas ───

const PATH_DESCRIPTION =
    'Repository-relative path, exactly as `git diff --name-only` prints it: no leading `./`, ' +
    'no absolute prefix.'
const PATHS = { type: 'array', items: { type: 'string', description: PATH_DESCRIPTION } }

const SCOPE_SCHEMA = {
    type: 'object',
    required: [
        'head', 'from_sha', 'repo_root', 'tree_at_head', 'from_ancestor', 'since_reachable',
        'range_files', 'range_file_count', 'units', 'version_at_head', 'version_at_from',
        'milestones', 'open_issues', 'ledger_records', 'delta_files', 'delta_file_count',
        'claimed_fixes', 'prior_known', 'prior_findings', 'since_record',
    ],
    properties: {
        head: { type: 'string', description: 'Full SHA of `git rev-parse HEAD`.' },
        from_sha: { type: 'string', description: 'Full SHA `from` resolves to.' },
        repo_root: {
            type: 'string',
            description: 'Absolute path printed by `git rev-parse --show-toplevel`.',
        },
        tree_at_head: { type: 'boolean', description: '`git status --porcelain` prints nothing.' },
        from_ancestor: {
            type: 'boolean',
            description: '`git merge-base --is-ancestor <from_sha> <head>` exits 0.',
        },
        since_reachable: {
            type: 'boolean',
            description: '`since` resolves to a commit in this clone; true without `since`.',
        },
        range_files: {
            type: 'array',
            description:
                'One entry per path `git diff --name-only --no-renames <from_sha> <head>` prints.',
            items: {
                type: 'object',
                required: ['path', 'changed', 'at_head', 'kind'],
                properties: {
                    path: { type: 'string', description: PATH_DESCRIPTION },
                    changed: {
                        type: 'integer',
                        description: 'Added plus deleted lines (0 where numstat prints `-`).',
                    },
                    at_head: {
                        type: 'boolean',
                        description: '`git cat-file -e <head>:<path>` succeeds.',
                    },
                    kind: { enum: ['code', 'markdown', 'rules', 'other'] },
                },
            },
        },
        range_file_count: {
            type: 'integer',
            description:
                'The number `git diff --name-only --no-renames <from_sha> <head> | wc -l` prints.',
        },
        units: {
            type: 'array',
            description:
                'One entry per commit `git log --first-parent <from_sha>..<head>` lists.',
            items: {
                type: 'object',
                required: ['sha', 'pr', 'title', 'files', 'file_count'],
                properties: {
                    sha: { type: 'string', description: 'Full SHA of the first-parent commit.' },
                    pr: {
                        type: 'integer',
                        description: 'N when the subject is `Merge pull request #N ...`, else 0.',
                    },
                    title: {
                        type: 'string',
                        description: 'The PR title (a merge\'s first body line), else the subject.',
                    },
                    files: {
                        ...PATHS,
                        description:
                            'Every path `git diff --name-only --no-renames <sha>^1 <sha>` prints.',
                    },
                    file_count: {
                        type: 'integer',
                        description: 'The number that list holds, as `wc -l` counts it.',
                    },
                },
            },
        },
        version_at_head: {
            type: 'string',
            description: '`[workspace.package] version` of the root `Cargo.toml` at the head.',
        },
        version_at_from: {
            type: 'string',
            description: '`[workspace.package] version` of the root `Cargo.toml` at from_sha.',
        },
        milestones: {
            type: 'array',
            items: { type: 'string' },
            description: 'The title of every open milestone.',
        },
        open_issues: {
            type: 'array',
            description: 'Every open Issue of the repository, by number and title.',
            items: {
                type: 'object',
                required: ['number', 'title'],
                properties: { number: { type: 'integer' }, title: { type: 'string' } },
            },
        },
        ledger_records: {
            ...PATHS,
            description: 'Every saved run record the `ls` commands print, as relative paths.',
        },
        delta_files: {
            ...PATHS,
            description:
                'In delta mode, every path `git diff --name-only --no-renames <since> <head>` ' +
                'prints; empty otherwise.',
        },
        delta_file_count: {
            type: 'integer',
            description: 'In delta mode, the number that list holds (`wc -l`); 0 otherwise.',
        },
        claimed_fixes: {
            type: 'array',
            items: {
                type: 'object',
                required: ['file', 'line', 'summary', 'pr'],
                properties: {
                    file: { type: 'string', description: PATH_DESCRIPTION },
                    line: { type: 'integer', description: '0 when unknown.' },
                    summary: { type: 'string' },
                    pr: { type: 'integer', description: 'The PR that claims it; 0 when none.' },
                },
            },
        },
        prior_known: {
            type: 'array',
            description:
                'Every entry of a `recorded` list in this release\'s saved records whose ' +
                '`disposition` is `known issue`, as its `issue` and `claim`.',
            items: {
                type: 'object',
                required: ['issue', 'claim'],
                properties: { issue: { type: 'integer' }, claim: { type: 'string' } },
            },
        },
        since_record: {
            type: 'boolean',
            description:
                'In delta mode, one of this release\'s saved records has `stats.head` equal to ' +
                '`since`; true when no `since` was given.',
        },
        prior_findings: {
            type: 'array',
            description:
                'In delta mode, every entry of the `findings` list of this release\'s saved ' +
                'record whose `stats.head` is `since` (resolved to its full SHA) and whose ' +
                '`status` is not `contested`, with its fields as saved; empty otherwise.',
            items: {
                type: 'object',
                required: [
                    'file', 'line', 'bucket', 'class', 'must_violation', 'issue', 'authority',
                    'claim', 'evidence', 'fix',
                ],
                properties: {
                    file: { type: 'string', description: PATH_DESCRIPTION },
                    line: { type: 'integer' },
                    bucket: { enum: ['critical', 'should', 'nit'] },
                    class: {
                        enum: [
                            'correctness', 'safety', 'contract', 'standards', 'doc-drift',
                            'coverage', 'style',
                        ],
                    },
                    must_violation: { type: 'boolean' },
                    issue: { type: 'integer' },
                    prs: { type: 'array', items: { type: 'integer' } },
                    authority: { type: 'string' },
                    claim: { type: 'string' },
                    evidence: { type: 'string' },
                    fix: { type: 'string' },
                },
            },
        },
    },
}

const FINDING_SCHEMA = {
    type: 'object',
    required: [
        'file', 'line', 'bucket', 'class', 'must_violation', 'ledger', 'issue', 'prs', 'authority',
        'claim', 'evidence', 'fix',
    ],
    properties: {
        file: { type: 'string', description: PATH_DESCRIPTION },
        line: { type: 'integer', description: '1-based line at the head the finding anchors to.' },
        bucket: {
            enum: ['critical', 'should', 'nit'],
            description:
                'Severity as you judge it; which findings block the release is decided by class, ' +
                'MUST flag, and the anchor file, not by the bucket.',
        },
        class: { enum: [...BLOCKING_CLASSES, ...OTHER_CLASSES] },
        must_violation: {
            type: 'boolean',
            description: 'It names a MUST violation of a binding standard.',
        },
        ledger: {
            type: 'boolean',
            description:
                'A ledger entry already states this finding, and the hunk it anchors to is ' +
                'unchanged since the run the entry names (false when that hunk changed or that ' +
                'run does not resolve in the clone).',
        },
        issue: {
            type: 'integer',
            description:
                'The open Issue that already names this work, when one does (0 otherwise). A ' +
                'follow-up Issue (title `<scope>: defects found by review`, or one beginning ' +
                '`<scope>: defects found by PR #<N>\'s review`) names findings, not work: never ' +
                'name one here.',
        },
        prs: {
            type: 'array',
            items: { type: 'integer' },
            description: 'The PRs of the range whose changes make up the defect (empty when none).',
        },
        authority: { type: 'string', description: 'Doc path and section, or contract location.' },
        claim: { type: 'string' },
        evidence: { type: 'string', description: 'Cites file:line.' },
        fix: { type: 'string' },
    },
}

const FINDINGS_SCHEMA = {
    type: 'object',
    required: ['findings'],
    properties: { findings: { type: 'array', items: FINDING_SCHEMA } },
}

const VERDICT_SCHEMA = {
    type: 'object',
    required: ['refuted', 'issue_refuted', 'names_issue', 'confidence', 'evidence'],
    properties: {
        refuted: { type: 'boolean' },
        issue_refuted: {
            type: 'boolean',
            description: 'The named open Issue does not name this work (false when none is named).',
        },
        names_issue: {
            type: 'integer',
            description:
                'For a carried finding the prompt asks about: the open Issue that names this ' +
                'work, else 0. Always 0 when the prompt does not ask.',
        },
        confidence: { enum: ['high', 'medium', 'low'] },
        evidence: { type: 'string' },
    },
}

const AUDIT_SCHEMA = {
    type: 'object',
    required: ['verdict', 'sections', 'known_issues'],
    properties: {
        verdict: { enum: ['AUDIT PASS', 'AUDIT FAIL'] },
        sections: {
            type: 'array',
            items: {
                type: 'object',
                required: ['name', 'verdict', 'items'],
                properties: {
                    name: { type: 'string' },
                    verdict: { enum: ['PASS', 'FAIL'] },
                    items: { type: 'array', items: { type: 'string' } },
                },
            },
        },
        known_issues: {
            type: 'array',
            description: 'The known-issue entries the audit\'s known-issues section establishes.',
            items: {
                type: 'object',
                required: ['number', 'title', 'summary'],
                properties: {
                    number: { type: 'integer' },
                    title: { type: 'string' },
                    summary: { type: 'string', description: 'One sentence: the shipped defect.' },
                },
            },
        },
    },
}

const REPORT_SCHEMA = {
    type: 'object',
    required: ['report'],
    properties: { report: { type: 'string' } },
}

const NOTES_SCHEMA = {
    type: 'object',
    required: ['notes'],
    properties: {
        notes: { type: 'string', description: 'The whole draft of docs/releases/v<X.Y.Z>.md.' },
    },
}

// ─── Helpers ───

let agent_calls = 0
const failed_review = [] // shard and lens reviewers that returned nothing: unreviewed composition
const failed_other = [] // auditor, renderer, notes, and verifier failures

function run(prompt, opts) {
    agent_calls += 1
    return agent(prompt, opts)
}

const NESTED = ['core', 'services', 'runtime', 'abi', 'shared', 'programs']

function component_of(path) {
    const parts = path.split('/')
    return NESTED.includes(parts[0]) && parts.length > 2 ? parts[0] + '/' + parts[1] : parts[0]
}

// Group the files by component and cut each group into shards of at most
// MAX_SHARD_FILES files and about MAX_SHARD_LINES changed lines. A file is
// never split, so a file whose own range diff exceeds MAX_SHARD_LINES is a
// shard of its own at that size: its reviewer reads one file whole, which the
// composition question needs. Group order follows the scope agent's file order, so the same
// scope yields the same shards on resume.
function shards_of(files) {
    const groups = new Map()
    for (const f of files) {
        const c = component_of(f.path)
        if (!groups.has(c)) groups.set(c, [])
        groups.get(c).push(f)
    }
    const shards = []
    for (const [component, list] of groups) {
        const sorted = [...list].sort((a, b) => b.changed - a.changed || (a.path < b.path ? -1 : 1))
        let current = []
        let lines = 0
        const cut = () => {
            if (current.length) shards.push({ component, files: current })
            current = []
            lines = 0
        }
        for (const f of sorted) {
            const full = current.length >= MAX_SHARD_FILES || lines + f.changed > MAX_SHARD_LINES
            if (current.length && full) cut()
            current.push(f)
            lines += f.changed
        }
        cut()
    }
    const per_component = new Map()
    for (const s of shards) {
        per_component.set(s.component, (per_component.get(s.component) || 0) + 1)
    }
    const seen_component = new Map()
    for (const s of shards) {
        const index = (seen_component.get(s.component) || 0) + 1
        seen_component.set(s.component, index)
        s.index = index
        s.count = per_component.get(s.component)
        s.label = 'review:' + s.component + (s.count > 1 ? '#' + index : '')
    }
    return shards
}

const bullets = (items, render) => (items.length ? items.map(render).join('\n') : '- (none)')
const short = (sha) => sha.slice(0, 8)
const fix_line = (c) =>
    '- ' + c.file + (c.line > 0 ? ':' + c.line : '') + ' — ' + c.summary +
    (c.pr ? ' (PR #' + c.pr + ')' : '')
const doc_line = (d) => '- ' + d

// ─── Phase: Scope ───

phase('Scope')

const SCOPE_PROMPT = [
    'Scope the release candidate for ' + TAG + ': the range from the previous release `' + FROM +
        '` to the checked-out head.' +
        (DELTA ? ' Re-review: the last run reviewed head ' + SINCE + '.' : ''),
    '',
    'Run, at the working tree root: `git rev-parse --show-toplevel`, `git rev-parse HEAD` (the ' +
        'head), `git status --porcelain`, `git rev-parse ' + FROM + '^{commit}` (from_sha), ' +
        '`git merge-base --is-ancestor <from_sha> <head>`, `git diff --name-only --no-renames ' +
        '<from_sha> <head>` (the range file list; count its lines with `wc -l`), `git diff ' +
        '--numstat --no-renames <from_sha> <head>` (its line counts), and `git log ' +
        '--first-parent --format=\'%H %s\' <from_sha>..<head>` (the units). For each unit run ' +
        '`git diff --name-only --no-renames <sha>^1 <sha>` (its files; count with `wc -l`) and ' +
        '`git log -1 --format=%b <sha>` (a merge\'s first body line is the PR title). Read ' +
        '`[workspace.package] version` from `git show <head>:Cargo.toml` and `git show ' +
        '<from_sha>:Cargo.toml`. Run `gh api \'repos/{owner}/{repo}/milestones?state=open&' +
        'per_page=100\' --jq \'.[].title\'` and `gh issue list --state open --limit 500 --json ' +
        'number,title`. List the saved review records with `ls -1 target/xtask/review/pr<N>/' +
        '*-*.json` for each unit\'s PR number N and `ls -1 ' + RECORD_DIR + '/*-*.json`; a ' +
        'directory or pattern that matches nothing lists nothing, which is not an error. Take ' +
        'every list from the local tree: never `gh pr diff` or the `files` field of `gh pr ' +
        'view`, which GitHub caps.' +
        (DELTA
            ? ' Then run `git cat-file -e ' + SINCE + '^{commit}`, `git diff --name-only ' +
                '--no-renames ' + SINCE + ' <head>` (the delta files; count with `wc -l`), and ' +
                '`git log --first-parent --format=%H ' + SINCE + '..<head>`; for each of those ' +
                'units read its PR body (`gh pr view <N> --json body`) and commit messages (`git ' +
                'log --format=%B <sha>^1..<sha>`) for the fixes they claim.'
            : ''),
    '',
    'Return, per the schema, every path repository-relative exactly as git prints it, every ' +
        'list complete however long:',
    '- head, from_sha, repo_root; tree_at_head: the status printed nothing; from_ancestor: the ' +
        'ancestry check exited 0; since_reachable: ' +
        (DELTA ? 'whether ' + SINCE + ' resolves to a commit.' : 'true (no `since` given).'),
    '- range_files: one entry per range path with changed = added plus deleted lines, at_head, ' +
        'and kind = code (Rust, assembly, linker scripts, build inputs, anything a build ' +
        'embeds), markdown, rules (under `.claude/` or `.github/`), or other; range_file_count.',
    '- units: one per first-parent commit, with its PR number (0 when its subject is not ' +
        '`Merge pull request #N ...`), title, files, and file_count.',
    '- version_at_head, version_at_from, milestones (every open milestone title), open_issues.',
    '- ledger_records: every path the `ls` commands printed.',
    '- delta_files and delta_file_count: ' +
        (DELTA ? 'the delta list and its count.' : 'an empty list and 0.'),
    '- claimed_fixes: ' +
        (DELTA
            ? 'every fix the PR bodies and commit messages since ' + SINCE + ' claim, as file, ' +
                'line (0 when unknown), a one-line summary, and the PR.'
            : 'an empty array.'),
    '- prior_known: every known-issue entry of this release\'s saved records: `jq -c ' +
        '\'(.recorded // [])[] | select(.disposition == "known issue") | {issue, claim}\' ' +
        RECORD_DIR + '/*-*.json` (none when no record exists).',
    '- prior_findings: ' +
        (DELTA
            ? 'the findings the last run left standing: `jq -c --arg h "$(git rev-parse ' +
                SINCE + ')" \'select(.stats.head == $h) | (.findings // [])[] | ' +
                'select(.status != "contested")\' ' + RECORD_DIR + '/*-*.json`, each with ' +
                'its fields as saved; since_record: whether any record matched `$h` at all.'
            : 'an empty array; since_record: true.'),
    '',
    'Only scope; do not review. Structured output only.',
].join('\n')

const scope = await run(SCOPE_PROMPT, {
    agentType: INVESTIGATOR, label: 'scope', phase: 'Scope', schema: SCOPE_SCHEMA,
})
if (!scope) return { error: 'Scope agent returned no result; nothing was reviewed.' }
if (!scope.tree_at_head) return { error: 'The working tree at ' + scope.head + ' is not clean.' }
if (!scope.from_ancestor) {
    return { error: FROM + ' (' + scope.from_sha + ') is not an ancestor of ' + scope.head }
}
if (DELTA && !scope.since_reachable) {
    return { error: 'since ' + SINCE + ' does not resolve in this clone; run mode full.' }
}
// A delta run carries the last run's standing findings forward; without that
// run's record it could not, and an unfixed blocker would vanish.
if (DELTA && MODE !== 'scope' && !scope.since_record) {
    return {
        error: 'no saved record under ' + RECORD_DIR + ' reviewed head ' + SINCE +
            '; save that run\'s record, or run mode full.',
    }
}

// The current milestone is the lowest-versioned open one (docs/conventions.md
// § Milestones); the run reviews the release that milestone names.
const version_key = (t) => t.slice(1).split('.').map(Number)
const by_version = (a, b) => {
    const x = version_key(a)
    const y = version_key(b)
    return x[0] - y[0] || x[1] - y[1] || x[2] - y[2]
}
const current_milestone =
    scope.milestones.filter((t) => /^v[0-9]+\.[0-9]+\.[0-9]+$/.test(t)).sort(by_version)[0] || null
if (current_milestone !== TAG) {
    return {
        error: 'args.version ' + VERSION + ' does not name the current milestone (' +
            (current_milestone || 'none open') + ')',
    }
}

// Every path the agents return joins by string equality below, so normalize
// the forms an agent may emit despite the schema description.
const root_prefix = scope.repo_root.replace(/\/+$/, '') + '/'
const normalize = (p) => {
    let s = String(p).trim()
    if (s.startsWith(root_prefix)) s = s.slice(root_prefix.length)
    while (s.startsWith('./')) s = s.slice(2)
    return s
}
for (const f of scope.range_files) f.path = normalize(f.path)
for (const u of scope.units) u.files = u.files.map(normalize)
for (const c of scope.claimed_fixes) c.file = normalize(c.file)
for (const f of scope.prior_findings) f.file = normalize(f.file)
scope.ledger_records = scope.ledger_records.map(normalize)
const delta_paths = new Set(scope.delta_files.map(normalize))

// Count checks: a short list would leave files unreviewed or the shard rule
// misapplied, so every list must hold exactly the count read from the local diff.
const range_paths = new Set(scope.range_files.map((f) => f.path))
if (!Number.isInteger(scope.range_file_count) || scope.range_file_count <= 0) {
    return { error: 'the range ' + scope.from_sha + '..' + scope.head + ' is empty or uncounted' }
}
if (range_paths.size !== scope.range_file_count || scope.range_files.length !== range_paths.size) {
    return {
        error: 'scope returned ' + scope.range_files.length + ' range files for a range of ' +
            scope.range_file_count + ' files',
    }
}
for (const u of scope.units) {
    if (new Set(u.files).size !== u.file_count || u.files.length !== u.file_count) {
        return {
            error: 'scope returned ' + u.files.length + ' files for unit ' + short(u.sha) +
                ' of ' + u.file_count + '; the shard rule cannot be applied',
        }
    }
}
if (DELTA && (delta_paths.size !== scope.delta_file_count)) {
    return {
        error: 'scope returned ' + delta_paths.size + ' delta files for a delta of ' +
            scope.delta_file_count + ' files',
    }
}

const unit_label = (u) => (u.pr ? '#' + u.pr : short(u.sha))
const unit_line = (u) => '- ' + unit_label(u) + ' (merge ' + short(u.sha) + ') ' + u.title

// The shard rule: a file is reviewed line by line only when two or more units
// of the range touched it. The units of a file are the first-parent commits
// whose own diff (`<sha>^1..<sha>`) names it.
const touched_by = new Map()
for (const u of scope.units) {
    for (const p of u.files) {
        if (!touched_by.has(p)) touched_by.set(p, [])
        touched_by.get(p).push(u)
    }
}
const multi = [...touched_by.entries()].filter(([, us]) => us.length >= 2).map(([p]) => p)
const skipped = { absent: [], unchanged: [], generated: [], outside_delta: [] }
const shard_files = []
for (const p of multi) {
    const f = scope.range_files.find((r) => r.path === p)
    if (!f) skipped.unchanged.push(p)
    else if (!f.at_head) skipped.absent.push(p)
    else if (SKIPPED_FILES.includes(p.split('/').pop())) skipped.generated.push(p)
    else if (DELTA && !delta_paths.has(p)) skipped.outside_delta.push(p)
    else shard_files.push({ ...f, units: touched_by.get(p) })
}
for (const [why, list] of Object.entries(skipped)) {
    if (list.length) log('multi-PR files not sharded (' + why + '): ' + list.join(', '))
}
const shards = shards_of(shard_files)

// The range the lenses read: the whole candidate, or in delta mode the delta.
const LENS_FROM = DELTA ? SINCE : scope.from_sha
const lens_paths = DELTA
    ? scope.range_files.filter((f) => delta_paths.has(f.path))
    : scope.range_files
const lens_has_code = lens_paths.some((f) => f.kind === 'code')
// The documents the documentation hierarchy holds (docs/documentation-standards.md
// § Document Hierarchy): Markdown outside `.claude/` and `.github/`, and not a
// per-tag release record or the template, which that standard's release-notes
// exception sets apart.
const in_hierarchy = (p) =>
    p.endsWith('.md') && !p.startsWith('.claude/') && !p.startsWith('.github/') &&
    !(p.startsWith('docs/releases/') && p !== 'docs/releases/README.md')
const design_docs = lens_paths.filter((f) => f.at_head && in_hierarchy(f.path)).map((f) => f.path)
const bumped = scope.version_at_head === VERSION
const sharded_paths = new Set(shard_files.map((f) => f.path))
const unmatched_fixes = scope.claimed_fixes.filter((c) => !sharded_paths.has(c.file))

log(
    TAG + ' ' + MODE + ': ' + scope.units.length + ' units, ' + scope.range_files.length +
        ' range files, ' + multi.length + ' touched by two or more PRs, ' + shard_files.length +
        ' sharded into ' + shards.length + ' shards, ' + design_docs.length + ' design docs, ' +
        scope.ledger_records.length + ' ledger records; head ' +
        (bumped ? 'carries' : 'predates') + ' the bump to ' + VERSION +
        (DELTA ? '; ' + delta_paths.size + ' delta files, ' + scope.claimed_fixes.length +
            ' claimed fixes' : ''),
)

// ─── Prompts ───

const HEAD_LINE =
    'Scope: release candidate ' + TAG + ', mode ' + MODE + '. The range runs from the previous ' +
    'release ' + FROM + ' (' + scope.from_sha + ') to the head ' + scope.head + ', at which the ' +
    'working tree is checked out; `git diff ' + scope.from_sha + ' ' + scope.head + '` is the ' +
    'range diff, and a PR\'s own change is `git diff <merge>^1 <merge>` (never `gh pr diff`, ' +
    'which GitHub caps). Every PR of the range passed its own pre-merge review; this review ' +
    'looks for what no single PR\'s review could see.' +
    (DELTA
        ? ' Re-review: the last run reviewed head ' + SINCE + '; `git diff ' + SINCE + ' ' +
            scope.head + '` is the delta, made of the PRs merged since then, which claim fixes ' +
            'for that run\'s findings.'
        : '')

// Work an open Issue already names does not block the release: such a finding
// is a known-issue candidate. A follow-up Issue holds findings, not work.
const ISSUES_BLOCK = [
    'Open Issues (set `issue` on a finding whose work one of them already names, reading the ' +
        'Issue body when its title matches the area; 0 otherwise). A follow-up Issue (title ' +
        '`<scope>: defects found by review`, or beginning `<scope>: defects found by PR ' +
        '#<N>\'s review`) names findings, not work: never set `issue` to one.',
    bullets(scope.open_issues, (i) => '- #' + i.number + ' ' + i.title),
].join('\n')

// The ledger filter of `.claude/CLAUDE.md` § PR workflow operations, guarded
// for records that lack a key, run over every saved record of the range's PRs
// and of this release's earlier runs.
const LEDGER_FILTER =
    '[.[] | .stats.head[0:8] as $run | (((.recorded // []) + (.dropped // []) + ' +
    '[(.findings // [])[] | select(.status == "contested")] + (if .verdict == ' +
    '"NON-BLOCKING ISSUES ONLY" then (.findings // []) else [] end))[] | {run: $run, file, ' +
    'line, class, bucket, must_violation, status, issue, claim, fix})] | unique'
const LEDGER_FILES = scope.ledger_records.join(' ')

const ledger_note = (paths) =>
    scope.ledger_records.length === 0
        ? '\nLedger: no saved run record exists for the range; set `ledger` false on every finding.'
        : '\nLedger: the findings the PRs\' own reviews and this release\'s earlier runs ' +
            'recorded, dropped, or put to the maintainer (status contested), each with the head ' +
            'of the run that reported it. ' +
            (paths
                ? 'Read the entries for your files: `jq -s \'' + LEDGER_FILTER + ' | map(select(' +
                    paths.map((p) => '.file == "' + p + '"').join(' or ') + '))\' ' +
                    LEDGER_FILES + '`. '
                : 'Read the entries for the files you report on: `jq -s \'' + LEDGER_FILTER +
                    ' | map(select(.file == "<path>"))\' ' + LEDGER_FILES + '`. ') +
            'Report a finding an entry already states with `ledger` true when the hunk it ' +
            'anchors to is unchanged since the run the entry names (`git diff <run> ' +
            scope.head + ' -- <file>`); the workflow lists it and does not count it. Report it ' +
            'with `ledger` false when that hunk changed, or when `<run>` does not resolve.'

function shard_prompt(shard) {
    const units = []
    for (const f of shard.files) for (const u of f.units) if (!units.includes(u)) units.push(u)
    const paths = shard.files.map((f) => f.path)
    const fixes = scope.claimed_fixes.filter((c) => paths.includes(c.file))
    return [
        HEAD_LINE,
        '',
        'Your shard: ' + shard.component +
            (shard.count > 1 ? ' (' + shard.index + ' of ' + shard.count + ')' : '') +
            '. Two or more PRs of the range changed each file below. Read each file whole at ' +
            'the head and each PR\'s own change to it, and apply your brief (steps 3 to 7) to ' +
            'the file as the range left it. Look first for composition defects: one PR\'s ' +
            'change breaking an assumption another relies on, a later change leaving an ' +
            'earlier one\'s comment, test, or invariant stale, definitions duplicated or in ' +
            'conflict, and a lock, ordering, or state rule two changes apply differently. ' +
            'Report every correctness, safety, or contract defect in the file too, and name in ' +
            '`prs` the PRs whose changes make up each finding.',
        bullets(shard.files, (f) =>
            '- ' + f.path + ' (' + f.changed + ' changed lines in the range; ' +
                f.units.map(unit_label).join(', ') + ')'),
        '',
        'PRs of these files:',
        bullets(units, unit_line),
        '',
        ISSUES_BLOCK,
        ledger_note(paths),
        DELTA
            ? '\nClaimed fixes for your files, each to be verified against the code; report a ' +
                'claimed fix not actually made as a contract finding at its location:\n' +
                bullets(fixes, fix_line)
            : null,
        '',
        'Other files belong to other reviewers: read them as callers or dependencies, and ' +
            'report on them only where such a read finds a defect.',
        'Fill the structured schema: one entry per finding. Structured output only.',
    ].filter((line) => line !== null).join('\n')
}

const RANGE = '`git diff ' + LENS_FROM + ' ' + scope.head + '`'
const lenses = []

if (lens_has_code) {
    lenses.push({
        name: 'abi',
        body: () => [
            'Lens: agreement across the boundary over ' + RANGE + '.',
            'For every syscall, ABI type, constant, structure layout, IPC label, and wire ' +
                'message the range adds or changes, check that the ABI crates (`abi/`), the ' +
                'kernel (`core/kernel/`), `shared/syscall` and `shared/ipc`, the runtime ' +
                '(`runtime/`), and the services that use them agree at the head, and agree with ' +
                'the documents that state the contract (`core/kernel/docs/syscalls.md`, the ' +
                'ABI crates\' READMEs, the services\' IPC interface documents): numbers, ' +
                'argument order and widths, error codes, rights, and layouts. Check that every ' +
                'breaking change to a protocol bumped its version constant ' +
                '(docs/conventions.md § ABI / wire-protocol versions). Report each ' +
                'disagreement at the side that is wrong.',
        ],
    })
}

// One lens agent per MAX_LENS_DOCS documents, so no agent holds every touched
// document at once. Each agent reads its documents once for both concerns:
// their whole text against the code, and their `## Summarized By` lists.
const doc_lens_count = Math.ceil(design_docs.length / MAX_LENS_DOCS)
for (let start = 0; start < design_docs.length; start += MAX_LENS_DOCS) {
    const docs = design_docs.slice(start, start + MAX_LENS_DOCS)
    const index = start / MAX_LENS_DOCS + 1
    const part = doc_lens_count > 1 ? ' (documents ' + index + ' of ' + doc_lens_count + ')' : ''
    lenses.push({
        name: 'design-docs' + (doc_lens_count > 1 ? '#' + index : ''),
        body: () => [
            'Lens: the documents ' + RANGE + ' touched' + part + ', each read in full, for two ' +
                'concerns.',
            'Whole-document truth: check every statement of fact, not only the hunks the range ' +
                'changed, against the code at the head (docs/documentation-standards.md § Design ' +
                'Intent: an unmarked statement of behaviour MUST match the code). Report each ' +
                'statement the code contradicts, each pair of statements two PRs of the range ' +
                'left in conflict, and each cross-reference that no longer resolves.',
            '`## Summarized By` integrity: apply docs/documentation-standards.md § Backlinks and ' +
                'Change Propagation and § Authority and Duplication to each document the ' +
                'standard makes authoritative: every document its list names still summarizes ' +
                'it, every tracked document that summarizes it is listed, and every such summary ' +
                'states what the document states at the head. Report a missing or stale entry at ' +
                'the list and a stale summary at the summary.',
            'Cite the document path and section.',
            '',
            'Documents:',
            bullets(docs, doc_line),
        ],
    })
}

if (lens_has_code) {
    lenses.push({
        name: 'unsafe',
        body: () => [
            'Lens: `unsafe` code over ' + RANGE + '.',
            'Find every `unsafe` block, `unsafe fn`, `unsafe impl`, and `unsafe extern` the ' +
                'range adds or changes. For each, check it against docs/coding-standards.md ' +
                '§ Unsafe Code: its safety comment states the invariants the operation needs, ' +
                'and the code and every caller uphold them at the head, including where another ' +
                'PR of the range changed a caller, a lock, a lifetime, or a layout the comment ' +
                'relies on.',
        ],
    })
    lenses.push({
        name: 'coverage',
        body: () => [
            'Lens: test coverage of new interfaces over ' + RANGE + '.',
            'List every syscall, syscall flag or argument, IPC label, and protocol message the ' +
                'range adds or whose contract it changes. For each, find the test that exercises ' +
                'it, per docs/coding-standards.md § D. Testing Invariants and docs/testing.md. ' +
                'Report, class coverage, each one whose success path or a documented error path ' +
                'no test exercises, anchored at its definition.',
        ],
    })
    lenses.push({
        name: 'limits-platform',
        body: () => [
            'Lens: the catalogues against the code over ' + RANGE + '.',
            'Read docs/limits.md and docs/platform-requirements.md in full. Report every bound ' +
                'the range adds or changes that docs/limits.md does not catalogue, or catalogues ' +
                'with a stale value or location, and every CPU or platform feature the range ' +
                'starts or stops requiring or using that docs/platform-requirements.md does not ' +
                'state as the code now stands.',
        ],
    })
}

if (DELTA) {
    lenses.push({
        name: 'regression',
        body: () => [
            'Lens: correctness only, over the delta `git diff ' + SINCE + ' ' + scope.head + '`.',
            'The fixes since ' + SINCE + ' may have introduced a defect. Read the delta with ' +
                'its surrounding code and report logic errors, unsoundness, memory or ' +
                'concurrency defects, resource leaks, and broken contracts. Do not report ' +
                'style, naming, or documentation.',
            '',
            'Claimed fixes outside the sharded files. Verify each against the code and report ' +
                'every fix not actually made as a contract finding at the claimed location:',
            bullets(unmatched_fixes, fix_line),
        ],
    })
}

const lens_prompt = (lens) =>
    [
        HEAD_LINE, '', ...lens.body(), '', ISSUES_BLOCK, ledger_note(null), '',
        'Fill the structured schema; name in `prs` the PRs whose changes make up each finding. ' +
            'Structured output only.',
    ]
        .filter((line) => line !== null)
        .join('\n')

// The audit runs after Verify, so its known-issue list can take the review's
// known-issue candidates: the findings on the blocking track an open Issue
// names, from this run and, while their Issue is open, from the release's
// earlier runs.
const audit_prompt = (candidates) => [
    'Release audit for ' + TAG + ' (mode ' + MODE + '): previous release ' + FROM + ' (' +
        scope.from_sha + '), candidate head ' + scope.head + '.',
    'Workspace version at the head ' + scope.version_at_head + ', at the previous release ' +
        scope.version_at_from + '; the head ' + (bumped ? 'carries' : 'predates') +
        ' the bump to ' + VERSION + '.',
    'Release host-run report: ' + (HOST_RUNS ? '`' + HOST_RUNS + '`.' : 'none given.'),
    'Known-issue candidates of the review (an open Issue names each finding\'s work):',
    bullets(candidates, (k) => '- #' + k.number + ': ' + k.summary),
    'Units of the range:',
    bullets(scope.units, unit_line),
    '',
    'Run your audit per your brief, every section, and fill the structured schema. Structured ' +
        'output only.',
].join('\n')

// An earlier run's known issue stays a candidate only while its Issue is open;
// the audit then confirms that its defect is still present at the head.
const prior_candidates = []
for (const k of scope.prior_known) {
    const open = scope.open_issues.some((i) => i.number === k.issue)
    if (open && !prior_candidates.some((e) => e.number === k.issue)) {
        prior_candidates.push({ number: k.issue, summary: k.claim })
    }
}

const plan = {
    units: scope.units.length,
    range_files: scope.range_files.length,
    multi_pr_files: multi.length,
    skipped,
    shards: shards.map((s) => ({
        label: s.label,
        files: s.files.map((f) => ({
            path: f.path, changed: f.changed, prs: f.units.map(unit_label),
        })),
    })),
    lenses: lenses.map((l) => l.name),
    design_docs,
    ledger_records: scope.ledger_records.length,
    carried_findings: scope.prior_findings.length,
    bumped,
    review_agents: shards.length + lenses.length,
    audit_agents: 1,
}

if (MODE === 'scope') {
    return {
        plan,
        scope,
        sample_prompts: {
            shard: shards.length ? shard_prompt(shards[0]) : null,
            lens: lenses.length ? lens_prompt(lenses[0]) : null,
            audit: audit_prompt(prior_candidates),
        },
    }
}

const issue_title = (n) => (scope.open_issues.find((i) => i.number === n) || {}).title || ''
const open_issue_numbers = new Set(scope.open_issues.map((i) => i.number))
const FOLLOW_UP = /^[^:]+: defects found by (?:review|PR #\d+'s review)/

function verify_prompt(f, lens) {
    const finding = [
        'Finding under test (release candidate ' + TAG + ', head ' + scope.head + '):',
        '- location: ' + f.file + ':' + f.line,
        '- class: ' + f.class + '; severity: ' + f.bucket,
        '- PRs: ' + (f.prs.length ? f.prs.map((n) => '#' + n).join(', ') : '(none named)'),
        '- claim: ' + f.claim,
        '- cited authority: ' + f.authority,
        '- evidence: ' + f.evidence,
        '- proposed fix: ' + f.fix,
        f.issue ? '- named open Issue: #' + f.issue + ' ' + issue_title(f.issue) : null,
        f.carried
            ? '- carried: the run at ' + SINCE + ' reported it, and PRs merged since may have ' +
                'fixed it or moved its line; refuted=true when the head no longer exhibits it.'
            : null,
    ].filter((line) => line !== null).join('\n')
    const tree =
        'The working tree is checked out at the head; `git diff ' + scope.from_sha + ' ' +
        scope.head + '` is the range diff. A defect may be in code or in a document; an absence ' +
        '(a missing check, test, or statement) is exhibited by the place where it should be.'
    if (lens === 'reality') {
        return [
            'You are an independent skeptic. Try to refute this review finding on the facts. ' +
                tree,
            '',
            finding,
            '',
            'Read the whole file at the location and every caller or dependency the claim ' +
                'depends on. refuted=true only with evidence that the defect does not exist as ' +
                'stated, that the code or document already handles the case, or that the ' +
                'evidence does not support the claim. refuted=false when you can point to the ' +
                'place that exhibits the defect, and also when you can neither confirm nor ' +
                'refute it; say so, with confidence low. Evidence must cite file:line. Return ' +
                'issue_refuted=false: whether a named Issue covers the work is the authority ' +
                'refuter\'s judgement, and so is names_issue: return 0. Structured output only.',
        ].join('\n')
    }
    return [
        'You are an independent skeptic. Try to refute this review finding on its authority. ' +
            tree,
        '',
        finding,
        '',
        'Read the cited authority in full. refuted=true only with quoted evidence that the ' +
            'authority does not say what the finding claims, that it is not binding here, or ' +
            'that the location does not violate it as claimed. refuted=false when the authority ' +
            'says what is claimed and the location violates it, when the authority is a ' +
            'correctness contract the location breaks, and also when you can neither confirm ' +
            'nor refute it; say so, with confidence low. ' +
            (f.issue
                ? 'The finding names an open Issue as already naming this work: read it (`gh ' +
                    'issue view ' + f.issue + '`) and set issue_refuted=true when it does not ' +
                    'name this work; that judgement is separate from refuted. '
                : '') +
            (f.carried && !f.issue
                ? 'An earlier run reported this finding, and an Issue may have been filed for ' +
                    'its work since: set names_issue to the open Issue below that names this ' +
                    'work, reading the body of any whose title matches the area, or 0 when none ' +
                    'does; a follow-up Issue (title `<scope>: defects found by review`, or ' +
                    'beginning `<scope>: defects found by PR #<N>\'s review`) names findings, ' +
                    'not work, and is never the answer. That judgement is separate from ' +
                    'refuted.\n' + bullets(scope.open_issues, (i) => '- #' + i.number + ' ' +
                    i.title) + '\n'
                : 'Return names_issue=0. ') +
            'Structured output only.',
    ].join('\n')
}

// ─── Phase: Review, with Verify per reviewer as it completes ───

phase('Review')

const seen = []
const ledgered = []

// A later finding from another agent on the same file, class, bucket, and
// MUST-violation flag within DEDUP_LINE_SLACK lines is the same finding: the
// nearest such record keeps its claim and evidence and absorbs the later one,
// its PRs, and, before its verification starts, a later reporter's Issue. A
// record absorbs at most one finding per agent, so one agent's own adjacent
// findings stay distinct. A finding flagged as already in the ledger becomes a
// `ledgered` record, or joins the ledgered record at its anchor: listed, never
// verified or counted.
const nearest = (list, f, source) =>
    list
        .filter(
            (s) =>
                !s.sources.includes(source) && s.file === f.file && s.class === f.class &&
                s.bucket === f.bucket && s.must_violation === f.must_violation &&
                Math.abs(s.line - f.line) <= DEDUP_LINE_SLACK,
        )
        .sort((a, b) => Math.abs(a.line - f.line) - Math.abs(b.line - f.line))[0]

const new_record = (f, source) => ({
    ...f, prs: [...new Set(f.prs)], sources: [source], duplicates: 0, status: 'pending',
    votes: [], verify_started: false, annotations: [], verification: null,
})

function absorb(dup, f, source) {
    dup.duplicates += 1
    dup.sources.push(source)
    for (const n of f.prs) if (!dup.prs.includes(n)) dup.prs.push(n)
    dup.evidence += '\n[also reported by ' + source + ': ' + f.claim + '] ' + f.evidence
    if (!dup.issue && f.issue) {
        if (dup.verify_started) {
            dup.annotations.push(source + ' named #' + f.issue + ' after verification began')
        } else {
            dup.issue = f.issue
            dup.annotations.push('#' + f.issue + ' adopted from ' + source)
        }
    }
}

function dedup(findings, source) {
    const fresh = []
    for (const f of findings) {
        f.file = normalize(f.file)
        if (f.issue && !open_issue_numbers.has(f.issue)) {
            log(source + ': ' + f.file + ':' + f.line + ' names #' + f.issue + ', not open')
            f.issue = 0
        } else if (f.issue && FOLLOW_UP.test(issue_title(f.issue))) {
            log(source + ': ' + f.file + ':' + f.line + ' names #' + f.issue + ', a follow-up')
            f.issue = 0
        }
        if (f.ledger === true && scope.ledger_records.length) {
            const same = nearest(ledgered, f, source)
            if (same) absorb(same, f, source)
            else {
                const record = new_record(f, source)
                record.status = 'ledgered'
                seen.push(record)
                ledgered.push(record)
            }
            continue
        }
        // A carried record's refuters start before any reviewer reports, so a
        // fresh finding beside it is never absorbed into it: it is verified on
        // its own, and survives when the carried one is dropped as fixed.
        const dup = nearest(
            seen.filter((s) => s.status !== 'ledgered' && !s.carried), f, source)
        if (dup) {
            absorb(dup, f, source)
            continue
        }
        const record = new_record(f, source)
        seen.push(record)
        fresh.push(record)
    }
    return fresh
}

// Verification writes into the record itself, so annotations dedup adds later
// still reach the report.
function verify_one(f) {
    if (!verifiable(f)) {
        f.status = 'nit'
        return Promise.resolve(f)
    }
    if (f.verification) return f.verification
    f.verify_started = true
    f.verification = parallel(
        VERIFY_LENSES.map((lens) => () => {
            // The 1-based record index keeps the label unique when two records
            // share a location (dedup keeps different buckets or flags apart).
            const index = seen.indexOf(f) + 1
            const label = 'verify:' + lens + ':' + f.file + ':' + f.line + '#' + index
            return run(verify_prompt(f, lens), {
                agentType: INVESTIGATOR, label, phase: 'Verify', schema: VERDICT_SCHEMA,
            }).then(
                (v) => (v ? { ...v, lens } : null),
                () => null,
            ).then((v) => {
                if (!v) {
                    failed_other.push(label)
                    log(label + ': no result (agent failed or was stopped)')
                }
                return v
            })
        }),
    ).then((votes) => {
        const valid = votes.filter(Boolean)
        const refutes = valid.filter((v) => v.refuted).length
        const all_refute = refutes === valid.length && valid.length >= VERIFY_LENSES.length
        if (valid.length === 0) f.status = 'unverified'
        else if (all_refute) f.status = 'dropped'
        else if (refutes > 0) f.status = 'contested'
        else f.status = 'confirmed'
        if (f.issue && valid.some((v) => v.lens === 'authority' && v.issue_refuted)) {
            f.annotations.push('#' + f.issue + ' does not name this work (authority refuter)')
            f.issue = 0
        } else if (f.issue && !valid.some((v) => v.lens === 'authority')) {
            f.annotations.push('#' + f.issue + ' unjudged: authority refuter returned no result')
        }
        // A carried finding may since have an Issue that names its work.
        const named = valid.find((v) => v.lens === 'authority' && v.names_issue > 0)
        if (f.carried && !f.issue && named) {
            const n = named.names_issue
            if (open_issue_numbers.has(n) && !FOLLOW_UP.test(issue_title(n))) {
                f.issue = n
                f.annotations.push('#' + n + ' names this work (authority refuter)')
            }
        }
        f.votes = valid
        return f
    })
    return f.verification
}

// A delta run carries forward the findings the last run left standing: each is
// put to the refuters again as still present at the head, so a blocker that no
// fix removed blocks again, and one the fixes removed is dropped.
const CARRIED = 'carried:' + (SINCE ? SINCE.slice(0, 8) : '')
const carried = dedup(
    scope.prior_findings.map((f) => ({ ...f, prs: f.prs || [], ledger: false })),
    CARRIED,
)
for (const f of carried) f.carried = true
const carried_verified = parallel(carried.map((f) => () => verify_one(f)))
if (carried.length) log(CARRIED + ': ' + carried.length + ' findings put to the refuters again')

const review_items = [
    ...shards.map((s) => ({ kind: 'shard', label: s.label, shard: s })),
    ...lenses.map((l) => ({ kind: 'lens', label: 'lens:' + l.name, lens: l })),
]

// The pipeline skips the remaining stages of an item whose stage value is
// null, so a failure is wrapped rather than passed through.
const reviewed = await pipeline(
    review_items,
    (item) =>
        run(item.kind === 'shard' ? shard_prompt(item.shard) : lens_prompt(item.lens), {
            agentType: REVIEWER, label: item.label, phase: 'Review', schema: FINDINGS_SCHEMA,
        }).then((result) => ({ result }), () => ({ result: null })),
    ({ result }, item) => {
        if (!result) {
            failed_review.push(item.label)
            log(item.label + ': no result (agent failed or was stopped)')
            return { item, findings: [] }
        }
        const fresh = dedup(result.findings, item.label)
        log(item.label + ': ' + result.findings.length + ' findings, ' + fresh.length + ' new')
        return parallel(fresh.map((f) => () => verify_one(f))).then((verified) => ({
            item,
            findings: verified.filter(Boolean),
        }))
    },
)

// Whatever the runtime did with a failed item, a missing slot is a failed
// reviewer. Reconcile by index so no failure slips past the accounting.
review_items.forEach((item, i) => {
    if (!reviewed[i] && !failed_review.includes(item.label)) {
        failed_review.push(item.label)
        log(item.label + ': no result (dropped by the pipeline)')
    }
})

const results = reviewed.filter(Boolean)
const carried_judged = (await carried_verified).filter(Boolean)
// A reviewer that reads the file whole reports a still-unfixed carried finding
// again. Once both are judged, a surviving fresh record that matches a
// surviving carried one, as dedup matches, is folded into it, so a standing
// blocker counts once in every run; when the carried record was dropped as
// fixed, the fresh one stands on its own.
// The match is dedup's, over every source of the fresh record, so one agent's
// own adjacent findings stay distinct. The fold takes the fresh record's line
// (the line at the head, so the next run matches it again), its sources, PRs,
// duplicates, and notes, and, when the carried record names no Issue, an
// Issue the fresh record's authority refuter left standing.
const fold_twin = (f) =>
    carried_judged
        .filter(
            (c) =>
                c.status !== 'dropped' && !c.sources.some((s) => f.sources.includes(s)) &&
                c.file === f.file && c.class === f.class && c.bucket === f.bucket &&
                c.must_violation === f.must_violation &&
                Math.abs(c.line - f.line) <= DEDUP_LINE_SLACK,
        )
        .sort((a, b) => Math.abs(a.line - f.line) - Math.abs(b.line - f.line))[0]

function fold(twin, f) {
    twin.duplicates += 1 + f.duplicates
    for (const s of f.sources) if (!twin.sources.includes(s)) twin.sources.push(s)
    for (const n of f.prs) if (!twin.prs.includes(n)) twin.prs.push(n)
    twin.evidence += '\n[re-reported by ' + f.sources.join(', ') + ' at line ' + f.line + ': ' +
        f.claim + '] ' + f.evidence
    twin.line = f.line
    twin.annotations.push(...f.annotations)
    if (!twin.issue && f.issue && f.votes.some((v) => v.lens === 'authority')) {
        twin.issue = f.issue
        twin.annotations.push('#' + f.issue + ' names this work (authority refuter of ' +
            f.sources[0] + ')')
    }
}

const fresh_judged = []
for (const f of results.flatMap((r) => r.findings)) {
    const twin = f.status === 'dropped' ? null : fold_twin(f)
    if (twin) fold(twin, f)
    else fresh_judged.push(f)
}
const all = [...carried_judged, ...fresh_judged]
const dropped = all.filter((f) => f.status === 'dropped')
const surviving = all.filter((f) => f.status !== 'dropped')
// A surviving finding on the blocking track blocks the release unless an open
// Issue names its work, which makes it a known-issue candidate; every other
// surviving finding is recorded on an Issue (docs/conventions.md § Release
// Production).
const findings = surviving.filter((f) => blocks(f) && !f.issue)
const known = surviving.filter((f) => blocks(f) && f.issue)
const nonblocking = surviving.filter((f) => !blocks(f))
for (const f of known) f.disposition = 'known issue'
for (const f of nonblocking) f.disposition = 'record'
const recorded = [...known, ...nonblocking]
const count = (list, status) => list.filter((f) => f.status === status).length

log(
    'Review done: ' + all.length + ' findings (' + carried.length + ' carried); ' +
        findings.length + ' blocking (' + count(findings, 'confirmed') + ' confirmed, ' +
        count(findings, 'contested') + ' contested, ' + count(findings, 'unverified') +
        ' unverified), ' + known.length + ' known-issue candidates, ' + nonblocking.length +
        ' to record, ' + dropped.length + ' dropped, ' + ledgered.length + ' in the ledger' +
        (failed_review.length ? '; failed reviewers: ' + failed_review.join(', ') : ''),
)

// ─── Phase: Audit ───

phase('Audit')

// The known-issue candidates: this run's blocking-track findings an open Issue
// names, and those of the release's earlier runs whose Issue is still open,
// one entry per Issue.
const candidates = [...prior_candidates]
for (const f of known) {
    if (!candidates.some((e) => e.number === f.issue)) {
        candidates.push({ number: f.issue, summary: f.claim })
    }
}

const audit = await run(audit_prompt(candidates), {
    agentType: AUDITOR, label: 'audit', phase: 'Audit', schema: AUDIT_SCHEMA,
}).catch(() => null)
if (!audit) {
    failed_other.push('audit')
    log('audit: no result (agent failed or was stopped)')
} else {
    log('audit: ' + audit.verdict)
}

// ─── Verdicts (computed here, not by an agent) ───

const section_present = (name) =>
    audit.sections.some((s) => s.name.toLowerCase().includes(name.toLowerCase()))
const missing_sections = audit ? AUDIT_SECTION_NAMES.filter((n) => !section_present(n)) : []
const audit_failed =
    !audit || missing_sections.length > 0 || audit.verdict === 'AUDIT FAIL' ||
    audit.sections.some((s) => s.verdict === 'FAIL')
const audit_verdict = audit_failed ? 'AUDIT FAIL' : 'AUDIT PASS'
// A failed reviewer leaves part of the composition unreviewed, which blocks in
// itself, as does an unresolved blocking finding or a failed audit.
const verdict =
    failed_review.length > 0 || findings.length > 0 || audit_failed
        ? 'RELEASE BLOCKED'
        : 'RELEASE READY'

const notes_lines = []
if (!audit) notes_lines.push('The auditor returned no result; treated as AUDIT FAIL.')
if (missing_sections.length) {
    notes_lines.push('The audit lacks the sections ' + missing_sections.join(', ') +
        '; treated as AUDIT FAIL.')
}
if (failed_review.length) {
    notes_lines.push('Incomplete run: ' + failed_review.join(', ') +
        ' returned no result; treated as blocking.')
}
const failed_verifiers = failed_other.filter((l) => l.startsWith('verify:'))
if (failed_verifiers.length) {
    notes_lines.push('Incomplete verification: ' + failed_verifiers.join(', ') + ' returned no ' +
        'result; the affected findings were judged on the remaining votes, or marked unverified.')
}

// The known issues of the release are the audit's list, which takes in the
// candidates above when their defect is still present, plus this run's own
// candidates, which the refuters have just judged present; one entry per Issue.
// An earlier run's candidate the audit left out is not added back.
const known_issues = []
for (const k of (audit && audit.known_issues) || []) {
    if (!known_issues.some((e) => e.number === k.number)) known_issues.push(k)
}
for (const f of known) {
    if (!known_issues.some((e) => e.number === f.issue)) {
        known_issues.push({ number: f.issue, title: issue_title(f.issue), summary: f.claim })
    }
}

// `failed` is read again after Synthesize, which can add to it.
const stats = {
    mode: MODE,
    version: VERSION,
    from: FROM,
    from_sha: scope.from_sha,
    since: SINCE,
    head: scope.head,
    bumped,
    units: scope.units.length,
    range_files: scope.range_files.length,
    multi_pr_files: multi.length,
    shards: shards.length,
    lenses: lenses.map((l) => l.name),
    blocking: findings.length,
    confirmed: count(findings, 'confirmed'),
    contested: count(findings, 'contested'),
    unverified: count(findings, 'unverified'),
    known: known.length,
    recorded: recorded.length,
    nits: count(recorded, 'nit'),
    dropped: dropped.length,
    ledgered: ledgered.length,
    get failed() {
        return [...failed_review, ...failed_other]
    },
}

// ─── Phase: Synthesize ───

phase('Synthesize')

const RENDER_EVIDENCE_CHARS = 400
const RENDER_VOTE_CHARS = 240
const clip = (s, n) => (s.length > n ? s.slice(0, n) + '…' : s)
function for_render(f) {
    const { annotations, verification, ...rest } = f
    return {
        ...rest,
        blocking: blocks(f),
        evidence: clip(f.evidence, RENDER_EVIDENCE_CHARS) +
            annotations.map((a) => '\n[' + a + ']').join(''),
        votes: f.votes.map((v) => ({ ...v, evidence: clip(v.evidence, RENDER_VOTE_CHARS) })),
    }
}

const SYNTH_PROMPT = [
    'Render the release review report for ' + TAG + ' (mode ' + MODE + ', head ' + scope.head +
        ') as Markdown.',
    '',
    'Rules: every finding appears exactly once, with its status tag; do not drop, add, merge, ' +
        're-rank, or soften one. Each entry: `file:line` [status] (bucket, class) claim, with ' +
        '`(MUST violation)` when must_violation is true and the PRs it names. Authority: the ' +
        'cited authority. Rationale: one sentence from the evidence. Fix: the proposed fix. ' +
        'Every bracketed note at the end of a finding\'s evidence is rendered verbatim as its ' +
        'own line. For contested and unverified entries add one line per verifier vote with ' +
        'its lens, refuted flag, confidence, and evidence. Dropped and ledgered findings take ' +
        'one line each. The audit section lists each audit section with its verdict and items, ' +
        'then the known issues.',
    '',
    'Headings, in this order: `# Release review: ' + TAG + '`, `## Blocking`, `## Known-issue ' +
        'candidates` (blocking-class findings an open Issue names; each names its Issue), ' +
        '`## Recorded` (non-blocking findings, recorded on the open Issue that names the work, ' +
        'else the follow-up Issue of their scope), `## Dropped by verification`, `## Ledger ' +
        '(not re-raised)`, `## Audit`. Write `(none)` under an empty heading. Do not write ' +
        'verdict lines; the workflow appends them.',
    '',
    'Blocking (JSON):',
    JSON.stringify(findings.map(for_render), null, 1),
    '',
    'Known-issue candidates (JSON):',
    JSON.stringify(known.map(for_render), null, 1),
    '',
    'Recorded (JSON):',
    JSON.stringify(nonblocking.map(for_render), null, 1),
    '',
    'Dropped (JSON):',
    JSON.stringify(dropped.map(for_render), null, 1),
    '',
    'Ledgered (JSON):',
    JSON.stringify(ledgered.map(for_render), null, 1),
    '',
    'Audit (JSON):',
    JSON.stringify(audit, null, 1),
    '',
    'Stats (JSON):',
    JSON.stringify(stats),
    '',
    'Structured output only.',
].join('\n')

const NOTES_PROMPT = [
    'Draft `docs/releases/' + TAG + '.md`, the release notes for tag ' + TAG + ', per ' +
        'docs/releases/README.md § Source of Truth.',
    'Copy the structure of docs/releases/TEMPLATE.md exactly: every `##` heading as a whole ' +
        'line, in its order, and nothing above the summary line (no `# Title`, no `## ' +
        'Summarized By`); follow each section\'s instructions in the template. Read ' +
        'docs/releases/' + FROM + '.md, when it exists, for tone and length.',
    'Sources: the PRs of the range (`gh pr view <N> --json title,body`), the Issues closed in ' +
        'milestone ' + TAG + ' (`gh issue list --milestone ' + TAG + ' --state closed --limit ' +
        '500 --json number,title,labels`), and the range diff `git diff ' + scope.from_sha +
        ' ' + scope.head + '` for the ABI and protocol version constants ' +
        '(docs/conventions.md § ABI / wire-protocol versions names where they live; list each ' +
        'whose value changed, with its new value). Known Issues lists exactly the entries ' +
        'below, each linking its Issue, or `None` when there are none.',
    '',
    'PRs of the range:',
    bullets(scope.units, unit_line),
    '',
    'Known issues (JSON):',
    JSON.stringify(known_issues, null, 1),
    '',
    'Return the whole file as `notes`. Structured output only.',
].join('\n')

const [synthesized, drafted] = await parallel([
    () => run(SYNTH_PROMPT, {
        agentType: INVESTIGATOR, label: 'synthesize', phase: 'Synthesize', schema: REPORT_SCHEMA,
    }),
    () => verdict === 'RELEASE READY'
        ? run(NOTES_PROMPT, {
            agentType: INVESTIGATOR, label: 'notes', phase: 'Synthesize', schema: NOTES_SCHEMA,
        })
        : Promise.resolve(null),
])

if (!synthesized) {
    failed_other.push('synthesize')
    notes_lines.push('The synthesizer returned no result; the report body is a placeholder.')
}
if (verdict === 'RELEASE READY' && !drafted) {
    failed_other.push('notes')
    notes_lines.push('The notes agent returned no result; no release-notes draft was produced.')
}

const body = synthesized
    ? synthesized.report
    : '# Release review: ' + TAG + '\n\nSynthesis agent returned no result; the raw findings ' +
        'are in the `findings`, `recorded`, `ledgered`, `dropped`, and `audit` fields.\n'

// The two verdict lines stand alone so they can be surfaced verbatim; notes
// follow on their own lines.
const report =
    body.replace(/\s+$/, '') + '\n\n' + verdict + '\n' + audit_verdict + '\n' +
    (notes_lines.length ? '\n' + notes_lines.join('\n') + '\n' : '')

stats.agents = agent_calls

const plain = (f) => {
    const { verification, ...rest } = f
    return rest
}

return {
    verdict,
    audit_verdict,
    report,
    notes: verdict === 'RELEASE READY' && drafted ? drafted.notes : null,
    findings: findings.map(plain),
    recorded: recorded.map(plain),
    ledgered: ledgered.map(plain),
    dropped: dropped.map(plain),
    audit,
    known_issues,
    plan,
    stats: { ...stats },
}
