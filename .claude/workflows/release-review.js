// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// .claude/workflows/release-review.js

// Sharded adversarial review and audit of a release candidate.
//
// The pre-merge review of every pull request read each PR's own lines; this
// workflow reviews what none of them saw, the composition of the merged PRs
// between the previous release tag and the candidate head
// (docs/conventions.md § Release Production says when it runs and what
// follows from it). It runs once per release, before the version bump; it is
// not run again over the fixes. Its reviewers report defects only
// (docs/conventions.md § Findings).
//
// Scope (one agent) lists the range, its first-parent units (one per merged
// PR), and each unit's files. Review runs one `pr-reviewer` per shard of the
// code files two or more units touched (no other code file is reviewed line by
// line), one lens over every Markdown document and instruction file the range
// touched, and the whole-range lenses, in parallel. Verify puts every defect that can
// block (one no open Issue names) to two independent refuters as soon as its
// reviewer completes; the reality refuter also judges whether the defect was
// already present at the previous release, which sets it apart as predating
// the range. A defect an open Issue names is a known issue and takes no
// refuters. Audit runs the `release-auditor` with the known-issue candidates.
// Synthesize renders one report and drafts the release notes from
// docs/releases/TEMPLATE.md. The script computes the verdict line itself:
// `RELEASE BLOCKED` when a reviewer failed, the run reached its agent ceiling,
// a confirmed defect stands that no open Issue names and that does not predate
// the range, or the audit fails; `RELEASE READY` otherwise. The confirmed
// defects go to the maintainer as one list, each with a recommendation.
//
// The ledger is the union of the saved run records of the range's PRs and of
// this release's own runs; reviewers read it with `cargo xtask review-ledger
// --release` (xtask/README.md), and a finding an entry states at a hunk
// unchanged since the run the entry names, when that run resolves in the
// clone, is listed, not counted.
//
// args: { mode: 'scope' | 'full' | 'audit', from: string, version: string,
//         host_runs?: string, max_agents?: number }
//   from         the previous release tag (or any commit) the range starts at.
//   version      the target version `X.Y.Z`; `vX.Y.Z` must be the current
//                milestone (docs/conventions.md § Milestones).
//   mode 'full'  reviews the whole range `from..HEAD` and audits it.
//   mode 'scope' stops after Scope and returns the agent plan, its agent
//                count before verification, and sample prompts (one agent).
//   mode 'audit' runs the release audit alone at the head (Release Production
//                step 5): Scope, then the `release-auditor`.
//   host_runs    path of the release host-run report; the audit requires it
//                once the head carries the version bump.
//   max_agents   the agent ceiling (default 250). A run whose plan exceeds it
//                stops before it reviews; a run that reaches it during
//                verification stops verifying, leaves the rest unverified,
//                and is `RELEASE BLOCKED` until the maintainer decides how to
//                go on.
//
// The agent types below resolve from the definitions the session loaded at its
// start, so the session that runs this workflow must have started after
// `.claude/agents/release-verifier.md` and `release-auditor.md` were on the
// checked-out branch.
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
        { title: 'Scope', detail: 'list the range, its PRs and files; count the agents' },
        { title: 'Review', detail: 'multi-PR code shards, the documents lens, range lenses' },
        { title: 'Verify', detail: 'two independent refuters per defect that can block' },
        { title: 'Audit', detail: 'release-auditor, given the known-issue candidates' },
        { title: 'Synthesize', detail: 'report and notes draft; verdict computed by the script' },
    ],
}

// ─── Arguments ───

const MODES = ['full', 'scope', 'audit']
const text_arg = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null)
const MODE = args && MODES.includes(args.mode) ? args.mode : null
const FROM = args ? text_arg(args.from) : null
const VERSION = args ? text_arg(args.version) : null
const HOST_RUNS = args ? text_arg(args.host_runs) : null
const DEFAULT_MAX_AGENTS = 250
const MAX_AGENTS =
    args && Number.isInteger(args.max_agents) && args.max_agents > 0
        ? args.max_agents
        : DEFAULT_MAX_AGENTS

if (MODE === null) return { error: "args.mode must be 'full', 'scope', or 'audit'" }
if (FROM === null) return { error: 'args.from must name the previous release tag' }
if (VERSION === null || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(VERSION)) {
    return { error: 'args.version must be the target version X.Y.Z' }
}

const TAG = 'v' + VERSION

// ─── Tunables ───

const MAX_SHARD_FILES = 6 // files per shard reviewer
const MAX_SHARD_LINES = 500 // changed lines per shard reviewer
const DEDUP_LINE_SLACK = 3 // lines apart at which two findings in one file are one
const VERIFY_LENSES = ['reality', 'authority']
// Agents a full run makes after Verify: audit, synthesize, and notes.
const AFTER_VERIFY = 3
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
        'head', 'from_sha', 'repo_root', 'tree_at_head', 'from_ancestor', 'range_files',
        'range_file_count', 'units', 'version_at_head', 'version_at_from', 'milestones',
        'open_issues',
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
    },
}

const FINDING_SCHEMA = {
    type: 'object',
    required: [
        'file', 'line', 'ledger', 'issue', 'prs', 'authority', 'claim', 'evidence', 'fix',
    ],
    properties: {
        file: { type: 'string', description: PATH_DESCRIPTION },
        line: { type: 'integer', description: '1-based line at the head the defect anchors to.' },
        ledger: {
            type: 'boolean',
            description:
                'A ledger entry already states this defect, and the hunk it anchors to is ' +
                'unchanged since the run the entry names (false when that hunk changed or that ' +
                'run does not resolve in the clone).',
        },
        issue: {
            type: 'integer',
            description:
                'The open Issue that already names this defect, when one does (0 otherwise): ' +
                'its body states it, it is an item of a rolling Issue, or an Issue comment ' +
                'lists it.',
        },
        prs: {
            type: 'array',
            items: { type: 'integer' },
            description: 'The PRs of the range whose changes make up the defect (empty when none).',
        },
        authority: {
            type: 'string',
            description: 'The contract, document section, or behaviour the location breaks.',
        },
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
    required: ['refuted', 'predates', 'confidence', 'evidence'],
    properties: {
        refuted: { type: 'boolean' },
        predates: {
            type: 'boolean',
            description:
                'The defect was already present at the previous release. Always false when ' +
                'the prompt does not ask.',
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

// ─── Phase: Scope ───

phase('Scope')

const SCOPE_PROMPT = [
    'Scope the release candidate for ' + TAG + ': the range from the previous release `' + FROM +
        '` to the checked-out head.',
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
        'number,title`. Take every list from the local tree: never `gh pr diff` or the `files` ' +
        'field of `gh pr view`, which GitHub caps.',
    '',
    'Return, per the schema, every path repository-relative exactly as git prints it, every ' +
        'list complete however long:',
    '- head, from_sha, repo_root; tree_at_head: the status printed nothing; from_ancestor: the ' +
        'ancestry check exited 0.',
    '- range_files: one entry per range path with changed = added plus deleted lines, at_head, ' +
        'and kind = code (Rust, assembly, linker scripts, build inputs, anything a build ' +
        'embeds), markdown, rules (under `.claude/` or `.github/`), or other; range_file_count.',
    '- units: one per first-parent commit, with its PR number (0 when its subject is not ' +
        '`Merge pull request #N ...`), title, files, and file_count.',
    '- version_at_head, version_at_from, milestones (every open milestone title), open_issues.',
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

const unit_label = (u) => (u.pr ? '#' + u.pr : short(u.sha))
const unit_line = (u) => '- ' + unit_label(u) + ' (merge ' + short(u.sha) + ') ' + u.title
const bumped = scope.version_at_head === VERSION
const issue_title = (n) => (scope.open_issues.find((i) => i.number === n) || {}).title || ''
const open_issue_numbers = new Set(scope.open_issues.map((i) => i.number))

// ─── The audit (every mode but scope) ───

// The known-issue candidates: in a full run, the defects an open Issue names
// (a defect that predates the range has no Issue yet, so it is not one); in
// audit mode, the Known Issues the release notes at the head list, which
// record the maintainer's decision on the full run's list.
const audit_prompt = (candidates) => [
    'Release audit for ' + TAG + ' (mode ' + MODE + '): previous release ' + FROM + ' (' +
        scope.from_sha + '), candidate head ' + scope.head + '.',
    'Workspace version at the head ' + scope.version_at_head + ', at the previous release ' +
        scope.version_at_from + '; the head ' + (bumped ? 'carries' : 'predates') +
        ' the bump to ' + VERSION + '.',
    'Release host-run report: ' + (HOST_RUNS ? '`' + HOST_RUNS + '`.' : 'none given.'),
    MODE === 'audit'
        ? 'Known-issue candidates: the entries of the Known Issues section of ' +
            '`docs/releases/' + TAG + '.md` at the head, which records the maintainer\'s ' +
            'decision on the release review\'s list.'
        : 'Known-issue candidates of the review (an open Issue names each defect):\n' +
            bullets(candidates, (k) => '- #' + k.number + ': ' + k.summary),
    'Units of the range:',
    bullets(scope.units, unit_line),
    '',
    'Run your audit per your brief, every section, and fill the structured schema. Structured ' +
        'output only.',
].join('\n')

async function run_audit(candidates) {
    const result = await run(audit_prompt(candidates), {
        agentType: AUDITOR, label: 'audit', phase: 'Audit', schema: AUDIT_SCHEMA,
    }).catch(() => null)
    if (!result) {
        failed_other.push('audit')
        log('audit: no result (agent failed or was stopped)')
    } else {
        log('audit: ' + result.verdict)
    }
    return result
}

function audit_outcome(audit) {
    const present = (name) =>
        audit.sections.some((s) => s.name.toLowerCase().includes(name.toLowerCase()))
    const missing = audit ? AUDIT_SECTION_NAMES.filter((n) => !present(n)) : []
    const failed =
        !audit || missing.length > 0 || audit.verdict === 'AUDIT FAIL' ||
        audit.sections.some((s) => s.verdict === 'FAIL')
    const notes = []
    if (!audit) notes.push('The auditor returned no result; treated as AUDIT FAIL.')
    if (missing.length) {
        notes.push('The audit lacks the sections ' + missing.join(', ') +
            '; treated as AUDIT FAIL.')
    }
    return { failed, verdict: failed ? 'AUDIT FAIL' : 'AUDIT PASS', notes }
}

if (MODE === 'audit') {
    phase('Audit')
    const audit = await run_audit([])
    const outcome = audit_outcome(audit)
    const verdict = outcome.failed ? 'RELEASE BLOCKED' : 'RELEASE READY'
    const sections = audit
        ? audit.sections.map((s) => '## ' + s.name + ': ' + s.verdict + '\n\n' +
            bullets(s.items, (i) => '- ' + i)).join('\n\n')
        : '(no audit result)'
    const notes = outcome.notes.length ? '\n' + outcome.notes.join('\n') + '\n' : ''
    return {
        verdict,
        audit_verdict: outcome.verdict,
        report: '# Release audit: ' + TAG + '\n\n' + sections + '\n\n' + verdict + '\n' +
            outcome.verdict + '\n' + notes,
        audit,
        stats: {
            mode: MODE, version: VERSION, from: FROM, from_sha: scope.from_sha, head: scope.head,
            bumped, agents: agent_calls, failed: [...failed_other],
        },
    }
}

// ─── Plan ───

// The shard rule: a code file is reviewed line by line only when two or more
// units of the range touched it. The units of a file are the first-parent
// commits whose own diff (`<sha>^1..<sha>`) names it. A Markdown file, a
// document or an instruction file under `.claude/` or `.github/`, is read by
// the documents lens instead; a rules file that is not Markdown (a CI
// workflow, this script, the settings) is code and is sharded.
const is_document = (f) => f.path.toLowerCase().endsWith('.md')
const touched_by = new Map()
for (const u of scope.units) {
    for (const p of u.files) {
        if (!touched_by.has(p)) touched_by.set(p, [])
        touched_by.get(p).push(u)
    }
}
const multi = [...touched_by.entries()].filter(([, us]) => us.length >= 2).map(([p]) => p)
const skipped = { absent: [], unchanged: [], generated: [], document: [] }
const shard_files = []
for (const p of multi) {
    const f = scope.range_files.find((r) => r.path === p)
    if (!f) skipped.unchanged.push(p)
    else if (!f.at_head) skipped.absent.push(p)
    else if (SKIPPED_FILES.includes(p.split('/').pop())) skipped.generated.push(p)
    else if (is_document(f)) skipped.document.push(p)
    else shard_files.push({ ...f, units: touched_by.get(p) })
}
for (const [why, list] of Object.entries(skipped)) {
    if (list.length) log('multi-PR files not sharded (' + why + '): ' + list.length)
}
const shards = shards_of(shard_files)

const lens_has_code = scope.range_files.some((f) => f.kind === 'code')
const documents = scope.range_files.filter((f) => f.at_head && is_document(f)).map((f) => f.path)

// ─── Prompts ───

const HEAD_LINE =
    'Scope: release candidate ' + TAG + '. The range runs from the previous release ' + FROM +
    ' (' + scope.from_sha + ') to the head ' + scope.head + ', at which the working tree is ' +
    'checked out; `git diff ' + scope.from_sha + ' ' + scope.head + '` is the range diff, and a ' +
    'PR\'s own change is `git diff <merge>^1 <merge>` (never `gh pr diff`, which GitHub caps). ' +
    'Every PR of the range passed its own pre-merge review; this review looks for what no ' +
    'single PR\'s review could see. Report defects only (docs/conventions.md § Findings): ' +
    'wrong or unsafe behaviour, a broken contract between components, or a document statement ' +
    'that would make its reader write wrong code. Report nothing else.'

const ISSUES_BLOCK = [
    'Open Issues. Set `issue` on a defect one of them already names: its body states it, it ' +
        'is an item of a rolling Issue (title `<scope>: defects found by review`), or a ' +
        'comment on the Issue lists it. Read the body and comments of any Issue whose title ' +
        'matches the area; 0 otherwise.',
    bullets(scope.open_issues, (i) => '- #' + i.number + ' ' + i.title),
].join('\n')

const LEDGER_COMMAND = 'cargo xtask review-ledger --release ' + VERSION + ' --from ' + FROM

const ledger_note = (paths) =>
    '\nLedger: the findings the PRs\' own reviews and this release\'s earlier runs recorded or ' +
    'dropped, or that a decision settled, each with the head of the run that reported it. ' +
    (paths
        ? 'Read the entries for your files: `' + LEDGER_COMMAND + ' ' +
            paths.map((p) => '--file ' + p).join(' ') + '`. '
        : 'Read the entries for the files you report on: `' + LEDGER_COMMAND +
            ' --file <path>`. ') +
    'Report a defect an entry already states with `ledger` true when the hunk it anchors to ' +
    'is unchanged since the run the entry names (`git diff <run> ' + scope.head + ' -- ' +
    '<file>`); the workflow lists it and does not count it. Report it with `ledger` false when ' +
    'that hunk changed, or when `<run>` does not resolve.'

function shard_prompt(shard) {
    const units = []
    for (const f of shard.files) for (const u of f.units) if (!units.includes(u)) units.push(u)
    const paths = shard.files.map((f) => f.path)
    return [
        HEAD_LINE,
        '',
        'Your shard: ' + shard.component +
            (shard.count > 1 ? ' (' + shard.index + ' of ' + shard.count + ')' : '') +
            '. Two or more PRs of the range changed each file below. Read each file whole at ' +
            'the head and each PR\'s own change to it, and apply your brief (steps 3 to 7) to ' +
            'the file as the range left it. Look first for composition defects: one PR\'s ' +
            'change breaking an assumption another relies on, a later change leaving an ' +
            'earlier one\'s invariant or documented contract untrue, definitions in conflict, ' +
            'and a lock, ordering, or state rule two changes apply differently. Report every ' +
            'other defect in the file too, and name in `prs` the PRs whose changes make up ' +
            'each one.',
        bullets(shard.files, (f) =>
            '- ' + f.path + ' (' + f.changed + ' changed lines in the range; ' +
                f.units.map(unit_label).join(', ') + ')'),
        '',
        'PRs of these files:',
        bullets(units, unit_line),
        '',
        ISSUES_BLOCK,
        ledger_note(paths),
        '',
        'Other files belong to other reviewers: read them as callers or dependencies, and ' +
            'report on them only where such a read finds a defect.',
        'Fill the structured schema: one entry per defect. Structured output only.',
    ].join('\n')
}

const RANGE = '`git diff ' + scope.from_sha + ' ' + scope.head + '`'
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

// One lens over every document and instruction file the range touched, in
// place of line-by-line shards of them: it reads the range's change to each
// and reports only a statement that would make its reader write wrong code.
if (documents.length) {
    lenses.push({
        name: 'documents',
        body: () => [
            'Lens: the documents and instruction files ' + RANGE + ' touched, read through the ' +
                'range\'s change to each (`git diff ' + scope.from_sha + ' ' + scope.head +
                ' -- <path>`) and the sections around it.',
            'Report a statement the range added or left standing that the code at the head ' +
                'contradicts and that would make its reader write wrong code (a syscall, ABI, ' +
                'IPC, command-line, or safety contract; a rule an instruction file states that ' +
                'its owning document contradicts), and a pair of statements two PRs of the ' +
                'range left in conflict on such a point. Do not report wording, layout, ' +
                '`## Summarized By` lists, or a statement that is merely incomplete; ' +
                '`cargo xtask lint-docs` checks what a script can decide.',
            '',
            'Documents:',
            bullets(documents, (d) => '- ' + d),
        ],
    })
}

if (lens_has_code) {
    lenses.push({
        name: 'unsafe',
        body: () => [
            'Lens: `unsafe` code over ' + RANGE + '.',
            'Find every `unsafe` block, `unsafe fn`, `unsafe impl`, and `unsafe extern` the ' +
                'range adds or changes. For each, check that the invariants the operation ' +
                'needs hold at the head, at the site and at every caller, including where ' +
                'another PR of the range changed a caller, a lock, a lifetime, or a layout the ' +
                'safety comment relies on (docs/coding-standards.md § Unsafe Code).',
        ],
    })
    lenses.push({
        name: 'limits-platform',
        body: () => [
            'Lens: the catalogues against the code over ' + RANGE + '.',
            'Read docs/limits.md and docs/platform-requirements.md in full. Report every bound ' +
                'the range adds or changes that docs/limits.md states with a value or location ' +
                'the code contradicts, and every CPU or platform feature the range starts or ' +
                'stops requiring that docs/platform-requirements.md states otherwise.',
        ],
    })
}

const lens_prompt = (lens) =>
    [
        HEAD_LINE, '', ...lens.body(), '', ISSUES_BLOCK, ledger_note(null), '',
        'Fill the structured schema: one entry per defect; name in `prs` the PRs whose changes ' +
            'make up each one. Structured output only.',
    ].join('\n')

// The agents the run makes before Verify, and after it; Verify adds two per
// defect that can block, which no plan can know.
const review_agents = shards.length + lenses.length
const fixed_agents = 1 + review_agents + AFTER_VERIFY

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
    documents: documents.length,
    bumped,
    review_agents,
    agents_without_verify: fixed_agents,
    verify_agents_per_defect: VERIFY_LENSES.length,
    max_agents: MAX_AGENTS,
}

log(
    TAG + ' ' + MODE + ': ' + scope.units.length + ' units, ' + scope.range_files.length +
        ' range files, ' + shard_files.length + ' multi-PR code files in ' + shards.length +
        ' shards, ' + lenses.length + ' lenses; ' + fixed_agents + ' agents before ' +
        'verification, 2 per defect that can block, ceiling ' + MAX_AGENTS,
)

if (MODE === 'scope') {
    return {
        plan,
        scope,
        sample_prompts: {
            shard: shards.length ? shard_prompt(shards[0]) : null,
            lens: lenses.length ? lens_prompt(lenses[0]) : null,
            audit: audit_prompt([]),
        },
    }
}

if (fixed_agents > MAX_AGENTS) {
    return {
        error: 'the run needs ' + fixed_agents + ' agents before verification, over the ' +
            'ceiling of ' + MAX_AGENTS + '; ask the maintainer, then run with a higher ' +
            'max_agents',
        plan,
    }
}

function verify_prompt(f, lens) {
    const finding = [
        'Defect under test (release candidate ' + TAG + ', head ' + scope.head + '):',
        '- location: ' + f.file + ':' + f.line,
        '- PRs: ' + (f.prs.length ? f.prs.map((n) => '#' + n).join(', ') : '(none named)'),
        '- claim: ' + f.claim,
        '- cited authority: ' + f.authority,
        '- evidence: ' + f.evidence,
        '- proposed fix: ' + f.fix,
    ].join('\n')
    const tree =
        'The working tree is checked out at the head; `git diff ' + scope.from_sha + ' ' +
        scope.head + '` is the range diff. A defect may be in code or in a document; an absence ' +
        '(a missing check or statement) is exhibited by the place where it should be.'
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
                'refute it; say so, with confidence low. Evidence must cite file:line. When the ' +
                'defect stands, also judge whether it was already present at the previous ' +
                'release ' + FROM + ': read the same place there (`git show ' + scope.from_sha +
                ':<path>`) and set predates=true when it exhibits the same defect. ' +
                'Structured output only.',
        ].join('\n')
    }
    return [
        'You are an independent skeptic. Try to refute this review finding on its authority. ' +
            tree,
        '',
        finding,
        '',
        'Read the cited authority in full. refuted=true only with quoted evidence that the ' +
            'authority does not say what the finding claims, that it is not binding here, that ' +
            'the location does not break it as claimed, or that what the finding describes is ' +
            'not a defect (docs/conventions.md § Findings: wrong or unsafe behaviour, a broken ' +
            'contract, or a document statement that would make its reader write wrong code). ' +
            'refuted=false when the location breaks it, and also when you can neither confirm ' +
            'nor refute it; say so, with confidence low. Return predates=false: that judgement ' +
            'is the reality refuter\'s. Structured output only.',
    ].join('\n')
}

// ─── Phase: Review, with Verify per reviewer as it completes ───

phase('Review')

const seen = []
const ledgered = []
let ceiling_reached = false
// The agents the run has committed to: every one the plan counts (scope, the
// reviewers whether started or not, and those after Verify), and each pair of
// refuters as it is granted, so the ceiling holds however the runtime orders
// the reviewers and the refuters.
let committed_agents = fixed_agents

// A later finding from another agent in the same file within DEDUP_LINE_SLACK
// lines is the same defect: the nearest such record keeps its claim and
// evidence and absorbs the later one, its PRs, and, before its verification
// starts, a later reporter's Issue. A record absorbs at most one finding per
// agent, so one agent's own adjacent findings stay distinct. A finding flagged
// as already in the ledger becomes a `ledgered` record, or joins the ledgered
// record at its anchor: listed, never verified or counted.
const nearest = (list, f, source) =>
    list
        .filter(
            (s) =>
                !s.sources.includes(source) && s.file === f.file &&
                Math.abs(s.line - f.line) <= DEDUP_LINE_SLACK,
        )
        .sort((a, b) => Math.abs(a.line - f.line) - Math.abs(b.line - f.line))[0]

const new_record = (f, source) => ({
    ...f, prs: [...new Set(f.prs)], sources: [source], duplicates: 0, status: 'pending',
    predates: false, votes: [], verify_started: false, annotations: [], verification: null,
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
        }
        if (f.ledger === true) {
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
        const dup = nearest(seen.filter((s) => s.status !== 'ledgered'), f, source)
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
// still reach the report. A defect an open Issue names cannot block and takes
// no refuters; one the ceiling leaves no room for stays unverified.
function verify_one(f) {
    if (f.issue) {
        f.status = 'known'
        return Promise.resolve(f)
    }
    if (f.verification) return f.verification
    if (committed_agents + VERIFY_LENSES.length > MAX_AGENTS) {
        ceiling_reached = true
        f.status = 'unverified'
        f.annotations.push('not verified: the run reached its ceiling of ' + MAX_AGENTS)
        return Promise.resolve(f)
    }
    committed_agents += VERIFY_LENSES.length
    f.verify_started = true
    f.verification = parallel(
        VERIFY_LENSES.map((lens) => () => {
            // The 1-based record index keeps the label unique when two records
            // share a location.
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
        f.predates = valid.some((v) => v.lens === 'reality' && !v.refuted && v.predates)
        f.votes = valid
        return f
    })
    return f.verification
}

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

const all = reviewed.filter(Boolean).flatMap((r) => r.findings)
const dropped = all.filter((f) => f.status === 'dropped')
// Only a confirmed defect that no open Issue names and that does not predate
// the range blocks the release; it is recommended for a fix before the tag.
// A defect an open Issue names, and a confirmed one that predates the range,
// is a known issue by default. A contested or unverified finding goes to the
// maintainer with the list, undecided.
const findings = all.filter((f) => f.status === 'confirmed' && !f.predates)
const predating = all.filter((f) => f.status === 'confirmed' && f.predates)
const known = all.filter((f) => f.status === 'known')
const undecided = all.filter((f) => f.status === 'contested' || f.status === 'unverified')
for (const f of findings) f.recommendation = 'fix'
for (const f of [...predating, ...known]) f.recommendation = 'known issue'
for (const f of undecided) f.recommendation = 'maintainer to decide'
const recorded = [...known, ...predating]
for (const f of recorded) f.disposition = 'known issue'

log(
    'Review done: ' + all.length + ' defects; ' + findings.length + ' blocking, ' +
        predating.length + ' predating the range, ' + known.length + ' named by an open ' +
        'Issue, ' + undecided.length + ' contested or unverified, ' + dropped.length +
        ' dropped, ' + ledgered.length + ' in the ledger' +
        (ceiling_reached ? '; the ceiling of ' + MAX_AGENTS + ' was reached' : '') +
        (failed_review.length ? '; failed reviewers: ' + failed_review.join(', ') : ''),
)

// ─── Phase: Audit ───

phase('Audit')

const candidates = []
for (const f of recorded) {
    if (f.issue && !candidates.some((e) => e.number === f.issue)) {
        candidates.push({ number: f.issue, summary: f.claim })
    }
}
const audit = await run_audit(candidates)
const outcome = audit_outcome(audit)
const audit_verdict = outcome.verdict

// ─── Verdicts (computed here, not by an agent) ───

// A failed reviewer leaves part of the composition unreviewed, and a run at
// its ceiling leaves defects unverified, which block in themselves, as does a
// blocking defect or a failed audit.
const verdict =
    failed_review.length > 0 || ceiling_reached || findings.length > 0 || outcome.failed
        ? 'RELEASE BLOCKED'
        : 'RELEASE READY'

const notes_lines = [...outcome.notes]
if (failed_review.length) {
    notes_lines.push('Incomplete run: ' + failed_review.join(', ') +
        ' returned no result; treated as blocking.')
}
if (ceiling_reached) {
    notes_lines.push('The run reached its ceiling of ' + MAX_AGENTS + ' agents; the defects ' +
        'it could not verify are unverified, and the maintainer decides how to go on.')
}
const failed_verifiers = failed_other.filter((l) => l.startsWith('verify:'))
if (failed_verifiers.length) {
    notes_lines.push('Incomplete verification: ' + failed_verifiers.join(', ') + ' returned no ' +
        'result; the affected defects were judged on the remaining votes, or marked unverified.')
}

// The known issues of the release are the audit's list, which takes in the
// candidates above when their defect is still present, plus this run's own
// Issue-named defects; one entry per Issue.
const known_issues = []
for (const k of (audit && audit.known_issues) || []) {
    if (!known_issues.some((e) => e.number === k.number)) known_issues.push(k)
}
for (const f of recorded) {
    if (f.issue && !known_issues.some((e) => e.number === f.issue)) {
        known_issues.push({ number: f.issue, title: issue_title(f.issue), summary: f.claim })
    }
}

// `failed` is read again after Synthesize, which can add to it.
const stats = {
    mode: MODE,
    version: VERSION,
    from: FROM,
    from_sha: scope.from_sha,
    head: scope.head,
    bumped,
    units: scope.units.length,
    range_files: scope.range_files.length,
    multi_pr_files: multi.length,
    shards: shards.length,
    lenses: lenses.map((l) => l.name),
    blocking: findings.length,
    predating: predating.length,
    known: known.length,
    undecided: undecided.length,
    dropped: dropped.length,
    ledgered: ledgered.length,
    max_agents: MAX_AGENTS,
    ceiling_reached,
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
        evidence: clip(f.evidence, RENDER_EVIDENCE_CHARS) +
            annotations.map((a) => '\n[' + a + ']').join(''),
        votes: f.votes.map((v) => ({ ...v, evidence: clip(v.evidence, RENDER_VOTE_CHARS) })),
    }
}

const SYNTH_PROMPT = [
    'Render the release review report for ' + TAG + ' (head ' + scope.head + ') as Markdown.',
    '',
    'Rules: every finding appears exactly once, with its status tag and its recommendation; do ' +
        'not drop, add, merge, re-rank, or soften one. Order the entries under a heading by ' +
        'file, then line. Each entry: `file:line` [status] claim, and the PRs it names. ' +
        'Authority: the cited authority. Rationale: one sentence from the evidence. Fix: the ' +
        'proposed fix. Recommendation: its recommendation. Every bracketed note at the end of ' +
        'a finding\'s evidence is rendered verbatim as its own line. For contested and ' +
        'unverified entries add one line per verifier vote with its lens, refuted flag, ' +
        'confidence, and evidence. Dropped and ledgered findings take one line each. The audit ' +
        'section lists each audit section with its verdict and items, then the known issues.',
    '',
    'Headings, in this order: `# Release review: ' + TAG + '`, `## For the maintainer: fix ' +
        'before the tag` (the blocking defects), `## Predating the range` (confirmed defects ' +
        'already present at ' + FROM + '; known issues by default), `## Named by an open ' +
        'Issue` (known issues; each names its Issue), `## Contested or unverified`, `## ' +
        'Dropped by verification`, `## Ledger (not re-raised)`, `## Audit`. Write `(none)` ' +
        'under an empty heading. Do not write verdict lines; the workflow appends them.',
    '',
    'Blocking (JSON):',
    JSON.stringify(findings.map(for_render), null, 1),
    '',
    'Predating (JSON):',
    JSON.stringify(predating.map(for_render), null, 1),
    '',
    'Named by an open Issue (JSON):',
    JSON.stringify(known.map(for_render), null, 1),
    '',
    'Contested or unverified (JSON):',
    JSON.stringify(undecided.map(for_render), null, 1),
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
        'below, each linking its Issue, or `None` when there are none; the release PR adds ' +
        'the defects the maintainer decides to ship.',
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
    () => run(NOTES_PROMPT, {
        agentType: INVESTIGATOR, label: 'notes', phase: 'Synthesize', schema: NOTES_SCHEMA,
    }),
])

if (!synthesized) {
    failed_other.push('synthesize')
    notes_lines.push('The synthesizer returned no result; the report body is a placeholder.')
}
if (!drafted) {
    failed_other.push('notes')
    notes_lines.push('The notes agent returned no result; no release-notes draft was produced.')
}

const body = synthesized
    ? synthesized.report
    : '# Release review: ' + TAG + '\n\nSynthesis agent returned no result; the raw findings ' +
        'are in the `findings`, `predating`, `recorded`, `undecided`, `ledgered`, `dropped`, ' +
        'and `audit` fields.\n'

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
    notes: drafted ? drafted.notes : null,
    findings: findings.map(plain),
    predating: predating.map(plain),
    recorded: recorded.map(plain),
    undecided: undecided.map(plain),
    ledgered: ledgered.map(plain),
    dropped: dropped.map(plain),
    audit,
    known_issues,
    plan,
    stats: { ...stats },
}
