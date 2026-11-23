// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// .claude/workflows/threat-audit.js

// Sharded adversarial audit of one trust boundary of docs/threat-model.md.
//
// docs/conventions.md § Threat audit says when it runs and where its findings
// go. The audit reviews the code one section of the threat model names
// against that section's attacker: not a diff, but the files as the head
// holds them. Its reviewers report defects only (docs/conventions.md
// § Findings).
//
// Scope reads the section from `cargo xtask threat-scope` (xtask/README.md),
// never from an agent's own reading of the document: one agent returns the
// command's summary and one each of its pages of open Issues, cut from the
// list the summary saved (the report states when it was read), and the script
// recomputes the digest each carries, so the attacker, the assets, the
// assumptions and every claim reach the reviewers byte for byte as the
// document states them; the script frames them and never rewrites them. The
// scope is the files the section's Mitigations and Fuzz targets items name,
// in the command's shards. A section whose scope is incomplete (a mitigation
// naming no file, a reference resolving to nothing) is refused by the command
// unless the call passes `allow_incomplete`.
//
// Review runs, in parallel, one `pr-reviewer` per shard, with the section's
// attacker model as its lens and the shard's items as the claims to break,
// and one document lens that reads the section against the code it cites.
// Verify puts each defect that neither an open Issue nor a gap of the section
// names to two independent refuters as soon as its reviewer completes: the
// reality refuter judges whether the defect exists as stated, the reach
// refuter whether it is a defect at all and whether the section's attacker,
// under its assumptions, can reach it. A defect both refute is dropped; one
// refuted once is contested. A confirmed defect the attacker cannot reach is
// still a defect and is reported, apart, and so is one whose reach refuter
// returned no result, since no one judged its reach.
//
// The script renders the report and the draft items in the form of
// docs/conventions.md § Recording findings itself; no agent renders, so no
// finding is dropped or softened. It has no file access: it returns the report
// with the directory to save it to, and the session that ran it saves it and
// records the findings. It files no Issue.
//
// args: { mode: 'scope' | 'full', section: string, tree?: string,
//         max_agents?: number, allow_incomplete?: boolean }
//   section      the section's `##` heading, as `Disk Images`.
//   mode 'scope' stops after Scope and returns the plan, its agent count
//                before verification, and sample prompts (the scope's agents
//                only). docs/conventions.md § Threat audit has the count
//                approved before a 'full' run.
//   tree         the absolute path of the working tree to audit instead of the
//                session's: it lets a branch that changes this script or the
//                command run before it merges. The tree must be clean.
//   max_agents   the agent ceiling (default 60). A plan over it stops before
//                it reviews; a run that reaches it while verifying leaves the
//                rest unverified and is incomplete.
//
// The agent types resolve from the definitions the session loaded at its
// start; every prompt below is complete without them. A change to this script
// alone needs no new session: the call names it by `scriptPath`.

export const meta = {
    name: 'threat-audit',
    description: 'Sharded audit of one docs/threat-model.md section against its attacker',
    whenToUse:
        'When an Issue or the maintainer calls for it, per docs/conventions.md § Threat audit',
    phases: [
        { title: 'Scope', detail: 'read the section, its files and shards, and the open Issues' },
        {
            title: 'Review',
            detail: 'one reviewer per shard with the section as lens; the document lens',
        },
        { title: 'Verify', detail: 'two independent refuters per defect not already named' },
        { title: 'Synthesize', detail: 'report and draft items, rendered by the script' },
    ],
}

// ─── Arguments ───

const MODES = ['full', 'scope']
const text_arg = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null)
const MODE = args && MODES.includes(args.mode) ? args.mode : null
const SECTION = args ? text_arg(args.section) : null
const TREE = args ? text_arg(args.tree) : null
const ALLOW_INCOMPLETE = !!(args && args.allow_incomplete === true)
const DEFAULT_MAX_AGENTS = 60
const MAX_AGENTS =
    args && Number.isInteger(args.max_agents) && args.max_agents > 0
        ? args.max_agents
        : DEFAULT_MAX_AGENTS

if (MODE === null) return { error: "args.mode must be 'full' or 'scope'" }
// The name goes into a shell command between single quotes: allow only what a
// section heading of the document uses.
if (SECTION === null || !/^[A-Za-z0-9][A-Za-z0-9 -]*$/.test(SECTION)) {
    return {
        error: 'args.section must name a section of docs/threat-model.md (letters, digits, ' +
            'spaces, hyphens)',
    }
}
if (TREE !== null && !/^\/[^'\s]*$/.test(TREE)) {
    return { error: 'args.tree is an absolute path without spaces or quotes' }
}

// ─── Tunables ───

const DEDUP_LINE_SLACK = 3 // lines apart at which two findings in one file are one
const VERIFY_LENSES = ['reality', 'reach']
const PAGE_ENTRIES = 200
const INVESTIGATOR = 'release-verifier'
const REVIEWER = 'pr-reviewer'

// ─── Schemas ───

const PATH_DESCRIPTION =
    'Repository-relative path, exactly as `git ls-files` prints it: no leading `./`, ' +
    'no absolute prefix.'
const COUNT = { type: 'integer' }
const DIGEST = { type: 'string', description: 'The `digest` field exactly as printed.' }
const STRINGS = { type: 'array', items: { type: 'string' } }

const SUMMARY_SCHEMA = {
    type: 'object',
    required: [
        'head', 'repo_root', 'tree_at_head', 'document', 'section', 'slug',
        'system_assumptions', 'blocks', 'documents', 'unanchored', 'unresolved', 'complete',
        'shards', 'page_entries', 'open_issue_count', 'open_issue_pages',
        'open_issues_digest', 'issues_as_of', 'digest',
    ],
    properties: {
        head: { type: 'string' },
        repo_root: { type: 'string' },
        tree_at_head: { type: 'boolean' },
        document: { type: 'string' },
        section: { type: 'string' },
        slug: { type: 'string' },
        system_assumptions: { type: 'string' },
        blocks: {
            type: 'array',
            items: {
                type: 'object',
                required: ['label', 'text', 'items'],
                properties: {
                    label: { type: 'string' },
                    text: { type: 'string' },
                    items: {
                        type: 'array',
                        items: {
                            type: 'object',
                            required: ['text', 'files', 'unresolved', 'unlocated'],
                            properties: {
                                text: { type: 'string' },
                                files: STRINGS,
                                unresolved: STRINGS,
                                unlocated: STRINGS,
                            },
                        },
                    },
                },
            },
        },
        documents: STRINGS,
        unanchored: STRINGS,
        unresolved: STRINGS,
        complete: { type: 'boolean' },
        shards: {
            type: 'array',
            items: {
                type: 'object',
                required: ['lines', 'files', 'items'],
                properties: {
                    lines: COUNT,
                    files: {
                        type: 'array',
                        items: {
                            type: 'object',
                            required: ['path', 'lines'],
                            properties: { path: { type: 'string' }, lines: COUNT },
                        },
                    },
                    items: STRINGS,
                },
            },
        },
        page_entries: COUNT,
        open_issue_count: COUNT,
        open_issue_pages: COUNT,
        open_issues_digest: DIGEST,
        issues_as_of: { type: 'string' },
        digest: DIGEST,
    },
}

const PAGE_SCHEMA = {
    type: 'object',
    required: ['list', 'head', 'page', 'pages', 'page_entries', 'items', 'digest'],
    properties: {
        list: { enum: ['issues'] },
        head: { type: 'string' },
        page: COUNT,
        pages: COUNT,
        page_entries: COUNT,
        items: {
            type: 'array',
            description: 'Every item, in the printed order.',
            items: {
                type: 'object',
                required: ['number', 'title'],
                properties: { number: COUNT, title: { type: 'string' } },
            },
        },
        digest: DIGEST,
    },
}

const FINDING_SCHEMA = {
    type: 'object',
    required: [
        'kind', 'file', 'line', 'issue', 'gap', 'authority', 'claim', 'evidence', 'reach', 'fix',
    ],
    properties: {
        kind: {
            enum: ['code', 'document'],
            description:
                '`document` for a statement of the threat-model section the code contradicts ' +
                '(file and line then point into docs/threat-model.md); `code` otherwise.',
        },
        file: { type: 'string', description: PATH_DESCRIPTION },
        line: { type: 'integer', description: '1-based line at the head the defect anchors to.' },
        issue: {
            type: 'integer',
            description:
                'The open Issue that already names this defect, when one does (0 otherwise): its ' +
                'body states it, it is an item of a rolling Issue, or an Issue comment lists it.',
        },
        gap: {
            type: 'integer',
            description:
                'The number of the gap of the section that already states this defect (0 ' +
                'otherwise). A defect worse than the gap states is not named by it: 0.',
        },
        authority: {
            type: 'string',
            description: 'The contract, document section, or behaviour the location breaks.',
        },
        claim: { type: 'string' },
        evidence: { type: 'string', description: 'Cites file:line.' },
        reach: {
            type: 'string',
            description:
                'How the section\'s attacker reaches the defect: the input it controls and the ' +
                'path to the location; or why it cannot.',
        },
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
    required: ['refuted', 'reachable', 'confidence', 'evidence'],
    properties: {
        refuted: { type: 'boolean' },
        reachable: {
            type: 'boolean',
            description:
                'The section\'s attacker, under its assumptions, can reach the defect. The ' +
                'reality refuter returns true.',
        },
        confidence: { enum: ['high', 'medium', 'low'] },
        evidence: { type: 'string' },
    },
}

// ─── Helpers ───

let agent_calls = 0
const failed_review = [] // reviewers that returned nothing: part of the scope unreviewed
const failed_other = [] // refuter failures

function run(prompt, opts) {
    agent_calls += 1
    return agent(prompt, opts)
}

const bullets = (items, render) => (items.length ? items.map(render).join('\n') : '- (none)')
const short = (sha) => sha.slice(0, 12)

// ─── Phase: Scope ───

phase('Scope')

// The digest `cargo xtask threat-scope` prints, the one `cargo xtask
// release-scope` prints: FNV-1a 64 over a sequence of fields, each its UTF-8
// bytes and then a NUL byte, as 16 hex digits. The self-test pins the value the
// command's test `the_digest_of_the_shared_vector_is_pinned` pins.
const FNV_OFFSET = BigInt('0xcbf29ce484222325')
const FNV_PRIME = BigInt('0x100000001b3')
const MASK_64 = BigInt('0xffffffffffffffff')

function utf8(s) {
    const out = []
    for (const ch of s) {
        const c = ch.codePointAt(0)
        if (c < 0x80) out.push(c)
        else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63))
        else if (c < 0x10000) {
            out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63))
        } else {
            out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63),
                0x80 | (c & 63))
        }
    }
    return out
}

function digest(fields) {
    let h = FNV_OFFSET
    for (const field of fields) {
        for (const b of [...utf8(String(field)), 0]) h = ((h ^ BigInt(b)) * FNV_PRIME) & MASK_64
    }
    return h.toString(16).padStart(16, '0')
}

if (digest(['seraph', '', 'é→1']) !== 'cd2f6e72302ab053') {
    return { error: 'the script\'s digest does not match the one cargo xtask threat-scope prints' }
}

// The fields of the summary and of a page, in the command's order
// (xtask/README.md § `cargo xtask threat-scope`).
const list_fields = (l) => [l.length, ...l]
const summary_digest = (s) =>
    digest([
        'threat-summary', s.head, s.repo_root, s.tree_at_head, s.document, s.section, s.slug,
        s.system_assumptions, s.blocks.length,
        ...s.blocks.flatMap((b) => [
            b.label, b.text, b.items.length,
            ...b.items.flatMap((i) => [
                i.text, ...list_fields(i.files), ...list_fields(i.unresolved),
                ...list_fields(i.unlocated),
            ]),
        ]),
        ...list_fields(s.documents), ...list_fields(s.unanchored), ...list_fields(s.unresolved),
        s.complete, s.shards.length,
        ...s.shards.flatMap((sh) => [
            sh.lines, sh.files.length, ...sh.files.flatMap((f) => [f.path, f.lines]),
            ...list_fields(sh.items),
        ]),
        s.page_entries, s.open_issue_count, s.open_issue_pages, s.open_issues_digest,
        s.issues_as_of,
    ])
const page_digest = (p) =>
    digest([
        'threat-issues', p.head, p.page, p.pages, p.page_entries,
        ...p.items.flatMap((i) => [i.number, i.title]),
    ])
const issues_digest = (items) => digest(['issues', ...items.flatMap((i) => [i.number, i.title])])

const quoted_section = "'" + SECTION + "'"
const SCOPE_COMMAND =
    'cargo xtask threat-scope --section ' + quoted_section + ' --page-entries ' + PAGE_ENTRIES +
    (ALLOW_INCOMPLETE ? ' --allow-incomplete' : '')

const transport_prompt = (command, what) => [
    'Scope a threat audit of docs/threat-model.md § ' + SECTION + ': ' + what + '.',
    '',
    'Run `' + (TREE ? 'cd ' + TREE + ' && ' : '') + command + '` at the working tree ' +
        'root. Its standard output is one JSON object (cargo\'s progress goes to standard ' +
        'error). Return that object as the structured output: every field exactly as ' +
        'printed, every list complete and in the printed order, every string unchanged, ' +
        'line breaks included. Run no other command, and do not derive, correct, or abridge ' +
        'a value: the workflow checks the object against the digest it carries. When the ' +
        'command fails, return its error message as `head` and leave every other field ' +
        'empty, false, or zero.',
    '',
    'Structured output only.',
].join('\n')

// One agent returns one object; an object that does not match its digest is
// asked for again once, and then the scope fails. A failed command's message
// arrives as `head` and is logged and returned.
const SHA = /^[0-9a-f]{40}$/
let scope_failure = null
async function transported(prompt, label, schema, intact) {
    for (const attempt of [1, 2]) {
        const out = await run(prompt, {
            agentType: INVESTIGATOR, label: attempt === 1 ? label : label + ':retry',
            phase: 'Scope', schema,
        }).catch(() => null)
        if (out && intact(out)) return out
        const why = !out
            ? 'no result'
            : SHA.test(String(out.head))
                ? 'the object does not match its digest, or is not the one asked for'
                : 'the command failed: ' + String(out.head).slice(0, 600)
        if (out && !SHA.test(String(out.head))) scope_failure = why
        log(label + ': ' + why + (attempt === 1 ? '; asking again' : ''))
    }
    return null
}

const scope = await transported(
    transport_prompt(SCOPE_COMMAND, 'the summary of the section at the checked-out head'),
    'scope', SUMMARY_SCHEMA, (s) => s.digest === summary_digest(s),
)
if (!scope) {
    return {
        error: 'the scope summary did not arrive intact; nothing was reviewed' +
            (scope_failure ? ' (' + scope_failure + ')' : ''),
    }
}
if (TREE && scope.repo_root.replace(/\/+$/, '') !== TREE.replace(/\/+$/, '')) {
    return { error: 'the scope was read in ' + scope.repo_root + ', not in ' + TREE }
}
if (scope.page_entries !== PAGE_ENTRIES) {
    return { error: 'the scope summary was cut at ' + scope.page_entries + ' entries a page' }
}
if (!scope.tree_at_head) {
    return {
        error: 'The working tree ' + scope.repo_root + ' is not clean, or not at ' + scope.head +
            '.',
    }
}
if (!scope.complete && !ALLOW_INCOMPLETE) {
    return { error: 'the section\'s scope is incomplete and allow_incomplete was not given' }
}
if (scope.shards.length === 0) {
    return { error: 'section ' + SECTION + ' names no file to audit' }
}

const page_jobs = Array.from({ length: scope.open_issue_pages }, (_, i) => i + 1)
const pages = await parallel(page_jobs.map((page) => () => transported(
    transport_prompt(
        SCOPE_COMMAND + ' --head ' + scope.head + ' --page issues:' + page + ' --issues ' +
            scope.open_issues_digest,
        'page ' + page + ' of ' + scope.open_issue_pages + ' of its open Issues',
    ),
    'scope:issues#' + page, PAGE_SCHEMA,
    (p) => p.digest === page_digest(p) && p.page === page &&
        p.pages === scope.open_issue_pages && p.head === scope.head &&
        p.page_entries === PAGE_ENTRIES,
)))
if (pages.some((p) => !p)) {
    return { error: 'the pages of open Issues did not arrive intact; nothing was reviewed' }
}
const open_issues = pages.sort((a, b) => a.page - b.page).flatMap((p) => p.items)
if (
    open_issues.length !== scope.open_issue_count ||
    issues_digest(open_issues) !== scope.open_issues_digest
) {
    return {
        error: 'the pages returned ' + open_issues.length + ' open Issues of the ' +
            scope.open_issue_count + ' the summary saved, or an Issue differs: the pages are ' +
            'cut from that saved list, so the transport altered one',
    }
}
const open_issue_numbers = new Set(open_issues.map((i) => i.number))
const scope_agents = agent_calls

const block = (label) => scope.blocks.find((b) => b.label === label)
const items_by_id = new Map()
for (const b of scope.blocks) {
    b.items.forEach((it, i) => items_by_id.set(b.label + '#' + (i + 1), it))
}
const gaps = block('Gaps').items

const root_prefix = scope.repo_root.replace(/\/+$/, '') + '/'
const normalize = (p) => {
    let s = String(p).trim()
    if (s.startsWith(root_prefix)) s = s.slice(root_prefix.length)
    while (s.startsWith('./')) s = s.slice(2)
    return s
}

// ─── Prompts ───

const TARGET = 'docs/threat-model.md § ' + scope.section

const HEAD_LINE =
    'Threat audit of ' + TARGET + ' at ' + scope.head + '. The working tree ' + scope.repo_root +
    ' is checked out clean at that head; read every file there. This is not a PR review: ' +
    'there is no diff, no review surface, no PR body, and no ledger. You review the files as ' +
    'the head holds them, adversarially, as the attacker below. Report defects only ' +
    '(docs/conventions.md § Findings): wrong or unsafe behaviour, a broken contract between ' +
    'components, or a document statement that would make its reader write wrong code. Report ' +
    'nothing else.'

// The lens: the section's own blocks, inserted as the command printed them.
// The labels in bold are the document's own.
const LENS = [
    'The section\'s attacker model, verbatim from the document:',
    '',
    '**Attacker.** ' + block('Attacker').text,
    '',
    '**Assets.** ' + block('Assets').text,
    '',
    '**Assumptions.** ' + block('Assumptions').text,
    '',
    'The document\'s system-wide assumptions, verbatim:',
    '',
    scope.system_assumptions,
].join('\n')

const GAPS_BLOCK = [
    'The section\'s gaps, verbatim, numbered in order. A defect a gap already states is known: ' +
        'report it with `gap` set to its number, and the workflow lists it without verifying ' +
        'it. A defect the code makes worse than its gap states is not known: `gap` 0.',
    '',
    ...gaps.map((g, i) => '[gap ' + (i + 1) + ']\n' + g.text),
].join('\n')

const ISSUES_BLOCK = [
    'Open Issues. Set `issue` on a defect one of them already names: its body states it, it ' +
        'is an item of a rolling Issue (title `<scope>: defects found by review`), or a ' +
        'comment on the Issue lists it. Read the body and comments of any Issue whose title ' +
        'matches the area (`gh issue view <N> --comments`); 0 otherwise.',
    bullets(open_issues, (i) => '- #' + i.number + ' ' + i.title),
].join('\n')

const AUTHORITIES =
    'Authorities: the documents the section links (' +
    (scope.documents.length ? scope.documents.join(', ') : 'none') + '), the README and ' +
    '`docs/*.md` of each component whose files you read, and docs/coding-standards.md.'

const FINDING_RULES = [
    'For each defect, `reach` states how the attacker reaches it: the input it controls and ' +
        'the path from that input to the location, or why it cannot. Report a defect the ' +
        'attacker cannot reach too: it is still a defect, and the workflow lists it apart.',
    'Fill the structured schema: one entry per defect, `file` repository-relative. ' +
        'Structured output only.',
].join('\n')

function shard_prompt(shard, index) {
    const claims = shard.items.map((id) => '[' + id + ']\n' + items_by_id.get(id).text)
    return [
        HEAD_LINE,
        '',
        LENS,
        '',
        'Your shard (' + index + ' of ' + scope.shards.length + '): read each file below whole ' +
            'at the head, as the attacker. The section claims the mitigations and coverage ' +
            'below of these files, verbatim. Try to break each claim: find an input the ' +
            'attacker controls that the code accepts against what the claim states, or that ' +
            'reaches an asset (out-of-bounds access, an arithmetic overflow, an unbounded loop ' +
            'or allocation, a check made on one copy and a use of another, a value trusted ' +
            'across a boundary, a panic that takes the service down). Then report every other ' +
            'defect in the files. Read callers and dependencies wherever the path from the ' +
            'attacker\'s input runs; report on another file only where that read finds a ' +
            'defect on the path.',
        bullets(shard.files, (f) => '- ' + f.path + ' (' + f.lines + ' lines)'),
        '',
        ...claims,
        '',
        GAPS_BLOCK,
        '',
        AUTHORITIES,
        '',
        ISSUES_BLOCK,
        '',
        FINDING_RULES,
    ].join('\n')
}

const hint = (label, list) => label + ': ' + (list.length ? list.join('; ') : 'none') + '.'
const unlocated = scope.blocks.flatMap((b) =>
    b.items.flatMap((it, i) => it.unlocated.map((u) => b.label + '#' + (i + 1) + ' `' + u + '`')))

const DOCUMENT_PROMPT = [
    HEAD_LINE,
    '',
    'Lens: the section itself. Read ' + TARGET + ' whole at the head (' + scope.repo_root +
        '/docs/threat-model.md) and every file and document it cites. Report, with ' +
        '`kind` `document` and the line of docs/threat-model.md, each statement of the ' +
        'section the code at the head contradicts: a mitigation the code does not implement ' +
        'as stated, a function or check named where its file does not hold it, a coverage ' +
        'item that is not true, a gap stated wrongly, an attacker or asset the code shows ' +
        'differently. A Mitigations item that names no file implementing it is a defect of ' +
        'the document. Report a code defect you meet on the way with `kind` `code`.',
    'What the command already found: ' +
        hint('Mitigations items naming no file', scope.unanchored) + ' ' +
        hint('items with a reference that resolves to nothing', scope.unresolved) + ' ' +
        hint('identifiers found in none of their item\'s files (judge each: an identifier ' +
            'that lives elsewhere is no defect when the item names where)', unlocated),
    '',
    LENS,
    '',
    GAPS_BLOCK,
    '',
    AUTHORITIES,
    '',
    ISSUES_BLOCK,
    '',
    FINDING_RULES,
].join('\n')

const review_items = [
    ...scope.shards.map((s, i) => ({
        label: 'review:shard#' + (i + 1), prompt: () => shard_prompt(s, i + 1), shard: s,
    })),
    { label: 'lens:document', prompt: () => DOCUMENT_PROMPT, shard: null },
]

const review_agents = review_items.length
const fixed_agents = scope_agents + review_agents

const plan = {
    section: scope.section,
    head: scope.head,
    tree: scope.repo_root,
    complete: scope.complete,
    unanchored: scope.unanchored,
    unresolved: scope.unresolved,
    unlocated,
    shards: scope.shards.map((s, i) => ({
        label: 'review:shard#' + (i + 1), lines: s.lines,
        files: s.files.map((f) => f.path + ' (' + f.lines + ')'), items: s.items,
    })),
    lenses: ['document'],
    open_issues: open_issues.length,
    scope_agents,
    review_agents,
    agents_without_verify: fixed_agents,
    verify_agents_per_defect: VERIFY_LENSES.length,
    max_agents: MAX_AGENTS,
}

log(
    TARGET + ' ' + MODE + ': ' + scope.shards.length + ' shards, 1 lens; ' + fixed_agents +
        ' agents before verification, 2 per defect not already named, ceiling ' + MAX_AGENTS,
)

if (MODE === 'scope') {
    return {
        plan,
        sample_prompts: { shard: shard_prompt(scope.shards[0], 1), document: DOCUMENT_PROMPT },
    }
}

if (fixed_agents > MAX_AGENTS) {
    return {
        error: 'the run needs ' + fixed_agents + ' agents before verification, over the ' +
            'ceiling of ' + MAX_AGENTS + '; run with a higher max_agents once it is approved',
        plan,
    }
}

function verify_prompt(f, lens) {
    const finding = [
        'Defect under test (threat audit of ' + TARGET + ', head ' + scope.head + '):',
        '- kind: ' + f.kind,
        '- location: ' + f.file + ':' + f.line,
        '- claim: ' + f.claim,
        '- cited authority: ' + f.authority,
        '- evidence: ' + f.evidence,
        '- reach: ' + f.reach,
        '- proposed fix: ' + f.fix,
    ].join('\n')
    const tree =
        'The working tree ' + scope.repo_root + ' is checked out clean at the head; read every ' +
        'file there. A defect may be in code or in the document; an absence (a missing check ' +
        'or statement) is exhibited by the place where it should be.'
    if (lens === 'reality') {
        return [
            'You are an independent skeptic. Try to refute this audit finding on the facts. ' +
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
                'reachable=true: that judgement is the reach refuter\'s. Structured output only.',
        ].join('\n')
    }
    return [
        'You are an independent skeptic. Try to refute this audit finding on whether it is a ' +
            'defect, and judge whether the section\'s attacker can reach it. ' + tree,
        '',
        finding,
        '',
        LENS,
        '',
        'Read the cited authority and docs/conventions.md § Findings. refuted=true only with ' +
            'quoted evidence that what the finding describes is not a defect (wrong or unsafe ' +
            'behaviour, a broken contract, or a document statement that would make its reader ' +
            'write wrong code), or that the authority does not say what the finding claims or ' +
            'is not binding here. refuted=false otherwise, and also when you can neither ' +
            'confirm nor refute it; say so, with confidence low. Whether the attacker can reach ' +
            'it does not decide `refuted`: a defect it cannot reach is still a defect. Set ' +
            'reachable=true only when you can trace a path from an input the attacker above ' +
            'controls, under the assumptions above, to the location, citing each step\'s ' +
            'file:line in the evidence; false otherwise. Structured output only.',
    ].join('\n')
}

// ─── Phase: Review, with Verify per reviewer as it completes ───

phase('Review')

const seen = []
let ceiling_reached = false
let committed_agents = fixed_agents

// A later finding from another agent in the same file within DEDUP_LINE_SLACK
// lines is the same defect: the nearest such record keeps its claim and
// absorbs the later one, and before its verification starts a later
// reporter's Issue or gap. One agent's own adjacent findings stay distinct.
const nearest = (f, source) =>
    seen
        .filter((s) => !s.sources.includes(source) && s.file === f.file &&
            Math.abs(s.line - f.line) <= DEDUP_LINE_SLACK)
        .sort((a, b) => Math.abs(a.line - f.line) - Math.abs(b.line - f.line))[0]

function absorb(dup, f, source) {
    dup.sources.push(source)
    dup.evidence += '\n[also reported by ' + source + ': ' + f.claim + '] ' + f.evidence
    for (const key of ['issue', 'gap']) {
        if (!dup[key] && f[key]) {
            if (dup.verify_started) {
                dup.annotations.push(
                    source + ' named ' + key + ' ' + f[key] + ' after verification began')
            } else {
                dup[key] = f[key]
                dup.annotations.push(key + ' ' + f[key] + ' adopted from ' + source)
            }
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
        if (f.gap && !(f.gap >= 1 && f.gap <= gaps.length)) f.gap = 0
        const dup = nearest(f, source)
        if (dup) {
            absorb(dup, f, source)
            continue
        }
        const record = {
            ...f, sources: [source], status: 'pending', reachable: null, votes: [],
            verify_started: false, annotations: [], verification: null,
        }
        seen.push(record)
        fresh.push(record)
    }
    return fresh
}

// A defect an open Issue or a gap names is known and takes no refuters; one
// the ceiling leaves no room for stays unverified.
function verify_one(f) {
    if (f.issue || f.gap) {
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
            const label =
                'verify:' + lens + ':' + f.file + ':' + f.line + '#' + (seen.indexOf(f) + 1)
            return run(verify_prompt(f, lens), {
                agentType: INVESTIGATOR, label, phase: 'Verify', schema: VERDICT_SCHEMA,
            }).then((v) => (v ? { ...v, lens } : null), () => null).then((v) => {
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
        if (valid.length === 0) f.status = 'unverified'
        else if (refutes === valid.length && valid.length >= VERIFY_LENSES.length) {
            f.status = 'dropped'
        } else if (refutes > 0) f.status = 'contested'
        else f.status = 'confirmed'
        const reach = valid.find((v) => v.lens === 'reach')
        f.reachable = reach ? reach.reachable : null
        f.votes = valid
        return f
    })
    return f.verification
}

const reviewed = await pipeline(
    review_items,
    (item) =>
        run(item.prompt(), {
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
            item, findings: verified.filter(Boolean),
        }))
    },
)

review_items.forEach((item, i) => {
    if (!reviewed[i] && !failed_review.includes(item.label)) {
        failed_review.push(item.label)
        log(item.label + ': no result (dropped by the pipeline)')
    }
})

// ─── Phase: Synthesize (by the script) ───

phase('Synthesize')

const by_place = (a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line)
const all = [...seen].sort(by_place)
const confirmed = all.filter((f) => f.status === 'confirmed')
const document_defects = confirmed.filter((f) => f.kind === 'document')
const code_defects = confirmed.filter((f) => f.kind !== 'document')
const reachable = code_defects.filter((f) => f.reachable === true)
const unreachable = code_defects.filter((f) => f.reachable === false)
// A confirmed defect whose reach refuter returned nothing: no one judged its reach.
const reach_unjudged = code_defects.filter((f) => f.reachable === null)
const undecided = all.filter((f) => f.status === 'contested' || f.status === 'unverified')
const known = all.filter((f) => f.status === 'known')
const dropped = all.filter((f) => f.status === 'dropped')

const incomplete = failed_review.length > 0 || failed_other.length > 0 || ceiling_reached
const status = incomplete ? 'THREAT AUDIT INCOMPLETE' : 'THREAT AUDIT COMPLETE'

const RUN_NAME = 'the threat audit of ' + TARGET + ' at ' + short(scope.head)
const one_line = (s) => String(s).replace(/\s*\n\s*/g, ' ').trim()

// One draft per confirmed defect, in the form of docs/conventions.md
// § Recording findings: file, line, authority, fix, and the run and head that
// reported it, which stand in for the PR.
const draft = (f) =>
    '- [ ] `' + f.file + ':' + f.line + '`: ' + one_line(f.claim) + ' Authority: ' +
    one_line(f.authority) + '. Fix: ' + one_line(f.fix) + ' Reach: ' + one_line(f.reach) +
    ' (found by ' + RUN_NAME + ')'

function entry(f, with_votes) {
    const lines = [
        '### `' + f.file + ':' + f.line + '` [' + f.status + ', ' + f.kind + ']',
        '',
        one_line(f.claim),
        '',
        '- Authority: ' + one_line(f.authority),
        '- Evidence: ' + one_line(f.evidence),
        '- Reach: ' + one_line(f.reach),
        '- Fix: ' + one_line(f.fix),
        '- Reported by: ' + f.sources.join(', '),
    ]
    if (f.issue) lines.push('- Named by: #' + f.issue)
    if (f.gap) lines.push('- Named by: gap ' + f.gap + ' of the section')
    if (f.reachable !== null && f.kind !== 'document') {
        lines.push('- Reachable by the section\'s attacker: ' + (f.reachable ? 'yes' : 'no'))
    }
    for (const a of f.annotations) lines.push('- [' + a + ']')
    if (with_votes) {
        for (const v of f.votes) {
            lines.push('- Vote ' + v.lens + ': refuted=' + v.refuted + ', reachable=' +
                v.reachable +
                ', confidence ' + v.confidence + '. ' + one_line(v.evidence))
        }
    }
    return lines.join('\n')
}

const section_of = (title, list, with_votes) =>
    '## ' + title + '\n\n' +
    (list.length ? list.map((f) => entry(f, with_votes)).join('\n\n') : '(none)')

const notes = []
if (failed_review.length) {
    notes.push('Reviewers that returned no result: ' + failed_review.join(', ') + '.')
}
if (failed_other.length) {
    notes.push('Refuters that returned no result: ' + failed_other.join(', ') + '.')
}
if (ceiling_reached) notes.push('The run reached its ceiling of ' + MAX_AGENTS + ' agents.')
if (!scope.complete) {
    notes.push('The section\'s scope is incomplete (allow_incomplete): unanchored ' +
        JSON.stringify(scope.unanchored) + ', unresolved ' + JSON.stringify(scope.unresolved) + '.')
}

const drafts = [...reachable, ...reach_unjudged, ...unreachable, ...document_defects].map(draft)
const report = [
    '# Threat audit: ' + TARGET,
    '',
    'Head ' + scope.head + ', tree ' + scope.repo_root + '. Open Issues as of ' +
        scope.issues_as_of + ' (' + scope.open_issue_count + ', the list the scope saved). ' +
        scope.shards.length +
        ' shards and the ' +
        'document lens; ' + agent_calls + ' agents. ' + all.length + ' defects: ' +
        reachable.length + ' confirmed and reachable, ' + reach_unjudged.length +
        ' confirmed with reach not judged, ' + unreachable.length +
        ' confirmed and not reachable, ' + document_defects.length +
        ' confirmed in the section itself, ' +
        undecided.length + ' contested or unverified, ' + known.length +
        ' known, ' + dropped.length + ' dropped.',
    '',
    '## Shards',
    '',
    plan.shards.map((s) => '- ' + s.label + ' (' + s.lines + ' lines): ' + s.files.join(', ') +
        '; ' + s.items.join(', ')).join('\n'),
    '',
    section_of('Confirmed, reachable by the section\'s attacker', reachable, true),
    '',
    section_of('Confirmed, reach not judged (its reach refuter returned no result)', reach_unjudged,
        true),
    '',
    section_of('Confirmed, not reachable by the section\'s attacker', unreachable, true),
    '',
    section_of('Confirmed in the section itself', document_defects, true),
    '',
    section_of('Contested or unverified (docs/conventions.md § Contested findings)', undecided,
        true),
    '',
    section_of('Known (an open Issue or a gap of the section names it)', known, false),
    '',
    section_of('Dropped by verification', dropped, true),
    '',
    '## Draft items (docs/conventions.md § Recording findings)',
    '',
    drafts.length ? drafts.join('\n') : '(none)',
    '',
    status,
    ...(notes.length ? ['', ...notes] : []),
    '',
].join('\n')

const plain = (f) => {
    const { verification, verify_started, ...rest } = f
    return rest
}

return {
    status,
    report,
    save_dir: 'target/xtask/review/threat-' + scope.slug + '/',
    save_as: { report: short(scope.head) + '.md', json: short(scope.head) + '.json' },
    drafts,
    reachable: reachable.map(plain),
    reach_unjudged: reach_unjudged.map(plain),
    unreachable: unreachable.map(plain),
    document: document_defects.map(plain),
    undecided: undecided.map(plain),
    known: known.map(plain),
    dropped: dropped.map(plain),
    plan,
    stats: {
        mode: MODE, section: scope.section, head: scope.head, agents: agent_calls,
        failed: [...failed_review, ...failed_other], ceiling_reached,
    },
}
