// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// .claude/workflows/pr-review.js

// Sharded adversarial pre-merge review and audit of a pull request.
//
// Scope (one agent) materializes the diff and the surfaces it touches. Review
// runs one `pr-reviewer` per shard of changed files, whole-diff lenses, and the
// `pr-auditor`, all in parallel. Verify puts every Critical and Should finding,
// and every finding that names a MUST violation, to two independent refuters as
// soon as its shard completes. Synthesize renders one report. The script
// computes the reviewer verdict line itself and derives the audit verdict line
// from the auditor's per-section verdicts. `.claude/CLAUDE.md` § PR workflow
// operations says when the assistant runs this workflow and what it does with
// the result.
//
// args: { pr: number, mode: 'full' | 'delta' | 'scope', since?: string }
//   mode 'full'  reviews every file in the PR diff.
//   mode 'delta' reviews the files whose content changed between `since` (the
//                head the previous run reviewed) and the head, verifies the
//                fixes claimed since then, and adds a whole-PR correctness-only
//                regression lens that also verifies claimed fixes for files
//                outside the delta. The whole-diff lenses run in both modes;
//                the cross-boundary lens runs whenever the PR diff, not only
//                the delta, touches a code file. `since` must resolve in this
//                clone; it need not be an ancestor of the head, so an amended
//                or rebased branch still works, at the cost of over-including
//                files a rebase brought in.
//   mode 'scope' stops after Scope and returns the shard plan and sample
//                prompts (one agent); with `since` it scopes as delta would.

export const meta = {
    name: 'pr-review',
    description: 'Sharded adversarial pre-merge review and audit of a pull request',
    whenToUse: 'After CI is green on a PR, per .claude/CLAUDE.md § PR workflow operations',
    phases: [
        { title: 'Scope', detail: 'materialize the diff, shard the files, list changed items' },
        { title: 'Review', detail: 'one pr-reviewer per shard, whole-diff lenses, pr-auditor' },
        {
            title: 'Verify',
            detail: 'two independent refuters per Critical, Should, or MUST-violation finding',
        },
        { title: 'Synthesize', detail: 'one report; verdict lines computed by the script' },
    ],
}

// ─── Arguments ───

const MODES = ['full', 'delta', 'scope']
const PR = Number(args && args.pr)
const MODE = args && MODES.includes(args.mode) ? args.mode : null
const SINCE = args && typeof args.since === 'string' && args.since.trim() ? args.since.trim() : null
const DELTA = SINCE !== null

if (!Number.isInteger(PR) || PR <= 0) return { error: 'args.pr must be a pull request number' }
if (MODE === null) return { error: "args.mode must be 'full', 'delta', or 'scope'" }
if (MODE === 'delta' && !DELTA) {
    return { error: "args.since (the head the previous run reviewed) is required in 'delta' mode" }
}
if (MODE === 'full' && DELTA) {
    return { error: "args.since is only meaningful with mode 'delta' or 'scope'" }
}

// ─── Tunables ───

const MAX_SHARD_FILES = 6 // files per shard reviewer
const MAX_SHARD_LINES = 500 // changed lines per shard reviewer
const MAX_LENS_DOCS = 8 // design documents per design-docs lens agent
const DEDUP_LINE_SLACK = 3 // lines apart at which same file, class, bucket, and flag are one
const VERIFY_LENSES = ['reality', 'authority']
// The sections pr-auditor's Output lists; the audit must return each of them.
const AUDIT_SECTION_NAMES = [
    'PR-body checklist', 'per-issue closure', 'silent-deferral scan', 'test-plan honesty',
    'commit-message compliance', 'validation claim', 'PR-body claims',
]
// Read-only agent type for scope, verify, and synthesize. Its brief pins the
// model: these stages answer bounded questions, so they run on a cheaper tier
// than the shard reviewers and lenses, which inherit the session model.
const INVESTIGATOR = 'pr-verifier'

// ─── Schemas ───

const PATH_DESCRIPTION =
    'Repository-relative path, exactly as `git diff --name-only` prints it: no leading `./`, ' +
    'no absolute prefix.'

const SCOPE_SCHEMA = {
    type: 'object',
    required: [
        'head', 'base', 'repo_root', 'tree_at_head', 'since_reachable', 'pr_has_code', 'files',
        'changed_items', 'design_docs', 'claimed_fixes',
    ],
    properties: {
        head: { type: 'string', description: 'Full SHA of the PR head commit.' },
        base: {
            type: 'string',
            description: 'Full SHA of the merge base of the PR head and its base branch.',
        },
        repo_root: {
            type: 'string',
            description: 'Absolute path printed by `git rev-parse --show-toplevel`.',
        },
        tree_at_head: {
            type: 'boolean',
            description:
                '`git rev-parse HEAD` equals `head` and `git status --porcelain` is empty.',
        },
        since_reachable: {
            type: 'boolean',
            description:
                '`since` resolves to a commit in this clone; true when no `since` was given.',
        },
        pr_has_code: {
            type: 'boolean',
            description: 'The whole PR diff (not only the delta) changes a file of kind code.',
        },
        files: {
            type: 'array',
            items: {
                type: 'object',
                required: ['path', 'changed', 'kind'],
                properties: {
                    path: { type: 'string', description: PATH_DESCRIPTION },
                    changed: { type: 'integer', description: 'Added plus deleted lines.' },
                    kind: { enum: ['code', 'markdown', 'comment-only', 'rules', 'other'] },
                },
            },
        },
        changed_items: {
            type: 'array',
            items: {
                type: 'object',
                required: ['symbol', 'file', 'change'],
                properties: {
                    symbol: { type: 'string' },
                    file: { type: 'string', description: PATH_DESCRIPTION },
                    change: { enum: ['signature', 'contract', 'doc', 'new', 'removed'] },
                },
            },
        },
        design_docs: { type: 'array', items: { type: 'string', description: PATH_DESCRIPTION } },
        claimed_fixes: {
            type: 'array',
            items: {
                type: 'object',
                required: ['file', 'line', 'summary'],
                properties: {
                    file: { type: 'string', description: PATH_DESCRIPTION },
                    line: { type: 'integer', description: '0 when unknown.' },
                    summary: { type: 'string' },
                },
            },
        },
    },
}

const FINDING_SCHEMA = {
    type: 'object',
    required: [
        'file', 'line', 'bucket', 'class', 'introduced', 'must_violation',
        'authority', 'claim', 'evidence', 'fix',
    ],
    properties: {
        file: { type: 'string', description: PATH_DESCRIPTION },
        line: { type: 'integer', description: '1-based line the finding anchors to.' },
        bucket: { enum: ['critical', 'should', 'nit'] },
        class: {
            enum: [
                'correctness', 'safety', 'contract', 'standards', 'doc-drift', 'coverage', 'style',
            ],
        },
        introduced: { type: 'boolean', description: 'The diff introduced it (else pre-existing).' },
        must_violation: {
            type: 'boolean',
            description: 'It names a MUST violation of a binding standard.',
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
    required: ['refuted', 'confidence', 'evidence'],
    properties: {
        refuted: { type: 'boolean' },
        confidence: { enum: ['high', 'medium', 'low'] },
        evidence: { type: 'string' },
    },
}

const AUDIT_SCHEMA = {
    type: 'object',
    required: ['verdict', 'sections'],
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
    },
}

const REPORT_SCHEMA = {
    type: 'object',
    required: ['report'],
    properties: { report: { type: 'string' } },
}

// ─── Helpers ───

let agent_calls = 0
const failed_review = [] // shard and lens reviewers that returned nothing: unreviewed surface
const failed_other = [] // auditor and synthesizer failures: reported, not blocking by themselves

function run(prompt, opts) {
    agent_calls += 1
    return agent(prompt, opts)
}

const NESTED = ['core', 'services', 'runtime', 'abi', 'shared', 'programs']

function component_of(path) {
    const parts = path.split('/')
    return NESTED.includes(parts[0]) && parts.length > 2 ? parts[0] + '/' + parts[1] : parts[0]
}

// Group the changed files by component and cut each group into shards of at
// most MAX_SHARD_FILES files and about MAX_SHARD_LINES changed lines. A file is
// never split. Insertion order of the groups follows the scope agent's file
// order, so the same scope yields the same shards on resume.
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

const file_line = (f) => '- ' + f.path + ' (' + f.changed + ' changed lines, ' + f.kind + ')'
const item_line = (i) => '- `' + i.symbol + '` (' + i.change + ') in ' + i.file
const fix_line = (c) => '- ' + c.file + (c.line > 0 ? ':' + c.line : '') + ' — ' + c.summary
const doc_line = (d) => '- ' + d

// ─── Phase: Scope ───

phase('Scope')

const DELTA_RANGE = DELTA ? SINCE + ' <head>' : null

const SCOPE_PROMPT = [
    'Scope pull request #' + PR + ' for a sharded review.' +
        (DELTA ? ' Re-review: the previous run reviewed head ' + SINCE + '.' : ''),
    '',
    'Run `gh pr view ' + PR + ' --json headRefOid,baseRefName,body,files,commits`, ' +
        '`git merge-base <head> origin/<baseRefName>`, `git rev-parse --show-toplevel`, ' +
        '`git rev-parse HEAD`, `git status --porcelain`, and `gh pr diff ' + PR + '`.' +
        (DELTA
            ? ' Then run `git cat-file -e ' + SINCE + '^{commit}` (reachability), ' +
                '`git diff --numstat ' + DELTA_RANGE + '` (a tree diff between the two ' +
                'commits, valid whether or not ' + SINCE + ' is an ancestor of the head), and ' +
                '`git log --format=%B ' + SINCE + '..<head>`.'
            : ''),
    '',
    'Return, per the schema, with every path repository-relative exactly as git prints it:',
    '- head: the PR head SHA; base: the merge base of the head and the base branch.',
    '- repo_root: the absolute path of the working tree root.',
    '- tree_at_head: whether HEAD is the PR head and the tree is clean.',
    '- since_reachable: ' +
        (DELTA ? 'whether ' + SINCE + ' resolves to a commit.' : 'true (no `since` given).'),
    '- pr_has_code: whether the whole PR diff changes a file of kind code.',
    '- files: one entry per file in ' +
        (DELTA ? 'the tree diff ' + DELTA_RANGE : 'the PR diff') +
        ', with path; changed = added plus deleted lines; kind = code (Rust, assembly, ' +
        'linker scripts, build inputs, anything a build embeds), markdown, comment-only (only ' +
        'comment lines changed), rules (`.claude/` and `.github/`), or other.',
    '- changed_items: every public or crate-visible function, type, trait, constant, syscall, ' +
        'or wire-protocol element whose signature, contract, semantics, or documentation the ' +
        'PR diff changes, with the kind of change.',
    '- design_docs: the system-scope documents (the root `README.md` and `docs/`) and the ' +
        'component-scope documents (`<component>/README.md`, `<component>/docs/*.md`, and the ' +
        'parent directory\'s `README.md`) that govern the touched areas, found by walking the ' +
        'scope order the root README and the component READMEs define; include every document ' +
        'the diff itself edits.',
    '- claimed_fixes: ' +
        (DELTA
            ? 'every fix the commit messages in ' + SINCE + '..<head> and the PR body claim, as ' +
                'file, line (0 when unknown), and a one-line summary.'
            : 'an empty array.'),
    '',
    'Only scope; do not review. Structured output only.',
].join('\n')

const scope = await run(SCOPE_PROMPT, {
    agentType: INVESTIGATOR, label: 'scope', phase: 'Scope', schema: SCOPE_SCHEMA,
})
if (!scope) return { error: 'Scope agent returned no result; nothing was reviewed.' }
if (!scope.tree_at_head) {
    return { error: 'The working tree is not a clean checkout of the PR head ' + scope.head + '.' }
}
if (DELTA && !scope.since_reachable) {
    return { error: 'since ' + SINCE + ' does not resolve in this clone; run mode full.' }
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
for (const f of scope.files) f.path = normalize(f.path)
for (const i of scope.changed_items) i.file = normalize(i.file)
for (const c of scope.claimed_fixes) c.file = normalize(c.file)
scope.design_docs = scope.design_docs.map(normalize)

const shards = shards_of(scope.files)
const delta_paths = new Set(scope.files.map((f) => f.path))
const unmatched_fixes = scope.claimed_fixes.filter((c) => !delta_paths.has(c.file))

log(
    'PR #' + PR + ' ' + MODE + ': ' + scope.files.length + ' files, ' + shards.length +
        ' shards, ' + scope.changed_items.length + ' changed items, ' +
        scope.design_docs.length + ' design docs' +
        (DELTA
            ? ', ' + scope.claimed_fixes.length + ' claimed fixes (' + unmatched_fixes.length +
                ' outside the delta)'
            : ''),
)

// ─── Prompts ───

const HEAD_LINE =
    'Scope: pull request #' + PR + ', mode ' + MODE + '. Merge base ' + scope.base + ', head ' +
    scope.head + '. The working tree is checked out at the head; `gh pr diff ' + PR +
    '` is the PR diff' +
    (DELTA ? ' and `git diff ' + SINCE + ' ' + scope.head + '` is the delta' : '') + '.'

const DELTA_NOTE = DELTA
    ? 'This is a re-review: the previous run reviewed head ' + SINCE + ', and the commits and ' +
        'PR body since then claim fixes for its findings.'
    : null

const SHARD_HEADER = [
    HEAD_LINE,
    DELTA_NOTE,
    DELTA
        ? 'Apply the scope-block rule of your brief: the changed hunks are those of the delta diff.'
        : null,
].filter((line) => line !== null).join('\n')

const LENS_HEADER = [
    HEAD_LINE,
    DELTA_NOTE,
    DELTA ? 'Your lens covers the whole PR diff in both modes.' : null,
].filter((line) => line !== null).join('\n')

// System-scope documents (the top-level `docs/` tree and the root README)
// govern every shard; a component's own documents and its parent directory's
// README govern only that component's shards.
const docs_for = (component) => {
    const top = component.split('/')[0]
    return scope.design_docs.filter(
        (d) =>
            d.startsWith('docs/') || d === 'README.md' || d === top + '/README.md' ||
            component_of(d) === component,
    )
}

function shard_prompt(shard) {
    const paths = new Set(shard.files.map((f) => f.path))
    const items = scope.changed_items.filter((i) => paths.has(i.file))
    const fixes = scope.claimed_fixes.filter((c) => paths.has(c.file))
    return [
        SHARD_HEADER,
        '',
        'Your shard: ' + shard.component +
            (shard.count > 1 ? ' (' + shard.index + ' of ' + shard.count + ')' : '') +
            '. Read each file whole and apply your brief in full to it:',
        bullets(shard.files, file_line),
        '',
        'Changed items in these files. Map the blast radius of each per your brief; report a ' +
            'defect at a caller under the caller\'s own file:line:',
        bullets(items, item_line),
        '',
        'Design documents governing this shard (read the relevant ones in full):',
        bullets(docs_for(shard.component), doc_line),
        DELTA
            ? '\nClaimed fixes for your files, each to be verified against the code:\n' +
                bullets(fixes, fix_line)
            : null,
        '',
        'Other files in the diff belong to other reviewers: read them as callers or reverse ' +
            'dependencies of the items above, and report on their bodies only where such a read ' +
            'finds a defect.',
        'Fill the structured schema: one entry per finding. Structured output only.',
    ].filter((line) => line !== null).join('\n')
}

const lenses = [
    {
        name: 'callsites',
        body: () => [
            'Lens: call sites and reverse dependencies over the whole diff.',
            'For every changed item below, find every caller and consumer in the workspace, ' +
                'read its surrounding context, and verify it still upholds the new signature, ' +
                'contract, semantics, or documented behaviour. Report breakage and contract ' +
                'drift at the caller\'s file:line. Do not re-review the changed files\' own ' +
                'bodies; shard reviewers cover them.',
            '',
            'Changed items:',
            bullets(scope.changed_items, item_line),
        ],
    },
]

if (scope.pr_has_code) {
    lenses.push({
        name: 'boundary',
        body: () => [
            'Lens: cross-boundary surfaces over the whole diff.',
            'Examine the syscall and wire-protocol contracts (`abi/`, `shared/syscall`, ' +
                '`core/kernel/docs/syscalls.md`), the kernel-state disclosure rules ' +
                '(`core/kernel/docs/cross-boundary-disclosure.md`), and the capability ' +
                'contracts (`docs/capability-model.md`). Report kernel-pointer or kernel-state ' +
                'leaks, ABI or wire drift, missing capability checks, and userspace-triggerable ' +
                'kernel faults that the diff introduces or touches.',
        ],
    })
}

// One design-docs lens per MAX_LENS_DOCS documents, so no single agent has to
// hold every governing document at once.
const doc_lens_count = Math.ceil(scope.design_docs.length / MAX_LENS_DOCS)
for (let start = 0; start < scope.design_docs.length; start += MAX_LENS_DOCS) {
    const docs = scope.design_docs.slice(start, start + MAX_LENS_DOCS)
    const index = start / MAX_LENS_DOCS + 1
    lenses.push({
        name: 'design-docs' + (doc_lens_count > 1 ? '#' + index : ''),
        body: () => [
            'Lens: design documents against the code, over the whole diff' +
                (doc_lens_count > 1 ? ' (documents ' + index + ' of ' + doc_lens_count + ')' : '') +
                '.',
            'Read each document below in full. Report every place the diff silently ' +
                'contradicts the model a document defines, and every statement in a document ' +
                'that the diff made stale without updating it. Cite the document path and ' +
                'section.',
            '',
            'Documents:',
            bullets(docs, doc_line),
        ],
    })
}

if (DELTA) {
    lenses.push({
        name: 'regression',
        body: () => [
            'Lens: correctness only, over the whole pull request diff (' + scope.base + '..' +
                scope.head + ').',
            'The fixes since ' + SINCE + ' may have introduced a defect anywhere in the PR. ' +
                'Read the whole diff with surrounding code and report logic errors, ' +
                'unsoundness, memory or concurrency defects, resource leaks, and broken ' +
                'contracts. Do not report style, naming, or documentation.',
            '',
            'Claimed fixes for files outside the delta (no file changed for them since ' +
                SINCE + '). Verify each against the code and report every fix not actually ' +
                'made as a contract finding at the claimed location:',
            bullets(unmatched_fixes, fix_line),
        ],
    })
}

const lens_prompt = (lens) =>
    [LENS_HEADER, '', ...lens.body(), '', 'Fill the structured schema. Structured output only.']
        .join('\n')

if (MODE === 'scope') {
    return {
        scope,
        shards,
        lenses: lenses.map((l) => l.name),
        sample_prompts: {
            shard: shards.length ? shard_prompt(shards[0]) : null,
            lens: lenses.length ? lens_prompt(lenses[0]) : null,
        },
    }
}

const AUDIT_PROMPT = [
    'Scope: pull request #' + PR + '. Run your audit per your brief, every step.',
    'Fill the structured schema: the overall verdict, and one section for each of ' +
        AUDIT_SECTION_NAMES.join(', ') + ' with its PASS or FAIL and the items it found. ' +
        'Structured output only.',
].join('\n')

function verify_prompt(f, lens) {
    const finding = [
        'Finding under test (pull request #' + PR + ', head ' + scope.head + '):',
        '- location: ' + f.file + ':' + f.line,
        '- class: ' + f.class + '; severity: ' + f.bucket,
        '- claim: ' + f.claim,
        '- cited authority: ' + f.authority,
        '- evidence: ' + f.evidence,
        '- proposed fix: ' + f.fix,
    ].join('\n')
    const tree =
        'The working tree is checked out at the head; `gh pr diff ' + PR + '` is the diff. ' +
        'A defect may be in code or in a document; an absence (a missing check, test, or ' +
        'statement) is exhibited by the place where it should be.'
    if (lens === 'reality') {
        return [
            'You are an independent skeptic. Try to refute this review finding on the facts. ' +
                tree,
            '',
            finding,
            '',
            'Read the whole file at the location and every caller or reverse dependency the ' +
                'claim depends on. refuted=true only with evidence that the defect does not ' +
                'exist as stated, that the code or document already handles the case, or that ' +
                'the evidence does not support the claim. refuted=false when you can point to ' +
                'the place that exhibits the defect, and also when you can neither confirm nor ' +
                'refute it; say so, with confidence low. Evidence must cite file:line. ' +
                'Structured output only.',
        ].join('\n')
    }
    return [
        'You are an independent skeptic. Try to refute this review finding on its authority. ' +
            tree,
        '',
        finding,
        '',
        'Read the cited authority in full: the document section, the standard, or the ' +
            'contract at the cited location. refuted=true only with quoted evidence that the ' +
            'authority does not say what the finding claims, that it is not binding on this ' +
            'surface, or that the code or document does not violate it as claimed. ' +
            'refuted=false when the authority says what is claimed and the location violates ' +
            'it, when the authority is a correctness contract the location breaks, and also ' +
            'when you can neither confirm nor refute it; say so, with confidence low. ' +
            'Structured output only.',
    ].join('\n')
}

// ─── Phase: Review, with Verify per shard as it completes ───

phase('Review')

const seen = []

// A later finding from another agent on the same file, class, bucket, and
// MUST-violation flag within DEDUP_LINE_SLACK lines is the same finding (one
// agent's own adjacent findings are distinct by construction); its claim and evidence
// are kept on the first record. Anything that differs in bucket or in the
// MUST-violation flag is a distinct finding with its own verification, so a
// stronger finding is never absorbed into a weaker record.
function dedup(findings, source) {
    const fresh = []
    for (const f of findings) {
        f.file = normalize(f.file)
        const dup = seen.find(
            (s) =>
                s.source !== source &&
                s.file === f.file && s.class === f.class && s.bucket === f.bucket &&
                s.must_violation === f.must_violation &&
                Math.abs(s.line - f.line) <= DEDUP_LINE_SLACK,
        )
        if (dup) {
            dup.duplicates += 1
            dup.evidence += '\n[also reported by ' + source + ': ' + f.claim + '] ' + f.evidence
            continue
        }
        const record = { ...f, source, duplicates: 0, status: 'pending', votes: [] }
        seen.push(record)
        fresh.push(record)
    }
    return fresh
}

// Verification writes into the record itself, so annotations dedup makes on
// the `seen` record later still reach the report.
function verify_one(f) {
    if (f.bucket === 'nit' && !f.must_violation) {
        f.status = 'nit'
        return Promise.resolve(f)
    }
    return parallel(
        VERIFY_LENSES.map((lens) => () =>
            run(verify_prompt(f, lens), {
                agentType: INVESTIGATOR,
                label: 'verify:' + lens + ':' + f.file + ':' + f.line,
                phase: 'Verify',
                schema: VERDICT_SCHEMA,
            }).then((v) => (v ? { lens, ...v } : null)),
        ),
    ).then((votes) => {
        const valid = votes.filter(Boolean)
        const refutes = valid.filter((v) => v.refuted).length
        const all_refute = refutes === valid.length && valid.length >= VERIFY_LENSES.length
        if (valid.length === 0) f.status = 'unverified'
        else if (all_refute) f.status = 'dropped'
        else if (refutes > 0) f.status = 'contested'
        else f.status = 'confirmed'
        f.votes = valid
        return f
    })
}

const review_items = [
    ...shards.map((s) => ({ kind: 'shard', label: s.label, shard: s })),
    ...lenses.map((l) => ({ kind: 'lens', label: 'lens:' + l.name, lens: l })),
    { kind: 'audit', label: 'audit' },
]

const reviewed = await pipeline(
    review_items,
    (item) => {
        const launch = item.kind === 'audit'
            ? run(AUDIT_PROMPT, {
                agentType: 'pr-auditor', label: item.label, phase: 'Review', schema: AUDIT_SCHEMA,
            })
            : run(item.kind === 'shard' ? shard_prompt(item.shard) : lens_prompt(item.lens), {
                agentType: 'pr-reviewer', label: item.label, phase: 'Review',
                schema: FINDINGS_SCHEMA,
            })
        // The pipeline skips the remaining stages of an item whose stage
        // value is null, and agent() returns null for a dead or skipped
        // subagent, so a failure is wrapped rather than passed through.
        return launch.then((result) => ({ result }), () => ({ result: null }))
    },
    ({ result }, item) => {
        if (!result) {
            ;(item.kind === 'audit' ? failed_other : failed_review).push(item.label)
            log(item.label + ': no result (agent failed or was stopped)')
            return { item, findings: [], audit: null }
        }
        if (item.kind === 'audit') {
            log('audit: ' + result.verdict)
            return { item, findings: [], audit: result }
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
// agent: a reviewer (blocking) or the auditor (an audit failure). Reconcile
// by index so no failure can slip past the accounting.
review_items.forEach((item, i) => {
    const slot = reviewed[i]
    const list = item.kind === 'audit' ? failed_other : failed_review
    if (!slot && !list.includes(item.label)) {
        list.push(item.label)
        log(item.label + ': no result (dropped by the pipeline)')
    }
})

const results = reviewed.filter(Boolean)
const audit = results.map((r) => r.audit).find(Boolean) || null
const all = results.flatMap((r) => r.findings)
const dropped = all.filter((f) => f.status === 'dropped')
const findings = all.filter((f) => f.status !== 'dropped')
const count = (status) => findings.filter((f) => f.status === status).length

log(
    'Review done: ' + all.length + ' findings; ' + count('confirmed') + ' confirmed, ' +
        count('contested') + ' contested, ' + count('unverified') + ' unverified, ' +
        count('nit') + ' nits, ' + dropped.length + ' dropped' +
        (failed_review.length ? '; failed reviewers: ' + failed_review.join(', ') : ''),
)

// ─── Verdicts (computed here, not by an agent) ───

// A failed shard or lens reviewer means part of the diff was never reviewed;
// that is a blocking condition in itself. A failed auditor or synthesizer
// is reported through the audit verdict and the notes, not through the
// reviewer verdict.
const blocking =
    failed_review.length > 0 ||
    findings.some((f) => f.bucket === 'critical' || f.must_violation)
const verdict = blocking
    ? 'BLOCKING ISSUES'
    : findings.length > 0
        ? 'NON-BLOCKING ISSUES ONLY'
        : 'READY TO MERGE'

// The auditor's own contract: any FAIL section forces AUDIT FAIL, and an
// audit that skipped a named section is not a pass.
const section_present = (name) =>
    audit.sections.some((s) => s.name.toLowerCase().includes(name.toLowerCase()))
const missing_sections = audit ? AUDIT_SECTION_NAMES.filter((n) => !section_present(n)) : []
const audit_failed =
    !audit || missing_sections.length > 0 || audit.verdict === 'AUDIT FAIL' ||
    audit.sections.some((s) => s.verdict === 'FAIL')
const audit_verdict = audit_failed ? 'AUDIT FAIL' : 'AUDIT PASS'
const notes = []
if (!audit) notes.push('The auditor returned no result; treated as AUDIT FAIL.')
if (missing_sections.length) {
    notes.push(
        'The audit lacks the sections ' + missing_sections.join(', ') +
            '; treated as AUDIT FAIL.',
    )
}
if (failed_review.length) {
    notes.push(
        'Incomplete run: ' + failed_review.join(', ') + ' returned no result; treated as blocking.',
    )
}

// `failed` is read again after Synthesize, which can add to it.
const stats = {
    pr: PR,
    mode: MODE,
    since: SINCE,
    head: scope.head,
    base: scope.base,
    files: scope.files.length,
    shards: shards.length,
    lenses: lenses.map((l) => l.name),
    findings: findings.length,
    confirmed: count('confirmed'),
    contested: count('contested'),
    unverified: count('unverified'),
    nits: count('nit'),
    dropped: dropped.length,
    get failed() {
        return [...failed_review, ...failed_other]
    },
}

// ─── Phase: Synthesize ───

phase('Synthesize')

const SYNTH_PROMPT = [
    'Render the pre-merge review report for pull request #' + PR + ' (mode ' + MODE +
        ', head ' + scope.head + ') as Markdown.',
    '',
    'Rules: every finding below appears exactly once, under its bucket, with its status tag; ' +
        'do not drop, add, merge, re-rank, or soften a finding. You may order entries within ' +
        'a bucket by file and group entries that share one root cause under one lead entry ' +
        'that still lists every file:line, each site with its own status and MUST-violation ' +
        'tags. Each entry: `file:line` [status] claim, with ' +
        '`(MUST violation)` after the status when must_violation is true, since such an entry ' +
        'blocks the merge whatever its bucket. Authority: ' +
        'the cited authority. Rationale: one sentence from the evidence. Fix: the proposed ' +
        'fix. For contested and unverified entries add one line per verifier vote with its ' +
        'lens, refuted flag, confidence, and evidence. The dropped section lists each dropped ' +
        'finding in one line with the refuting evidence. The audit section lists each audit ' +
        'section with its verdict and items.',
    '',
    'Headings, in this order: `# Pre-merge review: PR #' + PR + '`, `## Critical (blocking)`, ' +
        '`## Should fix`, `## Nit`, `## Dropped by verification`, `## Audit`. Write `(none)` ' +
        'under an empty heading. Do not write verdict lines; the workflow appends them.',
    '',
    'Findings (JSON):',
    JSON.stringify(findings, null, 1),
    '',
    'Dropped (JSON):',
    JSON.stringify(dropped, null, 1),
    '',
    'Audit (JSON):',
    JSON.stringify(audit, null, 1),
    '',
    'Stats (JSON):',
    JSON.stringify(stats),
    '',
    'Structured output only.',
].join('\n')

const synthesized = await run(SYNTH_PROMPT, {
    agentType: INVESTIGATOR, label: 'synthesize', phase: 'Synthesize', schema: REPORT_SCHEMA,
}).catch(() => null)

if (!synthesized) {
    failed_other.push('synthesize')
    notes.push('The synthesizer returned no result; the report body is a placeholder.')
}

const body = synthesized
    ? synthesized.report
    : '# Pre-merge review: PR #' + PR + '\n\nSynthesis agent returned no result; ' +
        'the raw findings are in the `findings`, `dropped`, and `audit` fields.\n'

// The two verdict lines stand alone so they can be surfaced verbatim; notes
// follow on their own lines.
const report =
    body.replace(/\s+$/, '') + '\n\n' + verdict + '\n' + audit_verdict + '\n' +
    (notes.length ? '\n' + notes.join('\n') + '\n' : '')

stats.agents = agent_calls

return { verdict, audit_verdict, report, findings, dropped, audit, stats: { ...stats } }
