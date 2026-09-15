// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// .claude/workflows/pr-review.js

// Sharded adversarial pre-merge review and audit of a pull request.
//
// Scope (one agent) materializes the diff and the surfaces it touches. Review
// runs one `pr-reviewer` per shard of changed files, whole-diff lenses, and the
// `pr-auditor`, all in parallel. Verify puts every Critical and Should finding
// to two independent refuters as soon as its shard completes. Synthesize
// renders one report; the script computes both verdict lines itself.
// `.claude/CLAUDE.md` § PR workflow operations says when the assistant runs
// this workflow and what it does with the result.
//
// args: { pr: number, mode: 'full' | 'delta', since?: string, dryRun?: boolean }
//   mode 'full'  reviews every file in the PR diff.
//   mode 'delta' reviews the files changed since `since` (the head the previous
//                run reviewed), verifies the fixes claimed since then, and adds a
//                whole-PR correctness-only regression lens.
//   dryRun       stops after Scope and returns the shard plan (one agent).

export const meta = {
  name: 'pr-review',
  description: 'Sharded adversarial pre-merge review and audit of a pull request',
  whenToUse: 'After CI is green on a PR, per .claude/CLAUDE.md § PR workflow operations',
  phases: [
    { title: 'Scope', detail: 'materialize the diff, shard the files, list changed items' },
    { title: 'Review', detail: 'one pr-reviewer per shard, whole-diff lenses, pr-auditor' },
    { title: 'Verify', detail: 'two independent refuters per Critical or Should finding' },
    { title: 'Synthesize', detail: 'one report; verdict lines computed by the script' },
  ],
}

// ─── Arguments ───

const PR = Number(args && args.pr)
const MODE = args && (args.mode === 'full' || args.mode === 'delta') ? args.mode : null
const SINCE = args && typeof args.since === 'string' && args.since.trim() ? args.since.trim() : null
const DRY_RUN = Boolean(args && args.dryRun)

if (!Number.isInteger(PR) || PR <= 0) return { error: 'args.pr must be a pull request number' }
if (MODE === null) return { error: "args.mode must be 'full' or 'delta'" }
if (MODE === 'delta' && SINCE === null) {
  return { error: "args.since (the head the previous run reviewed) is required in 'delta' mode" }
}

// ─── Tunables ───

const MAX_SHARD_FILES = 6 // files per shard reviewer
const MAX_SHARD_LINES = 500 // changed lines per shard reviewer
const MAX_LENS_DOCS = 8 // design documents per design-docs lens agent
const DEDUP_LINE_SLACK = 3 // findings this close on the same file and class are one finding
const VERIFY_LENSES = ['reality', 'authority']

// ─── Schemas ───

const SCOPE_SCHEMA = {
  type: 'object',
  required: ['head', 'base', 'files', 'changedItems', 'designDocs', 'claimedFixes'],
  properties: {
    head: { type: 'string' },
    base: { type: 'string' },
    files: {
      type: 'array',
      items: {
        type: 'object',
        required: ['path', 'changed', 'kind'],
        properties: {
          path: { type: 'string' },
          changed: { type: 'integer' },
          kind: { enum: ['code', 'markdown', 'comment-only', 'rules', 'other'] },
        },
      },
    },
    changedItems: {
      type: 'array',
      items: {
        type: 'object',
        required: ['symbol', 'file', 'change'],
        properties: {
          symbol: { type: 'string' },
          file: { type: 'string' },
          change: { enum: ['signature', 'contract', 'doc', 'new', 'removed'] },
        },
      },
    },
    designDocs: { type: 'array', items: { type: 'string' } },
    claimedFixes: {
      type: 'array',
      items: {
        type: 'object',
        required: ['file', 'line', 'summary'],
        properties: {
          file: { type: 'string' },
          line: { type: 'integer' },
          summary: { type: 'string' },
        },
      },
    },
  },
}

const FINDING_SCHEMA = {
  type: 'object',
  required: [
    'file', 'line', 'bucket', 'class', 'introduced', 'mustViolation',
    'authority', 'claim', 'evidence', 'fix',
  ],
  properties: {
    file: { type: 'string' },
    line: { type: 'integer' },
    bucket: { enum: ['critical', 'should', 'nit'] },
    class: {
      enum: ['correctness', 'safety', 'contract', 'standards', 'doc-drift', 'coverage', 'style'],
    },
    introduced: { type: 'boolean' },
    mustViolation: { type: 'boolean' },
    authority: { type: 'string' },
    claim: { type: 'string' },
    evidence: { type: 'string' },
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

let agentCalls = 0
const failed = []

function run(prompt, opts) {
  agentCalls += 1
  return agent(prompt, opts)
}

function componentOf(path) {
  const parts = path.split('/')
  const nested = parts[0] === 'core' || parts[0] === 'services' || parts[0] === 'runtime'
  return nested && parts.length > 2 ? parts[0] + '/' + parts[1] : parts[0]
}

// Group the changed files by component and cut each group into shards of at
// most MAX_SHARD_FILES files and about MAX_SHARD_LINES changed lines. A file is
// never split. Insertion order of the groups follows the scope agent's file
// order, so the same scope yields the same shards on resume.
function shardsOf(files) {
  const groups = new Map()
  for (const f of files) {
    const c = componentOf(f.path)
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
  const perComponent = new Map()
  for (const s of shards) perComponent.set(s.component, (perComponent.get(s.component) || 0) + 1)
  const seenComponent = new Map()
  for (const s of shards) {
    const index = (seenComponent.get(s.component) || 0) + 1
    seenComponent.set(s.component, index)
    s.index = index
    s.count = perComponent.get(s.component)
    s.label = 'review:' + s.component + (s.count > 1 ? '#' + index : '')
  }
  return shards
}

const bullets = (items, render) => (items.length ? items.map(render).join('\n') : '- (none)')

const fileLine = (f) => '- ' + f.path + ' (' + f.changed + ' changed lines, ' + f.kind + ')'
const itemLine = (i) => '- `' + i.symbol + '` (' + i.change + ') in ' + i.file
const fixLine = (c) => '- ' + c.file + (c.line > 0 ? ':' + c.line : '') + ' — ' + c.summary
const docLine = (d) => '- ' + d

// ─── Phase: Scope ───

phase('Scope')

const SCOPE_PROMPT = [
  'Scope pull request #' + PR + ' for a sharded review. Mode: ' + MODE + '.' +
    (MODE === 'delta' ? ' Previous run reviewed head ' + SINCE + '.' : ''),
  '',
  'Run `gh pr view ' + PR + ' --json headRefOid,baseRefOid,body,files,commits` and',
  '`gh pr diff ' + PR + '`.' +
    (MODE === 'delta'
      ? ' Then run `git diff --numstat ' + SINCE + '..<head>` and ' +
        '`git log --format=%B ' + SINCE + '..<head>`.'
      : ''),
  '',
  'Return, per the schema:',
  '- head, base: the head and base commit SHAs.',
  '- files: one entry per file in the diff' +
    (MODE === 'delta' ? ' that changed since ' + SINCE : '') +
    ', with path; changed = added plus deleted lines; kind = code (Rust, assembly, linker ' +
    'scripts, build inputs, anything a build embeds), markdown, comment-only (only comment ' +
    'lines changed), rules (`.claude/` and `.github/`), or other.',
  '- changedItems: every public or crate-visible function, type, trait, constant, syscall, or ' +
    'wire-protocol element whose signature, contract, semantics, or documentation the diff ' +
    'changes, with the kind of change.',
  '- designDocs: the system-scope (`docs/`) and component-scope (`<component>/README.md`, ' +
    '`<component>/docs/*.md`) documents that govern the touched areas, found by walking the ' +
    'scope order the root README and the component READMEs define; include every document ' +
    'the diff itself edits.',
  '- claimedFixes: ' +
    (MODE === 'delta'
      ? 'every fix the commit messages since ' + SINCE + ' and the PR body claim, as file, ' +
        'line (0 when unknown), and a one-line summary.'
      : 'an empty array in full mode.'),
  '',
  'Only scope; do not review. Structured output only.',
].join('\n')

const scope = await run(SCOPE_PROMPT, { label: 'scope', phase: 'Scope', schema: SCOPE_SCHEMA })
if (!scope) return { error: 'Scope agent returned no result; nothing was reviewed.' }

const shards = shardsOf(scope.files)
log(
  'PR #' + PR + ' ' + MODE + ': ' + scope.files.length + ' files, ' + shards.length +
    ' shards, ' + scope.changedItems.length + ' changed items, ' + scope.designDocs.length +
    ' design docs' + (MODE === 'delta' ? ', ' + scope.claimedFixes.length + ' claimed fixes' : ''),
)

// ─── Prompts ───

const HEADER = [
  'Scope: pull request #' + PR + ', mode ' + MODE + '. Base ' + scope.base + ', head ' +
    scope.head + '.',
  'The working tree is checked out at the head; `gh pr diff ' + PR + '` is the diff.',
  MODE === 'delta'
    ? 'This is a re-review: the previous run reviewed head ' + SINCE + ' and its findings ' +
      'were fixed since. Apply your brief\'s step 2a.'
    : '',
].filter(Boolean).join('\n')

// System-scope documents govern every shard; component-scope documents only
// the shard of their component.
const docsFor = (component) =>
  scope.designDocs.filter((d) => d.startsWith('docs/') || componentOf(d) === component)

function shardPrompt(shard) {
  const paths = new Set(shard.files.map((f) => f.path))
  const items = scope.changedItems.filter((i) => paths.has(i.file))
  const fixes = scope.claimedFixes.filter((c) => paths.has(c.file))
  const docs = docsFor(shard.component)
  return [
    HEADER,
    '',
    'Your shard: ' + shard.component +
      (shard.count > 1 ? ' (' + shard.index + ' of ' + shard.count + ')' : '') +
      '. Read each file whole and apply your brief in full to it:',
    bullets(shard.files, fileLine),
    '',
    'Changed items in these files. Map the blast radius of each (your step 5); report a ' +
      'defect at a caller under the caller\'s own file:line:',
    bullets(items, itemLine),
    '',
    'Design documents governing this shard (read the relevant ones in full):',
    bullets(docs, docLine),
    MODE === 'delta'
      ? '\nClaimed fixes for your files, each to be verified against the code:\n' +
        bullets(fixes, fixLine)
      : null,
    '',
    'Other files in the diff belong to other reviewers: read them as callers or reverse ' +
      'dependencies of the items above, and report on their bodies only where such a read ' +
      'finds a defect.',
    'Fill the structured schema: one entry per finding. Structured output only.',
  ].filter((line) => line !== null).join('\n')
}

const LENSES = [
  {
    name: 'callsites',
    body: () => [
      'Lens: call sites and reverse dependencies over the whole diff.',
      'For every changed item below, find every caller and consumer in the workspace, read ' +
        'its surrounding context, and verify it still upholds the new signature, contract, ' +
        'semantics, or documented behaviour. Report breakage and contract drift at the ' +
        'caller\'s file:line. Do not re-review the changed files\' own bodies; shard ' +
        'reviewers cover them.',
      '',
      'Changed items:',
      bullets(scope.changedItems, itemLine),
    ],
  },
  {
    name: 'boundary',
    body: () => [
      'Lens: cross-boundary surfaces over the whole diff.',
      'Examine the syscall and wire-protocol contracts (`abi/`, `shared/syscall`, ' +
        '`core/kernel/docs/syscalls.md`), the kernel-state disclosure rules ' +
        '(`core/kernel/docs/cross-boundary-disclosure.md`), and the capability contracts ' +
        '(`docs/capability-model.md`). Report kernel-pointer or kernel-state leaks, ABI or ' +
        'wire drift, missing capability checks, and userspace-triggerable kernel faults ' +
        'that the diff introduces or touches.',
    ],
  },
]

// One design-docs lens per MAX_LENS_DOCS documents, so no single agent has to
// hold every governing document at once.
for (let start = 0; start < scope.designDocs.length; start += MAX_LENS_DOCS) {
  const docs = scope.designDocs.slice(start, start + MAX_LENS_DOCS)
  const index = start / MAX_LENS_DOCS + 1
  LENSES.push({
    name: 'design-docs#' + index,
    body: () => [
      'Lens: design documents against the code, over the whole diff (documents ' + index +
        ' of ' + Math.ceil(scope.designDocs.length / MAX_LENS_DOCS) + ').',
      'Read each document below in full. Report every place the diff silently contradicts ' +
        'the model a document defines, and every statement in a document that the diff ' +
        'made stale without updating it. Cite the document path and section.',
      '',
      'Documents:',
      bullets(docs, docLine),
    ],
  })
}

if (MODE === 'delta') {
  LENSES.push({
    name: 'regression',
    body: () => [
      'Lens: correctness only, over the whole pull request diff (' + scope.base + '..' +
        scope.head + ').',
      'The fixes since ' + SINCE + ' may have introduced a defect anywhere in the PR. Read ' +
        'the whole diff with surrounding code and report logic errors, unsoundness, ' +
        'memory or concurrency defects, resource leaks, and broken contracts. Do not ' +
        'report style, naming, or documentation.',
    ],
  })
}

const lensPrompt = (lens) =>
  [HEADER, '', ...lens.body(), '', 'Fill the structured schema. Structured output only.']
    .join('\n')

if (DRY_RUN) {
  return {
    scope,
    shards,
    lenses: LENSES.map((l) => l.name),
    samplePrompts: {
      shard: shards.length ? shardPrompt(shards[0]) : null,
      lens: LENSES.length ? lensPrompt(LENSES[0]) : null,
    },
  }
}

const AUDIT_PROMPT = [
  'Scope: pull request #' + PR + '. Run your audit per your brief, every step.',
  'Fill the structured schema: the overall verdict, and one section per audit step with ' +
    'its PASS or FAIL and the items it found. Structured output only.',
].join('\n')

function verifyPrompt(f, lens) {
  const finding = [
    'Finding under test (pull request #' + PR + ', head ' + scope.head + '):',
    '- location: ' + f.file + ':' + f.line,
    '- class: ' + f.class + '; severity: ' + f.bucket,
    '- claim: ' + f.claim,
    '- cited authority: ' + f.authority,
    '- evidence: ' + f.evidence,
    '- proposed fix: ' + f.fix,
  ].join('\n')
  if (lens === 'reality') {
    return [
      'You are an independent skeptic. Try to refute this review finding on the facts of ' +
        'the code. The working tree is checked out at the head; `gh pr diff ' + PR +
        '` is the diff.',
      '',
      finding,
      '',
      'Read the whole file at the location and every caller or reverse dependency the claim ' +
        'depends on. refuted=true when the defect does not exist as stated, the code already ' +
        'handles the case, or the evidence does not support the claim; also refuted=true when ' +
        'you cannot confirm the defect from the code. refuted=false only when you can point ' +
        'to the code that exhibits it. Evidence must cite file:line. Structured output only.',
    ].join('\n')
  }
  return [
    'You are an independent skeptic. Try to refute this review finding on its authority. ' +
      'The working tree is checked out at the head; `gh pr diff ' + PR + '` is the diff.',
    '',
    finding,
    '',
    'Read the cited authority in full: the document section, the standard, or the contract ' +
      'at the cited location. refuted=true only with quoted evidence that the authority does ' +
      'not say what the finding claims, that it is not binding on this surface, or that the ' +
      'code does not violate it as claimed. refuted=false when the authority says what is ' +
      'claimed and the code violates it, or when the authority is a correctness contract ' +
      'the code at the location breaks. Structured output only.',
  ].join('\n')
}

// ─── Phase: Review, with Verify per shard as it completes ───

phase('Review')

const seen = []

function dedup(findings, source) {
  const fresh = []
  for (const f of findings) {
    const dup = seen.find(
      (s) => s.file === f.file && s.class === f.class &&
        Math.abs(s.line - f.line) <= DEDUP_LINE_SLACK,
    )
    if (dup) {
      dup.duplicates += 1
      dup.evidence += '\n[also reported by ' + source + '] ' + f.evidence
      continue
    }
    const record = { ...f, source, duplicates: 0 }
    seen.push(record)
    fresh.push(record)
  }
  return fresh
}

function verifyOne(f) {
  if (f.bucket === 'nit') return Promise.resolve({ ...f, status: 'nit', votes: [] })
  return parallel(
    VERIFY_LENSES.map((lens) => () =>
      run(verifyPrompt(f, lens), {
        label: 'verify:' + lens + ':' + f.file + ':' + f.line,
        phase: 'Verify',
        schema: VERDICT_SCHEMA,
        effort: 'xhigh',
      }).then((v) => (v ? { lens, ...v } : null)),
    ),
  ).then((votes) => {
    const valid = votes.filter(Boolean)
    const refutes = valid.filter((v) => v.refuted).length
    let status
    if (valid.length === 0) status = 'unverified'
    else if (refutes === valid.length && valid.length >= VERIFY_LENSES.length) status = 'dropped'
    else if (refutes > 0) status = 'contested'
    else status = 'confirmed'
    return { ...f, status, votes: valid }
  })
}

const reviewItems = [
  ...shards.map((s) => ({ kind: 'shard', label: s.label, shard: s })),
  ...LENSES.map((l) => ({ kind: 'lens', label: 'lens:' + l.name, lens: l })),
  { kind: 'audit', label: 'audit' },
]

const reviewed = await pipeline(
  reviewItems,
  (item) => {
    if (item.kind === 'audit') {
      return run(AUDIT_PROMPT, {
        agentType: 'pr-auditor', label: item.label, phase: 'Review', schema: AUDIT_SCHEMA,
      })
    }
    const prompt = item.kind === 'shard' ? shardPrompt(item.shard) : lensPrompt(item.lens)
    return run(prompt, {
      agentType: 'pr-reviewer', label: item.label, phase: 'Review', schema: FINDINGS_SCHEMA,
    })
  },
  (result, item) => {
    if (!result) {
      failed.push(item.label)
      log(item.label + ': no result (agent failed or was stopped)')
      return { item, findings: [], audit: null }
    }
    if (item.kind === 'audit') {
      log('audit: ' + result.verdict)
      return { item, findings: [], audit: result }
    }
    const fresh = dedup(result.findings, item.label)
    log(item.label + ': ' + result.findings.length + ' findings, ' + fresh.length + ' new')
    return parallel(fresh.map((f) => () => verifyOne(f))).then((verified) => ({
      item,
      findings: verified.filter(Boolean),
    }))
  },
)

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
    (failed.length ? '; failed agents: ' + failed.join(', ') : ''),
)

// ─── Verdicts (computed here, not by an agent) ───

const blocking = findings.some((f) => f.bucket === 'critical' || f.mustViolation)
const verdict = blocking
  ? 'BLOCKING ISSUES'
  : findings.length > 0
    ? 'NON-BLOCKING ISSUES ONLY'
    : 'READY TO MERGE'
const auditVerdict = audit ? audit.verdict : 'AUDIT FAIL'
const auditNote = audit ? '' : ' (the auditor returned no result; treated as FAIL)'

const stats = {
  pr: PR,
  mode: MODE,
  since: SINCE,
  head: scope.head,
  base: scope.base,
  files: scope.files.length,
  shards: shards.length,
  lenses: LENSES.map((l) => l.name),
  agents: agentCalls,
  findings: findings.length,
  confirmed: count('confirmed'),
  contested: count('contested'),
  unverified: count('unverified'),
  nits: count('nit'),
  dropped: dropped.length,
  failed,
}

// ─── Phase: Synthesize ───

phase('Synthesize')

const SYNTH_PROMPT = [
  'Render the pre-merge review report for pull request #' + PR + ' (mode ' + MODE +
    ', head ' + scope.head + ') as Markdown.',
  '',
  'Rules: every finding below appears exactly once, under its bucket, with its status tag; ' +
    'do not drop, add, merge, re-rank, or soften a finding. You may order entries within a ' +
    'bucket by file and group entries that share one root cause under one lead entry that ' +
    'still lists every file:line. Each entry: `file:line` [status] claim. Authority: the ' +
    'cited authority. Rationale: one sentence from the evidence. Fix: the proposed fix. For ' +
    'contested and unverified entries add one line per verifier vote with its lens, ' +
    'refuted flag, confidence, and evidence. The dropped section lists each dropped finding ' +
    'in one line with the refuting evidence. The audit section lists each audit section ' +
    'with its verdict and items.',
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
  label: 'synthesize', phase: 'Synthesize', schema: REPORT_SCHEMA,
})

const body = synthesized
  ? synthesized.report
  : '# Pre-merge review: PR #' + PR + '\n\nSynthesis agent returned no result; ' +
    'the raw findings are in the `findings`, `dropped`, and `audit` fields.\n'

const report =
  body.replace(/\s+$/, '') + '\n\n' + verdict + '\n' + auditVerdict + auditNote + '\n'

stats.agents = agentCalls

return { verdict, auditVerdict, report, findings, dropped, audit, stats }
