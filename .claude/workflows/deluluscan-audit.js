export const meta = {
  name: 'deluluscan-audit',
  description: 'Scan a target target with Deluluscan, adjudicate every candidate finding live (parallel for read-only checks, sequential for state-changing ones), centrally fix any scanner false-positive bugs, then regenerate the dashboard.',
  whenToUse: 'Use for a full Deluluscan audit pass once the target instance is already up and config.dev.yaml points at it. Does not stand up or tear down the instance, and does not push the dashboard — it only regenerates docs/dashboard.html for the caller to review and commit.',
  phases: [
    { title: 'Scan' },
    { title: 'Adjudicate' },
    { title: 'Fix scanners' },
    { title: 'Re-scan' },
    { title: 'Report' },
  ],
}

// Findings whose retest is a plain read (GET/HEAD) can safely run concurrently
// against the shared dev instance. Anything else (POST/PUT/DELETE/PATCH) may
// mutate or destroy live state (e.g. DELETE /api/bundle/all, purge queue,
// remove cluster nodes) and is rechecked one at a time so two agents never
// race a destructive action against the same instance.
const PARALLEL_CHUNK = 5
const READ_ONLY_METHODS = ['GET', 'HEAD']

const SCAN_SCHEMA = {
  type: 'object',
  properties: {
    resultsPath: { type: 'string' },
    totalFindings: { type: 'integer' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          index: { type: 'integer' },
          method: { type: 'string' },
          path: { type: 'string' },
          vulnClass: { type: 'string' },
          verdict: { type: 'string' },
          needsRetest: { type: 'boolean' },
        },
        required: ['index', 'method', 'path', 'verdict', 'needsRetest'],
      },
    },
  },
  required: ['resultsPath', 'totalFindings', 'findings'],
}

const VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    index: { type: 'integer' },
    method: { type: 'string' },
    path: { type: 'string' },
    finalVerdict: {
      type: 'string',
      enum: ['true_positive', 'likely_true_positive', 'conditional', 'inconclusive', 'false_positive'],
    },
    exploitability: { type: 'string' },
    notes: { type: 'string' },
    suspectedScannerBug: {
      type: ['object', 'null'],
      properties: {
        file: { type: 'string' },
        description: { type: 'string' },
      },
    },
  },
  required: ['index', 'method', 'path', 'finalVerdict'],
}

const FIX_SCHEMA = {
  type: 'object',
  properties: {
    filesChanged: { type: 'boolean' },
    changedFiles: { type: 'array', items: { type: 'string' } },
    silencedIndexes: { type: 'array', items: { type: 'integer' } },
    summary: { type: 'string' },
  },
  required: ['filesChanged', 'summary'],
}

const RESCAN_SCHEMA = {
  type: 'object',
  properties: {
    resultsPath: { type: 'string' },
    summary: { type: 'string' },
  },
  required: ['resultsPath', 'summary'],
}

const REPORT_SCHEMA = {
  type: 'object',
  properties: {
    dashboardPath: { type: 'string' },
    truePositives: { type: 'integer' },
    falsePositives: { type: 'integer' },
    summary: { type: 'string' },
  },
  required: ['dashboardPath', 'summary'],
}

function cliCommand(config, openapiFile) {
  const specFlag = openapiFile ? ` --openapi-file ${openapiFile}` : ''
  return `python3 -m deluluscan.cli --config ${config}${specFlag} --allow-state-changing --fuzz`
}

function scanPrompt(config, openapiFile) {
  return `You are running one pass of the Deluluscan security scanner in the repo root (/home/rashik/deluluscan). The target instance is already up and ${config} already points at it with base_url and identities set — do not start or stop docker, do not modify config.

Run exactly:
  ${cliCommand(config, openapiFile)}

Then read deluluscan-out/results.json (a JSON array of findings; each has a 0-based array index, "endpoint" like "GET /api/v1/foo", "vuln_class", "verdict"). A finding needs a live retest ("needsRetest": true) if its verdict is one of: unverified, tentative, inconclusive, or conditional. Confirmed true_positive/false_positive verdicts from a prior live recheck do not need retesting again.

Report back, via the required structured output: the path "deluluscan-out/results.json", the total finding count, and for every finding needing retest: its array index, HTTP method, path, vuln_class, and current verdict. For findings that do NOT need retest, omit them from the list entirely — only list ones needing retest.`
}

function adjudicatePrompt(config, item) {
  return `You are adjudicating ONE Deluluscan finding for an authorized security audit, in repo root /home/rashik/deluluscan. This is a live re-test, not a report of the scanner's raw hit.

Finding: array index ${item.index} in deluluscan-out/results.json, method ${item.method}, path ${item.path}, vuln_class ${item.vulnClass || 'unknown'}, current verdict ${item.verdict}.

Run:
  python3 -m deluluscan.recheck --config ${config} --from-results deluluscan-out/results.json --index ${item.index}

Read the JSON verdict it prints and decide:
- verdict false_positive / nothing reproduced -> it did NOT re-fire. Treat as a FALSE POSITIVE. If you believe this is a false positive caused by a tool bug (a soft-404 catch-all, a fingerprint mismatch, a scanner flagging benign behavior, etc.), DO NOT edit any code yourself — a separate pass fixes scanners centrally to avoid two agents editing the same file at once. Instead, report your suspected root cause (which file under deluluscan/, and why) in suspectedScannerBug.
- verdict true_positive / likely_true_positive / exploitable -> CONFIRMED. Dig deeper: re-run recheck with an adjacent --param or --path to map blast radius, and record a concrete reproduction in your notes. NEVER weaponize — no data exfiltration, no destructive follow-through beyond what's needed to confirm. If the endpoint is state-changing (POST/PUT/DELETE/PATCH) and executing it would mutate or destroy live server state (e.g. deleting all bundles, purging queues, removing cluster nodes), you may rely on the recheck tool's own confirmation rather than manually re-firing the action again yourself.
- conditional / inconclusive -> note exactly what additional condition or manual step would be needed; do not overclaim either direction.

Report back the finding's index, method, path, your finalVerdict, exploitability, your notes (include the concrete repro), and suspectedScannerBug (null if none).`
}

function fixScannersPrompt(bugReports) {
  const list = bugReports
    .map(b => `- index ${b.index} (${b.method} ${b.path}): suspected bug in ${b.suspectedScannerBug.file} — ${b.suspectedScannerBug.description}`)
    .join('\n')
  return `You are fixing Deluluscan scanner false-positive bugs found during a live adjudication pass, in repo root /home/rashik/deluluscan. You are the ONLY agent touching deluluscan/ in this pass, so it's safe to edit multiple files here.

Reported false positives believed to be caused by tool bugs, not by the target actually being safe:
${list}

For each one: find and fix the responsible scanner/module under deluluscan/, add or update a regression test under tests/ that would have caught it, then run the relevant test suite (python3 -m tests.<suite>) to confirm it passes. After fixing, re-run the recheck for that finding's index to confirm the fix silences the false positive without hiding a real issue:
  python3 -m deluluscan.recheck --config config.dev.yaml --from-results deluluscan-out/results.json --index <N>

If a reported issue turns out NOT to be a tool bug on closer inspection, leave it alone and say so in your summary rather than forcing a change.

Report back whether you changed any files, which files, which finding indexes you confirmed are now correctly silenced, and a summary.`
}

function rescanPrompt(config, openapiFile) {
  return `Scanner code under deluluscan/ was just modified to fix false-positive bugs, in repo root /home/rashik/deluluscan. Re-run the full scan so deluluscan-out/results.json reflects the fixed tool:
  ${cliCommand(config, openapiFile)}

Report back the results path and a one-line summary of anything that materially changed (counts of true/false positives) versus a typical run.`
}

function reportPrompt() {
  return `Regenerate the Deluluscan dashboard from the adjudicated results, in repo root /home/rashik/deluluscan:
  python3 -m deluluscan.dashboard deluluscan-out/results.json docs/dashboard.html

Do NOT git add, commit, or push anything — a human reviews the dashboard for sensitive content before it's committed. Just generate it and report back the path, the true_positive and false_positive counts shown in the dashboard's headline, and a short summary.`
}

async function adjudicateOne(config, item) {
  return agent(adjudicatePrompt(config, item), {
    phase: 'Adjudicate',
    label: `recheck:${item.index}`,
    schema: VERDICT_SCHEMA,
  })
}

async function parallelLane(config, items) {
  const out = []
  for (let i = 0; i < items.length; i += PARALLEL_CHUNK) {
    const batch = items.slice(i, i + PARALLEL_CHUNK)
    const res = await parallel(batch.map(item => () => adjudicateOne(config, item)))
    out.push(...res.filter(Boolean))
    log(`adjudicated ${Math.min(i + PARALLEL_CHUNK, items.length)}/${items.length} read-only findings`)
  }
  return out
}

async function sequentialLane(config, items) {
  const out = []
  for (const item of items) {
    const res = await adjudicateOne(config, item)
    if (res) out.push(res)
    log(`adjudicated ${out.length}/${items.length} state-changing findings (sequential)`)
  }
  return out
}

phase('Scan')
const config = (args && args.config) || 'config.dev.yaml'
const openapiFile = (args && args.openapiFile) || 'openapi.json'

const scanResult = await agent(scanPrompt(config, openapiFile), { schema: SCAN_SCHEMA })
log(`scan complete: ${scanResult.totalFindings} total findings, ${scanResult.findings.length} need live retest`)

let confirmed = []
let bugReports = []

if (scanResult.findings.length > 0) {
  phase('Adjudicate')
  const readOnly = scanResult.findings.filter(f => READ_ONLY_METHODS.includes((f.method || '').toUpperCase()))
  const stateChanging = scanResult.findings.filter(f => !READ_ONLY_METHODS.includes((f.method || '').toUpperCase()))
  log(`${readOnly.length} read-only findings (parallel, chunks of ${PARALLEL_CHUNK}) / ${stateChanging.length} state-changing findings (sequential)`)

  const [readOnlyResults, stateChangingResults] = await parallel([
    () => parallelLane(config, readOnly),
    () => sequentialLane(config, stateChanging),
  ])

  const adjudications = [...(readOnlyResults || []), ...(stateChangingResults || [])]
  confirmed = adjudications.filter(a => a.finalVerdict === 'true_positive' || a.finalVerdict === 'likely_true_positive')
  bugReports = adjudications.filter(a => !!(a.suspectedScannerBug && a.suspectedScannerBug.file))
  log(`adjudication done: ${confirmed.length} confirmed, ${bugReports.length} suspected scanner bugs`)
}

let fixResult = null
if (bugReports.length > 0) {
  phase('Fix scanners')
  fixResult = await agent(fixScannersPrompt(bugReports), { schema: FIX_SCHEMA })
  log(`fix pass: ${fixResult.summary}`)

  if (fixResult.filesChanged) {
    phase('Re-scan')
    await agent(rescanPrompt(config, openapiFile), { schema: RESCAN_SCHEMA })
  }
}

phase('Report')
const report = await agent(reportPrompt(), { schema: REPORT_SCHEMA })

return {
  scan: { totalFindings: scanResult.totalFindings, retested: scanResult.findings.length },
  confirmed,
  bugReports,
  fixResult,
  report,
}
