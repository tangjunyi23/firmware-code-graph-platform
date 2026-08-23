#!/usr/bin/env node
/**
 * verify_tools.mjs — boot the fwgraph dsh profile composition in-process
 * (with the headless task runner disabled, so NO LLM call is made) and print
 * the registered model-facing tool list, asserting the S1 lockdown:
 *
 *   - no web class      (web_search / web_fetch)
 *   - no subagent class (subagent / send_message / list_agents ...)
 *   - no pwsh / ralph / workflow / run_code
 *   - sandboxed bash/fs (write/edit) ARE allowed
 *   - fw_* series present, including fw_browse_firmware, fw_get_trace, record_finding
 *
 * Usage (on the VM):
 *   node ~/firmware-graph/vulnagent/dsh/verify_tools.mjs
 *   DSH_REPO=~/deepseek-harness node .../verify_tools.mjs   # custom checkout
 *
 * Exit code 0 = all assertions pass; 1 = violation found (details on stderr).
 */
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'

const HOME = process.env.HOME ?? ''
const DSH = process.env.DSH_REPO ?? join(HOME, 'deepseek-harness')

// The events plugin opens its SSE file at apply() time; keep the probe's
// writes out of any real session log.
process.env.FWGRAPH_EVENTS_FILE ??= '/tmp/fwgraph-verify-tools-events.sse'
process.env.FWGRAPH_SESSION_ID ??= 'verify-tools'

const appBoot = await import(
  join(DSH, 'apps/cli/node_modules/@deepseek-ai/dsh-app-boot/lib/index.js'))
const { boot, healProfilesModuleFallback, loadOptionalPatches, loadProfile } = appBoot

// Same composition path as apps/cli/src/profile-boot.ts (prepareProfile +
// bundle layers -> profile cordis.patch.yml -> home layer -> overlays).
const INSTALL_ANCHOR = join(DSH, 'apps/cli/package.json')
healProfilesModuleFallback(INSTALL_ANCHOR)
const profile = loadProfile('dsh', 'fwgraph', INSTALL_ANCHOR, undefined, { userLayer: true })

// prepareProfile() rewrites the empty root on every real boot (the loader can
// bake composed rows into it on write-back); mirror that here.
const rootConfig = join(profile.dir, 'cordis.yml')
writeFileSync(rootConfig, '# dsh profile root — rewritten by verify_tools.mjs (same as apps/cli prepareProfile)\n[]\n')

const bundlePatches = profile.layers.flatMap((layer) => layer.patches)
const homePatches = loadOptionalPatches(
  'dsh', join(process.env.DSH_HOME ?? join(HOME, '.dsh'), 'cordis.patch.yml')) ?? []
// Probe-only overlay: never run a task, we only enumerate the tool surface.
const overlays = [
  { id: 'headless-runner', disabled: true },
  { id: 'headless-startup', disabled: true },
]

const ctx = await boot(
  'dsh', rootConfig,
  structuredClone([...bundlePatches, ...profile.patches, ...homePatches, ...overlays]),
)

const FORBIDDEN = new Set([
  'pwsh', 'run_code', 'ralph', 'workflow',
  'web_search', 'web_fetch',
  'subagent', 'subagent_fork', 'send_message', 'interrupt_agent', 'list_agents', 'report',
])
const REQUIRED_FW = [
  'fw_get_identification', 'fw_list_surfaces', 'fw_get_surface',
  'fw_get_function_source', 'fw_attack_surface', 'fw_search', 'fw_call_trace',
  'fw_routes', 'fw_list_traces', 'fw_get_trace', 'fw_browse_firmware',
  'fw_get_fuzz_run', 'fw_get_cfg', 'fw_get_ast', 'record_finding',
]
const REQUIRED_SANDBOX = ['bash', 'write']
const DYNAMIC_ONLY = ['fw_request_trace', 'fw_request_fuzz', 'fw_request_frida', 'fw_qemu_exec']
const STATIC = (process.env.FWGRAPH_MODE ?? 'dynamic') === 'static'

let failed = false
try {
  const names = ctx.tools.schemas().map((s) => s.name).sort()
  console.log(`registered tools (${names.length}, mode=${STATIC ? 'static' : 'dynamic'}):`)
  for (const n of names) console.log(`  ${n}`)

  const bad = names.filter((n) => FORBIDDEN.has(n))
  if (bad.length) {
    failed = true
    console.error(`\nFAIL: forbidden tool(s) registered: ${bad.join(', ')}`)
  }
  const missing = REQUIRED_FW.filter((n) => !names.includes(n))
  if (missing.length) {
    failed = true
    console.error(`\nFAIL: missing fw_* tool(s): ${missing.join(', ')}`)
  }
  // 动态类工具：dynamic 模式必须在场，static 模式必须缺席
  const dynPresent = DYNAMIC_ONLY.filter((n) => names.includes(n))
  if (STATIC && dynPresent.length) {
    failed = true
    console.error(`\nFAIL: dynamic tool(s) visible in static mode: ${dynPresent.join(', ')}`)
  }
  if (!STATIC && dynPresent.length !== DYNAMIC_ONLY.length) {
    failed = true
    console.error(`\nFAIL: dynamic mode is missing: ${DYNAMIC_ONLY.filter((n) => !dynPresent.includes(n)).join(', ')}`)
  }
  const missingSandbox = REQUIRED_SANDBOX.filter((n) => !names.includes(n))
  if (missingSandbox.length) {
    failed = true
    console.error(`\nFAIL: sandbox tool(s) missing: ${missingSandbox.join(', ')}`)
  }
  const nonFw = names.filter((n) => !n.startsWith('fw_'))
  console.log(`\nnon-fw tools still visible: ${nonFw.join(', ') || '(none)'}`)
  if (!failed) console.log('\nOK: web/subagent locked; sandbox bash/write present; fw_* series complete.')
} finally {
  await ctx.fiber.dispose()
}
process.exit(failed ? 1 : 0)
