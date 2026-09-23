// probe_scheduler.mjs — 对比 dsh-tools 的三份可能副本 + composition 实例归属。
// 运行：cd ~/deepseek-harness && node --import tsx/esm probe_scheduler.mjs
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
const HOME = process.env.HOME ?? ''
const DSH = join(HOME, 'deepseek-harness')
process.env.FWGRAPH_EVENTS_FILE ??= '/tmp/fwgraph-probe-events.sse'
process.env.FWGRAPH_SESSION_ID ??= 'probe-scheduler'

const cliPkg = await import(join(DSH, 'apps/cli/node_modules/@deepseek-ai/dsh-tools/lib/index.js'))
const libPkg = await import(join(DSH, 'packages/core/tools/lib/index.js'))
const srcPkg = await import(join(DSH, 'packages/core/tools/src/index.ts'))
console.log('--- module copy identity ---')
console.log('cli-lib === tools-lib:', cliPkg.ToolRuntime === libPkg.ToolRuntime)
console.log('cli-lib === tools-src:', cliPkg.ToolRuntime === srcPkg.ToolRuntime)
console.log('tools-lib === tools-src:', libPkg.ToolRuntime === srcPkg.ToolRuntime)

const appBoot = await import(join(DSH, 'apps/cli/node_modules/@deepseek-ai/dsh-app-boot/lib/index.js'))
const { boot, healProfilesModuleFallback, loadOptionalPatches, loadProfile } = appBoot
const INSTALL_ANCHOR = join(DSH, 'apps/cli/package.json')
const profile = loadProfile('dsh', 'fwgraph', INSTALL_ANCHOR, undefined, { userLayer: true })
await healProfilesModuleFallback({ installAnchor: INSTALL_ANCHOR, profile })
const rootConfig = join(profile.dir, 'cordis.yml')
writeFileSync(rootConfig, '# probe rewrite\n[]\n')
const bundlePatches = profile.layers.flatMap((l) => l.patches)
const homePatches = loadOptionalPatches('dsh', join(HOME, '.dsh', 'cordis.patch.yml')) ?? []
const overlays = [
  { id: 'headless-runner', disabled: true },
  { id: 'headless-startup', disabled: true },
]
const ctx = await boot('dsh', rootConfig,
  structuredClone([...bundlePatches, ...profile.patches, ...homePatches, ...overlays]))

console.log('--- runtime instance ---')
const rt = ctx.tools
console.log('rt ctor:', rt?.constructor?.name)
console.log('rt instanceof cli-lib:', rt instanceof cliPkg.ToolRuntime)
console.log('rt instanceof tools-lib:', rt instanceof libPkg.ToolRuntime)
console.log('rt instanceof tools-src:', rt instanceof srcPkg.ToolRuntime)
console.log('scheduler via cli-lib symbol:', !!rt?.[cliPkg.TOOL_RUNTIME_SCHEDULER])
console.log('scheduler via tools-lib symbol:', !!rt?.[libPkg.TOOL_RUNTIME_SCHEDULER])
console.log('scheduler via tools-src symbol:', !!rt?.[srcPkg.TOOL_RUNTIME_SCHEDULER])
console.log('own symbols:', Object.getOwnPropertySymbols(rt).map(String).join(', ') || '(none)')
process.exit(0)
