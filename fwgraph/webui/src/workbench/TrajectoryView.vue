<template>
  <div class="mask" @click.self="$emit('close')">
    <div class="sheet">
      <div class="head">
        <span>{{ t('trajectory.title') }}</span>
        <div class="head-actions">
          <button
            type="button"
            class="exp"
            :disabled="exporting"
            title="导出会话完整日志（报告/journal/发现，ZIP）"
            @click="exportZip"
          >{{ exporting ? '打包中…' : '导出会话' }}</button>
          <button type="button" class="x" @click="$emit('close')">
            <IconCloseOutline16 :size="16" />
          </button>
        </div>
      </div>

      <!-- 工具调用统计（2026-09-23：对齐 dsh 官方 trajectory 统计能力） -->
      <div class="stats">
        <div class="stat">
          <b>{{ nodes.length }}</b><span>事件节点</span>
        </div>
        <div class="stat">
          <b>{{ toolTotal }}</b><span>工具调用</span>
        </div>
        <div class="stat">
          <b class="ok">{{ toolOk }}</b><span>成功</span>
        </div>
        <div class="stat">
          <b class="err">{{ toolErr }}</b><span>失败</span>
        </div>
        <div class="stat">
          <b>{{ turns }}</b><span>轮次</span>
        </div>
        <div class="stat">
          <b>{{ findings }}</b><span>发现</span>
        </div>
      </div>

      <!-- token 实时统计（累计自每步 usage，assistant/message 事件驱动） -->
      <div class="tok-panel">
        <div class="tok-row">
          <span class="tok-title">Token 累计消耗（{{ totals.calls }} 次 LLM 调用）</span>
        </div>
        <div class="tok-grid">
          <div class="tk"><b>{{ fmtTok(totals.input) }}</b><span>输入</span></div>
          <div class="tk"><b>{{ fmtTok(totals.output) }}</b><span>输出</span></div>
          <div class="tk"><b>{{ fmtTok(totals.cacheRead) }}</b><span>缓存读</span></div>
          <div class="tk"><b>{{ fmtTok(totals.cacheWrite) }}</b><span>缓存写</span></div>
          <div class="tk hot"><b>{{ fmtTok(totals.input + totals.output + totals.cacheRead + totals.cacheWrite) }}</b><span>总计</span></div>
        </div>
        <div class="tok-row sub">
          <span>当前上下文规模 ≈ {{ fmtTok(totals.contextTokens) }} tokens</span>
          <span v-if="usage" class="live">实时更新中</span>
        </div>
      </div>

      <div class="sec-title">工具调用排行</div>
      <div class="tops">
        <div v-for="row in toolTop" :key="row.name" class="top-row">
          <span class="tname" :title="row.name">{{ row.label }}</span>
          <span class="tbar"><i :style="{ width: row.pct + '%' }" /></span>
          <span class="tnum">{{ row.count }}<em v-if="row.err"> / {{ row.err }}败</em></span>
        </div>
        <div v-if="!toolTop.length" class="empty">本会话还没有工具调用</div>
      </div>

      <div class="sec-title">轨迹</div>
      <div class="list">
        <div v-for="node in nodes" :key="node.id" class="row">
          <span class="kind">{{ node.kind }}</span>
          <span class="sum">{{ line(node) }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { IconCloseOutline16 } from './icons.js'
import { t } from './locales.js'
import { getToken } from '../api'
const usage = computed(() =>
  props.session?.state?.projections?.lastUsage
  || props.session?.state?.projections?.tokenUsage || null)
const totals = computed(() =>
  props.session?.state?.usageTotals
  || { calls: 0, input: 0, output: 0, cacheRead: 0, cacheWrite: 0, contextTokens: 0 })

const exporting = ref(false)
const nodes = computed(() => props.session?.state?.nodes || [])
const tools = computed(() => nodes.value.filter((n) => n.kind === 'tool'))
const toolTotal = computed(() => tools.value.length)
const toolOk = computed(() => tools.value.filter((n) => n.status === 'ok').length)
const toolErr = computed(() => tools.value.filter((n) => n.status === 'error').length)
const turns = computed(() => props.session?.state?.turns || 0)
const findings = computed(() => (props.session?.state?.findings || []).length)

const TOOL_LABELS = {
  fw_get_identification: '盘点外部输入', fw_list_surfaces: '列攻击面',
  fw_get_surface: '读攻击面', fw_attack_surface: '查攻击路径',
  fw_get_function_source: '读伪代码', fw_search: '代码检索',
  fw_routes: '查路由', fw_call_trace: '追踪调用链',
  fw_get_cfg: '读控制流图', fw_browse_firmware: '浏览固件树',
  fw_list_binaries: '列二进制', fw_request_trace: 'qemu 差分 trace',
  fw_get_trace: '读 trace', fw_list_traces: 'trace 列表',
  fw_qemu_exec: 'qemu 试跑', fw_request_fuzz: 'AFL fuzz',
  fw_read_bytes: '直读数据段', fw_decompile_single: '单独反编译',
  fw_offer_emulation: '终局登记', record_finding: '记录漏洞',
  search: '检索', read: '读取', bash: '执行', write: '写入',
  edit: '编辑', skill: '加载技能',
}

const toolTop = computed(() => {
  const by = {}
  for (const n of tools.value) {
    const name = n.name || '?'
    if (!by[name]) by[name] = { name, label: TOOL_LABELS[name] || name, count: 0, err: 0 }
    by[name].count += 1
    if (n.status === 'error') by[name].err += 1
  }
  const rows = Object.values(by).sort((a, b) => b.count - a.count).slice(0, 12)
  const max = rows[0]?.count || 1
  return rows.map((r) => ({ ...r, pct: Math.round(100 * r.count / max) }))
})

function fmtTok (v) {
  const n = Number(v) || 0
  if (n > 1e6) return (n / 1e6).toFixed(1) + 'M'
  if (n > 1e3) return (n / 1e3).toFixed(1) + 'K'
  return String(n)
}

function line (n) {
  if (n.kind === 'tool') return `${n.name || ''} ${n.status || ''}`
  return String(n.text || n.reason || '').replace(/\s+/g, ' ').slice(0, 120)
}

async function exportZip () {
  const sid = props.session?.state?.sid
  if (!sid || exporting.value) return
  exporting.value = true
  try {
    const resp = await fetch(`/vulnagent/sessions/${sid}/export`, {
      headers: { Authorization: `Bearer ${getToken()}` } })
    if (!resp.ok) throw new Error(`${resp.status}`)
    const blob = await resp.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${sid}-session-log.zip`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    console.error('session export failed', e)
  } finally {
    exporting.value = false
  }
}
</script>

<style scoped>
.mask {
  position: absolute; inset: 0; z-index: 25;
  display: flex; justify-content: flex-end;
  background: var(--dsw-alias-bg-mask-2);
}
.sheet {
  width: min(480px, 100%); height: 100%;
  background: var(--dsw-alias-bg-layer-1);
  border-left: 1px solid var(--dsw-alias-border-l2);
  display: flex; flex-direction: column;
  overflow: hidden;
}
.head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 16px; border-bottom: 1px solid var(--dsw-alias-border-l2);
  font-weight: 600;
}
.head-actions { display: flex; align-items: center; gap: 8px; }
.exp {
  border: 1px solid var(--dsw-alias-border-l2); background: transparent;
  border-radius: 8px; padding: 5px 12px; font-size: 12px; cursor: pointer;
  color: inherit;
}
.exp:hover { background: var(--dsw-alias-interactive-bg-hover); }
.exp:disabled { opacity: .55; cursor: default; }
.x { border: none; background: transparent; cursor: pointer; color: inherit; }

.stats {
  display: grid; grid-template-columns: repeat(6, 1fr);
  gap: 6px; padding: 10px 16px 6px;
}
.stat {
  display: flex; flex-direction: column; align-items: center; gap: 1px;
  padding: 8px 4px; border-radius: 10px;
  background: var(--dsw-alias-interactive-bg-hover);
}
.stat b { font-size: 16px; line-height: 1.15; }
.stat b.ok { color: #16a34a; }
.stat b.err { color: #e11d48; }
.stat span { font-size: 10.5px; opacity: .6; }
.tok-panel {
  margin: 4px 16px 8px; padding: 10px 12px;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 12px;
  display: flex; flex-direction: column; gap: 8px;
}
.tok-row { display: flex; justify-content: space-between; align-items: center; }
.tok-title { font-size: 12px; font-weight: 600; opacity: .8; }
.tok-row.sub { font-size: 11px; opacity: .6; }
.tok-row.sub .live {
  color: #16a34a; font-weight: 600;
  display: inline-flex; align-items: center; gap: 4px;
}
.tok-row.sub .live::before {
  content: ''; width: 6px; height: 6px; border-radius: 50%;
  background: #16a34a; animation: tokpulse 1.4s ease-in-out infinite;
}
@keyframes tokpulse { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }
.tok-grid {
  display: grid; grid-template-columns: repeat(5, 1fr); gap: 6px;
}
.tk {
  display: flex; flex-direction: column; align-items: center; gap: 1px;
  padding: 6px 4px; border-radius: 8px;
  background: var(--dsw-alias-interactive-bg-hover);
}
.tk b { font-size: 14px; }
.tk.hot b { color: var(--fw-brand, #5b8cff); }
.tk span { font-size: 10px; opacity: .6; }
.sec-title {
  padding: 8px 16px 4px; font-size: 11.5px; font-weight: 600;
  opacity: .65; letter-spacing: .04em;
}
.tops { padding: 0 16px 8px; display: flex; flex-direction: column; gap: 4px; }
.top-row { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.tname { flex: 0 0 132px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tbar { flex: 1; height: 6px; border-radius: 4px; background: var(--dsw-alias-interactive-bg-hover); overflow: hidden; }
.tbar i { display: block; height: 100%; background: var(--fw-brand, #5b8cff); border-radius: 4px; }
.tnum { flex: 0 0 auto; opacity: .75; }
.tnum em { color: #e11d48; font-style: normal; }
.empty { font-size: 12px; opacity: .55; padding: 4px 0; }
.list { flex: 1; overflow: auto; padding: 4px 16px 16px; }
.row {
  display: flex; gap: 8px; padding: 5px 8px; border-radius: 8px;
  font-size: 12px;
}
.row:nth-child(odd) { background: var(--dsw-alias-interactive-bg-hover); }
.kind { flex: 0 0 64px; opacity: .55; }
.sum { flex: 1; opacity: .85; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
