<template>
  <div class="inputs-page">
    <header class="ins-head inputs-header">
      <div class="ins-head-row">
        <h1 class="ins-title">
          <span class="ins-ico"><component :is="NAV_ICONS.Download" :size="18" /></span>
          输入面
        </h1>
        <div class="ins-actions">
          <JobPicker v-model="jobId" :prefer="['surfaced', 'identified', 'routed', 'attacked', 'graphed', 'done']" @change="loadAll" />
          <el-button :icon="RefreshCw" :loading="loading" @click="loadAll">刷新</el-button>
          <el-button :icon="Radar" :loading="rerunningInputs" :disabled="!jobId || rerunningSurfaces" @click="rerunInputs">重新识别</el-button>
          <el-button :icon="Route" :loading="rerunningSurfaces" :disabled="!jobId || rerunningInputs" @click="rerunSurfaces">导出攻击面</el-button>
        </div>
      </div>
      <div v-if="gateNotes.length" class="input-evidence-note">
      <el-popover v-if="gateNotes.length" placement="bottom-start" :width="520" trigger="click">
        <template #reference>
          <button type="button" class="gate-chip" :class="{ err: hasGateErrors }">
            <component :is="NAV_ICONS.Collection" :size="13" />
            {{ gateNotes.length }} 条证据提示
            <span class="gate-chip-act">查看</span>
          </button>
        </template>
        <div class="gate-note-list">
          <p class="gate-note-title">以下攻击面文档的证据等级有限，结论需人工复核：</p>
          <p v-for="(n, i) in gateNotes" :key="i" class="gate-note" :data-kind="n.kind">{{ n.text }}</p>
        </div>
      </el-popover>
      </div>

    </header>

    <section class="inputs-metrics" aria-label="输入面统计">
      <article><span class="input-metric-icon"><Network :size="18" /></span><div><span>识别输入</span><strong>{{ loading ? '—' : inputs.length }}</strong></div></article>
      <article><span class="input-metric-icon cyan"><Layers :size="18" /></span><div><span>攻击面文档</span><strong>{{ surfSummary?.surfaces ?? '—' }}</strong></div></article>
      <article><span class="input-metric-icon purple"><Shield :size="18" /></span><div><span>授权链</span><strong>{{ surfSummary?.auth_chains ?? '—' }}</strong></div></article>
      <article><span class="input-metric-icon amber"><FileCode :size="18" /></span><div><span>仅静态</span><strong>{{ surfSummary?.static_only ?? '—' }}</strong></div></article>
    </section>

    <div class="inputs-layout">
      <!-- left: input list -->
      <el-card class="side-card" shadow="never">
        <template #header>
          <div class="row-between">
            <span class="panel-label"><Server :size="16" />输入列表</span>
            <span class="muted">{{ filteredInputs.length }} / {{ inputs.length }}</span>
          </div>
        </template>
        <div v-loading="loading">
          <el-empty v-if="identMissing" description="尚未运行输入识别，可点击上方「重新识别」" :image-size="80" />
          <el-empty v-else-if="!loading && !inputs.length" description="无输入数据" :image-size="80" />
          <template v-else>
            <label class="input-search"><Search :size="15" /><input v-model="inputQuery" aria-label="搜索输入" placeholder="搜索服务、协议、端口" /><button v-if="inputQuery" type="button" aria-label="清空输入搜索" @click="inputQuery = ''"><X :size="13" /></button></label>
            <div class="input-protocols" aria-label="协议筛选">
              <button type="button" :class="{ active: !protocolFilter }" :aria-pressed="!protocolFilter" @click="protocolFilter = ''">全部<span>{{ inputs.length }}</span></button>
              <button v-for="item in protocolOptions" :key="item" type="button" :class="{ active: protocolFilter === item }" :aria-pressed="protocolFilter === item" @click="protocolFilter = item">{{ item.toUpperCase() }}</button>
            </div>
            <div class="input-service-list">
              <button v-for="row in filteredInputs" :key="row.id" type="button" class="input-service" :class="{ selected: current?.id === row.id }" :aria-pressed="current?.id === row.id" @click="select(row)">
                <span class="service-glyph"><component :is="serviceIcon(row)" :size="17" /></span>
                <span class="service-copy"><strong>{{ row.service || row.id }}</strong><span><b>{{ (row.protocol || row.transport || '未知').toUpperCase() }}</b><span class="service-port">{{ endpoint(row) }}</span></span></span>
                <span class="service-tail"><span class="service-input-id">{{ row.id }}</span><span class="surface-indicator" :class="{ present: surfaceByInput[row.id] }">{{ surfaceByInput[row.id] ? surfaceByInput[row.id].surface_id : '未导出' }}</span></span>
                <ChevronRight :size="14" class="service-chevron" />
              </button>
              <div v-if="!filteredInputs.length" class="input-list-empty"><Search :size="22" /><span>无匹配输入</span><button type="button" @click="inputQuery = ''; protocolFilter = ''">清空筛选</button></div>
            </div>
          </template>

          <el-collapse v-if="(meta?.excluded || []).length || (meta?.unreadable || []).length" class="meta-collapse">
            <el-collapse-item v-if="(meta?.excluded || []).length" :title="`排除项（${meta.excluded.length}）`" name="excluded">
              <div v-for="(e, i) in meta.excluded" :key="i" class="meta-line mono">{{ e }}</div>
            </el-collapse-item>
            <el-collapse-item v-if="(meta?.unreadable || []).length" :title="`不可读项（${meta.unreadable.length}）`" name="unreadable">
              <div v-for="(e, i) in meta.unreadable" :key="i" class="meta-line mono">{{ e }}</div>
            </el-collapse-item>
          </el-collapse>
        </div>
      </el-card>

      <!-- right: input detail + attack surface -->
      <el-card class="main-card" shadow="never">
        <template #header>
          <div class="row-between">
            <span class="panel-label"><FileCode :size="16" />输入详情 <span v-if="current" class="input-detail-id">{{ current.id }}</span></span>
            <el-tag v-if="surface" size="small" type="success">{{ surface.surface_id }}</el-tag>
          </div>
        </template>
        <el-empty v-if="!current" description="从左侧列表选择一个输入" :image-size="80" />
        <div v-else class="detail">
          <div class="input-detail-identity">
            <span class="identity-glyph"><component :is="serviceIcon(current)" :size="25" /></span>
            <div><h2>{{ current.service || current.id }}</h2><span class="identity-endpoint">{{ endpoint(current) }}<span class="identity-protocol">{{ (current.protocol || current.transport || '未知').toUpperCase() }}</span></span></div>
            <span class="input-exposure" :class="{ public: current.public }"><i />{{ current.public ? '公网标记' : '内部输入' }}</span>
          </div>
          <nav class="input-detail-tabs" aria-label="输入详情视图">
            <button type="button" :class="{ active: detailTab === 'overview' }" :aria-pressed="detailTab === 'overview'" @click="detailTab = 'overview'">基本信息</button>
            <button type="button" :class="{ active: detailTab === 'surface' }" :aria-pressed="detailTab === 'surface'" @click="detailTab = 'surface'">攻击面<span v-if="surface">{{ surface.surface_id }}</span></button>
          </nav>
          <section v-show="detailTab === 'overview'" class="input-overview-section">
          <!-- 基本信息 -->
          <el-descriptions :column="2" size="default" class="input-facts">
            <el-descriptions-item label="服务">{{ current.service }}</el-descriptions-item>
            <el-descriptions-item label="协议">{{ current.protocol }}</el-descriptions-item>
            <el-descriptions-item label="地址"><span class="mono">{{ endpoint(current) }}</span></el-descriptions-item>
            <el-descriptions-item label="公网标记">
              <el-tag size="small" :type="current.public ? 'success' : 'info'" effect="plain">
                {{ current.public ? '是' : '否' }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="输入类型" :span="2">
              <el-tag v-for="t in visibleInputTypes" :key="t" size="small" effect="plain" class="tag-gap">{{ t }}</el-tag>
              <span v-if="!visibleInputTypes.length" class="muted">—</span>
            </el-descriptions-item>
            <el-descriptions-item v-if="binaryFingerprint" label="二进制 MD5" :span="2"><code class="input-fingerprint mono">{{ binaryFingerprint }}</code></el-descriptions-item>
          </el-descriptions>
          <div class="sub-block">
            <div class="sub-title muted">入口文件</div>
            <div v-for="f in current.entry_files || []" :key="f" class="mono file-line" :title="f">{{ baseName(f) }}</div>
          </div>
          <div v-for="(pc, i) in current.processing_chain || []" :key="i" class="sub-block">
            <div class="sub-title muted">处理链 · <span class="mono" :title="pc.file">{{ baseName(pc.file) }}</span></div>
            <el-tag v-for="lib in pc.libs || []" :key="lib" size="small" type="info" effect="plain" class="tag-gap mono">{{ lib }}</el-tag>
          </div>
          <p v-if="current.evidence" class="muted evidence">证据：{{ current.evidence }}</p>
          <p v-if="current.notes" class="muted">备注：{{ current.notes }}</p>

          <!-- 分发链 -->
          <template v-if="(current.dispatch_chain || []).length">
            <h4>分发链</h4>
            <div v-for="(d, i) in current.dispatch_chain" :key="i" class="dispatch-item">
              <el-tag v-if="d.route" size="small" type="warning" effect="plain" class="tag-gap mono">{{ d.route }}</el-tag>
              <span v-if="d.file" class="mono file-line" :title="d.file">{{ baseName(d.file) }}</span>
              <span v-if="d.note" class="muted">{{ d.note }}</span>
            </div>
          </template>

          </section>
          <section v-show="detailTab === 'surface'" class="input-surface-section">
          <!-- 攻击面文档 -->
          <template v-if="surface">
            <!-- 路由链 timeline -->
            <div class="sub-title muted">路由链</div>
            <div class="chain-v">
              <div v-for="(hop, index) in surface.routing_path || []" :key="index" class="step">
                <div class="rail">
                  <div class="dot" :style="{ background: stageColor(hop.stage) }" />
                  <div v-if="index < surface.routing_path.length - 1" class="line" />
                </div>
                <div class="node-card">
                  <div class="node-head">
                    <el-tag size="small" effect="plain" class="stage-tag"
                            :style="{ '--hop-color': stageColor(hop.stage) }">{{ hop.stage }}</el-tag>
                    <span v-if="hop.function" class="mono node-name">{{ hop.function }}</span>
                    <span class="mono muted file-ref" :title="hop.file">{{ baseName(hop.file) }}</span>
                  </div>
                  <div v-if="hop.detail" class="node-sub muted">{{ hop.detail }}</div>
                </div>
              </div>
            </div>

            <!-- 处理函数 -->
            <div v-if="surface.final_handler" class="sub-block">
              <div class="sub-title muted">处理函数</div>
              <div class="handler-card">
                <div class="node-head">
                  <span class="mono node-name">{{ surface.final_handler.function || '（未定位函数）' }}</span>
                  <el-tag v-if="surface.final_handler.route" size="small" type="warning" effect="plain" class="mono">
                    {{ surface.final_handler.route }}
                  </el-tag>
                </div>
                <div class="mono muted file-ref" :title="surface.final_handler.file">{{ baseName(surface.final_handler.file) }}</div>
                <div v-if="surface.final_handler.detail" class="node-sub muted">{{ surface.final_handler.detail }}</div>
              </div>
            </div>

            <!-- 组件清单 -->
            <div v-if="hasActors" class="sub-block">
              <div class="sub-title muted">组件清单</div>
              <div v-for="grp in actorGroups" :key="grp.label" class="actor-row">
                <span class="actor-label muted">{{ grp.label }}</span>
                <el-tag v-for="(a, i) in grp.items" :key="i" size="small" effect="plain" class="tag-gap mono"
                        :title="`${a.file}${a.detail ? ' · ' + a.detail : ''}`">
                  {{ a.function || a.detail || baseName(a.file) }}
                </el-tag>
              </div>
            </div>

            <!-- 载体绑定 -->
            <template v-if="(surface.carrier_bindings || []).length">
              <div class="sub-title muted">载体绑定</div>
              <el-table :data="surface.carrier_bindings" size="small" class="carrier-table">
                <el-table-column prop="carrier" label="载体" min-width="160" show-overflow-tooltip />
                <el-table-column prop="destination" label="去向" min-width="200" show-overflow-tooltip />
                <el-table-column prop="evidence" label="证据" min-width="180" show-overflow-tooltip />
              </el-table>
            </template>

            <!-- 授权链引用 -->
            <div v-if="(surface.auth_chain_refs || []).length" class="sub-block">
              <div class="sub-title muted">授权链引用</div>
              <el-tag v-for="ref in surface.auth_chain_refs" :key="ref" size="small" type="danger" effect="plain"
                      class="tag-gap mono auth-chip" @click="toggleAuth(ref)">
                {{ ref }}{{ expandedAuth === ref ? ' ▾' : ' ▸' }}
              </el-tag>
              <div v-if="expandedAuth" v-loading="authLoading" class="auth-panel">
                <template v-if="authDoc">
                  <div class="muted auth-applies">
                    适用于：
                    <el-tag v-for="a in authDoc.applies_to || []" :key="a" size="small" effect="plain" class="tag-gap mono">{{ a }}</el-tag>
                  </div>
                  <div class="chain-v">
                    <div v-for="(hop, index) in authDoc.chain || []" :key="index" class="step">
                      <div class="rail">
                        <div class="dot" :style="{ background: stageColor(hop.stage) }" />
                        <div v-if="index < authDoc.chain.length - 1" class="line" />
                      </div>
                      <div class="node-card">
                        <div class="node-head">
                          <el-tag size="small" effect="plain" class="stage-tag"
                                  :style="{ '--hop-color': stageColor(hop.stage) }">{{ hop.stage }}</el-tag>
                          <span v-if="hop.function" class="mono node-name">{{ hop.function }}</span>
                          <span class="mono muted file-ref" :title="hop.file">{{ baseName(hop.file) }}</span>
                        </div>
                        <div v-if="hop.detail" class="node-sub muted">{{ hop.detail }}</div>
                      </div>
                    </div>
                  </div>
                  <el-alert v-if="authDoc.bypass_notes" type="warning" :closable="false"
                            :title="`绕过备注：${authDoc.bypass_notes}`" class="bypass-alert" />
                  <p v-if="authDoc.evidence" class="muted evidence">证据：{{ authDoc.evidence }}</p>
                </template>
              </div>
            </div>

            <p v-if="surface.evidence" class="muted evidence">证据：{{ surface.evidence }}</p>
          </template>
          <el-empty v-else :description="surfMissing ? '尚未导出攻击面，可点击上方「导出攻击面」' : '该输入暂无攻击面文档'"
                    :image-size="70" />
          </section>
        </div>
      </el-card>
    </div>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Radar, RefreshCw, Route, Network, Layers, Shield, FileCode, Server, Search, ChevronRight, X, Globe } from '@lucide/vue'
import { api } from '../api'
import JobPicker from '../components/JobPicker.vue'
import { NAV_ICONS } from '../workbench/icons.js'

const jobId = ref('')
const inputQuery = ref('')
const protocolFilter = ref('')
const detailTab = ref('overview')
let requestVersion = 0
let loadController = null
let disposed = false

function endpoint(row) {
  const address = row?.address == null || row.address === '' ? '' : String(row.address)
  const port = row?.port == null ? '' : String(row.port)
  const transport = row?.transport || ''
  return address ? address + (port ? ':' + port : '') : port ? port + (transport ? ' / ' + transport.toUpperCase() : '') : '端口未确定'
}
function serviceIcon(row) {
  return /http|web|hnap/i.test(row?.protocol || row?.service || '') ? Globe : Server
}
const protocolOptions = computed(() => [...new Set(inputs.value.map(row => String(row.protocol || row.transport || '').toLowerCase()).filter(Boolean))].sort())
const filteredInputs = computed(() => {
  const query = inputQuery.value.trim().toLowerCase()
  return inputs.value.filter(row => (!protocolFilter.value || String(row.protocol || row.transport || '').toLowerCase() === protocolFilter.value)
    && (!query || [row.service, row.id, row.protocol, row.port, row.address, ...(row.entry_files || [])].join(' ').toLowerCase().includes(query)))
})
const loading = ref(false)
const rerunningInputs = ref(false)
const rerunningSurfaces = ref(false)

const meta = ref(null)
const inputs = ref([])
const identMissing = ref(false)
const surfSummary = ref(null)

// gate 提示改走摘要 chip，不再整屏堆 alert（内容被顶到看不见）
const GATE_TEXT_CN = [
  [/^(.+?):\s*carrier bindings are placeholder-grade \(no pseudo-C evidence\)$/, (m) => `${m[1]}：载体绑定证据不足（缺伪 C 证据）`],
  [/^(.+?):\s*final_handler unresolved \(static-only\)$/, (m) => `${m[1]}：最终处理函数未解析（仅静态）`],
  [/^(.+?):\s*no dispatcher identified$/, (m) => `${m[1]}：未识别出分发函数`]
]
const gateNotes = computed(() => {
  const sum = surfSummary.value || {}
  const conv = (list, kind) => (list || []).map((raw) => {
    let text = String(raw)
    for (const [re, fn] of GATE_TEXT_CN) {
      const m = text.match(re)
      if (m) { text = fn(m); break }
    }
    return { text, kind }
  })
  return [...conv(sum.gate_errors, 'err'), ...conv(sum.gate_warnings, 'warn')]
})
const hasGateErrors = computed(() => !!(surfSummary.value?.gate_errors || []).length)
const surfaces = ref([]) // non-AUTH surface docs
const surfMissing = ref(false)

const current = ref(null)
const visibleInputTypes = computed(() => (current.value?.input_types || []).filter(value => !String(value).startsWith('binary_md5=')))
const binaryFingerprint = computed(() => current.value?.binary_md5 || (current.value?.input_types || []).find(value => String(value).startsWith('binary_md5='))?.slice(11) || '')

// auth chain docs (lazy loaded)
const authDocs = ref({})
const authLoading = ref(false)
const expandedAuth = ref('')

const STAGE_COLORS = {
  listen: 'var(--fw-brand)', accept: 'var(--fw-brand)', parse: 'var(--fw-warn)',
  normalize: 'var(--fw-ok)', dispatch: 'var(--fw-brand)', handler: 'var(--fw-danger)',
  'permission-check': 'var(--fw-warn)'
}

function stageColor (stage) { return STAGE_COLORS[stage] || 'var(--fw-text-3)' }
function baseName (p) { return p ? String(p).split('/').filter(Boolean).pop() : '' }

const surfaceByInput = computed(() => {
  const map = {}
  for (const s of surfaces.value) {
    if (s.source_input) map[s.source_input] = s
  }
  return map
})

const surface = computed(() => (current.value ? surfaceByInput.value[current.value.id] : null))

const hasActors = computed(() => {
  const s = surface.value
  return Boolean(s && ((s.dispatchers || []).length || (s.parsers || []).length || (s.normalizers || []).length))
})
const actorGroups = computed(() => {
  const s = surface.value || {}
  return [
    { label: '分发函数', items: s.dispatchers || [] },
    { label: '解析函数', items: s.parsers || [] },
    { label: '规范化函数', items: s.normalizers || [] }
  ].filter(g => g.items.length)
})

const authDoc = computed(() => (expandedAuth.value ? authDocs.value[expandedAuth.value] : null))

function select (row) {
  current.value = row
  expandedAuth.value = ''
}

async function loadAll () {
  if (!jobId.value) return
  loadController?.abort()
  const controller = new AbortController()
  loadController = controller
  const version = ++requestVersion
  const id = jobId.value
  const options = { signal: controller.signal }
  const stale = () => disposed || version !== requestVersion || controller.signal.aborted
  loading.value = true
  inputQuery.value = ''
  protocolFilter.value = ''
  detailTab.value = 'overview'
  inputs.value = []
  meta.value = null
  surfaces.value = []
  surfSummary.value = null
  identMissing.value = false
  surfMissing.value = false
  current.value = null
  expandedAuth.value = ''
  authDocs.value = {}
  authLoading.value = false
  // identification
  try {
    const ident = await api(`/jobs/${id}/identification`, options)
    if (stale()) return
    meta.value = ident.metadata || null
    inputs.value = ident.inputs || []
    identMissing.value = false
    if (inputs.value.length) current.value = inputs.value[0]
  } catch (e) {
    if (stale()) return
    meta.value = null
    inputs.value = []
    identMissing.value = e.status === 404
    if (e.status !== 404) ElMessage.error('输入识别加载失败: ' + e.message)
  }
  // surfaces index + per-input docs
  surfaces.value = []
  surfSummary.value = null
  surfMissing.value = false
  try {
    const idx = await api(`/jobs/${id}/surfaces`, options)
    if (stale()) return
    surfSummary.value = idx.summary || null
    const names = (idx.files || [])
      .map(f => String(f).replace(/\.json$/, ''))
      .filter(id => id.startsWith('AS-') && !id.startsWith('AS-AUTH-'))
    const docs = await Promise.all(names.map(surfaceId =>
      api(`/jobs/${id}/surfaces/${surfaceId}`, options).catch(() => null)))
    if (stale()) return
    surfaces.value = docs.filter(Boolean)
  } catch (e) {
    if (stale()) return
    surfMissing.value = e.status === 404
    if (e.status !== 404) ElMessage.error('攻击面加载失败: ' + e.message)
  }
  if (!stale()) loading.value = false
}

async function toggleAuth (ref) {
  if (expandedAuth.value === ref) {
    expandedAuth.value = ''
    return
  }
  expandedAuth.value = ref
  if (authDocs.value[ref]) return
  const version = requestVersion
  authLoading.value = true
  try {
    const doc = await api(`/jobs/${jobId.value}/surfaces/${ref}`)
    if (!disposed && version === requestVersion) authDocs.value = { ...authDocs.value, [ref]: doc }
  } catch (e) {
    if (disposed || version !== requestVersion) return
    ElMessage.error(`授权链 ${ref} 加载失败: ` + e.message)
  } finally {
    if (version === requestVersion) authLoading.value = false
  }
}

// same polling pattern as AttackView.waitForStatus
async function waitForStatus (running) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const job = await api(`/jobs/${jobId.value}`)
    if (job.status !== running) return job.status
    await new Promise(resolve => setTimeout(resolve, 1000))
  }
  throw new Error('后台任务超时')
}

async function rerunInputs () {
  if (!jobId.value) return
  rerunningInputs.value = true
  try {
    await api(`/jobs/${jobId.value}/inputs`, { method: 'POST' })
    const status = await waitForStatus('identifying')
    if (status === 'failed') throw new Error('输入识别失败')
    await loadAll()
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    rerunningInputs.value = false
  }
}

async function rerunSurfaces () {
  if (!jobId.value) return
  rerunningSurfaces.value = true
  try {
    await api(`/jobs/${jobId.value}/surfaces`, { method: 'POST' })
    const status = await waitForStatus('surfacing')
    if (status === 'failed') throw new Error('攻击面导出失败')
    await loadAll()
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    rerunningSurfaces.value = false
  }
}

// 任务选择与自动选中由 JobPicker 完成
onBeforeUnmount(() => { disposed = true; requestVersion += 1; loadController?.abort() })
</script>

<style scoped>
.block { margin-bottom: 14px; }
.toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.summary { margin-top: 12px; }
.gate-chip {
  display: inline-flex; align-items: center; gap: 6px;
  height: 26px; padding: 0 11px;
  border: 1px solid color-mix(in srgb, var(--fw-warn) 40%, transparent);
  border-radius: 999px;
  background: color-mix(in srgb, var(--fw-warn) 9%, transparent);
  color: var(--fw-warn); font-size: 12px; cursor: pointer;
}
.gate-chip.err {
  border-color: color-mix(in srgb, var(--fw-danger) 40%, transparent);
  background: color-mix(in srgb, var(--fw-danger) 9%, transparent);
  color: var(--fw-danger);
}
.gate-chip-act { opacity: .75; font-size: 11px; }
.gate-note-list { max-height: 300px; overflow: auto; }
.gate-note-title { margin: 2px 0 8px; font-size: 12.5px; color: var(--fw-text-3); }
.gate-note { margin: 0 0 6px; font-size: 12.5px; color: var(--fw-text-2); }
.gate-note[data-kind='err'] { color: var(--fw-danger); }
.row-between { display: flex; justify-content: space-between; align-items: center; }
.mono { font-family: 'JetBrains Mono', ui-monospace, Consolas, 'Courier New', monospace; }
.muted { color: var(--fw-text-3); font-size: 12px; }
.tag-gap { margin: 2px 6px 2px 0; }

.inputs-layout { display: flex; gap: 12px; align-items: flex-start; }
.side-card { width: 520px; flex-shrink: 0; }
.main-card { flex: 1; min-width: 0; }
.meta-collapse { margin-top: 10px; }
.meta-line { font-size: 11.5px; color: var(--fw-text-3); word-break: break-all; line-height: 1.6; }

.detail h4 { margin: 16px 0 8px; letter-spacing: 1px; color: var(--fw-brand); }
.detail h4:first-child { margin-top: 0; }
.sub-block { margin: 10px 0; }
.sub-title { margin-bottom: 6px; letter-spacing: .5px; }
.file-line { font-size: 12.5px; color: var(--fw-text-2); word-break: break-all; }
.evidence { font-size: 12px; line-height: 1.6; word-break: break-word; }

.dispatch-item {
  padding: 6px 8px; margin-bottom: 6px; border-radius: 6px;
  border: 1px solid color-mix(in srgb, var(--fw-brand) 18%, transparent); background: color-mix(in srgb, var(--fw-brand) 05%, transparent);
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
}

/* 路由链 / 授权链 timeline —— 与 AttackView 链路样式保持一致 */
.chain-v { padding-top: 4px; }
.step { display: flex; align-items: stretch; }
.rail { display: flex; flex-direction: column; align-items: center; width: 20px; flex: none; }
.dot { width: 10px; height: 10px; border-radius: 50%; margin-top: 10px; flex: none; border: 2px solid rgba(28, 43, 58, .8); }
.line { width: 2px; flex: 1 1 auto; background: color-mix(in srgb, var(--fw-brand) 25%, transparent); margin: 2px 0; }
.node-card { flex: 1 1 auto; min-width: 0; margin: 0 0 10px 10px; padding: 8px 10px; border: 1px solid color-mix(in srgb, var(--fw-brand) 25%, transparent); border-radius: 8px; background: var(--fw-surface); }
.node-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.node-name { font-weight: 600; font-size: 13px; }
.node-sub { margin-top: 6px; font-size: 12px; word-break: break-word; }
.stage-tag { border: none; color: var(--fw-surface); font-weight: 600; }
.file-ref { font-size: 11.5px; word-break: break-all; }

.handler-card {
  padding: 10px 12px; border-radius: 8px;
  border: 1px solid rgba(220, 38, 38, .45); background: rgba(220, 38, 38, .07);
  box-shadow: 0 0 12px rgba(220, 38, 38, .12);
}

.actor-row { display: flex; align-items: baseline; gap: 6px; flex-wrap: wrap; margin-bottom: 4px; }
.actor-label { flex: 0 0 90px; font-size: 12px; }
.carrier-table { margin-bottom: 8px; }

.auth-chip { cursor: pointer; }
.auth-panel { margin-top: 8px; padding: 10px; border: 1px dashed rgba(220, 38, 38, .35); border-radius: 8px; }
.auth-applies { margin-bottom: 8px; }
.bypass-alert { margin-top: 8px; }

:deep(.clickable) { cursor: pointer; }
:deep(.el-badge__content) { position: static; transform: none; }

@media (max-width: 900px) {
  .inputs-layout { flex-direction: column; }
  .side-card { width: 100%; }
  .job-select { width: 100%; }
}
</style>
