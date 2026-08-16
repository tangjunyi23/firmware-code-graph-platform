<template>
  <div>
    <!-- toolbar + summary -->
    <el-card shadow="never" class="block">
      <div class="toolbar">
        <el-select v-model="jobId" placeholder="选择任务" class="job-select" @change="loadAll">
          <el-option v-for="job in jobs" :key="job.job_id" :value="job.job_id"
                     :label="`${job.job_id}  ${job.firmware}  (${job.status})`" />
        </el-select>
        <el-button :icon="RefreshCw" :loading="loading" @click="loadAll">刷新</el-button>
        <el-button :icon="Radar" :loading="rerunningInputs" :disabled="!jobId" @click="rerunInputs">重新识别</el-button>
        <el-button :icon="Route" :loading="rerunningSurfaces" :disabled="!jobId" @click="rerunSurfaces">重新导出攻击面</el-button>
      </div>
      <el-descriptions v-if="meta || surfSummary" :column="isNarrow ? 2 : 4" border size="small" class="summary">
        <el-descriptions-item v-if="meta" label="目标">{{ meta.target }}</el-descriptions-item>
        <el-descriptions-item v-if="meta" label="输入数">{{ meta.total_inputs }}</el-descriptions-item>
        <el-descriptions-item v-if="surfSummary" label="攻击面">{{ surfSummary.surfaces }}</el-descriptions-item>
        <el-descriptions-item v-if="surfSummary" label="授权链">{{ surfSummary.auth_chains }}</el-descriptions-item>
        <el-descriptions-item v-if="surfSummary" label="仅静态">{{ surfSummary.static_only }}</el-descriptions-item>
        <el-descriptions-item v-if="meta" label="门禁 1">{{ meta.gate_1 }}</el-descriptions-item>
        <el-descriptions-item v-if="meta" label="门禁 2">{{ meta.gate_2 }}</el-descriptions-item>
      </el-descriptions>
      <el-alert v-for="(g, i) in surfSummary?.gate_errors || []" :key="`ge-${i}`"
                type="error" :closable="false" :title="g" class="gate-alert" />
      <el-alert v-for="(g, i) in surfSummary?.gate_warnings || []" :key="`gw-${i}`"
                type="warning" :closable="false" :title="g" class="gate-alert" />
    </el-card>

    <div class="inputs-layout">
      <!-- left: input list -->
      <el-card class="side-card" shadow="never">
        <template #header>
          <div class="row-between">
            <span>输入列表</span>
            <span class="muted">{{ inputs.length }} 个输入</span>
          </div>
        </template>
        <div v-loading="loading">
          <el-empty v-if="identMissing" description="尚未运行输入识别，可点击上方「重新识别」" :image-size="80" />
          <el-empty v-else-if="!loading && !inputs.length" description="无输入数据" :image-size="80" />
          <el-table v-else :data="inputs" size="small" highlight-current-row
                    @row-click="select" row-class-name="clickable">
            <el-table-column prop="id" label="ID" width="80">
              <template #default="{ row }"><span class="mono">{{ row.id }}</span></template>
            </el-table-column>
            <el-table-column prop="service" label="服务" min-width="110" show-overflow-tooltip />
            <el-table-column prop="protocol" label="协议" width="100" show-overflow-tooltip />
            <el-table-column label="地址" min-width="150">
              <template #default="{ row }">
                <span class="mono">{{ row.address }}:{{ row.port }}/{{ row.transport }}</span>
              </template>
            </el-table-column>
            <el-table-column label="类型" width="70" align="center">
              <template #default="{ row }">
                <el-badge v-if="(row.input_types || []).length" :value="row.input_types.length" type="primary" />
                <span v-else class="muted">—</span>
              </template>
            </el-table-column>
            <el-table-column label="" width="70" align="center">
              <template #default="{ row }">
                <el-tag v-if="surfaceByInput[row.id]" size="small" type="success" effect="plain">
                  {{ surfaceByInput[row.id].surface_id }}
                </el-tag>
                <el-tag v-else-if="row.public" size="small" type="info" effect="plain">公网</el-tag>
              </template>
            </el-table-column>
          </el-table>

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
            <span>输入详情 <span v-if="current" class="mono muted">{{ current.id }}</span></span>
            <el-tag v-if="surface" size="small" type="success">{{ surface.surface_id }}</el-tag>
          </div>
        </template>
        <el-empty v-if="!current" description="从左侧列表选择一个输入" :image-size="80" />
        <div v-else class="detail">
          <!-- 基本信息 -->
          <h4>基本信息</h4>
          <el-descriptions :column="isNarrow ? 2 : 3" border size="small">
            <el-descriptions-item label="服务">{{ current.service }}</el-descriptions-item>
            <el-descriptions-item label="协议">{{ current.protocol }}</el-descriptions-item>
            <el-descriptions-item label="地址">
              <span class="mono">{{ current.address }}:{{ current.port }}/{{ current.transport }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="公网可达">
              <el-tag size="small" :type="current.public ? 'success' : 'info'" effect="plain">
                {{ current.public ? '是' : '否' }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="输入类型" :span="isNarrow ? 2 : 2">
              <el-tag v-for="t in current.input_types || []" :key="t" size="small" effect="plain" class="tag-gap">{{ t }}</el-tag>
              <span v-if="!(current.input_types || []).length" class="muted">—</span>
            </el-descriptions-item>
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

          <!-- 攻击面文档 -->
          <h4>攻击面</h4>
          <template v-if="surface">
            <!-- 路由链 timeline -->
            <div class="sub-title muted">路由链</div>
            <div class="chain-v">
              <div v-for="(hop, index) in surface.routing_path || []" :key="index" class="step">
                <div class="rail">
                  <div class="dot" :style="{ background: stageColor(hop.stage), boxShadow: `0 0 8px ${stageColor(hop.stage)}` }" />
                  <div v-if="index < surface.routing_path.length - 1" class="line" />
                </div>
                <div class="node-card">
                  <div class="node-head">
                    <el-tag size="small" effect="dark" class="stage-tag"
                            :color="stageColor(hop.stage)">{{ hop.stage }}</el-tag>
                    <span v-if="hop.function" class="mono node-name">{{ hop.function }}</span>
                    <span class="mono muted file-ref" :title="hop.file">{{ baseName(hop.file) }}</span>
                  </div>
                  <div v-if="hop.detail" class="node-sub muted">{{ hop.detail }}</div>
                </div>
              </div>
            </div>

            <!-- 终点 handler -->
            <div v-if="surface.final_handler" class="sub-block">
              <div class="sub-title muted">终点 handler</div>
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
                        <div class="dot" :style="{ background: stageColor(hop.stage), boxShadow: `0 0 8px ${stageColor(hop.stage)}` }" />
                        <div v-if="index < authDoc.chain.length - 1" class="line" />
                      </div>
                      <div class="node-card">
                        <div class="node-head">
                          <el-tag size="small" effect="dark" class="stage-tag"
                                  :color="stageColor(hop.stage)">{{ hop.stage }}</el-tag>
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
          <el-empty v-else :description="surfMissing ? '尚未导出攻击面，可点击上方「重新导出攻击面」' : '该输入暂无攻击面文档'"
                    :image-size="70" />
        </div>
      </el-card>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Radar, RefreshCw, Route } from '@lucide/vue'
import { api } from '../api'
import { useNarrowViewport } from '../useNarrowViewport'

const isNarrow = useNarrowViewport()

const jobs = ref([])
const jobId = ref('')
const loading = ref(false)
const rerunningInputs = ref(false)
const rerunningSurfaces = ref(false)

const meta = ref(null)
const inputs = ref([])
const identMissing = ref(false)
const surfSummary = ref(null)
const surfaces = ref([]) // non-AUTH surface docs
const surfMissing = ref(false)

const current = ref(null)

// auth chain docs (lazy loaded)
const authDocs = ref({})
const authLoading = ref(false)
const expandedAuth = ref('')

const STAGE_COLORS = {
  listen: '#2b6ce5', accept: '#2b6ce5', parse: '#b45309',
  normalize: '#16a34a', dispatch: '#7c3aed', handler: '#dc2626',
  'permission-check': '#ea580c'
}

function stageColor (stage) { return STAGE_COLORS[stage] || '#64748f' }
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
    { label: 'dispatchers', items: s.dispatchers || [] },
    { label: 'parsers', items: s.parsers || [] },
    { label: 'normalizers', items: s.normalizers || [] }
  ].filter(g => g.items.length)
})

const authDoc = computed(() => (expandedAuth.value ? authDocs.value[expandedAuth.value] : null))

function select (row) {
  current.value = row
  expandedAuth.value = ''
}

async function loadAll () {
  if (!jobId.value) return
  loading.value = true
  current.value = null
  expandedAuth.value = ''
  authDocs.value = {}
  // identification
  try {
    const ident = await api(`/jobs/${jobId.value}/identification`)
    meta.value = ident.metadata || null
    inputs.value = ident.inputs || []
    identMissing.value = false
    if (inputs.value.length) current.value = inputs.value[0]
  } catch (e) {
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
    const idx = await api(`/jobs/${jobId.value}/surfaces`)
    surfSummary.value = idx.summary || null
    const names = (idx.files || [])
      .map(f => String(f).replace(/\.json$/, ''))
      .filter(id => id.startsWith('AS-') && !id.startsWith('AS-AUTH-'))
    const docs = await Promise.all(names.map(id =>
      api(`/jobs/${jobId.value}/surfaces/${id}`).catch(() => null)))
    surfaces.value = docs.filter(Boolean)
  } catch (e) {
    surfMissing.value = e.status === 404
    if (e.status !== 404) ElMessage.error('攻击面加载失败: ' + e.message)
  }
  loading.value = false
}

async function toggleAuth (ref) {
  if (expandedAuth.value === ref) {
    expandedAuth.value = ''
    return
  }
  expandedAuth.value = ref
  if (authDocs.value[ref]) return
  authLoading.value = true
  try {
    authDocs.value = { ...authDocs.value, [ref]: await api(`/jobs/${jobId.value}/surfaces/${ref}`) }
  } catch (e) {
    ElMessage.error(`授权链 ${ref} 加载失败: ` + e.message)
  } finally {
    authLoading.value = false
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

onMounted(async () => {
  try {
    jobs.value = await api('/jobs')
    const ready = jobs.value.find(job =>
      ['surfaced', 'identified', 'routed', 'attacked', 'graphed', 'done'].includes(job.status))
    jobId.value = (ready || jobs.value[0] || {}).job_id || ''
    if (jobId.value) await loadAll()
  } catch (e) {
    ElMessage.error('加载任务失败: ' + e.message)
  }
})
</script>

<style scoped>
.block { margin-bottom: 14px; }
.toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.job-select { width: min(440px, 100%); }
.summary { margin-top: 12px; }
.gate-alert { margin-top: 10px; }
.row-between { display: flex; justify-content: space-between; align-items: center; }
.mono { font-family: 'JetBrains Mono', ui-monospace, Consolas, 'Courier New', monospace; }
.muted { color: #64748f; font-size: 12px; }
.tag-gap { margin: 2px 6px 2px 0; }

.inputs-layout { display: flex; gap: 12px; align-items: flex-start; }
.side-card { width: 520px; flex-shrink: 0; }
.main-card { flex: 1; min-width: 0; }
.meta-collapse { margin-top: 10px; }
.meta-line { font-size: 11.5px; color: #64748f; word-break: break-all; line-height: 1.6; }

.detail h4 { margin: 16px 0 8px; letter-spacing: 1px; color: #2b6ce5; }
.detail h4:first-child { margin-top: 0; }
.sub-block { margin: 10px 0; }
.sub-title { margin-bottom: 6px; letter-spacing: .5px; }
.file-line { font-size: 12.5px; color: #3d5470; word-break: break-all; }
.evidence { font-size: 12px; line-height: 1.6; word-break: break-word; }

.dispatch-item {
  padding: 6px 8px; margin-bottom: 6px; border-radius: 6px;
  border: 1px solid rgba(43, 108, 229, .18); background: rgba(43, 108, 229, .05);
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
}

/* 路由链 / 授权链 timeline —— 与 AttackView 链路样式保持一致 */
.chain-v { padding-top: 4px; }
.step { display: flex; align-items: stretch; }
.rail { display: flex; flex-direction: column; align-items: center; width: 20px; flex: none; }
.dot { width: 10px; height: 10px; border-radius: 50%; margin-top: 10px; flex: none; border: 2px solid rgba(28, 43, 58, .8); }
.line { width: 2px; flex: 1 1 auto; background: rgba(43, 108, 229, .25); margin: 2px 0; }
.node-card { flex: 1 1 auto; min-width: 0; margin: 0 0 10px 10px; padding: 8px 10px; border: 1px solid rgba(43, 108, 229, .25); border-radius: 8px; background: #ffffff; }
.node-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.node-name { font-weight: 600; font-size: 13px; }
.node-sub { margin-top: 6px; font-size: 12px; word-break: break-word; }
.stage-tag { border: none; color: #ffffff; font-weight: 600; }
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
