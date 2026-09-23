<template>
  <div>
    <header class="ins-head">
      <div class="ins-head-row">
        <h1 class="ins-title">
          <span class="ins-ico"><component :is="NAV_ICONS.Aim" :size="18" /></span>
          攻击面
        </h1>
        <div class="ins-actions">
          <JobPicker v-model="jobId" :prefer="['surfaced', 'routed', 'attacked', 'graphed']" @change="loadAll" />
          <el-button :icon="RefreshCw" :loading="loading" @click="loadAll">刷新</el-button>
          <el-button :icon="Radar" :loading="runningAttack" @click="rerunAttack">重算攻击面</el-button>
          <el-button :icon="Route" :loading="runningRoutes" @click="rerunRoutes">扫描路由</el-button>
        </div>
      </div>
      <p class="ins-sub">source → sink 候选路径评分与动态覆盖交叉验证，点行展开完整调用链。</p>
      <div v-if="attackSummary" class="ins-stats">
        <span class="stat-chip">输入源 <b>{{ attackSummary.sources }}</b></span>
        <span class="stat-chip">候选汇 <b>{{ attackSummary.sinks }}</b></span>
        <span class="stat-chip accent">候选路径 <b>{{ attackSummary.path_candidates }}</b></span>
        <span class="stat-chip">Top 路径 <b>{{ attackSummary.paths_returned }}</b></span>
        <span class="stat-chip">有效 trace <b>{{ cross.traces_considered ?? 0 }}</b></span>
        <span class="stat-chip">观测函数 <b>{{ cross.observed_functions ?? 0 }}</b></span>
        <span class="stat-chip accent">完整链观测 <b>{{ cross.verified_paths ?? 0 }}</b></span>
      </div>
    </header>

    <el-card shadow="never" class="block">
      <template #header>
        <div class="row-between">
          <span>攻击路径</span>
          <span class="muted">{{ paths.length }} 条 · 点击行查看详情</span>
        </div>
      </template>
      <div class="toolbar filters">
        <el-select v-model="sourceFilter" clearable placeholder="输入源" class="filter-select">
          <el-option v-for="item in sourceKinds" :key="item" :value="item" :label="item" />
        </el-select>
        <el-select v-model="sinkFilter" clearable placeholder="候选汇" class="filter-select">
          <el-option v-for="item in sinkKinds" :key="item" :value="item" :label="item" />
        </el-select>
        <span class="switch-label">仅完整链观测</span>
        <el-switch v-model="verifiedOnly" @change="loadPaths" />
        <el-button type="primary" :icon="Search" :loading="loadingPaths" @click="loadPaths">查询</el-button>
      </div>
      <el-table :data="paths" size="small" v-loading="loadingPaths"
        highlight-current-row @row-click="openPath" class="path-table">
        <el-table-column label="评分" prop="score" width="90" sortable>
          <template #default="{ row }">
            <span class="score-cell" :style="{ color: scoreColor(row.score) }">{{ row.score.toFixed(2) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="路径" min-width="300">
          <template #default="{ row }">
            <span class="chain-preview">
              <template v-for="(node, i) in chainPreview(row)" :key="`cp-${i}`">
                <span v-if="i > 0" class="cp-arrow">→</span>
                <span
                  class="mono cp-node"
                  :class="{ 'cp-src': (node.asrc || []).length, 'cp-sink': (node.asink || []).length }"
                >{{ displayName(node) }}</span>
              </template>
              <span v-if="chainHidden(row)" class="cp-more">+{{ chainHidden(row) }} 跳</span>
            </span>
          </template>
        </el-table-column>
        <el-table-column label="输入源" min-width="190">
          <template #default="{ row }">
            <span class="mono">{{ displayName(row.source) }}</span>
            <el-tag v-for="tag in row.source.asrc || []" :key="tag" size="small" type="warning" class="tag-gap">{{ tag }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="候选汇" min-width="190">
          <template #default="{ row }">
            <span class="mono">{{ displayName(row.sink) }}</span>
            <el-tag v-for="tag in row.sink.asink || []" :key="tag" size="small" type="danger" class="tag-gap">{{ tag }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="跳数" prop="edge_count" width="70" align="right" />
        <el-table-column label="AI 分诊" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.ai_review && row.ai_review.priority"
                    size="small" :type="priorityType(row.ai_review.priority)"
                    :effect="row.ai_review.priority === 'noise' ? 'plain' : 'dark'">
              {{ row.ai_review.priority }}
            </el-tag>
            <span v-else class="muted">—</span>
          </template>
        </el-table-column>
        <el-table-column label="动态状态" width="130">
          <template #default="{ row }">
            <el-tag v-if="row.verified_reachable" size="small" type="success">完整链观测</el-tag>
            <el-tag v-else-if="row.observed_node_count" size="small" type="warning">部分命中 {{ row.observed_node_count }}</el-tag>
            <span v-else class="muted">未观测</span>
          </template>
        </el-table-column>
        <el-table-column label="" width="86" align="center">
          <template #default="{ row }">
            <el-button size="small" text type="primary" @click.stop="openPath(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-if="!loadingPaths && jobId && paths.length === 0" description="无匹配攻击路径" />
    </el-card>

    <!-- path detail drawer -->
    <el-drawer v-model="drawerVisible" :size="drawerSize" destroy-on-close>
      <template #header>
        <div class="drawer-head">
          <span class="drawer-title">攻击路径详情</span>
          <span v-if="activePath" class="mono muted">{{ activePath.path_id }}</span>
        </div>
      </template>
      <div v-if="activePath" class="path-detail">
        <!-- score block -->
        <div class="score-panel">
          <div class="score-left">
            <div class="score-num" :style="{ color: scoreColor(activePath.score) }">{{ activePath.score.toFixed(2) }}</div>
            <el-progress :percentage="scorePct(activePath.score)" :stroke-width="8"
              :show-text="false" :color="scoreColor(activePath.score)" class="score-bar" />
          </div>
          <div class="score-facts">
            <div>跳数 <b>{{ activePath.edge_count }}</b>（每跳 −0.22）</div>
            <div>消毒函数 <b>{{ (activePath.sanitizers || []).length }}</b>（每个 −0.45）</div>
            <div>二进制 <span class="mono">{{ (activePath.binary_md5 || '').slice(0, 8) }}</span></div>
          </div>
        </div>

        <!-- dynamic evidence -->
        <el-alert v-if="activePath.verified_reachable" type="success" :closable="false" class="trace-alert">
          <template #title>
            完整链被同一次覆盖运行观测
            <el-tag v-for="t in activePath.trace_ids || []" :key="t" size="small" effect="plain" class="trace-tag mono">{{ t }}</el-tag>
          </template>
        </el-alert>
        <el-alert v-else-if="activePath.observed_node_count" type="warning" :closable="false" class="trace-alert">
          <template #title>
            部分节点被观测（{{ activePath.observed_node_count }} 个）
            <el-tag v-for="t in activePath.observed_trace_ids || []" :key="t" size="small" effect="plain" class="trace-tag mono">{{ t }}</el-tag>
          </template>
        </el-alert>
        <el-alert v-else type="info" :closable="false" class="trace-alert" title="无运行时覆盖证据（static-only）" />
        <el-alert v-if="activePath.ai_review" type="warning" :closable="false" class="trace-alert"
          title="模型分诊，不是漏洞结论">
          <div>优先级 <b>{{ activePath.ai_review.priority }}</b>
            <span v-if="activePath.ai_review.vuln_class_hint"> · {{ activePath.ai_review.vuln_class_hint }}</span>
            <span v-if="activePath.ai_review.cwe_hint"> · {{ activePath.ai_review.cwe_hint }}</span>
            <span v-if="activePath.ai_review.dataflow"> · 数据流 {{ activePath.ai_review.dataflow }}</span>
          </div>
          <div v-if="activePath.ai_review.reason" class="muted">{{ activePath.ai_review.reason }}</div>
        </el-alert>

        <!-- chain timeline -->
        <div class="chain-v">
          <div v-for="(node, index) in activePath.chain" :key="`${node.addr}-${index}`" class="step">
            <div class="rail">
              <div class="dot" :class="dotClass(node)" />
              <div v-if="index < activePath.chain.length - 1" class="line" />
            </div>
            <div class="node-card" :class="{ source: (node.asrc || []).length, sink: (node.asink || []).length }">
              <div class="node-head">
                <span class="mono node-name">{{ displayName(node) }}</span>
                <span class="mono muted">{{ node.addr }}</span>
                <el-button size="small" text type="primary" :icon="FileCode"
                  @click="showSource(activePath.binary_md5, node)">源码</el-button>
              </div>
              <div class="node-tags">
                <el-tag v-for="tag in node.asrc || []" :key="`s-${tag}`" size="small" type="warning">source: {{ tag }}</el-tag>
                <el-tag v-for="tag in node.asink || []" :key="`k-${tag}`" size="small" type="danger">sink: {{ tag }}</el-tag>
                <el-tag v-if="node.libc_equiv" size="small" type="danger" effect="plain">libc: {{ node.libc_equiv }}</el-tag>
                <template v-if="nodeExtra(node)">
                  <el-tag v-if="nodeExtra(node).verified_reachable" size="small" type="success">完整链观测</el-tag>
                  <el-tag v-else-if="nodeExtra(node).observed_in_trace" size="small" type="success" effect="plain">trace 命中</el-tag>
                  <el-tag v-if="nodeExtra(node).domain" size="small" type="info" effect="plain">{{ nodeExtra(node).domain }}</el-tag>
                  <el-tag v-for="tag in nodeExtra(node).tags || []" :key="tag" size="small" effect="plain">{{ tag }}</el-tag>
                </template>
              </div>
              <div v-if="nodeExtra(node) && nodeExtra(node).ai_reason" class="node-sub muted">
                {{ nodeExtra(node).ai_reason }}
              </div>
            </div>
          </div>
        </div>
      </div>
    </el-drawer>

    <!-- function source dialog -->
    <el-dialog v-model="srcVisible" width="880px" append-to-body>
      <template #header>
        <div class="src-head">
          <span class="mono">{{ srcNode ? displayName(srcNode) : '' }}</span>
          <span class="mono muted">{{ srcNode ? srcNode.addr : '' }}</span>
          <el-radio-group v-model="srcKind" size="small" @change="loadSource">
            <el-radio-button value="hexrays">伪代码</el-radio-button>
            <el-radio-button value="asm">汇编</el-radio-button>
          </el-radio-group>
        </div>
      </template>
      <CodeViewer :code="srcCode" :loading="srcLoading" :language="srcKind === 'asm' ? 'asm' : 'c'" />
    </el-dialog>

    <el-card shadow="never" class="block">
      <template #header>
        <div class="row-between">
          <span>静态路由映射</span>
          <span class="muted">{{ routeSummary.inserted ?? 0 }} 条 ROUTE 边</span>
        </div>
      </template>
      <div class="toolbar filters">
        <el-input v-model="routePattern" clearable placeholder="URL 路径" class="route-search" @keyup.enter="loadRoutes" />
        <el-button type="primary" :icon="Search" :loading="loadingRoutes" @click="loadRoutes">查询</el-button>
      </div>
      <el-table :data="routes" size="small" v-loading="loadingRoutes">
        <el-table-column prop="route" label="URL" min-width="240">
          <template #default="{ row }"><span class="mono">{{ row.route }}</span></template>
        </el-table-column>
        <el-table-column prop="method" label="方法" width="90" />
        <el-table-column prop="handler_name" label="处理函数" min-width="180">
          <template #default="{ row }"><span class="mono">{{ row.handler_name || row.handler_addr }}</span></template>
        </el-table-column>
        <el-table-column prop="handler_addr" label="地址" width="110">
          <template #default="{ row }"><span class="mono">{{ row.handler_addr }}</span></template>
        </el-table-column>
        <el-table-column prop="arch" label="架构" width="90" />
        <el-table-column label="置信度" width="90" align="right">
          <template #default="{ row }">{{ Number(row.confidence || 0).toFixed(2) }}</template>
        </el-table-column>
      </el-table>
      <el-empty v-if="!loadingRoutes && jobId && routes.length === 0" description="未发现静态 URL 路由表" />
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { FileCode, Radar, RefreshCw, Route, Search } from '@lucide/vue'
import { api } from '../api'
import CodeViewer from '../components/CodeViewer.vue'
import JobPicker from '../components/JobPicker.vue'
import { NAV_ICONS } from '../workbench/icons.js'
import { useNarrowViewport } from '../useNarrowViewport'

const isNarrow = useNarrowViewport()

const jobId = ref('')
const loading = ref(false)
const loadingPaths = ref(false)
const loadingRoutes = ref(false)
const runningAttack = ref(false)
const runningRoutes = ref(false)
const attackSummary = ref(null)
const cross = ref({})
const paths = ref([])
const routes = ref([])
const routeSummary = ref({})
const sourceFilter = ref('')
const sinkFilter = ref('')
const verifiedOnly = ref(false)
const routePattern = ref('')

// path detail drawer
const drawerVisible = ref(false)
const activePath = ref(null)
const funcMap = ref(new Map())

// function source dialog
const srcVisible = ref(false)
const srcLoading = ref(false)
const srcNode = ref(null)
const srcMd5 = ref('')
const srcKind = ref('hexrays')
const srcCode = ref('')

const drawerSize = computed(() => (isNarrow.value ? '96%' : '660px'))

const sourceKinds = computed(() => Object.keys(attackSummary.value?.source_counts || {}))
const sinkKinds = computed(() => Object.keys(attackSummary.value?.sink_counts || {}))

function displayName (node) {
  return node.ai_name || node.name || node.addr
}
// 表格内只露链路两端（source + sink），中间收敛成 "+N 跳"，详情抽屉里看全链
function chainPreview (row) {
  const chain = row.chain || []
  if (chain.length <= 2) return chain
  return [chain[0], chain[chain.length - 1]]
}
function chainHidden (row) {
  const chain = row.chain || []
  return chain.length > 2 ? chain.length - 2 : 0
}
function scorePct (score) {
  return Math.max(4, Math.min(100, Math.round((score / 5.5) * 100)))
}
function scoreColor (score) {
  if (score >= 5) return '#dc2626'
  if (score >= 4) return '#b45309'
  return '#16a34a'
}
function priorityType (p) {
  if (p === 'P0') return 'danger'
  if (p === 'P1') return 'warning'
  if (p === 'P2') return 'info'
  return 'info'
}
function dotClass (node) {
  const isSrc = (node.asrc || []).length > 0
  const isSink = (node.asink || []).length > 0
  if (isSrc && isSink) return 'dot-both'
  if (isSrc) return 'dot-src'
  if (isSink) return 'dot-sink'
  return 'dot-mid'
}
function nodeExtra (node) {
  if (!activePath.value) return null
  const key = `${activePath.value.binary_md5}:${String(node.addr).toLowerCase()}`
  return funcMap.value.get(key) || null
}

function openPath (row) {
  activePath.value = row
  drawerVisible.value = true
}

async function showSource (md5, node) {
  srcMd5.value = md5
  srcNode.value = node
  srcKind.value = 'hexrays'
  srcVisible.value = true
  await loadSource()
}

async function loadSource () {
  if (!srcNode.value) return
  srcLoading.value = true
  const base = `/jobs/${jobId.value}/functions/${srcMd5.value}/${srcNode.value.addr}/source`
  const query = srcKind.value === 'asm' ? '?asm=1' : ''
  try {
    srcCode.value = await api(base + query)
  } catch (error) {
    if (error.status === 404 && srcKind.value === 'asm') {
      try {
        const c = await api(base)
        srcCode.value = `// 该函数没有汇编导出，已显示伪代码。\n${c}`
      } catch (error2) {
        srcCode.value = `（源码加载失败：${error2.message}）`
      }
    } else {
      srcCode.value = `（源码加载失败：${error.message}）`
    }
  } finally {
    srcLoading.value = false
  }
}

async function loadPaths () {
  if (!jobId.value) return
  loadingPaths.value = true
  try {
    const result = await api('/graph/query', { method: 'POST', body: {
      job_id: jobId.value, op: 'attack_surface', source: sourceFilter.value,
      sink: sinkFilter.value, verified_only: verifiedOnly.value, limit: 100
    } })
    paths.value = result.paths || []
  } catch (error) {
    paths.value = []
    if (error.status !== 404) ElMessage.error('攻击路径加载失败: ' + error.message)
  } finally {
    loadingPaths.value = false
  }
}

async function loadFunctions () {
  if (!jobId.value) return
  try {
    const data = await api(`/jobs/${jobId.value}/functions`)
    const map = new Map()
    for (const fn of data.functions || []) {
      map.set(`${fn.binary}:${String(fn.addr).toLowerCase()}`, fn)
    }
    funcMap.value = map
  } catch { /* functions page data is optional enrichment */ }
}

async function loadRoutes () {
  if (!jobId.value) return
  loadingRoutes.value = true
  try {
    const result = await api('/graph/query', { method: 'POST', body: {
      job_id: jobId.value, op: 'routes', pattern: routePattern.value, limit: 200
    } })
    routes.value = result.routes || []
    routeSummary.value = result.summary || {}
  } catch (error) {
    routes.value = []
    routeSummary.value = {}
    if (error.status !== 404) ElMessage.error('路由映射加载失败: ' + error.message)
  } finally {
    loadingRoutes.value = false
  }
}

async function loadAll () {
  if (!jobId.value) return
  loading.value = true
  try {
    const attack = await api(`/jobs/${jobId.value}/attack`)
    attackSummary.value = attack.summary?.analysis || null
    cross.value = attack.summary?.cross_validation || {}
  } catch (error) {
    attackSummary.value = null
    cross.value = {}
    if (error.status !== 404) ElMessage.error('攻击面摘要加载失败: ' + error.message)
  }
  await Promise.all([loadPaths(), loadRoutes(), loadFunctions()])
  loading.value = false
}

async function waitForStatus (running) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const job = await api(`/jobs/${jobId.value}`)
    if (job.status !== running) return job.status
    await new Promise(resolve => setTimeout(resolve, 1000))
  }
  throw new Error('后台任务超时')
}

async function rerunAttack () {
  if (!jobId.value) return
  runningAttack.value = true
  try {
    await api(`/jobs/${jobId.value}/attack`, { method: 'POST' })
    const status = await waitForStatus('attacking')
    if (status === 'failed') throw new Error('攻击面分析失败')
    await loadAll()
  } catch (error) {
    ElMessage.error(error.message)
  } finally {
    runningAttack.value = false
  }
}

async function rerunRoutes () {
  if (!jobId.value) return
  runningRoutes.value = true
  try {
    await api(`/jobs/${jobId.value}/routes`, { method: 'POST' })
    const status = await waitForStatus('routing')
    if (status === 'failed') throw new Error('路由扫描失败')
    await loadRoutes()
  } catch (error) {
    ElMessage.error(error.message)
  } finally {
    runningRoutes.value = false
  }
}

// 任务选择与自动选中由 JobPicker 完成，change 后 loadAll
</script>

<style scoped>
.block { margin-bottom: 14px; }
.row-between { display: flex; justify-content: space-between; align-items: center; }
.filters { margin-bottom: 12px; }
.filter-select { width: 180px; }
.route-search { width: min(360px, 100%); }
.switch-label { color: var(--fw-text-3); font-size: 13px; }
.path-table :deep(.el-table__row) { cursor: pointer; }
.score-cell { font-weight: 700; font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace; }
.tag-gap { margin-left: 6px; }

/* 表格内链路预览：两端函数 + 折叠中间跳数 */
.chain-preview {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  max-width: 100%;
  overflow: hidden;
  white-space: nowrap;
}
.cp-node {
  overflow: hidden;
  text-overflow: ellipsis;
  font-size: 12px;
  color: var(--fw-text-2);
  max-width: 150px;
}
.cp-node.cp-src { color: var(--fw-brand); }
.cp-node.cp-sink { color: #d946ef; font-weight: 600; }
.cp-arrow { color: var(--fw-text-3); font-size: 11px; flex: none; }
.cp-more {
  flex: none;
  font-size: 11px;
  padding: 0 7px;
  border-radius: 999px;
  background: var(--fw-fill);
  color: var(--fw-brand);
  line-height: 18px;
}

/* path detail drawer */
.drawer-head { display: flex; align-items: baseline; gap: 10px; }
.drawer-title { font-weight: 600; font-size: 15px; letter-spacing: 1px; color: var(--fw-brand); }
.path-detail { padding-bottom: 24px; }
.score-panel { display: flex; gap: 18px; align-items: center; padding: 4px 0 12px; }
.score-left { flex: 0 0 180px; }
.score-num { font-size: 28px; font-weight: 700; font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace; line-height: 1.1; }
.score-bar { margin-top: 8px; }
.score-facts { font-size: 12px; color: var(--fw-text-3); display: flex; flex-direction: column; gap: 4px; }
.trace-alert { margin-bottom: 12px; }
.trace-tag { margin-left: 6px; }

.chain-v { padding-top: 4px; }
.step { display: flex; align-items: stretch; }
.rail { display: flex; flex-direction: column; align-items: center; width: 20px; flex: none; }
.dot { width: 10px; height: 10px; border-radius: 50%; margin-top: 10px; flex: none; border: 2px solid rgba(28, 43, 58, .8); box-shadow: 0 0 6px color-mix(in srgb, var(--fw-brand) 35%, transparent); }
.dot-src { background: var(--fw-brand); box-shadow: 0 0 8px color-mix(in srgb, var(--fw-brand) 55%, transparent); }
.dot-sink { background: #d946ef; box-shadow: 0 0 8px rgba(217, 70, 239, .55); }
.dot-both { background: linear-gradient(135deg, var(--fw-brand) 50%, #d946ef 50%); box-shadow: 0 0 8px rgba(217, 70, 239, .55); }
.dot-mid { background: #8b9cb3; }
.line { width: 2px; flex: 1 1 auto; background: color-mix(in srgb, var(--fw-brand) 25%, transparent); margin: 2px 0; }
.node-card { flex: 1 1 auto; min-width: 0; margin: 0 0 10px 10px; padding: 8px 10px; border: 1px solid color-mix(in srgb, var(--fw-brand) 25%, transparent); border-radius: 8px; background: var(--fw-surface); }
.node-card.source { border-left: 3px solid var(--fw-brand); }
.node-card.sink { border-left: 3px solid #d946ef; }
.node-card.source.sink { border-left: 3px solid; border-image: linear-gradient(to bottom, var(--fw-brand), #d946ef) 1; }
.node-head { display: flex; align-items: center; gap: 8px; }
.node-name { font-weight: 600; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.node-head .el-button { margin-left: auto; flex: none; }
.node-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.node-sub { margin-top: 6px; font-size: 12px; }

/* source dialog */
.src-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.src-head .el-radio-group { margin-left: auto; }
.src-hint { margin-bottom: 10px; }
@media (max-width: 720px) {
  .job-select, .filter-select, .route-search { width: 100%; }
  .summary :deep(.el-descriptions__body) { overflow-x: auto; }
  .score-panel { flex-direction: column; align-items: stretch; }
  .score-left { flex: none; }
}
</style>
