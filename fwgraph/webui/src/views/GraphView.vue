<template>
  <div>
    <header class="ins-head">
      <div class="ins-head-row">
        <h1 class="ins-title">
          <span class="ins-ico"><component :is="NAV_ICONS.Share" :size="18" /></span>
          图谱
        </h1>
        <div class="ins-actions">
          <JobPicker v-model="jobId" :prefer="['surfaced', 'graphed', 'attacked', 'routed']" />
          <el-button :icon="RefreshCw" :loading="layoutLoading" @click="loadLayout">刷新图谱</el-button>
        </div>
      </div>
      <p class="ins-sub">调用链追踪、敏感调用点与攻击路径检索，配合关系图可视化定位风险函数。</p>
    </header>

    <el-card shadow="never" class="block">
      <template #header>
        <div class="row-between">
          <span>图谱检索</span>
          <span v-if="resultMeta" class="muted">{{ resultMeta }}</span>
        </div>
      </template>
      <div class="toolbar">
        <el-select v-model="op" style="width: 150px">
          <el-option value="trace" label="调用链追踪" />
          <el-option value="snippet" label="函数源码" />
          <el-option value="dangerous" label="敏感调用点" />
          <el-option value="attack_surface" label="攻击路径" />
          <el-option value="routes" label="路由映射" />
          <el-option value="search" label="节点搜索" />
        </el-select>
        <el-input
          v-if="op === 'trace' || op === 'snippet' || op === 'search' || op === 'routes'"
          v-model="keyword"
          :placeholder="op === 'routes' ? 'URL 路径（可留空）' : (op === 'search' ? '搜索模式（节点名）' : '函数名（如 sub_401000）')"
          style="width: 280px"
          clearable
          @keyup.enter="runQuery"
        />
        <el-select v-if="op === 'trace'" v-model="direction" style="width: 130px">
          <el-option value="both" label="双向" />
          <el-option value="inbound" label="调用者" />
          <el-option value="outbound" label="被调者" />
        </el-select>
        <el-button type="primary" :loading="querying" @click="runQuery">查询</el-button>
      </div>

      <!-- 查询失败 -->
      <div v-if="queryError" class="q-error">
        <p>{{ queryError }}</p>
        <span>请确认任务已完成图谱构建、函数名确实存在，然后重试。</span>
      </div>

      <!-- 敏感调用点：表格 -->
      <template v-else-if="view === 'table'">
        <el-table :data="tableRows" size="small" max-height="420">
          <el-table-column
            v-for="(col, ci) in tableCols"
            :key="col.raw"
            :label="col.label"
            :min-width="ci === 0 ? 220 : 180"
            show-overflow-tooltip
          >
            <template #default="{ row }">
              <span :class="{ mono: looksLikeSymbol(row[col.raw]) }">{{ row[col.raw] }}</span>
            </template>
          </el-table-column>
        </el-table>
      </template>

      <!-- 攻击路径：摘要 + 路径卡 -->
      <template v-else-if="view === 'paths'">
        <div class="as-stats">
          <span class="stat-chip">入口 {{ result.summary?.sources ?? '—' }}</span>
          <span class="stat-chip">危险汇点 {{ result.summary?.sinks ?? '—' }}</span>
          <span class="stat-chip">候选路径 {{ result.summary?.path_candidates ?? '—' }}</span>
          <span class="stat-chip">返回 {{ result.total ?? result.paths.length }} 条</span>
        </div>
        <div class="path-list">
          <div v-for="(p, i) in result.paths" :key="p.path_id || i" class="path-card">
            <div class="path-top">
              <span class="path-rank">#{{ i + 1 }}</span>
              <span class="path-score">评分 {{ fmtScore(p.score) }}</span>
              <span class="muted">{{ p.edge_count ?? chainNames(p).length }} 跳</span>
            </div>
            <div class="path-chain">
              <template v-for="(n, ni) in chainNames(p)" :key="ni">
                <span class="cp-node" :class="{ src: chainNames(p).length > 1 && ni === 0, snk: chainNames(p).length > 1 && ni === chainNames(p).length - 1 }">{{ n }}</span>
                <span v-if="ni < chainNames(p).length - 1" class="cp-arrow">→</span>
              </template>
            </div>
          </div>
        </div>
      </template>

      <!-- 路由映射 -->
      <template v-else-if="view === 'routes'">
        <div class="as-stats">
          <span class="stat-chip">识别路由 {{ result.summary?.routes ?? '—' }}</span>
          <span class="stat-chip">已入库 {{ result.summary?.inserted ?? '—' }}</span>
          <span class="stat-chip">未匹配 {{ result.summary?.unmatched ?? '—' }}</span>
        </div>
        <el-table v-if="result.routes.length" :data="result.routes" size="small" max-height="420">
          <el-table-column
            v-for="col in routeCols"
            :key="col"
            :prop="col"
            :label="colLabel(col)"
            min-width="150"
            show-overflow-tooltip
          >
            <template #default="{ row }">
              <span :class="{ mono: looksLikeSymbol(String(row[col] ?? '')) }">{{ row[col] }}</span>
            </template>
          </el-table-column>
        </el-table>
        <p v-else class="muted q-empty">该固件未识别出 URL 路由（可能不含 HTTP 服务）。</p>
      </template>

      <!-- 节点搜索 -->
      <template v-else-if="view === 'search'">
        <el-table :data="result.results.slice(0, 50)" size="small" max-height="420">
          <el-table-column label="名称" min-width="220" show-overflow-tooltip>
            <template #default="{ row }"><span class="mono">{{ row.name }}</span></template>
          </el-table-column>
          <el-table-column label="限定名" min-width="260" show-overflow-tooltip>
            <template #default="{ row }"><span class="mono muted">{{ row.qualified_name }}</span></template>
          </el-table-column>
          <el-table-column label="类型" width="110">
            <template #default="{ row }">
              <el-tag size="small" effect="plain">{{ typeLabel(row.label) }}</el-tag>
            </template>
          </el-table-column>
        </el-table>
        <p v-if="result.has_more" class="muted q-empty">仅显示前 50 条，共 {{ result.total }} 个匹配。</p>
      </template>

      <!-- 函数源码 -->
      <pre v-else-if="view === 'code'" class="result mono">{{ codeText }}</pre>

      <!-- 调用链 -->
      <template v-else-if="view === 'chain'">
        <div class="path-chain flat">
          <template v-for="(n, ni) in chainNames(result)" :key="ni">
            <span class="cp-node">{{ n }}</span>
            <span v-if="ni < chainNames(result).length - 1" class="cp-arrow">→</span>
          </template>
        </div>
      </template>

      <!-- 兜底：折叠原始数据 -->
      <template v-else-if="result">
        <el-button size="small" text type="primary" @click="rawOpen = !rawOpen">
          {{ rawOpen ? '收起原始数据' : '查看原始数据' }}
        </el-button>
        <pre v-if="rawOpen" class="result mono">{{ JSON.stringify(result, null, 2) }}</pre>
      </template>

      <p v-else-if="queried" class="muted q-empty">没有匹配的结果。</p>
    </el-card>

    <el-card shadow="never" class="block">
      <template #header>
        <div class="row-between">
          <span>关系图</span>
          <span class="muted" v-if="layout">{{ layout.total_nodes }} 节点 / {{ layout.edges.length }} 边</span>
        </div>
      </template>
      <div class="toolbar">
        <el-checkbox-group v-model="enabledTypes" size="small">
          <el-checkbox v-for="t in typeOptions" :key="t.value" :value="t.value">
            <span class="type-dot" :style="{ background: typeColor(t.value) }"></span>{{ t.label }}
          </el-checkbox>
        </el-checkbox-group>
        <el-input v-model="highlight" placeholder="按名称高亮（如 sub_43785C）"
                  style="width: 240px" clearable />
        <el-button size="small" @click="fitSignal++">适应视图</el-button>
        <span class="edge-legend muted">
          <i class="edge-line call"></i>调用
          <i class="edge-line def"></i>定义
          <i class="edge-line other"></i>其他
        </span>
      </div>
      <CodeGraphCanvas
        v-if="layout"
        :nodes="layout.nodes"
        :edges="layout.edges"
        :types="enabledTypes"
        :highlight="highlight"
        :fitSignal="fitSignal"
        @select="onNodeSelect"
      />
      <p v-else class="muted">{{ layoutLoading ? '图谱加载中…' : '选择任务后自动加载图谱；暂无数据' }}</p>
      <div v-if="selectedNode" class="node-bar mono">
        <el-tag size="small" effect="plain">
          <span class="type-dot" :style="{ background: typeColor(selectedNode.label) }"></span>
          {{ typeLabel(selectedNode.label) }}
        </el-tag>
        <span class="node-name">{{ selectedNode.name }}</span>
        <span class="muted">{{ selectedNode.file_path }}</span>
        <span class="muted" v-if="selectedNode.in_calls != null">被调 {{ selectedNode.in_calls }} 次</span>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { RefreshCw } from '@lucide/vue'
import { api } from '../api'
import CodeGraphCanvas from '../components/CodeGraphCanvas.vue'
import JobPicker from '../components/JobPicker.vue'
import { NAV_ICONS } from '../workbench/icons.js'

const jobId = ref('')
const op = ref('trace')
const keyword = ref('')
const direction = ref('both')
const querying = ref(false)
const queried = ref(false)
const result = ref(null)
const queryError = ref('')
const rawOpen = ref(false)

const layout = ref(null)
const layoutLoading = ref(false)
const enabledTypes = ref(['File', 'Module', 'Function', 'Project', 'Branch', 'Folder'])
const highlight = ref('')
const fitSignal = ref(0)
const selectedNode = ref(null)

const TYPE_NAMES = {
  File: '文件', Module: '模块', Function: '函数',
  Project: '项目', Branch: '分支', Folder: '目录',
}
// 与全站 Teal 系一致的语义色板（深浅主题均可辨）
const TYPE_COLORS = {
  File: '#f59e0b', Module: '#2dd4bf', Function: '#34d399',
  Project: '#a78bfa', Branch: '#fb923c', Folder: '#38bdf8',
}
function typeColor (value) { return TYPE_COLORS[value] || 'var(--fw-brand)' }
const typeOptions = computed(() => {
  const present = new Set((layout.value?.nodes || []).map(n => n.label))
  return Object.entries(TYPE_NAMES)
    .filter(([value]) => present.size === 0 || present.has(value))
    .map(([value, label]) => ({ value, label }))
})
function typeLabel (value) { return TYPE_NAMES[value] || value }

// ---- 结果归一化渲染 ---------------------------------------------------------

// 表格列汉化（f.* = 调用方函数，g.* = 被调用的危险函数）
const COLUMN_LABELS = {
  'f.name': '调用函数', 'f.file_path': '所在文件', 'g.name': '敏感函数',
  name: '名称', file_path: '所在文件', url: 'URL', method: '方法',
  handler: '处理函数', function: '函数', label: '类型'
}
function colLabel (col) { return COLUMN_LABELS[col] || col }

const view = computed(() => {
  const r = result.value
  if (!r || typeof r !== 'object' || Array.isArray(r)) return typeof r === 'string' ? 'code' : null
  if (Array.isArray(r.columns) && Array.isArray(r.rows)) return 'table'
  if (Array.isArray(r.paths)) return 'paths'
  if (Array.isArray(r.routes)) return 'routes'
  if (Array.isArray(r.results)) return 'search'
  if (r.code || r.snippet || r.source) return 'code'
  if (Array.isArray(r.nodes)) return 'chain'
  return 'raw'
})
const tableCols = computed(() =>
  (result.value?.columns || []).map((c) => ({ raw: c, label: colLabel(c) })))
const tableRows = computed(() =>
  (result.value?.rows || []).map((cells) => {
    const row = {}
    ;(result.value?.columns || []).forEach((c, i) => { row[c] = cells[i] })
    return row
  }))
const routeCols = computed(() => {
  const first = result.value?.routes?.[0]
  return first ? Object.keys(first).slice(0, 5) : []
})
const codeText = computed(() => {
  const r = result.value
  if (typeof r === 'string') return r
  return r?.code || r?.snippet || r?.source || ''
})
const resultMeta = computed(() => {
  const r = result.value
  if (!r || typeof r !== 'object') return ''
  const total = r.total ?? r.count
  return total != null ? `共 ${total} 条` : ''
})
function looksLikeSymbol (v) {
  return typeof v === 'string' && /^[_a-zA-Z$][\w$.]*$/.test(v.trim()) && v.trim().length > 3
}
function chainNames (obj) {
  const chain = obj?.chain
  if (Array.isArray(chain)) {
    return chain
      .map((c) => (typeof c === 'string' ? c : (c?.name || c?.qualified_name || c?.label || '')))
      .filter(Boolean)
  }
  if (Array.isArray(obj?.nodes)) {
    return obj.nodes.map((n) => (typeof n === 'string' ? n : (n?.name || ''))).filter(Boolean)
  }
  return []
}
function fmtScore (s) {
  const n = Number(s)
  return Number.isFinite(n) ? n.toFixed(2) : '—'
}

async function runQuery () {
  if (!jobId.value) {
    ElMessage.warning('先选择固件任务')
    return
  }
  const needName = op.value === 'trace' || op.value === 'snippet'
  const needPattern = op.value === 'search'
  if (needName && !keyword.value) { ElMessage.warning('请输入函数名'); return }
  if (needPattern && !keyword.value) { ElMessage.warning('请输入搜索模式'); return }
  const body = { job_id: jobId.value, op: op.value }
  if (op.value === 'trace') {
    body.name = keyword.value
    body.direction = direction.value
  } else if (op.value === 'snippet') {
    body.name = keyword.value
  } else if (op.value === 'search') {
    body.pattern = keyword.value
  } else if (op.value === 'dangerous') {
    body.limit = 50
  } else if (op.value === 'attack_surface') {
    body.limit = 20
  } else if (op.value === 'routes') {
    body.pattern = keyword.value
    body.limit = 100
  }
  querying.value = true
  queried.value = true
  result.value = null
  queryError.value = ''
  rawOpen.value = false
  try {
    const r = await api('/graph/query', { method: 'POST', body })
    result.value = r
    if (r?.error) queryError.value = String(r.error)
  } catch (e) {
    queryError.value = e.message || '查询失败'
  } finally {
    querying.value = false
  }
}

async function loadLayout () {
  if (!jobId.value) return
  layoutLoading.value = true
  try {
    layout.value = await api(`/jobs/${jobId.value}/graph/layout`)
  } catch (e) {
    layout.value = null
    ElMessage.error('图谱加载失败: ' + e.message)
  } finally {
    layoutLoading.value = false
  }
}

function onNodeSelect (node) { selectedNode.value = node }

watch(jobId, () => {
  selectedNode.value = null
  loadLayout()
})

// 任务选择与自动选中由 JobPicker 完成；jobId 变化触发 loadLayout
</script>

<style scoped>
.block { margin-bottom: 14px; }
.toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; }
.row-between { display: flex; justify-content: space-between; align-items: center; }
.muted { color: var(--fw-text-3); }
.mono { font-family: var(--fw-font-mono, ui-monospace, monospace); }

.q-error {
  padding: 12px 14px; border-radius: 10px;
  border: 1px solid color-mix(in srgb, var(--fw-danger) 35%, transparent);
  background: color-mix(in srgb, var(--fw-danger) 7%, transparent);
}
.q-error p { margin: 0 0 4px; color: var(--fw-danger); font-size: 13px; overflow-wrap: anywhere; }
.q-error span { font-size: 12px; color: var(--fw-text-3); }
.q-empty { padding: 18px 4px 10px; font-size: 13px; }

.as-stats { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
.stat-chip {
  padding: 3px 11px; border-radius: 999px; font-size: 12px;
  background: var(--fw-fill); color: var(--fw-text-2);
  border: 1px solid var(--fw-line);
}
.path-list { display: grid; gap: 10px; }
.path-card {
  padding: 12px 14px; border: 1px solid var(--fw-line);
  border-radius: 12px; background: var(--fw-surface-2);
}
.path-top { display: flex; align-items: center; gap: 10px; margin-bottom: 9px; font-size: 12.5px; }
.path-rank { color: var(--fw-text-3); font-variant-numeric: tabular-nums; }
.path-score { color: var(--fw-brand); font-weight: 600; }
.path-chain { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.path-chain.flat { padding: 6px 2px; }
.cp-node {
  padding: 3px 10px; border-radius: 8px; font-size: 12px;
  font-family: var(--fw-font-mono, ui-monospace, monospace);
  background: var(--fw-fill); border: 1px solid var(--fw-line);
  color: var(--fw-text-2); max-width: 260px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.cp-node.src { border-color: color-mix(in srgb, var(--fw-ok) 45%, transparent); color: var(--fw-ok); }
.cp-node.snk { border-color: color-mix(in srgb, var(--fw-danger) 45%, transparent); color: var(--fw-danger); }
.cp-arrow { color: var(--fw-text-3); font-size: 12px; }

.result {
  background: var(--fw-surface-2); color: var(--fw-text-2);
  border: 1px solid var(--fw-line);
  padding: 12px; border-radius: 10px;
  font-size: 12px; overflow: auto; max-height: 46vh; margin-top: 12px;
}
.node-bar {
  margin-top: 10px; display: flex; gap: 12px; align-items: center;
  padding: 8px 12px; background: var(--fw-fill);
  border: 1px solid var(--fw-line); border-radius: 10px; flex-wrap: wrap;
}
.node-name { font-weight: 600; color: var(--fw-brand); }
.type-dot {
  display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  margin-right: 5px; vertical-align: middle;
}
.edge-legend { margin-left: auto; font-size: 12px; display: flex; align-items: center; gap: 6px; }
.edge-line { display: inline-block; width: 18px; height: 2px; margin: 0 2px 0 8px; vertical-align: middle; }
.edge-line.call { background: rgba(45, 212, 191, .8); }
.edge-line.def { background: rgba(100, 116, 139, .6); }
.edge-line.other { background: rgba(167, 139, 250, .6); }
</style>
