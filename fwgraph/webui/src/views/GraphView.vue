<template>
  <div>
    <el-card shadow="never" class="block">
      <template #header>图谱查询（/graph/query）</template>
      <div class="toolbar">
        <el-select v-model="jobId" placeholder="选择任务" style="width: 300px">
          <el-option v-for="j in jobs" :key="j.job_id" :value="j.job_id"
                     :label="`${j.job_id}  ${j.firmware}  (${j.status})`" />
        </el-select>
        <el-select v-model="op" style="width: 150px">
          <el-option value="trace" label="trace 调用链" />
          <el-option value="snippet" label="snippet 源码" />
          <el-option value="dangerous" label="dangerous 候选敏感调用" />
          <el-option value="attack_surface" label="attack_surface 路径" />
          <el-option value="routes" label="routes 路由映射" />
          <el-option value="search" label="search 节点搜索" />
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
      <pre v-if="resultText" class="result mono">{{ resultText }}</pre>
      <p v-else-if="queried" class="muted">无结果</p>
    </el-card>

    <el-card shadow="never" class="block">
      <template #header>
        <div class="row-between">
          <span>代码图谱</span>
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
        <el-button size="small" :loading="layoutLoading" @click="loadLayout">重新加载</el-button>
        <span class="edge-legend muted">
          <i class="edge-line" style="background: rgba(53,196,255,.7)"></i>调用
          <i class="edge-line" style="background: rgba(130,160,200,.5)"></i>定义
          <i class="edge-line" style="background: rgba(190,140,220,.5)"></i>其他
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
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import CodeGraphCanvas from '../components/CodeGraphCanvas.vue'

const jobs = ref([])
const jobId = ref('')
const op = ref('trace')
const keyword = ref('')
const direction = ref('both')
const querying = ref(false)
const queried = ref(false)
const resultText = ref('')

const layout = ref(null)
const layoutLoading = ref(false)
const enabledTypes = ref(['File', 'Module', 'Function', 'Project', 'Branch', 'Folder'])
const highlight = ref('')
const fitSignal = ref(0)
const selectedNode = ref(null)

const TYPE_NAMES = {
  File: '文件', Module: '模块', Function: '函数',
  Project: '项目', Branch: 'Branch', Folder: '目录',
}
const TYPE_COLORS = {
  File: '#ea580c', Module: '#2b6ce5', Function: '#16a34a',
  Project: '#7c3aed', Branch: '#b45309', Folder: '#0284c7',
}
function typeColor (value) { return TYPE_COLORS[value] || '#2b6ce5' }
const typeOptions = computed(() => {
  const present = new Set((layout.value?.nodes || []).map(n => n.label))
  return Object.entries(TYPE_NAMES)
    .filter(([value]) => present.size === 0 || present.has(value))
    .map(([value, label]) => ({ value, label }))
})
function typeLabel (value) { return TYPE_NAMES[value] || value }

async function runQuery () {
  if (!jobId.value) {
    ElMessage.warning('先选择任务')
    return
  }
  const body = { job_id: jobId.value, op: op.value }
  if (op.value === 'trace') {
    if (!keyword.value) { ElMessage.warning('trace 需要函数名'); return }
    body.name = keyword.value
    body.direction = direction.value
  } else if (op.value === 'snippet') {
    if (!keyword.value) { ElMessage.warning('snippet 需要函数名'); return }
    body.name = keyword.value
  } else if (op.value === 'search') {
    if (!keyword.value) { ElMessage.warning('search 需要搜索模式'); return }
    body.pattern = keyword.value
  } else if (op.value === 'dangerous') {
    body.limit = 50
  } else if (op.value === 'attack_surface') {
    body.limit = 50
  } else if (op.value === 'routes') {
    body.pattern = keyword.value
    body.limit = 100
  }
  querying.value = true
  queried.value = true
  resultText.value = ''
  try {
    const r = await api('/graph/query', { method: 'POST', body })
    resultText.value = JSON.stringify(r, null, 2)
  } catch (e) {
    resultText.value = '// 查询失败: ' + e.message
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

onMounted(async () => {
  try {
    jobs.value = await api('/jobs')
    const graphed = jobs.value.find(j => ['surfaced', 'graphed', 'attacked', 'routed'].includes(j.status))
    if (graphed) jobId.value = graphed.job_id
  } catch (e) {
    ElMessage.error('加载任务失败: ' + e.message)
  }
})
</script>

<style scoped>
.block { margin-bottom: 14px; }
.toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; }
.row-between { display: flex; justify-content: space-between; align-items: center; }
.result {
  background: #f4f8fd; color: #3d5470; border: 1px solid rgba(43, 108, 229, .18);
  padding: 12px; border-radius: 6px;
  font-size: 12px; overflow: auto; max-height: 46vh; margin-top: 12px;
}
.node-bar {
  margin-top: 10px; display: flex; gap: 12px; align-items: center;
  padding: 8px 12px; background: rgba(43, 108, 229, .06);
  border: 1px solid rgba(43, 108, 229, .2); border-radius: 6px; flex-wrap: wrap;
}
.node-name { font-weight: 600; color: #2b6ce5; }
.type-dot {
  display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  margin-right: 5px; vertical-align: middle;
}
.edge-legend { margin-left: auto; font-size: 12px; display: flex; align-items: center; gap: 6px; }
.edge-line { display: inline-block; width: 18px; height: 2px; margin: 0 2px 0 8px; vertical-align: middle; }
.muted { color: #64748f; }
.mono { font-family: ui-monospace, monospace; }
</style>
