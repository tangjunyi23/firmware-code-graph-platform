<template>
  <div>
    <el-card shadow="never" class="block">
      <div class="toolbar">
        <el-select v-model="jobId" placeholder="选择任务" class="job-select" @change="loadAll">
          <el-option v-for="job in jobs" :key="job.job_id" :value="job.job_id"
                     :label="`${job.job_id}  ${job.firmware}  (${job.status})`" />
        </el-select>
        <el-button :icon="RefreshCw" :loading="loading" @click="loadAll">刷新</el-button>
        <el-button :icon="Radar" :loading="runningAttack" @click="rerunAttack">重算攻击面</el-button>
        <el-button :icon="Route" :loading="runningRoutes" @click="rerunRoutes">扫描路由</el-button>
      </div>
      <el-descriptions v-if="attackSummary" :column="4" border size="small" class="summary">
        <el-descriptions-item label="输入源">{{ attackSummary.sources }}</el-descriptions-item>
        <el-descriptions-item label="候选汇">{{ attackSummary.sinks }}</el-descriptions-item>
        <el-descriptions-item label="候选路径">{{ attackSummary.path_candidates }}</el-descriptions-item>
        <el-descriptions-item label="Top 路径">{{ attackSummary.paths_returned }}</el-descriptions-item>
        <el-descriptions-item label="有效 trace">{{ cross.traces_considered ?? 0 }}</el-descriptions-item>
        <el-descriptions-item label="轨迹观测函数">{{ cross.observed_functions ?? 0 }}</el-descriptions-item>
        <el-descriptions-item label="候选链观测函数">{{ cross.verified_functions ?? 0 }}</el-descriptions-item>
        <el-descriptions-item label="完整链观测路径">{{ cross.verified_paths ?? 0 }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-card shadow="never" class="block">
      <template #header>
        <div class="row-between">
          <span>攻击路径</span>
          <span class="muted">{{ paths.length }} 条</span>
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
      <el-table :data="paths" size="small" v-loading="loadingPaths">
        <el-table-column type="expand">
          <template #default="{ row }">
            <div class="chain">
              <template v-for="(node, index) in row.chain" :key="`${node.addr}-${index}`">
                <div class="chain-node">
                  <span class="mono">{{ node.name || node.addr }}</span>
                  <span class="mono muted">{{ node.addr }}</span>
                  <el-tag v-for="tag in node.asrc || []" :key="`s-${tag}`" size="small" type="warning">{{ tag }}</el-tag>
                  <el-tag v-for="tag in node.asink || []" :key="`k-${tag}`" size="small" type="danger">{{ tag }}</el-tag>
                  <el-tag v-if="node.libc_equiv" size="small" type="danger" effect="plain">{{ node.libc_equiv }}</el-tag>
                </div>
                <ArrowRight v-if="index < row.chain.length - 1" :size="16" class="chain-arrow" />
              </template>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="评分" prop="score" width="80" sortable />
        <el-table-column label="输入源" min-width="190">
          <template #default="{ row }">
            <span class="mono">{{ row.source.name || row.source.addr }}</span>
            <el-tag v-for="tag in row.source.asrc || []" :key="tag" size="small" type="warning" class="tag-gap">{{ tag }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="候选汇" min-width="190">
          <template #default="{ row }">
            <span class="mono">{{ row.sink.name || row.sink.addr }}</span>
            <el-tag v-for="tag in row.sink.asink || []" :key="tag" size="small" type="danger" class="tag-gap">{{ tag }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="跳数" prop="edge_count" width="70" align="right" />
        <el-table-column label="动态状态" width="130">
          <template #default="{ row }">
            <el-tag v-if="row.verified_reachable" size="small" type="success">完整链观测</el-tag>
            <el-tag v-else-if="row.observed_node_count" size="small" type="warning">部分命中 {{ row.observed_node_count }}</el-tag>
            <span v-else class="muted">未观测</span>
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-if="!loadingPaths && jobId && paths.length === 0" description="无匹配攻击路径" />
    </el-card>

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
import { ArrowRight, Radar, RefreshCw, Route, Search } from '@lucide/vue'
import { api } from '../api'

const jobs = ref([])
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

const sourceKinds = computed(() => Object.keys(attackSummary.value?.source_counts || {}))
const sinkKinds = computed(() => Object.keys(attackSummary.value?.sink_counts || {}))

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
  await Promise.all([loadPaths(), loadRoutes()])
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

onMounted(async () => {
  try {
    jobs.value = await api('/jobs')
    const ready = jobs.value.find(job => ['routed', 'attacked', 'graphed'].includes(job.status))
    if (ready) {
      jobId.value = ready.job_id
      await loadAll()
    }
  } catch (error) {
    ElMessage.error('加载任务失败: ' + error.message)
  }
})
</script>

<style scoped>
.block { margin-bottom: 14px; }
.toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.job-select { width: min(440px, 100%); }
.summary { margin-top: 12px; }
.row-between { display: flex; justify-content: space-between; align-items: center; }
.filters { margin-bottom: 12px; }
.filter-select { width: 180px; }
.route-search { width: min(360px, 100%); }
.switch-label { color: #606266; font-size: 13px; }
.chain { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding: 4px 16px; }
.chain-node { display: flex; align-items: center; gap: 6px; min-height: 32px; }
.chain-arrow { color: #909399; flex: none; }
.tag-gap { margin-left: 6px; }
@media (max-width: 720px) {
  .job-select, .filter-select, .route-search { width: 100%; }
  .summary :deep(.el-descriptions__body) { overflow-x: auto; }
}
</style>
