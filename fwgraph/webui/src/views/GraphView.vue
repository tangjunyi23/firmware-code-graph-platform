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
          <span>CBM 图谱可视化（经 /cbmui 反代嵌入）</span>
          <el-button size="small" text type="primary" @click="reloadFrame">重新加载</el-button>
        </div>
      </template>
      <iframe :key="frameKey" src="/cbmui/" class="cbm-frame" title="CBM UI"></iframe>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

const jobs = ref([])
const jobId = ref('')
const op = ref('trace')
const keyword = ref('')
const direction = ref('both')
const querying = ref(false)
const queried = ref(false)
const resultText = ref('')
const frameKey = ref(0)

function reloadFrame () { frameKey.value += 1 }

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

onMounted(async () => {
  try {
    jobs.value = await api('/jobs')
    const graphed = jobs.value.find(j => ['graphed', 'attacked', 'routed'].includes(j.status))
    if (graphed) jobId.value = graphed.job_id
  } catch (e) {
    ElMessage.error('加载任务失败: ' + e.message)
  }
})
</script>

<style scoped>
.block { margin-bottom: 14px; }
.toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.row-between { display: flex; justify-content: space-between; align-items: center; }
.result {
  background: #1d1e1f; color: #d4d4d4; padding: 12px; border-radius: 6px;
  font-size: 12px; overflow: auto; max-height: 46vh; margin-top: 12px;
}
.cbm-frame { width: 100%; height: 72vh; border: 1px solid #dcdfe6; border-radius: 6px; background: #0a0a10; }
</style>
