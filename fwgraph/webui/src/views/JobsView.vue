<template>
  <div>
    <el-card shadow="never" class="block">
      <template #header>上传固件</template>
      <el-upload
        drag
        :show-file-list="false"
        :http-request="doUpload"
        accept=".bin,.img,.tar,.gz,.tgz,.zip,.trx,.chk,.fw"
      >
        <div class="upload-inner">
          <div>拖拽固件文件到此处，或 <em>点击选择文件</em></div>
          <div class="muted">{{ uploadHint }}</div>
        </div>
      </el-upload>
    </el-card>

    <el-card shadow="never" class="block">
      <template #header>
        <div class="row-between">
          <span>任务列表</span>
          <el-button size="small" :loading="loading" @click="loadJobs">刷新</el-button>
        </div>
      </template>
      <el-table :data="jobs" size="small" v-loading="loading" @row-click="openDetail" row-class-name="clickable">
        <el-table-column prop="job_id" label="job_id" width="130">
          <template #default="{ row }"><span class="mono">{{ row.job_id }}</span></template>
        </el-table-column>
        <el-table-column prop="firmware" label="固件" min-width="180" show-overflow-tooltip />
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" size="small">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" width="170">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="总耗时" width="100">
          <template #default="{ row }">{{ duration(row.created_at, row.updated_at) }}</template>
        </el-table-column>
        <el-table-column label="错误" min-width="140" show-overflow-tooltip>
          <template #default="{ row }"><span class="err">{{ row.error }}</span></template>
        </el-table-column>
        <el-table-column label="操作" width="130">
          <template #default="{ row }">
            <el-button size="small" text type="primary" @click.stop="$emit('open-functions', row.job_id)">函数</el-button>
            <el-button size="small" text type="primary" @click.stop="openDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-drawer v-model="detailVisible" :title="`任务详情 ${detail?.job_id || ''}`"
               :size="isNarrow ? '96%' : '52%'">
      <div v-if="detail" class="detail">
        <el-descriptions :column="isNarrow ? 1 : 2" border size="small">
          <el-descriptions-item label="固件">{{ detail.firmware }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="statusType(detail.status)" size="small">{{ detail.status }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="大小">{{ fmtSize(detail.size_bytes) }}</el-descriptions-item>
          <el-descriptions-item label="更新时间">{{ fmtTime(detail.updated_at) }}</el-descriptions-item>
        </el-descriptions>

        <h4>解包 manifest</h4>
        <template v-if="detail.manifest_summary">
          <el-descriptions :column="isNarrow ? 1 : 3" border size="small">
            <el-descriptions-item label="二进制数">{{ detail.manifest_summary.total_binaries }}</el-descriptions-item>
            <el-descriptions-item label="提取文件数">{{ detail.manifest_summary.extracted_files }}</el-descriptions-item>
            <el-descriptions-item label="架构分布">
              <el-tag v-for="(n, arch) in detail.manifest_summary.by_arch" :key="arch" size="small" class="tag-gap">
                {{ arch }}: {{ n }}
              </el-tag>
            </el-descriptions-item>
          </el-descriptions>
        </template>
        <p v-else class="muted">无 manifest（未解包或解包失败）</p>

        <h4>语义标签（M3）</h4>
        <template v-if="ailift && ailift.summary">
          <div v-for="(b, md5) in ailift.summary.binaries" :key="md5" class="ai-bin">
            <div class="mono muted">{{ shortMd5(md5) }}</div>
            <el-descriptions :column="isNarrow ? 2 : 4" border size="small">
              <el-descriptions-item label="总函数">{{ b.funnel?.total }}</el-descriptions-item>
              <el-descriptions-item label="入选 LLM">{{ b.llm_sent }}</el-descriptions-item>
              <el-descriptions-item label="完成标签">{{ b.tagged }}</el-descriptions-item>
              <el-descriptions-item label="耗时">{{ duration(ailift.summary.started_at, ailift.summary.finished_at) }}</el-descriptions-item>
            </el-descriptions>
          </div>
        </template>
        <p v-else class="muted">未运行 ailift</p>

        <h4>图谱（M4）</h4>
        <template v-if="graph && graph.summary">
          <el-descriptions :column="isNarrow ? 2 : 3" border size="small">
            <el-descriptions-item label="节点">{{ graph.summary.index?.nodes }}</el-descriptions-item>
            <el-descriptions-item label="边">{{ graph.summary.index?.edges }}</el-descriptions-item>
            <el-descriptions-item label="耗时">{{ duration(graph.summary.started_at, graph.summary.finished_at) }}</el-descriptions-item>
          </el-descriptions>
        </template>
        <p v-else class="muted">未建图</p>

        <h4>攻击面</h4>
        <template v-if="attack && attack.summary">
          <el-descriptions :column="isNarrow ? 2 : 4" border size="small">
            <el-descriptions-item label="输入源">{{ attack.summary.analysis?.sources }}</el-descriptions-item>
            <el-descriptions-item label="候选汇">{{ attack.summary.analysis?.sinks }}</el-descriptions-item>
            <el-descriptions-item label="Top 路径">{{ attack.summary.analysis?.paths_returned }}</el-descriptions-item>
            <el-descriptions-item label="完整链观测">{{ attack.summary.cross_validation?.verified_paths }}</el-descriptions-item>
          </el-descriptions>
        </template>
        <p v-else class="muted">未生成攻击面</p>

        <h4>静态路由</h4>
        <template v-if="routes && routes.summary">
          <el-descriptions :column="isNarrow ? 1 : 3" border size="small">
            <el-descriptions-item label="发现">{{ routes.summary.injection?.routes }}</el-descriptions-item>
            <el-descriptions-item label="ROUTE 边">{{ routes.summary.injection?.inserted }}</el-descriptions-item>
            <el-descriptions-item label="未匹配 handler">{{ routes.summary.injection?.unmatched }}</el-descriptions-item>
          </el-descriptions>
        </template>
        <p v-else class="muted">未扫描路由</p>

        <template v-if="detail.log_tail && detail.log_tail.length">
          <h4>日志尾部</h4>
          <pre class="log">{{ detail.log_tail.join('\n') }}</pre>
        </template>
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { useNarrowViewport } from '../useNarrowViewport'

defineEmits(['open-functions'])

const jobs = ref([])
const loading = ref(false)
const uploadHint = ref('支持 .bin/.img/.tar.gz 等固件包')
const detailVisible = ref(false)
const detail = ref(null)
const ailift = ref(null)
const graph = ref(null)
const attack = ref(null)
const routes = ref(null)
const isNarrow = useNarrowViewport()
let timer = null

const STATUS_TYPES = {
  graphed: 'success', attacked: 'success', routed: 'success',
  ailifted: 'success', decompiled: 'success', done: 'success',
  failed: 'danger',
  pending: 'info', extracting: 'warning', parsing: 'warning',
  decompiling: 'warning', ailifting: 'warning', graphing: 'warning',
  attacking: 'warning', routing: 'warning'
}

function statusType (s) { return STATUS_TYPES[s] || 'info' }
function shortMd5 (m) { return m ? m.slice(0, 12) : '' }

function fmtTime (iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return isNaN(d) ? iso : d.toLocaleString()
}

function fmtSize (n) {
  if (n == null) return ''
  if (n > 1048576) return (n / 1048576).toFixed(1) + ' MB'
  if (n > 1024) return (n / 1024).toFixed(1) + ' KB'
  return n + ' B'
}

function duration (a, b) {
  if (!a || !b) return ''
  const ms = new Date(b) - new Date(a)
  if (isNaN(ms) || ms < 0) return ''
  const s = Math.round(ms / 1000)
  if (s < 60) return s + 's'
  return Math.floor(s / 60) + 'm' + (s % 60) + 's'
}

async function loadJobs () {
  loading.value = true
  try {
    jobs.value = await api('/jobs')
  } catch (e) {
    ElMessage.error('加载任务失败: ' + e.message)
  } finally {
    loading.value = false
  }
}

async function doUpload ({ file }) {
  const fd = new FormData()
  fd.append('file', file)
  try {
    const r = await api('/firmware', { method: 'POST', formData: fd })
    ElMessage.success('已创建任务 ' + r.job_id)
    await loadJobs()
  } catch (e) {
    ElMessage.error('上传失败: ' + e.message)
  }
}

async function openDetail (row) {
  detailVisible.value = true
  detail.value = row
  ailift.value = null
  graph.value = null
  attack.value = null
  routes.value = null
  try {
    detail.value = await api(`/jobs/${row.job_id}`)
  } catch { /* keep list row data */ }
  try { ailift.value = await api(`/jobs/${row.job_id}/ailift`) } catch { /* not run */ }
  try { graph.value = await api(`/jobs/${row.job_id}/graph`) } catch { /* not run */ }
  try { attack.value = await api(`/jobs/${row.job_id}/attack`) } catch { /* not run */ }
  try { routes.value = await api(`/jobs/${row.job_id}/routes`) } catch { /* not run */ }
}

onMounted(() => {
  loadJobs()
  timer = setInterval(loadJobs, 10000)
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.block { margin-bottom: 14px; }
.row-between { display: flex; justify-content: space-between; align-items: center; }
.upload-inner { padding: 18px 0; color: #606266; }
.err { color: #f56c6c; font-size: 12px; }
.detail h4 { margin: 18px 0 8px; }
.tag-gap { margin-right: 6px; }
.ai-bin { margin-bottom: 10px; }
.log { background: #1d1e1f; color: #d4d4d4; padding: 10px; border-radius: 4px; font-size: 12px; overflow: auto; max-height: 300px; }
:deep(.clickable) { cursor: pointer; }
</style>
