<template>
  <div>
    <!-- ============ 简易模式：工作台 ============ -->
    <template v-if="isSimple">
      <el-card shadow="never" class="block upload-hero">
        <el-upload
          drag
          :show-file-list="false"
          :http-request="doUpload"
          accept=".bin,.img,.tar,.gz,.tgz,.zip,.trx,.chk,.fw"
        >
          <div class="hero-inner">
            <el-icon class="hero-icon"><UploadFilled /></el-icon>
            <div class="hero-title">拖拽固件文件到此处，或 <em>点击选择文件</em></div>
            <div class="muted">上传固件，全自动完成分析并生成报告</div>
          </div>
        </el-upload>
      </el-card>

      <el-empty v-if="!loading && !jobs.length" description="还没有分析任务，先上传一个固件吧" :image-size="90" />

      <el-card v-for="job in jobs" :key="job.job_id" shadow="never" class="block job-card">
        <div class="job-head">
          <div class="job-name">
            <el-icon><Box /></el-icon>
            <span>{{ job.firmware }}</span>
          </div>
          <el-tag size="small" :type="simpleTagType(job)" effect="dark">{{ simpleStatus(job) }}</el-tag>
        </div>
        <el-steps
          :active="stepActive(job)"
          :process-status="job.status === 'failed' ? 'error' : 'process'"
          finish-status="success"
          align-center
          :direction="isNarrow ? 'vertical' : 'horizontal'"
          class="job-steps"
        >
          <el-step v-for="s in STEPS" :key="s" :title="s" />
        </el-steps>
        <div v-if="job.status === 'failed'" class="job-error">
          分析失败：{{ job.error || '未知错误' }}
        </div>
        <div v-if="isDone(job)" class="job-done">
          <span class="done-summary">
            分析完成：发现 <b>{{ summaries[job.job_id]?.inputs ?? '-' }}</b> 个外部输入、
            <b>{{ summaries[job.job_id]?.surfaces ?? '-' }}</b> 个攻击面
          </span>
          <span class="done-actions">
            <el-button type="primary" size="small" @click="openReport(job)">查看报告</el-button>
            <el-button size="small" @click="$emit('goto', 'vuln')">去漏洞挖掘</el-button>
          </span>
        </div>
      </el-card>
    </template>

    <!-- ============ 专业模式：任务中心 ============ -->
    <template v-else>
      <el-card shadow="never" class="block">
        <template #header>
          <div class="row-between">
            <span>上传固件</span>
            <span class="auto-switch">
              <span class="muted">全自动分析</span>
              <el-switch v-model="autoUpload" inline-prompt active-text="开" inactive-text="关" />
            </span>
          </div>
        </template>
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
          <el-table-column prop="firmware" label="固件" min-width="160" show-overflow-tooltip />
          <el-table-column v-if="!isNarrow" label="属主" width="100">
            <template #default="{ row }">{{ row.owner || '—' }}</template>
          </el-table-column>
          <el-table-column label="状态" width="150">
            <template #default="{ row }">
              <el-tag :type="statusType(row.status)" size="small">{{ row.status }}</el-tag>
              <el-tag v-if="row.auto" size="small" type="warning" effect="plain" class="auto-badge">auto</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="创建时间" width="170">
            <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
          </el-table-column>
          <el-table-column label="总耗时" width="100">
            <template #default="{ row }">{{ duration(row.created_at, row.updated_at) }}</template>
          </el-table-column>
          <el-table-column label="错误" min-width="120" show-overflow-tooltip>
            <template #default="{ row }"><span class="err">{{ row.error }}</span></template>
          </el-table-column>
          <el-table-column label="操作" width="310" fixed="right" class-name="ops-cell">
            <template #default="{ row }">
              <el-button size="small" text type="primary" @click.stop="$emit('open-functions', row.job_id)">函数</el-button>
              <el-button size="small" text type="primary" @click.stop="openDetail(row)">详情</el-button>
              <el-button size="small" text type="primary" @click.stop="openReport(row)">报告</el-button>
              <el-button v-if="canRerun(row.status)" size="small" text type="warning" @click.stop="rerunAuto(row)">补跑</el-button>
              <el-popconfirm title="将删除该任务全部分析产物，不可恢复" width="240"
                             confirm-button-text="删除" confirm-button-type="danger"
                             cancel-button-text="取消" @confirm="removeJob(row)">
                <template #reference>
                  <el-button size="small" text type="danger" @click.stop>删除</el-button>
                </template>
              </el-popconfirm>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </template>

    <!-- 报告预览弹窗（两种模式共用） -->
    <el-dialog v-model="reportVisible" :title="reportTitle" :width="isNarrow ? '96%' : '60%'" top="4vh">
      <div v-loading="reportLoading" class="report-dialog-body">
        <div v-if="reportHtml" class="md-body" v-html="reportHtml"></div>
      </div>
      <template #footer>
        <el-button @click="reportVisible = false">关闭</el-button>
        <el-button type="primary" @click="gotoReports">去报告中心</el-button>
      </template>
    </el-dialog>

    <!-- 任务详情抽屉（专业模式） -->
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

        <div class="detail-actions">
          <el-popconfirm title="将删除该任务全部分析产物，不可恢复" width="240"
                         confirm-button-text="删除" confirm-button-type="danger"
                         cancel-button-text="取消" @confirm="removeJob(detail)">
            <template #reference>
              <el-button size="small" type="danger" plain>删除任务</el-button>
            </template>
          </el-popconfirm>
        </div>

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
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { marked } from 'marked'
import { api } from '../api'
import { useNarrowViewport } from '../useNarrowViewport'

marked.setOptions({ breaks: true, gfm: true })

const props = defineProps({
  mode: { type: String, default: 'pro' }
})
const emit = defineEmits(['open-functions', 'goto'])

const isSimple = computed(() => props.mode === 'simple')
const jobs = ref([])
const loading = ref(false)
const autoUpload = ref(false)
const uploadHint = ref('支持 .bin/.img/.tar.gz 等固件包')
const detailVisible = ref(false)
const detail = ref(null)
const ailift = ref(null)
const graph = ref(null)
const attack = ref(null)
const routes = ref(null)
const isNarrow = useNarrowViewport()
const summaries = reactive({})
const reportVisible = ref(false)
const reportLoading = ref(false)
const reportTitle = ref('')
const reportHtml = ref('')
let timer = null

const STATUS_TYPES = {
  surfaced: 'success', graphed: 'success', attacked: 'success', routed: 'success',
  ailifted: 'success', decompiled: 'success', done: 'success', identified: 'success',
  failed: 'danger',
  pending: 'info', extracting: 'warning', parsing: 'warning',
  decompiling: 'warning', ailifting: 'warning', graphing: 'warning',
  attacking: 'warning', routing: 'warning', identifying: 'warning', surfacing: 'warning'
}

// 简易模式步骤条：状态 → 步骤序号
const STEPS = ['解包固件', '解析文件系统', '反编译', 'AI 语义标注', '代码图谱',
  '攻击路径分析', '路由识别', '输入识别', '攻击面导出', '完成']
const STATUS_STEP = {
  pending: 0, extracting: 0, parsing: 1, decompiling: 2, ailifting: 3,
  graphing: 4, attacking: 5, routing: 6, identifying: 7, surfacing: 8
}
const RERUNNABLE = ['surfaced', 'done', 'failed', 'decompiled', 'ailifted',
  'graphed', 'attacked', 'routed', 'identified']

function statusType (s) { return STATUS_TYPES[s] || 'info' }
function shortMd5 (m) { return m ? m.slice(0, 12) : '' }
function canRerun (s) { return RERUNNABLE.includes(s) }
function isRunning (job) { return Object.prototype.hasOwnProperty.call(STATUS_STEP, job.status) }
function isDone (job) { return job.status !== 'failed' && !isRunning(job) }
function stepActive (job) {
  if (isDone(job)) return STEPS.length
  return STATUS_STEP[job.status] ?? 0
}
function simpleStatus (job) {
  if (job.status === 'failed') return '分析失败'
  if (isDone(job)) return '分析完成'
  return '分析中…'
}
function simpleTagType (job) {
  if (job.status === 'failed') return 'danger'
  if (isDone(job)) return 'success'
  return 'warning'
}

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
    if (isSimple.value) {
      for (const job of jobs.value) {
        if (isDone(job)) loadSummary(job.job_id)
      }
    }
  } catch (e) {
    ElMessage.error('加载任务失败: ' + e.message)
  } finally {
    loading.value = false
  }
}

// 简易模式完成卡片的摘要数字：外部输入数 + 攻击面数
async function loadSummary (jobId) {
  if (summaries[jobId]) return
  const s = { inputs: null, surfaces: null }
  try {
    const ident = await api(`/jobs/${jobId}/identification`)
    s.inputs = ident.metadata?.total_inputs ?? ident.inputs?.length ?? null
  } catch { /* 未完成识别 */ }
  try {
    const idx = await api(`/jobs/${jobId}/surfaces`)
    s.surfaces = idx.summary?.surfaces ?? null
  } catch { /* 未导出攻击面 */ }
  summaries[jobId] = s
}

async function doUpload ({ file }) {
  const fd = new FormData()
  fd.append('file', file)
  const auto = isSimple.value || autoUpload.value
  try {
    const r = await api(`/firmware${auto ? '?auto=1' : ''}`, { method: 'POST', formData: fd })
    ElMessage.success(auto ? '已创建任务，开始全自动分析' : '已创建任务 ' + r.job_id)
    await loadJobs()
  } catch (e) {
    ElMessage.error('上传失败: ' + e.message)
  }
}

async function rerunAuto (row) {
  try {
    await api(`/jobs/${row.job_id}/auto`, { method: 'POST' })
    ElMessage.success('已启动全自动补跑')
    await loadJobs()
  } catch (e) {
    ElMessage.error('补跑失败: ' + e.message)
  }
}

// 删除任务及其全部分析产物（owner/admin；running 时后端 409，detail 直接透出）
async function removeJob (row) {
  if (!row) return
  try {
    await api(`/jobs/${row.job_id}`, { method: 'DELETE' })
    ElMessage.success('任务已删除')
    if (detail.value && detail.value.job_id === row.job_id) detailVisible.value = false
    await loadJobs()
  } catch (e) {
    ElMessage.error('删除失败: ' + e.message)
  }
}

// 报告：已有则直接预览，未生成则先 POST 生成
async function openReport (row) {
  reportTitle.value = `${row.firmware} 综合报告`
  reportVisible.value = true
  reportLoading.value = true
  reportHtml.value = ''
  try {
    let md
    try {
      md = await api(`/jobs/${row.job_id}/report`)
    } catch (e) {
      if (e.status !== 404) throw e
      await api(`/jobs/${row.job_id}/report`, { method: 'POST' })
      md = await api(`/jobs/${row.job_id}/report`)
    }
    reportHtml.value = marked.parse(String(md))
  } catch (e) {
    reportVisible.value = false
    ElMessage.error('报告获取失败: ' + e.message)
  } finally {
    reportLoading.value = false
  }
}

function gotoReports () {
  reportVisible.value = false
  emit('goto', 'reports')
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

function startTimer () {
  if (timer) clearInterval(timer)
  timer = setInterval(loadJobs, isSimple.value ? 3000 : 10000)
}
watch(isSimple, startTimer)

onMounted(() => {
  loadJobs()
  startTimer()
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.block { margin-bottom: 14px; }
.row-between { display: flex; justify-content: space-between; align-items: center; }
.upload-inner { padding: 18px 0; color: #3d5470; }
.auto-switch { display: inline-flex; align-items: center; gap: 8px; }
.auto-badge { margin-left: 6px; }
.err { color: #dc2626; font-size: 12px; }
.detail h4 { margin: 18px 0 8px; letter-spacing: 1px; color: #2b6ce5; }
.detail-actions { margin-top: 12px; display: flex; justify-content: flex-end; }
.tag-gap { margin-right: 6px; }
.ai-bin { margin-bottom: 10px; }
.log { background: #f4f8fd; color: #3d5470; border: 1px solid rgba(43, 108, 229, .18); padding: 10px; border-radius: 4px; font-size: 12px; overflow: auto; max-height: 300px; }
:deep(.clickable) { cursor: pointer; }
:deep(.ops-cell .el-button + .el-button) { margin-left: 6px; }
.report-dialog-body { min-height: 200px; max-height: 72vh; overflow: auto; }

/* ===== 简易模式 ===== */
.upload-hero :deep(.el-upload-dragger) { padding: 30px 20px; }
.hero-inner { color: #3d5470; }
.hero-icon { font-size: 46px; color: #2b6ce5; filter: drop-shadow(0 0 10px rgba(43, 108, 229, .6)); margin-bottom: 10px; }
.hero-title { font-size: 16px; margin-bottom: 6px; }
.job-card :deep(.el-card__body) { padding-top: 16px; }
.job-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; gap: 10px; }
.job-name { display: flex; align-items: center; gap: 8px; font-size: 15px; color: #1c2b3a; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.job-steps { margin: 6px 0 4px; }
.job-steps :deep(.el-step__title) { font-size: 12px; }
.job-steps :deep(.el-step__title.is-process) { color: #2b6ce5; }
.job-error {
  margin-top: 10px;
  color: #b91c1c;
  background: rgba(220, 38, 38, .08);
  border: 1px solid rgba(220, 38, 38, .3);
  border-radius: 6px;
  padding: 8px 12px;
  font-size: 13px;
}
.job-done {
  margin-top: 12px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.done-summary { color: #3d5470; font-size: 14px; }
.done-summary b { color: #2b6ce5; font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace; }
.done-actions { display: inline-flex; gap: 10px; }
</style>
