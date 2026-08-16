<template>
  <div>
    <div class="pf-layout">
      <!-- 新建测试 -->
      <el-card shadow="never" class="new-card">
        <template #header>
          <div class="row-between">
            <span>新建协议测试</span>
            <el-tag size="small" type="info" effect="plain">M-ICS</el-tag>
          </div>
        </template>

        <el-radio-group v-model="entryMode" size="small" class="entry-mode">
          <el-radio-button value="real">真机连接</el-radio-button>
          <el-radio-button value="firmware">工控固件联动</el-radio-button>
        </el-radio-group>

        <template v-if="entryMode === 'firmware'">
          <el-select v-model="fwJobId" placeholder="选择已分析的固件任务" class="full"
                     :loading="jobsLoading" @change="loadIdentification">
            <el-option v-for="j in jobs" :key="j.job_id" :value="j.job_id"
                       :label="`${j.job_id} · ${j.firmware}（${j.status}）`" />
          </el-select>
          <div v-loading="idLoading" class="svc-box">
            <template v-if="services.length">
              <div class="muted svc-tip">点击服务行自动填充端口与协议：</div>
              <div v-for="s in services" :key="s.id" class="svc-row" @click="pickService(s)">
                <span class="mono svc-name">{{ s.service }}</span>
                <span class="mono muted">{{ s.protocol }}<template v-if="s.port">:{{ s.port }}/{{ s.transport }}</template></span>
                <el-tag size="small" effect="plain" :type="s.port ? 'success' : 'info'">
                  {{ s.port ? '可联动' : '无端口' }}
                </el-tag>
              </div>
            </template>
            <el-empty v-else-if="!idLoading" description="选择任务后列出识别到的服务"
                      :image-size="60" />
          </div>
        </template>

        <el-form label-width="86px" label-position="left" class="cfg-form">
          <el-form-item label="目标地址">
            <el-input v-model="form.host" placeholder="设备 / 仿真环境 IP，如 192.168.1.10" />
          </el-form-item>
          <el-form-item label="协议模板">
            <el-select v-model="form.protocol" class="full" @change="onProtocolChange">
              <el-option v-for="p in protocolList" :key="p.name" :value="p.name"
                         :label="`${p.label}（:${p.default_port}/${p.transport}）`" />
            </el-select>
          </el-form-item>
          <el-form-item label="端口">
            <el-input-number v-model="form.port" :min="1" :max="65535" class="full" />
          </el-form-item>
          <el-form-item label="传输层">
            <el-radio-group v-model="form.transport" size="small">
              <el-radio-button value="tcp">TCP</el-radio-button>
              <el-radio-button value="udp">UDP</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item label="监视器">
            <el-checkbox-group v-model="form.monitors">
              <el-checkbox value="tcp_probe">TCP 探活</el-checkbox>
              <el-checkbox value="icmp_ping">ICMP Ping</el-checkbox>
              <el-checkbox value="protocol_probe">协议探测</el-checkbox>
            </el-checkbox-group>
          </el-form-item>
          <el-form-item label="名称">
            <el-input v-model="form.name" maxlength="80" placeholder="可选，便于在运行列表中辨认" />
          </el-form-item>
        </el-form>

        <el-collapse class="adv">
          <el-collapse-item title="高级参数" name="adv">
            <el-form label-width="110px" label-position="left" size="small">
              <el-form-item label="用例上限">
                <el-input-number v-model="form.case_limit" :min="1" :max="5000" />
              </el-form-item>
              <el-form-item label="用例间隔 ms">
                <el-input-number v-model="form.delay_ms" :min="0" :max="10000" />
              </el-form-item>
              <el-form-item label="响应超时 ms">
                <el-input-number v-model="form.timeout_ms" :min="100" :max="10000" :step="100" />
              </el-form-item>
              <el-form-item label="确认故障即停">
                <el-switch v-model="form.stop_on_fault" />
              </el-form-item>
            </el-form>
          </el-collapse-item>
        </el-collapse>

        <el-alert type="error" :closable="false" class="warn">
          <template #title>
            <el-checkbox v-model="form.acknowledge" class="ack">
              我已获得被测设备授权，了解畸形报文可能导致设备异常甚至损坏
            </el-checkbox>
          </template>
        </el-alert>
        <el-button type="primary" class="start-btn" :loading="starting"
                   :disabled="!canStart" @click="start">
          开始测试
        </el-button>
      </el-card>

      <!-- 运行列表 -->
      <el-card shadow="never" class="runs-card">
        <template #header>
          <div class="row-between">
            <span>测试运行</span>
            <div>
              <span v-if="polling" class="muted poll-dot">●</span>
              <el-button size="small" :icon="RefreshCw" :loading="runsLoading" @click="loadRuns">刷新</el-button>
            </div>
          </div>
        </template>
        <el-table :data="runs" size="small" v-loading="runsLoading" @row-click="openRun"
                  row-class-name="clickable">
          <el-table-column label="运行" width="110">
            <template #default="{ row }"><span class="mono">{{ row.run_id }}</span></template>
          </el-table-column>
          <el-table-column label="名称 / 目标" min-width="200" show-overflow-tooltip>
            <template #default="{ row }">
              <div>{{ row.name }}</div>
              <div class="muted mono">{{ row.target_host }}:{{ row.target_port }}/{{ row.transport }}</div>
            </template>
          </el-table-column>
          <el-table-column label="协议" width="150">
            <template #default="{ row }">{{ row.protocol_label }}</template>
          </el-table-column>
          <el-table-column label="状态" width="96">
            <template #default="{ row }">
              <el-tag size="small" :type="statusType(row.status)">{{ statusText(row.status) }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="进度" width="110" align="right">
            <template #default="{ row }">
              {{ row.cases_done }}/{{ row.cases_total ?? '?' }}
            </template>
          </el-table-column>
          <el-table-column label="故障" width="70" align="right">
            <template #default="{ row }">
              <span :class="{ 'fault-n': row.fault_count > 0 }">{{ row.fault_count }}</span>
            </template>
          </el-table-column>
          <el-table-column label="时间" width="160">
            <template #default="{ row }"><span class="muted">{{ fmtTime(row.created_at) }}</span></template>
          </el-table-column>
        </el-table>
        <el-empty v-if="!runsLoading && runs.length === 0"
                  description="还没有协议测试运行——左侧配置目标后开始" />
      </el-card>
    </div>

    <!-- 运行详情抽屉 -->
    <el-drawer v-model="detailVisible" :size="isNarrow ? '96%' : '720px'" destroy-on-close>
      <template #header>
        <div class="drawer-head">
          <span class="drawer-title">运行详情</span>
          <span v-if="detail" class="mono muted">{{ detail.run_id }}</span>
        </div>
      </template>
      <div v-if="detail" class="detail-body" v-loading="detailLoading">
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="目标">
            {{ detail.target_host }}:{{ detail.target_port }}/{{ detail.transport }}
          </el-descriptions-item>
          <el-descriptions-item label="协议">{{ detail.protocol_label }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag size="small" :type="statusType(detail.status)">{{ statusText(detail.status) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="关联固件任务">{{ detail.job_id || '—' }}</el-descriptions-item>
          <el-descriptions-item label="监视器">{{ (detail.monitors || []).join(', ') }}</el-descriptions-item>
          <el-descriptions-item label="时间">{{ fmtTime(detail.created_at) }}</el-descriptions-item>
        </el-descriptions>

        <div class="progress-row">
          <el-progress :percentage="progressPct" :stroke-width="10"
                       :status="detail.status === 'error' ? 'exception' : undefined" />
          <span class="muted">{{ detail.cases_done }}/{{ detail.cases_total ?? '?' }} 用例</span>
        </div>
        <div class="outcomes">
          <el-tag v-for="(n, k) in detail.outcome_counts || {}" :key="k" size="small"
                  effect="plain" :type="k === 'response' ? 'success' : k === 'empty' ? 'info' : 'warning'">
            {{ k }} × {{ n }}
          </el-tag>
        </div>

        <div class="row-between sec-head">
          <span>故障（{{ (detail.faults || []).length }}）</span>
          <div>
            <el-button v-if="detail.status === 'running'" size="small" type="danger" plain
                       @click="stopRun">停止</el-button>
            <el-button size="small" type="primary" plain :loading="reporting"
                       @click="makeReport">生成报告</el-button>
          </div>
        </div>
        <el-table :data="detail.faults || []" size="small" max-height="300">
          <el-table-column prop="seq" label="#" width="60" />
          <el-table-column label="模板 / 字段" min-width="170">
            <template #default="{ row }">
              <span class="mono">{{ row.template }}</span>
              <div class="muted mono">{{ row.field }} · {{ row.strategy }}/{{ row.variant }}</div>
            </template>
          </el-table-column>
          <el-table-column prop="outcome" label="触发" width="80" />
          <el-table-column label="确认" width="90">
            <template #default="{ row }">
              <el-tag size="small" :type="row.confirmed ? 'danger' : 'warning'">
                {{ row.confirmed ? '已确认' : '疑似' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="复现" width="80" align="right">
            <template #default="{ row }">{{ row.reproduced }}/{{ row.replay_total }}</template>
          </el-table-column>
          <el-table-column label="恢复" width="80">
            <template #default="{ row }">
              <span v-if="row.recovered === true" class="ok">已恢复</span>
              <span v-else-if="row.recovered === false" class="fault-n">未恢复</span>
              <span v-else class="muted">—</span>
            </template>
          </el-table-column>
        </el-table>
        <el-empty v-if="!(detail.faults || []).length" description="未发现故障" :image-size="60" />

        <div class="sec-head"><span>最近用例</span></div>
        <el-table :data="detail.recent_cases || []" size="small" max-height="260">
          <el-table-column prop="seq" label="#" width="60" />
          <el-table-column prop="template" label="模板" width="160" show-overflow-tooltip />
          <el-table-column prop="field" label="字段" width="130" show-overflow-tooltip />
          <el-table-column prop="outcome" label="结果" width="90" />
          <el-table-column prop="elapsed_ms" label="耗时 ms" width="90" align="right" />
        </el-table>
      </div>
    </el-drawer>

    <!-- 报告预览 -->
    <el-dialog v-model="reportVisible" title="协议测试报告" width="860px" append-to-body>
      <div v-html="reportHtml" class="report-md" />
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { RefreshCw } from '@lucide/vue'
import { marked } from 'marked'
import { api } from '../api'
import { useNarrowViewport } from '../useNarrowViewport'

marked.setOptions({ breaks: true, gfm: true })

const isNarrow = useNarrowViewport()
const entryMode = ref('real')
const jobs = ref([])
const jobsLoading = ref(false)
const fwJobId = ref('')
const services = ref([])
const idLoading = ref(false)
const protocolList = ref([])
const starting = ref(false)
const runs = ref([])
const runsLoading = ref(false)
const polling = ref(false)
const detailVisible = ref(false)
const detail = ref(null)
const detailLoading = ref(false)
const reporting = ref(false)
const reportVisible = ref(false)
const reportHtml = ref('')

const form = ref({
  host: '', protocol: 'modbus_tcp', port: 502, transport: 'tcp',
  monitors: ['tcp_probe', 'protocol_probe'], name: '',
  case_limit: 300, delay_ms: 50, timeout_ms: 1500, stop_on_fault: false,
  acknowledge: false
})

let pollTimer = null

const canStart = computed(() =>
  form.value.acknowledge && form.value.host.trim() && form.value.protocol)

const progressPct = computed(() => {
  const d = detail.value
  if (!d || !d.cases_total) return d && d.status !== 'running' ? 100 : 0
  return Math.min(100, Math.round((d.cases_done / d.cases_total) * 100))
})

// 固件服务 → 协议模板的启发式映射
const SERVICE_PROTO = [
  [/modbus/i, 'modbus_tcp'], [/s7|siemens/i, 's7'], [/opc/i, 'opc_ua'],
  [/dnp3/i, 'dnp3'], [/mqtt/i, 'mqtt'], [/http|web|goahead|lighttpd|nginx/i, 'http']
]

function statusType (s) {
  return { running: 'primary', done: 'success', stopped: 'warning', error: 'danger' }[s] || 'info'
}
function statusText (s) {
  return { running: '运行中', done: '完成', stopped: '已停止', error: '失败' }[s] || s
}
function fmtTime (iso) {
  return iso ? new Date(iso).toLocaleString('zh-CN', { hour12: false }) : ''
}

async function loadProtocols () {
  try {
    const data = await api('/protofuzz/protocols')
    protocolList.value = data.protocols || []
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function loadJobs () {
  jobsLoading.value = true
  try {
    jobs.value = await api('/jobs')
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    jobsLoading.value = false
  }
}

async function loadIdentification () {
  services.value = []
  if (!fwJobId.value) return
  idLoading.value = true
  try {
    const data = await api(`/jobs/${fwJobId.value}/identification`)
    services.value = (data.inputs || []).map(i => ({
      id: i.id, service: i.service, protocol: i.protocol,
      port: i.port, transport: i.transport || 'tcp'
    }))
  } catch (e) {
    if (e.status !== 404) ElMessage.error(e.message)
  } finally {
    idLoading.value = false
  }
}

function pickService (s) {
  if (s.port) form.value.port = s.port
  form.value.transport = s.transport === 'udp' ? 'udp' : 'tcp'
  const hit = SERVICE_PROTO.find(([re]) => re.test(`${s.service} ${s.protocol}`))
  if (hit) form.value.protocol = hit[1]
  ElMessage.success(`已按 ${s.service} 预填；请补填目标设备 IP`)
}

function onProtocolChange (name) {
  const p = protocolList.value.find(x => x.name === name)
  if (p) {
    form.value.port = p.default_port
    form.value.transport = p.transport
  }
}

async function start () {
  starting.value = true
  try {
    const body = {
      target_host: form.value.host.trim(),
      target_port: form.value.port,
      transport: form.value.transport,
      protocol: form.value.protocol,
      monitors: form.value.monitors,
      name: form.value.name,
      case_limit: form.value.case_limit,
      delay_ms: form.value.delay_ms,
      timeout_ms: form.value.timeout_ms,
      stop_on_fault: form.value.stop_on_fault,
      acknowledge: true
    }
    if (entryMode.value === 'firmware' && fwJobId.value) body.job_id = fwJobId.value
    const resp = await api('/protofuzz', { method: 'POST', body })
    ElMessage.success(`已启动 ${resp.run_id}`)
    form.value.acknowledge = false
    await loadRuns()
    startPolling()
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    starting.value = false
  }
}

async function loadRuns () {
  runsLoading.value = true
  try {
    runs.value = (await api('/protofuzz')).runs || []
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    runsLoading.value = false
  }
}

async function openRun (row) {
  detailVisible.value = true
  detailLoading.value = true
  try {
    detail.value = await api(`/protofuzz/${row.run_id}`)
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    detailLoading.value = false
  }
  if (row.status === 'running') pollDetail(row.run_id)
}

function pollDetail (runId) {
  const tick = async () => {
    if (!detailVisible.value || !detail.value || detail.value.run_id !== runId) return
    try {
      detail.value = await api(`/protofuzz/${runId}`)
      if (detail.value.status === 'running') {
        pollTimer = setTimeout(tick, 2000)
        return
      }
    } catch { /* 抽屉已关或网络抖动 */ }
  }
  pollTimer = setTimeout(tick, 2000)
}

async function stopRun () {
  try {
    await api(`/protofuzz/${detail.value.run_id}/stop`, { method: 'POST' })
    ElMessage.success('已请求停止')
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function makeReport () {
  reporting.value = true
  try {
    const resp = await api(`/protofuzz/${detail.value.run_id}/report`, { method: 'POST' })
    const text = await api(`/reports/${resp.report_id}`)
    reportHtml.value = marked.parse(String(text))
    reportVisible.value = true
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    reporting.value = false
  }
}

function startPolling () {
  if (pollTimer) return
  polling.value = true
  const tick = async () => {
    await loadRuns()
    const active = runs.value.some(r => r.status === 'running')
    if (active) {
      pollTimer = setTimeout(tick, 3000)
    } else {
      polling.value = false
      pollTimer = null
    }
  }
  pollTimer = setTimeout(tick, 3000)
}

onMounted(async () => {
  await Promise.all([loadProtocols(), loadJobs(), loadRuns()])
  if (runs.value.some(r => r.status === 'running')) startPolling()
})
onUnmounted(() => { if (pollTimer) clearTimeout(pollTimer) })
</script>

<style scoped>
.pf-layout { display: flex; gap: 12px; align-items: flex-start; }
.new-card { width: 420px; flex-shrink: 0; }
.runs-card { flex: 1; min-width: 0; }
.entry-mode { margin-bottom: 14px; }
.full { width: 100%; }
.cfg-form { margin-top: 12px; }
.svc-box { margin: 8px 0 12px; max-height: 260px; overflow-y: auto; }
.svc-tip { margin-bottom: 6px; }
.svc-row {
  display: flex; align-items: center; gap: 8px; padding: 6px 8px;
  border-radius: 6px; cursor: pointer; border: 1px solid rgba(43, 108, 229, .12);
  margin-bottom: 4px;
}
.svc-row:hover { background: rgba(43, 108, 229, .08); }
.svc-name { font-weight: 600; min-width: 90px; }
.adv { margin-bottom: 12px; }
.warn { margin-bottom: 12px; }
.ack { font-weight: 600; }
:deep(.ack .el-checkbox__label) { color: #b91c1c; white-space: normal; line-height: 1.5; }
.start-btn { width: 100%; }
.row-between { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.muted { color: #64748f; font-size: 12px; }
.mono { font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace; }
.poll-dot { color: #2b6ce5; margin-right: 8px; animation: pulse 1.4s ease-in-out infinite; }
.fault-n { color: #dc2626; font-weight: 700; }
.ok { color: #16a34a; }
.drawer-head { display: flex; align-items: baseline; gap: 10px; }
.drawer-title { font-weight: 600; font-size: 15px; letter-spacing: 1px; color: #2b6ce5; }
.detail-body { padding-bottom: 24px; }
.progress-row { display: flex; align-items: center; gap: 10px; margin: 14px 0 8px; }
.progress-row .el-progress { flex: 1; }
.outcomes { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px; }
.sec-head { margin: 16px 0 8px; font-weight: 600; color: #2b6ce5; }
.report-md { max-height: 62vh; overflow-y: auto; line-height: 1.7; color: #1c2b3a; }
:deep(.clickable) { cursor: pointer; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }
@media (max-width: 960px) {
  .pf-layout { flex-direction: column; }
  .new-card { width: 100%; }
}
</style>
