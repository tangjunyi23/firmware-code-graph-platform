<template>
  <div class="wish wb-root" :data-wb-theme="themePref">
    <section v-if="!armed" class="hero">
      <p class="kicker">快速模式</p>
      <h1>三步发起自动化漏洞挖掘</h1>
      <p class="lead">依次完成固件选择、目标设定与任务确认，平台自动执行解密、解包、代码图谱与攻击面分析，再按所选方向开展自动化挖掘。</p>

      <!-- 步骤卡片：一次只显示一步，选择后动画前进 -->
      <div class="wiz-card">
        <div class="wiz-card-head">
          <ol class="stepper">
            <li
              v-for="(st, i) in WIZARD_STEPS"
              :key="st.id"
              :data-state="step > i + 1 ? 'done' : step === i + 1 ? 'now' : 'todo'"
              :class="{ clickable: step > i + 1 }"
              @click="step > i + 1 && goStep(i + 1)"
            >
              <span class="st-dot">
                <template v-if="step > i + 1"><component :is="NAV_ICONS.Guide" :size="12" /></template>
                <template v-else>{{ i + 1 }}</template>
              </span>
              <span class="st-lbl">{{ st.label }}</span>
            </li>
          </ol>
          <span class="wiz-step-count">第 {{ step }} / {{ WIZARD_STEPS.length }} 步</span>
        </div>
        <Transition :name="stepDir === 'back' ? 'wz-back' : 'wz-fwd'" mode="out-in">
          <!-- 第 1 步：选固件 -->
          <div v-if="step === 1" key="s1" class="wz-step">
            <h2 class="wz-q">选择目标固件</h2>
            <p class="wz-sub">上传固件镜像，或复用已完成前置分析的任务</p>
            <div
              class="drop"
              :class="{ over: dragOver, ready: !!file }"
              @dragenter.prevent="dragOver = true"
              @dragover.prevent="dragOver = true"
              @dragleave.prevent="dragOver = false"
              @drop.prevent="onDrop"
              @click="fileInput.click()"
            >
              <input ref="fileInput" type="file" class="hidden" :accept="FW_ACCEPT" @change="onPick" />
              <strong>{{ file ? file.name : '将固件镜像拖拽至此，或点击选择文件' }}</strong>
              <span v-if="uploadPct != null">正在上传 {{ uploadPct }}%</span>
              <span v-else>{{ file ? fmtSize(file.size) : '支持 bin / img / tar / zip / trx 等常见固件格式' }}</span>
              <i v-if="uploadPct != null" class="drop-bar" :style="{ width: uploadPct + '%' }" />
            </div>
            <div v-if="file" class="picked-line">
              <span class="picked-ok"><component :is="NAV_ICONS.Guide" :size="13" /> 已选择 {{ file.name }}（{{ fmtSize(file.size) }}）</span>
              <button type="button" class="ghost" @click="file = null">重选</button>
            </div>
            <template v-if="readyJobs.length">
              <p class="reuse-lead">或复用已完成前置分析的任务</p>
              <div class="reuse">
                <button
                  v-for="item in readyJobs"
                  :key="item.job_id"
                  type="button"
                  :class="{ on: pickedJobId === item.job_id && !file }"
                  @click="pickReady(item)"
                >{{ item.firmware }}</button>
              </div>
            </template>
          </div>

          <!-- 第 2 步：选目标（单选，选中即前进） -->
          <div v-else-if="step === 2" key="s2" class="wz-step">
            <h2 class="wz-q">选择检测目标</h2>
            <p class="wz-sub">选择重点漏洞类型，确认前可返回调整或补充说明</p>
            <div class="chips">
              <button
                v-for="opt in WISH_OPTIONS"
                :key="opt.id"
                type="button"
                :class="{ on: selected.includes(opt.id) }"
                @click="choose(opt.id)"
              >
                <span class="opt-ico"><component :is="NAV_ICONS[OPT_ICONS[opt.id] || 'Star']" :size="16" /></span>
                <span class="opt-copy">
                  <b>{{ opt.label }}</b>
                  <small>{{ opt.hint }}</small>
                </span>
              </button>
            </div>
            <div class="wz-nav">
              <button type="button" class="ghost" @click="goStep(1)">上一步</button>
            </div>
          </div>

          <!-- 第 3 步：确认出发 -->
          <div v-else key="s3" class="wz-step">
            <h2 class="wz-q">确认并启动</h2>
            <p class="wz-sub">请核对以下配置，确认无误后启动挖掘</p>
            <ul class="sum">
              <li @click="goStep(1)">
                <span>固件</span>
                <b>{{ file ? file.name : (job?.firmware || jobs.find(j => j.job_id === pickedJobId)?.firmware || '未选择') }}</b>
                <em>修改</em>
              </li>
              <li @click="goStep(2)">
                <span>目标</span>
                <b>{{ selected.length ? wishShort : '未选择' }}</b>
                <em>修改</em>
              </li>
            </ul>
            <label class="extra">
              <span>补充要求（可选）</span>
              <textarea v-model="extra" rows="2" placeholder="例如：优先检测 HTTP 管理界面，跳过无关守护进程" />
            </label>
            <p v-if="notice" class="err">{{ notice }}</p>
            <div class="wz-nav">
              <button type="button" class="ghost" @click="goStep(2)">上一步</button>
              <button type="button" class="go" :disabled="!canStart || sending" @click="onStart">
                {{ sending ? '正在启动…' : '启动挖掘' }}
              </button>
            </div>
          </div>
        </Transition>
      </div>
    </section>

    <section v-else class="run">
      <header class="run-head">
        <div>
          <p class="kicker">全自动挖掘</p>
          <h1>{{ job?.firmware || '固件任务' }}</h1>
          <p class="tags">
            <span v-for="id in selected" :key="id">{{ wishLabel(id) }}</span>
          </p>
        </div>
        <div class="run-acts">
          <button v-if="sid && running" type="button" class="ghost" @click="onStop">停止</button>
          <button type="button" class="ghost" @click="reset">新建任务</button>
        </div>
      </header>

      <div class="cockpit">
        <article class="ring-card">
          <ProgressRing :value="overallPct" :label="stageLabel" :sub="stageSub" />
        </article>
        <div class="kpis">
          <button type="button" class="kpi" @click="inspect = 'prep'">
            <span>前置分析</span>
            <strong><CountUp :value="prep.pct + '%'" /></strong>
            <em>{{ prep.done }}/{{ prep.total }} 步 · {{ prep.label }}</em>
          </button>
          <button type="button" class="kpi" @click="inspect = 'hunt'">
            <span>挖掘轮次</span>
            <strong><CountUp :value="huntPct + '%'" /></strong>
            <em>{{ turns }}/{{ maxTurns }} 轮{{ findings.length ? ` · 入库 ${findings.length}` : '' }}</em>
          </button>
          <button type="button" class="kpi" @click="inspect = 'binaries'">
            <span>二进制</span>
            <strong><CountUp :value="stats.total_binaries ?? '—'" /></strong>
            <em>{{ stats.extracted_files ? `解出 ${stats.extracted_files} 个文件` : '解包后可见' }}</em>
          </button>
          <button type="button" class="kpi" @click="inspect = 'surface'">
            <span>攻击面</span>
            <strong><CountUp :value="surfaces" /></strong>
            <em>输入 {{ inputs }} · 路径 {{ paths }}</em>
          </button>
          <button type="button" class="kpi" @click="inspect = 'traces'">
            <span>动态验证</span>
            <strong><CountUp :value="tracesHit" />/{{ tracesTotal }}</strong>
            <em>非空差分 / 全部 trace</em>
          </button>
          <button type="button" class="kpi" @click="inspect = 'findings'">
            <span>已入库</span>
            <strong><CountUp :value="findings.length" /></strong>
            <em>{{ highRisk }} 个高危及以上</em>
          </button>
        </div>
      </div>

      <ol class="track">
        <li
          v-for="(step, i) in PIPE_STEPS"
          :key="step.key"
          :data-state="stepState(i, job)"
          @click="inspect = 'prep'"
        >
          <span class="t-top">
            <b>{{ stepPct(i) }}%</b>
            <i />
          </span>
          <span class="t-lbl">{{ step.label }}</span>
        </li>
      </ol>
      <p v-if="phase === 'failed'" class="err">{{ job?.error || '前置分析失败，请换固件或到专家模式查看日志。' }}</p>

      <div class="workspace">
        <div class="chat">
          <header class="pane-h">
            <h2>执行过程</h2>
            <span>{{ sid ? '挖掘会话' : '前置分析完成后自动开始挖掘' }}</span>
          </header>
          <MessageList v-if="sid" :session="dsh" @inspect="onInspect" />
          <p v-else class="empty">前置分析进行中，完成后将自动展示思考、工具调用与结论。</p>
        </div>

        <aside class="dock">
          <div class="tabs">
            <button
              v-for="tab in tabs"
              :key="tab.id"
              type="button"
              :class="{ on: inspect === tab.id }"
              @click="inspect = tab.id"
            >{{ tab.label }}</button>
          </div>
          <div class="dock-body">
            <template v-if="inspect === 'prep'">
              <p class="dock-lead">当前阶段 {{ prep.label }}，完成度 {{ prep.pct }}%。</p>
              <ul class="rows">
                <li v-for="(step, i) in PIPE_STEPS" :key="step.key">
                  <span>{{ step.label }}</span>
                  <b :data-state="stepState(i, job)">{{ stepState(i, job) === 'ok' ? '完成' : stepState(i, job) === 'now' ? '进行中' : stepState(i, job) === 'err' ? '失败' : '等待' }}</b>
                </li>
              </ul>
            </template>
            <template v-else-if="inspect === 'hunt'">
              <p class="dock-lead">会话 {{ sid || '尚未拉起' }} · {{ turns }}/{{ maxTurns }} 轮。</p>
              <ul class="rows">
                <li><span>状态</span><b>{{ sessionStatus }}</b></li>
                <li><span>模式</span><b>动静结合 · 自动放行</b></li>
                <li><span>任务</span><b class="wrap">{{ wishShort }}</b></li>
              </ul>
            </template>
            <template v-else-if="inspect === 'binaries'">
              <p class="dock-lead">{{ stats.total_binaries ? `识别到 ${stats.total_binaries} 个 ELF` : '解包完成后显示。' }}</p>
              <ul class="rows">
                <li v-for="(n, arch) in (stats.by_arch || {})" :key="arch">
                  <span>{{ arch }}</span><b>{{ n }}</b>
                </li>
                <li v-if="intel.size"><span>固件大小</span><b>{{ fmtSize(intel.size) }}</b></li>
              </ul>
            </template>
            <template v-else-if="inspect === 'surface'">
              <p class="dock-lead">攻击面 {{ surfaces }} · 公网输入 {{ inputs }} · 路径 {{ paths }}。</p>
              <ul class="rows">
                <li v-for="(n, k) in sourceCounts" :key="k"><span>{{ k }}</span><b>{{ n }}</b></li>
              </ul>
            </template>
            <template v-else-if="inspect === 'traces'">
              <p class="dock-lead">{{ tracesTotal }} 条 trace，{{ tracesHit }} 条非空差分。</p>
              <ul class="rows clickable">
                <li v-for="t in recentTraces" :key="t.trace_id">
                  <span>{{ t.trace_id }} · {{ t.status }}</span>
                  <b>{{ t.diff_functions ?? 0 }} 函数</b>
                </li>
                <li v-if="!recentTraces.length"><span>还没有动态记录</span><b>—</b></li>
              </ul>
            </template>
            <template v-else-if="inspect === 'findings'">
              <p class="dock-lead">{{ findings.length ? `已入库 ${findings.length} 个` : '确认后才会写入，空差分不会进库。' }}</p>
              <ul class="finds">
                <li v-for="f in findings" :key="f.id" @click="openFinding = openFinding === f.id ? '' : f.id">
                  <div class="f-top">
                    <i :data-sev="f.severity" />
                    <strong>{{ f.title }}</strong>
                    <em>{{ sevLabel(f.severity) }}</em>
                  </div>
                  <p v-if="openFinding === f.id" class="f-body">
                    {{ f.summary || f.vuln_class }} · {{ f.function_name || f.function_addr || '' }}
                  </p>
                </li>
              </ul>
            </template>
            <template v-else>
              <p class="dock-lead">最近日志，点开可核对卡在哪一步。</p>
              <pre class="log">{{ logText }}</pre>
            </template>
          </div>
        </aside>
      </div>
    </section>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, provide, reactive, ref, watch } from 'vue'
import { api, uploadFirmware } from '../api.js'
import { themePref } from '../themePrefs'
import MessageList from '../workbench/MessageList.vue'
import ProgressRing from '../components/ProgressRing.vue'
import CountUp from '../components/fx/CountUp.vue'
import { createDshSession } from '../workbench/dshClient.js'
import { NAV_ICONS } from '../workbench/icons.js'
import {
  FW_ACCEPT, HUNT_TURNS, PIPE_STEPS, RUNNING, WISH_OPTIONS, buildWishTask,
  fmtSize, pipeProgress, pipelineFinished, stepState
} from '../workbench/pipeline.js'
import '../workbench/tokens.css'

const RUN_KEY = 'fwgraph_wish_run'
const DEFAULT_PREPARE = '完成解包、反编译、图谱和攻击面分析，供快速模式自动挖掘。'
const tabs = [
  { id: 'prep', label: '前置' },
  { id: 'hunt', label: '挖掘' },
  { id: 'surface', label: '攻击面' },
  { id: 'traces', label: '动态' },
  { id: 'findings', label: '入库' },
  { id: 'logs', label: '日志' }
]

const file = ref(null)
const fileInput = ref(null)
const dragOver = ref(false)
const uploadPct = ref(null)
const selected = ref([])

// 三步向导：1 固件 → 2 目标 → 3 确认；选择完成动画前进
const WIZARD_STEPS = [
  { id: 'fw', label: '选择固件' },
  { id: 'goal', label: '设定目标' },
  { id: 'go', label: '确认启动' }
]
const OPT_ICONS = {
  all: 'Star', cmdi: 'Share', mem: 'Cpu', auth: 'Lock',
  file: 'Download', info: 'Search', preauth: 'Aim'
}
const step = ref(1)
const stepDir = ref('fwd')
function goStep (n) {
  if (n === step.value || n < 1 || n > 3) return
  stepDir.value = n < step.value ? 'back' : 'fwd'
  step.value = n
}
let chooseTimer = null
function choose (id) {
  selected.value = [id]
  // 短暂展示选中态后前进，给点击一个可感知的反馈
  if (chooseTimer) clearTimeout(chooseTimer)
  chooseTimer = setTimeout(() => goStep(3), 220)
}
const extra = ref('')
const notice = ref('')
const sending = ref(false)
const armed = ref(false)
const job = ref(null)
const pickedJobId = ref('')
const jobs = ref([])
const sid = ref('')
const huntStarted = ref(false)
const inspect = ref('prep')
const openFinding = ref('')
const intel = reactive({
  attack: null, inputs: null, surfaces: null, traces: null,
  session: null, logTail: [], size: 0
})
const dsh = createDshSession()
provide('wbSession', dsh)

const readyJobs = computed(() =>
  (jobs.value || []).filter((item) => pipelineFinished(item) && item.status !== 'failed').slice(0, 6)
)
const canStart = computed(() => !!(file.value || pickedJobId.value) && selected.value.length)
const running = computed(() => dsh.state.running || (job.value && RUNNING.has(job.value.status)))
const phase = computed(() => {
  if (!job.value) return 'idle'
  if (job.value.status === 'failed') return 'failed'
  if (sid.value) return 'hunting'
  if (pipelineFinished(job.value)) return 'ready'
  return 'prepare'
})
const prep = computed(() => pipeProgress(job.value))
const stats = computed(() => job.value?.manifest_summary || {})
const turns = computed(() => Number(intel.session?.turns ?? dsh.state.turns ?? 0))
const maxTurns = computed(() => Number(intel.session?.max_turns ?? dsh.state.maxTurns ?? HUNT_TURNS))
const huntPct = computed(() => {
  if (!sid.value) return 0
  return Math.min(100, Math.round((turns.value / Math.max(1, maxTurns.value)) * 100))
})
const overallPct = computed(() => {
  if (phase.value === 'prepare' || phase.value === 'failed') {
    return Math.round(prep.value.pct * 0.62)
  }
  return Math.min(100, 62 + Math.round(huntPct.value * 0.38))
})
const stageLabel = computed(() => {
  if (phase.value === 'failed') return '失败'
  if (phase.value === 'prepare') return '前置中'
  if (dsh.state.huntStatus === 'done') return '本轮完成'
  if (sid.value) return '挖掘中'
  return '衔接中'
})
const stageSub = computed(() => {
  if (phase.value === 'prepare') return prep.value.label
  if (sid.value) return `${turns.value}/${maxTurns.value} 轮`
  return '即将自动开挖'
})
const surfaces = computed(() => intel.surfaces?.summary?.surfaces ?? intel.surfaces?.files?.length ?? 0)
const inputs = computed(() => intel.inputs?.summary?.total_inputs ?? 0)
const paths = computed(() => intel.attack?.summary?.analysis?.paths_returned ?? 0)
const sourceCounts = computed(() => intel.attack?.summary?.analysis?.source_counts || {})
const tracesTotal = computed(() => intel.traces?.total ?? 0)
const tracesHit = computed(() =>
  (intel.traces?.traces || []).filter((t) => (t.diff_functions || 0) > 0).length
)
const recentTraces = computed(() => (intel.traces?.traces || []).slice(0, 8))
const findings = computed(() => intel.session?.finding_objects || [])
const highRisk = computed(() =>
  findings.value.filter((f) => f.severity === 'critical' || f.severity === 'high').length
)
const sessionStatus = computed(() => intel.session?.status || dsh.state.huntStatus || 'running')
const wishShort = computed(() =>
  selected.value.map(wishLabel).join('、')
)
const logText = computed(() => (intel.logTail || []).slice(-18).join('\n') || '还没有日志。')

function wishLabel (id) {
  return WISH_OPTIONS.find((o) => o.id === id)?.label || id
}
function sevLabel (s) {
  return ({ critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' })[s] || s
}
function stepPct (i) {
  const st = stepState(i, job.value)
  if (st === 'ok') return 100
  if (st === 'now') return 46
  return 0
}

function toggle (id) {
  if (id === 'all') {
    selected.value = ['all']
    return
  }
  const next = selected.value.filter((x) => x !== 'all')
  if (next.includes(id)) selected.value = next.filter((x) => x !== id)
  else selected.value = [...next, id]
  if (!selected.value.length) selected.value = ['all']
}

function onPick (e) {
  const picked = e.target.files && e.target.files[0]
  if (picked) {
    file.value = picked
    pickedJobId.value = ''
    goStep(2)
  }
  e.target.value = ''
}
function onDrop (e) {
  dragOver.value = false
  const picked = e.dataTransfer?.files?.[0]
  if (picked) {
    file.value = picked
    pickedJobId.value = ''
    goStep(2)
  }
}
function pickReady (item) {
  file.value = null
  pickedJobId.value = item.job_id
  job.value = item
  goStep(2)
}

function persist () {
  try {
    sessionStorage.setItem(RUN_KEY, JSON.stringify({
      armed: armed.value,
      jobId: job.value?.job_id || '',
      sid: sid.value,
      selected: selected.value,
      extra: extra.value,
      firmware: job.value?.firmware || '',
      huntStarted: huntStarted.value,
      inspect: inspect.value
    }))
  } catch { /* ignore */ }
}

function restore () {
  try {
    const rec = JSON.parse(sessionStorage.getItem(RUN_KEY) || 'null')
    if (!rec?.armed) return
    selected.value = Array.isArray(rec.selected) && rec.selected.length ? rec.selected : ['all']
    extra.value = rec.extra || ''
    armed.value = true
    huntStarted.value = !!rec.huntStarted
    sid.value = rec.sid || ''
    inspect.value = rec.inspect || 'prep'
    if (rec.jobId) job.value = { job_id: rec.jobId, firmware: rec.firmware || rec.jobId, status: 'pending' }
  } catch { /* ignore */ }
}

async function refreshJobs () {
  try {
    const list = await api('/jobs')
    jobs.value = Array.isArray(list) ? list : []
    if (job.value) {
      const fresh = jobs.value.find((item) => item.job_id === job.value.job_id)
      if (fresh) job.value = { ...job.value, ...fresh }
    }
  } catch { /* keep */ }
}

async function refreshIntel () {
  const id = job.value?.job_id
  if (!id) return
  try {
    const detail = await api(`/jobs/${id}`)
    job.value = { ...job.value, ...detail }
    intel.logTail = detail.log_tail || []
    intel.size = detail.size_bytes || 0
  } catch { /* ignore */ }
  const grab = async (path, key) => {
    try { intel[key] = await api(path) } catch { /* 阶段未到 */ }
  }
  await Promise.all([
    grab(`/jobs/${id}/attack`, 'attack'),
    grab(`/jobs/${id}/inputs`, 'inputs'),
    grab(`/jobs/${id}/surfaces`, 'surfaces'),
    grab(`/jobs/${id}/traces?limit=12`, 'traces')
  ])
  if (sid.value) {
    try { intel.session = await api(`/vulnagent/sessions/${sid.value}`) } catch { /* ignore */ }
  }
}

async function startHunt (target) {
  if (huntStarted.value && sid.value) return
  huntStarted.value = true
  inspect.value = 'hunt'
  const sess = await api('/vulnagent/sessions', {
    method: 'POST',
    body: {
      task: buildWishTask(selected.value, extra.value),
      job_id: target.job_id,
      mode: 'dynamic',
      max_turns: HUNT_TURNS,
      approval_policy: 'auto'
    }
  })
  sid.value = sess.session_id
  persist()
  await dsh.attach(sess.session_id, { expectRunning: true })
}

async function onStart () {
  if (!canStart.value || sending.value) return
  notice.value = ''
  sending.value = true
  try {
    if (file.value) {
      const fname = file.value.name
      uploadPct.value = 0
      const resp = await uploadFirmware(file.value, {
        auto: true,
        task: DEFAULT_PREPARE,
        onProgress: (loaded, total) => {
          uploadPct.value = total ? Math.round((loaded / total) * 100) : 0
        }
      })
      job.value = { job_id: resp.job_id, firmware: fname, status: resp.status || 'pending' }
    } else {
      const existing = jobs.value.find((item) => item.job_id === pickedJobId.value)
      if (!existing) throw new Error('请选择固件')
      job.value = existing
    }
    armed.value = true
    huntStarted.value = false
    sid.value = ''
    inspect.value = 'prep'
    persist()
    if (pipelineFinished(job.value) && job.value.status !== 'failed') {
      await startHunt(job.value)
    }
  } catch (err) {
    notice.value = err.message || '启动失败'
    armed.value = false
  } finally {
    uploadPct.value = null
    sending.value = false
    refreshJobs()
    refreshIntel()
  }
}

async function onStop () {
  if (!sid.value) return
  try { await api(`/vulnagent/sessions/${sid.value}/stop`, { method: 'POST' }) } catch { /* ignore */ }
  try { await dsh.cancel() } catch { /* ignore */ }
  dsh.state.running = false
}

function reset () {
  armed.value = false
  huntStarted.value = false
  sid.value = ''
  job.value = null
  file.value = null
  pickedJobId.value = ''
  notice.value = ''
  inspect.value = 'prep'
  step.value = 1
  selected.value = []
  dsh.detach()
  try { sessionStorage.removeItem(RUN_KEY) } catch { /* ignore */ }
}

function onInspect () { inspect.value = 'hunt' }

let timer = null
watch(() => [job.value?.status, armed.value], async () => {
  if (!armed.value || !job.value || huntStarted.value) return
  if (pipelineFinished(job.value) && job.value.status !== 'failed') {
    try { await startHunt(job.value) } catch (err) { notice.value = err.message || '挖掘未能启动' }
  }
})

onMounted(async () => {
  restore()
  await refreshJobs()
  await refreshIntel()
  if (sid.value) await dsh.attach(sid.value, { expectRunning: true })
  timer = setInterval(async () => {
    await refreshJobs()
    if (armed.value) await refreshIntel()
  }, 3000)
})
onBeforeUnmount(() => {
  if (timer) clearInterval(timer)
  if (chooseTimer) clearTimeout(chooseTimer)
  persist()
  dsh.detach()
})
</script>

<style scoped>
.wish {
  min-height: 100%;
  padding: 24px 28px 48px;
  color: var(--fw-text);
}
.hero { max-width: 760px; margin: 0 auto; }

/* ---- 三步向导 ---- */
.wiz-card-head {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 16px;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--fw-line);
}
.wiz-step-count {
  flex: none;
  padding: 2px 10px;
  border-radius: 999px;
  background: var(--fw-fill);
  color: var(--fw-text-3);
  font-size: 11.5px;
  font-variant-numeric: tabular-nums;
}
.stepper {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 0;
  margin: 0;
  padding: 0;
  list-style: none;
}
.stepper li {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 9px;
  min-width: 0;
  position: relative;
}
.stepper li:not(:last-child)::after {
  content: '';
  flex: 1;
  height: 2px;
  margin: 0 10px;
  border-radius: 2px;
  background: var(--fw-line-strong);
  transition: background-color .3s ease;
}
.stepper li[data-state='done']:not(:last-child)::after { background: var(--fw-brand); }
.st-dot {
  flex: none;
  display: grid;
  place-items: center;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  border: 2px solid var(--fw-line-strong);
  background: var(--fw-surface);
  color: var(--fw-text-3);
  font-size: 12.5px;
  font-weight: 650;
  transition: all .25s ease;
}
.stepper li[data-state='now'] .st-dot {
  border-color: var(--fw-brand);
  color: var(--fw-brand);
  box-shadow: 0 0 0 4px rgba(19, 76, 255, .12);
}
.stepper li[data-state='done'] .st-dot {
  border-color: var(--fw-brand);
  background: var(--fw-brand);
  color: #fff;
}
.st-lbl {
  font-size: 13px;
  font-weight: 600;
  color: var(--fw-text-3);
  white-space: nowrap;
}
.stepper li[data-state='now'] .st-lbl { color: var(--fw-text); }
.stepper li[data-state='done'] .st-lbl { color: var(--fw-text-2); }
.stepper li.clickable { cursor: pointer; }

.wiz-card {
  border: 1px solid var(--fw-line);
  border-radius: 18px;
  background: var(--fw-surface);
  box-shadow: var(--fw-shadow-lg);
  padding: 26px 26px 22px;
  min-height: 320px;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
.wz-step { display: flex; flex-direction: column; flex: 1; }
.wz-q {
  margin: 0 0 4px;
  font-size: 19px;
  font-weight: 650;
  letter-spacing: -0.02em;
}
.wz-sub { margin: 0 0 18px; color: var(--fw-text-3); font-size: 13px; }

/* 步骤切换动画：前进右进左出，回退反向 */
.wz-fwd-enter-active, .wz-fwd-leave-active,
.wz-back-enter-active, .wz-back-leave-active {
  transition: transform .3s cubic-bezier(.2, .7, .3, 1), opacity .22s ease;
}
.wz-fwd-enter-from { transform: translateX(42px); opacity: 0; }
.wz-fwd-leave-to { transform: translateX(-30px); opacity: 0; }
.wz-back-enter-from { transform: translateX(-42px); opacity: 0; }
.wz-back-leave-to { transform: translateX(30px); opacity: 0; }
@media (prefers-reduced-motion: reduce) {
  .wz-fwd-enter-active, .wz-fwd-leave-active,
  .wz-back-enter-active, .wz-back-leave-active { transition: opacity .12s ease; }
  .wz-fwd-enter-from, .wz-fwd-leave-to,
  .wz-back-enter-from, .wz-back-leave-to { transform: none; }
}

.wiz-card .drop { background: var(--fw-bg); }
.picked-line {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-top: 12px;
  padding: 8px 12px;
  border-radius: 10px;
  background: rgba(22, 163, 74, .08);
  color: var(--fw-ok);
  font-size: 13px;
}
.picked-line span { display: inline-flex; align-items: center; gap: 6px; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.reuse-lead { margin: 18px 0 0; color: var(--fw-text-3); font-size: 12px; }
.reuse { margin: 8px 0 0; }

.wiz-card .chips { grid-template-columns: 1fr 1fr; }
.chips button {
  display: flex;
  align-items: center;
  gap: 12px;
  text-align: left;
  padding: 14px 16px;
  border-radius: 14px;
  border: 1px solid var(--fw-line);
  background: var(--fw-bg);
  color: inherit;
  cursor: pointer;
  transition: border-color .16s ease, background-color .16s ease, transform .16s ease, box-shadow .16s ease;
}
.chips button:hover {
  border-color: rgba(19, 76, 255, .35);
  transform: translateY(-1px);
  box-shadow: 0 6px 18px -8px rgba(16, 24, 40, .18);
}
.chips button.on {
  border-color: var(--fw-brand);
  background: var(--fw-fill);
  box-shadow: 0 0 0 3px rgba(19, 76, 255, .1);
}
.opt-ico {
  flex: none;
  display: grid;
  place-items: center;
  width: 36px;
  height: 36px;
  border-radius: 11px;
  background: var(--fw-fill);
  color: var(--fw-brand);
}
.chips button.on .opt-ico { background: rgba(19, 76, 255, .16); }
.opt-copy { display: flex; flex-direction: column; min-width: 0; }
.chips b { display: block; font-size: 14px; }
.chips small { color: var(--fw-text-3); font-size: 12px; margin-top: 2px; }

.wz-nav {
  margin-top: auto;
  padding-top: 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}
.sum { list-style: none; margin: 0; padding: 0; }
.sum li {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 12px 14px;
  border: 1px solid var(--fw-line);
  border-radius: 12px;
  background: var(--fw-bg);
  margin-bottom: 10px;
  cursor: pointer;
  transition: border-color .15s ease;
}
.sum li:hover { border-color: rgba(19, 76, 255, .35); }
.sum span { flex: none; color: var(--fw-text-3); font-size: 12px; width: 34px; }
.sum b { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 14px; }
.sum em { flex: none; color: var(--fw-brand); font-size: 12px; font-style: normal; }
.wiz-card .extra { margin-top: 4px; }
.wiz-card .go { margin-top: 0; }
.run { max-width: 1180px; margin: 0 auto; }
.kicker {
  margin: 0 0 8px;
  color: var(--fw-brand);
  font-size: 11px;
  letter-spacing: .18em;
  text-transform: uppercase;
}
h1 {
  margin: 0 0 8px;
  font-size: 28px;
  letter-spacing: -0.04em;
  font-weight: 650;
}
h2 { margin: 28px 0 12px; font-size: 15px; }
.lead { margin: 0 0 22px; color: var(--fw-text-2); font-size: 14px; line-height: 1.6; }
.tags { display: flex; flex-wrap: wrap; gap: 6px; margin: 0; }
.tags span {
  height: 22px;
  padding: 0 8px;
  border-radius: 999px;
  background: var(--fw-fill);
  color: var(--fw-brand);
  font-size: 11px;
  line-height: 22px;
}
.drop {
  position: relative;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 28px 20px;
  border: 1px dashed var(--fw-line-strong);
  border-radius: 16px;
  background: var(--fw-surface);
  cursor: pointer;
}
.drop.over, .drop.ready { border-color: var(--fw-brand); background: var(--fw-fill); }
.drop strong { font-size: 15px; }
.drop span { color: var(--fw-text-3); font-size: 12px; }
.drop-bar {
  position: absolute;
  left: 0; bottom: 0; height: 3px;
  background: var(--fw-brand);
}
.hidden { display: none; }
.reuse { margin: 14px 0 0; color: var(--fw-text-3); font-size: 12px; }
.reuse button {
  margin: 6px 6px 0 0;
  height: 28px;
  padding: 0 10px;
  border-radius: 999px;
  border: 1px solid var(--fw-line);
  background: transparent;
  color: var(--fw-text-2);
  cursor: pointer;
}
.reuse button.on { border-color: var(--fw-brand); color: var(--fw-brand); background: var(--fw-fill); }
.chips { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.chips button {
  text-align: left;
  padding: 12px 14px;
  border-radius: 14px;
  border: 1px solid var(--fw-line);
  background: var(--fw-surface);
  color: inherit;
  cursor: pointer;
}
.chips button.on { border-color: var(--fw-brand); background: var(--fw-fill); }
.chips b { display: block; font-size: 14px; }
.chips small { color: var(--fw-text-3); font-size: 12px; }
.extra { display: flex; flex-direction: column; gap: 8px; margin-top: 22px; color: var(--fw-text-3); font-size: 12px; }
.extra textarea {
  width: 100%;
  resize: vertical;
  border: 1px solid var(--fw-line);
  border-radius: 12px;
  background: var(--fw-surface);
  color: var(--fw-text);
  padding: 10px 12px;
  font: inherit;
}
.go {
  margin-top: 22px;
  height: 44px;
  padding: 0 22px;
  border: none;
  border-radius: 12px;
  background: var(--fw-brand);
  color: #041018;
  font-weight: 650;
  cursor: pointer;
}
.go:disabled { opacity: .45; cursor: default; }
.err { color: var(--fw-danger); font-size: 13px; }
.run-head {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: flex-start;
  margin-bottom: 18px;
}
.ghost {
  height: 32px;
  padding: 0 12px;
  border-radius: 8px;
  border: 1px solid var(--fw-line);
  background: transparent;
  color: var(--fw-text-2);
  cursor: pointer;
}

.cockpit {
  display: grid;
  grid-template-columns: 220px minmax(0, 1fr);
  gap: 14px;
  margin-bottom: 16px;
}
.ring-card, .kpi, .chat, .dock {
  border: 1px solid var(--fw-line);
  border-radius: 18px;
  background: rgba(17, 26, 43, .72);
  box-shadow: 0 18px 40px rgba(0, 0, 0, .18);
}
.ring-card { display: flex; align-items: center; justify-content: center; padding: 18px 10px; }
.kpis { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
.kpi {
  text-align: left;
  padding: 14px 14px 12px;
  color: inherit;
  cursor: pointer;
}
.kpi:hover { border-color: var(--fw-brand); }
.kpi span { color: var(--fw-text-3); font-size: 12px; }
.kpi strong {
  display: block;
  margin: 6px 0 2px;
  font-size: 26px;
  letter-spacing: -0.04em;
  font-variant-numeric: tabular-nums;
}
.kpi em { font-style: normal; color: var(--fw-text-3); font-size: 11px; }

.track {
  display: grid;
  grid-template-columns: repeat(8, minmax(0, 1fr));
  gap: 8px;
  margin: 0 0 16px;
  padding: 0;
  list-style: none;
}
.track li { cursor: pointer; min-width: 0; }
.t-top { display: flex; align-items: center; gap: 6px; }
.t-top b { font-size: 11px; font-variant-numeric: tabular-nums; color: var(--fw-text-3); }
.t-top i {
  flex: 1;
  height: 4px;
  border-radius: 99px;
  background: rgba(255,255,255,.08);
  position: relative;
  overflow: hidden;
}
.t-top i::after {
  content: '';
  position: absolute;
  inset: 0 auto 0 0;
  width: 0;
  background: var(--fw-brand);
}
.track li[data-state='ok'] .t-top i::after { width: 100%; background: var(--fw-ok); }
.track li[data-state='now'] .t-top i::after { width: 46%; }
.track li[data-state='err'] .t-top i::after { width: 100%; background: var(--fw-danger); }
.t-lbl {
  display: block;
  margin-top: 6px;
  font-size: 11px;
  color: var(--fw-text-3);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.track li[data-state='now'] .t-lbl { color: var(--fw-brand); }

.workspace {
  display: grid;
  grid-template-columns: minmax(0, 1.35fr) minmax(300px, .9fr);
  gap: 12px;
  min-height: 420px;
}
.chat, .dock { min-width: 0; display: flex; flex-direction: column; overflow: hidden; }
.pane-h, .tabs {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 10px;
  padding: 12px 14px 0;
}
.pane-h h2 { margin: 0; font-size: 14px; }
.pane-h span, .dock-lead { color: var(--fw-text-3); font-size: 12px; }
.chat { max-height: calc(100vh - 220px); overflow: auto; }
.empty { margin: 24px 16px; color: var(--fw-text-3); font-size: 13px; }
.tabs { flex-wrap: wrap; padding-bottom: 0; }
.tabs button {
  height: 28px;
  padding: 0 8px;
  border: none;
  border-radius: 8px;
  background: transparent;
  color: var(--fw-text-3);
  cursor: pointer;
}
.tabs button.on { background: var(--fw-fill); color: var(--fw-brand); }
.dock-body { padding: 12px 14px 16px; overflow: auto; flex: 1; }
.rows { list-style: none; margin: 10px 0 0; padding: 0; }
.rows li {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  padding: 8px 0;
  border-top: 1px solid var(--fw-line);
  font-size: 13px;
}
.rows b { font-variant-numeric: tabular-nums; color: var(--fw-text); }
.rows b[data-state='now'] { color: var(--fw-brand); }
.rows b[data-state='ok'] { color: var(--fw-ok); }
.rows b[data-state='err'] { color: var(--fw-danger); }
.rows .wrap { font-weight: 500; text-align: right; max-width: 60%; }
.log {
  margin: 8px 0 0;
  max-height: 280px;
  overflow: auto;
  padding: 10px;
  border-radius: 10px;
  background: var(--fw-bg);
  color: var(--fw-text-2);
  font-size: 11px;
  line-height: 1.5;
  white-space: pre-wrap;
}
.finds { list-style: none; margin: 8px 0 0; padding: 0; }
.finds li { padding: 8px 0; border-top: 1px solid var(--fw-line); cursor: pointer; }
.f-top { display: flex; align-items: center; gap: 8px; }
.f-top i { width: 8px; height: 8px; border-radius: 50%; background: var(--fw-text-3); }
.f-top i[data-sev='critical'] { background: #fb7185; }
.f-top i[data-sev='high'] { background: #fb923c; }
.f-top i[data-sev='medium'] { background: #fbbf24; }
.f-top strong { flex: 1; font-size: 13px; }
.f-top em { color: var(--fw-text-3); font-size: 11px; font-style: normal; }
.f-body { margin: 6px 0 0 16px; color: var(--fw-text-2); font-size: 12px; line-height: 1.5; }

@media (max-width: 1100px) {
  .cockpit, .workspace, .track { grid-template-columns: 1fr 1fr; }
  .track { grid-template-columns: repeat(4, minmax(0, 1fr)); }
}
@media (max-width: 720px) {
  .wish { padding: 16px 12px 32px; }
  .chips, .cockpit, .workspace, .kpis { grid-template-columns: 1fr; }
  h1 { font-size: 22px; }
  .run-head { flex-direction: column; }
  .wiz-card { padding: 18px 14px 16px; }
  .st-lbl { font-size: 12px; }
}
</style>
