<template>
  <div class="proto">
    <header class="hero">
      <div>
        <p class="kicker">协议逆向</p>
        <h1>标识 · 算法 · 解码 · 攻击面</h1>
        <p>只分析你选中的固件任务，以及你粘贴的报文。不会对公网主机抽密钥，也不会破解密文。</p>
      </div>
      <div class="hero-side">
        <el-select v-model="jobId" placeholder="选择固件任务" class="job" filterable @change="loadReport">
          <el-option
            v-for="j in jobs"
            :key="j.job_id"
            :value="j.job_id"
            :label="`${j.firmware} · ${STATUS_TEXT[j.status] || j.status}`"
          />
        </el-select>
        <button type="button" class="ghost" :disabled="!jobId || loading" @click="loadReport">重新分析</button>
      </div>
    </header>

    <section class="kpis">
      <button v-for="card in kpiCards" :key="card.id" type="button" class="kpi" @click="tab = card.tab">
        <span class="kpi-label">{{ card.label }}</span>
        <strong><CountUp :value="card.value" /></strong>
        <em>{{ card.hint }}</em>
      </button>
    </section>

    <nav class="caps" aria-label="协议逆向能力">
      <button
        v-for="t in tabs"
        :key="t.id"
        type="button"
        class="cap"
        :class="{ on: tab === t.id }"
        :aria-current="tab === t.id ? 'page' : undefined"
        @click="tab = t.id"
      >
        <span class="cap-ico"><component :is="NAV_ICONS[t.icon] || NAV_ICONS.Share" :size="18" /></span>
        <span class="cap-copy">
          <span class="cap-no">{{ t.no }}</span>
          <b class="cap-label">{{ t.label }}</b>
          <span class="cap-hint">{{ t.hint }}</span>
        </span>
        <span v-if="capCount(t.id) !== null" class="cap-count">{{ capCount(t.id) }}</span>
      </button>
    </nav>

    <p v-if="err" class="banner bad">{{ err }}</p>
    <p v-if="missing.length" class="banner">尚未生成：{{ missing.join('、') }}。已有产物仍会展示。</p>

    <!-- 1 协议标识 -->
    <section v-if="tab === 'ident'" class="row split">
      <article class="panel">
        <header>
          <h2>协议标识</h2>
          <span>{{ protocols.total || 0 }} 个入口</span>
        </header>
        <table>
          <thead>
            <tr>
              <th>协议</th><th>服务</th><th>端口</th><th>族</th><th>置信</th><th>暴露</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="row in protocols.items || []"
              :key="row.id"
              :class="{ on: selectedInput === row.id }"
              @click="selectedInput = row.id"
            >
              <td>
                <b>{{ row.protocol }}</b>
                <small v-if="row.plaintext" class="warn">明文</small>
              </td>
              <td>{{ row.service }}</td>
              <td class="mono">{{ fmtPort(row) }}</td>
              <td>{{ row.family }}</td>
              <td>{{ pct(row.confidence) }}</td>
              <td>{{ row.public ? '公网' : '内部' }}</td>
            </tr>
            <tr v-if="!(protocols.items || []).length">
              <td colspan="6" class="empty">选择已识别输入的固件任务后，这里列出协议标识。</td>
            </tr>
          </tbody>
        </table>
      </article>
      <article class="panel">
        <header>
          <h2>协议族</h2>
          <span>按入口计数</span>
        </header>
        <DonutChart :items="protocols.families || []" sub="入口" title="协议族分布" />
        <div v-if="currentInput" class="detail">
          <h3>{{ currentInput.id }} · {{ currentInput.service }}</h3>
          <p>证据：{{ currentInput.evidence || '无' }}</p>
          <div class="chips">
            <span v-for="t in visibleTypes(currentInput.input_types)" :key="t">{{ t }}</span>
          </div>
          <p class="mono files">{{ (currentInput.entry_files || []).join('\n') }}</p>
        </div>
      </article>
    </section>

    <!-- 2 加密算法识别 -->
    <section v-else-if="tab === 'algo'" class="row split">
      <article class="panel">
        <header>
          <h2>加密算法识别</h2>
          <span>{{ (crypto.algorithms || []).length }} 种</span>
        </header>
        <ul class="algo-grid">
          <li
            v-for="a in crypto.algorithms || []"
            :key="a.id"
            :class="['algo', a.strength, { on: algoFilter === a.id }]"
            @click="algoFilter = algoFilter === a.id ? '' : a.id"
          >
            <b>{{ a.label }}</b>
            <em>{{ a.strength_label }}</em>
            <span>{{ a.count }} 处 · {{ a.binaries }} 个二进制</span>
            <small>{{ a.family }}</small>
          </li>
          <li v-if="!(crypto.algorithms || []).length" class="empty-row">没有扫到明显的算法符号。</li>
        </ul>
      </article>
      <article class="panel">
        <header>
          <h2>命中函数</h2>
          <span>{{ filteredFns.length }} / {{ crypto.function_total || 0 }}</span>
        </header>
        <ul class="list">
          <li v-for="fn in filteredFns" :key="fn.binary + fn.addr" @click="openReverse(fn)">
            <b>{{ fn.name }}</b>
            <span>{{ fn.algos.join(', ') }} · {{ fn.role }} · {{ shortMd5(fn.binary) }} {{ fn.addr }}</span>
          </li>
          <li v-if="!filteredFns.length" class="empty-row">选择左侧算法，或换一个已反编译的任务。</li>
        </ul>
      </article>
    </section>

    <!-- 3 深度分析 -->
    <section v-else-if="tab === 'deep'" class="row split">
      <article class="panel">
        <header>
          <h2>加密算法深度分析</h2>
          <span>模式 / 角色 / 常量表</span>
        </header>
        <div v-for="row in cryptoDeep" :key="row.binary + row.addr" class="deep-card" @click="openReverse(row)">
          <div class="deep-head">
            <b>{{ row.name }}</b>
            <span class="pill">{{ row.role }}</span>
            <span v-for="a in row.algos" :key="a" class="chip">{{ a }}</span>
          </div>
          <p v-for="n in row.notes" :key="n">{{ n }}</p>
          <p v-if="row.constants.length" class="mono">常量：{{ row.constants.join('、') }}</p>
          <pre v-if="row.source_head" class="out slim">{{ row.source_head }}</pre>
        </div>
        <p v-if="!cryptoDeep.length" class="empty">先完成反编译，再看算法实现细节。</p>
      </article>
      <article class="panel">
        <header>
          <h2>材料线索</h2>
          <span>固件内字符串，不是在线抽钥</span>
        </header>
        <ul class="list">
          <li v-for="(m, i) in crypto.materials || []" :key="i">
            <b>{{ m.kind }}</b>
            <span class="mono">{{ m.preview }}</span>
          </li>
          <li v-if="!(crypto.materials || []).length" class="empty-row">没有发现 PEM / 长十六进制材料。</li>
        </ul>
        <RadarChart
          v-if="deepRadar.axes.length"
          title="算法态势"
          :axes="deepRadar.axes"
          :scores="deepRadar.scores"
        />
      </article>
    </section>

    <!-- 4 算法逆向 -->
    <section v-else-if="tab === 'rev'" class="row split">
      <article class="panel">
        <header>
          <h2>算法逆向</h2>
          <span>伪 C 归纳，不是破解</span>
        </header>
        <el-select v-model="revKey" placeholder="选择算法函数" class="full" filterable @change="loadReverse">
          <el-option
            v-for="fn in crypto.functions || []"
            :key="fn.binary + fn.addr"
            :value="fn.binary + '@' + fn.addr"
            :label="`${fn.name} · ${(fn.algos || []).join('/')}`"
          />
        </el-select>
        <div v-if="rev" class="rev-meta">
          <p class="narrative">{{ rev.narrative }}</p>
          <div class="chips">
            <span v-for="p in rev.primitives || []" :key="p.id">{{ p.label }}</span>
            <span v-for="m in rev.modes || []" :key="m">{{ m }}</span>
          </div>
          <p v-if="(rev.calls || []).length" class="muted">调用：{{ rev.calls.slice(0, 12).join(', ') }}</p>
          <div class="acts">
            <button type="button" class="ghost" :class="{ on: showAsm }" @click="showAsm = !showAsm">
              {{ showAsm ? '看伪 C' : '看汇编' }}
            </button>
          </div>
        </div>
        <p v-else class="empty">从算法识别结果里点一个函数，查看实现路径。</p>
      </article>
      <article class="panel">
        <header>
          <h2>{{ showAsm ? '汇编' : '伪 C' }}</h2>
          <span v-if="rev" class="mono">{{ shortMd5(rev.binary) }} {{ rev.addr }}</span>
        </header>
        <pre class="out code">{{ reverseText || '等待选择函数。' }}</pre>
      </article>
    </section>

    <!-- 5 流量实时解码 -->
    <section v-else-if="tab === 'decode'" class="row split">
      <article class="panel">
        <header>
          <h2>流量实时解码</h2>
          <span class="live"><i />粘贴即拆字段</span>
        </header>
        <textarea
          v-model="hex"
          rows="12"
          placeholder="十六进制或 Base64，例如 474554202f20485454502f312e310d0a"
        />
        <div class="acts">
          <button type="button" class="go" @click="runDecode">立即解码</button>
          <button type="button" class="ghost" @click="hex = ''">清空</button>
        </div>
        <div class="samples">
          <button v-for="s in samples" :key="s.id" type="button" @click="hex = s.hex">{{ s.label }}</button>
        </div>
      </article>
      <article class="panel">
        <header>
          <h2>{{ decode.label || '解码结果' }}</h2>
          <span v-if="decode.protocol">{{ pct(decode.confidence) }} · {{ decode.length || 0 }} 字节</span>
        </header>
        <p v-if="decode.summary">{{ decode.summary }}</p>
        <p v-for="n in decode.notes || []" :key="n" class="muted">{{ n }}</p>
        <table v-if="(decode.fields || []).length">
          <thead><tr><th>字段</th><th>偏移</th><th>值</th><th>说明</th></tr></thead>
          <tbody>
            <tr v-for="(f, i) in decode.fields" :key="i">
              <td>{{ f.name }}</td>
              <td class="mono">{{ f.offset }}</td>
              <td class="mono">{{ f.value }}</td>
              <td>{{ f.note }}</td>
            </tr>
          </tbody>
        </table>
        <pre class="out slim">{{ liveDump || '等待粘贴报文。识别 HTTP / DNS / TLS / DHCP / MQTT / Modbus / CoAP / S7 / OPC UA / DNP3。' }}</pre>
      </article>
    </section>

    <!-- 6 攻击面评估 -->
    <section v-else class="row split">
      <article class="panel">
        <header>
          <h2>攻击面评估</h2>
          <span>{{ assessment.level || '—' }}风险</span>
        </header>
        <div class="assess-top">
          <ProgressRing :value="assessment.score || 0" label="综合风险" :sub="assessment.level || '待评估'" />
          <RadarChart
            title="协议攻击面"
            :axes="assessAxes"
            :scores="assessScores"
          />
        </div>
        <ul class="recs">
          <li v-for="r in assessment.recommendations || []" :key="r">{{ r }}</li>
        </ul>
      </article>
      <article class="panel">
        <header>
          <h2>入口风险排序</h2>
          <span>{{ (assessment.ranked || []).length }} 条</span>
        </header>
        <ul class="rank">
          <li v-for="(row, i) in assessment.ranked || []" :key="row.id || i">
            <em>{{ i + 1 }}</em>
            <span>{{ row.protocol }} · {{ row.service }}</span>
            <b>{{ row.score }}</b>
            <small>{{ row.level }} · {{ (row.reasons || []).join(' / ') }}</small>
          </li>
          <li v-if="!(assessment.ranked || []).length" class="empty-row">没有可评估的协议入口。</li>
        </ul>
      </article>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { api } from '../api'
import DonutChart from '../components/charts/DonutChart.vue'
import RadarChart from '../components/charts/RadarChart.vue'
import CountUp from '../components/fx/CountUp.vue'
import ProgressRing from '../components/ProgressRing.vue'
import { NAV_ICONS } from '../workbench/icons.js'
import { STATUS_TEXT } from '../workbench/pipeline.js'


const tabs = [
  { id: 'ident', no: '01', label: '协议标识', hint: '识别服务、端口与协议族', icon: 'Search' },
  { id: 'algo', no: '02', label: '加密算法识别', hint: '扫描符号与字符串命中', icon: 'Lock' },
  { id: 'deep', no: '03', label: '深度分析', hint: '运算模式与魔数常量', icon: 'Cpu' },
  { id: 'rev', no: '04', label: '算法逆向', hint: '定位伪 C 实现路径', icon: 'Document' },
  { id: 'decode', no: '05', label: '流量实时解码', hint: '粘贴报文即拆字段', icon: 'Download' },
  { id: 'assess', no: '06', label: '攻击面评估', hint: '入口风险综合排序', icon: 'Aim' }
]

// 能力卡右上角实时计数（null = 交互型工具不显计数）
function capCount (id) {
  if (!report.value) return null
  if (id === 'ident') return protocols.value.total || 0
  if (id === 'algo') return (crypto.value.algorithms || []).length
  if (id === 'deep') return (cryptoDeep.value || []).length
  if (id === 'assess') return (assessment.value.ranked || []).length
  return null
}

// ?tab= 深链：命令面板/分享链接直达某个能力；切换时写回地址栏
const tab = ref((() => {
  const q = new URLSearchParams(window.location.search).get('tab')
  if (tabs.some((t) => t.id === q)) return q
  // 命令面板深链：面板把目标能力放 sessionStorage 后重挂载本页
  try {
    const st = sessionStorage.getItem('fwgraph_proto_tab')
    sessionStorage.removeItem('fwgraph_proto_tab')
    if (tabs.some((t) => t.id === st)) return st
  } catch { /* private mode */ }
  return 'ident'
})())
watch(tab, (t) => {
  const url = new URL(window.location.href)
  url.searchParams.set('tab', t)
  window.history.replaceState(null, '', url)
}, { immediate: true })
const jobs = ref([])
const jobId = ref('')
const loading = ref(false)
const err = ref('')
const report = ref(null)
const selectedInput = ref('')
const algoFilter = ref('')
const hex = ref('')
const decode = ref({})
const liveDump = ref('')
const revKey = ref('')
const rev = ref(null)
const showAsm = ref(false)
let decodeTimer = 0

const samples = [
  { id: 'http', label: 'HTTP GET', hex: '474554202f20485454502f312e310d0a486f73743a20726f757465720d0a0d0a' },
  { id: 'tls', label: 'TLS 记录', hex: '160301000401000000' },
  { id: 'modbus', label: 'Modbus', hex: '00010000000601030000000a' },
  { id: 'mqtt', label: 'MQTT', hex: '101000044d5154540402003c0000' }
]

const protocols = computed(() => report.value?.protocols || {})
const crypto = computed(() => report.value?.crypto || {})
const cryptoDeep = computed(() => report.value?.crypto_deep || [])
const assessment = computed(() => report.value?.assessment || {})
const missing = computed(() => report.value?.missing || [])

const currentInput = computed(() =>
  (protocols.value.items || []).find((row) => row.id === selectedInput.value)
  || (protocols.value.items || [])[0]
  || null
)

const filteredFns = computed(() => {
  const rows = crypto.value.functions || []
  if (!algoFilter.value) return rows.slice(0, 24)
  return rows.filter((fn) => (fn.algos || []).includes(algoFilter.value)).slice(0, 40)
})

const kpiCards = computed(() => [
  { id: 'p', tab: 'ident', label: '协议入口', value: protocols.value.total || 0, hint: '已标识输入' },
  { id: 'pub', tab: 'ident', label: '公网暴露', value: protocols.value.public || 0, hint: '非回环入口' },
  { id: 'a', tab: 'algo', label: '算法种类', value: (crypto.value.algorithms || []).length, hint: '符号命中' },
  { id: 'w', tab: 'deep', label: '弱算法', value: (crypto.value.weak || []).length, hint: 'MD5 / DES / RC4' },
  { id: 's', tab: 'assess', label: '攻击面', value: assessment.value.surfaces || 0, hint: '已导出表面' },
  { id: 'r', tab: 'assess', label: '综合风险', value: assessment.value.score || 0, hint: assessment.value.level || '待评估' }
])

const deepRadar = computed(() => {
  const algos = crypto.value.algorithms || []
  const weak = (crypto.value.weak || []).length
  const legacy = (crypto.value.legacy || []).length
  const mats = (crypto.value.materials || []).length
  const pathN = (crypto.value.functions || []).filter((f) => f.on_attack_path).length
  const obs = (crypto.value.functions || []).filter((f) => f.observed_in_trace).length
  return {
    axes: [
      { key: 'n', label: '种类' },
      { key: 'weak', label: '弱算法' },
      { key: 'leg', label: '过时' },
      { key: 'mat', label: '材料' },
      { key: 'path', label: '路径' },
      { key: 'obs', label: '观测' }
    ],
    scores: [
      Math.min(1, algos.length / 8),
      Math.min(1, weak / 3),
      Math.min(1, legacy / 3),
      Math.min(1, mats / 6),
      Math.min(1, pathN / 8),
      Math.min(1, obs / 8)
    ]
  }
})

const assessAxes = computed(() => (assessment.value.axes || []).map((a) => ({
  key: a.key,
  label: a.label
})))
const assessScores = computed(() => (assessment.value.axes || []).map((a) => a.score || 0))

const reverseText = computed(() => {
  if (!rev.value) return ''
  return showAsm.value ? (rev.value.asm || '没有汇编导出。') : (rev.value.source || '没有伪 C。')
})

onMounted(async () => {
  try {
    const list = await api('/jobs')
    jobs.value = Array.isArray(list) ? list : []
    if (!jobId.value && jobs.value[0]) {
      jobId.value = jobs.value[0].job_id
      loadReport()
    }
  } catch {
    jobs.value = []
  }
})

onUnmounted(() => {
  if (decodeTimer) window.clearTimeout(decodeTimer)
})

watch(hex, () => {
  liveDump.value = localDump(hex.value)
  if (decodeTimer) window.clearTimeout(decodeTimer)
  decodeTimer = window.setTimeout(runDecode, 280)
})

function pct (n) {
  return `${Math.round((Number(n) || 0) * 100)}%`
}
function shortMd5 (s) {
  return String(s || '').slice(0, 8)
}
function fmtPort (row) {
  const port = row.port ?? '—'
  return `${row.address || '*'}:${port}/${row.transport || '?'}`
}
function visibleTypes (types) {
  return (types || []).filter((t) => !String(t).startsWith('binary_md5=')).slice(0, 8)
}

async function loadReport () {
  if (!jobId.value) return
  loading.value = true
  err.value = ''
  try {
    report.value = await api(`/jobs/${jobId.value}/protocol-reverse`)
    selectedInput.value = report.value?.protocols?.items?.[0]?.id || ''
    algoFilter.value = ''
    rev.value = null
    revKey.value = ''
  } catch (e) {
    report.value = null
    err.value = e.message || '分析失败'
  } finally {
    loading.value = false
  }
}

function openReverse (fn) {
  revKey.value = `${fn.binary}@${fn.addr}`
  tab.value = 'rev'
  loadReverse()
}

async function loadReverse () {
  if (!jobId.value || !revKey.value) return
  const [md5, addr] = revKey.value.split('@')
  err.value = ''
  try {
    rev.value = await api(
      `/jobs/${jobId.value}/protocol-reverse/functions/${md5}/${addr}`
    )
    showAsm.value = false
  } catch (e) {
    rev.value = null
    err.value = e.message || '无法打开函数'
  }
}

function parseBytes (text) {
  const compact = String(text || '').replace(/\s+/g, '')
  if (!compact) return []
  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0) {
    const out = []
    for (let i = 0; i < compact.length; i += 2) out.push(parseInt(compact.slice(i, i + 2), 16))
    return out
  }
  try {
    const bin = atob(compact)
    return Array.from(bin, (c) => c.charCodeAt(0))
  } catch {
    return []
  }
}

function localDump (text) {
  const bytes = parseBytes(text)
  if (!bytes.length) return text.trim() ? '无法解析为十六进制或 Base64。' : ''
  const lines = [`长度 ${bytes.length} 字节`]
  for (let i = 0; i < Math.min(bytes.length, 160); i += 16) {
    const chunk = bytes.slice(i, i + 16)
    const hx = chunk.map((b) => b.toString(16).padStart(2, '0')).join(' ')
    const ascii = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('')
    lines.push(`${i.toString(16).padStart(8, '0')}  ${hx.padEnd(47)}  ${ascii}`)
  }
  return lines.join('\n')
}

async function runDecode () {
  const raw = hex.value.trim()
  if (!raw) {
    decode.value = {}
    liveDump.value = ''
    return
  }
  liveDump.value = localDump(raw)
  try {
    decode.value = await api('/protocol/decode', { method: 'POST', body: { text: raw } })
  } catch (e) {
    decode.value = { label: '解码失败', notes: [e.message], fields: [] }
  }
}
</script>

<style scoped>
.proto { min-height: 100%; padding: 22px 24px 40px; color: var(--fw-text); }
.hero { display: flex; justify-content: space-between; gap: 16px; align-items: flex-end; margin-bottom: 16px; }
.kicker { margin: 0 0 6px; color: var(--fw-brand); letter-spacing: .04em; font-size: 12px; font-weight: 600; }
h1 { margin: 0 0 6px; font-size: 26px; letter-spacing: -.04em; }
.hero p { margin: 0; color: var(--fw-text-2); font-size: 13px; max-width: 640px; }
.hero-side { display: flex; gap: 8px; align-items: center; }
.job { width: 320px; }
.kpis { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; margin-bottom: 14px; }
.kpi {
  text-align: left; padding: 12px 14px;
  border: 1px solid var(--fw-line); border-radius: 14px;
  background: var(--fw-surface);
  color: inherit; cursor: pointer;
  box-shadow: var(--fw-shadow);
}
.kpi:hover { border-color: rgba(19, 76, 255, .28); }
.kpi-label { color: var(--fw-text-3); font-size: 12px; }
.kpi strong {
  display: block; margin: 6px 0 2px; font-size: 26px; color: var(--fw-text);
}
.kpi em { font-style: normal; color: var(--fw-text-3); font-size: 11px; }
.caps {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 16px;
}
.cap {
  position: relative;
  display: flex;
  align-items: flex-start;
  gap: 10px;
  text-align: left;
  padding: 13px 12px 12px;
  border-radius: 14px;
  cursor: pointer;
  border: 1px solid var(--fw-line);
  background: var(--fw-surface);
  color: var(--fw-text-2);
  box-shadow: var(--fw-shadow);
  font-family: inherit;
  transition: border-color .16s ease, box-shadow .16s ease, transform .16s ease;
}
.cap:hover {
  border-color: rgba(19, 76, 255, .32);
  box-shadow: 0 6px 18px -6px rgba(16, 24, 40, .14);
  transform: translateY(-1px);
}
.cap.on {
  border-color: rgba(19, 76, 255, .55);
  background: linear-gradient(180deg, rgba(19, 76, 255, .07), rgba(19, 76, 255, .03)), var(--fw-surface);
  box-shadow: 0 0 0 3px rgba(19, 76, 255, .09);
}
.cap.on::after {
  content: '';
  position: absolute;
  left: 12px;
  right: 12px;
  bottom: -1px;
  height: 2px;
  border-radius: 2px;
  background: var(--fw-brand);
}
.cap-ico {
  flex: none;
  display: grid;
  place-items: center;
  width: 34px;
  height: 34px;
  border-radius: 10px;
  background: var(--fw-fill);
  color: var(--fw-brand);
}
.cap.on .cap-ico { background: rgba(19, 76, 255, .14); }
.cap-copy { flex: 1; min-width: 0; display: flex; flex-direction: column; }
.cap-no {
  color: var(--fw-text-3);
  font-size: 10px;
  letter-spacing: .16em;
  font-weight: 650;
}
.cap-label { display: block; margin: 3px 0 2px; font-size: 13.5px; color: var(--fw-text); line-height: 1.3; }
.cap.on .cap-label { color: var(--fw-brand); font-weight: 650; }
.cap-hint {
  font-size: 11px;
  color: var(--fw-text-3);
  line-height: 1.45;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.cap-count {
  flex: none;
  min-width: 22px;
  height: 20px;
  padding: 0 6px;
  border-radius: 999px;
  background: var(--fw-bg-2);
  color: var(--fw-text-2);
  font-size: 11px;
  font-weight: 650;
  line-height: 20px;
  text-align: center;
  font-variant-numeric: tabular-nums;
}
.cap.on .cap-count { background: rgba(19, 76, 255, .14); color: var(--fw-brand); }
.banner { margin: 0 0 12px; color: var(--fw-warn); font-size: 12px; }
/* 能力切换时内容区淡入，避免生硬跳变 */
.proto > section.row { animation: fw-page-in .2s ease both; }
.banner.bad { color: var(--fw-danger); }
.row { display: grid; gap: 12px; }
.row.split { grid-template-columns: minmax(0, 1.2fr) minmax(0, .8fr); }
.panel {
  padding: 16px; border: 1px solid var(--fw-line); border-radius: 16px;
  background-color: var(--fw-surface); box-shadow: var(--fw-shadow);
}
.panel header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 12px; }
h2 { margin: 0; font-size: 14px; }
.panel header span { color: var(--fw-text-3); font-size: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { text-align: left; color: var(--fw-text-3); font-weight: 500; padding: 0 8px 8px 0; }
td { padding: 8px 8px 8px 0; border-top: 1px solid var(--fw-line); }
tr.on td, tbody tr:hover td { background: var(--fw-fill); }
tbody tr { cursor: pointer; }
.warn { margin-left: 6px; color: var(--fw-warn); font-size: 10px; }
.mono { font-family: var(--fw-font-mono); font-size: 11px; color: var(--fw-brand); }
.empty, .empty-row { color: var(--fw-text-3); font-size: 13px; }
.detail { margin-top: 14px; }
.detail h3 { margin: 0 0 6px; font-size: 14px; }
.detail p { margin: 0 0 8px; color: var(--fw-text-2); font-size: 12px; line-height: 1.55; }
.chips, .samples { display: flex; flex-wrap: wrap; gap: 6px; }
.chips span, .chip, .pill {
  display: inline-block; padding: 2px 8px; border-radius: 99px;
  background: var(--fw-fill); color: var(--fw-brand); font-size: 11px;
}
.files { white-space: pre-wrap; word-break: break-all; }
.algo-grid { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.algo {
  padding: 10px 12px; border-radius: 12px; cursor: pointer;
  border: 1px solid var(--fw-line); background: var(--fw-surface);
}
.algo.on { border-color: var(--fw-brand); }
.algo.weak { border-color: rgba(225, 29, 72, .45); }
.algo.legacy { border-color: rgba(217, 119, 6, .4); }
.algo b { display: block; }
.algo em { font-style: normal; font-size: 11px; color: var(--fw-brand); }
.algo span, .algo small { display: block; color: var(--fw-text-3); font-size: 11px; }
.list { list-style: none; margin: 0; padding: 0; max-height: 460px; overflow: auto; }
.list li { padding: 8px 0; border-top: 1px solid var(--fw-line); cursor: pointer; }
.list b { display: block; font-size: 13px; }
.list span { display: block; color: var(--fw-text-3); font-size: 12px; }
.deep-card {
  padding: 10px 0; border-top: 1px solid var(--fw-line); cursor: pointer;
}
.deep-head { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 6px; }
.deep-card p { margin: 0 0 4px; color: var(--fw-text-2); font-size: 12px; }
.out {
  width: 100%; min-height: 160px; border: 1px solid var(--fw-line); border-radius: 10px;
  background: var(--fw-bg); color: var(--fw-text); padding: 12px 14px; font: 500 13px/1.6 var(--fw-font-mono);
  white-space: pre-wrap; word-break: break-all;
}
.out.slim { min-height: 80px; max-height: 220px; overflow: auto; }
.out.code { min-height: 360px; max-height: 62vh; overflow: auto; color: #854d0e; }
textarea {
  width: 100%; min-height: 220px; border: 1px solid var(--fw-line); border-radius: 10px;
  background: var(--fw-bg); color: var(--fw-text); padding: 10px; font: 12px/1.5 var(--fw-font-mono);
}
.acts { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
.go, .ghost {
  height: 34px; padding: 0 14px; border-radius: 8px; cursor: pointer; font-weight: 600;
}
.go { border: none; background: var(--fw-brand); color: #fff; }
.ghost { border: 1px solid var(--fw-line); background: transparent; color: var(--fw-text-2); }
.ghost.on { border-color: var(--fw-brand); color: var(--fw-brand); }
.samples { margin-top: 10px; }
.samples button {
  height: 26px; padding: 0 10px; border-radius: 99px; cursor: pointer;
  border: 1px solid var(--fw-line); background: transparent; color: var(--fw-brand); font-size: 12px;
}
.live { display: inline-flex; align-items: center; gap: 6px; color: var(--fw-ok); }
.live i {
  width: 7px; height: 7px; border-radius: 50%; background: var(--fw-ok);
}
.narrative { color: var(--fw-text-2); font-size: 13px; line-height: 1.65; }
.muted { color: var(--fw-text-3); font-size: 12px; }
.full { width: 100%; margin-bottom: 10px; }
.assess-top { display: grid; grid-template-columns: 180px 1fr; gap: 8px; align-items: center; }
.recs { margin: 12px 0 0; padding-left: 18px; color: var(--fw-text-2); font-size: 13px; line-height: 1.6; }
.rank { list-style: none; margin: 0; padding: 0; }
.rank li {
  display: grid; grid-template-columns: 22px 1fr auto; gap: 8px; align-items: center;
  padding: 8px 0; border-top: 1px solid var(--fw-line); font-size: 13px;
}
.rank em { color: var(--fw-brand); font-style: normal; }
.rank small { grid-column: 2; color: var(--fw-text-3); font-size: 11px; }
@media (max-width: 1100px) {
  .kpis { grid-template-columns: repeat(4, minmax(0, 1fr)); }
  .caps { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .row.split, .assess-top, .hero { display: block; }
  .job { width: 100%; margin-bottom: 8px; }
}
@media (max-width: 720px) {
  .kpis, .caps { grid-template-columns: 1fr 1fr; }
  .proto { padding: 16px 12px 28px; }
}
</style>
