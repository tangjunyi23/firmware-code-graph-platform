<template>
  <div class="vulnlib lib-page">
    <header class="ins-head">
      <div class="ins-head-row">
        <h1 class="ins-title"><span class="ins-ico"><component :is="NAV_ICONS.Collection" :size="18" /></span>漏洞库</h1>
        <div class="ins-actions">
          <el-radio-group v-model="viewMode" size="small">
            <el-radio-button value="lib">条目库</el-radio-button>
            <el-radio-button value="firmware">按固件</el-radio-button>
          </el-radio-group>
        </div>
      </div>
      <p class="ins-sub">已知漏洞检索：CVE / CNVD / 厂商通告。</p>
    </header>

    <div v-if="viewMode === 'lib'" class="lib-layout">
      <!-- 左列：筛选 + 列表（与报告中心同范式） -->
      <div class="lib-card list-col">
        <div class="lib-head">
          <h2>{{ mode === 'nday' ? 'N-day 候选' : '漏洞条目' }}</h2>
          <span class="lib-count">{{ items.length }}{{ mode === 'nday' ? '' : ` / ${total}` }}</span>
          <div class="lib-actions">
            <el-button size="small" @click="showAdd = true">收录</el-button>
            <el-button size="small" @click="showImport = true">导入</el-button>
            <el-button size="small" :loading="seeding" @click="loadSamples">示例</el-button>
          </div>
        </div>
        <div class="lib-toolbar">
          <el-input
            v-model="q"
            clearable
            placeholder="CVE / CNVD / 厂商 / 产品 / 摘要"
            class="grow"
            @keyup.enter="runSearch"
          />
          <el-select v-model="source" clearable placeholder="来源" class="w-src" @change="runSearch">
            <el-option value="cve" label="CVE" />
            <el-option value="cnvd" label="CNVD" />
            <el-option value="cnnvd" label="CNNVD" />
            <el-option value="manual" label="手工" />
            <el-option value="trivy" label="Trivy SCA" />
          </el-select>
          <el-select v-model="severity" clearable placeholder="危害" class="w-src" @change="runSearch">
            <el-option value="critical" label="严重" />
            <el-option value="high" label="高危" />
            <el-option value="medium" label="中危" />
            <el-option value="low" label="低危" />
            <el-option value="info" label="提示" />
          </el-select>
          <el-input v-model="vendor" clearable placeholder="厂商" class="w-src" @keyup.enter="runSearch" />
          <el-input v-model="product" clearable placeholder="产品" class="w-src" @keyup.enter="runSearch" />
          <el-input v-model="cwe" clearable placeholder="CWE" class="w-cwe" @keyup.enter="runSearch" />
          <el-button type="primary" :loading="loading" @click="runSearch">查询</el-button>
          <el-button :loading="ndayLoading" @click="runNday">查 N-day</el-button>
        </div>
        <div class="lib-stats">
          <span>库内 <b>{{ stats.total || 0 }}</b> 条</span>
          <span v-for="(n, k) in stats.by_source || {}" :key="k">{{ sourceLabel(k) }} <b>{{ n }}</b></span>
          <el-select v-model="jobId" clearable placeholder="N-day 对照任务" size="small" class="job-select">
            <el-option
              v-for="j in jobs"
              :key="j.job_id"
              :value="j.job_id"
              :label="`${j.firmware}  (${j.job_id})`"
            />
          </el-select>
        </div>
        <div class="list-scroll">
          <el-empty v-if="!loading && !items.length" :description="emptyHint" :image-size="70" />
          <div
            v-for="row in items"
            :key="row.id"
            class="lib-item"
            :class="{ active: row.id === currentId }"
            @click="open(row)"
          >
            <div class="li-top">
              <span class="li-id">{{ row.id }}</span>
              <el-tag size="small" :type="sevType(row.severity)" effect="dark">{{ sevLabel(row.severity) }}</el-tag>
            </div>
            <div class="li-title" :title="row.title">{{ row.title }}</div>
            <div class="li-meta">
              {{ sourceLabel(row.source) }}
              <template v-if="(row.vendors || []).length"> · {{ (row.vendors || []).join(' / ') }}</template>
              <template v-if="row.match_score"> · 匹配 {{ row.match_score }}</template>
            </div>
          </div>
        </div>
      </div>

      <!-- 右列：条目详情 -->
      <div class="lib-card detail-col">
        <div class="lib-head">
          <h2 class="viewer-title">{{ current?.id || '条目详情' }}</h2>
          <div class="lib-actions">
            <el-button
              v-if="isAdmin && currentId"
              size="small"
              type="danger"
              plain
              @click="removeCurrent"
            >删除</el-button>
          </div>
        </div>
        <el-empty v-if="!current" description="从左侧选一条，或先导入 CVE/CNVD JSON" :image-size="80" />
        <template v-else>
          <h2 class="title">{{ current.title }}</h2>
          <el-descriptions :column="2" border size="small">
            <el-descriptions-item label="编号">
              <span class="mono">{{ current.id }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="来源">{{ sourceLabel(current.source) }}</el-descriptions-item>
            <el-descriptions-item label="危害">
              <el-tag size="small" :type="sevType(current.severity)" effect="dark">{{ sevLabel(current.severity) }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="CVSS">{{ current.cvss ?? '—' }}</el-descriptions-item>
            <el-descriptions-item label="CWE">
              <span class="mono">{{ (current.cwes || []).join(' ') || '—' }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="发布">{{ current.published || '—' }}</el-descriptions-item>
            <el-descriptions-item label="厂商" :span="2">{{ (current.vendors || []).join(' / ') || '—' }}</el-descriptions-item>
            <el-descriptions-item label="产品" :span="2">{{ (current.products || []).join(' / ') || '—' }}</el-descriptions-item>
            <el-descriptions-item v-if="(current.aliases || []).length" label="别名" :span="2">
              <span class="mono">{{ current.aliases.join(' ') }}</span>
            </el-descriptions-item>
          </el-descriptions>
          <div class="sec">漏洞点</div>
          <p class="point">{{ current.vuln_point || '未填写。收录时请写触发入口、处理函数和危险调用。' }}</p>
          <div class="sec">漏洞描述</div>
          <div class="desc">{{ current.description || current.summary || '未填写中文描述。' }}</div>
          <div v-if="(current.references || []).length" class="refs">
            <div class="sec">参考链接</div>
            <a v-for="r in current.references" :key="r" :href="r" target="_blank" rel="noopener" class="ref">{{ r }}</a>
          </div>
          <div v-if="(current.matches || []).length" class="matches">
            <div class="sec">命中的本机任务（候选，不是判定）</div>
            <div v-for="m in current.matches" :key="m.job_id" class="match">
              <span class="mono">{{ m.job_id }}</span>
              <span>{{ m.firmware }}</span>
              <span class="muted">{{ (m.reasons || []).join('；') }}</span>
            </div>
          </div>
        </template>
      </div>
    </div>

    <!-- 按固件视角：选已分析固件，看它的漏洞清单 -->
    <div v-else class="lib-layout">
      <div class="lib-card list-col">
        <div class="lib-head">
          <h2>固件</h2>
          <span class="lib-count">{{ fwJobs.length }} 台</span>
        </div>
        <div class="list-scroll">
          <el-empty v-if="!fwJobs.length" description="还没有完成分析的固件任务" :image-size="70" />
          <div
            v-for="j in fwJobs"
            :key="j.job_id"
            class="lib-item"
            :class="{ active: fwSel === j.job_id }"
            @click="pickFw(j.job_id)"
          >
            <div class="li-top">
              <span class="li-id">{{ fwLabel(j) }}</span>
              <span v-if="fwCount(j.job_id)" class="fw-badge">{{ fwCount(j.job_id) }} 发现</span>
            </div>
            <div class="li-meta">{{ STATUS_TEXT[j.status] || j.status }} · {{ fwSev(j.job_id) || '暂无发现' }}</div>
          </div>
        </div>
      </div>

      <div class="lib-card detail-col">
        <div class="lib-head">
          <h2 class="viewer-title">{{ fwSelLabel || '固件漏洞清单' }}</h2>
        </div>
        <el-empty v-if="!fwSel" description="从左侧选择一台固件" :image-size="80" />
        <template v-else>
          <div class="fw-stats">
            <span class="lib-chip">挖掘发现 <b>{{ fwFindingsOf(fwSel).length }}</b></span>
            <span class="lib-chip">SCA CVE <b>{{ fwSca?.result?.cve_total ?? '—' }}</b></span>
            <span class="lib-chip" :class="{ hot: fwScaSecrets > 0 }">密钥泄漏 <b>{{ fwScaSecrets }}</b></span>
          </div>

          <div class="sec">挖掘发现（AI 挖掘会话产出）</div>
          <div v-for="f in fwFindingsOf(fwSel)" :key="f.id" class="fw-finding" @click="toggleFw(f.id)">
            <div class="fd-row">
              <el-tag size="small" :type="sevType(f.severity)" effect="dark">{{ sevLabel(f.severity) }}</el-tag>
              <b class="fw-title">{{ f.title }}</b>
              <span class="fw-reach" :class="{ ok: f.reachability === 'verified' }">{{ reachLabel(f.reachability) }}</span>
            </div>
            <div class="fw-meta mono">{{ f.function_name || '—' }}{{ f.cwe ? ` · ${f.cwe}` : '' }}{{ f.confidence ? ` · 置信 ${f.confidence}` : '' }}</div>
            <pre v-if="fwOpen === f.id" class="fw-ev mono">{{ f.evidence || f.call_chain || f.summary || '（无证据摘录）' }}</pre>
          </div>
          <el-empty v-if="!fwFindingsOf(fwSel).length" description="该固件暂无挖掘发现" :image-size="60" />

          <div class="sec">SCA 组件风险（Trivy）</div>
          <template v-if="fwSca?.status === 'done'">
            <p class="fw-sca-note muted">{{ fwSca.result.note }}</p>
            <el-table v-if="(fwSca.result.vulns || []).length" :data="fwSca.result.vulns" size="small" max-height="300">
              <el-table-column label="CVE" width="170">
                <template #default="{ row }"><span class="mono">{{ row.cve }}</span></template>
              </el-table-column>
              <el-table-column label="危害" width="80">
                <template #default="{ row }">
                  <el-tag size="small" :type="sevType(row.severity)" effect="dark">{{ sevLabel(row.severity) }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="pkg" label="组件" min-width="130" show-overflow-tooltip />
              <el-table-column prop="installed" label="版本" width="90" />
              <el-table-column prop="fixed" label="修复" width="90" />
            </el-table>
            <div v-for="(sec, i) in (fwSca.result.secrets || []).slice(0, 10)" :key="`s-${i}`" class="fw-secret">
              <el-tag size="small" type="danger" effect="dark">密钥泄漏</el-tag>
              <span class="mono">{{ sec.rule }}</span>
              <span class="mono muted">{{ sec.path }}</span>
            </div>
          </template>
          <p v-else-if="fwSca?.status === 'running'" class="fw-sca-note muted">SCA 扫描进行中…</p>
          <p v-else class="fw-sca-note muted">该任务暂无 SCA 结果（旧任务或未扫描）。</p>
        </template>
      </div>
    </div>

    <el-dialog v-model="showAdd" title="收录一条" width="560px" append-to-body>
      <el-form label-width="88px">
        <el-form-item label="编号">
          <el-input v-model="form.id" placeholder="CVE-2017-13772 / CNVD-2019-01348，可空则自动编号" />
        </el-form-item>
        <el-form-item label="标题" required>
          <el-input v-model="form.title" />
        </el-form-item>
        <el-form-item label="来源">
          <el-select v-model="form.source" class="full">
            <el-option value="cve" label="CVE" />
            <el-option value="cnvd" label="CNVD" />
            <el-option value="cnnvd" label="CNNVD" />
            <el-option value="manual" label="手工" />
          </el-select>
        </el-form-item>
        <el-form-item label="危害">
          <el-select v-model="form.severity" class="full">
            <el-option value="critical" label="严重" />
            <el-option value="high" label="高危" />
            <el-option value="medium" label="中危" />
            <el-option value="low" label="低危" />
            <el-option value="info" label="提示" />
          </el-select>
        </el-form-item>
        <el-form-item label="厂商">
          <el-input v-model="form.vendors" placeholder="逗号分隔，如 TP-Link" />
        </el-form-item>
        <el-form-item label="产品">
          <el-input v-model="form.products" placeholder="逗号分隔，如 Archer C7" />
        </el-form-item>
        <el-form-item label="CWE">
          <el-input v-model="form.cwe" placeholder="CWE-121" />
        </el-form-item>
        <el-form-item label="漏洞点" required>
          <el-input v-model="form.vuln_point" type="textarea" :rows="3" placeholder="入口、处理函数、危险调用。例如：httpd /userRpm/PinRpm.htm → httpWscPin → strcpy 栈缓冲" />
        </el-form-item>
        <el-form-item label="漏洞描述" required>
          <el-input v-model="form.description" type="textarea" :rows="6" placeholder="用中文写清成因、触发条件、影响和利用方式" />
        </el-form-item>
        <el-form-item label="参考">
          <el-input v-model="form.references" placeholder="URL，逗号分隔" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAdd = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="saveOne">写入</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showImport" title="导入 JSON" width="640px" append-to-body>
      <p class="hint">对象、数组，或 <span class="mono">{ "advisories": [ ... ] }</span>。字段：id, title, vuln_point, description, severity, vendors, products, cwe。描述和漏洞点请用中文。</p>
      <el-input v-model="importText" type="textarea" :rows="12" placeholder='[{"id":"CVE-2017-13772","title":"...","vendors":["TP-Link"],"products":["Archer C7"]}]' />
      <div class="import-file">
        <input type="file" accept=".json,application/json" @change="onFile" />
      </div>
      <template #footer>
        <el-button @click="showImport = false">取消</el-button>
        <el-button type="primary" :loading="importing" @click="doImport">导入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { NAV_ICONS } from '../workbench/icons.js'
import { computed, inject, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { STATUS_TEXT } from '../workbench/pipeline.js'

const SAMPLE = [
  {
    id: 'CVE-2017-13772',
    title: 'TP-Link Archer C7 httpd 栈溢出',
    summary: '无线 PIN 处理路径栈溢出，可导致远程代码执行。',
    vuln_point: 'httpd 管理面 /userRpm/PinRpm.htm（WPS PIN）→ httpWscPin / PIN 解析函数，把攻击者控制的 PIN 字符串无界拷入固定栈缓冲（strcpy/sprintf），溢出覆盖返回地址。',
    description: '影响 TP-Link Archer C7 等机型的定制 httpd。攻击者向无线 PIN / WPS 相关管理接口提交超长 PIN 后，处理函数未校验长度，直接把输入写入栈上固定缓冲区。成功溢出可劫持控制流，在 httpd 进程（通常为 root）里执行任意代码。触发条件：能访问设备管理 Web 或相应 LAN 接口；部分版本无需完整认证。利用方式：构造超长 PIN，覆盖保存的返回地址或函数指针后跳到注入的 shellcode / ROP。修复应改为有界拷贝并拒绝超长 PIN，同时在 Web 与二进制两侧做长度校验。',
    severity: 'high',
    cvss: 8.8,
    cwe: 'CWE-121',
    vendors: ['TP-Link'],
    products: ['Archer C7'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2017-13772'],
    published: '2017-09-14'
  },
  {
    id: 'CVE-2019-18371',
    title: '小米路由器 R3 命令注入',
    summary: '小米 Mi WiFi R3 远程命令注入，可拿到设备 shell。',
    vuln_point: 'WAN/远程辅助通道上的 HTTP 接口（常见为 get_sta_list / 诊断类 CGI）→ 把用户可控参数拼进 system()/popen() 命令行，未过滤 shell 元字符。',
    description: '小米路由器 R3（miwifi）在处理部分 HTTP API 时，把调用方传入的 SSID、主机名或诊断参数直接拼进 shell 命令。攻击者可插入 ;、|、$(...) 等元字符，使设备以 root 执行任意命令。该问题曾与未授权或弱鉴权的远程通道组合，造成广域网可达的命令执行。触发条件：能访问有漏洞的 HTTP 接口（部分固件无需登录）。修复应对参数做白名单校验，改为 execve 参数数组，禁止经过 /bin/sh -c。',
    severity: 'high',
    cwe: 'CWE-78',
    vendors: ['小米'],
    products: ['miwifi R3', 'Mi WiFi R3'],
    references: ['https://nvd.nist.gov/vuln/detail/CVE-2019-18371'],
    published: '2019-10-23'
  },
  {
    id: 'CNVD-2019-22242',
    title: 'TP-Link 路由器 httpd 命令注入',
    summary: '管理 Web 表单字段拼进 system()，可造成命令执行。',
    vuln_point: 'httpd 管理页表单字段（如 nas_admin_pwd / 诊断主机名）→ nasSambaSetUserList / 诊断处理函数 → execFormatCmd → tp_systemEx("/bin/sh -c")。',
    description: 'TP-Link 定制 httpd 把部分管理表单字段未经转义拼进格式化命令，再经 execFormatCmd、tp_systemEx 以 root 调用 /bin/sh -c。攻击者提交含分号的口令或主机名即可执行任意命令。该编号用于 CNVD 检索演示，收录时请按实际公告核对受影响型号与版本。触发条件：能提交对应管理表单（多数需登录）。修复应过滤 shell 元字符，并改为 execve 参数数组调用 smbpasswd 等工具。',
    severity: 'high',
    cwe: 'CWE-78',
    vendors: ['TP-Link'],
    products: ['Archer C7'],
    source: 'cnvd'
  }
]

const principal = inject('wbAccount', ref(null))
const isAdmin = computed(() => principal.value?.role === 'admin')

const q = ref('')
const source = ref('')
const severity = ref('')
const vendor = ref('')
const product = ref('')
const cwe = ref('')
const jobId = ref('')
const jobs = ref([])
const items = ref([])
const total = ref(0)
const stats = ref({})
const loading = ref(false)
const ndayLoading = ref(false)
const seeding = ref(false)

// ---- 按固件视角 ----
const viewMode = ref('lib')
const fwJobs = ref([])
const fwAll = ref([])
const fwSel = ref('')
const fwSca = ref(null)
const fwOpen = ref('')

async function loadFwView () {
  try {
    const [jobs, findings] = await Promise.all([
      api('/jobs'),
      api('/vulnagent/findings')
        .then((d) => (Array.isArray(d) ? d : d.findings || d.items || []))
        .catch(() => [])
    ])
    fwAll.value = findings
    const has = new Set(findings.map((f) => f.job_id))
    fwJobs.value = (jobs || []).slice().sort((a, b) =>
      (has.has(b.job_id) ? 1 : 0) - (has.has(a.job_id) ? 1 : 0))
    if (!fwSel.value && fwJobs.value.length) pickFw(fwJobs.value[0].job_id)
  } catch { /* 保持空态 */ }
}

async function pickFw (jobId) {
  fwSel.value = jobId
  fwOpen.value = ''
  fwSca.value = null
  try {
    fwSca.value = await api(`/jobs/${jobId}/sca`)
  } catch { fwSca.value = null }
}

function fwLabel (j) {
  return String(j.firmware || j.job_id).replace(/\.(bin|img|chk|trx|tar|gz|zip)$/i, '') || j.job_id
}
const fwSelLabel = computed(() => {
  const j = fwJobs.value.find((x) => x.job_id === fwSel.value)
  return j ? fwLabel(j) : ''
})
function fwFindingsOf (jobId) {
  const rank = { critical: 0, high: 1, medium: 2, low: 3 }
  return fwAll.value.filter((f) => f.job_id === jobId)
    .sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9))
}
function fwCount (jobId) { return fwFindingsOf(jobId).length }
function fwSev (jobId) {
  const f = fwFindingsOf(jobId)
  if (!f.length) return ''
  const c = f.filter((x) => x.severity === 'critical').length
  const h = f.filter((x) => x.severity === 'high').length
  return `严重 ${c} · 高危 ${h}`
}
const fwScaSecrets = computed(() => (fwSca.value?.result?.secrets || []).length)
function reachLabel (r) {
  return { 'static-only': '仅静态', static: '仅静态', observed: '已观测', verified: '已验证' }[r] || r || '—'
}
function toggleFw (id) { fwOpen.value = fwOpen.value === id ? '' : id }

watch(viewMode, (m) => { if (m === 'firmware' && !fwJobs.value.length) loadFwView() })
const mode = ref('search')
const currentId = ref('')
const current = ref(null)
const showAdd = ref(false)
const showImport = ref(false)
const saving = ref(false)
const importing = ref(false)
const importText = ref('')
const form = reactive({
  id: '', title: '', source: 'cve', severity: 'high',
  vendors: '', products: '', cwe: '', vuln_point: '', description: '', references: ''
})

const emptyHint = computed(() => (
  mode.value === 'nday'
    ? '当前任务没有命中库内条目。先收录/导入 CVE、CNVD，再查 N-day。'
    : '库是空的。点「收录」或「导入 JSON」，也可先装入 Archer C7 / 小米 R3 示例。'
))

function sourceLabel (s) {
  return ({ cve: 'CVE', cnvd: 'CNVD', cnnvd: 'CNNVD', manual: '手工', trivy: 'Trivy SCA' })[s] || s || '—'
}
function sevLabel (s) {
  return ({ critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' })[s] || s || '—'
}
function sevType (s) {
  return ({ critical: 'danger', high: 'warning', medium: '', low: 'success', info: 'info' })[s] || 'info'
}
function splitCsv (text) {
  return String(text || '').split(/[,，]/).map((s) => s.trim()).filter(Boolean)
}

async function loadJobs () {
  try {
    jobs.value = await api('/jobs')
  } catch {
    jobs.value = []
  }
}

async function runSearch () {
  mode.value = 'search'
  loading.value = true
  try {
    const sp = new URLSearchParams()
    if (q.value) sp.set('q', q.value)
    if (source.value) sp.set('source', source.value)
    if (severity.value) sp.set('severity', severity.value)
    if (vendor.value) sp.set('vendor', vendor.value)
    if (product.value) sp.set('product', product.value)
    if (cwe.value) sp.set('cwe', cwe.value)
    sp.set('limit', '80')
    const data = await api(`/vulnlib?${sp}`)
    items.value = data.items || []
    total.value = data.total || 0
    stats.value = data.stats || {}
    if (items.value.length && !items.value.some((r) => r.id === currentId.value)) {
      open(items.value[0])
    }
  } catch (e) {
    ElMessage.error('查询失败: ' + e.message)
  } finally {
    loading.value = false
  }
}

async function runNday () {
  mode.value = 'nday'
  ndayLoading.value = true
  try {
    const sp = new URLSearchParams()
    if (q.value) sp.set('q', q.value)
    if (source.value) sp.set('source', source.value)
    if (vendor.value) sp.set('vendor', vendor.value)
    if (product.value) sp.set('product', product.value)
    if (jobId.value) sp.set('job_id', jobId.value)
    sp.set('limit', '80')
    const data = await api(`/vulnlib/nday?${sp}`)
    items.value = data.items || []
    total.value = data.total || 0
    stats.value = data.stats || {}
    if (items.value.length) open(items.value[0])
    else current.value = null
  } catch (e) {
    ElMessage.error('N-day 查询失败: ' + e.message)
  } finally {
    ndayLoading.value = false
  }
}

async function open (row) {
  currentId.value = row.id
  try {
    const doc = await api(`/vulnlib/${encodeURIComponent(row.id)}`)
    current.value = { ...doc, matches: row.matches }
  } catch (e) {
    current.value = row
    ElMessage.error('详情加载失败: ' + e.message)
  }
}

async function saveOne () {
  if (!form.title.trim()) {
    ElMessage.error('标题必填')
    return
  }
  if (!form.vuln_point.trim() || !form.description.trim()) {
    ElMessage.error('请用中文填写漏洞点和漏洞描述')
    return
  }
  saving.value = true
  try {
    const payload = {
      title: form.title.trim(),
      source: form.source,
      severity: form.severity,
      vuln_point: form.vuln_point.trim(),
      description: form.description.trim(),
      summary: form.description.trim().slice(0, 80),
      vendors: splitCsv(form.vendors),
      products: splitCsv(form.products),
      cwe: form.cwe.trim(),
      references: splitCsv(form.references)
    }
    if (form.id.trim()) payload.id = form.id.trim()
    if (!payload.cwe) delete payload.cwe
    const doc = await api('/vulnlib', { method: 'POST', body: payload })
    showAdd.value = false
    ElMessage.success('已写入 ' + doc.id)
    await runSearch()
    open(doc)
  } catch (e) {
    ElMessage.error('收录失败: ' + e.message)
  } finally {
    saving.value = false
  }
}

async function doImport () {
  let payload
  try {
    payload = JSON.parse(importText.value || 'null')
  } catch {
    ElMessage.error('JSON 无法解析')
    return
  }
  importing.value = true
  try {
    const r = await api('/vulnlib/import', { method: 'POST', body: payload })
    ElMessage.success(`导入 ${r.imported} 条` + (r.errors?.length ? `，失败 ${r.errors.length}` : ''))
    showImport.value = false
    await runSearch()
  } catch (e) {
    ElMessage.error('导入失败: ' + e.message)
  } finally {
    importing.value = false
  }
}

async function onFile (ev) {
  const file = ev.target.files && ev.target.files[0]
  if (!file) return
  importText.value = await file.text()
}

async function loadSamples () {
  seeding.value = true
  try {
    const r = await api('/vulnlib/import', { method: 'POST', body: SAMPLE })
    ElMessage.success(`示例已写入 ${r.imported} 条`)
    await runSearch()
  } catch (e) {
    ElMessage.error('示例写入失败: ' + e.message)
  } finally {
    seeding.value = false
  }
}

async function removeCurrent () {
  if (!currentId.value) return
  try {
    await ElMessageBox.confirm(`删除 ${currentId.value}？不可恢复。`, '删除条目', { type: 'warning' })
  } catch {
    return
  }
  try {
    await api(`/vulnlib/${encodeURIComponent(currentId.value)}`, { method: 'DELETE' })
    current.value = null
    currentId.value = ''
    await runSearch()
  } catch (e) {
    ElMessage.error('删除失败: ' + e.message)
  }
}

onMounted(async () => {
  await loadJobs()
  await runSearch()
})
</script>

<style scoped>
.vulnlib { display: flex; flex-direction: column; gap: 14px; }
.w-src { width: 108px; }
.w-cwe { width: 92px; }
.lib-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  padding: 8px 2px 10px;
  border-bottom: 1px dashed var(--fw-line);
  color: var(--fw-text-3);
  font-size: 12px;
}
.lib-stats b { color: var(--fw-text); font-variant-numeric: tabular-nums; margin-left: 2px; }
.job-select { min-width: 220px; margin-left: auto; }
.list-col { position: sticky; top: 0; max-height: calc(100vh - 40px); }
.list-scroll { flex: 1; min-height: 120px; overflow: auto; padding-right: 2px; }
.title { font-size: 18px; margin: 0 0 12px; }
.body { color: var(--fw-text-2); line-height: 1.6; }
.point {
  color: var(--fw-text);
  line-height: 1.65;
  margin: 0;
  padding: 10px 12px;
  background: rgba(19, 76, 255, .06);
  border-left: 3px solid var(--fw-brand);
  border-radius: 0 8px 8px 0;
}
.desc {
  white-space: pre-wrap;
  background: var(--fw-surface-2);
  padding: 10px 12px;
  border-radius: 8px;
  font-size: 13px;
  line-height: 1.7;
  color: var(--fw-text-2);
  max-height: 360px;
  overflow: auto;
}
.sec { font-size: 12px; color: var(--fw-text-3); margin: 14px 0 6px; }
.ref { display: block; font-size: 12.5px; word-break: break-all; margin-bottom: 4px; }
.match { display: flex; flex-direction: column; gap: 2px; padding: 8px 0; border-bottom: 1px solid var(--fw-line); }
.hint { color: var(--fw-text-3); font-size: 12.5px; margin-top: 0; }
.full { width: 100%; }
.import-file { margin-top: 10px; }
.viewer-title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.muted { color: var(--fw-text-3); }
.mono { font-family: var(--fw-font-mono); }
@media (max-width: 980px) {
  .list-col { position: static; max-height: none; }
  .job-select { margin-left: 0; }
}

.fw-badge {
  flex: none; padding: 0 7px; border-radius: 999px; font-size: 11px; line-height: 17px;
  color: var(--fw-danger); background: color-mix(in srgb, var(--fw-danger) 10%, transparent);
}
.fw-stats { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 4px; }
.lib-chip { padding: 3px 11px; border-radius: 999px; font-size: 12px; background: var(--fw-fill); color: var(--fw-text-2); border: 1px solid var(--fw-line); }
.lib-chip.hot b { color: var(--fw-danger); }
.fw-finding { padding: 9px 6px; border-bottom: 1px solid var(--fw-line); cursor: pointer; border-radius: 6px; }
.fw-finding:hover { background: var(--fw-fill); }
.fd-row { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }
.fw-title { font-size: 13.5px; line-height: 1.5; }
.fw-reach { margin-left: auto; flex: none; font-size: 11.5px; color: var(--fw-text-3); }
.fw-reach.ok { color: var(--fw-ok); }
.fw-meta { margin-top: 4px; font-size: 11.5px; color: var(--fw-text-3); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.fw-ev { margin: 8px 0 0; padding: 9px 11px; background: var(--fw-surface-2); border: 1px solid var(--fw-line); border-radius: 8px; font-size: 11.5px; line-height: 1.6; color: var(--fw-text-2); max-height: 220px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; }
.fw-sca-note { font-size: 12px; line-height: 1.7; }
.fw-secret { display: flex; align-items: center; gap: 10px; padding: 7px 10px; border: 1px solid color-mix(in srgb, var(--fw-danger) 30%, transparent); border-radius: 8px; margin-bottom: 8px; font-size: 12px; overflow-wrap: anywhere; }
.muted { color: var(--fw-text-3); }
.mono { font-family: var(--fw-font-mono, ui-monospace, monospace); }
</style>
