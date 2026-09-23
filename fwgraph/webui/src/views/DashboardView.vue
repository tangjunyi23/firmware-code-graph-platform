<template>
  <div class="screen">
    <!-- 告警滚动条 -->
    <div class="ticker">
      <div class="ticker-label"><span class="dot" />严重告警</div>
      <div class="ticker-track">
        <div class="ticker-inner">
          <template v-for="(item, i) in tickerItems" :key="i">
            <button
              v-for="(dup, j) in 2"
              :key="`${i}-${j}`"
              type="button"
              class="tk-item"
              :class="{ link: !!item.finding }"
              @click="onTickerClick(item)"
            >⚠ <span v-html="item.html" /></button>
          </template>
        </div>
      </div>
    </div>

    <!-- 顶栏 -->
    <header class="screen-head">
      <div class="hd-left" />
      <div class="brand">
        <div class="logo">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-3.6 8-10V5l-8-3-8 3v7c0 6.4 8 10 8 10z" /><path d="M9 12l2 2 4-4" />
          </svg>
        </div>
        <div class="brand-copy">
          <h1>FWGraph · 固件威胁态势大屏</h1>
          <p>FIRMWARE THREAT INTELLIGENCE · LIVE</p>
        </div>
      </div>
      <div class="hd-right">
        <div class="chip"><span class="dot" />分析引擎在线</div>
        <div class="chip">漏洞库 {{ dash?.findings_total || 0 }} 条</div>
        <div class="chip">挖掘会话 {{ dash?.sessions_total || 0 }}</div>
        <div class="clock"><span>{{ clock }}</span><small>{{ clockDate }}</small></div>
      </div>
    </header>

    <main class="with-pipe">
      <!-- KPI -->
      <div class="kpis">
        <div v-for="(k, i) in kpis" :key="k.lab" class="card kpi" :style="{ '--i': i, '--c': k.color }">
          <div class="kpi-ic" v-html="k.icon" />
          <div class="kpi-copy">
            <div class="kpi-val" :style="k.valColor ? { color: k.valColor } : null">
              <CountUp :value="k.value" /><small v-if="k.small">{{ k.small }}</small>
            </div>
            <div class="kpi-lab">{{ k.lab }}<span v-if="k.delta" class="kpi-delta" :class="{ warn: k.warn }">{{ k.delta }}</span></div>
          </div>
        </div>
      </div>

      <!-- 分析管线 -->
      <div class="card pipeline" style="--i:1">
        <template v-for="(n, i) in pipeNodes" :key="n.label">
          <div class="pl-node" :class="n.state">
            <span class="st">{{ n.state === 'done' ? '✓' : n.state === 'active' ? '●' : '·' }}</span>{{ n.label }}
          </div>
          <div
            v-if="i < pipeNodes.length - 1"
            class="pl-link"
            :class="linkState(i)"
          />
        </template>
        <div class="pl-meta">
          {{ pipeMeta }}
        </div>
      </div>

      <!-- 趋势 -->
      <div class="card" style="--i:2; grid-area: trend">
        <div class="card-h"><div class="card-t">漏洞发现趋势</div><div class="card-sub">近 14 天</div></div>
        <div ref="elTrend" class="chart" />
      </div>

      <!-- 雷达 -->
      <div class="card radar-card" style="--i:3">
        <div class="card-h">
          <div class="card-t">威胁雷达 · 攻击面态势</div>
          <div class="card-h-right">
            <span class="card-sub">半径 = 严重度 · 角度 = 漏洞类别</span>
            <span class="live">LIVE</span>
          </div>
        </div>
        <div class="radar-body">
          <div class="rail">
            <div class="rail-h">扫描队列<span>{{ running.length }} 运行中</span></div>
            <div v-for="(j, i) in running" :key="j.job_id" class="rq" :style="{ '--j': i }">
              <div class="rq-top"><span class="rq-name">{{ j.firmware || j.job_id }}</span><b class="rq-pct">{{ j.progress || 0 }}%</b></div>
              <div class="rq-track"><div class="rq-bar" :style="{ width: (j.progress || 0) + '%' }" /></div>
              <div class="rq-meta">{{ statusLabel(j.status) }} · 漏洞 {{ j.findings ?? 0 }}</div>
            </div>
            <div v-if="!running.length" class="rail-empty">当前没有运行中的任务</div>
          </div>
          <div class="radar-wrap">
            <RadarScreen
              :sectors="radarSectors"
              :targets="radarTargets"
              :center-value="dash?.findings_total ?? 0"
              center-label="威胁指数"
              :period="5.5"
              @select="openDetail"
            />
          </div>
          <div class="rail">
            <div class="rail-h">严重 · 待处置<span>{{ critFindings.length }}</span></div>
            <div v-for="(f, i) in critFindings.slice(0, 3)" :key="f.id" class="rc" :style="{ '--j': i }">
              <div class="rc-name"><span class="rc-dot" />{{ shortName(f.title, 22) }}<span v-if="f.cwe" class="cwe">{{ f.cwe }}</span></div>
              <div class="rc-meta">{{ f.function_name || f.binary_path?.split('/').pop() || '—' }}{{ f.confidence ? ` · 置信 ${f.confidence}` : '' }}</div>
            </div>
            <div v-if="!critFindings.length" class="rail-empty">暂无严重级别发现</div>
            <div class="rail-div" />
            <div class="rail-h">扫描状态</div>
            <div class="rs"><span>旋转速度</span><b>5.5s / 圈</b></div>
            <div class="rs"><span>跟踪目标</span><b>{{ radarTargets.length }}</b></div>
            <div class="rs"><span>已验证</span><b>{{ dash?.confirmed || 0 }}</b></div>
            <div class="rs"><span>动态命中</span><b>{{ dash?.traces_with_diff || 0 }}/{{ dash?.traces_total || 0 }}</b></div>
          </div>
        </div>
      </div>

      <!-- 玫瑰图：危害等级 -->
      <div class="card" style="--i:4; grid-area: rose">
        <div class="card-h"><div class="card-t">危害等级分布</div><div class="card-sub">全量发现</div></div>
        <div ref="elRose" class="chart" />
      </div>

      <!-- 漏洞类型 -->
      <div class="card" style="--i:5; grid-area: types">
        <div class="card-h"><div class="card-t">漏洞类型 Top 6</div><div class="card-sub">按类别归类</div></div>
        <div ref="elTypes" class="chart" />
      </div>

      <!-- 厂商排行（竞速条 + 最近报告批次） -->
      <div class="card vendors" style="--i:6">
        <div class="card-h"><div class="card-t">厂商漏洞排行</div><div class="card-sub">按入库数量</div></div>
        <div class="v-list">
          <div v-for="(v, i) in vendorRank.slice(0, 4)" :key="v.vendor" class="vendor" :class="{ top: i === 0 }">
            <span class="v-name"><span class="v-rank">{{ String(i + 1).padStart(2, '0') }}</span>{{ v.vendor }}</span>
            <div class="v-track"><div class="v-bar" :style="{ width: vPct(v) + '%' }" /></div>
            <span class="v-num">{{ v.findings }}</span>
          </div>
          <div v-if="!vendorRank.length" class="rail-empty">还没有可排名的厂商数据</div>
        </div>
        <template v-if="recentReports.length">
          <div class="rail-div" />
          <div class="rail-h">最近报告批次<span>{{ dash?.reports_total || recentReports.length }} 份</span></div>
          <div class="rep-list">
            <div v-for="r in recentReports" :key="r.report_id" class="rep">
              <span class="rep-name">{{ shortName(r.title, 22) }}</span>
              <span class="rep-sev" :class="'sev-' + (SEV_KEY_ZH[r.max_severity] || 'low')">{{ r.max_severity || '无风险' }}</span>
              <b class="rep-n">{{ r.vuln_count }}</b>
            </div>
          </div>
        </template>
      </div>

      <!-- 底部一行：左“最新发现” + 右“风险组件” 各占 50% -->
      <div class="bottom-row">
        <div class="card feed" style="--i:7">
          <div class="card-h">
            <div class="card-t">最新发现</div>
            <div class="card-h-right">
              <span class="card-sub">实时扫描日志 · 自动刷新</span><span class="live">STREAMING</span>
            </div>
          </div>
          <div class="feed-scroll">
            <div v-for="f in feedRows" :key="f.id" class="fl" :style="{ animationDelay: (f.i * 40) + 'ms' }">
              <span class="fl-time">[{{ fmtHMS(f.recorded_at) }}]</span>
              <span class="tag" :class="f.sev === 'critical' ? 'tag-alarm' : f.ver ? 'tag-ver' : 'tag-new'">
                {{ f.sev === 'critical' ? '告警' : f.ver ? '已验证' : '新发现' }}
              </span>
              <span class="fl-fw">{{ f.fw }}</span>
              <span class="fl-title">▸ {{ shortName(f.title, 40) }}</span>
              <span v-if="f.cwe" class="cwe">{{ f.cwe }}</span>
              <span class="sev" :class="'sev-' + f.sevKey">{{ f.sevLabel }}</span>
              <span v-if="f.conf" class="fl-conf">置信 {{ f.conf }}</span>
            </div>
            <div v-if="!feedRows.length" class="rail-empty">暂无入库发现</div>
          </div>
        </div>

        <!-- 风险组件 Top 5：按二进制聚合，色块为严重度构成 -->
        <div class="card xmod" style="--i:8">
          <div class="card-h">
            <div class="card-t">风险组件 Top 5</div>
            <div class="card-h-right legend">
              <span class="lg"><i class="lg-dot d-crit" />严重</span>
              <span class="lg"><i class="lg-dot d-high" />高危</span>
              <span class="lg"><i class="lg-dot d-med" />中危</span>
              <span class="lg"><i class="lg-dot d-low" />低危</span>
            </div>
          </div>
          <div class="bin-list">
            <div
              v-for="(b, i) in binaryRank"
              :key="b.name"
              class="bin"
              :title="`${b.name}：${b.segs.map((s) => SEV_LABEL[s.k] + ' ' + s.n).join(' · ')}`"
            >
              <span class="bin-rank">{{ String(i + 1).padStart(2, '0') }}</span>
              <div class="bin-main">
                <div class="bin-top">
                  <span class="bin-name">{{ b.name }}</span>
                  <b class="bin-count">{{ b.total }}</b>
                </div>
                <div class="bin-track">
                  <span
                    v-for="s in b.segs"
                    :key="s.k"
                    class="bin-seg"
                    :class="'seg-' + s.k"
                    :style="{ width: s.pct + '%' }"
                  />
                </div>
              </div>
            </div>
            <div v-if="!binaryRank.length" class="rail-empty">暂无组件级统计</div>
          </div>
        </div>
      </div>
    </main>

    <!-- 发现详情抽屉：告警条 / 雷达目标点击进入 -->
    <el-drawer v-model="detailOpen" title="漏洞发现详情" size="380px" :append-to-body="true">
      <div v-if="detail" class="fd-body">
        <div class="fd-sev" :data-sev="detail.sev">{{ sevZh(detail.sev) }}</div>
        <h3 class="fd-title">{{ detail.full || detail.name }}</h3>
        <div class="fd-grid">
          <span>CWE</span><b class="mono">{{ detail.cwe || '—' }}</b>
          <span>置信度</span><b>{{ detail.conf }}</b>
          <span>可达性</span><b :class="{ ok: detail.ver }">{{ detail.reach }}</b>
          <span>动态证据</span><b>{{ detail.ver ? '有' : '暂无' }}</b>
        </div>
        <p class="fd-hint">点击雷达目标或告警条可在此查看详情；完整证据链在对应任务的挖掘会话与报告中。</p>
        <el-button type="primary" @click="emit('goto', 'jobs')">前往工作台查看会话</el-button>
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
import * as echarts from 'echarts'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import CountUp from '../components/fx/CountUp.vue'
import RadarScreen from '../components/charts/RadarScreen.vue'

const emit = defineEmits(['goto'])

const dash = ref(null)
const agentFindings = ref([])
const clock = ref('')
const clockDate = ref('')

const SEV_LABEL = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' }
const SEV_COLOR = { critical: '#F43F5E', high: '#FB923C', medium: '#FACC15', low: '#34D399', info: '#5F6B85' }
const SEV_KEY = { critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'low' }
const SEV_KEY_ZH = { 严重: 'crit', 高危: 'high', 中危: 'med', 低危: 'low' }
const CLASS_L = {
  'command-injection': '命令注入', 'stack-overflow': '栈溢出', 'buffer-overflow': '缓冲区溢出',
  'oob-write': '越界写', other: '其他'
}
const STATUS_L = {
  uploaded: '已上传', decrypting: '解密中', extracting: '解包中', extracted: '已解包',
  identifying: '识别中', identified: '已识别', decompiling: '反编译', decompiled: '已反编译',
  attacking: '攻击面', attacked: '攻击面完成', routing: '路由分析', routed: '路由完成',
  surfacing: '面提取', surfaced: '面已就绪', graphing: '构图中', graphed: '图谱完成',
  done: '完成', error: '失败', unknown: '未知'
}
const MONO = '"Cascadia Code","JetBrains Mono",Consolas,monospace'
const ICONS = {
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-3.6 8-10V5l-8-3-8 3v7c0 6.4 8 10 8 10z"/></svg>',
  alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>',
  warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"/><circle cx="12" cy="12" r="10"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z"/><path d="m9 12 2 2 4-4"/></svg>',
  radar: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
  graph: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="5" cy="6" r="2.5"/><circle cx="19" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M6.8 8 10.5 15.7M17.2 8 13.5 15.7M7.5 6h9"/></svg>'
}

function statusLabel (s) { return STATUS_L[s] || s || '—' }
function shortName (s, n = 24) {
  const t = String(s || '')
  return t.length > n ? t.slice(0, n - 1) + '…' : t
}
function fmtHMS (iso) {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '--:--:--'
  const p = (x) => String(x).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/* ---------- 数据派生 ---------- */
const sevCount = (key) =>
  (dash.value?.findings_by_severity || []).find((r) => r.key === key)?.count || 0

const kpis = computed(() => {
  const d = dash.value || {}
  const days = d.series?.days || []
  const vals = d.series?.findings || []
  const today = vals.length && days.length &&
    days[days.length - 1] === new Date().toISOString().slice(0, 10)
    ? vals[vals.length - 1] : 0
  return [
    { icon: ICONS.shield, color: 'var(--sc-blue)', value: d.findings_total ?? 0, lab: '漏洞总数', delta: today ? `▲${today} 今日` : '', warn: false },
    { icon: ICONS.alert, color: 'var(--sc-red)', valColor: 'var(--sc-red2)', value: sevCount('critical'), lab: '严重', delta: critFindings.value.length ? `${critFindings.value.length} 待处置` : '', warn: true },
    { icon: ICONS.warn, color: 'var(--sc-orange)', valColor: 'var(--sc-orange)', value: sevCount('high'), lab: '高危' },
    { icon: ICONS.check, color: 'var(--sc-green)', valColor: 'var(--sc-green)', value: d.confirmed ?? 0, small: `/ ${d.findings_total ?? 0}`, lab: '已验证 · 动态取证' },
    { icon: ICONS.radar, color: 'var(--sc-cyan)', valColor: 'var(--sc-cyan2)', value: d.surfaces_total ?? 0, lab: '暴露攻击面' },
    { icon: ICONS.graph, color: 'var(--sc-blue2)', value: d.sessions_total ?? 0, lab: '挖掘会话' }
  ]
})

const critFindings = computed(() =>
  agentFindings.value.filter((f) => f.severity === 'critical').slice(0, 8))
const running = computed(() => dash.value?.running || [])

/* 告警条条目：带 finding 的可点击进入详情 */
const tickerItems = computed(() => {
  const d = dash.value || {}
  const crit = critFindings.value.slice(0, 3)
  const items = []
  if (crit.length || sevCount('critical')) {
    items.push({ html: `<b>严重 ${sevCount('critical')}</b> 个漏洞待处置` +
      (crit[0]?.confidence ? ` · 最高置信度 ${crit[0].confidence}` : ''), finding: null })
  }
  for (const f of crit) {
    items.push({
      html: `<b>${shortName(f.title, 30)}</b> · ${f.cwe || 'CWE-?'} · 置信 ${f.confidence || '—'}`,
      finding: f
    })
  }
  items.push({
    html: `动态验证命中 <b>${d.traces_with_diff || 0}/${d.traces_total || 0}</b> · 已验证 <b>${d.confirmed || 0}</b> · 数据每 8 秒自动刷新`,
    finding: null
  })
  return items
})

/* 发现详情抽屉 */
const detailOpen = ref(false)
const detail = ref(null)
function openDetail (target) {
  detail.value = target
  detailOpen.value = true
}
function onTickerClick (item) {
  if (item.finding) {
    openDetail({
      sev: SEV_KEY[item.finding.severity] || 'low',
      full: item.finding.title,
      cwe: item.finding.cwe || '',
      conf: item.finding.confidence || '—',
      ver: item.finding.reachability === 'observed' || item.finding.reachability === 'verified' || item.finding.status === 'verified',
      reach: item.finding.reachability === 'verified' ? '已验证' : item.finding.reachability === 'observed' ? '已观测' : '仅静态'
    })
  }
}
function sevZh (sev) {
  return { crit: '严重', high: '高危', med: '中危', low: '低危' }[sev] || sev
}
/* 管线连接线状态：已完成段流动、进行中段脉冲、未到达段静止 */
function linkState (i) {
  const nodes = pipeNodes.value
  const a = nodes[i]?.state
  const b = nodes[i + 1]?.state
  if (a === 'done' && b === 'done') return 'flow'
  if (b === 'active' || a === 'active') return 'to-active'
  return 'dim'
}

const tickerHtml = computed(() => {
  const d = dash.value || {}
  const items = []
  const crit = critFindings.value.slice(0, 3)
  if (crit.length || sevCount('critical')) {
    items.push(`<b>严重 ${sevCount('critical')}</b> 个漏洞待处置` +
      (crit[0]?.confidence ? ` · 最高置信度 ${crit[0].confidence}` : ''))
  }
  for (const f of crit) {
    items.push(`<b>${shortName(f.title, 30)}</b> · ${f.cwe || 'CWE-?'} · 置信 ${f.confidence || '—'}`)
  }
  items.push(`动态验证命中 <b>${d.traces_with_diff || 0}/${d.traces_total || 0}</b> · 已验证 <b>${d.confirmed || 0}</b> · 数据每 8 秒自动刷新`)
  const html = items.map((i) => `<span>⚠ ${i}</span>`).join('')
  return html + html // 双份无缝滚动
})

/* ---------- 管线 ---------- */
const STAGE_OF = {
  uploaded: 0, decrypting: 1, extracted: 2, extracting: 2, identified: 3, identifying: 3,
  decompiled: 4, graphed: 4, graphing: 4, attacked: 5, attacking: 5, routed: 5, routing: 5,
  surfaced: 5, surfacing: 5, done: 6, error: 6
}
const pipeNodes = computed(() => {
  const d = dash.value || {}
  const job = (d.running || [])[0]
  const stage = job ? (STAGE_OF[job.status] ?? 0) : -1
  const mining = (d.sessions_running || 0) > 0
  const labels = ['固件解密', '解包 · 文件系统', '架构识别', '知识图谱构建', '攻击面提取', '自动挖掘']
  return labels.map((label, i) => {
    const idx = i + 1
    let state = ''
    if (stage >= 6 || (stage < 0 && (d.jobs_total || 0) > 0 && !job)) state = i < 5 ? 'done' : ''
    else if (idx < stage) state = 'done'
    else if (idx === stage) state = 'active'
    if (i === 5 && mining) state = 'active'
    else if (i === 5 && stage >= 6) state = 'done'
    return { label, state }
  })
})
const pipeActive = computed(() => pipeNodes.value.some((n) => n.state === 'active'))
const pipeMeta = computed(() => {
  const d = dash.value || {}
  const job = (d.running || [])[0]
  if (job) return `批次 ${job.firmware || job.job_id} · ${statusLabel(job.status)} · 进度 ${job.progress || 0}%`
  if (d.sessions_running) return `${d.sessions_running} 路挖掘会话运行中`
  return '空闲 · 等待任务上传'
})

/* ---------- 雷达数据 ---------- */
const radarSectors = computed(() => {
  const rows = [...(dash.value?.findings_by_class || [])]
    .sort((a, b) => b.count - a.count).slice(0, 5)
  const secs = rows.map((r) => CLASS_L[r.key] || r.key)
  return secs.length ? secs : ['其他']
})
const radarTargets = computed(() =>
  agentFindings.value.slice(0, 18).map((f) => ({
    sector: sectorOfClass(f.vuln_class),
    sev: SEV_KEY[f.severity] || 'low',
    name: shortName(f.title, 16),
    full: f.title,
    cwe: f.cwe || '',
    ver: f.reachability === 'observed' || f.reachability === 'verified' || f.status === 'verified',
    reach: f.reachability === 'verified' ? '已验证' : f.reachability === 'observed' ? '已观测' : '仅静态',
    conf: f.confidence || '—',
    n: 1
  })))
function sectorOfClass (cls) {
  const label = CLASS_L[cls] || cls || '其他'
  return radarSectors.value.includes(label) ? label : (radarSectors.value.includes('其他') ? '其他' : radarSectors.value[0])
}

/* ---------- 厂商 / Feed ---------- */
const vendorRank = computed(() => dash.value?.vendor_rank || [])
const vMax = computed(() => Math.max(1, ...vendorRank.value.map((v) => v.findings || 0)))
function vPct (v) { return Math.round(((v.findings || 0) / vMax.value) * 100) }
const recentReports = computed(() =>
  [...(dash.value?.reports || [])]
    .sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''))
    .slice(0, 3))

/* 风险组件 Top5：按二进制聚合发现，段条展示严重度构成 */
const binaryRank = computed(() => {
  const map = new Map()
  for (const f of agentFindings.value) {
    const name = (f.binary_path || '').split('/').pop() || '未知组件'
    if (!map.has(name)) map.set(name, { name, total: 0, critical: 0, high: 0, medium: 0, low: 0 })
    const b = map.get(name)
    b.total++
    if (f.severity in SEV_LABEL && f.severity !== 'info') b[f.severity]++
  }
  return [...map.values()]
    .sort((a, b) => b.total - a.total)
    .slice(0, 5)
    .map((b) => ({
      name: b.name,
      total: b.total,
      segs: ['critical', 'high', 'medium', 'low']
        .filter((k) => b[k] > 0)
        .map((k) => ({ k, n: b[k], pct: Math.round((b[k] / b.total) * 100) }))
    }))
})

const feedRows = computed(() =>
  agentFindings.value.slice(0, 16).map((f, i) => ({
    id: f.id || i,
    i,
    title: f.title,
    sev: f.severity,
    sevKey: SEV_KEY[f.severity] || 'low',
    sevLabel: SEV_LABEL[f.severity] || f.severity,
    cwe: f.cwe,
    fw: f.binary_path?.split('/').pop() || f.job_id?.slice(0, 8) || '—',
    conf: f.confidence,
    ver: f.reachability === 'observed' || f.reachability === 'verified' || f.status === 'verified',
    recorded_at: f.recorded_at
  })))

/* ---------- 拉取 ---------- */
let timer = null
let clockTimer = null
let dashTick = 0
async function loadDashboard () {
  try {
    dash.value = await api('/dashboard')
    if (dashTick++ % 5 === 0) loadFindings()
  } catch (e) {
    ElMessage.error('仪表盘加载失败: ' + e.message)
  }
}
async function loadFindings () {
  try {
    const list = await api('/vulnagent/findings')
    agentFindings.value = Array.isArray(list) ? list : []
  } catch { /* 雷达空态 */ }
}
function tickClock () {
  const d = new Date()
  const p = (x) => String(x).padStart(2, '0')
  const W = ['日', '一', '二', '三', '四', '五', '六']
  clock.value = `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  clockDate.value = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} 周${W[d.getDay()]}`
}

/* ---------- ECharts ---------- */
const elTrend = ref(null)
const elRose = ref(null)
const elTypes = ref(null)
let chTrend = null
let chRose = null
let chTypes = null

const TIP = {
  backgroundColor: 'rgba(10,16,30,.96)', borderColor: 'rgba(148,163,184,.22)',
  textStyle: { color: '#E6EDF7', fontSize: 11, fontFamily: MONO },
  axisPointer: { lineStyle: { color: 'rgba(125,211,252,.4)' } }
}
const AX = {
  axisTick: { show: false },
  axisLine: { lineStyle: { color: 'rgba(148,163,184,.16)' } },
  axisLabel: { color: '#8A94AD', fontSize: 10 }
}

function renderCharts () {
  if (!chTrend) return
  const s = dash.value?.series || {}
  const cut = (arr) => (arr || []).slice(-14)
  const days = (s.days || []).slice(-14).map((iso) => {
    const d = new Date(iso)
    return Number.isNaN(d.getTime()) ? String(iso).slice(5) : `${d.getMonth() + 1}/${d.getDate()}`
  })
  chTrend.setOption({
    xAxis: { data: days },
    series: [
      { name: '新增发现', data: cut(s.findings) },
      { name: '动态验证', data: cut(s.traces) }
    ]
  })
  chRose.setOption({
    series: [{
      data: (dash.value?.findings_by_severity || [])
        .filter((r) => r.count > 0)
        .map((r) => ({ name: SEV_LABEL[r.key] || r.key, value: 1, count: r.count, itemStyle: { color: SEV_COLOR[r.key] || '#5F6B85' } }))
    }],
    graphic: [
      { style: { text: String(dash.value?.findings_total ?? 0) } },
      { style: { text: '漏洞总数' } }
    ]
  })
  const rows = [...(dash.value?.findings_by_class || [])].sort((a, b) => b.count - a.count).slice(0, 6)
  chTypes.setOption({
    yAxis: { data: rows.map((r) => CLASS_L[r.key] || r.key) },
    series: [{ data: rows.map((r) => r.count) }]
  })
}

watch([dash, agentFindings], renderCharts)

onMounted(() => {
  tickClock()
  clockTimer = setInterval(tickClock, 1000)
  loadDashboard()
  loadFindings()
  timer = setInterval(loadDashboard, 8000)

  chTrend = echarts.init(elTrend.value)
  chTrend.setOption({
    grid: { left: 30, right: 14, top: 32, bottom: 20 },
    tooltip: { trigger: 'axis', ...TIP },
    legend: { right: 0, top: 0, itemWidth: 14, itemHeight: 2, textStyle: { color: '#8A94AD', fontSize: 10 } },
    xAxis: { type: 'category', ...AX, boundaryGap: true },
    yAxis: {
      type: 'value',
      minInterval: 1,
      splitNumber: 3,
      axisLabel: { ...AX.axisLabel, formatter: (v) => (Number.isInteger(v) ? v : '') },
      splitLine: { lineStyle: { color: 'rgba(148,163,184,.08)' } }
    },
    series: [
      {
        name: '新增发现', type: 'line', smooth: 0.45, symbol: 'circle', symbolSize: 5, z: 3,
        lineStyle: { width: 2.5, color: '#5B7CFA' },
        itemStyle: { color: '#5B7CFA', borderColor: '#0B1120', borderWidth: 1 },
        areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: 'rgba(91,124,250,.40)' }, { offset: 1, color: 'rgba(91,124,250,0)' }]) }
      },
      {
        name: '动态验证', type: 'line', smooth: 0.45, symbol: 'none',
        lineStyle: { width: 1.5, type: 'dashed', color: 'rgba(34,211,238,.85)' }
      }
    ]
  })
  chRose = echarts.init(elRose.value)
  chRose.setOption({
    tooltip: { ...TIP, formatter: (p) => `${p.name}：${p.data.count} 个` },
    series: [{
      // 等分扇区：数值统一为 1，真实数量放 label/tooltip（原玫瑰图按数量变径，视觉误导）
      type: 'pie', radius: ['46%', '72%'], center: ['50%', '50%'],
      itemStyle: { borderRadius: 5, borderColor: '#0B1120', borderWidth: 2 },
      label: { color: '#8A94AD', fontSize: 10, lineHeight: 14,
               formatter: (p) => `${p.name}  ${p.data.count}` },
      labelLine: { length: 10, length2: 10, lineStyle: { color: 'rgba(148,163,184,.25)' } }
    }],
    graphic: [
      { type: 'text', left: 'center', top: '41%', style: { text: '0', fill: '#E6EDF7', font: '700 22px ' + MONO, textAlign: 'center' } },
      { type: 'text', left: 'center', top: '53%', style: { text: '漏洞总数', fill: '#8A94AD', font: '10px sans-serif', textAlign: 'center' } }
    ]
  })
  chTypes = echarts.init(elTypes.value)
  chTypes.setOption({
    grid: { left: 2, right: 30, top: 6, bottom: 2, containLabel: true },
    tooltip: { ...TIP, formatter: '{b}：{c} 个' },
    xAxis: { type: 'value', show: false },
    yAxis: {
      type: 'category', inverse: true,
      axisTick: { show: false }, axisLine: { show: false },
      axisLabel: { color: '#AAB6CF', fontSize: 11 }
    },
    series: [{
      type: 'bar', barWidth: 9,
      showBackground: true,
      backgroundStyle: { color: 'rgba(148,163,184,.07)', borderRadius: [0, 5, 5, 0] },
      itemStyle: {
        borderRadius: [0, 5, 5, 0],
        color: (p) => new echarts.graphic.LinearGradient(0, 0, 1, 0, [
          { offset: 0, color: 'rgba(91,124,250,.35)' }, { offset: 1, color: '#22D3EE' }])
      },
      label: { show: true, position: 'right', color: '#CBD6EC', fontSize: 10.5, fontFamily: MONO }
    }],
    animationDuration: 1200
  })
  renderCharts()
  window.addEventListener('resize', onWinResize)
})
function onWinResize () {
  chTrend?.resize(); chRose?.resize(); chTypes?.resize()
}
onBeforeUnmount(() => {
  if (timer) clearInterval(timer)
  if (clockTimer) clearInterval(clockTimer)
  window.removeEventListener('resize', onWinResize)
  chTrend?.dispose(); chRose?.dispose(); chTypes?.dispose()
})
</script>

<style scoped>
/* ===== 固件威胁态势大屏（按 demo 复刻，深色固定主题） ===== */
/* demo 依赖全局 border-box 重置；这里只对大屏作用域内补齐，避免影响外壳 */
.screen, .screen *, .screen *::before, .screen *::after { box-sizing: border-box; }
.screen {
  --sc-bg: #070B14;
  --sc-card: rgba(15, 22, 38, .92);
  --sc-card2: rgba(10, 15, 28, .92);
  --sc-line: rgba(148, 163, 184, .10);
  --sc-txt: #E6EDF7;
  --sc-txt2: #98A3BC;
  --sc-txt3: #5F6B85;
  --sc-blue: #5B7CFA;
  --sc-blue2: #7DA2FF;
  --sc-cyan: #22D3EE;
  --sc-cyan2: #7DD3FC;
  --sc-red: #F43F5E;
  --sc-red2: #FF8FA5;
  --sc-orange: #FB923C;
  --sc-yellow: #FACC15;
  --sc-green: #34D399;
  height: 100%;
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  color: var(--sc-txt);
  background:
    radial-gradient(900px 520px at 10% -12%, rgba(91, 124, 250, .11), transparent 62%),
    radial-gradient(820px 520px at 96% 112%, rgba(34, 211, 238, .08), transparent 62%),
    linear-gradient(rgba(148, 163, 184, .035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(148, 163, 184, .035) 1px, transparent 1px),
    var(--sc-bg);
  background-size: auto, auto, 44px 44px, 44px 44px, auto;
}

/* 告警滚动条 */
.ticker {
  height: 30px; flex: none; display: flex; align-items: stretch; overflow: hidden;
  background: linear-gradient(90deg, rgba(244, 63, 94, .12), rgba(244, 63, 94, .03) 45%, transparent 80%);
  border-bottom: 1px solid rgba(244, 63, 94, .22);
}
.ticker-label {
  flex: none; display: flex; align-items: center; gap: 7px; padding: 0 14px;
  background: rgba(244, 63, 94, .18); color: var(--sc-red2);
  font-weight: 700; font-size: 12px; letter-spacing: 2px;
  border-right: 1px solid rgba(244, 63, 94, .35); white-space: nowrap;
}
.ticker-label .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--sc-red); animation: blink 1.1s infinite; }
.ticker-track { flex: 1; overflow: hidden; display: flex; align-items: center; }
.ticker-track:hover .ticker-inner { animation-play-state: paused; }
.ticker-inner {
  display: inline-flex; white-space: nowrap; animation: marquee 30s linear infinite;
  font: 12px var(--fw-font-mono, monospace); color: #F0A8B6;
}
.ticker-inner :deep(span) { padding-right: 4px; }
.tk-item {
  flex: none; display: inline-flex; align-items: center;
  margin-right: 64px; padding: 3px 8px;
  border: none; border-radius: 6px; background: transparent;
  color: #C7D2E8; font-size: 12px; white-space: nowrap; cursor: default;
  font-family: inherit;
}
.tk-item.link { cursor: pointer; transition: background .15s ease, color .15s ease; }
.tk-item.link:hover { background: rgba(244, 63, 94, .14); color: #F1F5FB; }
.ticker-inner :deep(b) { color: var(--sc-red2); font-weight: 700; }
@keyframes marquee { to { transform: translateX(-50%); } }
@keyframes blink { 50% { opacity: .25; } }

/* 顶栏 */
.screen-head {
  height: 60px; flex: none;
  display: grid; grid-template-columns: 1fr auto 1fr; align-items: center;
  padding: 0 18px; position: relative;
  background: linear-gradient(180deg, rgba(15, 22, 38, .55), rgba(15, 22, 38, 0));
}
/* 底部青蓝渐变光带，替代生硬的暗色边线 */
.screen-head::after {
  content: ''; position: absolute; left: 0; right: 0; bottom: 0; height: 1px;
  background: linear-gradient(90deg,
    transparent 0%, rgba(34, 211, 238, .38) 18%,
    rgba(91, 124, 250, .38) 50%, rgba(34, 211, 238, .38) 82%, transparent 100%);
  pointer-events: none;
}
.screen-head::before {
  content: ''; position: absolute; left: 0; right: 0; bottom: 0; height: 14px;
  background: linear-gradient(180deg, transparent, rgba(34, 211, 238, .04));
  pointer-events: none;
}
.logo {
  width: 36px; height: 36px; flex: none; border-radius: 10px; display: grid; place-items: center;
  background: linear-gradient(135deg, var(--sc-blue), var(--sc-cyan));
  box-shadow: 0 0 22px rgba(91, 124, 250, .45), inset 0 1px 0 rgba(255, 255, 255, .25);
}
.logo svg { width: 20px; height: 20px; stroke: #fff; }
.brand { min-width: 0; }
.brand h1 {
  margin: 0; font-size: 21px; font-weight: 800; letter-spacing: .5px; line-height: 1.15;
  white-space: nowrap;
  background: linear-gradient(110deg, #F2F7FF 15%, #9BD9FF 55%, #7DA2FF 90%);
  -webkit-background-clip: text; background-clip: text; color: transparent;
}
.brand p {
  font-size: 10px; color: var(--sc-txt3); font-family: var(--fw-font-mono, monospace);
  letter-spacing: 2.2px; margin: 3px 0 0;
  display: flex; align-items: center; gap: 10px; white-space: nowrap;
}
/* 副标题两侧的翅膀渐变线，营造大屏氛围 */
.brand p::before,
.brand p::after {
  content: ''; height: 1px; width: 26px; flex: none;
  background: linear-gradient(90deg, transparent, rgba(125, 211, 252, .55));
}
.brand p::after { background: linear-gradient(90deg, rgba(125, 211, 252, .55), transparent); }
.hd-left { min-width: 0; }
.brand { display: flex; align-items: center; justify-self: center; gap: 12px; }
.brand-copy h1 { font-size: 21px; }
.hd-right {
  position: absolute; right: 18px; top: 50%; transform: translateY(-50%);
  justify-self: end; margin-left: auto; display: flex; align-items: center; gap: 10px; }
.chip {
  display: flex; align-items: center; gap: 7px; font: 11px var(--fw-font-mono, monospace);
  color: var(--sc-txt2); border: 1px solid var(--sc-line); border-radius: 999px;
  padding: 5px 12px; background: rgba(148, 163, 184, .05); white-space: nowrap;
  transition: border-color .2s ease, color .2s ease;
}
.chip:hover { border-color: rgba(125, 211, 252, .35); color: var(--sc-txt); }
.chip .dot {
  width: 6px; height: 6px; border-radius: 50%; background: var(--sc-green);
  box-shadow: 0 0 8px var(--sc-green); animation: blink 2s infinite;
}
.clock {
  display: flex; align-items: baseline; gap: 9px;
  font-family: var(--fw-font-mono, monospace); white-space: nowrap;
  padding: 6px 14px; border: 1px solid rgba(34, 211, 238, .28);
  border-radius: 9px; background: rgba(34, 211, 238, .06);
}
.clock span {
  font-size: 17px; font-weight: 700; color: var(--sc-cyan2); letter-spacing: 1px;
  font-variant-numeric: tabular-nums;
  text-shadow: 0 0 14px rgba(34, 211, 238, .4);
}
.clock small { color: var(--sc-txt3); font-weight: 400; font-size: 10.5px; letter-spacing: .5px; }

/* 主网格 */
main.with-pipe {
  flex: 1; min-height: 0; display: grid; gap: 11px; padding: 11px 14px 13px;
  grid-template-columns: minmax(290px, 370px) minmax(420px, 1fr) minmax(290px, 370px);
  grid-template-rows: auto 46px minmax(0, 1.15fr) minmax(0, .92fr) 186px;
  grid-template-areas:
    "kpis kpis kpis"
    "pipe pipe pipe"
    "trend radar rose"
    "types radar vendors"
    "bottom bottom bottom";
}
.card {
  background: linear-gradient(180deg, var(--sc-card), var(--sc-card2));
  border: 1px solid var(--sc-line); border-radius: 12px; padding: 13px 15px;
  min-height: 0; display: flex; flex-direction: column; position: relative;
  animation: rise .6s cubic-bezier(.22, .8, .3, 1) both;
  animation-delay: calc(var(--i, 0) * 80ms);
  transition: border-color .25s;
}
.card:hover { border-color: rgba(148, 163, 184, .22); }
@keyframes rise { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: none; } }
.card-h { flex: none; display: flex; align-items: center; justify-content: space-between; margin-bottom: 9px; }
.card-h-right { display: flex; align-items: center; gap: 12px; }
.card-t {
  font-size: 12.5px; font-weight: 600; color: #CBD6EC; letter-spacing: .5px;
  display: flex; align-items: center; gap: 8px;
}
.card-t::before {
  content: ''; width: 3px; height: 12px; border-radius: 2px;
  background: linear-gradient(180deg, var(--sc-blue), var(--sc-cyan));
}
.card-sub { font: 10px var(--fw-font-mono, monospace); color: var(--sc-txt3); letter-spacing: .5px; }
.live {
  display: flex; align-items: center; gap: 6px;
  font: 10px var(--fw-font-mono, monospace); color: var(--sc-cyan2); letter-spacing: 1px;
}
.live::before {
  content: ''; width: 6px; height: 6px; border-radius: 50%; background: var(--sc-cyan);
  box-shadow: 0 0 8px var(--sc-cyan); animation: blink 1.4s infinite;
}
.chart { flex: 1; min-height: 0; }
.radar-wrap { flex: 1; min-height: 0; }

/* KPI */
.kpis { grid-area: kpis; display: grid; grid-template-columns: repeat(6, 1fr); gap: 11px; }
.kpi { display: flex; flex-direction: row; align-items: center; gap: 13px; padding: 13px 15px; min-height: 78px; overflow: hidden; }
/* 底部与图标同色的渐变饰条，六张卡各带一抹主题色 */
.kpi::after {
  content: ''; position: absolute; left: 14px; right: 14px; bottom: 0; height: 2px;
  border-radius: 2px; opacity: .5;
  background: linear-gradient(90deg, var(--c), transparent 78%);
}
.kpi-copy { flex: 1; min-width: 0; }
.kpi-ic {
  width: 40px; height: 40px; flex: none; border-radius: 11px; display: grid; place-items: center;
  color: var(--c);
  background: linear-gradient(135deg,
    color-mix(in srgb, var(--c) 17%, transparent),
    color-mix(in srgb, var(--c) 7%, transparent));
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--c) 16%, transparent);
}
.kpi-ic :deep(svg) { width: 20px; height: 20px; }
.kpi-val { font: 700 26px / 1.05 var(--fw-font-mono, monospace); color: var(--sc-txt); white-space: nowrap; }
.kpi-val small { font-size: 12px; color: var(--sc-txt3); font-weight: 400; margin-left: 3px; }
.kpi-lab {
  font-size: 11px; color: var(--sc-txt2); margin-top: 3px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.kpi-delta {
  font: 10px var(--fw-font-mono, monospace); color: var(--sc-green);
  margin-left: 8px; padding-left: 8px; border-left: 1px solid rgba(148, 163, 184, .25);
}
.kpi-delta.warn { color: var(--sc-red2); }

/* 管线 */
.pipeline { grid-area: pipe; flex-direction: row; align-items: center; padding: 9px 15px; overflow: hidden; gap: 0; }
.pl-node {
  flex: none; display: flex; align-items: center; gap: 7px; font-size: 11.5px; color: var(--sc-txt2);
  padding: 5px 12px; border: 1px solid var(--sc-line); border-radius: 999px;
  background: rgba(148, 163, 184, .04); white-space: nowrap;
}
.pl-node .st { font-size: 10px; font-family: var(--fw-font-mono, monospace); }
.pl-node.done { color: #9FB4E8; border-color: rgba(91, 124, 250, .32); }
.pl-node.active { animation: pl-node-pulse 1.2s ease-in-out infinite; }
@keyframes pl-node-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(34, 211, 238, .35); }
  50% { box-shadow: 0 0 0 5px rgba(34, 211, 238, 0); }
}
.pl-node.done .st { color: var(--sc-green); }
.pl-node.active {
  color: var(--sc-cyan2); border-color: rgba(34, 211, 238, .5); background: rgba(34, 211, 238, .08);
  box-shadow: 0 0 18px rgba(34, 211, 238, .15);
}
.pl-node.active .st { color: var(--sc-cyan2); animation: blink 1.2s infinite; }
.pl-link {
  flex: 1; min-width: 22px; height: 2px; position: relative; border-radius: 2px;
  background: rgba(148, 163, 184, .14);
  overflow: hidden;
}
/* 已完成段：光点沿线流动 */
.pl-link.flow {
  background: linear-gradient(90deg, rgba(91, 124, 250, .38), rgba(34, 211, 238, .38));
}
.pl-link.flow::before {
  content: ''; position: absolute; inset: 0;
  background: linear-gradient(90deg,
    transparent 0%, rgba(125, 211, 252, .95) 42%, rgba(34, 211, 238, .95) 58%, transparent 100%);
  background-size: 46% 100%;
  background-repeat: no-repeat;
  animation: pl-flow 1.6s linear infinite;
}
/* 正在推进的段：脉冲呼吸 */
.pl-link.to-active {
  background: rgba(34, 211, 238, .35);
  animation: pl-pulse 1.2s ease-in-out infinite;
}
@keyframes pl-flow { from { background-position: -60% 0; } to { background-position: 160% 0; } }
@keyframes pl-pulse { 0%, 100% { opacity: .45; } 50% { opacity: 1; } }
.pl-link::after {
  content: ''; position: absolute; top: -2px; left: 0; width: 5px; height: 5px; border-radius: 50%;
  background: var(--sc-cyan2); box-shadow: 0 0 9px var(--sc-cyan); animation: flow 2.2s linear infinite;
}
.pl-link.dim::after { display: none; }
@keyframes flow { to { left: calc(100% - 5px); } }
.pl-meta {
  margin-left: auto; min-width: 0; overflow: hidden; text-overflow: ellipsis;
  font: 10.5px var(--fw-font-mono, monospace); color: var(--sc-txt3);
  white-space: nowrap; padding-left: 14px; border-left: 1px solid var(--sc-line);
}

/* 雷达区 */
.radar-card { grid-area: radar; overflow: visible; }
.radar-body { flex: 1; min-height: 0; display: flex; gap: 10px; }
.rail {
  flex: none; width: 178px; display: flex; flex-direction: column; gap: 5px; padding: 7px 8px;
  /* 隐性滚动兜底：数据再多也绝不静默裁切（桌面布局已按 3 条收纳，正常无滚动） */
  overflow-y: auto; scrollbar-width: none;
  border: 1px solid rgba(148, 163, 184, .09); border-radius: 10px;
  background: rgba(148, 163, 184, .03);
}
.rail::-webkit-scrollbar { display: none; }
.rail-h {
  font: 600 10px var(--fw-font-mono, monospace); color: var(--sc-txt3);
  letter-spacing: 1.5px; display: flex; justify-content: space-between; align-items: center;
}
.rail-h span { color: var(--sc-cyan2); font-weight: 400; letter-spacing: .5px; }
.rail-div { height: 1px; background: var(--sc-line); margin: 2px 0; }
.rail-empty { color: var(--sc-txt3); font-size: 11.5px; padding: 8px 2px; }
.rq { animation: rise .5s ease both; animation-delay: calc(var(--j, 0) * 60ms); }
.rq-top { display: flex; justify-content: space-between; align-items: baseline; gap: 6px; }
.rq-name { font-size: 11px; color: #C9D4EA; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.rq-pct { font: 600 10px var(--fw-font-mono, monospace); color: var(--sc-cyan2); flex: none; }
.rq-track { height: 4px; border-radius: 2px; background: rgba(148, 163, 184, .10); overflow: hidden; margin: 5px 0 4px; }
.rq-bar {
  height: 100%; border-radius: 2px;
  background: linear-gradient(90deg, rgba(91, 124, 250, .5), var(--sc-cyan));
  transition: width 1.1s cubic-bezier(.22, .8, .3, 1);
}
.rq-meta {
  font: 9.5px var(--fw-font-mono, monospace); color: var(--sc-txt3); letter-spacing: .2px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.rc {
  padding: 4px 8px; border: 1px solid rgba(244, 63, 94, .25); border-radius: 8px;
  background: rgba(244, 63, 94, .06);
  animation: rise .5s ease both; animation-delay: calc(var(--j, 0) * 60ms);
}
.rc-name { font-size: 11px; font-weight: 600; display: flex; align-items: center; gap: 6px; flex-wrap: wrap; row-gap: 2px; }
.rc-dot {
  width: 6px; height: 6px; border-radius: 50%; background: var(--sc-red);
  box-shadow: 0 0 8px var(--sc-red); animation: blink 1.2s infinite; flex: none;
}
.rc-name .cwe {
  font: 9.5px var(--fw-font-mono, monospace); background: rgba(91, 124, 250, .14);
  padding: 0 5px; border-radius: 3px; flex: none; color: var(--sc-blue2);
}
.rc-meta {
  font: 9.5px var(--fw-font-mono, monospace); color: var(--sc-txt3); letter-spacing: .2px; margin-top: 4px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.rs { display: flex; justify-content: space-between; font: 10px var(--fw-font-mono, monospace); color: var(--sc-txt3); }
.rs b { color: #C9D4EA; font-weight: 600; }

/* 厂商排行 */
.vendors { grid-area: vendors; justify-content: flex-start; gap: 4px; }
.v-list { flex: 1; display: flex; flex-direction: column; justify-content: space-evenly; min-height: 0; gap: 6px; }
.vendor { display: grid; grid-template-columns: 92px 1fr 30px; align-items: center; gap: 10px; }
.v-name { font-size: 11.5px; color: var(--sc-txt2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.v-rank { font: 700 10px var(--fw-font-mono, monospace); color: var(--sc-txt3); margin-right: 5px; }
.v-track { height: 8px; border-radius: 4px; background: rgba(148, 163, 184, .08); overflow: hidden; }
.v-bar {
  height: 100%; border-radius: 4px;
  background: linear-gradient(90deg, rgba(91, 124, 250, .45), var(--sc-cyan));
  box-shadow: 0 0 10px rgba(34, 211, 238, .35);
  transition: width 1.3s cubic-bezier(.22, .8, .3, 1);
}
.vendor.top .v-bar {
  background: linear-gradient(90deg, rgba(244, 63, 94, .5), var(--sc-orange));
  box-shadow: 0 0 10px rgba(251, 146, 60, .35);
}
.v-num { font: 600 12px var(--fw-font-mono, monospace); color: #CBD6EC; text-align: right; }
.rep-list { flex: none; display: flex; flex-direction: column; gap: 5px; }
.rep {
  display: flex; align-items: center; gap: 8px; font-size: 11px;
  padding: 4px 8px; border: 1px solid rgba(148, 163, 184, .08); border-radius: 7px;
  background: rgba(148, 163, 184, .035);
}
.rep-name { flex: 1; min-width: 0; color: var(--sc-txt2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.rep-sev { flex: none; font-size: 10px; padding: 1px 6px; border-radius: 4px; font-weight: 600; }
.rep-n { flex: none; font: 600 11px var(--fw-font-mono, monospace); color: #CBD6EC; }

/* Feed + 风险组件：底部一行 50/50 对分 */
.bottom-row { grid-area: bottom; display: flex; gap: 11px; min-height: 0; }
.bottom-row .card { flex: 1; min-width: 0; }
.feed .feed-scroll {
  flex: 1; min-height: 0; overflow: hidden; display: flex; flex-direction: column; gap: 5px;
  -webkit-mask-image: linear-gradient(180deg, #000 86%, transparent);
  mask-image: linear-gradient(180deg, #000 86%, transparent);
}
.fl {
  flex: none; display: flex; align-items: center; gap: 9px;
  font: 11.5px var(--fw-font-mono, monospace); color: #AAB6CF;
  background: rgba(148, 163, 184, .045); border: 1px solid rgba(148, 163, 184, .07);
  border-radius: 8px; padding: 5px 10px;
  animation: flIn .45s ease both; white-space: nowrap; overflow: hidden;
}
@keyframes flIn { from { opacity: 0; transform: translateY(-9px); } }
.fl-time { color: var(--sc-txt3); flex: none; }
.fl-title { min-width: 0; overflow: hidden; text-overflow: ellipsis; }
.tag { flex: none; font-size: 10px; padding: 1px 7px; border-radius: 4px; letter-spacing: .5px; }
.tag-new { color: var(--sc-blue2); background: rgba(91, 124, 250, .15); }
.tag-ver { color: var(--sc-green); background: rgba(52, 211, 153, .13); }
.tag-alarm { color: var(--sc-red2); background: rgba(244, 63, 94, .15); }
.cwe { color: var(--sc-blue2); flex: none; }
.sev { flex: none; font-size: 10px; padding: 1px 6px; border-radius: 4px; font-weight: 600; }
.sev-crit { color: var(--sc-red2); background: rgba(244, 63, 94, .15); }
.sev-high { color: var(--sc-orange); background: rgba(251, 146, 60, .14); }
.sev-med { color: var(--sc-yellow); background: rgba(250, 204, 21, .12); }
.sev-low { color: var(--sc-green); background: rgba(52, 211, 153, .12); }
.fl-conf { margin-left: auto; color: var(--sc-txt3); flex: none; }
.fl-fw { color: #8FA0C4; flex: none; max-width: 150px; overflow: hidden; text-overflow: ellipsis; }

/* 风险组件 Top5（底部右半）：按二进制聚合，色块为严重度构成 */
.xmod { padding: 10px 14px 12px; }
.xmod .card-h { margin-bottom: 7px; }
.legend { gap: 10px; }
.lg { display: inline-flex; align-items: center; gap: 4px; font-size: 10px; color: var(--sc-txt2); }
.lg-dot { width: 7px; height: 7px; border-radius: 2px; }
.lg-dot.d-crit { background: #F43F5E; }
.lg-dot.d-high { background: #FB923C; }
.lg-dot.d-med { background: #FACC15; }
.lg-dot.d-low { background: #34D399; }
.bin-list { flex: 1; min-height: 0; display: flex; flex-direction: column; justify-content: space-evenly; gap: 4px; }
.bin { display: flex; align-items: center; gap: 10px; }
.bin-rank { flex: none; width: 20px; font: 700 10px var(--fw-font-mono, monospace); color: var(--sc-txt3); }
.bin-main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 3px; }
.bin-top { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
.bin-name {
  min-width: 0; font-size: 11.5px; color: #C9D4EA;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.bin-count { flex: none; font: 600 12px var(--fw-font-mono, monospace); color: #CBD6EC; }
.bin-track {
  height: 6px; border-radius: 3px; overflow: hidden; display: flex;
  background: rgba(148, 163, 184, .08);
}
.bin-seg { height: 100%; }
.bin-seg:first-child { border-radius: 4px 0 0 4px; }
.bin-seg:last-child { border-radius: 0 4px 4px 0; }
.bin-seg.seg-critical { background: linear-gradient(180deg, #FB7185, #F43F5E); }
.bin-seg.seg-high { background: linear-gradient(180deg, #FDBA74, #FB923C); }
.bin-seg.seg-medium { background: linear-gradient(180deg, #FDE047, #FACC15); }
.bin-seg.seg-low { background: linear-gradient(180deg, #6EE7B7, #34D399); }

/* 响应式：外壳侧栏(~250px)偷走宽度，断点相对 demo 整体右移 */
@media (max-width: 1700px) {
  main.with-pipe { grid-template-columns: 260px minmax(340px, 1fr) 260px; }
  .rail { width: 138px; padding: 8px; }
  .kpi { gap: 10px; padding: 12px 13px; }
  .kpi-ic { width: 36px; height: 36px; border-radius: 10px; }
  .kpi-ic :deep(svg) { width: 18px; height: 18px; }
  .kpi-val { font-size: 22px; }
}
@media (max-width: 1380px) {
  .screen { overflow: auto; }
  .kpis { grid-template-columns: repeat(3, 1fr); }
  main.with-pipe {
    grid-template-columns: 1fr 1fr; grid-template-rows: none; grid-template-areas:
      "kpis kpis" "pipe pipe" "radar radar" "trend rose" "types vendors" "bottom bottom";
  }
  /* 两列回退时改为按内容撑高（.screen 滚动），否则 flex:1+min-height:0
     会把 auto 行压到内容以下，雷达卡片塌成一条、内容溢出盖到邻卡 */
  main.with-pipe { flex: none; }
  main.with-pipe .card { min-height: 220px; }
  .bottom-row { min-height: 260px; }
  .radar-wrap { min-height: 400px; }
}
@media (max-width: 1024px) {
  .rail { display: none; }
  .radar-body { gap: 0; }
}
@media (max-width: 760px) {
  .kpis { grid-template-columns: repeat(2, 1fr); }
  main.with-pipe {
    grid-template-columns: 1fr; grid-template-areas:
      "kpis" "pipe" "radar" "trend" "rose" "types" "vendors" "bottom";
  }
  .bottom-row { flex-direction: column; }
  .bottom-row .card { min-height: 220px; }
  .hd-right .chip { display: none; }
  .pipeline { flex-wrap: wrap; gap: 6px; }
  .pl-link { display: none; }
}
@media (prefers-reduced-motion: reduce) {
  .ticker-inner, .pl-link::after, .rc-dot, .ticker-label .dot, .chip .dot, .live::before { animation: none !important; }
  .card, .rq, .rc, .fl { animation-duration: .01ms !important; }
}

.fd-body { display: flex; flex-direction: column; gap: 12px; }
.fd-sev { align-self: flex-start; padding: 2px 12px; border-radius: 999px; font-weight: 700; font-size: 13px; }
.fd-sev[data-sev='crit'] { color: #F43F5E; background: rgba(244, 63, 94, .12); }
.fd-sev[data-sev='high'] { color: #FB923C; background: rgba(251, 146, 60, .12); }
.fd-sev[data-sev='med'] { color: #FACC15; background: rgba(250, 204, 21, .12); }
.fd-sev[data-sev='low'] { color: #34D399; background: rgba(52, 211, 153, .12); }
.fd-title { margin: 0; font-size: 16px; line-height: 1.5; }
.fd-grid { display: grid; grid-template-columns: auto 1fr; gap: 8px 14px; font-size: 13px; }
.fd-grid span { color: #8A94AD; }
.fd-grid b.ok { color: #34D399; }
.fd-hint { font-size: 12px; color: #8A94AD; line-height: 1.7; margin: 0; }
@media (prefers-reduced-motion: reduce) {
  .pl-link.flow::before, .pl-link.to-active, .pl-node.active { animation: none; }
}
</style>
