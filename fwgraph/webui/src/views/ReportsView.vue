<template>
  <div class="reports-page lib-page">
    <header class="ins-head">
      <div class="ins-head-row">
        <h1 class="ins-title"><span class="ins-ico"><component :is="NAV_ICONS.Notebook" :size="18" /></span>报告中心</h1>
      </div>
      <p class="ins-sub">漏洞报告汇总、预览与导出。</p>
    </header>

    <!-- 统计总览：KPI + 图表（2026-09-23 用户要求：报告中心要多统计图，
         数据一眼可读） -->
    <div class="stats-band">
      <div class="kpi-row">
        <div class="kpi">
          <span class="kpi-num">{{ findingsTotal }}</span>
          <span class="kpi-label">入库发现</span>
        </div>
        <div class="kpi hot">
          <span class="kpi-num">{{ criticalCount }}</span>
          <span class="kpi-label">严重 / 高危</span>
        </div>
        <div class="kpi">
          <span class="kpi-num">{{ verifiedCount }}</span>
          <span class="kpi-label">动态验证（observed+）</span>
        </div>
        <div class="kpi">
          <span class="kpi-num">{{ fwCount }}</span>
          <span class="kpi-label">涉及固件</span>
        </div>
        <div class="kpi">
          <span class="kpi-num">{{ reports.length }}</span>
          <span class="kpi-label">生成报告</span>
        </div>
      </div>
      <div class="charts-row">
        <div class="chart-card">
          <h3>等级分布</h3>
          <DonutChart :items="sevItems" title="等级分布" :size="180" />
        </div>
        <div class="chart-card">
          <h3>可达性分布</h3>
          <DonutChart :items="reachItems" title="可达性分布" :size="180" />
        </div>
        <div class="chart-card grow">
          <h3>按固件发现数</h3>
          <BarChart :items="fwItems" />
        </div>
        <div class="chart-card grow">
          <h3>高频目标二进制 Top8</h3>
          <BarChart :items="binItems" />
        </div>
      </div>
    </div>

    <div class="lib-layout">
      <!-- 左列：筛选 + 报告列表（与漏洞库同范式） -->
      <div class="lib-card list-col">
        <div class="lib-head">
          <h2>历史报告</h2>
          <span class="lib-count">{{ visible.length }} / {{ reports.length }}</span>
          <div class="lib-actions">
            <el-button size="small" :loading="loadingList" @click="loadReports">刷新</el-button>
          </div>
        </div>
        <div class="lib-toolbar">
          <button
            v-for="c in cats"
            :key="c"
            type="button"
            class="lib-chip"
            :class="{ on: filter === c }"
            @click="filter = c"
          >{{ c }}</button>
        </div>
        <div class="list-scroll">
          <div
            v-for="r in visible"
            :key="r.report_id"
            class="lib-item"
            :class="{ active: r.report_id === currentId }"
            @click="openReport(r)"
          >
            <div class="li-top">
              <el-tag size="small"
                      :type="r.kind === 'job' ? 'success' : r.kind === 'protofuzz' ? 'primary' : 'warning'"
                      effect="dark">
                {{ r.category || (r.kind === 'job' ? '专项报告' : r.kind === 'protofuzz' ? '协议专项' : '报告') }}
              </el-tag>
              <span class="li-date">{{ fmtDate(r.created_at) }}</span>
            </div>
            <div class="li-title" :title="fwLabel(r)">
              <span v-if="r.report_id === latestId" class="ri-latest">最新</span>
              {{ fwLabel(r) }}
            </div>
            <div class="li-meta">
              <template v-if="r.max_severity">
                <span class="ri-sev" :data-sev="r.max_severity">{{ r.max_severity }}</span>
                ·
              </template>
              {{ fmtSize(r.size) }}
            </div>
          </div>
          <el-empty v-if="!loadingList && !visible.length" description="还没有生成报告" :image-size="70" />
        </div>
      </div>

      <!-- 右列：报告预览与导出 -->
      <div class="lib-card detail-col">
        <div class="lib-head">
          <h2 class="viewer-title">{{ currentTitle || '报告预览' }}</h2>
          <div class="lib-actions">
            <el-button size="small" :disabled="!currentId" :loading="exporting === 'docx'" @click="exportFmt('docx')">
              导出 DOCX
            </el-button>
            <el-button size="small" :disabled="!currentId" :loading="exporting === 'pdf'" @click="exportFmt('pdf')">
              导出 PDF
            </el-button>
            <el-button size="small" :disabled="!currentId" @click="download">
              下载 MD
            </el-button>
          </div>
        </div>
        <div v-loading="loadingText" class="viewer-body">
          <div v-if="html" class="md-body" v-html="html"></div>
          <el-empty v-else-if="!loadingText" description="从左侧选择一份报告" :image-size="80" />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { NAV_ICONS } from '../workbench/icons.js'
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api, getToken } from '../api'
import { renderMarkdown } from '../highlight.js'
import DonutChart from '../components/charts/DonutChart.vue'
import BarChart from '../components/charts/BarChart.vue'

const findings = ref([])
async function loadFindings () {
  try {
    const list = await api('/vulnagent/findings')
    findings.value = Array.isArray(list) ? list : (list?.items || [])
  } catch { /* 图表降级为空态 */ }
}
// ---------------- 统计聚合（findings 库直读） ----------------
const SEV_META = {
  critical: { label: '严重', color: '#e11d48' },
  high: { label: '高危', color: '#ea580c' },
  medium: { label: '中危', color: '#d97706' },
  low: { label: '低危', color: '#16a34a' }
}
const REACH_META = {
  verified: { label: '已验证', color: '#16a34a' },
  observed: { label: '观测到', color: '#2563eb' },
  static: { label: '静态可达', color: '#94a3b8' }
}
const findingsTotal = computed(() => findings.value.length)
const criticalCount = computed(() => findings.value.filter((f) =>
  ['critical', '严重', 'high', '高危'].includes(String(f.severity || '').toLowerCase()) || ['critical', 'high'].includes(String(f.severity || ''))).length)
const verifiedCount = computed(() => findings.value.filter((f) =>
  ['observed', 'verified'].includes(String(f.reachability || '').toLowerCase())).length)
const fwCount = computed(() => new Set(findings.value.map((f) => f.job_id).filter(Boolean)).size)
const sevItems = computed(() => {
  const by = {}
  for (const f of findings.value) {
    const key = String(f.severity || 'unknown').toLowerCase()
    by[key] = (by[key] || 0) + 1
  }
  return Object.keys(SEV_META).map((k) => ({
    key: k, value: by[k] || 0, label: SEV_META[k].label, color: SEV_META[k].color
  })).filter((s) => s.value > 0)
})
const reachItems = computed(() => {
  const by = {}
  for (const f of findings.value) {
    const key = String(f.reachability || 'static').toLowerCase()
    by[key] = (by[key] || 0) + 1
  }
  return Object.keys(REACH_META).map((k) => ({
    key: k, value: by[k] || 0, label: REACH_META[k].label, color: REACH_META[k].color
  })).filter((s) => s.value > 0)
})
const fwItems = computed(() => {
  const by = {}
  for (const f of findings.value) {
    const name = String(f.job_id || f.firmware || '未知').slice(0, 12)
    by[name] = (by[name] || 0) + 1
  }
  return Object.entries(by).map(([label, value]) => ({
    key: label, label, value, color: '#5b8cff'
  })).sort((a, b) => b.value - a.value).slice(0, 8)
})
const binItems = computed(() => {
  const by = {}
  for (const f of findings.value) {
    const name = String(f.binary_path || '').split('/').pop() || '未知'
    by[name] = (by[name] || 0) + 1
  }
  return Object.entries(by).map(([label, value]) => ({
    key: label, label, value, color: '#22c55e'
  })).sort((a, b) => b.value - a.value).slice(0, 8)
})

const reports = ref([])
const currentId = ref('')
const currentTitle = ref('')
const html = ref('')
const loadingList = ref(false)
const loadingText = ref(false)
const exporting = ref('')
const filter = ref('全部')
const cats = ['全部', '专项报告', '季度报告', '协议专项']
const visible = computed(() => {
  if (filter.value === '全部') return reports.value
  if (filter.value === '季度报告') {
    const seen = new Set()
    return reports.value.filter((r) => {
      if (!r.quarter || seen.has(r.quarter)) return false
      seen.add(r.quarter)
      return true
    }).map((r) => ({
      ...r,
      category: '季度报告',
      title: `${r.quarter} 季度风险汇编（${r.firmware || r.title}）`
    }))
  }
  return reports.value.filter((r) => (r.category || '') === filter.value)
})

// 列表按时间倒序，当前筛选下的第一份打“最新”标记，解决同固件多报告难区分
const latestId = computed(() => visible.value[0]?.report_id || '')

function fmtTime (iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return isNaN(d) ? iso : d.toLocaleString()
}

function fmtDate (iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return iso
  const sameDay = new Date().toDateString() === d.toDateString()
  const day = d.toLocaleDateString('zh-CN', { month: 'numeric', day: 'numeric' })
  const hm = d.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit' })
  return sameDay ? `今天 ${hm}` : `${day} ${hm}`
}

// 固件名去掉扩展名，多份报告靠日期 + 漏洞数区分
function fwLabel (r) {
  const raw = String(r.firmware || r.title || '')
  return raw.replace(/\.(bin|img|chk|trx|tar|gz|zip)$/i, '') || raw
}

function fmtSize (n) {
  if (n == null) return ''
  if (n > 1048576) return (n / 1048576).toFixed(1) + ' MB'
  if (n > 1024) return (n / 1024).toFixed(1) + ' KB'
  return n + ' B'
}

async function loadReports () {
  loadingList.value = true
  try {
    reports.value = await api('/reports')
    if (!currentId.value && reports.value.length) openReport(reports.value[0])
  } catch (e) {
    ElMessage.error('报告列表加载失败: ' + e.message)
  } finally {
    loadingList.value = false
  }
}

async function openReport (r) {
  currentId.value = r.report_id
  currentTitle.value = r.title
  html.value = ''
  loadingText.value = true
  try {
    const text = await api(`/reports/${r.report_id}`)
    html.value = renderMarkdown(String(text))
  } catch (e) {
    ElMessage.error('报告加载失败: ' + e.message)
  } finally {
    loadingText.value = false
  }
}

async function download () {
  if (!currentId.value) return
  try {
    const resp = await fetch(`/reports/${currentId.value}/download`, {
      headers: { Authorization: `Bearer ${getToken()}` }
    })
    if (!resp.ok) throw new Error(`${resp.status}`)
    const blob = await resp.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${currentId.value}.md`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    ElMessage.error('下载失败: ' + e.message)
  }
}

async function exportFmt (fmt) {
  if (!currentId.value || exporting.value) return
  exporting.value = fmt
  try {
    const resp = await fetch(`/reports/${currentId.value}/export?fmt=${fmt}`, {
      headers: { Authorization: `Bearer ${getToken()}` }
    })
    if (!resp.ok) {
      let msg = `${resp.status}`
      try {
        const body = await resp.json()
        if (body && body.detail) msg = body.detail
      } catch { /* non-JSON error body */ }
      throw new Error(msg)
    }
    const blob = await resp.blob()
    const dispo = resp.headers.get('Content-Disposition') || ''
    const m = dispo.match(/filename\*?=(?:UTF-8''|")?([^";]+)/i)
    const fname = m ? decodeURIComponent(m[1].replace(/"$/, '')) : `${currentId.value}.${fmt}`
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = fname
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    ElMessage.error('导出失败: ' + e.message)
  } finally {
    exporting.value = ''
  }
}

onMounted(() => { loadReports(); loadFindings() })
</script>


<style scoped>
/* 统计总览带（2026-09-23） */
.stats-band { margin: 0 0 14px; }
.kpi-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 10px;
  margin-bottom: 12px;
}
.kpi {
  background: var(--fw-surface, #fff);
  border: 1px solid var(--fw-line, rgba(128, 128, 128, .2));
  border-radius: 12px;
  padding: 12px 14px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.kpi-num { font-size: 24px; font-weight: 700; line-height: 1.1; }
.kpi.hot .kpi-num { color: #e11d48; }
.kpi-label { font-size: 12px; opacity: .65; }
.charts-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 10px;
}
.chart-card {
  background: var(--fw-surface, #fff);
  border: 1px solid var(--fw-line, rgba(128, 128, 128, .2));
  border-radius: 12px;
  padding: 12px 14px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  min-width: 0;
}
.chart-card h3 {
  margin: 0;
  font-size: 13px;
  font-weight: 600;
  opacity: .8;
}
.chart-card.grow { min-height: 180px; }
</style>
<style scoped>
/* 列表列与详情列跟随 lib-page 范式（theme.css），这里只补报告页私有样式 */
.list-col { position: sticky; top: 0; max-height: calc(100vh - 40px); }
.list-scroll { flex: 1; min-height: 120px; overflow: auto; padding-right: 2px; }
.viewer-title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.viewer-body { flex: 1; min-height: 320px; overflow: auto; }
.ri-latest {
  flex: none;
  padding: 0 6px;
  border-radius: 999px;
  font-size: 10.5px;
  line-height: 16px;
  font-weight: 600;
  color: var(--fw-brand);
  background: var(--fw-fill);
}
.li-title { display: flex; align-items: center; gap: 6px; }
.li-meta { display: flex; align-items: center; gap: 6px; }
.ri-vuln { color: var(--fw-text-2); }
.ri-vuln b { color: var(--fw-danger); font-size: 13px; margin-left: 2px; }
.ri-sev {
  padding: 0 7px; border-radius: 999px; line-height: 18px; font-size: 11px; font-weight: 600;
}
.ri-sev[data-sev='严重'] { color: #e11d48; background: rgba(225, 29, 72, .14); }
.ri-sev[data-sev='高危'] { color: #ea580c; background: rgba(234, 88, 12, .14); }
.ri-sev[data-sev='中危'] { color: #d97706; background: rgba(217, 119, 6, .16); }
.ri-sev[data-sev='低危'] { color: #16a34a; background: rgba(22, 163, 74, .14); }
@media (max-width: 980px) {
  .list-col { position: static; max-height: none; }
}
</style>
