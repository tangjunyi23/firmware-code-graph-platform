<template>
  <div :class="active ? 'workspace-conversation' : 'workspace-overview'">
    <template v-if="!active">
      <header class="workspace-overview-head">
        <h1>安全工作台</h1>
        <a href="?page=prepare&mode=expert" class="workspace-upload-link"><component :is="NAV_ICONS.Upload" :size="15" />上传固件</a>
      </header>
      <div class="workspace-summary" aria-label="工作台概览" :aria-busy="loading">
        <a class="workspace-summary-item" href="?page=prepare&mode=expert">
          <span class="workspace-summary-icon"><component :is="NAV_ICONS.Cpu" :size="18" /></span>
          <span><span class="workspace-summary-label">可分析固件</span><strong>{{ initialLoading ? '—' : readyCount }}</strong></span>
          <span class="workspace-summary-arrow">↗</span>
        </a>
        <button v-for="metric in metrics" :key="metric.key" class="workspace-summary-item" type="button" :class="[metric.key, { selected: filter === metric.key }]" :aria-pressed="filter === metric.key" @click="setFilter(metric.key)">
          <span class="workspace-summary-icon"><component :is="NAV_ICONS[metric.icon]" :size="18" /></span>
          <span><span class="workspace-summary-label">{{ metric.label }}</span><strong>{{ initialLoading ? '—' : metric.count }}</strong></span>
          <span class="workspace-summary-arrow">↘</span>
        </button>
      </div>
      <p v-if="error" class="workspace-overview-error" role="status">{{ error }}<button type="button" @click="$emit('refresh')">重新加载</button></p>
    </template>

    <slot />

    <section v-if="!active" ref="recentRef" class="workspace-recent" aria-label="分析会话">
      <div class="workspace-recent-head">
        <h2>分析会话 <span>{{ sessions.length }}</span></h2>
        <button type="button" class="workspace-refresh" :disabled="loading" @click="$emit('refresh')"><component :is="NAV_ICONS.Refresh" :size="14" :class="{ spinning: loading }" />刷新</button>
      </div>
      <div class="workspace-recent-toolbar">
        <div class="workspace-recent-filters" aria-label="筛选分析会话">
          <button v-for="item in filters" :key="item.key" type="button" :class="{ on: filter === item.key }" :aria-pressed="filter === item.key" @click="filter = item.key">{{ item.label }}</button>
        </div>
        <label class="workspace-recent-search"><component :is="NAV_ICONS.Search" :size="14" /><input v-model="query" type="search" placeholder="搜索会话或固件" aria-label="搜索会话或固件" /></label>
      </div>
      <div class="workspace-session-table" :aria-busy="loading">
        <div class="workspace-session-columns" aria-hidden="true"><span>会话 / 固件</span><span>状态</span><span>发现</span><span>最近更新</span><span /></div>
        <button v-for="row in pageRows" :key="row.session_id" type="button" class="workspace-session-row" :aria-label="'打开会话：' + sessionTitle(row)" @click="$emit('select', { sid: row.session_id, jobId: row.job_id || '' })">
          <span class="workspace-session-name"><span class="workspace-session-glyph"><component :is="NAV_ICONS.ChatDotRound" :size="16" /></span><span><strong :title="sessionTitle(row)">{{ sessionTitle(row) }}</strong><small :title="firmwareName(row)">{{ firmwareName(row) }}</small></span></span>
          <span><span class="workspace-state" :data-state="row.status"><i />{{ sessionStatus(row.status) }}</span></span>
          <span class="workspace-session-findings">{{ (row.findings || []).length }}</span>
          <time :datetime="row.updated_at || row.created_at" :title="fullDate(row)">{{ shortDate(row) }}</time>
          <span class="workspace-session-enter"><component :is="NAV_ICONS.ArrowRight" :size="16" /></span>
        </button>
        <div v-if="!pageRows.length" class="workspace-sessions-empty" role="status"><component :is="NAV_ICONS.ChatDotRound" :size="24" /><span>{{ initialLoading ? '正在加载会话' : query || filter !== 'all' ? '没有匹配的会话' : '暂无分析会话' }}</span><button v-if="query || filter !== 'all'" type="button" @click="query = ''; filter = 'all'">清除筛选</button></div>
      </div>
      <footer class="workspace-recent-footer"><span>{{ filtered.length }} 个会话</span><div v-if="pageCount > 1"><button type="button" aria-label="上一页会话" :disabled="page === 1" @click="page--">‹</button><span>{{ page }} / {{ pageCount }}</span><button type="button" aria-label="下一页会话" :disabled="page === pageCount" @click="page++">›</button></div></footer>
    </section>
  </div>
</template>

<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import { NAV_ICONS } from './icons.js'
import { pipelineFinished } from './pipeline.js'

const props = defineProps({
  active: Boolean,
  jobs: { type: Array, default: () => [] },
  allSessions: { type: Array, default: () => [] },
  loading: Boolean,
  error: { type: String, default: '' }
})
defineEmits(['select', 'refresh'])
const query = ref('')
const filter = ref('all')
const page = ref(1)
const recentRef = ref(null)
const sessions = computed(() => props.allSessions.filter(row => !row.archived))
const initialLoading = computed(() => props.loading && !props.jobs.length && !props.allSessions.length)
const readyCount = computed(() => props.jobs.filter(job => job.status !== 'failed' && pipelineFinished(job)).length)
const metrics = computed(() => [
  { key: 'running', label: '正在分析', icon: 'Activity', count: sessions.value.filter(row => row.status === 'running').length },
  { key: 'waiting', label: '等待确认', icon: 'Clock', count: sessions.value.filter(row => isWaiting(row.status)).length },
  { key: 'all', label: '分析会话', icon: 'ChatDotRound', count: sessions.value.length }
])
const filters = [{ key: 'all', label: '全部' }, { key: 'running', label: '进行中' }, { key: 'waiting', label: '待确认' }, { key: 'done', label: '已完成' }, { key: 'error', label: '异常' }]
const jobNames = computed(() => new Map(props.jobs.map(job => [job.job_id, job.firmware])))
function isWaiting(status) { return ['awaiting_continue', 'awaiting_emulation', 'awaiting_approval'].includes(status) }
function firmwareName(row) { return jobNames.value.get(row.job_id) || row.firmware || row.job_id || '未绑定固件' }
function sessionTitle(row) {
  const line = String(row.task || '').split('\n')[0].replace(/【[^】]*】/g, '').replace(/^(?:本次挖掘目标|用户希望挖到)[:：]\s*/, '').trim()
  return line || row.session_id || '未命名会话'
}
function sessionStatus(status) { return ({ running: '进行中', done: '已完成', error: '异常', failed: '失败', interrupted: '已中断', awaiting_continue: '待确认', awaiting_emulation: '待模拟', awaiting_approval: '待审批', pending: '等待中' })[status] || status || '未知' }
function timestamp(row) { return Date.parse(row.updated_at || row.created_at) || 0 }
function fullDate(row) { return timestamp(row) ? new Date(timestamp(row)).toLocaleString('zh-CN') : '更新时间未记录' }
function shortDate(row) { return timestamp(row) ? new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).format(timestamp(row)) : '—' }
const filtered = computed(() => {
  const q = query.value.trim().toLowerCase()
  return sessions.value.filter(row => {
    if (filter.value === 'waiting' && !isWaiting(row.status)) return false
    if (filter.value === 'error' && !['error', 'failed', 'interrupted'].includes(row.status)) return false
    if (['running', 'done'].includes(filter.value) && row.status !== filter.value) return false
    return !q || `${sessionTitle(row)} ${firmwareName(row)} ${row.session_id}`.toLowerCase().includes(q)
  }).sort((a, b) => timestamp(b) - timestamp(a))
})
const pageCount = computed(() => Math.max(1, Math.ceil(filtered.value.length / 6)))
const pageRows = computed(() => filtered.value.slice((page.value - 1) * 6, page.value * 6))
watch([query, filter], () => { page.value = 1 })
watch(pageCount, count => { page.value = Math.min(page.value, count) })
async function setFilter(key) {
  filter.value = key
  await nextTick()
  recentRef.value?.scrollIntoView({ behavior: 'auto', block: 'nearest' })
}
</script>

<style scoped>
.workspace-conversation { display: contents; }
.workspace-overview { width: 100%; max-width: 1160px; margin: 0 auto; padding: 30px 34px 40px; box-sizing: border-box; color: var(--ui-text); }
.workspace-overview-head, .workspace-recent-head, .workspace-recent-toolbar, .workspace-recent-footer { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.workspace-overview-head { margin-bottom: 24px; }
h1 { font-size: 26px; font-weight: 600; letter-spacing: -.6px; margin: 0; }
.workspace-upload-link, .workspace-refresh { display: inline-flex; align-items: center; gap: 7px; color: var(--ui-secondary); font: inherit; font-size: 12px; border: 1px solid var(--ui-border-strong); border-radius: 7px; background: var(--ui-surface); padding: 9px 12px; text-decoration: none; cursor: pointer; }
.workspace-upload-link:hover, .workspace-refresh:hover { color: var(--ui-accent); border-color: var(--ui-accent); }
.workspace-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 24px; }
.workspace-summary-item { display: flex; position: relative; align-items: center; gap: 12px; min-width: 0; padding: 18px 16px; border: 1px solid var(--ui-border); background: var(--ui-surface); border-radius: 9px; color: var(--ui-text); text-decoration: none; text-align: left; cursor: pointer; font: inherit; }
.workspace-summary-item:hover { border-color: var(--ui-border-strong); background: var(--ui-subtle); }
.workspace-summary-item.selected { border-color: color-mix(in srgb,var(--ui-accent) 55%,var(--ui-border)); }
.workspace-summary-item > span:nth-child(2) { display: flex; flex-direction: column; gap: 8px; }
.workspace-summary-icon { display: grid; place-items: center; width: 34px; height: 34px; flex: none; border-radius: 8px; background: var(--ui-accent-fill); color: var(--ui-accent); }
.running .workspace-summary-icon { background: color-mix(in srgb,var(--ui-green) 12%,transparent); color: var(--ui-green); }
.waiting .workspace-summary-icon { background: color-mix(in srgb,var(--ui-amber) 12%,transparent); color: var(--ui-amber); }
.workspace-summary-label { font-size: 11px; color: var(--ui-secondary); white-space: nowrap; }
.workspace-summary strong { font-size: 27px; font-weight: 550; font-variant-numeric: tabular-nums; line-height: 1; letter-spacing: -.8px; }
.workspace-summary-arrow { position: absolute; top: 14px; right: 12px; color: var(--ui-muted); font-size: 12px; }
.workspace-overview-error { display: flex; justify-content: space-between; color: var(--ui-amber); border: 1px solid var(--ui-border); border-radius: 8px; padding: 12px 14px; font-size: 12px; }
.workspace-overview-error button, .workspace-sessions-empty button { border: 0; background: transparent; color: var(--ui-accent); font: inherit; cursor: pointer; }
.workspace-recent { margin-top: 26px; border: 1px solid var(--ui-border); border-radius: 10px; background: var(--ui-surface); overflow: hidden; }
.workspace-recent-head { padding: 16px 20px; }
h2 { font-size: 14px; font-weight: 600; margin: 0; display: inline-flex; align-items: center; gap: 9px; }
h2 span { font-size: 10px; font-weight: 500; color: var(--ui-muted); background: var(--ui-subtle); padding: 3px 7px; border-radius: 5px; }
.workspace-refresh { border-color: transparent; padding: 4px; font-size: 11px; background: transparent; }
.workspace-refresh:disabled { opacity: .5; }
.workspace-recent-toolbar { padding: 0 20px 14px; }
.workspace-recent-filters { display: flex; align-items: center; gap: 3px; }
.workspace-recent-filters button { border: 0; border-radius: 5px; padding: 7px 10px; background: transparent; color: var(--ui-muted); font: inherit; font-size: 11px; cursor: pointer; white-space: nowrap; }
.workspace-recent-filters button.on { color: var(--ui-accent); background: var(--ui-accent-fill); }
.workspace-recent-filters button:hover { color: var(--ui-text); }
.workspace-recent-search { display: flex; align-items: center; gap: 8px; padding: 8px 10px; border: 1px solid var(--ui-border); border-radius: 6px; color: var(--ui-muted); max-width: 205px; min-width: 100px; }
.workspace-recent-search:focus-within { border-color: var(--ui-accent); }
.workspace-recent-search input { width: 100%; min-width: 0; border: 0; outline: 0; color: var(--ui-text); background: transparent; font: inherit; font-size: 11px; }
.workspace-recent-search input::placeholder { color: var(--ui-muted); }
.workspace-session-columns, .workspace-session-row { display: grid; grid-template-columns: minmax(0,1fr) 100px 55px 120px 20px; gap: 14px; align-items: center; padding: 0 20px; }
.workspace-session-columns { min-height: 34px; background: var(--ui-subtle); border-block: 1px solid var(--ui-border); color: var(--ui-muted); font-size: 10px; }
.workspace-session-row { width: 100%; min-height: 69px; border: 0; border-bottom: 1px solid var(--ui-border); background: transparent; color: var(--ui-secondary); font: inherit; text-align: left; cursor: pointer; }
.workspace-session-row:hover { background: var(--ui-subtle); }
.workspace-session-name { display: flex; align-items: center; gap: 11px; min-width: 0; }
.workspace-session-name > span:last-child { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
.workspace-session-name strong { font-size: 12px; font-weight: 500; color: var(--ui-text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.workspace-session-name small { font-size: 10px; color: var(--ui-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.workspace-session-glyph { color: var(--ui-muted); display: grid; place-items: center; flex: none; width: 30px; height: 32px; border: 1px solid var(--ui-border); border-radius: 6px; }
.workspace-state { display: inline-flex; gap: 5px; align-items: center; white-space: nowrap; font-size: 10px; color: var(--ui-secondary); background: var(--ui-subtle); border: 1px solid var(--ui-border); padding: 4px 7px; border-radius: 5px; }
.workspace-state i { width: 4px; height: 4px; border-radius: 50%; background: currentColor; }
.workspace-state[data-state='running'] { color: var(--ui-green); border-color: color-mix(in srgb,var(--ui-green) 22%,transparent); background: color-mix(in srgb,var(--ui-green) 7%,transparent); }
.workspace-state[data-state^='awaiting'] { color: var(--ui-amber); border-color: color-mix(in srgb,var(--ui-amber) 22%,transparent); background: color-mix(in srgb,var(--ui-amber) 7%,transparent); }
.workspace-state:is([data-state='error'],[data-state='failed']) { color: var(--ui-red); }
.workspace-session-findings, time { font-size: 10px; font-variant-numeric: tabular-nums; }
.workspace-session-enter { color: var(--ui-muted); }
.workspace-session-row:hover .workspace-session-enter { color: var(--ui-accent); }
.workspace-recent-footer { padding: 13px 20px; color: var(--ui-muted); font-size: 10px; }
.workspace-recent-footer > div { display: flex; align-items: center; gap: 12px; }
.workspace-recent-footer button { border: 1px solid var(--ui-border); background: transparent; color: var(--ui-secondary); border-radius: 4px; width: 25px; height: 24px; cursor: pointer; font-size: 16px; }
.workspace-recent-footer button:disabled { opacity: .3; }
.workspace-sessions-empty { min-height: 132px; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; font-size: 12px; color: var(--ui-muted); }
.spinning { animation: workspace-spin 1.5s linear infinite; }
@keyframes workspace-spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spinning { animation: none; } }
</style>
