<template>
  <Teleport to="body">
    <div v-if="open" class="cp-root" @keydown="onKey">
      <div class="cp-mask" @click="emit('close')" />
      <div class="cp-panel" role="dialog" aria-modal="true" aria-label="全局搜索">
        <div class="cp-head">
          <span class="cp-search-ico"><component :is="NAV_ICONS.Search" :size="16" /></span>
          <input
            ref="inputRef"
            v-model="query"
            class="cp-input"
            placeholder="搜索页面、固件任务、挖掘会话、漏洞…"
            aria-label="搜索"
            @input="activeIndex = 0"
          >
          <kbd class="cp-kbd">Esc</kbd>
        </div>
        <div class="cp-body">
          <p v-if="!results.length" class="cp-empty">
            {{ loading ? '加载中…' : (query ? '没有匹配的结果' : '输入关键词，或直接选择下方入口') }}
          </p>
          <template v-for="group in results" :key="group.label">
            <div class="cp-group">{{ group.label }}<span class="cp-group-count">{{ group.items.length }}</span></div>
            <button
              v-for="item in group.items"
              :key="item.key"
              type="button"
              class="cp-item"
              :class="[{ active: item.flatIndex === activeIndex }, 'k-' + item.kind]"
              @mouseenter="activeIndex = item.flatIndex"
              @click="pick(item)"
            >
              <span class="cp-item-ico" :class="'kind-' + item.kind"><component :is="item.icon ? NAV_ICONS[item.icon] : NAV_ICONS.Menu" :size="14" /></span>
              <span class="cp-item-title">{{ item.title }}</span>
              <span v-if="item.sub" class="cp-item-sub">{{ item.sub }}</span>
              <span v-if="item.badge" class="cp-item-badge" :class="'sev-' + item.badge">{{ item.badge }}</span>
              <span class="cp-item-enter">↵</span>
            </button>
          </template>
        </div>
        <div class="cp-foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> 选择</span>
          <span><kbd>↵</kbd> 打开</span>
          <span><kbd>Esc</kbd> 关闭</span>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import { api } from '../api'
import { NAV_ICONS } from '../workbench/icons.js'

// 命令面板：页面 / 固件任务 / 挖掘会话 / 漏洞 全局检索。
// 动态数据开面板时拉取，缓存 30s，避免常驻轮询。
const props = defineProps({
  open: { type: Boolean, default: false },
  pages: { type: Array, default: () => [] }
})
const emit = defineEmits(['close', 'navigate'])

const query = ref('')
const activeIndex = ref(0)
const inputRef = ref(null)
const loading = ref(false)
const jobs = ref([])
const sessions = ref([])
const findings = ref([])
let cachedAt = 0
let fetchSeq = 0

const PAGE_KIND_LABEL = { page: '页面', job: '固件任务', session: '挖掘会话', finding: '漏洞' }

async function refreshData () {
  if (Date.now() - cachedAt < 30000) return
  const seq = ++fetchSeq
  loading.value = true
  try {
    const [j, s, f] = await Promise.all([
      api('/jobs').catch(() => []),
      api('/vulnagent/sessions').catch(() => []),
      api('/vulnagent/findings').catch(() => [])
    ])
    if (seq !== fetchSeq) return
    jobs.value = Array.isArray(j) ? j : []
    sessions.value = Array.isArray(s) ? s : []
    findings.value = Array.isArray(f) ? f : []
    cachedAt = Date.now()
  } finally {
    if (seq === fetchSeq) loading.value = false
  }
}

const results = computed(() => {
  const q = query.value.trim().toLowerCase()
  const groups = []
  const match = (...fields) => !q || fields.some((f) => String(f || '').toLowerCase().includes(q))

  const pageItems = props.pages
    .filter((p) => match(p.title, p.index, p.sub))
    .map((p) => ({
      kind: 'page',
      key: 'pg-' + p.index + (p.protoTab ? '-' + p.protoTab : ''),
      title: p.title,
      sub: p.sub || '',
      icon: p.icon,
      page: p.index,
      protoTab: p.protoTab || '',
      flatIndex: 0
    }))
  if (pageItems.length) groups.push({ label: '页面', items: pageItems })

  const jobItems = jobs.value
    .filter((j) => match(j.firmware, j.job_id, j.status))
    .slice(0, 6)
    .map((j) => ({ kind: 'job', key: 'jb-' + j.job_id, title: String(j.firmware || j.job_id), sub: `${j.job_id} · ${j.status}`, icon: 'Cpu', flatIndex: 0 }))
  if (jobItems.length) groups.push({ label: '固件任务', items: jobItems })

  const sessItems = sessions.value
    .filter((s) => !s.archived && match(s.task, s.session_id, s.firmware))
    .slice(0, 6)
    .map((s) => {
      let title = String(s.task || s.session_id).replace(/\s+/g, ' ')
      const wish = title.match(/^用户希望挖到[:：]\s*(.+?)(?:。|$)/)
      if (wish) title = wish[1].trim()
      return { kind: 'session', key: 'ss-' + s.session_id, title, sub: s.session_id, icon: 'ChatDotRound', flatIndex: 0, sid: s.session_id }
    })
  if (sessItems.length) groups.push({ label: '挖掘会话', items: sessItems })

  const findItems = findings.value
    .filter((f) => match(f.title, f.id, f.cwe, f.vuln_class, f.function_name))
    .slice(0, 8)
    .map((f) => ({ kind: 'finding', key: 'fd-' + f.id, title: String(f.title || f.id).slice(0, 80), sub: [f.id, f.cwe].filter(Boolean).join(' · '), icon: 'Collection', flatIndex: 0, badge: f.severity }))
  if (findItems.length) groups.push({ label: '漏洞', items: findItems })

  let idx = 0
  for (const g of groups) {
    for (const it of g.items) it.flatIndex = idx++
  }
  return groups.slice(0, 4)
})

watch(() => props.open, async (on) => {
  if (on) {
    query.value = ''
    activeIndex.value = 0
    await nextTick()
    inputRef.value?.focus()
    refreshData()
  }
})

function flatItems () {
  return results.value.flatMap((g) => g.items)
}

function pick (item) {
  emit('navigate', {
    kind: item.kind,
    page: item.page || '',
    protoTab: item.protoTab || '',
    sid: item.sid || ''
  })
  emit('close')
}

function onKey (e) {
  const items = flatItems()
  if (e.key === 'Escape') {
    e.preventDefault()
    emit('close')
  } else if (e.key === 'ArrowDown') {
    e.preventDefault()
    activeIndex.value = items.length ? (activeIndex.value + 1) % items.length : 0
    scrollActive()
  } else if (e.key === 'ArrowUp') {
    e.preventDefault()
    activeIndex.value = items.length ? (activeIndex.value - 1 + items.length) % items.length : 0
    scrollActive()
  } else if (e.key === 'Enter') {
    e.preventDefault()
    const it = items[activeIndex.value]
    if (it) pick(it)
  }
}

function scrollActive () {
  nextTick(() => {
    document.querySelector('.cp-item.active')?.scrollIntoView({ block: 'nearest' })
  })
}
</script>

<style scoped>
.cp-root { position: fixed; inset: 0; z-index: 5300; }
.cp-mask {
  position: absolute;
  inset: 0;
  background: rgba(9, 12, 20, .48);
  backdrop-filter: blur(2px);
}
.cp-panel {
  position: absolute;
  top: 12vh;
  left: 50%;
  transform: translateX(-50%);
  width: min(620px, calc(100vw - 32px));
  max-height: 64vh;
  display: flex;
  flex-direction: column;
  border-radius: 16px;
  border: 1px solid var(--fw-line-strong);
  background: var(--fw-surface);
  box-shadow: 0 24px 64px rgba(9, 12, 20, .32);
  overflow: hidden;
}
.cp-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--fw-line);
}
.cp-search-ico { color: var(--fw-text-3); display: inline-flex; }
.cp-input {
  flex: 1;
  min-width: 0;
  border: none;
  outline: none;
  background: transparent;
  color: var(--fw-text);
  font-size: 15px;
  font-family: inherit;
}
.cp-input::placeholder { color: var(--fw-text-3); }
.cp-kbd, .cp-foot kbd {
  border: 1px solid var(--fw-line-strong);
  border-radius: 5px;
  padding: 1px 6px;
  font-size: 11px;
  color: var(--fw-text-3);
  background: var(--fw-bg);
  font-family: var(--fw-font-mono);
}
.cp-body {
  flex: 1;
  min-height: 120px;
  overflow-y: auto;
  padding: 8px;
}
.cp-empty {
  margin: 40px 0;
  text-align: center;
  color: var(--fw-text-3);
  font-size: 13px;
}
.cp-group {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 10px 4px;
  font-size: 11px;
  font-weight: 650;
  letter-spacing: .08em;
  text-transform: uppercase;
  color: var(--fw-text-3);
}
.cp-group-count {
  font-weight: 500;
  letter-spacing: 0;
  background: var(--fw-bg-2);
  border-radius: 999px;
  padding: 0 7px;
  line-height: 16px;
}
.cp-item {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  padding: 8px 10px;
  border: none;
  border-radius: 10px;
  background: transparent;
  color: var(--fw-text-2);
  text-align: left;
  cursor: pointer;
  font-family: inherit;
}
.cp-item { transition: background-color .1s ease; }
.cp-item.active { background: var(--fw-fill); color: var(--fw-text); }
.cp-item-ico {
  flex: none;
  display: grid;
  place-items: center;
  width: 27px;
  height: 27px;
  border-radius: 8px;
  background: var(--fw-bg-2);
  color: var(--fw-text-3);
  transition: background-color .14s ease, color .14s ease;
}
/* 分类语义色：页面=品牌蓝 任务=青 会话=绿 漏洞=红 */
.cp-item-ico.kind-page { background: rgba(19, 76, 255, .10); color: var(--fw-brand); }
.cp-item-ico.kind-job { background: rgba(13, 148, 178, .12); color: #0d94b2; }
.cp-item-ico.kind-session { background: rgba(22, 163, 74, .12); color: var(--fw-ok); }
.cp-item-ico.kind-finding { background: rgba(225, 29, 72, .10); color: var(--fw-danger); }
html[data-fw-theme='dark'] .cp-item-ico.kind-job { color: #38b6cc; }
.cp-item.active .cp-item-ico {
  filter: brightness(1.15) saturate(1.1);
  box-shadow: inset 0 0 0 1px rgba(19, 76, 255, .18);
}
.cp-item-title {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13.5px;
  color: var(--fw-text);
}
.cp-item-sub {
  flex: none;
  max-width: 180px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 11.5px;
  color: var(--fw-text-3);
  font-family: var(--fw-font-mono);
}
.cp-item-badge {
  flex: none;
  font-size: 10.5px;
  border-radius: 999px;
  padding: 0 7px;
  line-height: 16px;
  font-weight: 650;
}
.cp-item-badge.sev-critical, .cp-item-badge.sev-high { color: #9f1239; background: #ffe4e6; }
.cp-item-badge.sev-medium { color: #854d0e; background: #fef9c3; }
.cp-item-badge.sev-low, .cp-item-badge.sev-info { color: #1e3a8a; background: #e0e7ff; }
html[data-fw-theme='dark'] .cp-item-badge.sev-critical,
html[data-fw-theme='dark'] .cp-item-badge.sev-high { color: #fca5b5; background: rgba(225, 29, 72, .18); }
html[data-fw-theme='dark'] .cp-item-badge.sev-medium { color: #fde68a; background: rgba(217, 119, 6, .18); }
html[data-fw-theme='dark'] .cp-item-badge.sev-low,
html[data-fw-theme='dark'] .cp-item-badge.sev-info { color: #b9c6ff; background: rgba(91, 124, 255, .16); }
.cp-item-enter { flex: none; color: var(--fw-text-3); font-size: 12px; opacity: 0; }
.cp-item.active .cp-item-enter { opacity: 1; }
.cp-foot {
  display: flex;
  gap: 16px;
  padding: 8px 16px;
  border-top: 1px solid var(--fw-line);
  color: var(--fw-text-3);
  font-size: 11.5px;
}
.cp-foot kbd { margin-right: 4px; }
</style>
