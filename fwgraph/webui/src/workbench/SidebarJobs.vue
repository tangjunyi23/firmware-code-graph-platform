<template>
  <div class="rail">
    <button type="button" class="new-chat" data-tour="wb-new" @click="$emit('new-session')">
      <IconNewChatOutline16 :size="16" />
      {{ t('session.new') }}
    </button>

    <div class="section-head">
      <span class="section-label">{{ t('session.heading') }}</span>
    </div>

    <div class="search-row">
      <IconSearchOutline16 :size="14" class="search-icon" />
      <input
        v-model="query"
        class="search-input"
        :placeholder="t('firmware.search')"
      />
    </div>

    <div class="list">
      <p v-if="!filtered.length && !ungrouped.length && !archived.length" class="empty">{{ t('firmware.empty') }}</p>

      <div v-for="folder in filtered" :key="folder.job.job_id" class="folder">
        <button
          type="button"
          class="project-row"
          :class="{ selected: jobId === folder.job.job_id && !activeSid }"
          @click="onProjectClick(folder)"
        >
          <IconChevronDownOutline14
            class="arrow"
            :class="{ open: isOpen(folder.job.job_id) }"
            :size="12"
          />
          <span class="title" :title="folder.job.firmware">{{ firmwareLabel(folder.job) }}</span>
        </button>
        <template v-if="isOpen(folder.job.job_id)">
          <div
            v-for="sess in folder.sessions"
            :key="sess.session_id"
            class="session-row"
            :class="{ selected: activeSid === sess.session_id }"
          >
            <button
              type="button"
              class="session-main"
              @click="$emit('select', { sid: sess.session_id, jobId: folder.job.job_id })"
            >
              <span class="dot" :data-on="sess.status === 'running' || sess.status === 'awaiting_continue' || undefined" />
              <span class="title" :title="sess.task || sess.session_id">{{ sessTitle(sess) }}</span>
              <span class="sess-time">{{ relTime(sess) }}</span>
            </button>
            <button
              type="button"
              class="sess-act"
              :title="t('session.more')"
              :aria-label="t('session.more')"
              :aria-expanded="menu && menu.sid === sess.session_id ? 'true' : 'false'"
              @click.stop="openMenu($event, sess, folder.job.job_id)"
            >
              <IconMore :size="14" />
            </button>
          </div>
          <button
            v-if="!folder.sessions.length"
            type="button"
            class="session-row ghost"
            @click="$emit('select-job', folder.job)"
          >
            <span class="title">{{ t('prepare.startHunt') }}</span>
          </button>
        </template>
      </div>

      <div
        v-for="sess in ungrouped"
        :key="sess.session_id"
        class="session-row"
        :class="{ selected: activeSid === sess.session_id }"
      >
        <button
          type="button"
          class="session-main"
          @click="$emit('select', { sid: sess.session_id, jobId: sess.job_id || '' })"
        >
          <span class="dot" :data-on="sess.status === 'running' || sess.status === 'awaiting_continue' || undefined" />
          <span class="title" :title="sess.task || sess.session_id">{{ sessTitle(sess) }}</span>
              <span class="sess-time">{{ relTime(sess) }}</span>
        </button>
        <button
          type="button"
          class="sess-act"
          :title="t('session.more')"
          :aria-label="t('session.more')"
          @click.stop="openMenu($event, sess, sess.job_id || '')"
        >
          <IconMore :size="14" />
        </button>
      </div>

      <div v-if="archived.length" class="archive-block">
        <div class="section-head archive-head">
          <span class="section-label">{{ t('session.archived') }}</span>
          <button
            type="button"
            class="purge"
            @click="$emit('purge-archived')"
          >{{ t('session.purgeArchived') }}</button>
        </div>
        <div
          v-for="sess in archived"
          :key="sess.session_id"
          class="session-row"
          :class="{ selected: activeSid === sess.session_id }"
        >
          <button
            type="button"
            class="session-main"
            @click="$emit('select', { sid: sess.session_id, jobId: sess.job_id || '' })"
          >
            <span class="dot" />
            <span class="title" :title="sess.task || sess.session_id">{{ sessTitle(sess) }}</span>
          </button>
          <button
            type="button"
            class="sess-act"
            :title="t('session.more')"
            :aria-label="t('session.more')"
            @click.stop="openMenu($event, sess, sess.job_id || '')"
          >
            <IconMore :size="14" />
          </button>
        </div>
      </div>
    </div>

    <button type="button" class="settings-btn" @click="openSettings()">
      <IconSettingsOutline16 :size="16" />
      {{ t('settings.title') }}
    </button>

    <Teleport to="body">
      <div
        v-if="menu"
        class="wb-root sess-menu-root"
        :data-wb-theme="theme"
        :style="{ top: menu.top + 'px', left: menu.left + 'px' }"
        @click.stop
      >
        <div class="sess-menu" role="menu">
          <button
            v-if="menu.running"
            type="button"
            class="sess-menu-item"
            role="menuitem"
            @click="pick('stop')"
          >{{ t('session.stop') }}</button>
          <button
            type="button"
            class="sess-menu-item"
            role="menuitem"
            @click="pick(menu.archived ? 'unarchive' : 'archive')"
          >{{ menu.archived ? t('session.unarchive') : t('session.archive') }}</button>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { computed, inject, onMounted, onUnmounted, ref, watch } from 'vue'
import {
  IconSearchOutline16, IconChevronDownOutline14,
  IconNewChatOutline16, IconSettingsOutline16, IconMore
} from './icons.js'
import { t } from './locales.js'

const props = defineProps({
  activeSid: { type: String, default: null },
  jobId: { type: String, default: '' }
})
const emit = defineEmits([
  'select', 'select-job', 'new-session', 'stop', 'archive', 'unarchive', 'purge-archived'
])

const catalog = inject('wbCatalog')
const openSettings = inject('wbOpenSettings', () => {})
const theme = inject('wbTheme', ref('light'))
const query = ref('')
const openFolders = ref(new Set())
const menu = ref(null)


function isOpen (id) {
  if (query.value) return true
  if (openFolders.value.size === 0 && catalog.groups.value.folders.length) {
    return catalog.groups.value.folders[0].job.job_id === id
  }
  return openFolders.value.has(id)
}
function toggleFolder (id) {
  const next = new Set(openFolders.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  openFolders.value = next
}
function onProjectClick (folder) {
  toggleFolder(folder.job.job_id)
  if (!folder.sessions.length) emit('select-job', folder.job)
}
watch(() => props.jobId, (id) => {
  if (id) {
    const next = new Set(openFolders.value)
    next.add(id)
    openFolders.value = next
  }
})

function activeOf (sessions) {
  return (sessions || []).filter((s) => !s.archived)
}

const filtered = computed(() => {
  const q = query.value.trim().toLowerCase()
  const folders = catalog.groups.value.folders.map((f) => ({
    ...f,
    sessions: activeOf(f.sessions)
  }))
  if (!q) return folders
  return folders.filter((f) => {
    const name = (f.job.firmware || '').toLowerCase()
    const hitSess = f.sessions.some((s) => (s.task || '').toLowerCase().includes(q))
    return name.includes(q) || hitSess
  })
})
const ungrouped = computed(() => activeOf(catalog.groups.value.ungrouped))
const archived = computed(() =>
  (catalog.state.sessions || []).filter((s) => s.archived)
)

function firmwareLabel (job) {
  const name = String(job?.firmware || job?.job_id || '').trim()
  return name.replace(/\.(bin|img|chk|trx|tar|gz|zip)$/i, '') || job?.job_id || '未命名固件'
}

function sessTitle (sess) {
  let task = (sess.task || '').replace(/\s+/g, ' ').trim()
  const wish = task.match(/^用户希望挖到[:：]\s*(.+?)(?:。|$)/)
  if (wish) task = wish[1].trim()
  if (!task) return sess.session_id || '未命名对话'
  return task
}

// 相对时间：同名会话靠它区分（"3 小时前"）
function relTime (sess) {
  const iso = sess.updated_at || sess.created_at || ''
  if (!iso) return ''
  const then = new Date(iso).getTime()
  if (isNaN(then)) return ''
  const diff = Date.now() - then
  if (diff < 0) return ''
  const m = Math.floor(diff / 60000)
  if (m < 1) return '刚刚'
  if (m < 60) return `${m} 分钟前`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h} 小时前`
  const d = Math.floor(h / 24)
  if (d < 30) return `${d} 天前`
  const mo = Math.floor(d / 30)
  return mo < 12 ? `${mo} 个月前` : `${Math.floor(mo / 12)} 年前`
}

function openMenu (ev, sess, jobId) {
  ev.stopPropagation()
  const r = ev.currentTarget.getBoundingClientRect()
  const width = 148
  const left = Math.min(window.innerWidth - width - 8, Math.max(8, r.right - width))
  const approxH = sess.status === 'running' ? 76 : 40
  let top = r.bottom + 4
  if (top + approxH > window.innerHeight - 8) {
    top = Math.max(8, r.top - approxH - 4)
  }
  menu.value = {
    sid: sess.session_id,
    jobId: jobId || sess.job_id || '',
    running: sess.status === 'running',
    archived: !!sess.archived,
    top,
    left
  }
}

function pick (action) {
  const cur = menu.value
  menu.value = null
  if (!cur) return
  if (action === 'stop') emit('stop', { sid: cur.sid })
  else if (action === 'archive') emit('archive', { sid: cur.sid, jobId: cur.jobId })
  else if (action === 'unarchive') emit('unarchive', { sid: cur.sid })
}

function onDocClick () {
  menu.value = null
}
onMounted(() => document.addEventListener('click', onDocClick))
onUnmounted(() => document.removeEventListener('click', onDocClick))
</script>

<style scoped>
.rail {
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  padding: 12px 12px 8px;
  box-sizing: border-box;
  color: var(--dsw-alias-label-primary);
  font-size: 14px;
  /* 与主站侧栏同族的底色 + 右侧分隔线，消除中性灰断层 */
  background:
    radial-gradient(120% 120px at 50% 0%, rgba(91, 140, 255, .06), transparent 70%),
    #0d1322;
  border-right: 1px solid #1a2233;
}
html[data-fw-theme='light'] .rail {
  background:
    radial-gradient(120% 120px at 50% 0%, rgba(59, 130, 246, .04), transparent 70%),
    var(--fw-surface);
  border-right-color: var(--fw-line);
}
/* 主题统一：rail 子树内的 harness 别名重绑到 fw 令牌
   （不动 tokens.css 的 1:1 移植契约，只在 rail 作用域覆盖） */
.rail {
  --dsw-alias-label-primary: var(--fw-text, #e7ebf3);
  --dsw-alias-label-secondary: var(--fw-text-2, #a8b2c6);
  --dsw-alias-label-tertiary: var(--fw-text-3, #66708a);
  --dsw-alias-interactive-bg-hover: var(--fw-surface-2, #1a2233);
  --dsw-alias-interactive-bg-hover-solid: var(--fw-bg-2, #10141d);
  --dsw-alias-border-l2: var(--fw-line-strong, #2e3a52);
  --dsw-alias-state-error-primary: var(--fw-danger, #f26076);
}
.new-chat {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  height: 38px;
  margin: 0 2px 8px;
  padding: 8px 16px;
  box-sizing: border-box;
  border: none;
  border-radius: 12px;
  /* 主站主按钮质感：品牌蓝渐变 + 白字 */
  background: linear-gradient(180deg, #5b8cff 0%, #2f6bff 100%);
  color: #fff;
  font-size: 14px;
  font-weight: 600;
  line-height: 22px;
  cursor: pointer;
  font-family: inherit;
  box-shadow:
    0 1px 2px rgba(13, 27, 62, .18),
    0 4px 14px -4px rgba(47, 107, 255, .45),
    inset 0 1px 0 rgba(255, 255, 255, .18);
  transition: box-shadow .16s ease, filter .16s ease;
}
.new-chat:hover {
  background: linear-gradient(180deg, #6e9bff 0%, #3f6fe0 100%);
  box-shadow:
    0 2px 4px rgba(13, 27, 62, .2),
    0 8px 20px -6px rgba(47, 107, 255, .55),
    inset 0 1px 0 rgba(255, 255, 255, .2);
}
.new-chat:active { filter: saturate(1.1); }


.section-head {
  display: flex;
  align-items: center;
  height: 28px;
  padding: 0 6px;
  margin: 2px 0 2px;
}
.section-label {
  font-size: 12px;
  font-weight: 500;
  line-height: 20px;
  color: var(--dsw-alias-label-tertiary);
}
.archive-head {
  justify-content: space-between;
  gap: 8px;
  margin-top: 10px;
}
.purge {
  border: none;
  background: transparent;
  color: var(--dsw-alias-label-tertiary);
  font-size: 11px;
  line-height: 18px;
  cursor: pointer;
  font-family: inherit;
  padding: 0;
}
.purge:hover { color: var(--dsw-alias-state-error-primary); }

.search-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 0 2px 8px;
  padding: 0 10px;
  height: 32px;
  border: 1px solid var(--fw-line-strong, #2e3a52);
  border-radius: 10px;
  background: transparent;
  transition: border-color .15s ease, box-shadow .15s ease;
}
.search-row:focus-within {
  border-color: rgba(91, 140, 255, .45);
  box-shadow: 0 0 0 3px rgba(91, 140, 255, .12);
}
.search-icon { color: var(--dsw-alias-label-tertiary); flex: none; }
.search-input {
  flex: 1;
  min-width: 0;
  border: none;
  background: transparent;
  color: var(--dsw-alias-label-primary);
  outline: none;
  font-size: 13px;
  font-family: inherit;
}

.list {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  padding: 2px 0 8px;
}
.empty {
  margin: 16px 8px;
  font-size: 13px;
  color: var(--dsw-alias-label-tertiary);
}
.project-row,
.session-row {
  display: flex;
  align-items: center;
  gap: 4px;
  width: 100%;
  min-width: 0;
  overflow: hidden;
  border: none;
  border-radius: 8px;
  padding: 0 4px 0 8px;
  background: transparent;
  color: var(--dsw-alias-label-primary);
  text-align: left;
  font-family: inherit;
}
.project-row { height: 34px; cursor: pointer; }
.session-row { height: 32px; padding-left: 20px; }
.folder { min-width: 0; }
.session-main {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  flex: 1;
  height: 100%;
  overflow: hidden;
  border: none;
  background: transparent;
  color: inherit;
  cursor: pointer;
  text-align: left;
  font-family: inherit;
  padding: 0;
}
.title {
  display: block;
  min-width: 0;
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13px;
  line-height: 20px;
}
.sess-time {
  flex: none;
  margin-left: 6px;
  color: var(--dsw-alias-label-tertiary);
  font-size: 11px;
  line-height: 20px;
  opacity: .85;
}
.dot {
  flex: none;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--dsw-alias-label-tertiary);
}
.dot[data-on] { background: var(--fw-ok, #16a34a); }
.project-row:hover,
.session-row:hover { background: var(--dsw-alias-interactive-bg-hover); }
/* 选中态与主导航激活样式同族：品牌色文字 + 浅底 + 左侧指示条 */
.project-row.selected,
.session-row.selected {
  background: rgba(91, 140, 255, .13);
  color: #a9c3ff;
  box-shadow: inset 2px 0 0 #5b8cff;
}
html[data-fw-theme='light'] .project-row.selected,
html[data-fw-theme='light'] .session-row.selected {
  background: var(--fw-fill);
  color: var(--fw-brand);
  box-shadow: inset 2px 0 0 var(--fw-brand);
}
.session-row.selected .title,
.project-row.selected .title { font-weight: 600; }
.session-row.ghost { color: var(--dsw-alias-label-tertiary); }
.sess-act {
  flex: none;
  display: none;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  border: none;
  border-radius: 6px;
  background: transparent;
  color: var(--dsw-alias-label-tertiary);
  cursor: pointer;
}
.session-row:hover .sess-act,
.session-row.selected .sess-act { display: inline-flex; }
.sess-act:hover { background: var(--dsw-alias-interactive-bg-hover-solid); color: var(--dsw-alias-label-primary); }
.arrow {
  flex: none;
  color: var(--dsw-alias-label-tertiary);
  transform: rotate(-90deg);
  transition: transform 150ms var(--ds-ease-in-out, ease);
}
.arrow.open { transform: rotate(0deg); }
.settings-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  height: 36px;
  padding: 0 10px;
  border: none;
  border-radius: 8px;
  background: transparent;
  color: var(--dsw-alias-label-secondary);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  font-family: inherit;
}
.settings-btn:hover {
  background: var(--dsw-alias-interactive-bg-hover);
  color: var(--dsw-alias-label-primary);
}
.acct {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 6px;
  padding: 6px 8px;
}
.acct-av {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: var(--fw-fill, rgba(19,76,255,.08));
  color: var(--fw-brand, #134cff);
  font-size: 12px;
  font-weight: 650;
  text-transform: uppercase;
  flex: none;
}
.acct-meta { display: flex; flex-direction: column; min-width: 0; }
.acct-name { font-size: 13px; font-weight: 600; color: var(--dsw-alias-label-primary); }
.acct-role { font-size: 11px; color: var(--dsw-alias-label-tertiary); }


.sess-menu-root {
  position: fixed;
  z-index: 80;
  width: max-content;
  height: auto;
  overflow: visible;
  background: transparent;
}
.sess-menu {
  display: flex;
  flex-direction: column;
  min-width: 132px;
  padding: 4px;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 10px;
  background: var(--dsw-alias-bg-base);
  box-shadow: var(--dsw-shadow-lv2);
}
.sess-menu-item {
  display: block;
  width: 100%;
  height: 32px;
  padding: 0 10px;
  border: none;
  border-radius: 6px;
  background: transparent;
  color: var(--dsw-alias-label-primary);
  font-size: 13px;
  line-height: 32px;
  text-align: left;
  cursor: pointer;
  font-family: inherit;
}
.sess-menu-item:hover {
  background: var(--dsw-alias-interactive-bg-hover);
}
</style>
