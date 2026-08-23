<template>
  <div class="rail">
    <button type="button" class="new-chat" @click="$emit('new-session')">
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
          <span class="title" :title="folder.job.firmware">{{ folder.job.firmware }}</span>
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
              <span class="title">{{ sessTitle(sess) }}</span>
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
          <span class="title">{{ sessTitle(sess) }}</span>
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
            <span class="title">{{ sessTitle(sess) }}</span>
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

function sessTitle (sess) {
  const task = (sess.task || '').replace(/\s+/g, ' ').trim()
  return task.slice(0, 36) || sess.session_id
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
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 12px;
  background: var(--dsw-alias-button-elevated-fill);
  color: var(--dsw-alias-label-primary);
  font-size: 14px;
  font-weight: 500;
  line-height: 22px;
  cursor: pointer;
  font-family: inherit;
}
.new-chat:hover { background: var(--dsw-alias-button-floating-hover); }

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
  border-radius: 8px;
  background: var(--dsw-alias-interactive-bg-hover);
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
.session-main {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  flex: 1;
  height: 100%;
  border: none;
  background: transparent;
  color: inherit;
  cursor: pointer;
  text-align: left;
  font-family: inherit;
  padding: 0;
}
.project-row:hover,
.session-row:hover,
.session-row.selected,
.project-row.selected { background: var(--dsw-alias-interactive-bg-hover); }
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
.title {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13.5px;
  line-height: 20px;
  letter-spacing: -0.01em;
}
.dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--dsw-alias-label-caption);
  flex: none;
}
.dot[data-on] { background: var(--dsw-alias-state-success-primary); }

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
