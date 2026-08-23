<template>
  <div class="wb-root" data-wb-theme="light">
    <div class="body">
      <aside class="rail">
        <button type="button" class="new-btn" @click="reset">{{ t('prepare.new') }}</button>
        <div class="section">{{ t('prepare.heading') }}</div>
        <div class="list">
          <p v-if="!jobs.length" class="empty">{{ t('prepare.empty') }}</p>
          <button
            v-for="job in jobs"
            :key="job.job_id"
            type="button"
            class="row"
            :class="{ on: current && current.job_id === job.job_id }"
            @click="openJob(job)"
          >
            <span class="dot" :data-on="RUNNING.has(job.status) || undefined" />
            <span class="title" :title="job.firmware">{{ job.firmware }}</span>
            <span class="meta">{{ STATUS_TEXT[job.status] || job.status }}</span>
          </button>
        </div>
      </aside>
      <main class="main">
        <div class="pane" :class="{ hero: !current }">
          <PipelineCard v-if="current" :job="current" />
          <p v-if="current && current.task" class="task">前置提示词：{{ current.task }}</p>
          <p v-if="current && pipelineFinished(current)" class="hint">
            前置任务已保存。到「工作台」选中该任务，输入挖掘提示词后发送即可开始漏洞挖掘。
          </p>
          <p v-if="notice" class="notice" :class="{ error: notice.level === 'error' }">{{ notice.text }}</p>
          <div v-if="!current || !pipelineFinished(current)" class="composer-wrap">
            <div v-if="file" class="chip">
              <span>{{ file.name }}</span>
              <button type="button" @click="file = null">×</button>
            </div>
            <textarea
              v-model="draft"
              class="input"
              rows="3"
              :placeholder="t('placeholder.prepare')"
              :disabled="busy"
            />
            <div class="actions">
              <input ref="fileInput" type="file" class="hidden" :accept="FW_ACCEPT" @change="onPick" />
              <button type="button" class="add" :disabled="busy" @click="fileInput.click()">
                {{ t('input.upload') }}
              </button>
              <button
                type="button"
                class="send"
                :disabled="busy || (!file && !current)"
                @click="onSend"
              >开始前置分析</button>
            </div>
          </div>
          <div v-if="uploadPct !== null" class="toast">正在上传固件… {{ uploadPct }}%</div>
        </div>
      </main>
    </div>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { api, uploadFirmware } from '../api.js'
import PipelineCard from '../workbench/PipelineCard.vue'
import { t } from '../workbench/locales.js'
import {
  DEFAULT_PREPARE_TASK, FW_ACCEPT, RUNNING, STATUS_TEXT, pipelineFinished
} from '../workbench/pipeline.js'
import '../workbench/tokens.css'

const jobs = ref([])
const current = ref(null)
const draft = ref('')
const file = ref(null)
const fileInput = ref(null)
const notice = ref(null)
const uploadPct = ref(null)
const sending = ref(false)
const busy = computed(() => sending.value || (current.value && RUNNING.has(current.value.status)))

let timer = null
async function refresh () {
  try {
    const list = await api('/jobs')
    jobs.value = Array.isArray(list) ? list : []
    if (current.value) {
      const fresh = jobs.value.find((j) => j.job_id === current.value.job_id)
      if (fresh) current.value = { ...current.value, ...fresh }
    }
  } catch {
    /* keep last list */
  }
}

function reset () {
  current.value = null
  file.value = null
  draft.value = ''
  notice.value = null
}

function openJob (job) {
  current.value = job
  notice.value = null
}

function onPick (e) {
  const picked = e.target.files && e.target.files[0]
  if (picked) file.value = picked
  e.target.value = ''
}

async function onSend () {
  if (sending.value) return
  const task = draft.value.trim() || DEFAULT_PREPARE_TASK
  if (!file.value && !(current.value && RUNNING.has(current.value.status))) {
    notice.value = { level: 'error', text: '请先选择固件文件' }
    return
  }
  sending.value = true
  notice.value = null
  try {
    if (file.value) {
      uploadPct.value = 0
      const fname = file.value.name
      const resp = await uploadFirmware(file.value, {
        auto: true,
        task,
        onProgress: (loaded, total) => {
          uploadPct.value = total ? Math.round((loaded / total) * 100) : 0
        }
      })
      file.value = null
      current.value = {
        job_id: resp.job_id,
        firmware: fname,
        status: resp.status || 'pending',
        task
      }
    }
  } catch (err) {
    notice.value = { level: 'error', text: err.message || '上传失败' }
  } finally {
    uploadPct.value = null
    sending.value = false
    refresh()
  }
}

onMounted(() => {
  refresh()
  timer = setInterval(refresh, 3000)
})
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.wb-root {
  height: 100%;
  min-height: 0;
  background: var(--dsw-alias-bg-base);
  color: var(--dsw-alias-label-primary);
  font-family: var(--dsw-font-family);
}
.body { display: grid; grid-template-columns: 280px minmax(0, 1fr); height: 100%; min-height: 0; }
.rail {
  display: flex;
  flex-direction: column;
  min-width: 0;
  padding: 12px;
  border-right: 1px solid var(--dsw-alias-border-l1);
  background: var(--dsw-specific-sidebar-fill);
}
.new-btn {
  height: 38px;
  margin-bottom: 8px;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 12px;
  background: var(--dsw-alias-button-elevated-fill);
  font-weight: 500;
  cursor: pointer;
}
.new-btn:hover { background: var(--dsw-alias-button-floating-hover); }
.section {
  height: 28px;
  padding: 0 6px;
  font-size: 12px;
  color: var(--dsw-alias-label-tertiary);
}
.list { flex: 1; min-height: 0; overflow: auto; }
.empty { margin: 16px 8px; font-size: 13px; color: var(--dsw-alias-label-tertiary); }
.row {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  height: 36px;
  padding: 0 8px;
  border: none;
  border-radius: 8px;
  background: transparent;
  cursor: pointer;
  text-align: left;
  font-family: inherit;
}
.row:hover, .row.on { background: var(--dsw-alias-interactive-bg-hover); }
.dot { width: 6px; height: 6px; border-radius: 50%; background: var(--dsw-alias-label-caption); flex: none; }
.dot[data-on] { background: var(--dsw-alias-state-success-primary); }
.title { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13.5px; }
.meta { font-size: 12px; color: var(--dsw-alias-label-tertiary); flex: none; }
.main { min-width: 0; overflow: auto; }
.pane { max-width: 748px; margin: 0 auto; padding: 32px 24px; }
.pane.hero { padding-top: 12vh; }
.task, .hint { font-size: 13px; color: var(--dsw-alias-label-secondary); line-height: 1.6; }
.notice { margin: 12px 0; font-size: 13px; }
.notice.error { color: var(--dsw-alias-state-error-primary); }
.composer-wrap {
  margin-top: 16px;
  padding: 12px 14px;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 22px;
  background: var(--dsw-specific-input-major);
  box-shadow: var(--dsw-shadow-lv1);
}
.chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
  padding: 4px 10px;
  border-radius: 999px;
  background: var(--dsw-alias-interactive-bg-hover);
  font-size: 13px;
}
.chip button { border: none; background: none; cursor: pointer; }
.input {
  width: 100%;
  border: none;
  resize: none;
  outline: none;
  font: inherit;
  background: transparent;
  color: inherit;
}
.actions { display: flex; justify-content: space-between; align-items: center; margin-top: 8px; }
.hidden { display: none; }
.add, .send {
  height: 34px;
  padding: 0 14px;
  border-radius: 8px;
  border: none;
  cursor: pointer;
  font-weight: 500;
}
.add { background: var(--dsw-alias-interactive-bg-hover); }
.send { background: #2563eb; color: #fff; }
.send:disabled, .add:disabled { opacity: 0.5; cursor: default; }
.toast {
  margin-top: 12px;
  font-size: 13px;
  color: var(--dsw-alias-label-secondary);
}
</style>
