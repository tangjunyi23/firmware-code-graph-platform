<template>
  <div>
    <header class="ins-head">
      <div class="ins-head-row">
        <h1 class="ins-title"><span class="ins-ico"><component :is="NAV_ICONS.Tickets" :size="18" /></span>日志审计</h1>
      </div>
      <p class="ins-sub">运行与服务日志检索、实时跟踪。</p>
    </header>

    <el-card shadow="never" class="block">
      <el-tabs v-model="tab">
        <el-tab-pane label="运行日志" name="runtime">
          <div class="log-controls">
            <el-select v-model="logName" placeholder="选择日志文件" style="width: 280px" @change="loadTail">
              <el-option
                v-for="f in logFiles"
                :key="f.name"
                :value="f.name"
                :label="`${f.name} (${fmtSize(f.size)})`"
              />
            </el-select>
            <el-select v-model="lines" style="width: 110px" @change="loadTail">
              <el-option v-for="n in [100, 200, 500, 1000]" :key="n" :value="n" :label="`${n} 行`" />
            </el-select>
            <el-button size="small" :loading="loadingTail" @click="loadTail">刷新</el-button>
            <el-switch v-model="autoRefresh" active-text="自动刷新" inline-prompt />
          </div>
          <pre ref="logBox" class="log-view">{{ logText }}</pre>
        </el-tab-pane>

        <el-tab-pane v-if="isAdmin" label="审计日志" name="audit">
          <div class="log-controls">
            <el-button size="small" :loading="loadingAudit" @click="loadAudit">刷新</el-button>
          </div>
          <el-alert
            v-if="auditUnavailable"
            type="info"
            :closable="false"
            title="审计日志读取接口暂未在后端开放"
            style="margin-bottom: 10px"
          />
          <el-table v-else :data="auditRows" size="small" v-loading="loadingAudit" max-height="460">
            <el-table-column label="时间" width="180">
              <template #default="{ row }">{{ fmtTime(row.ts) }}</template>
            </el-table-column>
            <el-table-column prop="user" label="用户" width="140" />
            <el-table-column label="动作" width="160">
              <template #default="{ row }">
                <span class="act-tag" :class="actionKind(row.action)">{{ row.action }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="detail" label="详情" min-width="220" show-overflow-tooltip />
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup>
import { NAV_ICONS } from '../workbench/icons.js'
import { nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

defineProps({ isAdmin: { type: Boolean, default: false } })

const tab = ref('runtime')
const logFiles = ref([])
const logName = ref('')
const lines = ref(200)
const logText = ref('')
const loadingTail = ref(false)
const autoRefresh = ref(false)
const logBox = ref(null)
const auditRows = ref([])
const auditUnavailable = ref(false)
const loadingAudit = ref(false)
let timer = null

function fmtTime (iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return isNaN(d) ? iso : d.toLocaleString()
}

function fmtSize (n) {
  if (n == null) return ''
  if (n > 1048576) return (n / 1048576).toFixed(1) + ' MB'
  if (n > 1024) return (n / 1024).toFixed(1) + ' KB'
  return n + ' B'
}

// 审计动作三级分色：读操作灰、写操作蓝、敏感操作红（登录/令牌/用户/配置）
function actionKind (action) {
  const a = String(action || '').toLowerCase()
  if (/(login|logout|token|password|user|config|fuzz|exec|trace|delete|remove)/.test(a)) return 'act-danger'
  if (/(upload|create|post|put|graph|attack|route|decompile|extract)/.test(a)) return 'act-write'
  return 'act-read'
}

async function loadFiles () {
  try {
    logFiles.value = await api('/logs')
    if (!logName.value && logFiles.value.length) {
      // 默认选最近修改的日志
      const sorted = [...logFiles.value].sort((a, b) => String(b.mtime).localeCompare(String(a.mtime)))
      logName.value = sorted[0].name
    }
  } catch (e) {
    ElMessage.error('日志列表加载失败: ' + e.message)
  }
}

async function loadTail () {
  if (!logName.value) return
  loadingTail.value = true
  try {
    const r = await api(`/logs/tail?name=${encodeURIComponent(logName.value)}&lines=${lines.value}`)
    logText.value = (r.lines || []).join('\n')
    await nextTick()
    if (logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight
  } catch (e) {
    ElMessage.error('日志加载失败: ' + e.message)
  } finally {
    loadingTail.value = false
  }
}

async function loadAudit () {
  loadingAudit.value = true
  try {
    const r = await api('/audit?limit=200')
    if (Array.isArray(r)) {
      auditRows.value = [...r].reverse()
      auditUnavailable.value = false
    } else {
      auditUnavailable.value = true
    }
  } catch {
    auditUnavailable.value = true
  } finally {
    loadingAudit.value = false
  }
}

watch(autoRefresh, (on) => {
  if (timer) { clearInterval(timer); timer = null }
  if (on) timer = setInterval(() => { if (tab.value === 'runtime') loadTail() }, 3000)
})
watch(tab, (t) => { if (t === 'audit') loadAudit() })

onMounted(async () => {
  await loadFiles()
  await loadTail()
})
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.block { margin-bottom: 14px; }
.act-tag {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 999px;
  font-size: 12px;
  line-height: 18px;
  white-space: nowrap;
}
.act-read {
  color: var(--fw-text-2);
  background: var(--fw-bg-2);
}
.act-write {
  color: var(--fw-brand);
  background: var(--fw-fill);
}
.act-danger {
  color: var(--fw-danger);
  background: rgba(225, 29, 72, .1);
}
.log-controls {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.log-view {
  background: var(--fw-surface-2);
  color: var(--fw-text-2);
  border: 1px solid color-mix(in srgb, var(--fw-brand) 18%, transparent);
  border-radius: 6px;
  padding: 12px;
  font-size: 12px;
  line-height: 1.6;
  height: 460px;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
}
</style>
