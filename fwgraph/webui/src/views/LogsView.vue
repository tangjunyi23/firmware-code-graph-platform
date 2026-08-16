<template>
  <div>
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
            <el-table-column prop="action" label="动作" width="160" />
            <el-table-column prop="detail" label="详情" min-width="220" show-overflow-tooltip />
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup>
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
.log-controls {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.log-view {
  background: #f4f8fd;
  color: #3d5470;
  border: 1px solid rgba(43, 108, 229, .18);
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
