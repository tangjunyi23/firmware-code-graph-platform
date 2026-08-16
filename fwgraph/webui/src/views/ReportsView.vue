<template>
  <div class="reports-layout">
    <!-- 报告列表 -->
    <el-card shadow="never" class="list-card">
      <template #header>
        <div class="row-between">
          <span>报告列表</span>
          <el-button size="small" :loading="loadingList" @click="loadReports">刷新</el-button>
        </div>
      </template>
      <div
        v-for="r in reports"
        :key="r.report_id"
        class="report-item"
        :class="{ active: r.report_id === currentId }"
        @click="openReport(r)"
      >
        <div class="ri-top">
          <el-tag size="small"
                  :type="r.kind === 'job' ? 'success' : r.kind === 'protofuzz' ? 'primary' : 'warning'"
                  effect="dark">
            {{ r.kind === 'job' ? '综合报告' : r.kind === 'protofuzz' ? '协议测试' : '挖掘报告' }}
          </el-tag>
          <span class="muted">{{ fmtTime(r.created_at) }}</span>
        </div>
        <div class="ri-title" :title="r.title">{{ r.title }}</div>
        <div class="muted">{{ fmtSize(r.size) }}</div>
      </div>
      <el-empty v-if="!loadingList && !reports.length" description="还没有生成报告" :image-size="70" />
    </el-card>

    <!-- 报告预览 -->
    <el-card shadow="never" class="viewer-card">
      <template #header>
        <div class="row-between">
          <span class="viewer-title">{{ currentTitle || '报告预览' }}</span>
          <div>
            <el-button size="small" :disabled="!currentId" :loading="exporting === 'docx'" @click="exportFmt('docx')">
              导出 DOCX
            </el-button>
            <el-button size="small" :disabled="!currentId" :loading="exporting === 'pdf'" @click="exportFmt('pdf')">
              导出 PDF
            </el-button>
            <el-button size="small" :disabled="!currentId" @click="download">
              <el-icon style="margin-right:4px"><Download /></el-icon>下载 Markdown
            </el-button>
          </div>
        </div>
      </template>
      <div v-loading="loadingText" class="viewer-body">
        <div v-if="html" class="md-body" v-html="html"></div>
        <el-empty v-else-if="!loadingText" description="从左侧选择一份报告" :image-size="80" />
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { marked } from 'marked'
import { api, getToken } from '../api'

marked.setOptions({ breaks: true, gfm: true })

const reports = ref([])
const currentId = ref('')
const currentTitle = ref('')
const html = ref('')
const loadingList = ref(false)
const loadingText = ref(false)
const exporting = ref('')

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
    html.value = marked.parse(String(text))
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

onMounted(loadReports)
</script>

<style scoped>
.reports-layout {
  display: grid;
  grid-template-columns: 320px minmax(0, 1fr);
  gap: 14px;
  align-items: start;
}
@media (max-width: 900px) {
  .reports-layout { grid-template-columns: 1fr; }
}
.row-between { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.viewer-title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.report-item {
  padding: 10px 12px;
  border: 1px solid rgba(43, 108, 229, .14);
  border-radius: 8px;
  margin-bottom: 10px;
  cursor: pointer;
  transition: border-color .15s ease, box-shadow .15s ease;
}
.report-item:hover { border-color: rgba(102, 224, 255, .4); }
.report-item.active {
  border-color: rgba(43, 108, 229, .6);
  box-shadow: 0 0 12px rgba(43, 108, 229, .18), inset 3px 0 0 #2b6ce5;
  background: rgba(43, 108, 229, .06);
}
.ri-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
.ri-title {
  color: #1c2b3a;
  font-size: 13.5px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  margin-bottom: 4px;
}
.viewer-body { min-height: 300px; max-height: calc(100vh - 220px); overflow: auto; }
.list-card :deep(.el-card__body) { max-height: calc(100vh - 220px); overflow: auto; }
</style>
