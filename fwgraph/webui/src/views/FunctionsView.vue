<template>
  <div>
    <header class="ins-head">
      <div class="ins-head-row">
        <h1 class="ins-title">
          <span class="ins-ico"><component :is="NAV_ICONS.Document" :size="18" /></span>
          函数
        </h1>
        <div class="ins-actions">
          <JobPicker v-model="jobId" :prefer="['routed', 'surfaced', 'attacked', 'graphed']" @change="loadJob" />
          <el-button :icon="RefreshCw" :loading="loading" @click="jobId && loadJob(jobId)">刷新</el-button>
        </div>
      </div>
      <p class="ins-sub">反编译函数检索：按名称、语义标签、domain 与 libc 等价过滤，点行查看伪代码。</p>
    </header>

    <el-card shadow="never">
      <div class="ins-filter">
        <el-input v-model="search" placeholder="名称 / domain / libc" clearable style="width: 220px" />
        <el-select v-model="tagFilter" multiple collapse-tags placeholder="按 tag 过滤" style="width: 230px">
          <el-option v-for="t in KNOWN_TAGS" :key="t" :value="t" :label="t" />
        </el-select>
        <el-select v-model="domainFilter" clearable placeholder="按 domain 过滤" style="width: 160px">
          <el-option v-for="d in domains" :key="d" :value="d" :label="d" />
        </el-select>
        <el-select v-model="sortBy" style="width: 150px">
          <el-option value="lines" label="按行数降序" />
          <el-option value="addr" label="按地址升序" />
        </el-select>
        <span class="spacer" />
        <span class="ins-count">{{ filtered.length }} / {{ functions.length }} 个函数</span>
      </div>
      <el-table :data="pageRows" size="small" v-loading="loading" @row-click="openFunc" row-class-name="clickable">
        <el-table-column label="名称" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="mono" :title="nameTooltip(row)">{{ displayFnName(row) }}</span>
            <span v-if="fnAlias(row)" class="mono fn-alias">{{ fnAlias(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="addr" label="地址" width="100">
          <template #default="{ row }"><span class="mono">{{ row.addr }}</span></template>
        </el-table-column>
        <el-table-column label="二进制" min-width="180" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="muted">{{ binLabel(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="语义标签" min-width="250">
          <template #default="{ row }">
            <el-tag v-for="t in row.tags || []" :key="t" size="small" :type="tagType(t)" class="tag-gap">{{ t }}</el-tag>
            <el-tag v-if="row.domain" size="small" type="primary" effect="plain" class="tag-gap">{{ row.domain }}</el-tag>
            <el-tag v-if="row.libc_equiv" size="small" type="danger" effect="plain" class="tag-gap">{{ row.libc_equiv }}</el-tag>
            <el-tag v-if="row.verified_reachable" size="small" type="success" class="tag-gap">完整链观测</el-tag>
            <el-tag v-else-if="row.observed_in_trace" size="small" type="warning" class="tag-gap">trace 命中</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="lines" label="行数" width="70" align="right" />
      </el-table>
      <el-pagination
        v-model:current-page="page"
        :page-size="pageSize"
        :total="filtered.length"
        layout="total, prev, pager, next, jumper"
        class="pager"
      />
      <el-empty v-if="!loading && functions.length === 0" description="选择任务后加载函数列表（任务需已完成反编译）" />
    </el-card>

    <el-drawer v-model="funcVisible" :size="isNarrow ? '96%' : '58%'">
      <template #header>
        <span class="mono">{{ current?.name || '' }}</span>
        <span class="muted mono" v-if="current"> &nbsp;{{ current.addr }} @ {{ binLabel(current) }}</span>
      </template>
      <div v-if="current">
        <div class="fn-meta">
          <el-tag v-for="t in current.tags || []" :key="t" size="small" :type="tagType(t)" class="tag-gap">{{ t }}</el-tag>
          <el-tag v-if="current.domain" size="small" type="primary" effect="plain">{{ current.domain }}</el-tag>
          <el-tag v-if="current.libc_equiv" size="small" type="danger" effect="plain">{{ current.libc_equiv }}</el-tag>
          <el-tag v-if="current.verified_reachable" size="small" type="success">完整链观测</el-tag>
          <span class="muted">{{ current.lines }} 行 / {{ current.size }} 字节</span>
        </div>
        <div class="src-bar">
          <el-radio-group v-model="srcKind" size="small" @change="loadSource">
            <el-radio-button value="hexrays">伪代码</el-radio-button>
            <el-radio-button value="asm">汇编</el-radio-button>
          </el-radio-group>
        </div>
        <CodeViewer :code="source" :loading="sourceLoading" :language="srcKind === 'asm' ? 'asm' : 'c'" />
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import CodeViewer from '../components/CodeViewer.vue'
import JobPicker from '../components/JobPicker.vue'
import { NAV_ICONS } from '../workbench/icons.js'
import { RefreshCw } from '@lucide/vue'
import { useNarrowViewport } from '../useNarrowViewport'

const KNOWN_TAGS = ['auth_related', 'network_facing', 'calls_dangerous', 'entrypoint']
const TAG_TYPES = { auth_related: 'danger', network_facing: 'warning', calls_dangerous: 'danger', entrypoint: 'success' }

const jobId = ref('')
const binaries = ref({})
const functions = ref([])
const loading = ref(false)
const search = ref('')
const tagFilter = ref([])
const domainFilter = ref('')
const sortBy = ref('lines')
const page = ref(1)
const pageSize = 50

const funcVisible = ref(false)
const current = ref(null)
const source = ref('')
const sourceLoading = ref(false)
const srcKind = ref('hexrays')
const isNarrow = useNarrowViewport()

function tagType (t) { return TAG_TYPES[t] || 'info' }
// IDA 原名是 sub_XXXX 时优先显示 AI/规则恢复的名字，原名降级为次要信息
function displayFnName (f) {
  return f.ai_name || f.rule_name || f.name
}
function fnAlias (f) {
  const recovered = f.ai_name || f.rule_name
  if (!recovered || recovered === f.name) return ''
  return f.name
}
function nameTooltip (f) {
  const alias = fnAlias(f)
  return alias ? `${displayFnName(f)}（IDA: ${alias}）` : f.name
}
function binLabel (f) {
  const b = binaries.value[f.binary]
  return b ? `${b.path} (${b.arch})` : f.binary
}
const filtered = computed(() => {
  const q = search.value.trim().toLowerCase()
  let rows = functions.value
  if (tagFilter.value.length) {
    rows = rows.filter(f => (f.tags || []).some(t => tagFilter.value.includes(t)))
  }
  if (domainFilter.value) rows = rows.filter(f => f.domain === domainFilter.value)
  if (q) {
    rows = rows.filter(f =>
      (f.name || '').toLowerCase().includes(q) ||
      (f.ai_name || '').toLowerCase().includes(q) ||
      (f.rule_name || '').toLowerCase().includes(q) ||
      (f.domain || '').toLowerCase().includes(q) ||
      (f.libc_equiv || '').toLowerCase().includes(q))
  }
  rows = [...rows]
  if (sortBy.value === 'lines') {
    rows.sort((a, b) => (b.lines || 0) - (a.lines || 0))
  } else {
    rows.sort((a, b) => (a.addr || '').localeCompare(b.addr || ''))
  }
  return rows
})

const domains = computed(() => [...new Set(functions.value.map(f => f.domain).filter(Boolean))].sort())

const pageRows = computed(() => {
  const start = (page.value - 1) * pageSize
  return filtered.value.slice(start, start + pageSize)
})

async function loadJob (id) {
  if (!id) return
  loading.value = true
  functions.value = []
  binaries.value = {}
  page.value = 1
  try {
    const r = await api(`/jobs/${id}/functions`)
    functions.value = r.functions
    binaries.value = r.binaries || {}
  } catch (e) {
    ElMessage.warning('加载函数失败: ' + e.message)
  } finally {
    loading.value = false
  }
}

async function openFunc (row) {
  current.value = row
  funcVisible.value = true
  srcKind.value = 'hexrays'
  source.value = ''
  await loadSource()
}

async function loadSource () {
  if (!current.value) return
  sourceLoading.value = true
  source.value = ''
  const base = `/jobs/${jobId.value}/functions/${current.value.binary}/${current.value.addr}/source`
  try {
    source.value = await api(srcKind.value === 'asm' ? `${base}?asm=1` : base)
  } catch (e) {
    if (e.status === 404 && srcKind.value === 'asm') {
      try {
        const c = await api(base)
        source.value = `// 该函数没有汇编导出，已显示伪代码。\n${c}`
      } catch (e2) {
        source.value = `// 加载伪代码失败: ${e2.message}`
      }
    } else {
      source.value = `// 加载伪代码失败: ${e.message}`
    }
  } finally {
    sourceLoading.value = false
  }
}

defineExpose({ loadJob })
</script>

<style scoped>
.block { margin-bottom: 14px; }
.toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.tag-gap { margin-left: 6px; }
.fn-alias {
  margin-left: 6px;
  font-size: 11.5px;
  color: var(--fw-text-3);
}
.pager { margin-top: 10px; justify-content: flex-end; }
.fn-meta { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }
.src-bar { display: flex; justify-content: flex-end; margin-bottom: 8px; }
.src-hint { margin-bottom: 10px; }
:deep(.clickable) { cursor: pointer; }
</style>
