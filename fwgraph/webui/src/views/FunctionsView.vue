<template>
  <div>
    <el-card shadow="never" class="block">
      <div class="toolbar">
        <el-select v-model="jobId" placeholder="选择任务" style="width: 320px" @change="loadJob">
          <el-option v-for="j in jobs" :key="j.job_id" :value="j.job_id"
                     :label="`${j.job_id}  ${j.firmware}  (${j.status})`" />
        </el-select>
        <el-input v-model="search" placeholder="名称 / domain / libc" clearable style="width: 240px" />
        <el-select v-model="tagFilter" multiple collapse-tags placeholder="按 tag 过滤" style="width: 260px">
          <el-option v-for="t in KNOWN_TAGS" :key="t" :value="t" :label="t" />
        </el-select>
        <el-select v-model="domainFilter" clearable placeholder="按 domain 过滤" style="width: 170px">
          <el-option v-for="d in domains" :key="d" :value="d" :label="d" />
        </el-select>
        <el-select v-model="sortBy" style="width: 190px">
          <el-option value="lines" label="按行数降序" />
          <el-option value="addr" label="按地址升序" />
        </el-select>
        <span class="muted">{{ filtered.length }} / {{ functions.length }} 个函数</span>
      </div>
    </el-card>

    <el-card shadow="never">
      <el-table :data="pageRows" size="small" v-loading="loading" @row-click="openFunc" row-class-name="clickable">
        <el-table-column label="名称" min-width="220" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="mono">{{ row.name }}</span>
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
        <CodeViewer :code="source" :loading="sourceLoading" />
      </div>
    </el-drawer>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import CodeViewer from '../components/CodeViewer.vue'
import { useNarrowViewport } from '../useNarrowViewport'

const KNOWN_TAGS = ['auth_related', 'network_facing', 'calls_dangerous', 'entrypoint']
const TAG_TYPES = { auth_related: 'danger', network_facing: 'warning', calls_dangerous: 'danger', entrypoint: 'success' }

const jobs = ref([])
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
  jobId.value = id
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
    source.value = `// 加载伪代码失败: ${e.message}`
  } finally {
    sourceLoading.value = false
  }
}

onMounted(async () => {
  try {
    jobs.value = await api('/jobs')
  } catch (e) {
    ElMessage.error('加载任务失败: ' + e.message)
  }
})

defineExpose({ loadJob })
</script>

<style scoped>
.block { margin-bottom: 14px; }
.toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.tag-gap { margin-left: 6px; }
.pager { margin-top: 10px; justify-content: flex-end; }
.fn-meta { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }
.src-bar { display: flex; justify-content: flex-end; margin-bottom: 8px; }
.src-hint { margin-bottom: 10px; }
:deep(.clickable) { cursor: pointer; }
</style>
