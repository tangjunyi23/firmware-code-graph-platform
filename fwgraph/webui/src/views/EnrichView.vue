<template>
  <div>
    <el-card class="toolbar-card">
      <div class="toolbar">
        <el-select
          v-model="jobId"
          placeholder="选择任务"
          class="job-select"
          :loading="jobsLoading"
          @change="onJobChange"
        >
          <el-option
            v-for="j in jobs"
            :key="j.job_id"
            :value="j.job_id"
            :label="`${j.job_id} · ${j.firmware}（${j.status}）`"
          />
        </el-select>
        <el-button size="small" :loading="dirLoading" :disabled="!jobId" @click="loadDirectory">
          刷新
        </el-button>
        <span v-if="totalFunctions" class="muted">
          {{ binaries.length }} 个二进制 · {{ total }}/{{ totalFunctions }} 个函数已 AI 增强
        </span>
      </div>
    </el-card>

    <div class="enrich-layout">
      <el-card class="side-card" :body-style="{ padding: '8px' }">
        <el-input
          v-model="filter"
          size="small"
          clearable
          placeholder="按名称 / 地址过滤"
          class="side-filter"
        />
        <el-checkbox v-model="onlyEnriched" size="small" class="side-only">
          仅显示 AI 增强（{{ total }}）
        </el-checkbox>
        <div v-loading="dirLoading" class="side-list">
          <el-empty
            v-if="!dirLoading && binaries.length === 0"
            description="该任务暂无函数产物（需先完成反编译）"
            :image-size="80"
          />
          <el-collapse v-else v-model="openGroups">
            <el-collapse-item v-for="b in filteredBinaries" :key="b.md5" :name="b.md5">
              <template #title>
                <span class="mono bin-path" :title="b.path || b.md5">{{ b.path || b.md5 }}</span>
                <el-tag size="small" type="info" effect="plain" class="bin-count">
                  {{ b.count }}/{{ b.total }}
                </el-tag>
              </template>
              <div
                v-for="f in b.functions"
                :key="f.addr"
                class="fn-row"
                :class="{ active: selMd5 === b.md5 && selAddr === f.addr, enriched: f.enriched }"
                @click="select(b.md5, f)"
              >
                <template v-if="f.enriched">
                  <div class="fn-head">
                    <span class="mono fn-name" :title="f.name">{{ f.name }}</span>
                    <el-tag size="small" type="success" class="ai-badge">AI</el-tag>
                    <el-tag size="small" :type="confType(f.confidence)" effect="plain">
                      {{ f.confidence != null ? f.confidence.toFixed(2) : '—' }}
                    </el-tag>
                  </div>
                  <div class="fn-sub">
                    <span class="mono">{{ f.addr }}</span>
                    <el-tag v-if="f.domain" size="small" effect="plain" type="info">
                      {{ f.domain }}
                    </el-tag>
                    <el-tag v-if="f.synthetic" size="small" type="warning" effect="plain">
                      synthetic
                    </el-tag>
                  </div>
                </template>
                <template v-else>
                  <div class="fn-head">
                    <span class="mono fn-name fn-plain" :title="f.name">{{ f.name }}</span>
                  </div>
                  <div class="fn-sub">
                    <span class="mono">{{ f.addr }}</span>
                  </div>
                </template>
              </div>
              <el-empty
                v-if="b.functions.length === 0"
                description="无匹配函数"
                :image-size="60"
              />
            </el-collapse-item>
          </el-collapse>
        </div>
      </el-card>

      <div class="main-area">
        <template v-if="current">
          <el-card class="info-card">
            <div class="info-head">
              <div class="info-id">
                <span class="mono info-name">{{ current.name }}</span>
                <span class="mono info-addr">{{ current.addr }}</span>
              </div>
              <div class="info-tags">
                <template v-if="current.enriched">
                  <el-tag size="small" type="success">AI 增强</el-tag>
                  <el-tag size="small" :type="confType(current.confidence)">
                    置信度 {{ current.confidence != null ? current.confidence.toFixed(2) : '—' }}
                  </el-tag>
                  <el-tag v-if="current.domain" size="small" effect="plain">
                    {{ current.domain }}
                  </el-tag>
                  <el-tag v-if="current.synthetic" size="small" type="warning" effect="plain">
                    synthetic 汇编直译
                  </el-tag>
                  <el-tag size="small" type="info" effect="plain">
                    重命名 {{ current.renames }}
                  </el-tag>
                  <el-tag size="small" type="info" effect="plain">
                    参数恢复 {{ current.call_args }}
                  </el-tag>
                </template>
                <el-tag v-else size="small" type="info" effect="plain">未 AI 增强</el-tag>
              </div>
            </div>
            <p v-if="current.enriched && current.summary" class="summary">
              {{ current.summary }}
              <span class="muted">—— AI 生成摘要，未人工抽检</span>
            </p>
          </el-card>

          <template v-if="current.enriched">
            <el-alert
              v-if="origMissing"
              type="warning"
              :closable="false"
              class="syn-alert"
              title="该函数无原始伪代码（反编译失败），右侧为 AI 从汇编直译（synthetic），仅作可读性参考。"
            />
            <div v-loading="srcLoading">
              <CodeDiff :original="origSource" :enriched="aiSource" />
            </div>
          </template>
          <template v-else>
            <el-alert
              v-if="origMissing"
              type="warning"
              :closable="false"
              class="syn-alert"
              title="该函数反编译失败，无伪代码可显示。"
            />
            <template v-else>
              <el-alert
                type="info"
                :closable="false"
                class="syn-alert"
                title="该函数未经过 AI 增强，仅显示 Hex-Rays 原始伪代码。"
              />
              <CodeViewer :code="origSource" :loading="srcLoading" />
            </template>
          </template>
        </template>
        <el-empty v-else description="从左侧目录选择一个函数；绿色标记的可查看优化前后对比" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import CodeDiff from '../components/CodeDiff.vue'
import CodeViewer from '../components/CodeViewer.vue'

const jobs = ref([])
const jobId = ref('')
const jobsLoading = ref(false)
const dirLoading = ref(false)
const binaries = ref([])
const total = ref(0)
const totalFunctions = ref(0)
const filter = ref('')
const onlyEnriched = ref(false)
const openGroups = ref([])
const selMd5 = ref('')
const selAddr = ref('')
const current = ref(null)
const origSource = ref('')
const aiSource = ref('')
const srcLoading = ref(false)
const origMissing = ref(false)

let dirCtrl = null
let srcCtrl = null

const filteredBinaries = computed(() => {
  const kw = filter.value.trim().toLowerCase()
  return binaries.value
    .map(b => ({
      ...b,
      functions: b.functions.filter(f =>
        (!onlyEnriched.value || f.enriched) &&
        (!kw || (f.name || '').toLowerCase().includes(kw) || f.addr.includes(kw)))
    }))
    .filter(b => b.functions.length > 0)
})

function confType (c) {
  if (c == null) return 'info'
  if (c >= 0.9) return 'success'
  if (c >= 0.75) return 'warning'
  return 'info'
}

async function loadJobs () {
  jobsLoading.value = true
  try {
    jobs.value = await api('/jobs')
    if (!jobId.value && jobs.value.length > 0) {
      jobId.value = jobs.value[0].job_id
      await loadDirectory()
    }
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    jobsLoading.value = false
  }
}

async function loadDirectory () {
  if (!jobId.value) return
  if (dirCtrl) dirCtrl.abort()
  const ctrl = new AbortController()
  dirCtrl = ctrl
  dirLoading.value = true
  try {
    const data = await api(`/jobs/${jobId.value}/aienrich`, { signal: ctrl.signal })
    // 轮询/刷新时保持数组引用不变再替换，避免折叠态与选中态丢失（约束 5）
    if (JSON.stringify(data.binaries || []) !== JSON.stringify(binaries.value)) {
      binaries.value = data.binaries || []
    }
    total.value = data.total || 0
    totalFunctions.value = data.total_functions || 0
    openGroups.value = (data.binaries || []).map(b => b.md5)
    if (!current.value) {
      // 默认选中第一个 AI 增强函数（有对比内容可看）
      for (const b of binaries.value) {
        const f = b.functions.find(x => x.enriched)
        if (f) { select(b.md5, f); break }
      }
    }
  } catch (e) {
    if (e.name !== 'AbortError') ElMessage.error(e.message)
  } finally {
    if (dirCtrl === ctrl) dirLoading.value = false
  }
}

function onJobChange () {
  current.value = null
  selMd5.value = ''
  selAddr.value = ''
  origSource.value = ''
  aiSource.value = ''
  binaries.value = []
  total.value = 0
  totalFunctions.value = 0
  loadDirectory()
}

async function select (md5, fn) {
  selMd5.value = md5
  selAddr.value = fn.addr
  current.value = fn
  if (srcCtrl) srcCtrl.abort()
  const ctrl = new AbortController()
  srcCtrl = ctrl
  srcLoading.value = true
  origMissing.value = false
  origSource.value = ''
  aiSource.value = ''
  try {
    const base = `/jobs/${jobId.value}/functions/${md5}/${fn.addr}/source`
    if (fn.enriched) {
      const [orig, ai] = await Promise.all([
        api(base, { signal: ctrl.signal }).catch(e => {
          if (e.status === 404) { origMissing.value = true; return '' } // 资源未就绪静默（约束）
          throw e
        }),
        api(`${base}?ai=1`, { signal: ctrl.signal }).catch(e => {
          if (e.status === 404) return ''
          throw e
        })
      ])
      origSource.value = orig
      aiSource.value = ai
    } else {
      origSource.value = await api(base, { signal: ctrl.signal }).catch(e => {
        if (e.status === 404) { origMissing.value = true; return '' }
        throw e
      })
    }
  } catch (e) {
    if (e.name !== 'AbortError') ElMessage.error(e.message)
  } finally {
    if (srcCtrl === ctrl) srcLoading.value = false
  }
}

onMounted(loadJobs)
onUnmounted(() => {
  if (dirCtrl) dirCtrl.abort()
  if (srcCtrl) srcCtrl.abort()
})
</script>

<style scoped>
.toolbar-card { margin-bottom: 12px; }
.toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.job-select { width: 420px; }
.enrich-layout { display: flex; gap: 12px; align-items: flex-start; }
.side-card { width: 350px; flex-shrink: 0; }
.side-filter { margin-bottom: 6px; }
.side-only { margin: 0 0 6px 2px; }
.side-list { max-height: calc(100vh - 240px); overflow-y: auto; }
.bin-path {
  font-size: 12.5px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.bin-count { margin-left: 8px; flex-shrink: 0; }
.fn-row {
  padding: 6px 8px;
  border-radius: 6px;
  cursor: pointer;
  border-left: 3px solid transparent;
  margin-bottom: 2px;
}
.fn-row:hover { background: #f5f7fa; }
.fn-row.active { background: rgba(64, 158, 255, 0.08); border-left-color: #409eff; }
/* AI 增强行的特殊标记：淡绿底 + 绿色 AI 徽标（active 选中态优先） */
.fn-row.enriched { background: rgba(103, 194, 58, 0.08); }
.fn-row.enriched:hover { background: rgba(103, 194, 58, 0.14); }
.fn-row.enriched.active { background: rgba(64, 158, 255, 0.10); border-left-color: #409eff; }
.fn-head { display: flex; justify-content: space-between; align-items: center; gap: 6px; }
.fn-name {
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
}
.fn-plain { color: #909399; }
.ai-badge { flex-shrink: 0; font-weight: 700; }
.fn-sub { display: flex; align-items: center; gap: 6px; margin-top: 2px; color: #909399; font-size: 12px; }
.main-area { flex: 1; min-width: 0; }
.info-card { margin-bottom: 12px; }
.info-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
.info-name { font-size: 15px; font-weight: 600; }
.info-addr { margin-left: 10px; color: #909399; font-size: 13px; }
.info-tags { display: flex; gap: 6px; flex-wrap: wrap; }
.summary { margin: 10px 0 0; color: #606266; font-size: 13px; }
.muted { color: #909399; font-size: 12px; }
.syn-alert { margin-bottom: 12px; }
@media (max-width: 720px) {
  .enrich-layout { flex-direction: column; }
  .side-card { width: 100%; }
  .side-list { max-height: 320px; }
  .job-select { width: 100%; }
}
</style>
