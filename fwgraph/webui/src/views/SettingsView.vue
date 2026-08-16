<template>
  <div>
    <!-- 系统信息 -->
    <el-card shadow="never" class="block">
      <template #header>
        <div class="row-between">
          <span>系统信息</span>
          <el-button size="small" :loading="loadingInfo" @click="loadInfo">刷新</el-button>
        </div>
      </template>
      <template v-if="info">
        <el-descriptions :column="isNarrow ? 1 : 3" border size="small">
          <el-descriptions-item label="Python">{{ info.python }}</el-descriptions-item>
          <el-descriptions-item label="平台">{{ info.platform }}</el-descriptions-item>
          <el-descriptions-item label="运行时长">{{ fmtUptime(info.uptime_seconds) }}</el-descriptions-item>
          <el-descriptions-item label="LLM 模型">{{ info.components?.llm?.model || '-' }}</el-descriptions-item>
          <el-descriptions-item label="LLM Base URL">
            <span class="mono" style="font-size:12px">{{ info.components?.llm?.base_url || '-' }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="LLM API Key">{{ info.components?.llm?.api_key || '-' }}</el-descriptions-item>
        </el-descriptions>

        <h4 class="sec-title">组件健康</h4>
        <div class="comp-list">
          <span v-for="c in compList" :key="c.name" class="comp-item">
            <span class="dot" :class="c.ok ? 'ok' : 'off'"></span>{{ c.name }}
          </span>
        </div>

        <template v-if="info.resources">
        <h4 class="sec-title">资源占用</h4>
        <div class="res-grid">
          <div class="res-item">
            <div class="res-label">磁盘 {{ diskPercent }}%（{{ fmtBytes(info.resources?.disk?.used) }} / {{ fmtBytes(info.resources?.disk?.total) }}）</div>
            <el-progress :percentage="diskPercent" :stroke-width="10" :color="resColor(diskPercent)" />
          </div>
          <div class="res-item">
            <div class="res-label">内存 {{ memPercent }}%（可用 {{ info.resources?.mem_available_mb }} MB / 共 {{ info.resources?.mem_total_mb }} MB）</div>
            <el-progress :percentage="memPercent" :stroke-width="10" :color="resColor(memPercent)" />
          </div>
          <div class="res-item">
            <div class="res-label">负载（1 / 5 / 15 分钟）</div>
            <div class="mono loadavg">{{ (info.resources?.loadavg || []).map(n => n.toFixed(2)).join('  ·  ') }}</div>
          </div>
        </div>
        </template>
      </template>
      <el-empty v-else description="系统信息不可用" :image-size="70" />
    </el-card>

    <!-- 系统配置 -->
    <el-card shadow="never" class="block">
      <template #header>
        <div class="row-between">
          <span>系统配置</span>
          <el-tag v-if="!isAdmin" size="small" type="info" effect="plain">只读（需要管理员权限）</el-tag>
        </div>
      </template>
      <el-form label-width="210px" label-position="left" :disabled="!isAdmin">
        <h4 class="sec-title">自动化流水线</h4>
        <el-form-item v-for="k in AUTO_KEYS" :key="k.key" :label="k.label">
          <el-switch v-model="autoFlags[k.key]" inline-prompt active-text="开" inactive-text="关" />
        </el-form-item>

        <h4 class="sec-title">引擎与模型</h4>
        <el-form-item label="漏洞挖掘引擎（VULNAGENT_ENGINE）">
          <el-select v-model="form.VULNAGENT_ENGINE" placeholder="默认" style="width: 260px">
            <el-option label="默认" value="" />
            <el-option label="dsh" value="dsh" />
            <el-option label="builtin" value="builtin" />
          </el-select>
        </el-form-item>
        <el-form-item label="LLM 模型（LLM_MODEL）">
          <el-input v-model="form.LLM_MODEL" style="width: 320px" />
        </el-form-item>
        <el-form-item label="LLM Base URL（LLM_BASE_URL）">
          <el-input v-model="form.LLM_BASE_URL" style="width: 320px" />
        </el-form-item>
        <el-form-item label="单任务 LLM 函数上限">
          <el-input-number v-model="form.AI_MAX_FUNCS_PER_JOB" :min="1" :max="100000" />
        </el-form-item>
        <el-form-item label="IDA 并发数（IDA_WORKERS）">
          <el-input-number v-model="form.IDA_WORKERS" :min="1" :max="64" />
        </el-form-item>
        <el-form-item label="EMBA 超时秒数（EMBA_TIMEOUT）">
          <el-input-number v-model="form.EMBA_TIMEOUT" :min="60" :max="86400" :step="60" />
        </el-form-item>

        <el-form-item v-if="isAdmin">
          <el-button type="primary" :loading="saving" @click="save">保存配置</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { useNarrowViewport } from '../useNarrowViewport'

const props = defineProps({ isAdmin: { type: Boolean, default: false } })

const info = ref(null)
const loadingInfo = ref(false)
const saving = ref(false)
const isNarrow = useNarrowViewport()

const AUTO_KEYS = [
  { key: 'AUTO_INPUTS', label: '自动识别外部输入（AUTO_INPUTS）' },
  { key: 'AUTO_DECOMPILE', label: '自动反编译（AUTO_DECOMPILE）' },
  { key: 'AUTO_ATTACK', label: '自动攻击面分析（AUTO_ATTACK）' },
  { key: 'AUTO_ROUTES', label: '自动路由识别（AUTO_ROUTES）' },
  { key: 'AUTO_SURFACES', label: '自动攻击面导出（AUTO_SURFACES）' },
  { key: 'AUTO_GRAPHEXT', label: '自动图谱扩展（AUTO_GRAPHEXT）' },
  { key: 'AUTO_FULL', label: '全自动分析链（AUTO_FULL）' }
]
const autoFlags = reactive({})
const form = reactive({
  VULNAGENT_ENGINE: '',
  LLM_MODEL: '',
  LLM_BASE_URL: '',
  AI_MAX_FUNCS_PER_JOB: 300,
  IDA_WORKERS: 3,
  EMBA_TIMEOUT: 7200
})

const compList = computed(() => {
  const c = info.value?.components
  if (!c) return []
  const list = ['ida', 'emba', 'cbm', 'frida', 'dsh'].map(name => ({
    name: name.toUpperCase(), ok: !!c[name]
  }))
  for (const [arch, ok] of Object.entries(c.afl_qemu || {})) {
    list.push({ name: `AFL ${arch}`, ok: !!ok })
  }
  return list
})

const diskPercent = computed(() => {
  const d = info.value?.resources?.disk
  if (!d || !d.total) return 0
  return Math.round((d.used / d.total) * 100)
})
const memPercent = computed(() => {
  const r = info.value?.resources
  if (!r || !r.mem_total_mb) return 0
  return Math.round(((r.mem_total_mb - r.mem_available_mb) / r.mem_total_mb) * 100)
})

function resColor (p) {
  if (p >= 90) return '#dc2626'
  if (p >= 70) return '#b45309'
  return '#2b6ce5'
}

function fmtUptime (s) {
  if (s == null) return '-'
  s = Math.floor(s)
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d) return `${d} 天 ${h} 小时`
  if (h) return `${h} 小时 ${m} 分`
  return `${m} 分 ${s % 60} 秒`
}

function fmtBytes (n) {
  if (n == null) return '-'
  if (n > 1073741824) return (n / 1073741824).toFixed(1) + ' GB'
  if (n > 1048576) return (n / 1048576).toFixed(1) + ' MB'
  return n + ' B'
}

async function loadInfo () {
  loadingInfo.value = true
  try {
    info.value = await api('/system/info')
  } catch (e) {
    ElMessage.error('系统信息加载失败: ' + e.message)
  } finally {
    loadingInfo.value = false
  }
}

async function loadConfig () {
  try {
    const cfg = await api('/system/config')
    for (const { key } of AUTO_KEYS) autoFlags[key] = cfg[key] === '1'
    form.VULNAGENT_ENGINE = cfg.VULNAGENT_ENGINE || ''
    form.LLM_MODEL = cfg.LLM_MODEL || ''
    form.LLM_BASE_URL = cfg.LLM_BASE_URL || ''
    form.AI_MAX_FUNCS_PER_JOB = parseInt(cfg.AI_MAX_FUNCS_PER_JOB, 10) || 300
    form.IDA_WORKERS = parseInt(cfg.IDA_WORKERS, 10) || 3
    form.EMBA_TIMEOUT = parseInt(cfg.EMBA_TIMEOUT, 10) || 7200
  } catch (e) {
    ElMessage.error('配置加载失败: ' + e.message)
  }
}

async function save () {
  saving.value = true
  const body = {
    VULNAGENT_ENGINE: form.VULNAGENT_ENGINE,
    LLM_MODEL: form.LLM_MODEL,
    LLM_BASE_URL: form.LLM_BASE_URL,
    AI_MAX_FUNCS_PER_JOB: String(form.AI_MAX_FUNCS_PER_JOB),
    IDA_WORKERS: String(form.IDA_WORKERS),
    EMBA_TIMEOUT: String(form.EMBA_TIMEOUT)
  }
  for (const { key } of AUTO_KEYS) body[key] = autoFlags[key] ? '1' : '0'
  try {
    await api('/system/config', { method: 'PUT', body })
    ElMessage.success('配置已保存')
  } catch (e) {
    ElMessage.error('保存失败: ' + e.message)
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  loadInfo()
  loadConfig()
})
</script>

<style scoped>
.block { margin-bottom: 14px; }
.row-between { display: flex; justify-content: space-between; align-items: center; }
.sec-title { margin: 18px 0 10px; letter-spacing: 1px; color: #2b6ce5; font-size: 14px; }
.comp-list { display: flex; flex-wrap: wrap; gap: 14px; }
.comp-item { display: inline-flex; align-items: center; gap: 7px; font-size: 13px; letter-spacing: 1px; }
.dot { width: 9px; height: 9px; border-radius: 50%; }
.dot.ok { background: #16a34a; box-shadow: 0 0 8px rgba(22, 163, 74, .8); }
.dot.off { background: #9aa9bd; }
.res-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }
.res-label { font-size: 13px; color: #3d5470; margin-bottom: 6px; }
.loadavg { font-size: 16px; color: #2b6ce5; padding-top: 4px; }
</style>
