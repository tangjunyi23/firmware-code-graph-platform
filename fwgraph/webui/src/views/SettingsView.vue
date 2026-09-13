<template>
  <div class="settings">
    <header class="ins-head">
      <div class="ins-head-row">
        <h1 class="ins-title">
          <span class="ins-ico"><component :is="NAV_ICONS.Setting" :size="18" /></span>系统设置
        </h1>
        <div class="ins-actions">
          <button type="button" class="ghost-btn" :disabled="loadingInfo" @click="loadInfo">
            <component :is="NAV_ICONS.Guide" :size="14" :class="{ spin: loadingInfo }" />
            <span>刷新状态</span>
          </button>
        </div>
      </div>
      <p class="ins-sub">系统信息与平台运行参数。</p>
    </header>

    <!-- ===== 运行状态一览 ===== -->
    <section class="set-tiles">
      <div class="panel set-tile">
        <span class="tile-ico"><component :is="NAV_ICONS.Cpu" :size="16" /></span>
        <b class="tile-val mono">{{ info?.python || '—' }}</b>
        <span class="tile-label">Python 版本</span>
      </div>
      <div class="panel set-tile">
        <span class="tile-ico"><component :is="NAV_ICONS.Odometer" :size="16" /></span>
        <b class="tile-val mono">{{ info?.platform || '—' }}</b>
        <span class="tile-label">运行平台</span>
      </div>
      <div class="panel set-tile">
        <span class="tile-ico on"><component :is="NAV_ICONS.Star" :size="16" /></span>
        <b class="tile-val mono">{{ fmtUptime(info?.uptime_seconds) }}</b>
        <span class="tile-label">持续运行</span>
      </div>
      <div class="panel set-tile wide">
        <span class="tile-ico" :class="llmOk ? 'on' : 'off'"><component :is="NAV_ICONS.Key" :size="16" /></span>
        <div class="tile-copy">
          <b class="tile-val">{{ llmOk ? '已配置' : '未配置' }}</b>
          <span class="tile-sub mono">{{ info?.components?.llm?.base_url || 'LLM Base URL 未设置' }}</span>
          <span v-if="llmOk" class="tile-sub mono">Key {{ maskKey(info?.components?.llm?.api_key) }}</span>
        </div>
        <span class="tile-label">大模型接口</span>
      </div>
    </section>

    <div class="set-grid">
      <!-- ===== 左列：系统状态 ===== -->
      <section class="panel set-card">
        <header class="set-card-head">
          <h2>系统状态</h2>
          <span class="head-sub">{{ healthyCount }} / {{ compList.length }} 组件在线</span>
        </header>

        <template v-if="info">
          <h3 class="sec-title">组件健康</h3>
          <div class="comp-grid">
            <div v-for="c in compList" :key="c.key" class="comp-item" :class="{ off: !c.ok }">
              <span class="dot" :class="c.ok ? 'ok' : 'off'" />
              <span class="comp-copy">
                <b>{{ c.label }}</b>
                <small>{{ c.ok ? c.hint : '离线' }}</small>
              </span>
              <em>{{ c.ok ? '在线' : '离线' }}</em>
            </div>
          </div>

          <template v-if="info.resources">
            <h3 class="sec-title">资源占用</h3>
            <div class="res-item">
              <div class="res-top">
                <span>磁盘</span>
                <b class="mono">{{ diskPercent }}%</b>
              </div>
              <el-progress :percentage="diskPercent" :stroke-width="8" :show-text="false" :color="resColor(diskPercent)" />
              <small class="res-note mono">{{ fmtBytes(info.resources?.disk?.used) }} / {{ fmtBytes(info.resources?.disk?.total) }}</small>
            </div>
            <div class="res-item">
              <div class="res-top">
                <span>内存</span>
                <b class="mono">{{ memPercent }}%</b>
              </div>
              <el-progress :percentage="memPercent" :stroke-width="8" :show-text="false" :color="resColor(memPercent)" />
              <small class="res-note mono">可用 {{ info.resources?.mem_available_mb }} MB / 共 {{ info.resources?.mem_total_mb }} MB</small>
            </div>
            <div class="load-row">
              <span class="load-label">系统负载</span>
              <div class="load-chips">
                <span v-for="(lv, i) in loadavg" :key="i" class="load-chip mono">
                  <small>{{ [1, 5, 15][i] }}m</small>{{ lv }}
                </span>
              </div>
            </div>
          </template>
        </template>
        <el-empty v-else description="系统信息不可用" :image-size="70" />
      </section>

      <!-- ===== 右列：系统配置 ===== -->
      <section class="panel set-card">
        <header class="set-card-head">
          <h2>系统配置</h2>
          <span v-if="!isAdmin" class="readonly-tag"><component :is="NAV_ICONS.Lock" :size="12" />只读 · 需要管理员权限</span>
          <span v-else-if="isDirty" class="dirty-tag"><i />有未保存的更改</span>
          <span v-else class="head-sub clean">已同步</span>
        </header>

        <div class="readonly-banner" v-if="!isAdmin">
          以下配置当前为只读视图，如需调整请联系管理员。
        </div>

        <el-form label-position="top" :disabled="!isAdmin" class="cfg-form">
          <h3 class="sec-title">界面</h3>
          <div class="opt-row">
            <div class="opt-copy">
              <b>登录后自动弹出新手教程</b>
              <small>关闭后登录不再自动走教程；头像菜单里的「新手教程」仍可手动打开。</small>
            </div>
            <el-switch v-model="uiOnboardTour" inline-prompt active-text="开" inactive-text="关" />
          </div>

          <h3 class="sec-title">自动化流水线</h3>
          <div class="opt-list">
            <div v-for="row in autoRows" :key="row.key" class="opt-row">
              <div class="opt-copy">
                <b>{{ row.title }}<code class="env">{{ row.key }}</code></b>
                <small>{{ row.desc }}</small>
              </div>
              <el-switch
                v-model="autoFlags[row.key]"
                inline-prompt active-text="开" inactive-text="关"
                :disabled="!isAdmin || (row.key === 'AUTO_FULL' && !autoFlags.AUTO_FULL && fullConfirming)"
                @change="onAutoChange(row.key, $event)"
              />
            </div>
          </div>

          <h3 class="sec-title">引擎与模型</h3>
          <div class="field-grid">
            <el-form-item label="LLM 模型" class="field">
              <el-input v-model="form.LLM_MODEL" class="mono-val" />
            </el-form-item>
            <el-form-item label="LLM Base URL" class="field">
              <el-input v-model="form.LLM_BASE_URL" class="mono-val" />
            </el-form-item>
          </div>
          <div class="stepper-grid">
            <el-form-item v-for="s in steppers" :key="s.key" :label="s.title" class="stepper">
              <el-input-number v-model="form[s.key]" :min="s.min" :max="s.max" :step="s.step || 1" />
              <small class="step-note">{{ s.desc }}</small>
            </el-form-item>
          </div>
        </el-form>

        <footer v-if="isAdmin" class="save-bar">
          <span class="save-hint" :class="{ show: isDirty }">配置尚未保存，离开前记得点「保存配置」</span>
          <div class="save-actions">
            <button type="button" class="ghost-btn" :disabled="!isDirty || saving" @click="resetForm">放弃更改</button>
            <el-button type="primary" :loading="saving" :disabled="!isDirty" @click="save">保存配置</el-button>
          </div>
        </footer>
      </section>
    </div>
  </div>
</template>

<script setup>
import { NAV_ICONS } from '../workbench/icons.js'
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { applyOnboardConfig, parseOnboardAuto, UI_ONBOARD_TOUR } from '../onboardPref'
import { componentHealth } from '../componentHealth'

const props = defineProps({ isAdmin: { type: Boolean, default: false } })

const info = ref(null)
const loadingInfo = ref(false)
const saving = ref(false)

// 自动化开关：中文标题 + 环境变量名 + 说明（说明文案对齐 .env 注释口径）
const autoRows = [
  { key: 'AUTO_INPUTS', title: '自动识别外部输入', desc: '解包后自动扫描 rootfs，识别公网可达的外部输入' },
  { key: 'AUTO_DECOMPILE', title: '自动反编译', desc: '解包后自动触发 IDA 无头反编译导出' },
  { key: 'AUTO_ATTACK', title: '自动攻击面分析', desc: '图谱就绪后自动跑 source/sink 攻击路径分析' },
  { key: 'AUTO_ROUTES', title: '自动路由识别', desc: '自动恢复 (字符串, handler) 静态路由表' },
  { key: 'AUTO_SURFACES', title: '自动攻击面导出', desc: '每个外部输入导出独立攻击面文件（AS-xxx）' },
  { key: 'AUTO_GRAPHEXT', title: '自动图谱扩展', desc: '图谱构建时同步导出 CFG / AST 扩展结构' },
  { key: 'AUTO_ATTACK_AI', title: '攻击路径 AI 分诊', desc: 'LLM 对 Top-N 攻击路径做优先级分诊' },
  { key: 'AUTO_FULL', title: '全自动分析链', desc: '上传固件即跑完整链：解包→反编译→图谱→攻击面，占用大量资源' }
]
const autoFlags = reactive({})
const uiOnboardTour = ref(true)
const form = reactive({
  VULNAGENT_ENGINE: '',
  LLM_MODEL: '',
  LLM_BASE_URL: '',
  IDA_WORKERS: 3,
  EMBA_TIMEOUT: 7200,
  TRACE_DAILY_PER_JOB: 96,
  EXEC_DAILY_PER_JOB: 48,
  FUZZ_DAILY_PER_JOB: 12
})
const steppers = [
  { key: 'IDA_WORKERS', title: 'IDA 并发数', min: 1, max: 64, desc: '同时运行的 IDA 无头实例数' },
  { key: 'EMBA_TIMEOUT', title: 'EMBA 超时（秒）', min: 60, max: 86400, step: 60, desc: '单次解包最长等待时间' },
  { key: 'TRACE_DAILY_PER_JOB', title: '每日 trace 配额', min: 8, max: 512, desc: '每任务每日差分覆盖次数' },
  { key: 'EXEC_DAILY_PER_JOB', title: '每日 exec 配额', min: 4, max: 256, desc: '每任务每日 PoC 执行次数' },
  { key: 'FUZZ_DAILY_PER_JOB', title: '每日 fuzz 配额', min: 2, max: 64, desc: '每任务每日模糊测试次数' }
]

const compList = computed(() => componentHealth(info.value?.components))
const healthyCount = computed(() => compList.value.filter((c) => c.ok).length)
const llmOk = computed(() => !!(info.value?.components?.llm?.api_key))
const loadavg = computed(() =>
  (info.value?.resources?.loadavg || []).map((n) => Number(n).toFixed(2)))

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

// ---- 脏检查：和最近一次保存的快照对比，驱动保存按钮/提示 ----
const savedSnapshot = ref('')
function snapshot () {
  const auto = {}
  for (const { key } of autoRows) auto[key] = !!autoFlags[key]
  return JSON.stringify({ auto, form: { ...form }, onboard: uiOnboardTour.value })
}
// 注意先读 ref 再短路：保证 loadConfig 写入快照后能触发一次重算，
// 进而跟踪 autoFlags/form/uiOnboardTour 的后续变化
const isDirty = computed(() => {
  if (!savedSnapshot.value) return false
  return snapshot() !== savedSnapshot.value
})
function resetForm () {
  if (!savedSnapshot.value) return
  const snap = JSON.parse(savedSnapshot.value)
  for (const { key } of autoRows) autoFlags[key] = snap.auto[key]
  Object.assign(form, snap.form)
  uiOnboardTour.value = snap.onboard
}

function resColor (p) {
  if (p >= 90) return '#dc2626'
  if (p >= 70) return '#b45309'
  return 'var(--fw-brand)'
}

function fmtUptime (s) {
  if (s == null) return '—'
  s = Math.floor(s)
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d) return `${d} 天 ${h} 小时`
  if (h) return `${h} 小时 ${m} 分`
  return `${m} 分 ${s % 60} 秒`
}

function fmtBytes (n) {
  if (n == null) return '—'
  if (n > 1073741824) return (n / 1073741824).toFixed(1) + ' GB'
  if (n > 1048576) return (n / 1048576).toFixed(1) + ' MB'
  return n + ' B'
}

// 密钥只露头尾，避免肩窥/截屏泄露
function maskKey (key) {
  const k = String(key || '').trim()
  if (!k || k === '-') return '—'
  if (k.length <= 8) return k.slice(0, 2) + '****'
  return `${k.slice(0, 4)}****${k.slice(-4)}`
}

// 危险开关（全自动链）开启前二次确认
const fullConfirming = ref(false)
async function onAutoChange (key, value) {
  if (key !== 'AUTO_FULL' || !value) return
  fullConfirming.value = true
  try {
    await ElMessageBox.confirm(
      '全自动链开启后，每次上传固件都会自动跑完解包、反编译、图谱与攻击面，占用大量计算资源。确定开启？',
      '开启全自动分析链',
      { type: 'warning', confirmButtonText: '确定开启', cancelButtonText: '暂不开启' }
    )
  } catch {
    autoFlags.AUTO_FULL = false
  } finally {
    fullConfirming.value = false
  }
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
    for (const { key } of autoRows) autoFlags[key] = cfg[key] === '1'
    form.VULNAGENT_ENGINE = cfg.VULNAGENT_ENGINE || ''
    form.LLM_MODEL = cfg.LLM_MODEL || ''
    form.LLM_BASE_URL = cfg.LLM_BASE_URL || ''
    form.IDA_WORKERS = parseInt(cfg.IDA_WORKERS, 10) || 3
    form.EMBA_TIMEOUT = parseInt(cfg.EMBA_TIMEOUT, 10) || 7200
    form.TRACE_DAILY_PER_JOB = parseInt(cfg.TRACE_DAILY_PER_JOB, 10) || 96
    form.EXEC_DAILY_PER_JOB = parseInt(cfg.EXEC_DAILY_PER_JOB, 10) || 48
    form.FUZZ_DAILY_PER_JOB = parseInt(cfg.FUZZ_DAILY_PER_JOB, 10) || 12
    uiOnboardTour.value = parseOnboardAuto(cfg[UI_ONBOARD_TOUR])
    savedSnapshot.value = snapshot()
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
    IDA_WORKERS: String(form.IDA_WORKERS),
    EMBA_TIMEOUT: String(form.EMBA_TIMEOUT),
    TRACE_DAILY_PER_JOB: String(form.TRACE_DAILY_PER_JOB),
    EXEC_DAILY_PER_JOB: String(form.EXEC_DAILY_PER_JOB),
    FUZZ_DAILY_PER_JOB: String(form.FUZZ_DAILY_PER_JOB),
    [UI_ONBOARD_TOUR]: uiOnboardTour.value ? '1' : '0'
  }
  for (const { key } of autoRows) body[key] = autoFlags[key] ? '1' : '0'
  try {
    const saved = await api('/system/config', { method: 'PUT', body })
    applyOnboardConfig(saved)
    savedSnapshot.value = snapshot()
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
.settings { padding: 20px 26px 40px; }

/* ---- 顶部信息瓷片 ---- */
.set-tiles {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr)) minmax(0, 1.6fr);
  gap: 12px;
  margin-bottom: 14px;
}
.set-tile {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 14px 16px 12px;
  border: 1px solid var(--fw-line);
  border-radius: 14px;
  box-shadow: var(--fw-shadow);
}
.set-tile.wide { flex-direction: row; align-items: center; gap: 12px; }
.set-tile.wide .tile-copy { display: flex; flex-direction: column; gap: 2px; min-width: 0; flex: 1; }
.set-tile.wide .tile-label {
  flex: none;
  align-self: flex-start;
  margin-left: auto;
  writing-mode: vertical-rl;
  letter-spacing: .18em;
  font-size: 10px;
  color: var(--fw-text-3);
}
.tile-ico {
  display: grid;
  place-items: center;
  width: 30px;
  height: 30px;
  margin-bottom: 6px;
  border-radius: 10px;
  background: var(--fw-fill);
  color: var(--fw-brand);
  flex: none;
}
.set-tile.wide .tile-ico { margin-bottom: 0; }
.tile-ico.on { background: rgba(62, 207, 142, .12); color: var(--fw-ok); }
.tile-ico.off { background: var(--fw-bg-2); color: var(--fw-text-3); }
.tile-val {
  font-size: 15px;
  font-weight: 700;
  letter-spacing: -0.01em;
  color: var(--fw-text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-variant-numeric: tabular-nums;
}
.tile-sub {
  font-size: 11px;
  color: var(--fw-text-3);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.tile-label { font-size: 11.5px; color: var(--fw-text-3); }

/* ---- 双列骨架 ---- */
.set-grid {
  display: grid;
  grid-template-columns: minmax(0, 5fr) minmax(0, 7fr);
  gap: 14px;
  align-items: start;
}
.set-card {
  display: flex;
  flex-direction: column;
  padding: 16px 18px 14px;
  border: 1px solid var(--fw-line);
  border-radius: 14px;
  box-shadow: var(--fw-shadow);
}
.set-card-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding-bottom: 12px;
  margin-bottom: 4px;
  border-bottom: 1px solid var(--fw-line);
}
.set-card-head h2 {
  margin: 0;
  font-size: 15px;
  font-weight: 650;
  letter-spacing: -0.01em;
  color: var(--fw-text);
}
.head-sub { font-size: 12px; color: var(--fw-text-3); }
.head-sub.clean { color: var(--fw-ok); }
.readonly-tag {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 11.5px;
  color: var(--fw-warn);
  background: rgba(229, 165, 75, .1);
  border: 1px solid rgba(229, 165, 75, .28);
  border-radius: 999px;
  padding: 2px 10px;
}
.dirty-tag {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11.5px;
  color: var(--fw-brand);
  background: var(--fw-fill);
  border-radius: 999px;
  padding: 2px 10px;
}
.dirty-tag i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--fw-brand);
  animation: dirty-pulse 1.6s ease-in-out infinite;
}
@keyframes dirty-pulse {
  0%, 100% { opacity: .35; }
  50% { opacity: 1; }
}

.sec-title {
  margin: 16px 0 8px;
  font-size: 12px;
  font-weight: 650;
  letter-spacing: .1em;
  color: var(--fw-text-3);
  display: flex;
  align-items: center;
  gap: 8px;
}
.sec-title::after {
  content: '';
  flex: 1;
  height: 1px;
  background: linear-gradient(90deg, var(--fw-line), transparent);
}

/* ---- 组件健康 ---- */
.comp-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
  gap: 8px;
}
.comp-item {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 8px 10px;
  border: 1px solid var(--fw-line);
  border-radius: 10px;
  background: var(--fw-surface-2);
}
.comp-item .comp-copy { display: flex; flex-direction: column; min-width: 0; flex: 1; }
.comp-item b { font-size: 12.5px; font-weight: 600; color: var(--fw-text); }
.comp-item small {
  font-size: 10.5px;
  color: var(--fw-text-3);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.comp-item em {
  font-style: normal;
  font-size: 10.5px;
  font-weight: 650;
  color: var(--fw-ok);
  flex: none;
}
.comp-item.off { opacity: .72; }
.comp-item.off em { color: var(--fw-text-3); }
.dot { width: 8px; height: 8px; border-radius: 50%; flex: none; }
.dot.ok { background: var(--fw-ok); box-shadow: 0 0 8px rgba(62, 207, 142, .8); animation: ok-breathe 2.4s ease-in-out infinite; }
.dot.off { background: var(--fw-text-3); }
@keyframes ok-breathe {
  0%, 100% { box-shadow: 0 0 4px rgba(62, 207, 142, .5); }
  50% { box-shadow: 0 0 10px rgba(62, 207, 142, .9); }
}

/* ---- 资源占用 ---- */
.res-item { margin-bottom: 14px; }
.res-top {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  margin-bottom: 6px;
  font-size: 13px;
  color: var(--fw-text-2);
}
.res-top b { font-size: 14px; color: var(--fw-text); font-variant-numeric: tabular-nums; }
.res-note { display: block; margin-top: 5px; font-size: 11px; color: var(--fw-text-3); }
.load-row {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  padding-top: 4px;
}
.load-label { font-size: 13px; color: var(--fw-text-2); }
.load-chips { display: flex; gap: 8px; flex: 1; min-width: 180px; }
.load-chip {
  flex: 1;
  display: flex;
  align-items: baseline;
  gap: 6px;
  padding: 7px 12px;
  border: 1px solid var(--fw-line);
  border-radius: 10px;
  background: var(--fw-surface-2);
  color: var(--fw-text);
  font-size: 14.5px;
  font-variant-numeric: tabular-nums;
}
.load-chip small { font-size: 10.5px; color: var(--fw-text-3); }

/* ---- 配置区 ---- */
.readonly-banner {
  margin: 12px 0 2px;
  padding: 9px 12px;
  border-radius: 10px;
  border: 1px solid rgba(229, 165, 75, .3);
  background: rgba(229, 165, 75, .08);
  color: var(--fw-warn);
  font-size: 12.5px;
}
.opt-list { border: 1px solid var(--fw-line); border-radius: 12px; overflow: hidden; }
.opt-row {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 11px 14px;
  transition: background-color .14s ease;
}
.opt-row + .opt-row { border-top: 1px dashed var(--fw-line); }
.opt-row:hover { background: var(--fw-surface-2); }
/* 界面小节只有一行：与列表同款外观 */
.sec-title + .opt-row {
  border: 1px solid var(--fw-line);
  border-radius: 12px;
  margin-bottom: 2px;
}
.opt-copy { display: flex; flex-direction: column; gap: 3px; min-width: 0; flex: 1; }
.opt-copy b {
  font-size: 13.5px;
  font-weight: 600;
  color: var(--fw-text);
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.opt-copy small { font-size: 11.5px; line-height: 1.5; color: var(--fw-text-3); }
code.env {
  font-family: var(--fw-font-mono);
  font-size: 10.5px;
  font-weight: 550;
  color: var(--fw-text-3);
  background: var(--fw-bg-2);
  border: 1px solid var(--fw-line);
  border-radius: 5px;
  padding: 0 6px;
  line-height: 17px;
}
.cfg-form :deep(.el-form-item__label) {
  font-size: 12.5px;
  color: var(--fw-text-2);
  font-weight: 600;
  padding-bottom: 4px;
}
.field-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 16px;
}
.stepper-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(215px, 1fr));
  gap: 2px 16px;
}
.stepper :deep(.el-input-number) { width: 100%; }
.step-note { display: block; margin-top: 3px; font-size: 11px; color: var(--fw-text-3); }

/* ---- 保存栏 ---- */
.save-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 16px;
  padding-top: 14px;
  border-top: 1px solid var(--fw-line);
}
.save-hint {
  flex: 1;
  font-size: 12px;
  color: var(--fw-warn);
  opacity: 0;
  transition: opacity .2s ease;
}
.save-hint.show { opacity: 1; }
.save-actions { display: flex; gap: 10px; align-items: center; }

/* ---- 幽灵按钮（与仪表盘 ghost 同款） ---- */
.ghost-btn {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  height: 32px;
  padding: 0 12px;
  border-radius: 10px;
  border: 1px solid var(--fw-line);
  background: var(--fw-surface);
  color: var(--fw-text-2);
  font-size: 12.5px;
  font-weight: 550;
  font-family: inherit;
  cursor: pointer;
  transition: border-color .15s ease, color .15s ease;
}
.ghost-btn:hover:not(:disabled) { border-color: rgba(91, 140, 255, .45); color: var(--fw-brand); }
.ghost-btn:disabled { opacity: .5; cursor: not-allowed; }
.ghost-btn .spin { animation: spin 1s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

@media (max-width: 1280px) {
  .set-grid { grid-template-columns: 1fr; }
  .set-tiles { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .set-tile.wide { grid-column: 1 / -1; }
}
@media (max-width: 720px) {
  .settings { padding: 14px 12px 30px; }
  .set-tiles { grid-template-columns: 1fr; }
  .set-tile.wide { grid-column: auto; flex-direction: column; align-items: flex-start; }
  .set-tile.wide .tile-label { writing-mode: horizontal-tb; margin-left: 0; }
  .field-grid { grid-template-columns: 1fr; }
  .save-bar { flex-direction: column; align-items: stretch; }
  .save-actions { justify-content: flex-end; }
}
</style>
