<template>
  <div>
    <!-- 统计卡片 -->
    <div class="stat-grid">
      <el-card v-for="c in statCards" :key="c.label" shadow="never" class="stat-card">
        <div class="stat-num">{{ c.value }}</div>
        <div class="stat-label">
          <el-icon><component :is="c.icon" /></el-icon>{{ c.label }}
        </div>
      </el-card>
    </div>

    <div class="dash-cols">
      <!-- 运行中任务 -->
      <el-card shadow="never" class="block">
        <template #header>
          <div class="row-between">
            <span>运行中任务</span>
            <el-button size="small" :loading="loading" @click="loadDashboard">刷新</el-button>
          </div>
        </template>
        <el-table :data="dash?.running || []" size="small">
          <el-table-column prop="job_id" label="job_id" width="130">
            <template #default="{ row }"><span class="mono">{{ row.job_id }}</span></template>
          </el-table-column>
          <el-table-column prop="firmware" label="固件" min-width="150" show-overflow-tooltip />
          <el-table-column label="状态" width="110">
            <template #default="{ row }">
              <el-tag size="small" type="warning">{{ row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="更新时间" width="165">
            <template #default="{ row }">{{ fmtTime(row.updated_at) }}</template>
          </el-table-column>
          <template #empty><el-empty description="当前没有运行中的任务" :image-size="60" /></template>
        </el-table>
      </el-card>

      <!-- 组件健康 -->
      <el-card shadow="never" class="block">
        <template #header>组件健康</template>
        <div v-if="info" class="comp-list">
          <div v-for="c in compList" :key="c.name" class="comp-item">
            <span class="dot" :class="c.ok ? 'ok' : 'off'"></span>
            <span class="comp-name">{{ c.name }}</span>
            <span v-if="c.note" class="muted">{{ c.note }}</span>
          </div>
        </div>
        <el-empty v-else description="系统信息不可用" :image-size="60" />
      </el-card>
    </div>

    <!-- 快捷操作 -->
    <el-card shadow="never" class="block">
      <template #header>快捷操作</template>
      <div class="quick-actions">
        <el-button type="primary" @click="$emit('goto', 'jobs')">
          <el-icon style="margin-right:6px"><Upload /></el-icon>上传固件
        </el-button>
        <el-button @click="$emit('goto', 'vuln')">
          <el-icon style="margin-right:6px"><Warning /></el-icon>新建挖掘会话
        </el-button>
        <el-button @click="$emit('goto', 'reports')">
          <el-icon style="margin-right:6px"><Notebook /></el-icon>查看报告
        </el-button>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

defineEmits(['goto'])

const dash = ref(null)
const info = ref(null)
const loading = ref(false)
let timer = null

const statCards = computed(() => {
  const d = dash.value || {}
  return [
    { label: '任务总数', value: d.jobs_total ?? '-', icon: 'Files' },
    { label: '运行中', value: (d.running || []).length, icon: 'Loading' },
    { label: '外部输入', value: d.inputs_total ?? '-', icon: 'Download' },
    { label: '攻击面', value: d.surfaces_total ?? '-', icon: 'Aim' },
    { label: 'AI 发现', value: d.findings_total ?? '-', icon: 'MagicStick' },
    { label: '挖掘会话', value: d.sessions_total ?? '-', icon: 'Warning' },
    { label: '报告数', value: d.reports_total ?? '-', icon: 'Notebook' }
  ]
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
  if (c.llm) {
    list.push({ name: 'LLM', ok: !!c.llm.api_key, note: c.llm.model || '' })
  }
  return list
})

function fmtTime (iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return isNaN(d) ? iso : d.toLocaleString()
}

async function loadDashboard () {
  loading.value = true
  try {
    dash.value = await api('/dashboard')
  } catch (e) {
    ElMessage.error('仪表盘加载失败: ' + e.message)
  } finally {
    loading.value = false
  }
}

async function loadInfo () {
  try {
    info.value = await api('/system/info')
  } catch { /* 组件健康区块显示空态 */ }
}

onMounted(() => {
  loadDashboard()
  loadInfo()
  timer = setInterval(loadDashboard, 4000)
})
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 14px;
}
.stat-card { text-align: center; }
.stat-num {
  font-size: 30px;
  font-weight: 700;
  color: #2b6ce5;  font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace;
}
.stat-label {
  margin-top: 4px;
  color: #64748f;
  font-size: 13px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 5px;
}
.dash-cols {
  display: grid;
  grid-template-columns: minmax(0, 3fr) minmax(0, 2fr);
  gap: 14px;
}
@media (max-width: 1100px) { .dash-cols { grid-template-columns: 1fr; } }
.block { margin-bottom: 14px; }
.row-between { display: flex; justify-content: space-between; align-items: center; }
.comp-list { display: flex; flex-direction: column; gap: 10px; }
.comp-item { display: flex; align-items: center; gap: 10px; }
.comp-name { letter-spacing: 1px; }
.dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  flex: none;
}
.dot.ok { background: #16a34a; box-shadow: 0 0 8px rgba(22, 163, 74, .8); }
.dot.off { background: #9aa9bd; box-shadow: none; }
.quick-actions { display: flex; gap: 12px; flex-wrap: wrap; }
</style>
