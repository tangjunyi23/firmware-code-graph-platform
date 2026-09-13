<template>
  <div class="dec">
    <header class="hero">
      <div>
        <p class="kicker">固件解密</p>
        <h1>上传即解密 · 进度实时可见</h1>
        <p>在「分析任务」或「快速挖掘」上传固件后会自动开始。这里只剥离已知厂商容器和压缩包装，不会去猜未知密钥。</p>
      </div>
      <div class="hero-side">
        <span class="live"><i />{{ current && current.status === 'running' ? '解密进行中' : '自动监视' }}</span>
        <button type="button" class="ghost" :disabled="loading" @click="load">刷新</button>
      </div>
    </header>

    <section class="kpis">
      <button v-for="card in kpiCards" :key="card.id" type="button" class="kpi" @click="filter = card.id">
        <span class="kpi-label">{{ card.label }}</span>
        <strong><CountUp :value="card.value" /></strong>
        <em>{{ card.hint }}</em>
      </button>
    </section>

    <section class="row split">
      <article class="panel current">
        <header>
          <h2>{{ current ? (current.firmware || current.job_id) : '当前任务' }}</h2>
          <span>{{ currentLabel }}</span>
        </header>
        <div v-if="current" class="now">
          <ProgressRing :value="current.progress || 0" :label="current.stage_label || '等待'" :sub="statusText(current.status)" />
          <ol class="steps">
            <li v-for="s in current.steps || []" :key="s.id" :data-state="s.status">
              <i />
              <div>
                <b>{{ s.label }}</b>
                <span>{{ s.detail || stepHint(s.status) }}</span>
              </div>
              <em v-if="s.pct != null">{{ s.pct }}%</em>
            </li>
          </ol>
        </div>
        <p v-else class="empty">还没有解密任务。在「分析任务」或「快速挖掘」上传固件后会自动开始。</p>
      </article>
      <article class="panel">
        <header>
          <h2>实时日志</h2>
          <span>{{ current ? (current.vendor || '未知厂商') : '' }}</span>
        </header>
        <ul class="log">
          <li v-for="(line, i) in (current && current.log) || []" :key="i">{{ line }}</li>
          <li v-if="!(current && current.log && current.log.length)" class="empty-row">等待解密日志</li>
        </ul>
        <dl v-if="current" class="meta">
          <div><dt>方法</dt><dd>{{ current.method || '—' }}</dd></div>
          <div><dt>熵</dt><dd>{{ current.entropy ?? '—' }}</dd></div>
          <div><dt>内部</dt><dd>{{ (current.inner || []).join(' / ') || '—' }}</dd></div>
          <div><dt>算法</dt><dd>{{ current.cipher || '—' }}</dd></div>
        </dl>
      </article>
    </section>

    <section class="panel list-panel">
      <header>
        <h2>全部固件</h2>
        <span>{{ filtered.length }} 个</span>
      </header>
      <table>
        <thead>
          <tr>
            <th>固件</th><th>状态</th><th>进度</th><th>厂商</th><th>结果</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in filtered"
            :key="row.job_id"
            :class="{ on: current && current.job_id === row.job_id }"
            @click="select(row.job_id)"
          >
            <td>{{ row.firmware || row.job_id }}</td>
            <td><span class="pill" :data-kind="row.status">{{ statusText(row.status) }}</span></td>
            <td>
              <span class="bar"><i :style="{ width: (row.progress || 0) + '%' }" /></span>
              {{ row.progress || 0 }}%
            </td>
            <td>{{ row.vendor || '—' }}</td>
            <td>{{ row.stage_label || '—' }}</td>
          </tr>
          <tr v-if="!filtered.length">
            <td colspan="5" class="empty">还没有上传过固件。</td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api'
import CountUp from '../components/fx/CountUp.vue'
import ProgressRing from '../components/ProgressRing.vue'


const data = ref({ summary: {}, items: [], running: [] })
const jobId = ref('')
const loading = ref(false)
const filter = ref('all')
let timer = null

const items = computed(() => data.value.items || [])
const current = computed(() => {
  const list = items.value
  if (!list.length) return null
  return list.find((row) => row.job_id === jobId.value)
    || list.find((row) => row.status === 'running' || row.job_status === 'decrypting')
    || list[0]
})
const currentLabel = computed(() => {
  if (!current.value) return '等待上传'
  return current.value.stage_label || statusText(current.value.status)
})
const summary = computed(() => data.value.summary || {})
const kpiCards = computed(() => [
  { id: 'all', label: '全部任务', value: summary.value.total || 0, hint: '已上传固件' },
  { id: 'running', label: '正在解密', value: summary.value.running || 0, hint: '实时进度' },
  { id: 'decrypted', label: '已解开', value: summary.value.decrypted || 0, hint: '容器已剥离' },
  { id: 'plain', label: '明文无需解密', value: summary.value.plain || 0, hint: '可直接解包' },
  { id: 'identified', label: '已识别加密', value: summary.value.identified || 0, hint: '不解未知密钥' },
  { id: 'failed', label: '失败', value: summary.value.failed || 0, hint: '读写或解压出错' }
])
const filtered = computed(() => {
  if (filter.value === 'all') return items.value
  if (filter.value === 'running') {
    return items.value.filter((r) => r.status === 'running' || r.job_status === 'decrypting')
  }
  return items.value.filter((r) => r.status === filter.value)
})

onMounted(() => {
  load()
  timer = window.setInterval(load, 2000)
})
onUnmounted(() => {
  if (timer) window.clearInterval(timer)
})

async function load () {
  loading.value = true
  try {
    data.value = await api('/decrypt')
    if (!jobId.value && data.value.running && data.value.running[0]) {
      jobId.value = data.value.running[0].job_id
    }
  } catch {
    /* keep last */
  } finally {
    loading.value = false
  }
}

function select (id) {
  jobId.value = id
}

function statusText (s) {
  return {
    running: '进行中',
    decrypted: '已解密',
    plain: '明文',
    identified: '已识别加密',
    failed: '失败',
    peek: '待自动解密',
    none: '未开始',
    idle: '未开始'
  }[s] || s || '—'
}

function stepHint (st) {
  return { wait: '等待', now: '进行中', ok: '完成', err: '失败' }[st] || ''
}
</script>

<style scoped>
.dec { min-height: 100%; padding: 22px 24px 40px; color: var(--fw-text); }
.hero { display: flex; justify-content: space-between; gap: 16px; align-items: flex-end; margin-bottom: 16px; }
.kicker { margin: 0 0 6px; color: var(--fw-brand); letter-spacing: .04em; font-size: 12px; font-weight: 600; }
h1 { margin: 0 0 6px; font-size: 26px; letter-spacing: -.04em; }
.hero p { margin: 0; color: var(--fw-text-2); font-size: 13px; max-width: 640px; }
.hero-side { display: flex; align-items: center; gap: 10px; }
.live { display: inline-flex; align-items: center; gap: 6px; color: var(--fw-ok); font-size: 12px; }
.live i {
  width: 7px; height: 7px; border-radius: 50%; background: var(--fw-ok);
}
.ghost {
  height: 30px; padding: 0 12px; border-radius: 8px; cursor: pointer;
  border: 1px solid var(--fw-line); background: var(--fw-surface); color: var(--fw-text-2);
}
.kpis { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; margin-bottom: 14px; }
.kpi {
  text-align: left; padding: 12px 14px; border-radius: 14px; cursor: pointer; color: inherit;
  border: 1px solid var(--fw-line);
  background: var(--fw-surface);
  box-shadow: var(--fw-shadow);
}
.kpi:hover { border-color: rgba(19, 76, 255, .28); }
.kpi-label { color: var(--fw-text-3); font-size: 12px; }
.kpi strong {
  display: block; margin: 6px 0 2px; font-size: 26px; color: var(--fw-text);
}
.kpi em { font-style: normal; color: var(--fw-text-3); font-size: 11px; }
.row { display: grid; gap: 12px; margin-bottom: 12px; }
.row.split { grid-template-columns: minmax(0, 1.15fr) minmax(0, .85fr); }
.panel {
  padding: 16px; border: 1px solid var(--fw-line); border-radius: 16px;
  background-color: var(--fw-surface); box-shadow: var(--fw-shadow);
}
.panel header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 12px; }
h2 { margin: 0; font-size: 14px; }
.panel header span { color: var(--fw-text-3); font-size: 12px; }
.now { display: grid; grid-template-columns: 180px 1fr; gap: 12px; align-items: center; }
.steps { list-style: none; margin: 0; padding: 0; }
.steps li { display: grid; grid-template-columns: 12px 1fr auto; gap: 8px; padding: 7px 0; }
.steps i { width: 8px; height: 8px; margin-top: 5px; border-radius: 50%; background: #c8ccd3; }
.steps li[data-state='ok'] i { background: var(--fw-ok); }
.steps li[data-state='now'] i { background: var(--fw-brand); }
.steps li[data-state='err'] i { background: var(--fw-danger); }
.steps b { display: block; font-size: 13px; }
.steps span { color: var(--fw-text-3); font-size: 12px; }
.steps em { color: var(--fw-brand); font-style: normal; font-size: 12px; }
.empty, .empty-row { color: var(--fw-text-3); font-size: 13px; }
.acts { display: flex; gap: 8px; margin-top: 12px; }
.log {
  list-style: none; margin: 0; padding: 0; max-height: 240px; overflow: auto;
  font: 12px/1.55 var(--fw-font-mono); color: var(--fw-text-2);
}
.log li { padding: 4px 0; border-top: 1px solid var(--fw-line); }
.meta { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 12px 0 0; }
.meta dt { color: var(--fw-text-3); font-size: 11px; }
.meta dd { margin: 2px 0 0; font-size: 13px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { text-align: left; color: var(--fw-text-3); font-weight: 500; padding: 0 8px 8px 0; }
td { padding: 8px 8px 8px 0; border-top: 1px solid var(--fw-line); }
tbody tr { cursor: pointer; }
tr.on td { background: var(--fw-fill); }
.pill {
  display: inline-block; padding: 1px 8px; border-radius: 99px;
  background: var(--fw-fill); color: var(--fw-brand);
}
.pill[data-kind='decrypted'] { color: var(--fw-ok); background: #dcfce7; }
.pill[data-kind='plain'] { color: var(--fw-brand); }
.pill[data-kind='running'] { color: var(--fw-warn); background: #fef9c3; }
.pill[data-kind='failed'] { color: var(--fw-danger); background: #ffe4e6; }
.bar {
  display: inline-block; width: 72px; height: 5px; margin-right: 6px;
  border-radius: 99px; background: var(--fw-bg-2); vertical-align: middle; overflow: hidden;
}
.bar i { display: block; height: 100%; background: var(--fw-brand); }
@media (max-width: 1100px) {
  .kpis { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .row.split, .now, .hero { display: block; }
}
@media (max-width: 720px) {
  .kpis { grid-template-columns: 1fr 1fr; }
  .dec { padding: 16px 12px 28px; }
}
</style>
