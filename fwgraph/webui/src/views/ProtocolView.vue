<template>
  <div class="proto">
    <header class="hero">
      <div>
        <p class="kicker">入口风险评估</p>
        <h1>固件对外入口风险综合评估</h1>
        <p>对选中固件任务的对外服务入口（监听端口 / 协议 / 暴露面）做综合风险排序，只读取已解包产物。</p>
      </div>
      <div class="hero-side">
        <el-select v-model="jobId" placeholder="选择固件任务" class="job" filterable @change="loadReport">
          <el-option
            v-for="j in jobs"
            :key="j.job_id"
            :value="j.job_id"
            :label="`${j.firmware} · ${STATUS_TEXT[j.status] || j.status}`"
          />
        </el-select>
        <button type="button" class="ghost" :disabled="!jobId || loading" @click="loadReport">重新分析</button>
      </div>
    </header>

    <section class="kpis">
      <button v-for="card in kpiCards" :key="card.id" type="button" class="kpi">
        <span class="kpi-label">{{ card.label }}</span>
        <strong><CountUp :value="card.value" /></strong>
        <em>{{ card.hint }}</em>
      </button>
    </section>

    <p v-if="err" class="banner bad">{{ err }}</p>
    <p v-if="missing.length" class="banner">尚未生成：{{ missing.join('、') }}。已有产物仍会展示。</p>

    <!-- 攻击面评估 -->
    <section class="row split">
      <article class="panel">
        <header>
          <h2>攻击面评估</h2>
          <span>{{ assessment.level || '—' }}风险</span>
        </header>
        <div class="assess-top">
          <ProgressRing :value="assessment.score || 0" label="综合风险" :sub="assessment.level || '待评估'" />
          <RadarChart
            title="协议攻击面"
            :axes="assessAxes"
            :scores="assessScores"
          />
        </div>
        <ul class="recs">
          <li v-for="r in assessment.recommendations || []" :key="r">{{ r }}</li>
        </ul>
      </article>
      <article class="panel">
        <header>
          <h2>入口风险排序</h2>
          <span>{{ (assessment.ranked || []).length }} 条</span>
        </header>
        <ul class="rank">
          <li v-for="(row, i) in assessment.ranked || []" :key="row.id || i">
            <em>{{ i + 1 }}</em>
            <span>{{ row.protocol }} · {{ row.service }}</span>
            <b>{{ row.score }}</b>
            <small>{{ row.level }} · {{ (row.reasons || []).join(' / ') }}</small>
          </li>
          <li v-if="!(assessment.ranked || []).length" class="empty-row">没有可评估的协议入口。</li>
        </ul>
      </article>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'
import RadarChart from '../components/charts/RadarChart.vue'
import CountUp from '../components/fx/CountUp.vue'
import ProgressRing from '../components/ProgressRing.vue'
import { STATUS_TEXT } from '../workbench/pipeline.js'


const jobs = ref([])
const jobId = ref('')
const loading = ref(false)
const err = ref('')
const report = ref(null)

const protocols = computed(() => report.value?.protocols || {})
const assessment = computed(() => report.value?.assessment || {})
const missing = computed(() => report.value?.missing || [])

const kpiCards = computed(() => [
  { id: 'p', label: '协议入口', value: protocols.value.total || 0, hint: '已标识输入' },
  { id: 'pub', label: '公网暴露', value: protocols.value.public || 0, hint: '非回环入口' },
  { id: 's', label: '攻击面', value: assessment.value.surfaces || 0, hint: '已导出表面' },
  { id: 'r', label: '综合风险', value: assessment.value.score || 0, hint: assessment.value.level || '待评估' }
])

const assessAxes = computed(() => (assessment.value.axes || []).map((a) => ({
  key: a.key,
  label: a.label
})))
const assessScores = computed(() => (assessment.value.axes || []).map((a) => a.score || 0))

onMounted(async () => {
  try {
    const list = await api('/jobs')
    jobs.value = Array.isArray(list) ? list : []
    if (!jobId.value && jobs.value[0]) {
      jobId.value = jobs.value[0].job_id
      loadReport()
    }
  } catch {
    jobs.value = []
  }
})

async function loadReport () {
  if (!jobId.value) return
  loading.value = true
  err.value = ''
  try {
    report.value = await api(`/jobs/${jobId.value}/protocol-reverse`)
  } catch (e) {
    report.value = null
    err.value = e.message || '分析失败'
  } finally {
    loading.value = false
  }
}

</script>

<style scoped>
.proto { min-height: 100%; padding: 22px 24px 40px; color: var(--fw-text); }
.hero { display: flex; justify-content: space-between; gap: 16px; align-items: flex-end; margin-bottom: 16px; }
.kicker { margin: 0 0 6px; color: var(--fw-brand); letter-spacing: .04em; font-size: 12px; font-weight: 600; }
h1 { margin: 0 0 6px; font-size: 26px; letter-spacing: -.04em; }
.hero p { margin: 0; color: var(--fw-text-2); font-size: 13px; max-width: 640px; }
.hero-side { display: flex; gap: 8px; align-items: center; }
.job { width: 320px; }
.kpis { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; margin-bottom: 14px; }
.kpi {
  text-align: left; padding: 12px 14px;
  border: 1px solid var(--fw-line); border-radius: 14px;
  background: var(--fw-surface);
  color: inherit; cursor: pointer;
  box-shadow: var(--fw-shadow);
}
.kpi:hover { border-color: rgba(19, 76, 255, .28); }
.kpi-label { color: var(--fw-text-3); font-size: 12px; }
.kpi strong {
  display: block; margin: 6px 0 2px; font-size: 26px; color: var(--fw-text);
}
.kpi em { font-style: normal; color: var(--fw-text-3); font-size: 11px; }
.caps {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 16px;
}
.cap {
  position: relative;
  display: flex;
  align-items: flex-start;
  gap: 10px;
  text-align: left;
  padding: 13px 12px 12px;
  border-radius: 14px;
  cursor: pointer;
  border: 1px solid var(--fw-line);
  background: var(--fw-surface);
  color: var(--fw-text-2);
  box-shadow: var(--fw-shadow);
  font-family: inherit;
  transition: border-color .16s ease, box-shadow .16s ease, transform .16s ease;
}
.cap:hover {
  border-color: rgba(19, 76, 255, .32);
  box-shadow: 0 6px 18px -6px rgba(16, 24, 40, .14);
  transform: translateY(-1px);
}
.cap.on {
  border-color: rgba(19, 76, 255, .55);
  background: linear-gradient(180deg, rgba(19, 76, 255, .07), rgba(19, 76, 255, .03)), var(--fw-surface);
  box-shadow: 0 0 0 3px rgba(19, 76, 255, .09);
}
.cap.on::after {
  content: '';
  position: absolute;
  left: 12px;
  right: 12px;
  bottom: -1px;
  height: 2px;
  border-radius: 2px;
  background: var(--fw-brand);
}
.cap-ico {
  flex: none;
  display: grid;
  place-items: center;
  width: 34px;
  height: 34px;
  border-radius: 10px;
  background: var(--fw-fill);
  color: var(--fw-brand);
}
.cap.on .cap-ico { background: rgba(19, 76, 255, .14); }
.cap-copy { flex: 1; min-width: 0; display: flex; flex-direction: column; }
.cap-no {
  color: var(--fw-text-3);
  font-size: 10px;
  letter-spacing: .16em;
  font-weight: 650;
}
.cap-label { display: block; margin: 3px 0 2px; font-size: 13.5px; color: var(--fw-text); line-height: 1.3; }
.cap.on .cap-label { color: var(--fw-brand); font-weight: 650; }
.cap-hint {
  font-size: 11px;
  color: var(--fw-text-3);
  line-height: 1.45;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.cap-count {
  flex: none;
  min-width: 22px;
  height: 20px;
  padding: 0 6px;
  border-radius: 999px;
  background: var(--fw-bg-2);
  color: var(--fw-text-2);
  font-size: 11px;
  font-weight: 650;
  line-height: 20px;
  text-align: center;
  font-variant-numeric: tabular-nums;
}
.cap.on .cap-count { background: rgba(19, 76, 255, .14); color: var(--fw-brand); }
.banner { margin: 0 0 12px; color: var(--fw-warn); font-size: 12px; }
/* 能力切换时内容区淡入，避免生硬跳变 */
.proto > section.row { animation: fw-page-in .2s ease both; }
.banner.bad { color: var(--fw-danger); }
.row { display: grid; gap: 12px; }
.row.split { grid-template-columns: minmax(0, 1.2fr) minmax(0, .8fr); }
.panel {
  padding: 16px; border: 1px solid var(--fw-line); border-radius: 16px;
  background-color: var(--fw-surface); box-shadow: var(--fw-shadow);
}
.panel header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 12px; }
h2 { margin: 0; font-size: 14px; }
.panel header span { color: var(--fw-text-3); font-size: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { text-align: left; color: var(--fw-text-3); font-weight: 500; padding: 0 8px 8px 0; }
td { padding: 8px 8px 8px 0; border-top: 1px solid var(--fw-line); }
tr.on td, tbody tr:hover td { background: var(--fw-fill); }
tbody tr { cursor: pointer; }
.warn { margin-left: 6px; color: var(--fw-warn); font-size: 10px; }
.mono { font-family: var(--fw-font-mono); font-size: 11px; color: var(--fw-brand); }
.empty, .empty-row { color: var(--fw-text-3); font-size: 13px; }
.detail { margin-top: 14px; }
.detail h3 { margin: 0 0 6px; font-size: 14px; }
.detail p { margin: 0 0 8px; color: var(--fw-text-2); font-size: 12px; line-height: 1.55; }
.chips, .samples { display: flex; flex-wrap: wrap; gap: 6px; }
.chips span, .chip, .pill {
  display: inline-block; padding: 2px 8px; border-radius: 99px;
  background: var(--fw-fill); color: var(--fw-brand); font-size: 11px;
}
.files { white-space: pre-wrap; word-break: break-all; }
.algo-grid { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.algo {
  padding: 10px 12px; border-radius: 12px; cursor: pointer;
  border: 1px solid var(--fw-line); background: var(--fw-surface);
}
.algo.on { border-color: var(--fw-brand); }
.algo.weak { border-color: rgba(225, 29, 72, .45); }
.algo.legacy { border-color: rgba(217, 119, 6, .4); }
.algo b { display: block; }
.algo em { font-style: normal; font-size: 11px; color: var(--fw-brand); }
.algo span, .algo small { display: block; color: var(--fw-text-3); font-size: 11px; }
.list { list-style: none; margin: 0; padding: 0; max-height: 460px; overflow: auto; }
.list li { padding: 8px 0; border-top: 1px solid var(--fw-line); cursor: pointer; }
.list b { display: block; font-size: 13px; }
.list span { display: block; color: var(--fw-text-3); font-size: 12px; }
.deep-card {
  padding: 10px 0; border-top: 1px solid var(--fw-line); cursor: pointer;
}
.deep-head { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 6px; }
.deep-card p { margin: 0 0 4px; color: var(--fw-text-2); font-size: 12px; }
.out {
  width: 100%; min-height: 160px; border: 1px solid var(--fw-line); border-radius: 10px;
  background: var(--fw-bg); color: var(--fw-text); padding: 12px 14px; font: 500 13px/1.6 var(--fw-font-mono);
  white-space: pre-wrap; word-break: break-all;
}
.out.slim { min-height: 80px; max-height: 220px; overflow: auto; }
.out.code { min-height: 360px; max-height: 62vh; overflow: auto; color: #854d0e; }
textarea {
  width: 100%; min-height: 220px; border: 1px solid var(--fw-line); border-radius: 10px;
  background: var(--fw-bg); color: var(--fw-text); padding: 10px; font: 12px/1.5 var(--fw-font-mono);
}
.acts { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
.go, .ghost {
  height: 34px; padding: 0 14px; border-radius: 8px; cursor: pointer; font-weight: 600;
}
.go { border: none; background: var(--fw-brand); color: #fff; }
.ghost { border: 1px solid var(--fw-line); background: transparent; color: var(--fw-text-2); }
.ghost.on { border-color: var(--fw-brand); color: var(--fw-brand); }
.samples { margin-top: 10px; }
.samples button {
  height: 26px; padding: 0 10px; border-radius: 99px; cursor: pointer;
  border: 1px solid var(--fw-line); background: transparent; color: var(--fw-brand); font-size: 12px;
}
.live { display: inline-flex; align-items: center; gap: 6px; color: var(--fw-ok); }
.live i {
  width: 7px; height: 7px; border-radius: 50%; background: var(--fw-ok);
}
.narrative { color: var(--fw-text-2); font-size: 13px; line-height: 1.65; }
.muted { color: var(--fw-text-3); font-size: 12px; }
.full { width: 100%; margin-bottom: 10px; }
.assess-top { display: grid; grid-template-columns: 180px 1fr; gap: 8px; align-items: center; }
.recs { margin: 12px 0 0; padding-left: 18px; color: var(--fw-text-2); font-size: 13px; line-height: 1.6; }
.rank { list-style: none; margin: 0; padding: 0; }
.rank li {
  display: grid; grid-template-columns: 22px 1fr auto; gap: 8px; align-items: center;
  padding: 8px 0; border-top: 1px solid var(--fw-line); font-size: 13px;
}
.rank em { color: var(--fw-brand); font-style: normal; }
.rank small { grid-column: 2; color: var(--fw-text-3); font-size: 11px; }
@media (max-width: 1100px) {
  .kpis { grid-template-columns: repeat(4, minmax(0, 1fr)); }
  .caps { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .row.split, .assess-top, .hero { display: block; }
  .job { width: 100%; margin-bottom: 8px; }
}
@media (max-width: 720px) {
  .kpis, .caps { grid-template-columns: 1fr 1fr; }
  .proto { padding: 16px 12px 28px; }
}
</style>
