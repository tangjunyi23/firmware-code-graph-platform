<template>
  <div class="board">
    <section class="hero">
      <div class="ring-wrap">
        <ProgressRing :value="progress.pct" :label="progress.label" :sub="sub" />
      </div>
      <div class="facts">
        <div class="fact">
          <span>完成步骤</span>
          <strong>{{ progress.done }}/{{ progress.total }}</strong>
        </div>
        <div class="fact">
          <span>二进制</span>
          <strong><CountUp :value="stats.total_binaries ?? '—'" /></strong>
        </div>
        <div class="fact">
          <span>解出文件</span>
          <strong><CountUp :value="stats.extracted_files ?? '—'" /></strong>
        </div>
        <div class="fact">
          <span>当前阶段</span>
          <strong class="live-label">{{ currentTalk }}</strong>
        </div>
      </div>
    </section>

    <ol class="steps">
      <li
        v-for="(s, i) in PIPE_STEPS"
        :key="s.key"
        :data-state="stepState(i, job)"
        :style="{ '--delay': i * 40 + 'ms' }"
      >
        <div class="orb">
          <i class="spin" />
          <em v-if="stepState(i, job) === 'ok'">✓</em>
          <em v-else-if="stepState(i, job) === 'err'">!</em>
          <b v-else>{{ String(i + 1).padStart(2, '0') }}</b>
        </div>
        <div class="body">
          <h3>{{ s.label }}</h3>
          <p>{{ talk(i) }}</p>
          <span class="bar"><i :style="{ width: stepPct(i, job, decrypt) + '%' }" /></span>
        </div>
        <small :data-state="stepState(i, job)">{{ stepState(i, job) === 'err' ? '失败' : stepPct(i, job, decrypt) + '%' }}</small>
      </li>
    </ol>

    <aside class="radio">
      <header>
        <h2>进度播报</h2>
        <span class="live"><i />实时</span>
      </header>
      <ul ref="feedEl" class="feed">
        <li v-for="line in lines" :key="line.id" :data-kind="line.kind">
          <time>{{ fmt(line.ts) }}</time>
          <span>{{ line.text }}</span>
        </li>
        <li v-if="!lines.length" class="empty">上传固件后，这里会逐条播报九步进度。</li>
      </ul>
    </aside>

    <section v-if="job.status === 'failed'" class="fail-card" data-tour="prepare-fail">
      <div class="fail-head">
        <span class="fail-ico">!</span>
        <div class="fail-title">
          <h2>前置分析失败</h2>
          <p>失败阶段：<b>{{ failedLabel }}</b> · 第 {{ failIdx + 1 }} / {{ PIPE_STEPS.length }} 步</p>
        </div>
        <button
          v-if="retryable"
          type="button"
          class="fail-retry"
          :disabled="retrying"
          @click="$emit('retry')"
        >{{ retrying ? '正在重试…' : '重试本阶段' }}</button>
      </div>
      <p class="fail-msg">{{ failMsg }}</p>
      <p v-if="!retryable" class="fail-hint">此阶段在上传固件后自动执行，无法单独重试；请处理后重新上传固件。</p>
      <button v-if="logTail && logTail.length" type="button" class="fail-log-toggle" @click="logOpen = !logOpen">
        {{ logOpen ? '收起任务日志' : `展开任务日志（最近 ${logTail.length} 行）` }}
      </button>
      <pre v-if="logOpen && logTail && logTail.length" class="fail-log">{{ logTailText }}</pre>
    </section>
  </div>
</template>

<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import ProgressRing from '../components/ProgressRing.vue'
import CountUp from '../components/fx/CountUp.vue'
import {
  PIPE_STEPS, STEP_TALK, STATUS_TEXT, stepState, stepPct, pipeProgress,
  pipeIndex, failedStep, failedStepLabel, humanizeError, RETRYABLE_STEPS
} from './pipeline.js'

const props = defineProps({
  job: { type: Object, required: true },
  decrypt: { type: Object, default: null },
  lines: { type: Array, default: () => [] },
  stats: { type: Object, default: () => ({}) },
  logTail: { type: Array, default: () => [] },
  retrying: { type: Boolean, default: false }
})
defineEmits(['retry'])

const logOpen = ref(false)
const failIdx = computed(() => pipeIndex(props.job))
const failedLabel = computed(() => failedStepLabel(props.job))
const retryable = computed(() => RETRYABLE_STEPS.has(failedStep(props.job)))
const failMsg = computed(() => humanizeError(props.job.error))
const logTailText = computed(() => (props.logTail || []).slice(-80).join('\n'))

const feedEl = ref(null)
const progress = computed(() => pipeProgress(props.job))
const sub = computed(() => {
  if (props.job.status === 'uploading') return `上传 ${props.job.uploadPct || 0}%`
  if (props.decrypt && props.job.status === 'decrypting') {
    return props.decrypt.stage_label || '解密中'
  }
  return `${progress.value.done} / ${progress.value.total} 步`
})
const currentTalk = computed(() => {
  const idx = PIPE_STEPS.findIndex((_, i) => stepState(i, props.job) === 'now')
  if (idx >= 0 && STEP_TALK[PIPE_STEPS[idx].key]) return STEP_TALK[PIPE_STEPS[idx].key].now
  return STATUS_TEXT[props.job.status] || props.job.status
})

function talk (i) {
  const st = stepState(i, props.job)
  const rec = STEP_TALK[PIPE_STEPS[i].key] || {}
  if (st === 'ok') return rec.ok || '已完成'
  if (st === 'now') return rec.now || '进行中'
  if (st === 'err') return '本步失败'
  return '等待开始'
}

function fmt (ts) {
  const d = new Date(ts)
  return d.toLocaleTimeString('zh-CN', { hour12: false })
}

watch(() => props.lines.length, async () => {
  await nextTick()
  const el = feedEl.value
  if (el) el.scrollTop = el.scrollHeight
})
</script>

<style scoped>
.board {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(280px, .75fr);
  grid-template-areas:
    "hero hero"
    "steps radio";
  gap: 12px;
}
.hero {
  grid-area: hero;
  display: grid;
  grid-template-columns: 200px 1fr;
  gap: 16px;
  align-items: center;
  padding: 16px 18px;
  border: 1px solid var(--fw-line);
  border-radius: 18px;
  background: var(--fw-surface);
  box-shadow: var(--fw-shadow);
}
.facts { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
.fact span { display: block; color: var(--fw-text-3); font-size: 12px; }
.fact strong {
  display: block; margin-top: 6px; font-size: 22px; color: var(--fw-text);
}
.live-label { font-size: 16px !important; color: var(--fw-brand) !important; }
.steps {
  grid-area: steps;
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 10px;
}
.steps li {
  display: grid;
  grid-template-columns: 44px 1fr auto;
  gap: 10px;
  align-items: center;
  padding: 12px;
  border-radius: 14px;
  border: 1px solid var(--fw-line);
  background: var(--fw-surface);
}
.steps li[data-state='ok'] { border-color: #86efac; }
.steps li[data-state='now'] { border-color: var(--fw-brand); }
.steps li[data-state='err'] { border-color: #fecdd3; }
.orb {
  position: relative;
  width: 40px; height: 40px;
  border-radius: 50%;
  display: grid; place-items: center;
  border: 1.5px solid var(--fw-line);
  color: var(--fw-text-3);
  font-size: 12px;
}
.orb em {
  font-style: normal; font-size: 16px; color: #fff;
}
.steps li[data-state='ok'] .orb {
  background: var(--fw-ok); border-color: var(--fw-ok); color: #fff;
}
.steps li[data-state='err'] .orb { background: var(--fw-danger); border-color: var(--fw-danger); color: #fff; }
.steps li[data-state='now'] .orb { color: var(--fw-brand); border-color: var(--fw-brand); }
.spin {
  display: none;
  position: absolute; inset: -3px;
  border-radius: 50%;
  background: conic-gradient(var(--fw-brand), transparent 55%);
  animation: spin 1s linear infinite;
  -webkit-mask: radial-gradient(farthest-side, transparent calc(100% - 2px), #000 0);
  mask: radial-gradient(farthest-side, transparent calc(100% - 2px), #000 0);
}
.steps li[data-state='now'] .spin { display: block; }
.body h3 { margin: 0; font-size: 13px; }
.body p { margin: 2px 0 6px; color: var(--fw-text-3); font-size: 11px; }
.bar {
  display: block; height: 4px; border-radius: 99px;
  background: var(--fw-bg-2); overflow: hidden;
}
.bar i {
  display: block; height: 100%; width: 0;
  background: var(--fw-brand);
  transition: width .6s ease;
}
.steps li[data-state='ok'] .bar i { background: var(--fw-ok); }
.steps li[data-state='err'] .bar i { background: var(--fw-danger); }
.steps li small[data-state='err'] { color: var(--fw-danger); }
.steps li[data-state='now'] .bar i { background: var(--fw-brand); }
.steps li small { color: var(--fw-brand); font-variant-numeric: tabular-nums; }
.radio {
  grid-area: radio;
  min-height: 280px;
  display: flex; flex-direction: column;
  padding: 14px;
  border: 1px solid var(--fw-line);
  border-radius: 16px;
  background: var(--fw-surface);
}
.radio header { display: flex; justify-content: space-between; align-items: center; }
.radio h2 { margin: 0; font-size: 14px; }
.live { display: inline-flex; align-items: center; gap: 6px; color: var(--fw-ok); font-size: 12px; }
.live i {
  width: 7px; height: 7px; border-radius: 50%; background: var(--fw-ok);
}
.feed {
  list-style: none; margin: 10px 0 0; padding: 0;
  overflow: auto; flex: 1; min-height: 220px;
}
.feed li {
  display: grid; grid-template-columns: 76px 1fr; gap: 8px;
  padding: 7px 0; border-top: 1px solid var(--fw-line);
  font-size: 12px; color: var(--fw-text-2);
}
.feed time { color: var(--fw-text-3); font-variant-numeric: tabular-nums; }
.feed li[data-kind='ok'] span { color: var(--fw-ok); }
.feed li[data-kind='err'] span { color: var(--fw-danger); }
.feed li[data-kind='now'] span { color: var(--fw-brand); }
.empty { color: var(--fw-text-3); }
.fail-card {
  grid-column: 1 / -1;
  padding: 14px 16px;
  border: 1px solid color-mix(in srgb, var(--fw-danger) 38%, transparent);
  border-left: 3px solid var(--fw-danger);
  border-radius: 14px;
  background: color-mix(in srgb, var(--fw-danger) 7%, var(--fw-surface));
}
.fail-head { display: flex; align-items: center; gap: 12px; }
.fail-ico {
  flex: none; width: 34px; height: 34px; border-radius: 50%;
  display: grid; place-items: center;
  background: var(--fw-danger); color: #fff; font-style: normal;
  font-size: 17px; font-weight: 700;
}
.fail-title { flex: 1; min-width: 0; }
.fail-title h2 { margin: 0; font-size: 15px; }
.fail-title p { margin: 3px 0 0; font-size: 12.5px; color: var(--fw-text-3); }
.fail-title b { color: var(--fw-danger); }
.fail-retry {
  flex: none; height: 34px; padding: 0 16px;
  border: none; border-radius: 10px; cursor: pointer;
  background: var(--fw-brand); color: #fff; font-weight: 600; font-size: 13px;
}
.fail-retry:disabled { opacity: 0.55; cursor: default; }
.fail-msg {
  margin: 10px 0 0; padding: 9px 12px;
  border-radius: 8px; background: var(--fw-bg-2);
  font-size: 13px; line-height: 1.65; color: var(--fw-text);
  overflow-wrap: anywhere;
}
.fail-hint { margin: 8px 0 0; font-size: 12.5px; color: var(--fw-text-3); }
.fail-log-toggle {
  margin: 10px 0 0; border: none; background: none; padding: 0;
  color: var(--fw-brand); font-size: 12.5px; cursor: pointer;
}
.fail-log {
  margin: 8px 0 0; padding: 10px 12px; max-height: 240px; overflow: auto;
  border: 1px solid var(--fw-line); border-radius: 8px;
  background: var(--fw-bg-2);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 11.5px; line-height: 1.6; color: var(--fw-text-2);
  white-space: pre-wrap; overflow-wrap: anywhere;
}

@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) {
  .spin { animation: none; }
}
@media (max-width: 1100px) {
  .board, .hero { display: block; }
  .facts, .steps { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 720px) {
  .facts, .steps { grid-template-columns: 1fr; }
}
</style>
