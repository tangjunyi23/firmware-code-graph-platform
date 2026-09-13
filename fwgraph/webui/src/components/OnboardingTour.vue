<template>
  <Teleport to="body">
    <div
      v-if="visible"
      class="tour-root"
      :class="{ 'has-spot': !!spot }"
      role="dialog"
      aria-modal="true"
      :aria-labelledby="titleId"
      @keydown="onKey"
    >
      <div class="tour-dim" />
      <div
        v-if="spot"
        class="tour-spot"
        :style="spotStyle"
        aria-hidden="true"
      />
      <div
        ref="cardRef"
        class="tour-card"
        :style="cardStyle"
        tabindex="-1"
      >
        <div class="tour-kicker">{{ step.kicker }} · {{ index + 1 }}/{{ steps.length }}</div>
        <h2 :id="titleId" class="tour-title">{{ step.title }}</h2>
        <p class="tour-body">{{ step.body }}</p>
        <div class="tour-actions">
          <button type="button" class="tour-link" @click="skip">跳过</button>
          <div class="tour-nav">
            <button
              v-if="index > 0"
              type="button"
              class="tour-btn"
              @click="prev"
            >上一步</button>
            <button
              ref="nextRef"
              type="button"
              class="tour-btn primary"
              @click="next"
            >{{ index === steps.length - 1 ? '完成' : '下一步' }}</button>
          </div>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { computed, nextTick, onUnmounted, ref, watch } from 'vue'

const STORAGE_PREFIX = 'fwgraph_onboard_v2'

const STEPS = [
  {
    id: 'welcome',
    page: 'jobs',
    kicker: '新手教程',
    title: '欢迎使用 FWGraph',
    body: '这是固件攻击面分析平台。左侧大项是功能，小项收在里面：新对话含分析任务，代码洞察含函数和攻击面。漏洞库收录 CVE/CNVD 并可查 N-day。快速模式把解密到挖掘串成一条龙。按 Esc 可随时退出教程。'
  },
  {
    id: 'mode',
    page: 'jobs',
    target: '[data-tour="mode-switch"]',
    kicker: '模式',
    title: '专家 / 快速',
    body: '专家自己管分析任务和对话。快速模式把解密、解包到挖掘串成一条龙。随时可以来回切。'
  },
  {
    id: 'nav',
    page: 'jobs',
    target: '[data-tour="nav-main"]',
    kicker: '功能栏',
    title: '大功能在外，小功能在里',
    body: '挖洞点「新对话」。要上传分析，展开后点「分析任务」。CVE/CNVD 在「漏洞库」。解密、协议、代码洞察页同样收在对应大项下。'
  },
  {
    id: 'prepare-nav',
    page: 'prepare',
    target: '[data-tour="nav-prepare"]',
    fallback: '[data-tour="nav-chat"]',
    kicker: '前置分析',
    title: '分析任务在新对话里',
    body: '挖掘依赖解密、解包、反编译和攻击面。还没有完成的任务时，在「新对话 → 分析任务」上传。'
  },
  {
    id: 'prepare-board',
    page: 'prepare',
    target: '[data-tour="prepare-board"]',
    fallback: '[data-tour="prepare-new"]',
    kicker: '前置分析',
    title: '九步看板会实时播报',
    body: '固件解密 → 解包 → 解析 → 反编译 → 图谱 → 攻击路径 → 路由 → 输入 → 攻击面。完成打勾，当前步有动画，右侧是中文进度播报。'
  },
  {
    id: 'prepare-start',
    page: 'prepare',
    target: '[data-tour="prepare-send"]',
    fallback: '[data-tour="prepare-upload"]',
    kicker: '前置分析',
    title: '上传固件并开始',
    body: '点「上传固件」选镜像，再点「开始前置分析」。解密和解包会自动跑，进度在这块看板上更新。'
  },
  {
    id: 'decrypt',
    page: 'decrypt',
    target: '[data-tour="nav-decrypt"]',
    kicker: '解密',
    title: '固件解密',
    body: '上传后会自动解密。这一页看总进度、步骤和日志。把 IDA 放到投放目录也会在后续反编译里被识别。'
  },
  {
    id: 'protocol',
    page: 'protocol',
    target: '[data-tour="nav-protocol"]',
    kicker: '协议',
    title: '协议逆向',
    body: '六块能力：协议标识、加密算法识别、深度分析、算法逆向、流量实时解码、攻击面评估。只分析你选中的固件和粘贴的报文。'
  },
  {
    id: 'workspace',
    page: 'jobs',
    target: '[data-tour="wb-workspace"]',
    fallback: '[data-tour="wb-new"]',
    kicker: '挖掘',
    title: '回工作台选任务',
    body: '前置完成后打开「工作台」，点「选择已完成的分析任务」。没选中任务时发送会被拦住。'
  },
  {
    id: 'composer',
    page: 'jobs',
    target: '[data-tour="wb-composer"]',
    fallback: '[data-tour="wb-new"]',
    kicker: '挖掘',
    title: '写下目标并发送',
    body: '写清范围，例如「优先看 httpd 的命令注入」。回车或点发送开始。左下角可选「全部同意」自动放行工具。'
  },
  {
    id: 'dashboard',
    page: 'dashboard',
    target: '[data-tour="nav-dashboard"]',
    kicker: '态势',
    title: '仪表盘',
    body: '看 AI 命中率、进行中任务、威胁雷达、厂商排行和中文扫描日志。点 KPI 可跳到对应模块。'
  },
  {
    id: 'reports',
    page: 'reports',
    target: '[data-tour="nav-reports"]',
    kicker: '结果',
    title: '报告中心',
    body: '入库结果按固件命名，分专项 / 季度 / 协议。可预览并导出。教程结束，头像菜单里可重看。'
  }
]

const props = defineProps({
  open: { type: Boolean, default: false },
  username: { type: String, default: '' }
})

const emit = defineEmits(['close', 'navigate'])

const visible = ref(false)
const index = ref(0)
const spot = ref(null)
const cardRef = ref(null)
const nextRef = ref(null)
const cardPos = ref({ top: '40%', left: '50%' })
const titleId = 'fwgraph-onboard-title'

const steps = STEPS
const step = computed(() => STEPS[index.value] || STEPS[0])

const spotStyle = computed(() => {
  const s = spot.value
  if (!s) return {}
  return {
    top: `${s.top}px`,
    left: `${s.left}px`,
    width: `${s.width}px`,
    height: `${s.height}px`
  }
})

const cardStyle = computed(() => ({
  top: cardPos.value.top,
  left: cardPos.value.left
}))

function storageKey () {
  return `${STORAGE_PREFIX}:${props.username || 'anon'}`
}

function markDone () {
  try {
    localStorage.setItem(storageKey(), 'done')
  } catch { /* ignore quota / private mode */ }
}

function sleep (ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function waitForEl (selector, fallback, ms = 1600) {
  const deadline = Date.now() + ms
  while (Date.now() < deadline) {
    const el = selector && document.querySelector(selector)
    if (el && el.getClientRects().length) return el
    await new Promise((r) => requestAnimationFrame(r))
  }
  if (fallback) {
    const el = document.querySelector(fallback)
    if (el && el.getClientRects().length) return el
  }
  return null
}

function measureSpot (el) {
  if (!el) {
    spot.value = null
    return
  }
  const pad = 8
  const r = el.getBoundingClientRect()
  spot.value = {
    top: Math.max(8, r.top - pad),
    left: Math.max(8, r.left - pad),
    width: Math.min(window.innerWidth - 16, r.width + pad * 2),
    height: Math.min(window.innerHeight - 16, r.height + pad * 2)
  }
}

function placeCard () {
  const card = cardRef.value
  const cw = card?.offsetWidth || 360
  const ch = card?.offsetHeight || 220
  const margin = 16
  const s = spot.value
  if (!s) {
    cardPos.value = {
      top: `${Math.max(margin, Math.round((window.innerHeight - ch) / 2))}px`,
      left: `${Math.max(margin, Math.round((window.innerWidth - cw) / 2))}px`
    }
    return
  }
  const below = s.top + s.height + 14
  const above = s.top - ch - 14
  let top
  if (below + ch <= window.innerHeight - margin) top = below
  else if (above >= margin) top = above
  else top = Math.max(margin, window.innerHeight - ch - margin)
  let left = s.left
  if (left + cw > window.innerWidth - margin) left = window.innerWidth - cw - margin
  if (left < margin) left = margin
  cardPos.value = { top: `${Math.round(top)}px`, left: `${Math.round(left)}px` }
}

let applying = 0

async function applyStep () {
  const token = ++applying
  const current = STEPS[index.value]
  emit('navigate', current.page)
  await nextTick()
  // page-pane fade is 250ms; async views (prepare/decrypt/protocol) need more
  await sleep(420)
  if (token !== applying) return
  let el = null
  if (current.target) {
    el = await waitForEl(current.target, current.fallback)
  }
  if (token !== applying) return
  if (el) el.scrollIntoView({ block: 'nearest', inline: 'nearest' })
  measureSpot(el)
  await nextTick()
  placeCard()
  await nextTick()
  nextRef.value?.focus()
}

function next () {
  if (index.value >= STEPS.length - 1) {
    finish()
    return
  }
  index.value += 1
  applyStep()
}

function prev () {
  if (index.value <= 0) return
  index.value -= 1
  applyStep()
}

function finish () {
  markDone()
  visible.value = false
  emit('close', 'done')
}

function skip () {
  markDone()
  visible.value = false
  emit('close', 'skip')
}

function onKey (e) {
  if (e.key === 'Escape') {
    e.preventDefault()
    skip()
  } else if (e.key === 'ArrowRight') {
    e.preventDefault()
    next()
  } else if (e.key === 'ArrowLeft') {
    e.preventDefault()
    prev()
  }
}

function onViewport () {
  const current = STEPS[index.value]
  if (!current) return
  const el = (current.target && document.querySelector(current.target))
    || (current.fallback && document.querySelector(current.fallback))
    || null
  measureSpot(el)
  placeCard()
}

watch(() => props.open, async (open) => {
  if (!open) {
    visible.value = false
    applying += 1
    return
  }
  index.value = 0
  visible.value = true
  spot.value = null
  await applyStep()
})

onUnmounted(() => {
  applying += 1
  window.removeEventListener('resize', onViewport)
  window.removeEventListener('scroll', onViewport, true)
})

watch(visible, (on) => {
  if (on) {
    window.addEventListener('resize', onViewport)
    window.addEventListener('scroll', onViewport, true)
  } else {
    window.removeEventListener('resize', onViewport)
    window.removeEventListener('scroll', onViewport, true)
  }
})
</script>

<style scoped>
.tour-root {
  position: fixed;
  inset: 0;
  z-index: 5200;
  overflow: hidden;
}
.tour-dim {
  position: absolute;
  inset: 0;
  background: rgba(19, 18, 18, .28);
}
.tour-spot {
  position: absolute;
  z-index: 1;
  border-radius: 12px;
  box-shadow: 0 0 0 9999px rgba(19, 18, 18, .28), 0 0 0 2px var(--fw-brand);
  background: transparent;
  pointer-events: none;
  transition: top .18s ease, left .18s ease, width .18s ease, height .18s ease;
}
.tour-root.has-spot .tour-dim { background: transparent; }
.tour-card {
  position: absolute;
  z-index: 2;
  width: min(380px, calc(100vw - 32px));
  padding: 16px 16px 14px;
  border: 1px solid var(--fw-line);
  border-radius: 14px;
  background: var(--fw-surface);
  box-shadow: var(--fw-shadow-lg);
  outline: none;
}
.tour-kicker {
  font-size: 11px;
  font-weight: 650;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--fw-brand);
}
.tour-title {
  margin: 6px 0 8px;
  font-size: 16px;
  font-weight: 650;
  letter-spacing: -0.02em;
  color: var(--fw-text);
  line-height: 1.3;
}
.tour-body {
  margin: 0 0 16px;
  font-size: 13.5px;
  line-height: 1.6;
  color: var(--fw-text-2);
}
.tour-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.tour-nav { display: flex; gap: 8px; }
.tour-btn {
  height: 32px;
  padding: 0 12px;
  border: 1px solid var(--fw-line);
  border-radius: 8px;
  background: var(--fw-surface);
  color: var(--fw-text-2);
  font-size: 13px;
  font-weight: 550;
  cursor: pointer;
}
.tour-btn:hover { background: var(--fw-fill); color: var(--fw-text); }
.tour-btn.primary {
  background: var(--fw-brand);
  border-color: var(--fw-brand);
  color: #fff;
  font-weight: 600;
}
.tour-btn.primary:hover { background: var(--fw-brand-hover); border-color: var(--fw-brand-hover); }
.tour-link {
  border: none;
  background: none;
  color: var(--fw-text-3);
  font-size: 13px;
  cursor: pointer;
  padding: 0;
}
.tour-link:hover { color: var(--fw-text); }
</style>
