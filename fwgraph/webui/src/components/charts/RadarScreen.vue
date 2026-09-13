<template>
  <div ref="wrap" class="rs-wrap">
    <canvas ref="cv" class="rs-canvas" />
    <div ref="tip" class="rs-tip">
      <div v-if="hover" class="rt-name">
        {{ hover.full || hover.name }}<span v-if="hover.cwe" class="cwe">{{ hover.cwe }}</span>
      </div>
      <div v-if="hover" class="rt-row">
        <span class="sev" :class="'sev-' + hover.sev">{{ SEV[hover.sev]?.label || hover.sev }}</span>
        {{ hover.sector }}
        <span v-if="hover.ver" class="rt-ver">✓ 已验证</span>
        <span v-else class="rt-pend">待验证</span>
      </div>
      <div v-if="hover" class="rt-row dim">{{ hover.reach }} · 置信 {{ hover.conf }}</div>
    </div>
  </div>
</template>

<script setup>
/* 威胁雷达（Canvas）：按态势大屏 demo 移植 —— 扫描余晖波束、严重度色带、
   扇区标签、杂波噪点、攻击链、悬停下钻。数据来自 /vulnagent/findings。 */
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'

const props = defineProps({
  // 扇区名（攻击面/类别）
  sectors: { type: Array, default: () => [] },
  // 目标: {sector, sev, name, cwe, ver, reach, conf, n}
  targets: { type: Array, default: () => [] },
  centerValue: { type: [String, Number], default: '' },
  centerLabel: { type: String, default: '攻击面总数' },
  period: { type: Number, default: 5.5 } // 秒/圈
})

const wrap = ref(null)
const cv = ref(null)
const tip = ref(null)
const hover = ref(null)

const SEV = {
  crit: { label: '严重', color: '#F43F5E', band: [0.13, 0.30] },
  high: { label: '高危', color: '#FB923C', band: [0.30, 0.55] },
  med: { label: '中危', color: '#FACC15', band: [0.55, 0.78] },
  low: { label: '低危', color: '#34D399', band: [0.78, 0.97] }
}
const MONO = '"Cascadia Code","JetBrains Mono",Consolas,monospace'
const REDUCED = typeof window !== 'undefined' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches

function hexA (hex, a) {
  const n = parseInt(hex.slice(1), 16)
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`
}

let ctx = null
let w = 0; let h = 0; let cx = 0; let cy = 0; let R = 0
let beam = -Math.PI / 2; let prevBeam = beam; let last = 0
let sweeps = 0; let sweepIdx = 0
let blips = []
let chains = []
let clutter = []
let raf = 0
let ro = null

function rebuild () {
  const nSec = Math.max(props.sectors.length, 1)
  const secIdx = new Map(props.sectors.map((s, i) => [s, i]))
  // 确定性伪随机（同数据同布局）
  let seed = 42
  const rnd = () => {
    seed = (seed * 16807) % 2147483647
    return (seed - 1) / 2147483646
  }
  blips = props.targets.map((t, i) => {
    const s = secIdx.has(t.sector) ? secIdx.get(t.sector) : (i % nSec)
    const step = 360 / nSec
    const mid = (-90 + step * s + step / 2) * Math.PI / 180
    const jit = (rnd() * 44 - 22) * Math.PI / 180
    const sev = SEV[t.sev] ? t.sev : 'low'
    const band = SEV[sev].band
    return {
      ...t, sev, s,
      a: mid + jit,
      d: band[0] + rnd() * (band[1] - band[0]),
      size: 3.5 + Math.sqrt(t.n || 1) * 2.2,
      glow: 0, seed: rnd(), x: 0, y: 0
    }
  })
  // 攻击链：每个扇区第一条 严重/高危 → 同扇区下一条
  chains = []
  for (let s = 0; s < nSec; s++) {
    const group = blips.filter((b) => b.s === s)
    if (group.length >= 2) chains.push([blips.indexOf(group[0]), blips.indexOf(group[1])])
  }
  clutter = Array.from({ length: 48 }, () => ({
    a: rnd() * Math.PI * 2, d: 0.16 + rnd() * 0.82, p: 0, s: 0.6 + rnd()
  }))
}

function resize () {
  if (!wrap.value || !cv.value) return
  const r = wrap.value.getBoundingClientRect()
  if (r.width < 60 || r.height < 60) return
  w = r.width; h = r.height
  const dpr = window.devicePixelRatio || 1
  cv.value.width = w * dpr; cv.value.height = h * dpr
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  cx = w / 2; cy = h / 2 + 4
  R = Math.min(w, h) / 2 - 30
}

function draw (ts) {
  raf = requestAnimationFrame(draw)
  if (!ctx || R <= 10) return
  try {
    const dt = Math.min(64, ts - (last || ts)); last = ts
    const speed = (Math.PI * 2) / (props.period * 1000)
    if (!REDUCED) { prevBeam = beam; beam += dt * speed } else { prevBeam = beam }
    const step = (beam - prevBeam + Math.PI * 2) % (Math.PI * 2)
    const idx = Math.floor((beam + Math.PI / 2) / (Math.PI * 2))
    if (idx > sweepIdx) sweepIdx = idx
    for (const b of blips) {
      const fwd = (b.a - prevBeam + Math.PI * 2) % (Math.PI * 2)
      if (fwd <= step + 0.001) b.glow = 1
      b.glow *= Math.pow(0.994, dt / 16.7)
      b.x = cx + Math.cos(b.a) * b.d * R
      b.y = cy + Math.sin(b.a) * b.d * R
    }
    ctx.clearRect(0, 0, w, h)
    // 标签保留区：目标名称不得压盖扇区标签 / 严重度标签 / 四角 HUD
    const reserved = [
      { x: 0, y: 0, w: 150, h: 24 }, { x: w - 150, y: 0, w: 150, h: 24 },
      { x: 0, y: h - 24, w: 200, h: 24 }, { x: w - 110, y: h - 24, w: 110, h: 24 }
    ]

    // 严重度色带（分层填充）
    for (const k of ['low', 'med', 'high', 'crit']) {
      ctx.fillStyle = hexA(SEV[k].color, k === 'crit' ? 0.07 : 0.05)
      ctx.beginPath(); ctx.arc(cx, cy, R * SEV[k].band[1], 0, Math.PI * 2); ctx.fill()
    }
    // 细网格：细环 + 辐条
    ctx.save()
    ctx.strokeStyle = 'rgba(148,163,184,.045)'; ctx.lineWidth = 1
    for (let i = 1; i <= 8; i++) { ctx.beginPath(); ctx.arc(cx, cy, R * i / 9, 0, Math.PI * 2); ctx.stroke() }
    ctx.strokeStyle = 'rgba(148,163,184,.035)'
    for (let i = 0; i < 24; i++) {
      const a = i / 24 * Math.PI * 2
      ctx.beginPath()
      ctx.moveTo(cx + Math.cos(a) * R * 0.16, cy + Math.sin(a) * R * 0.16)
      ctx.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R); ctx.stroke()
    }
    ctx.restore()

    // 刻度环
    ctx.save()
    for (let i = 0; i < 60; i++) {
      const a = i / 60 * Math.PI * 2; const long = i % 5 === 0
      ctx.strokeStyle = hexA('#22D3EE', long ? 0.28 : 0.12); ctx.lineWidth = 1
      ctx.beginPath()
      ctx.moveTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R)
      ctx.lineTo(cx + Math.cos(a) * (R + (long ? 7 : 4)), cy + Math.sin(a) * (R + (long ? 7 : 4)))
      ctx.stroke()
    }
    // 严重度环 + 标签
    ctx.font = '10px ' + MONO; ctx.textAlign = 'left'
    for (const k in SEV) {
      const v = SEV[k]
      ctx.strokeStyle = hexA(v.color, 0.17); ctx.lineWidth = 1
      ctx.beginPath(); ctx.arc(cx, cy, R * v.band[1], 0, Math.PI * 2); ctx.stroke()
      ctx.fillStyle = hexA(v.color, 0.55)
      ctx.fillText(v.label, cx + 3, cy - R * v.band[1] + 11)
      reserved.push({ x: cx + 1, y: cy - R * v.band[1] + 2, w: ctx.measureText(v.label).width + 6, h: 12 })
    }
    // 扇区分隔 + 标签
    const nSec = Math.max(props.sectors.length, 1)
    const secStep = 360 / nSec
    const secCount = props.sectors.map((_, i) => blips.filter((b) => b.s === i).length)
    ctx.textAlign = 'center'
    for (let i = 0; i < props.sectors.length; i++) {
      const a = (-90 + secStep * i) * Math.PI / 180
      ctx.strokeStyle = 'rgba(148,163,184,.10)'
      ctx.beginPath(); ctx.moveTo(cx, cy)
      ctx.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R); ctx.stroke()
      const m = (-90 + secStep * i + secStep / 2) * Math.PI / 180
      ctx.fillStyle = hover.value && hover.value.s === i ? '#C9D4EA' : '#7C89A6'
      ctx.font = '10.5px sans-serif'
      const label = `${props.sectors[i]} · ${secCount[i]}`
      const lw = ctx.measureText(label).width
      let sx = cx + Math.cos(m) * (R + 24)
      sx = Math.max(lw / 2 + 6, Math.min(w - lw / 2 - 6, sx))
      const sy = cy + Math.sin(m) * (R + 24) + 4
      ctx.fillText(label, sx, sy)
      reserved.push({ x: sx - lw / 2 - 3, y: sy - 9, w: lw + 6, h: 15 })
    }
    ctx.restore()

    // 杂波噪点
    ctx.save(); ctx.globalCompositeOperation = 'lighter'
    for (const c of clutter) {
      const fwd = (c.a - prevBeam + Math.PI * 2) % (Math.PI * 2)
      if (fwd <= step + 0.001) c.p = 1
      c.p *= Math.pow(0.988, dt / 16.7)
      const x = cx + Math.cos(c.a) * c.d * R; const y = cy + Math.sin(c.a) * c.d * R
      ctx.fillStyle = `rgba(125,211,252,${0.05 + c.p * 0.28})`
      ctx.beginPath(); ctx.arc(x, y, 0.8 * c.s, 0, Math.PI * 2); ctx.fill()
    }
    ctx.restore()

    // 攻击链（流动虚线）
    ctx.save()
    ctx.lineWidth = 1; ctx.setLineDash([5, 4])
    ctx.lineDashOffset = -(ts * 0.012) % 9
    for (const [ai, bi] of chains) {
      const A = blips[ai]; const B = blips[bi]
      if (!A || !B) continue
      const mx = (A.x + B.x) / 2 - (A.y - B.y) * 0.14
      const my = (A.y + B.y) / 2 + (A.x - B.x) * 0.14
      ctx.strokeStyle = hexA('#F43F5E', 0.15 + 0.28 * Math.max(A.glow, B.glow))
      ctx.beginPath(); ctx.moveTo(A.x, A.y); ctx.quadraticCurveTo(mx, my, B.x, B.y); ctx.stroke()
      ctx.fillStyle = hexA('#F43F5E', 0.35 + 0.4 * B.glow)
      ctx.beginPath(); ctx.arc(B.x, B.y, 1.6, 0, Math.PI * 2); ctx.fill()
    }
    ctx.restore()

    // 目标核心 + 悬停十字（按用户要求去掉辉光/脉冲环，只留实心点）
    const hov = hover.value
    for (const b of blips) {
      const c = SEV[b.sev].color
      ctx.fillStyle = c
      ctx.beginPath(); ctx.arc(b.x, b.y, b.size * 0.62, 0, Math.PI * 2); ctx.fill()
      ctx.fillStyle = 'rgba(255,255,255,.9)'
      ctx.beginPath(); ctx.arc(b.x, b.y, Math.max(1.4, b.size * 0.24), 0, Math.PI * 2); ctx.fill()
      if (b === hov) {
        ctx.strokeStyle = hexA(c, 0.5); ctx.setLineDash([4, 4]); ctx.lineWidth = 1
        ctx.beginPath()
        ctx.moveTo(b.x, b.y - b.size - 14); ctx.lineTo(b.x, b.y + b.size + 14)
        ctx.moveTo(b.x - b.size - 14, b.y); ctx.lineTo(b.x + b.size + 14, b.y)
        ctx.stroke(); ctx.setLineDash([])
      }
    }
    // 扫描波束
    if (!REDUCED) {
      ctx.save(); ctx.globalCompositeOperation = 'lighter'
      if (ctx.createConicGradient) {
        const trail = 1.9; const start = beam - trail
        const g = ctx.createConicGradient(start, cx, cy)
        const span = trail / (Math.PI * 2)
        g.addColorStop(0, 'rgba(91,124,250,0)')
        g.addColorStop(Math.max(0, span - 0.004), 'rgba(91,124,250,0)')
        g.addColorStop(span, 'rgba(125,211,252,.30)')
        g.addColorStop(Math.min(1, span + 0.005), 'rgba(125,211,252,0)')
        g.addColorStop(1, 'rgba(91,124,250,0)')
        ctx.fillStyle = g
        ctx.beginPath(); ctx.moveTo(cx, cy); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.fill()
      }
      const lg = ctx.createLinearGradient(cx, cy, cx + Math.cos(beam) * R, cy + Math.sin(beam) * R)
      lg.addColorStop(0, 'rgba(125,211,252,0)')
      lg.addColorStop(0.7, 'rgba(125,211,252,.75)')
      lg.addColorStop(1, 'rgba(125,211,252,.95)')
      ctx.strokeStyle = lg; ctx.lineWidth = 2
      ctx.shadowColor = '#22D3EE'; ctx.shadowBlur = 12
      ctx.beginPath(); ctx.moveTo(cx, cy)
      ctx.lineTo(cx + Math.cos(beam) * R, cy + Math.sin(beam) * R); ctx.stroke()
      ctx.restore()
    }

    // 目标名称：画在波束之后，保证文字永远在最上层。
    // 悬停 > 严重（常显）> 高危（被扫到点亮）；
    // 逐个放置 + 碰撞检测：重叠的弱标签让位给强标签，杜绝文字糊成一团
    ctx.font = '10px ' + MONO
    ctx.textBaseline = 'middle'
    const placed = []
    const cands = blips
      .filter((b) => b === hov || b.sev === 'crit' || (b.sev === 'high' && b.glow > 0.1))
      .sort((a, b) => (a === hov ? -1 : a === hov ? 1 : 0) ||
        (b.sev === 'crit' ? 1 : 0) - (a.sev === 'crit' ? 1 : 0) || b.glow - a.glow)
    for (const b of cands) {
      const la = b === hov ? 1
        : b.sev === 'crit'
          ? 0.8 + 0.15 * Math.sin(ts / 300 + b.seed * 7)
          : b.glow * 0.95
      if (la < 0.12) continue
      const name = b.name.length > 14 ? b.name.slice(0, 13) + '…' : b.name
      const tw = ctx.measureText(name).width
      if (tw < 2) continue
      // 锚点沿目标向外，超界则钳制回画布内并按可用空间选对齐方向
      const ox = Math.cos(b.a); const oy = Math.sin(b.a)
      let lx = b.x + ox * (b.size + 10)
      let ly = Math.max(11, Math.min(h - 11, b.y + oy * (b.size + 10)))
      let left = ox >= 0 ? lx : lx - tw
      if (left < 4) { left = 4 }
      if (left + tw > w - 4) { left = w - 4 - tw }
      const rect = { x: left - 2, y: ly - 7, w: tw + 4, h: 14 }
      const hit = [...reserved, ...placed].some((p) =>
        rect.x < p.x + p.w && p.x < rect.x + rect.w &&
        rect.y < p.y + p.h && p.y < rect.y + rect.h)
      if (hit) continue
      placed.push(rect)
      ctx.textAlign = 'left'
      ctx.lineWidth = 3; ctx.strokeStyle = 'rgba(7,11,20,.95)'
      ctx.strokeText(name, left, ly)
      ctx.fillStyle = hexA(SEV[b.sev].color, Math.min(0.95, la))
      ctx.fillText(name, left, ly)
    }
    ctx.textBaseline = 'alphabetic'

    // 中心信息
    ctx.save()
    ctx.fillStyle = 'rgba(10,16,30,.95)'
    ctx.beginPath(); ctx.arc(cx, cy, R * 0.16, 0, Math.PI * 2); ctx.fill()
    ctx.strokeStyle = 'rgba(148,163,184,.18)'; ctx.stroke()
    ctx.textAlign = 'center'
    ctx.fillStyle = '#E6EDF7'; ctx.font = '700 22px ' + MONO
    ctx.fillText(String(props.centerValue), cx, cy - 2)
    ctx.fillStyle = '#8A94AD'; ctx.font = '9.5px sans-serif'
    ctx.fillText(props.centerLabel, cx, cy + 14)
    ctx.restore()

    // 四角 HUD
    ctx.font = '10px ' + MONO
    ctx.fillStyle = 'rgba(125,211,252,.5)'
    ctx.textAlign = 'left'
    ctx.fillText('MODE · DEEP-SCAN', 14, 18)
    ctx.fillText(`SWEEP ${String(sweeps % 1000).padStart(3, '0')} · ${props.period}s/rev`, 14, h - 12)
    ctx.textAlign = 'right'
    ctx.fillText('TARGETS ' + blips.length, w - 14, 18)
    ctx.fillText('LIVE', w - 14, h - 12)
  } catch (e) { /* 单帧绘制异常，下一帧自动恢复 */ }
}

function onMove (e) {
  if (!cv.value) return
  const r = cv.value.getBoundingClientRect()
  const mx = e.clientX - r.left; const my = e.clientY - r.top
  let best = null; let bd = 22
  for (const b of blips) {
    const d = Math.hypot(b.x - mx, b.y - my)
    if (d < bd + b.size * 0.5) { bd = d; best = b }
  }
  hover.value = best
  if (best && tip.value) {
    tip.value.style.display = 'block'
    const tw = tip.value.offsetWidth; const th = tip.value.offsetHeight
    let x = e.clientX + 16; let y = e.clientY - th / 2
    if (x + tw > window.innerWidth - 8) x = e.clientX - tw - 16
    y = Math.max(8, Math.min(window.innerHeight - th - 8, y))
    tip.value.style.left = x + 'px'
    tip.value.style.top = y + 'px'
    cv.value.style.cursor = 'pointer'
  } else {
    if (tip.value) tip.value.style.display = 'none'
    if (cv.value) cv.value.style.cursor = 'crosshair'
  }
}
function onLeave () {
  hover.value = null
  if (tip.value) tip.value.style.display = 'none'
}

watch(() => [props.sectors, props.targets, props.centerValue], rebuild, { deep: true })

onMounted(() => {
  ctx = cv.value.getContext('2d')
  rebuild()
  resize()
  ro = new ResizeObserver(resize)
  ro.observe(wrap.value)
  cv.value.addEventListener('mousemove', onMove)
  cv.value.addEventListener('mouseleave', onLeave)
  raf = requestAnimationFrame(draw)
})
onBeforeUnmount(() => {
  if (raf) cancelAnimationFrame(raf)
  if (ro) ro.disconnect()
  if (cv.value) {
    cv.value.removeEventListener('mousemove', onMove)
    cv.value.removeEventListener('mouseleave', onLeave)
  }
})
</script>

<style scoped>
.rs-wrap { position: relative; width: 100%; height: 100%; min-height: 0; }
.rs-canvas { width: 100%; height: 100%; display: block; cursor: crosshair; }
.rs-tip {
  position: fixed;
  z-index: 50;
  pointer-events: none;
  display: none;
  min-width: 200px;
  background: rgba(10, 16, 30, .96);
  border: 1px solid rgba(91, 124, 250, .4);
  border-radius: 10px;
  padding: 10px 12px;
  box-shadow: 0 10px 34px rgba(0, 0, 0, .55), 0 0 24px rgba(91, 124, 250, .12);
  backdrop-filter: blur(6px);
  color: #E6EDF7;
}
.rt-name { font-size: 12.5px; font-weight: 600; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.rt-name .cwe {
  font: 10.5px var(--fw-font-mono, monospace);
  color: #7DA2FF;
  background: rgba(91, 124, 250, .14);
  padding: 1px 6px;
  border-radius: 4px;
}
.rt-row { margin-top: 7px; font-size: 11px; color: #98A3BC; display: flex; align-items: center; gap: 8px; }
.rt-row.dim { color: #5F6B85; font-size: 10.5px; }
.rt-ver { color: #34D399; font-size: 10.5px; }
.rt-pend { color: #8A94AD; font-size: 10.5px; }
.sev { flex: none; font-size: 10px; padding: 1px 6px; border-radius: 4px; font-weight: 600; }
.sev-crit { color: #FF8FA5; background: rgba(244, 63, 94, .15); }
.sev-high { color: #FB923C; background: rgba(251, 146, 60, .14); }
.sev-med { color: #FACC15; background: rgba(250, 204, 21, .12); }
.sev-low { color: #34D399; background: rgba(52, 211, 153, .12); }
</style>
