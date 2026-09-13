<template>
  <canvas ref="el" class="fx-particles" aria-hidden="true" />
</template>

<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'

const props = defineProps({
  density: { type: Number, default: 90 }
})

const el = ref(null)
let raf = 0
let pts = []
let w = 0
let h = 0
let dpr = 1
let mx = -9999
let my = -9999
let themeObs = null
// 颜色从主题令牌读取，深浅色主题各自协调
let colA = [110, 155, 255]
let colB = [129, 140, 255]

function readTheme () {
  const cs = getComputedStyle(document.documentElement)
  const pick = (name, fallback) => {
    const v = cs.getPropertyValue(name).trim()
    if (/^#[0-9a-fA-F]{6}$/.test(v)) {
      return [parseInt(v.slice(1, 3), 16), parseInt(v.slice(3, 5), 16), parseInt(v.slice(5, 7), 16)]
    }
    return fallback
  }
  colA = pick('--fw-brand', colA)
  colB = pick('--fw-accent', colB)
}

function spawn () {
  const n = Math.max(36, Math.min(150, props.density))
  pts = Array.from({ length: n }, (_, i) => ({
    x: Math.random() * w,
    y: Math.random() * h,
    vx: (Math.random() - 0.5) * 0.28,
    vy: (Math.random() - 0.5) * 0.28,
    r: i % 11 === 0 ? 2.4 + Math.random() * 1.2 : 0.9 + Math.random() * 1.3,
    alt: Math.random() > 0.6
  }))
}

function resize () {
  const canvas = el.value
  if (!canvas) return
  const rect = canvas.getBoundingClientRect()
  dpr = Math.min(window.devicePixelRatio || 1, 1.6)
  w = Math.max(1, rect.width)
  h = Math.max(1, rect.height)
  canvas.width = Math.floor(w * dpr)
  canvas.height = Math.floor(h * dpr)
  const ctx = canvas.getContext('2d')
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  if (!pts.length) spawn()
}

function tick () {
  raf = 0
  const canvas = el.value
  if (!canvas || document.hidden) {
    raf = requestAnimationFrame(tick)
    return
  }
  const ctx = canvas.getContext('2d')
  ctx.clearRect(0, 0, w, h)

  for (const p of pts) {
    // 光标周围轻微汇聚，让背景对交互有回应
    const dx = mx - p.x
    const dy = my - p.y
    const d2 = dx * dx + dy * dy
    if (d2 < 240 * 240 && d2 > 400) {
      const d = Math.sqrt(d2)
      p.vx += (dx / d) * 0.006
      p.vy += (dy / d) * 0.006
    }
    p.vx *= 0.995
    p.vy *= 0.995
    // 保底漂移速度，避免全部静止
    if (Math.abs(p.vx) < 0.05) p.vx += 0.02
    if (Math.abs(p.vy) < 0.05) p.vy -= 0.02
    p.x += p.vx
    p.y += p.vy
    if (p.x < -8) p.x = w + 8
    if (p.x > w + 8) p.x = -8
    if (p.y < -8) p.y = h + 8
    if (p.y > h + 8) p.y = -8
  }

  const reach = 150
  ctx.lineWidth = 0.9
  for (let i = 0; i < pts.length; i++) {
    for (let j = i + 1; j < pts.length; j++) {
      const a = pts[i]
      const b = pts[j]
      const dx = a.x - b.x
      const dy = a.y - b.y
      const d2 = dx * dx + dy * dy
      if (d2 < reach * reach) {
        const alpha = 1 - Math.sqrt(d2) / reach
        ctx.strokeStyle = `rgba(${colA[0]},${colA[1]},${colA[2]},${0.16 * alpha})`
        ctx.beginPath()
        ctx.moveTo(a.x, a.y)
        ctx.lineTo(b.x, b.y)
        ctx.stroke()
      }
    }
  }
  for (const p of pts) {
    const c = p.alt ? colB : colA
    ctx.shadowColor = `rgba(${c[0]},${c[1]},${c[2]},0.9)`
    ctx.shadowBlur = 7
    ctx.fillStyle = `rgba(${c[0]},${c[1]},${c[2]},0.75)`
    ctx.beginPath()
    ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
    ctx.fill()
  }
  ctx.shadowBlur = 0
  raf = requestAnimationFrame(tick)
}

function onPointer (e) {
  mx = e.clientX
  my = e.clientY
}
function onPointerLeave () {
  mx = -9999
  my = -9999
}

onMounted(() => {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
  readTheme()
  resize()
  raf = requestAnimationFrame(tick)
  window.addEventListener('resize', resize)
  window.addEventListener('pointermove', onPointer, { passive: true })
  document.addEventListener('pointerleave', onPointerLeave)
  // 主题切换时重读令牌颜色
  themeObs = new MutationObserver(readTheme)
  themeObs.observe(document.documentElement, {
    attributes: true, attributeFilter: ['data-fw-theme']
  })
})
onBeforeUnmount(() => {
  if (raf) cancelAnimationFrame(raf)
  window.removeEventListener('resize', resize)
  window.removeEventListener('pointermove', onPointer)
  document.removeEventListener('pointerleave', onPointerLeave)
  if (themeObs) themeObs.disconnect()
})
</script>

<style scoped>
.fx-particles {
  position: fixed;
  inset: 0;
  width: 100%;
  height: 100%;
  pointer-events: none;
  z-index: 0;
  opacity: 0.55;
}
html[data-fw-theme='light'] .fx-particles {
  opacity: 0.35;
}
</style>
