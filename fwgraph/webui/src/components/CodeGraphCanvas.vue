<template>
  <div class="graph-canvas-wrap" ref="wrap">
    <canvas
      ref="canvas"
      @wheel.prevent="onWheel"
      @mousedown="onDown"
      @mousemove="onMove"
      @mouseup="onUp"
      @mouseleave="onUp"
      @click="onClick"
      @dblclick="fit"
    ></canvas>
  </div>
</template>

<script setup>
import { onMounted, onBeforeUnmount, ref, watch } from 'vue'

const props = defineProps({
  nodes: { type: Array, default: () => [] },
  edges: { type: Array, default: () => [] },
  types: { type: Array, default: () => [] },
  highlight: { type: String, default: '' },
  fitSignal: { type: Number, default: 0 },
})
const emit = defineEmits(['select'])

const wrap = ref(null)
const canvas = ref(null)
let ctx = null
let dpr = 1
let viewW = 0
let viewH = 0
const transform = { scale: 1, ox: 0, oy: 0 }
const drag = { active: false, moved: false, x: 0, y: 0 }
let dirty = true
let rafId = 0
let visible = []
let nodeById = new Map()
let selected = null

const EDGE_COLORS = {
  CALLS: 'rgba(43, 108, 229, 0.38)',
  DEFINES: 'rgba(130, 160, 200, 0.22)',
  CONTAINS_FILE: 'color-mix(in srgb, var(--fw-brand) 10%, transparent)',
  CONTAINS_FOLDER: 'color-mix(in srgb, var(--fw-brand) 10%, transparent)',
}
const DEFAULT_EDGE_COLOR = 'rgba(190, 140, 220, 0.24)'

// soft modern palette by node label; the CBM per-node color is only a
// fallback so the view stays consistent with the SPA theme
const LABEL_COLORS = {
  File: '#f59e0b',
  Module: '#2dd4bf',
  Function: '#34d399',
  Project: '#a78bfa',
  Branch: '#fb923c',
  Folder: '#38bdf8',
}

function rebuild () {
  nodeById = new Map()
  const enabled = new Set(props.types)
  visible = props.nodes.filter(n => enabled.size === 0 || enabled.has(n.label))
  for (const n of visible) nodeById.set(n.id, n)
  dirty = true
}

function fit () {
  if (!visible.length) return
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity
  for (const n of visible) {
    if (n.x < minX) minX = n.x
    if (n.x > maxX) maxX = n.x
    if (n.y < minY) minY = n.y
    if (n.y > maxY) maxY = n.y
  }
  const w = Math.max(maxX - minX, 1)
  const h = Math.max(maxY - minY, 1)
  transform.scale = Math.min(viewW / w, viewH / h) * 0.9
  transform.ox = viewW / 2 - (minX + w / 2) * transform.scale
  transform.oy = viewH / 2 - (minY + h / 2) * transform.scale
  dirty = true
}

function toScreen (x, y) {
  return [x * transform.scale + transform.ox, y * transform.scale + transform.oy]
}

function radius (n) {
  return Math.max(1.5, Math.min(9, (n.size || 5) * 0.55)) *
    Math.max(0.6, Math.min(2.5, transform.scale * 0.09))
}

function render () {
  rafId = 0
  if (!dirty || !ctx) return
  dirty = false
  ctx.save()
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  ctx.fillStyle = '#f7f8fa'
  ctx.fillRect(0, 0, viewW, viewH)
  ctx.fillStyle = 'rgba(19, 76, 255, 0.10)'
  const grid = 28
  for (let gx = (transform.ox % grid + grid) % grid; gx < viewW; gx += grid) {
    for (let gy = (transform.oy % grid + grid) % grid; gy < viewH; gy += grid) {
      ctx.fillRect(gx, gy, 1.2, 1.2)
    }
  }

  const hl = (props.highlight || '').trim().toLowerCase()
  const margin = 24
  const inView = (n) => {
    const [sx, sy] = toScreen(n.x, n.y)
    return sx > -margin && sx < viewW + margin && sy > -margin && sy < viewH + margin
  }

  // edges, batched one stroke per color bucket
  const buckets = new Map()
  for (const e of props.edges) {
    const s = nodeById.get(e.source)
    const t = nodeById.get(e.target)
    if (!s || !t) continue
    if (!inView(s) && !inView(t)) continue
    const color = EDGE_COLORS[e.type] || DEFAULT_EDGE_COLOR
    let list = buckets.get(color)
    if (!list) buckets.set(color, (list = []))
    list.push([s, t])
  }
  ctx.lineWidth = 0.7
  for (const [color, list] of buckets) {
    ctx.strokeStyle = color
    ctx.beginPath()
    for (const [s, t] of list) {
      const [x1, y1] = toScreen(s.x, s.y)
      const [x2, y2] = toScreen(t.x, t.y)
      ctx.moveTo(x1, y1)
      ctx.lineTo(x2, y2)
    }
    ctx.stroke()
  }

  // nodes
  const showLabels = transform.scale >= 2.2
  for (const n of visible) {
    if (!inView(n)) continue
    const [sx, sy] = toScreen(n.x, n.y)
    const r = radius(n)
    const isHl = hl && (n.name || '').toLowerCase().includes(hl)
    ctx.beginPath()
    ctx.arc(sx, sy, isHl ? r + 2.5 : r, 0, Math.PI * 2)
    ctx.fillStyle = LABEL_COLORS[n.label] || n.color || '#38bdf8'
    ctx.fill()
    ctx.lineWidth = 0.8
    ctx.strokeStyle = 'rgba(8, 15, 28, 0.55)'
    ctx.stroke()
    if (isHl) {
      ctx.lineWidth = 1.6
      ctx.strokeStyle = '#dc2626'
      ctx.stroke()
    }
    if (selected && selected.id === n.id) {
      ctx.beginPath()
      ctx.arc(sx, sy, r + 4, 0, Math.PI * 2)
      ctx.lineWidth = 1.8
      ctx.strokeStyle = '#38bdf8'
      ctx.stroke()
    }
    if ((isHl || showLabels || (selected && selected.id === n.id)) && n.name) {
      ctx.fillStyle = '#e8eef8'
      ctx.font = '10px sans-serif'
      ctx.fillText(n.name.length > 40 ? n.name.slice(0, 39) + '…' : n.name, sx + r + 2, sy + 3)
    }
  }
  ctx.restore()
}

function schedule () {
  dirty = true
  if (!rafId) rafId = requestAnimationFrame(render)
}

function resize () {
  if (!wrap.value || !canvas.value) return
  dpr = window.devicePixelRatio || 1
  viewW = wrap.value.clientWidth
  viewH = wrap.value.clientHeight
  canvas.value.width = viewW * dpr
  canvas.value.height = viewH * dpr
  canvas.value.style.width = viewW + 'px'
  canvas.value.style.height = viewH + 'px'
  schedule()
}

function onWheel (e) {
  const rect = canvas.value.getBoundingClientRect()
  const mx = e.clientX - rect.left
  const my = e.clientY - rect.top
  const factor = e.deltaY < 0 ? 1.18 : 1 / 1.18
  const wx = (mx - transform.ox) / transform.scale
  const wy = (my - transform.oy) / transform.scale
  transform.scale = Math.max(0.02, Math.min(60, transform.scale * factor))
  transform.ox = mx - wx * transform.scale
  transform.oy = my - wy * transform.scale
  schedule()
}

function onDown (e) {
  drag.active = true
  drag.moved = false
  drag.x = e.clientX
  drag.y = e.clientY
}

function onMove (e) {
  if (!drag.active) return
  const dx = e.clientX - drag.x
  const dy = e.clientY - drag.y
  if (Math.abs(dx) + Math.abs(dy) > 2) drag.moved = true
  transform.ox += dx
  transform.oy += dy
  drag.x = e.clientX
  drag.y = e.clientY
  schedule()
}

function onUp () { drag.active = false }

function onClick (e) {
  if (drag.moved) return
  const rect = canvas.value.getBoundingClientRect()
  const mx = e.clientX - rect.left
  const my = e.clientY - rect.top
  let best = null
  let bestD = Infinity
  for (const n of visible) {
    const [sx, sy] = toScreen(n.x, n.y)
    const d = (sx - mx) ** 2 + (sy - my) ** 2
    if (d < bestD) { bestD = d; best = n }
  }
  if (best && bestD <= Math.max(100, radius(best) ** 2 * 4)) {
    selected = best
    emit('select', best)
  } else {
    selected = null
    emit('select', null)
  }
  schedule()
}

let observer = null
onMounted(() => {
  ctx = canvas.value.getContext('2d')
  observer = new ResizeObserver(() => { resize(); fit() })
  observer.observe(wrap.value)
  resize()
  rebuild()
  fit()
})
onBeforeUnmount(() => {
  if (observer) observer.disconnect()
  if (rafId) cancelAnimationFrame(rafId)
})

watch(() => [props.nodes, props.edges], () => { rebuild(); fit() }, { deep: false })
watch(() => props.types, rebuild)
watch(() => props.highlight, schedule)
watch(() => props.fitSignal, fit)
</script>

<style scoped>
.graph-canvas-wrap {
  width: 100%;
  height: 66vh;
  border: 1px solid color-mix(in srgb, var(--fw-brand) 25%, transparent);
  border-radius: 6px;
  overflow: hidden;
  background: var(--fw-bg-2);
  box-shadow: inset 0 0 30px color-mix(in srgb, var(--fw-brand) 06%, transparent);
}
canvas { display: block; cursor: grab; }
canvas:active { cursor: grabbing; }
</style>
