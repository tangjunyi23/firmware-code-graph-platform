<template>
  <div class="codediff">
    <div class="diff-head">
      <div class="diff-col-title">{{ leftTitle }}</div>
      <div class="diff-col-title">{{ rightTitle }}</div>
    </div>
    <div class="diff-meta">
      <span class="stat stat-add">+{{ adds }}</span>
      <span class="stat stat-del">−{{ dels }}</span>
      <span class="legend">
        <i class="sw sw-add"></i>优化后新增/变更行
        <i class="sw sw-del"></i>优化前被替换行
      </span>
      <span v-if="fallback" class="muted">（内容过大，未做行间对齐）</span>
    </div>
    <div class="diff-body">
      <div ref="leftPane" class="diff-pane" @scroll.passive="onScrollLeft">
        <div class="diff-inner">
          <div
            v-for="(row, i) in rows"
            :key="i"
            class="diff-line"
            :class="row.leftCls"
          >
            <span class="ln">{{ row.leftNo ?? '' }}</span>
            <span class="code">{{ row.leftText }}</span>
          </div>
        </div>
      </div>
      <div ref="rightPane" class="diff-pane" @scroll.passive="onScrollRight">
        <div class="diff-inner">
          <div
            v-for="(row, i) in rows"
            :key="i"
            class="diff-line"
            :class="row.rightCls"
          >
            <span class="ln">{{ row.rightNo ?? '' }}</span>
            <span class="code">{{ row.rightText }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'

// Side-by-side line diff for decompiled-vs-AI-enriched pseudo-C.
// highlight.js is NOT used here on purpose: per-line rendering would break
// tokens spanning lines, and the diff coloring is the point of this view.
// Text goes through {{ }} interpolation (auto-escaped), never v-html.

const props = defineProps({
  original: { type: String, default: '' },
  enriched: { type: String, default: '' },
  leftTitle: { type: String, default: '优化前 · Hex-Rays 原始伪代码' },
  rightTitle: { type: String, default: '优化后 · AI 增强伪代码' }
})

const LCS_LIMIT = 4000000 // n*m guard; real functions are a few hundred lines

function splitLines (text) {
  if (!text) return []
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n')
}

// Classic LCS on lines. Common prefix/suffix is trimmed first so the
// O(n·m) table only spans the changed middle of the file.
function buildRows (aLines, bLines) {
  let lo = 0
  while (lo < aLines.length && lo < bLines.length && aLines[lo] === bLines[lo]) lo++
  let hiA = aLines.length
  let hiB = bLines.length
  while (hiA > lo && hiB > lo && aLines[hiA - 1] === bLines[hiB - 1]) { hiA--; hiB-- }
  const midA = aLines.slice(lo, hiA)
  const midB = bLines.slice(lo, hiB)
  const ops = [] // {type: 'eq'|'del'|'add', text}
  let fallback = false
  if (midA.length * midB.length <= LCS_LIMIT) {
    const n = midA.length
    const m = midB.length
    const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1))
    for (let i = n - 1; i >= 0; i--) {
      const row = dp[i]
      const next = dp[i + 1]
      for (let j = m - 1; j >= 0; j--) {
        row[j] = midA[i] === midB[j] ? next[j + 1] + 1 : Math.max(next[j], row[j + 1])
      }
    }
    let i = 0
    let j = 0
    while (i < n && j < m) {
      if (midA[i] === midB[j]) { ops.push({ type: 'eq', text: midA[i] }); i++; j++ } else if (dp[i + 1][j] >= dp[i][j + 1]) { ops.push({ type: 'del', text: midA[i] }); i++ } else { ops.push({ type: 'add', text: midB[j] }); j++ }
    }
    while (i < n) ops.push({ type: 'del', text: midA[i++] })
    while (j < m) ops.push({ type: 'add', text: midB[j++] })
  } else {
    fallback = true // oversized: still show both sides, just unaligned
    for (const t of midA) ops.push({ type: 'del', text: t })
    for (const t of midB) ops.push({ type: 'add', text: t })
  }
  const rows = []
  let adds = 0
  let dels = 0
  let aNo = 0
  let bNo = 0
  const pushEq = (t) => {
    rows.push({ leftNo: ++aNo, leftText: t, rightNo: ++bNo, rightText: t,
                leftCls: '', rightCls: '' })
  }
  // A run of del+add ops is one change hunk; zip it pairwise so removed
  // lines (red, left) face their replacements (green, right) on the same
  // visual row instead of forming two separate blocks.
  const pushRun = (ds, as) => {
    const n = Math.max(ds.length, as.length)
    for (let k = 0; k < n; k++) {
      const d = ds[k]
      const a = as[k]
      rows.push({
        leftNo: d === undefined ? null : ++aNo,
        leftText: d === undefined ? '' : d,
        leftCls: d === undefined ? 'line-gap' : 'line-del',
        rightNo: a === undefined ? null : ++bNo,
        rightText: a === undefined ? '' : a,
        rightCls: a === undefined ? 'line-gap' : 'line-add'
      })
    }
  }
  for (let k = 0; k < lo; k++) pushEq(aLines[k])
  let i = 0
  while (i < ops.length) {
    if (ops[i].type === 'eq') { pushEq(ops[i].text); i++; continue }
    const ds = []
    const as = []
    while (i < ops.length && ops[i].type !== 'eq') {
      if (ops[i].type === 'del') { ds.push(ops[i].text); dels++ } else { as.push(ops[i].text); adds++ }
      i++
    }
    pushRun(ds, as)
  }
  for (let k = hiA; k < aLines.length; k++) pushEq(aLines[k])
  return { rows, adds, dels, fallback }
}

const diff = computed(() => buildRows(splitLines(props.original), splitLines(props.enriched)))
const rows = computed(() => diff.value.rows)
const adds = computed(() => diff.value.adds)
const dels = computed(() => diff.value.dels)
const fallback = computed(() => diff.value.fallback)

// Mirror scroll between the two panes; the rAF-flag breaks the feedback
// loop that programmatic scrollTop assignment would otherwise cause.
const leftPane = ref(null)
const rightPane = ref(null)
let syncing = false

function mirror (src, dst) {
  if (syncing || !dst) return
  syncing = true
  dst.scrollTop = src.scrollTop
  dst.scrollLeft = src.scrollLeft
  requestAnimationFrame(() => { syncing = false })
}

function onScrollLeft () { mirror(leftPane.value, rightPane.value) }
function onScrollRight () { mirror(rightPane.value, leftPane.value) }
</script>

<style scoped>
.codediff { border: 1px solid rgba(43, 108, 229, .25); border-radius: 8px; background: #ffffff; overflow: hidden; }
.diff-head { display: flex; border-bottom: 1px solid rgba(43, 108, 229, .22); background: #f4f8fd; }
.diff-col-title { flex: 1; padding: 8px 12px; font-size: 13px; font-weight: 600; color: #2b6ce5; letter-spacing: .5px; }
.diff-col-title + .diff-col-title { border-left: 1px solid rgba(43, 108, 229, .22); }
.diff-meta { display: flex; align-items: center; gap: 10px; padding: 6px 12px; border-bottom: 1px solid rgba(43, 108, 229, .22); font-size: 12px; color: #64748f; }
.stat { font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace; font-weight: 600; }
.stat-add { color: #16a34a; }
.stat-del { color: #dc2626; }
.legend { display: inline-flex; align-items: center; gap: 4px; }
.sw { display: inline-block; width: 12px; height: 12px; border-radius: 2px; margin-left: 8px; }
.sw-add { background: rgba(22, 163, 74, 0.22); border: 1px solid rgba(22, 163, 74, 0.55); }
.sw-del { background: rgba(220, 38, 38, 0.2); border: 1px solid rgba(220, 38, 38, 0.55); }
.muted { color: #8b9cb3; }
.diff-body { display: flex; height: 640px; }
.diff-pane { flex: 1; overflow: auto; background: #ffffff; }
.diff-pane + .diff-pane { border-left: 1px solid rgba(43, 108, 229, .22); }
.diff-inner { min-width: 100%; width: max-content; padding: 6px 0; }
.diff-line {
  display: flex;
  height: 20px;
  line-height: 20px;
  font-family: 'JetBrains Mono', ui-monospace, Consolas, 'Courier New', monospace;
  font-size: 12.5px;
}
.ln {
  flex: 0 0 46px;
  padding-right: 8px;
  text-align: right;
  color: #8b9cb3;
  background: #f4f8fd;
  user-select: none;
}
.code { flex: 1; white-space: pre; padding: 0 12px 0 8px; color: #3d5470; }
.line-del { background: rgba(220, 38, 38, 0.13); }
.line-del .ln { background: rgba(220, 38, 38, 0.2); color: #dc2626; }
.line-add { background: rgba(22, 163, 74, 0.11); }
.line-add .ln { background: rgba(22, 163, 74, 0.18); color: #16a34a; }
.line-gap { background: rgba(43, 108, 229, 0.05); }
.line-gap .ln { background: #f4f8fd; }
@media (max-width: 720px) {
  .diff-body { height: 480px; }
}
</style>
