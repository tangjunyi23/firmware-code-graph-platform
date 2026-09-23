<template>
  <Transition name="pipe-in">
    <div v-if="visible" class="end-card">
      <div class="end-inner">
        <div class="end-head">
          <span class="end-ico">📄</span>
          <div class="end-title">
            <b>本轮挖掘报告已生成</b>
            <span>
              <template v-if="count > 0">{{ count }} 项发现已入库（{{ sevLine }}）。</template>
              <template v-else>本轮未记录发现，报告含完整过程与排除项。</template>
              完整调用链、PoC 与验证记录请前往报告中心查看。
            </span>
          </div>
        </div>
        <div class="end-actions">
          <button type="button" class="end-btn primary" @click="goReports">
            前往报告中心查看完整报告
          </button>
          <button type="button" class="end-btn ghost" @click="newHunt">
            开始新一轮挖掘
          </button>
        </div>
      </div>
    </div>
  </Transition>
</template>

<script setup>
import { computed, inject } from 'vue'
import { t } from './locales.js'

const emit = defineEmits(['new-hunt'])
const session = inject('wbSession')
const catalog = inject('wbCatalog', null)

const visible = computed(() => {
  const st = session?.state
  if (!st) return false
  // 终局两态都给报告入口：done，或已转"等待模拟确认"（用户反馈
  // awaiting 时看不到跳报告中心的卡片——2026-09-23）
  if (st.huntStatus === 'done') return Number(st.turns || 0) > 0
  return st.huntStatus === 'awaiting_continue'
    && String(st.awaitNote || '').includes('固件模拟')
})
const findings = computed(() => session?.state?.findings || [])
const count = computed(() => findings.value.length)
const sevLine = computed(() => {
  const rows = {}
  for (const f of findings.value) {
    const s = f.severity || f.level || '未分级'
    rows[s] = (rows[s] || 0) + 1
  }
  const order = ['critical', '严重', 'high', '高危', 'medium', '中危', 'low', '低危']
  return Object.keys(rows).sort((a, b) =>
    (order.findIndex((k) => a.startsWith(k)) + 99) % 99
    - (order.findIndex((k) => b.startsWith(k)) + 99) % 99)
    .map((k) => `${k}×${rows[k]}`).join('、') || '—'
})

function goReports () {
  // App 由 ?page= 驱动；带上 token 上下文由 api 层 localStorage 维持
  const url = new URL(window.location.href)
  url.searchParams.set('page', 'reports')
  window.location.href = url.toString()
}
function newHunt () {
  emit('new-hunt')
}
</script>

<style scoped>
.end-card {
  max-width: var(--dsh-chat-content-width, 1080px);
  margin: 0 auto 10px;
  padding: 10px calc(var(--dsh-composer-side-clearance, 16px) + 16px) 0;
}
.end-inner {
  border: 1px solid rgba(22, 163, 74, .35);
  background: linear-gradient(180deg, rgba(22, 163, 74, .09), rgba(22, 163, 74, .03));
  border-radius: 14px;
  padding: 14px 16px;
}
.end-head { display: flex; gap: 12px; align-items: flex-start; }
.end-ico { font-size: 20px; line-height: 1.2; }
.end-title { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.end-title b { font-size: 14px; }
.end-title span { font-size: 12.5px; opacity: .75; line-height: 1.55; }
.end-actions { display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }
.end-btn {
  border: none; border-radius: 10px; padding: 8px 16px;
  font-size: 13px; font-weight: 600; cursor: pointer;
}
.end-btn.primary { background: #16a34a; color: #fff; }
.end-btn.primary:hover { background: #15803d; }
.end-btn.ghost { background: transparent; color: inherit; border: 1px solid rgba(128, 128, 128, .4); }
[data-wb-theme='dark'] .end-inner { border-color: rgba(74, 222, 128, .4); }
</style>
