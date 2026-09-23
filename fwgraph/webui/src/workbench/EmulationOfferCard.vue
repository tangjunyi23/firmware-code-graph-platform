<template>
  <Transition name="pipe-in">
    <div v-if="visible" class="emu-card">
      <div class="emu-head">
        <span class="emu-ico">🧪</span>
        <div class="emu-title">
          <b>挖掘完成 · 固件模拟真实测试</b>
          <span>{{ note || '静态与动态验证已闭环，可在真实服务环境中验证 PoC 落地。' }}</span>
        </div>
      </div>
      <div class="emu-actions">
        <button
          type="button"
          class="emu-btn primary"
          :disabled="busy"
          @click="accept"
        >{{ busy ? '正在发起…' : '发起模拟测试' }}</button>
        <button
          type="button"
          class="emu-btn ghost"
          :disabled="busy"
          @click="decline"
        >跳过，仅收尾</button>
      </div>
      <p v-if="error" class="emu-err">{{ error }}</p>
    </div>
  </Transition>
</template>

<script setup>
import { computed, inject, ref } from 'vue'
import { HUNT_TURNS } from './pipeline.js'

const emit = defineEmits(['answered'])
const session = inject('wbSession')
const busy = ref(false)
const error = ref('')

// awaiting_continue 且来自模拟询问（autopilot 写入 await_note）时显示，
// 与 ContinueCapPanel 互斥：轮次上限面板让位。
const visible = computed(() => {
  const st = session?.state
  return !!st && st.huntStatus === 'awaiting_continue'
    && String(st.awaitNote || st.await_note || '').includes('固件模拟')
})
const note = computed(() => {
  const st = session?.state
  return String(st?.awaitNote || st?.await_note || '')
})

async function answer (text) {
  if (busy.value) return
  busy.value = true
  error.value = ''
  try {
    await session.continueHunt(HUNT_TURNS, text)
    emit('answered', text)
  } catch (err) {
    error.value = err?.message || '操作失败，请重试'
  } finally {
    busy.value = false
  }
}
function accept () { answer('同意进行固件模拟真实测试。') }
function decline () { answer('不进行固件模拟，直接收尾即可。') }
</script>

<style scoped>
.emu-card {
  max-width: var(--dsh-chat-content-width, 1080px);
  margin: 0 auto 10px;
  padding: 10px calc(var(--dsh-composer-side-clearance, 16px) + 16px) 0;
}
.emu-card > div {
  border: 1px solid rgba(59, 130, 246, .35);
  background: linear-gradient(180deg, rgba(59, 130, 246, .10), rgba(59, 130, 246, .04));
  border-radius: 14px;
  padding: 14px 16px;
}
.emu-head { display: flex; gap: 12px; align-items: flex-start; }
.emu-ico { font-size: 20px; line-height: 1.2; }
.emu-title { display: flex; flex-direction: column; gap: 3px; min-width: 0; }
.emu-title b { font-size: 14px; }
.emu-title span { font-size: 12.5px; opacity: .75; }
.emu-actions { display: flex; gap: 10px; margin-top: 12px; }
.emu-btn {
  border: none; border-radius: 10px; padding: 8px 16px;
  font-size: 13px; font-weight: 600; cursor: pointer;
}
.emu-btn.primary { background: #2563eb; color: #fff; }
.emu-btn.primary:hover { background: #1d4ed8; }
.emu-btn.ghost { background: transparent; color: inherit; border: 1px solid rgba(128, 128, 128, .4); }
.emu-btn:disabled { opacity: .55; cursor: default; }
.emu-err { margin: 8px 0 0; font-size: 12px; color: #e11d48; }
[data-wb-theme='dark'] .emu-card > div { border-color: rgba(96, 165, 250, .4); }
</style>
