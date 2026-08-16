<template>
  <el-button size="small" :icon="Sparkles" :disabled="!jobId" @click="openDialog">
    运行 AI 增强
  </el-button>
  <span v-if="running" class="enrich-running">AI 增强进行中…</span>
  <el-dialog v-model="dialog" title="运行 AI 增强" width="500px" append-to-body>
    <el-alert
      type="info"
      :closable="false"
      class="tip"
      title="AI 增强对伪代码做参数恢复与可读化重命名，供攻击面与调用链分析参考；漏洞挖掘的证据引用仍以原始伪代码的地址与函数名为准（调用 LLM，消耗 token，每日有配额）。"
    />
    <el-form label-width="110px">
      <el-form-item label="目标二进制">
        <el-select v-model="md5" filterable placeholder="选择二进制" style="width: 100%">
          <el-option
            v-for="b in binaries"
            :key="b.md5"
            :value="b.md5"
            :label="`${b.path || b.md5}（${b.total} 函数）`"
          />
        </el-select>
      </el-form-item>
      <el-form-item label="增强范围">
        <el-checkbox v-model="attackOnly">仅攻击面相关函数（推荐，省 token）</el-checkbox>
      </el-form-item>
      <el-form-item label="函数上限">
        <el-input-number v-model="limit" :min="0" :max="500" />
        <span class="muted" style="margin-left: 8px">0 = 不限制</span>
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="dialog = false">取消</el-button>
      <el-button type="primary" :loading="starting" @click="start">开始增强</el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Sparkles } from '@lucide/vue'
import { api } from '../api'

// AI 增强触发器：按钮 + 参数对话框 + 完成轮询。嵌入攻击面/函数等分析视图，
// 增强产物（ai/<addr>.c 可读化覆盖层）只服务攻击面与调用链分析，不回喂漏洞挖掘 AI。
const props = defineProps({ jobId: { type: String, default: '' } })
const emit = defineEmits(['done'])

const dialog = ref(false)
const binaries = ref([])
const md5 = ref('')
const attackOnly = ref(true)
const limit = ref(0)
const starting = ref(false)
const running = ref(false)
let timer = null

async function openDialog () {
  if (!props.jobId) return
  dialog.value = true
  try {
    const data = await api(`/jobs/${props.jobId}/aienrich`)
    binaries.value = data.binaries || []
    if (!md5.value || !binaries.value.some(b => b.md5 === md5.value)) {
      md5.value = (binaries.value[0] && binaries.value[0].md5) || ''
    }
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function start () {
  if (!md5.value) {
    ElMessage.warning('请选择目标二进制')
    return
  }
  starting.value = true
  try {
    await api(`/jobs/${props.jobId}/aienrich`, {
      method: 'POST',
      body: {
        binary_md5: md5.value,
        attack_only: attackOnly.value,
        include_failed: true,
        limit: limit.value || 0
      }
    })
    ElMessage.success('AI 增强已启动，完成后自动刷新')
    dialog.value = false
    running.value = true
    poll(md5.value)
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    starting.value = false
  }
}

function poll (target) {
  const startedAt = Date.now()
  const tick = async () => {
    try {
      const data = await api(`/jobs/${props.jobId}/aienrich`)
      const b = (data.binaries || []).find(x => x.md5 === target)
      if ((b && b.count > 0) || Date.now() - startedAt > 8 * 60 * 1000) {
        running.value = false
        if (b && b.count > 0) {
          ElMessage.success('AI 增强完成')
          emit('done')
        }
        return
      }
    } catch { /* 轮询偶发失败下一拍重试 */ }
    timer = setTimeout(tick, 5000)
  }
  timer = setTimeout(tick, 5000)
}

onUnmounted(() => { if (timer) clearTimeout(timer) })
</script>

<style scoped>
.enrich-running { color: #2b6ce5; font-size: 12px; animation: enrichPulse 1.6s ease-in-out infinite; }
.tip { margin-bottom: 12px; }
.muted { color: #64748f; font-size: 12px; }
@keyframes enrichPulse { 0%, 100% { opacity: 1; } 50% { opacity: .45; } }
</style>
