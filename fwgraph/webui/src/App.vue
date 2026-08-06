<template>
  <div class="page">
    <!-- login card -->
    <div v-if="!token" class="login-wrap">
      <el-card class="login-card">
        <h2>固件代码图谱</h2>
        <p class="muted">请输入 orchestrator 的访问 token（ORCH_TOKEN）</p>
        <el-input
          v-model="tokenInput"
          type="password"
          show-password
          placeholder="Bearer token"
          @keyup.enter="login"
        />
        <el-button type="primary" class="login-btn" @click="login">登 录</el-button>
        <el-alert v-if="loginError" :title="loginError" type="error" :closable="false" />
      </el-card>
    </div>

    <!-- main shell -->
    <template v-else>
      <header class="topbar">
        <span class="brand">固件代码图谱 <span class="muted">fwgraph</span></span>
        <el-button size="small" text @click="logout">退出登录</el-button>
      </header>
      <el-tabs v-model="tab" class="main-tabs">
        <el-tab-pane label="任务" name="jobs" lazy>
          <JobsView @open-functions="openFunctions" />
        </el-tab-pane>
        <el-tab-pane label="函数" name="functions" lazy>
          <FunctionsView ref="functionsView" />
        </el-tab-pane>
        <el-tab-pane label="攻击面" name="attack" lazy>
          <AttackView />
        </el-tab-pane>
        <el-tab-pane label="增强对比" name="enrich" lazy>
          <EnrichView />
        </el-tab-pane>
        <el-tab-pane label="漏洞挖掘" name="vuln" lazy>
          <VulnView />
        </el-tab-pane>
        <el-tab-pane label="图谱" name="graph" lazy>
          <GraphView />
        </el-tab-pane>
      </el-tabs>
    </template>
  </div>
</template>

<script setup>
import { defineAsyncComponent, nextTick, ref, watch } from 'vue'
import { getToken, setToken, clearToken, api } from './api'

const JobsView = defineAsyncComponent(() => import('./views/JobsView.vue'))
const FunctionsView = defineAsyncComponent(() => import('./views/FunctionsView.vue'))
const AttackView = defineAsyncComponent(() => import('./views/AttackView.vue'))
const EnrichView = defineAsyncComponent(() => import('./views/EnrichView.vue'))
const VulnView = defineAsyncComponent(() => import('./views/VulnView.vue'))
const GraphView = defineAsyncComponent(() => import('./views/GraphView.vue'))

const token = ref(getToken())
const tokenInput = ref('')
const loginError = ref('')
const tab = ref('jobs')
const functionsView = ref(null)
const pendingFunctionJob = ref('')

async function login () {
  loginError.value = ''
  if (!tokenInput.value) return
  setToken(tokenInput.value.trim())
  try {
    await api('/jobs') // validate the token against a real endpoint
    token.value = getToken()
  } catch (e) {
    clearToken()
    loginError.value = e.message || '登录失败'
  }
}

function logout () {
  clearToken()
  token.value = ''
  tokenInput.value = ''
}

function loadPendingFunctionJob () {
  if (!functionsView.value || !pendingFunctionJob.value) return
  const jobId = pendingFunctionJob.value
  pendingFunctionJob.value = ''
  functionsView.value.loadJob(jobId)
}

async function openFunctions (jobId) {
  pendingFunctionJob.value = jobId
  tab.value = 'functions'
  await nextTick()
  loadPendingFunctionJob()
}

watch(functionsView, loadPendingFunctionJob)
</script>

<style>
body { margin: 0; font-family: -apple-system, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif; background: #f5f7fa; }
.page { max-width: 1280px; margin: 0 auto; padding: 12px 16px 40px; }
.login-wrap { display: flex; justify-content: center; padding-top: 12vh; }
.login-card { width: 380px; }
.login-card h2 { margin: 0 0 4px; }
.login-btn { width: 100%; margin: 12px 0; }
.muted { color: #909399; font-size: 13px; }
.topbar { display: flex; justify-content: space-between; align-items: center; padding: 4px 0 8px; }
.brand { font-size: 18px; font-weight: 600; }
.main-tabs .el-tabs__content { overflow: visible; }
.mono, pre { font-family: 'JetBrains Mono', Consolas, 'Courier New', monospace; }
</style>
