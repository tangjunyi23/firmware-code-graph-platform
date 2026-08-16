<template>
  <div class="app-root">
    <!-- ===== 登录页 ===== -->
    <div v-if="!token" class="login-wrap">
      <div class="login-brand">
        <h1 class="login-title">固件攻击面分析平台</h1>
        <p class="login-slogan">FWGraph · 固件解包 / 代码图谱 / 攻击面分析 / 智能漏洞挖掘</p>
      </div>
      <el-card class="login-card">
        <h2>登 录</h2>
        <el-input
          v-model="loginForm.username"
          placeholder="用户名"
          class="login-field"
          @keyup.enter="doLogin"
        >
          <template #prefix><el-icon><User /></el-icon></template>
        </el-input>
        <el-input
          v-model="loginForm.password"
          type="password"
          show-password
          placeholder="密码"
          class="login-field"
          @keyup.enter="doLogin"
        >
          <template #prefix><el-icon><Lock /></el-icon></template>
        </el-input>
        <el-button type="primary" class="login-btn" :loading="loginLoading" @click="doLogin">
          登 录
        </el-button>
        <el-alert v-if="loginError" :title="loginError" type="error" :closable="false" />
        <el-collapse class="token-collapse">
          <el-collapse-item title="使用访问令牌登录" name="token">
            <el-input
              v-model="tokenInput"
              type="password"
              show-password
              placeholder="Bearer token"
              @keyup.enter="tokenLogin"
            />
            <el-button class="login-btn" :loading="loginLoading" @click="tokenLogin">
              令牌登录
            </el-button>
          </el-collapse-item>
        </el-collapse>
      </el-card>
    </div>

    <!-- ===== 主壳 ===== -->
    <div v-else class="shell">
      <aside class="sidebar" :class="{ collapsed }">
        <div class="side-brand" @click="go(defaultPage)">
          <span class="logo-dot"></span>
          <span v-if="!collapsed" class="side-brand-text">FWGraph</span>
        </div>
        <el-menu
          :default-active="page"
          class="side-menu"
          :collapse="collapsed"
          @select="go"
        >
          <template v-for="item in menuItems" :key="item.index || item.group">
            <el-sub-menu v-if="item.group" :index="item.group">
              <template #title>
                <el-icon><component :is="item.icon" /></el-icon>
                <span>{{ item.title }}</span>
              </template>
              <el-menu-item v-for="child in item.children" :key="child.index" :index="child.index">
                <el-icon><component :is="child.icon" /></el-icon>
                <span>{{ child.title }}</span>
              </el-menu-item>
            </el-sub-menu>
            <el-menu-item v-else :index="item.index">
              <el-icon><component :is="item.icon" /></el-icon>
              <span>{{ item.title }}</span>
            </el-menu-item>
          </template>
        </el-menu>
      </aside>

      <div class="main">
        <header class="topbar">
          <div class="topbar-left">
            <span class="page-title">{{ pageTitle }}</span>
          </div>
          <div class="topbar-right">
            <el-segmented
              v-model="mode"
              :options="modeOptions"
              size="small"
              @change="onModeChange"
            />
            <el-dropdown trigger="click" @command="onUserCommand">
              <span class="user-chip">
                <el-icon><User /></el-icon>
                <span class="user-name">{{ principal?.username || '用户' }}</span>
                <el-tag size="small" :type="isAdmin ? 'warning' : 'info'" effect="dark">
                  {{ principal?.role === 'admin' ? '管理员' : '普通用户' }}
                </el-tag>
                <el-icon class="muted"><ArrowDown /></el-icon>
              </span>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="password">
                    <el-icon><Key /></el-icon>修改密码
                  </el-dropdown-item>
                  <el-dropdown-item command="logout" divided>
                    <el-icon><SwitchButton /></el-icon>退出登录
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </div>
        </header>

        <main class="content">
          <transition name="fade">
            <div :key="page" class="page-pane">
              <DashboardView v-if="page === 'dashboard'" @goto="go" />
              <JobsView
                v-else-if="page === 'jobs'"
                :mode="mode"
                @open-functions="openFunctions"
                @goto="go"
              />
              <FunctionsView v-else-if="page === 'functions'" ref="functionsView" />
              <AttackView v-else-if="page === 'attack'" />
              <InputsView v-else-if="page === 'inputs'" />
              <GraphView v-else-if="page === 'graph'" />
              <VulnView v-else-if="page === 'vuln'" />
              <ProtofuzzView v-else-if="page === 'protofuzz'" />
              <ReportsView v-else-if="page === 'reports'" />
              <UsersView v-else-if="page === 'users'" />
              <LogsView v-else-if="page === 'logs'" :is-admin="isAdmin" />
              <SettingsView v-else-if="page === 'settings'" :is-admin="isAdmin" />
            </div>
          </transition>
        </main>
      </div>
    </div>

    <!-- 修改密码（pwdForced 时为首次登录强制改密，不可关闭） -->
    <el-dialog v-model="pwdVisible" :title="pwdForced ? '首次登录请修改密码' : '修改密码'" width="400px" append-to-body
               :show-close="!pwdForced" :close-on-click-modal="false" :close-on-press-escape="!pwdForced">
      <el-alert v-if="pwdForced" type="warning" :closable="false" class="pwd-alert"
                title="首次登录，必须修改密码后才能继续使用（新密码至少 10 位）" />
      <el-form label-width="80px">
        <el-form-item label="原密码">
          <el-input v-model="pwdForm.old" type="password" show-password />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="pwdForm.new" type="password" show-password placeholder="至少 10 位" />
        </el-form-item>
        <el-form-item label="确认新密码">
          <el-input v-model="pwdForm.confirm" type="password" show-password />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button v-if="!pwdForced" @click="pwdVisible = false">取消</el-button>
        <el-button type="primary" :loading="pwdLoading" @click="submitPassword">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, defineAsyncComponent, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import {
  getToken, setToken, clearToken, api,
  login as apiLogin, logout as apiLogout, fetchMe, changePassword,
  setUnauthorizedHandler
} from './api'

const DashboardView = defineAsyncComponent(() => import('./views/DashboardView.vue'))
const JobsView = defineAsyncComponent(() => import('./views/JobsView.vue'))
const FunctionsView = defineAsyncComponent(() => import('./views/FunctionsView.vue'))
const AttackView = defineAsyncComponent(() => import('./views/AttackView.vue'))
const InputsView = defineAsyncComponent(() => import('./views/InputsView.vue'))
const VulnView = defineAsyncComponent(() => import('./views/VulnView.vue'))
const ProtofuzzView = defineAsyncComponent(() => import('./views/ProtofuzzView.vue'))
const GraphView = defineAsyncComponent(() => import('./views/GraphView.vue'))
const ReportsView = defineAsyncComponent(() => import('./views/ReportsView.vue'))
const UsersView = defineAsyncComponent(() => import('./views/UsersView.vue'))
const LogsView = defineAsyncComponent(() => import('./views/LogsView.vue'))
const SettingsView = defineAsyncComponent(() => import('./views/SettingsView.vue'))

// ---- deep links: ?token= (fws- session tokens only), ?page= / ?tab=, ?mode= --
const qs = new URLSearchParams(window.location.search)
const qsToken = (qs.get('token') || '').trim()
let deepLinkError = ''
if (qsToken) {
  // 深链只接受 fws- 会话 token；主令牌（ORCH_TOKEN 等）经 URL 传递一律拒绝，
  // 后端对非 fws- 的 URL token 同样会 401
  if (qsToken.startsWith('fws-')) {
    setToken(qsToken)
  } else {
    deepLinkError = '主令牌不允许通过 URL 传递，请使用账号密码登录'
  }
  // 无论接受与否，消费后立即从地址栏抹掉 token，避免留在历史记录/分享链接里
  const cleanUrl = new URL(window.location.href)
  cleanUrl.searchParams.delete('token')
  window.history.replaceState(null, '', cleanUrl)
}

const MODE_KEY = 'fwgraph_mode'
const qsMode = qs.get('mode')
if (qsMode === 'simple' || qsMode === 'pro') localStorage.setItem(MODE_KEY, qsMode)
const mode = ref(localStorage.getItem(MODE_KEY) === 'pro' ? 'pro' : 'simple')
const modeOptions = [
  { label: '简易模式', value: 'simple' },
  { label: '专业模式', value: 'pro' }
]

const ALL_PAGES = ['dashboard', 'jobs', 'functions', 'attack', 'inputs',
  'graph', 'vuln', 'protofuzz', 'reports', 'users', 'logs', 'settings']
const PAGE_TITLES = {
  dashboard: '仪表盘', jobs: '任务中心', functions: '函数', attack: '攻击面',
  inputs: '输入面', graph: '图谱', vuln: '漏洞挖掘', protofuzz: '协议挖掘',
  reports: '报告中心', users: '用户管理', logs: '日志审计', settings: '系统设置'
}
const SIMPLE_PAGES = ['jobs', 'vuln', 'reports']
const PRO_PAGES = ['dashboard', 'jobs', 'functions', 'attack', 'inputs',
  'graph', 'vuln', 'protofuzz', 'reports']
const ADMIN_PAGES = ['users', 'logs', 'settings']

const qsPage = qs.get('page') || qs.get('tab')
const page = ref(ALL_PAGES.includes(qsPage) ? qsPage : '')

const token = ref(getToken())
const principal = ref(null)
const loginForm = ref({ username: '', password: '' })
const tokenInput = ref('')
const loginError = ref(deepLinkError)
const loginLoading = ref(false)
const functionsView = ref(null)
const pendingFunctionJob = ref('')

const isAdmin = computed(() => principal.value?.role === 'admin')
const defaultPage = computed(() => (mode.value === 'simple' ? 'jobs' : 'dashboard'))
const pageTitle = computed(() => {
  if (page.value === 'jobs' && mode.value === 'simple') return '工作台'
  return PAGE_TITLES[page.value] || ''
})

const MENUS = {
  simple: [
    { index: 'jobs', title: '工作台', icon: 'Monitor' },
    { index: 'vuln', title: '漏洞挖掘', icon: 'Warning' },
    { index: 'reports', title: '报告中心', icon: 'Notebook' }
  ],
  pro: [
    { index: 'dashboard', title: '仪表盘', icon: 'Odometer' },
    { index: 'jobs', title: '任务中心', icon: 'Files' },
    {
      group: 'analysis', title: '分析视图', icon: 'Search',
      children: [
        { index: 'functions', title: '函数', icon: 'Document' },
        { index: 'attack', title: '攻击面', icon: 'Aim' },
        { index: 'inputs', title: '输入面', icon: 'Download' },
        { index: 'graph', title: '图谱', icon: 'Share' }
      ]
    },
    { index: 'vuln', title: '漏洞挖掘', icon: 'Warning' },
    { index: 'protofuzz', title: '协议挖掘', icon: 'Connection' },
    { index: 'reports', title: '报告中心', icon: 'Notebook' }
  ],
  admin: [
    {
      group: 'system', title: '系统管理', icon: 'Setting',
      children: [
        { index: 'users', title: '用户管理', icon: 'User' },
        { index: 'logs', title: '日志审计', icon: 'Tickets' },
        { index: 'settings', title: '系统设置', icon: 'Setting' }
      ]
    }
  ]
}
const menuItems = computed(() => {
  const base = mode.value === 'simple' ? MENUS.simple : MENUS.pro
  return isAdmin.value ? base.concat(MENUS.admin) : base
})

function allowedPages () {
  const base = mode.value === 'simple' ? SIMPLE_PAGES : PRO_PAGES
  return isAdmin.value ? base.concat(ADMIN_PAGES) : base
}

function ensurePageAllowed () {
  if (!page.value || !allowedPages().includes(page.value)) {
    page.value = defaultPage.value
  }
}

function go (p) {
  if (!ALL_PAGES.includes(p)) return
  if (!allowedPages().includes(p)) return
  page.value = p
}

function onModeChange (val) {
  localStorage.setItem(MODE_KEY, val)
  ensurePageAllowed()
}

// keep the address bar shareable (?page=), drop the token once consumed
watch(page, (p) => {
  const url = new URL(window.location.href)
  url.searchParams.delete('token')
  if (p) url.searchParams.set('page', p)
  window.history.replaceState(null, '', url)
})

// ---- auth ------------------------------------------------------------------
setUnauthorizedHandler(() => {
  clearToken()
  token.value = ''
  principal.value = null
})

async function doLogin () {
  loginError.value = ''
  if (!loginForm.value.username || !loginForm.value.password) {
    loginError.value = '请输入用户名和密码'
    return
  }
  loginLoading.value = true
  try {
    const r = await apiLogin(loginForm.value.username.trim(), loginForm.value.password)
    setToken(r.token)
    token.value = r.token
    principal.value = r.user || null
    ensurePageAllowed()
    if (principal.value?.must_change_password) openPasswordDialog(true)
  } catch (e) {
    loginError.value = e.message || '登录失败'
  } finally {
    loginLoading.value = false
  }
}

async function tokenLogin () {
  loginError.value = ''
  if (!tokenInput.value) return
  loginLoading.value = true
  setToken(tokenInput.value.trim())
  try {
    principal.value = await fetchMe()
    token.value = getToken()
    ensurePageAllowed()
    if (principal.value?.must_change_password) openPasswordDialog(true)
  } catch (e) {
    clearToken()
    loginError.value = e.message || '令牌无效'
  } finally {
    loginLoading.value = false
  }
}

async function doLogout () {
  await apiLogout()
  clearToken()
  token.value = ''
  principal.value = null
  loginForm.value = { username: '', password: '' }
  tokenInput.value = ''
}

onMounted(async () => {
  if (!token.value) return
  try {
    principal.value = await fetchMe()
  } catch (e) {
    clearToken()
    token.value = ''
    loginError.value = '登录状态已失效，请重新登录'
    return
  }
  ensurePageAllowed()
  if (principal.value?.must_change_password) openPasswordDialog(true)
})

// ---- user menu ---------------------------------------------------------------
const pwdVisible = ref(false)
const pwdLoading = ref(false)
const pwdForced = ref(false)
const pwdForm = ref({ old: '', new: '', confirm: '' })

function openPasswordDialog (forced) {
  pwdForm.value = { old: '', new: '', confirm: '' }
  pwdForced.value = forced
  pwdVisible.value = true
}

function onUserCommand (cmd) {
  if (cmd === 'logout') doLogout()
  if (cmd === 'password') openPasswordDialog(false)
}

async function submitPassword () {
  if (!pwdForm.value.old || !pwdForm.value.new) {
    ElMessage.warning('请填写原密码和新密码')
    return
  }
  if (pwdForm.value.new.length < 10) {
    ElMessage.warning('新密码长度至少 10 位')
    return
  }
  if (pwdForm.value.new !== pwdForm.value.confirm) {
    ElMessage.warning('两次输入的新密码不一致')
    return
  }
  pwdLoading.value = true
  try {
    await changePassword(pwdForm.value.old, pwdForm.value.new)
    ElMessage.success('密码已修改')
    pwdForced.value = false
    pwdVisible.value = false
    if (principal.value) principal.value.must_change_password = false
  } catch (e) {
    ElMessage.error('修改失败: ' + e.message)
  } finally {
    pwdLoading.value = false
  }
}

// ---- cross-view navigation ---------------------------------------------------
function loadPendingFunctionJob () {
  if (!functionsView.value || !pendingFunctionJob.value) return
  const jobId = pendingFunctionJob.value
  pendingFunctionJob.value = ''
  functionsView.value.loadJob(jobId)
}

async function openFunctions (jobId) {
  // 函数视图属于专业模式；简易模式下跳转时自动升级模式
  if (mode.value === 'simple') {
    mode.value = 'pro'
    localStorage.setItem(MODE_KEY, 'pro')
  }
  pendingFunctionJob.value = jobId
  page.value = 'functions'
  await nextTick()
  loadPendingFunctionJob()
}

watch(functionsView, loadPendingFunctionJob)

// ---- narrow viewport: collapse the sidebar to an icon rail ------------------
const collapsed = ref(false)
let mq = null
function onMq (e) { collapsed.value = e.matches }
onMounted(() => {
  mq = window.matchMedia('(max-width: 900px)')
  onMq(mq)
  mq.addEventListener('change', onMq)
})
onUnmounted(() => mq?.removeEventListener('change', onMq))
</script>

<style>
/* ===== 浅蓝专业主题：Element Plus 浅色变量覆写 ===== */
:root {
  color-scheme: light;
  --el-color-primary: #2b6ce5;
  --el-color-primary-dark-2: #1f56b8;
  --el-color-primary-light-3: #5d8dec;
  --el-color-primary-light-5: #8fb3f2;
  --el-color-primary-light-7: #c0d4f8;
  --el-color-primary-light-8: #d9e5fb;
  --el-color-primary-light-9: #eaf1fd;
  --el-color-success: #16a34a;
  --el-color-success-dark-2: #12813c;
  --el-color-success-light-3: #4cb578;
  --el-color-success-light-5: #8cd0aa;
  --el-color-success-light-7: #c2e7d2;
  --el-color-success-light-8: #d9efe1;
  --el-color-success-light-9: #ecf7f0;
  --el-color-warning: #d97706;
  --el-color-warning-dark-2: #b45309;
  --el-color-warning-light-3: #e1953a;
  --el-color-warning-light-5: #ecba83;
  --el-color-warning-light-7: #f4d6b4;
  --el-color-warning-light-8: #f8e3c9;
  --el-color-warning-light-9: #fcf2e4;
  --el-color-danger: #dc2626;
  --el-color-danger-dark-2: #b91c1c;
  --el-color-danger-light-3: #e35b5b;
  --el-color-danger-light-5: #ee9d9d;
  --el-color-danger-light-7: #f5c6c6;
  --el-color-danger-light-8: #f8dada;
  --el-color-danger-light-9: #fceeee;
  --el-color-error: #dc2626;
  --el-color-error-dark-2: #b91c1c;
  --el-color-error-light-3: #e35b5b;
  --el-color-error-light-5: #ee9d9d;
  --el-color-error-light-7: #f5c6c6;
  --el-color-error-light-8: #f8dada;
  --el-color-error-light-9: #fceeee;
  --el-color-info: #64748f;
  --el-color-info-dark-2: #4e6076;
  --el-color-info-light-3: #8594ab;
  --el-color-info-light-5: #b1bdcb;
  --el-color-info-light-7: #d2d9e2;
  --el-color-info-light-8: #e1e6ec;
  --el-color-info-light-9: #f0f3f6;
  --el-bg-color: #ffffff;
  --el-bg-color-page: #eef3fa;
  --el-bg-color-overlay: #ffffff;
  --el-text-color-primary: #1c2b3a;
  --el-text-color-regular: #3d5470;
  --el-text-color-secondary: #64748f;
  --el-text-color-placeholder: #9aa9bd;
  --el-text-color-disabled: #b0bccb;
  --el-border-color: #d7e2ee;
  --el-border-color-light: #e2eaf3;
  --el-border-color-lighter: #eaf0f7;
  --el-border-color-extra-light: #f0f4fa;
  --el-border-color-hover: #a3c2f0;
  --el-fill-color: rgba(43, 108, 229, .08);
  --el-fill-color-light: rgba(43, 108, 229, .06);
  --el-fill-color-lighter: rgba(43, 108, 229, .04);
  --el-fill-color-extra-light: rgba(43, 108, 229, .025);
  --el-fill-color-dark: rgba(43, 108, 229, .12);
  --el-fill-color-darker: rgba(43, 108, 229, .16);
  --el-fill-color-blank: #ffffff;
  --el-mask-color: rgba(15, 35, 60, .45);
  --el-box-shadow: 0 12px 32px 4px rgba(16, 42, 67, .10), 0 8px 20px rgba(16, 42, 67, .08);
  --el-box-shadow-light: 0 2px 12px rgba(16, 42, 67, .08);
  --el-box-shadow-lighter: 0 1px 8px rgba(16, 42, 67, .06);
  --el-box-shadow-dark: 0 16px 48px 16px rgba(16, 42, 67, .14), 0 12px 32px rgba(16, 42, 67, .10), 0 8px 16px -8px rgba(16, 42, 67, .10);
}

body {
  margin: 0;
  font-family: -apple-system, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
  color: #1c2b3a;
  background-color: #eef3fa;
  background-image:
    radial-gradient(ellipse 80% 50% at 50% -10%, rgba(43, 108, 229, .07), transparent);
  background-attachment: fixed;
}

::selection { background: rgba(43, 108, 229, .18); color: #1c2b3a; }

::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #c6d5e6; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #a8bed6; }

.muted { color: #64748f; font-size: 13px; }
.mono, pre { font-family: 'JetBrains Mono', ui-monospace, Consolas, 'Courier New', monospace; }

/* ===== 登录页 ===== */
.login-wrap {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 24px 16px 8vh;
  box-sizing: border-box;
}
.login-brand { text-align: center; margin-bottom: 26px; }
.login-title {
  margin: 0;
  font-size: 32px;
  letter-spacing: 4px;
  color: #1c2b3a;
}
.login-title::first-letter { color: #2b6ce5; }
.login-slogan { margin: 10px 0 0; color: #64748f; letter-spacing: 1.5px; font-size: 13px; }
.login-card {
  width: 400px;
  max-width: 92vw;
  border: 1px solid #e2eaf3;
  box-shadow: 0 8px 40px rgba(16, 42, 67, .10);
}
.login-card h2 {
  margin: 0 0 18px;
  letter-spacing: 3px;
  text-align: center;
  color: #1c2b3a;
}
.login-field { margin-bottom: 14px; }
.login-btn { width: 100%; margin: 6px 0 12px; }
.token-collapse { margin-top: 6px; --el-collapse-header-bg-color: transparent; --el-collapse-content-bg-color: transparent; }
.pwd-alert { margin-bottom: 14px; }

/* ===== 主壳布局 ===== */
.shell { display: flex; min-height: 100vh; }
.sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  width: 208px;
  flex: none;
  display: flex;
  flex-direction: column;
  background: #ffffff;
  border-right: 1px solid #e3ebf4;
  transition: width .2s ease;
  z-index: 20;
}
.sidebar.collapsed { width: 64px; }
.side-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  height: 56px;
  padding: 0 18px;
  cursor: pointer;
  border-bottom: 1px solid #eef2f8;
  overflow: hidden;
  white-space: nowrap;
}
.logo-dot {
  width: 12px;
  height: 12px;
  flex: none;
  border-radius: 50%;
  background: radial-gradient(circle at 35% 35%, #5d8dec, #2b6ce5);
}
.side-brand-text {
  font-size: 17px;
  font-weight: 700;
  letter-spacing: 2px;
  color: #2b6ce5;
}
.side-menu {
  flex: 1;
  border-right: none;
  background: transparent;
  --el-menu-bg-color: transparent;
  --el-menu-text-color: #44586f;
  --el-menu-hover-bg-color: #f0f5fb;
  --el-menu-active-color: #2b6ce5;
  --el-menu-item-height: 46px;
  --el-menu-sub-item-height: 40px;
  overflow-y: auto;
  overflow-x: hidden;
}
.side-menu:not(.el-menu--collapse) { width: 100%; }
.side-menu .el-menu-item:hover, .side-menu .el-sub-menu__title:hover {
  background: #f0f5fb;
}
.side-menu .el-menu-item.is-active {
  color: #2b6ce5;
  font-weight: 600;
  background: #e9f2fd;
  box-shadow: inset 3px 0 0 #2b6ce5;
}
.side-menu .el-sub-menu.is-active > .el-sub-menu__title { color: #2b6ce5; }
.side-menu .el-menu--inline { background: #f7fafd; }

.main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
.topbar {
  position: sticky;
  top: 0;
  z-index: 15;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  height: 56px;
  padding: 0 20px;
  background: rgba(255, 255, 255, .88);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid #e3ebf4;
}
.page-title {
  font-size: 16px;
  font-weight: 600;
  letter-spacing: 1px;
  color: #1c2b3a;
}
.topbar-right { display: flex; align-items: center; gap: 16px; }
.user-chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: #3d5470;
  padding: 5px 10px;
  border: 1px solid #dbe6f2;
  border-radius: 8px;
  background: #f7fafd;
  outline: none;
}
.user-chip:hover { border-color: #a3c2f0; background: #eef4fc; }
.user-name { font-size: 13px; }
.content { padding: 16px 20px 40px; }
.page-pane { max-width: 1500px; margin: 0 auto; }

/* 页面入场淡入 */
.fade-enter-active, .fade-leave-active { transition: opacity .25s ease, transform .25s ease; }
.fade-enter-from { opacity: 0; transform: translateY(6px); }
.fade-leave-to { opacity: 0; }
.fade-leave-active { position: absolute; width: 100%; }

@media (max-width: 900px) {
  .content { padding: 12px 10px 32px; }
  .topbar { padding: 0 12px; }
  .user-name { display: none; }
}

/* 卡片：白底 + 细浅边 + 轻投影 */
.el-card {
  --el-card-border-color: #e3ebf4;
  --el-card-bg-color: #ffffff;
  border: 1px solid var(--el-card-border-color);
  border-radius: 10px;
  box-shadow: 0 1px 2px rgba(16, 42, 67, .04), 0 4px 16px rgba(16, 42, 67, .05);
}
.el-card__header {
  letter-spacing: .5px;
  color: #1c2b3a;
  font-weight: 600;
  border-bottom: 1px solid #eef2f8;
}

/* 主按钮：实心蓝，hover 加深 */
.el-button--primary {
  --el-button-text-color: #ffffff;
  --el-button-hover-text-color: #ffffff;
  --el-button-active-text-color: #ffffff;
  background: #2b6ce5;
  border-color: #2b6ce5;
  font-weight: 600;
}
.el-button--primary:hover,
.el-button--primary:focus {
  background: #2559c7;
  border-color: #2559c7;
  box-shadow: 0 4px 12px rgba(43, 108, 229, .25);
}
.el-button--primary:active { background: #1f4faf; border-color: #1f4faf; }
.el-button--primary.is-link,
.el-button--primary.is-text { background: none; color: #2b6ce5; }
.el-button:not(.el-button--primary):not(.el-button--danger):not(.el-button--success):not(.el-button--warning):hover {
  box-shadow: 0 2px 8px rgba(43, 108, 229, .12);
}

/* 表格行 hover */
.el-table { --el-table-row-hover-bg-color: #f0f5fb; }

/* markdown 报告渲染基础排版 */
.md-body { line-height: 1.7; color: #3d5470; font-size: 14px; }
.md-body h1, .md-body h2, .md-body h3, .md-body h4 {
  color: #1c2b3a;
  letter-spacing: .5px;
}
.md-body h1 { font-size: 20px; border-bottom: 1px solid #e3ebf4; padding-bottom: 8px; }
.md-body h2 { font-size: 17px; margin-top: 22px; }
.md-body h3 { font-size: 15px; }
.md-body table { border-collapse: collapse; width: 100%; font-size: 13px; }
.md-body th, .md-body td { border: 1px solid #dbe6f2; padding: 6px 10px; text-align: left; }
.md-body th { background: #f0f5fb; color: #1c2b3a; }
.md-body code {
  background: #eef3fa;
  border-radius: 4px;
  padding: 1px 5px;
  font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace;
  font-size: 12.5px;
}
.md-body pre {
  background: #f4f8fd;
  border: 1px solid #e3ebf4;
  border-radius: 6px;
  padding: 12px;
  overflow: auto;
}
.md-body pre code { background: none; padding: 0; }
.md-body a { color: #2b6ce5; }
.md-body blockquote { border-left: 3px solid #a3c2f0; margin-left: 0; padding-left: 12px; color: #64748f; }

</style>

