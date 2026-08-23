<template>
  <div class="app-root">
    <!-- ===== 登录页 ===== -->
    <div v-if="!token" class="login-wrap">
      <div class="login-brand">
        <BrandMark :size="40" class="login-mark" />
        <h1 class="login-title">FWGraph</h1>
        <p class="login-slogan">固件攻击面分析平台</p>
        <p class="login-hint">解包 · 代码图谱 · 攻击面 · 智能挖掘</p>
      </div>
      <el-card class="login-card">
        <h2>欢迎回来</h2>
        <p class="login-card-sub">使用账号登录以继续</p>
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
          登录
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
      <header class="topbar">
        <div class="topbar-left">
          <div class="side-brand" @click="go(defaultPage)">
            <BrandMark :size="26" class="top-mark" />
            <span class="side-brand-text">FWGraph</span>
          </div>
          <nav class="top-nav">
            <template v-for="item in menuItems" :key="item.index || item.group">
              <div v-if="item.group" class="nav-wrap">
                <button
                  type="button"
                  class="nav-tab"
                  :class="{
                    active: isGroupActive(item),
                    open: openGroup === item.group
                  }"
                  @click.stop="toggleGroup(item.group, $event)"
                >
                  {{ item.title }}
                  <el-icon class="nav-chev" :class="{ flip: openGroup === item.group }"><ArrowDown /></el-icon>
                </button>
                <Teleport to="body">
                  <div
                    v-if="openGroup === item.group"
                    class="nav-drop"
                    :style="dropStyle"
                    @click.stop
                  >
                    <button
                      v-for="child in item.children"
                      :key="child.index"
                      type="button"
                      class="nav-drop-item"
                      :class="{ active: page === child.index }"
                      @click="go(child.index)"
                    >{{ child.title }}</button>
                  </div>
                </Teleport>
              </div>
              <button
                v-else
                type="button"
                class="nav-tab"
                :class="{ active: page === item.index }"
                @click="go(item.index)"
              >{{ item.title }}</button>
            </template>
          </nav>
        </div>
        <div class="topbar-right">
          <el-dropdown trigger="click" @command="onUserCommand">
            <span class="user-chip">
              <span class="user-avatar">{{ (principal?.username || '用').slice(0, 1) }}</span>
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

      <main class="content" :class="{ 'chat-home': isChatHome }">
          <transition name="fade">
            <div :key="page" class="page-pane">
              <DashboardView v-if="page === 'dashboard'" @goto="go" />
              <JobsView
                v-else-if="page === 'jobs'"
                @open-functions="openFunctions"
                @goto="go"
              />
              <PrepareView v-else-if="page === 'prepare'" />
              <EventsView v-else-if="page === 'events'" />
              <FunctionsView v-else-if="page === 'functions'" ref="functionsView" />
              <AttackView v-else-if="page === 'attack'" />
              <InputsView v-else-if="page === 'inputs'" />
              <GraphView v-else-if="page === 'graph'" />
              <ProtofuzzView v-else-if="page === 'protofuzz'" />
              <ReportsView v-else-if="page === 'reports'" />
              <UsersView v-else-if="page === 'users'" />
              <LogsView v-else-if="page === 'logs'" :is-admin="isAdmin" />
              <SettingsView v-else-if="page === 'settings'" :is-admin="isAdmin" />
            </div>
          </transition>
        </main>
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
import BrandMark from './components/BrandMark.vue'

const DashboardView = defineAsyncComponent(() => import('./views/DashboardView.vue'))
const JobsView = defineAsyncComponent(() => import('./views/JobsView.vue'))
const PrepareView = defineAsyncComponent(() => import('./views/PrepareView.vue'))
const FunctionsView = defineAsyncComponent(() => import('./views/FunctionsView.vue'))
const AttackView = defineAsyncComponent(() => import('./views/AttackView.vue'))
const InputsView = defineAsyncComponent(() => import('./views/InputsView.vue'))
const EventsView = defineAsyncComponent(() => import('./views/EventsView.vue'))
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

const ALL_PAGES = ['jobs', 'prepare', 'events', 'dashboard', 'functions', 'attack', 'inputs',
  'graph', 'protofuzz', 'reports', 'users', 'logs', 'settings']
const PAGE_TITLES = {
  jobs: '工作台', prepare: '前置任务', events: '事件流', dashboard: '仪表盘', functions: '函数',
  attack: '攻击面', inputs: '输入面', graph: '图谱', protofuzz: '协议挖掘',
  reports: '报告中心', users: '用户管理', logs: '日志审计', settings: '系统设置'
}
const USER_PAGES = ['jobs', 'prepare', 'events', 'dashboard', 'functions', 'attack', 'inputs',
  'graph', 'protofuzz', 'reports']
const ADMIN_PAGES = ['users', 'logs', 'settings']

const qsPageRaw = qs.get('page') || qs.get('tab')
const qsPage = qsPageRaw === 'vuln' ? 'events' : qsPageRaw
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
const defaultPage = computed(() => 'jobs')
const isChatHome = computed(() => page.value === 'jobs' || page.value === 'prepare')
const pageTitle = computed(() => PAGE_TITLES[page.value] || '')

const MENUS = {
  main: [
    { index: 'jobs', title: '工作台', icon: 'Monitor' },
    { index: 'prepare', title: '前置任务', icon: 'Upload' },
    { index: 'events', title: '事件流', icon: 'ChatDotRound' },
    { index: 'dashboard', title: '仪表盘', icon: 'Odometer' },
    {
      group: 'analysis', title: '分析视图', icon: 'Search',
      children: [
        { index: 'functions', title: '函数', icon: 'Document' },
        { index: 'attack', title: '攻击面', icon: 'Aim' },
        { index: 'inputs', title: '输入面', icon: 'Download' },
        { index: 'graph', title: '图谱', icon: 'Share' }
      ]
    },
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
const menuItems = computed(() => (
  isAdmin.value ? MENUS.main.concat(MENUS.admin) : MENUS.main
))

function allowedPages () {
  return isAdmin.value ? USER_PAGES.concat(ADMIN_PAGES) : USER_PAGES
}

function ensurePageAllowed () {
  if (!page.value || !allowedPages().includes(page.value)) {
    page.value = defaultPage.value
  }
}

const openGroup = ref('')
const dropStyle = ref({})
function isGroupActive (item) {
  return (item.children || []).some((c) => c.index === page.value)
}
function toggleGroup (group, ev) {
  if (openGroup.value === group) {
    openGroup.value = ''
    return
  }
  const r = ev.currentTarget.getBoundingClientRect()
  dropStyle.value = {
    top: `${Math.round(r.bottom + 6)}px`,
    left: `${Math.round(r.left)}px`
  }
  openGroup.value = group
}
function onDocClick (e) {
  if (e.target.closest('.nav-wrap') || e.target.closest('.nav-drop')) return
  openGroup.value = ''
}

function go (p) {
  if (p === 'vuln') p = 'events'
  if (!ALL_PAGES.includes(p)) return
  if (!allowedPages().includes(p)) return
  page.value = p
  openGroup.value = ''
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
  pendingFunctionJob.value = jobId
  page.value = 'functions'
  await nextTick()
  loadPendingFunctionJob()
}

watch(functionsView, loadPendingFunctionJob)

onMounted(() => document.addEventListener('click', onDocClick))
onUnmounted(() => document.removeEventListener('click', onDocClick))
</script>

<style>
/* ===== 浅蓝专业主题：Element Plus 浅色变量覆写 ===== */
:root {
  color-scheme: light;
  --el-color-primary: #2563eb;
  --el-color-primary-dark-2: #1d4ed8;
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
  color: var(--fw-text, #152033);
  background-color: var(--fw-page, #f3f6fb);
  background-image:
    radial-gradient(ellipse 90% 55% at 50% -8%, rgba(37, 99, 235, .08), transparent 60%);
  background-attachment: fixed;
}

::selection { background: rgba(37, 99, 235, .16); color: #152033; }

::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #c5d0de; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #a8b6c8; }

.muted { color: var(--fw-text-3, #6b7c90); font-size: 13px; }

/* ===== 登录页 ===== */
.login-wrap {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 32px 16px 10vh;
  box-sizing: border-box;
}
.login-brand {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  margin-bottom: 28px;
}
.login-mark { color: #2563eb; margin-bottom: 14px; }
.login-title {
  margin: 0;
  font-size: 28px;
  font-weight: 650;
  letter-spacing: -0.03em;
  color: #152033;
  line-height: 1.2;
}
.login-slogan {
  margin: 8px 0 0;
  color: #3d4f66;
  font-size: 15px;
  font-weight: 500;
  letter-spacing: 0;
}
.login-hint {
  margin: 6px 0 0;
  color: #6b7c90;
  font-size: 12px;
  letter-spacing: 0.08em;
}
.login-card {
  width: 380px;
  max-width: 92vw;
  border: 1px solid #e4ebf3;
  border-radius: 16px;
  box-shadow: 0 1px 2px rgba(16, 42, 67, .04), 0 16px 40px rgba(16, 42, 67, .08);
}
.login-card .el-card__body { padding: 28px 28px 22px; }
.login-card h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  letter-spacing: -0.02em;
  text-align: left;
  color: #152033;
}
.login-card-sub {
  margin: 4px 0 20px;
  color: #6b7c90;
  font-size: 13px;
}
.login-field { margin-bottom: 12px; }
.login-btn { width: 100%; margin: 8px 0 12px; height: 40px; font-weight: 600; }
.token-collapse { margin-top: 4px; --el-collapse-header-bg-color: transparent; --el-collapse-content-bg-color: transparent; }
.token-collapse .el-collapse-item__header { font-size: 13px; color: #6b7c90; }
.pwd-alert { margin-bottom: 14px; }

/* ===== 主壳布局 ===== */
.shell {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  height: 100vh;
}
.side-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  flex: none;
  cursor: pointer;
  overflow: hidden;
  white-space: nowrap;
}
.top-mark { color: #2563eb; flex: none; display: block; }
.side-brand-text {
  font-size: 15px;
  font-weight: 650;
  letter-spacing: -0.03em;
  color: #152033;
}
.topbar {
  position: sticky;
  top: 0;
  z-index: 30;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  height: 56px;
  padding: 0 18px 0 20px;
  background: rgba(255, 255, 255, .86);
  backdrop-filter: blur(16px) saturate(1.4);
  -webkit-backdrop-filter: blur(16px) saturate(1.4);
  border-bottom: 1px solid rgba(216, 226, 237, .9);
}
.topbar-left {
  display: flex;
  align-items: center;
  gap: 18px;
  min-width: 0;
  flex: 1;
}
.top-nav {
  display: flex;
  align-items: center;
  gap: 2px;
  min-width: 0;
  overflow: visible;
}
.nav-wrap { position: relative; flex: none; }
.nav-tab {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  height: 34px;
  padding: 0 12px;
  border: none;
  border-radius: 8px;
  background: transparent;
  color: #3d4f66;
  font-size: 13.5px;
  font-weight: 500;
  line-height: 20px;
  letter-spacing: -0.01em;
  white-space: nowrap;
  cursor: pointer;
}
.nav-tab:hover { background: #f0f4fa; color: #152033; }
.nav-tab.active {
  color: #2563eb;
  font-weight: 600;
  background: #edf3ff;
}
.nav-tab.open { background: #e9f2fd; }
.nav-chev { font-size: 12px; color: #8aa0b8; transition: transform .15s ease; }
.nav-chev.flip { transform: rotate(180deg); }
.nav-drop {
  position: fixed;
  z-index: 4000;
  min-width: 160px;
  padding: 6px;
  border: 1px solid #e3ebf4;
  border-radius: 10px;
  background: #ffffff;
  box-shadow: 0 8px 24px rgba(16, 42, 67, .12);
}
.nav-drop-item {
  display: block;
  width: 100%;
  height: 34px;
  padding: 0 10px;
  border: none;
  border-radius: 8px;
  background: transparent;
  color: #3d5470;
  font-size: 13px;
  text-align: left;
  cursor: pointer;
}
.nav-drop-item:hover { background: #f0f5fb; color: #1c2b3a; }
.nav-drop-item.active { color: #2b6ce5; font-weight: 600; background: #e9f2fd; }
.topbar-right { display: flex; align-items: center; gap: 16px; }
.user-chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: #3d4f66;
  padding: 4px 8px 4px 4px;
  border: 1px solid #e2eaf3;
  border-radius: 999px;
  background: #fff;
  outline: none;
}
.user-chip:hover { border-color: #c5d6ef; background: #f7f9fc; }
.user-avatar {
  width: 26px;
  height: 26px;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: #edf3ff;
  color: #2563eb;
  font-size: 12px;
  font-weight: 650;
  letter-spacing: 0;
  text-transform: uppercase;
}
.user-name { font-size: 13px; font-weight: 500; }
.content {
  flex: 1;
  min-height: 0;
  overflow: auto;
  padding: 16px 20px 40px;
}
.content.chat-home {
  padding: 0;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}
.content.chat-home .page-pane {
  max-width: none;
  margin: 0;
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  height: 100%;
}
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
  --el-card-border-color: #e4ebf3;
  --el-card-bg-color: #ffffff;
  border: 1px solid var(--el-card-border-color);
  border-radius: 12px;
  box-shadow: 0 1px 2px rgba(16, 42, 67, .04), 0 8px 24px rgba(16, 42, 67, .04);
}
.el-card__header {
  letter-spacing: -0.01em;
  color: #152033;
  font-weight: 600;
  font-size: 14px;
  border-bottom: 1px solid #eef2f8;
}

/* 主按钮：实心蓝，hover 加深 */
.el-button--primary {
  --el-button-text-color: #ffffff;
  --el-button-hover-text-color: #ffffff;
  --el-button-active-text-color: #ffffff;
  background: #2563eb;
  border-color: #2563eb;
  font-weight: 600;
  letter-spacing: -0.01em;
  border-radius: 8px;
}
.el-button--primary:hover,
.el-button--primary:focus {
  background: #1d4ed8;
  border-color: #1d4ed8;
  box-shadow: 0 4px 12px rgba(43, 108, 229, .25);
}
.el-button--primary:active { background: #1f4faf; border-color: #1f4faf; }
.el-button { border-radius: 8px; font-weight: 500; }
.el-button--primary.is-link,
.el-button--primary.is-text { background: none; color: #2563eb; }
.el-button:not(.el-button--primary):not(.el-button--danger):not(.el-button--success):not(.el-button--warning):hover {
  box-shadow: 0 2px 8px rgba(43, 108, 229, .12);
}

/* 表格行 hover */
.el-table { --el-table-row-hover-bg-color: #f0f5fb; }

/* markdown 报告渲染基础排版 */
.md-body { line-height: 1.7; color: #3d4f66; font-size: 14px; }
.md-body h1, .md-body h2, .md-body h3, .md-body h4 {
  color: #152033;
  letter-spacing: -0.02em;
  font-weight: 650;
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

