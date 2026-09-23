<template>
  <div class="app-root">
    <!-- 全局动态粒子背景（登录页与主壳共用，位于内容之下） -->
    <ParticleField :density="90" />

    <!-- ===== 登录页（居中卡片 + 青色氛围背景） ===== -->
    <div v-if="!token" class="login-wrap">
      <div class="login-grid" aria-hidden="true" />
      <div class="login-panel">
        <div class="login-brand">
          <span class="login-logo"><BrandMark :size="30" /></span>
          <div>
            <h1 class="login-title">FWGraph</h1>
            <p class="login-slogan">固件攻击面分析平台</p>
          </div>
        </div>
        <el-card class="login-card" shadow="never">
          <h2>欢迎回来</h2>
          <p class="login-card-sub">使用账号登录以继续</p>
          <el-input
            v-model="loginForm.username"
            placeholder="用户名"
            class="login-field"
            @keyup.enter="doLogin"
          >
            <template #prefix><span class="field-ico"><component :is="NAV_ICONS.User" :size="16" /></span></template>
          </el-input>
          <el-input
            v-model="loginForm.password"
            type="password"
            show-password
            placeholder="密码"
            class="login-field"
            @keyup.enter="doLogin"
          >
            <template #prefix><span class="field-ico"><component :is="NAV_ICONS.Lock" :size="16" /></span></template>
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
        <ul class="login-stats">
          <li><b>99.8%</b><i>反编译成功率</i></li>
          <li><b>33万+</b><i>单任务图谱节点</i></li>
          <li><b>15+</b><i>指令集全链路</i></li>
        </ul>
        <p class="login-hint">解包 · 代码图谱 · 攻击面 · 智能挖掘</p>
      </div>
    </div>

    <!-- ===== 主壳 ===== -->
    <div v-else class="shell">
      <div v-if="mobileNavOpen" class="nav-mask" aria-hidden="true" @click="mobileNavOpen = false" />

      <aside class="sidebar" :class="{ open: mobileNavOpen, mini: sideMini }">
        <div class="side-brand" @click="go(defaultPage)">
          <BrandMark :size="28" class="top-mark" />
          <div class="side-brand-copy">
            <span class="side-brand-text">FWGraph</span>
            <span class="side-brand-sub">固件分析平台</span>
          </div>
          <button
            type="button"
            class="side-collapse"
            :aria-label="sideMini ? '展开侧栏' : '收起侧栏'"
            :title="sideMini ? '展开侧栏' : '收起侧栏'"
            @click.stop="toggleSideMini"
          >
            <component :is="NAV_ICONS.ArrowDown" :size="15" :class="{ flip: sideMini }" />
          </button>
          <button type="button" class="side-close" aria-label="关闭导航菜单" @click.stop="mobileNavOpen = false">
            <component :is="NAV_ICONS.SwitchButton" :size="16" style="transform: rotate(180deg)" />
          </button>
        </div>

        <div class="mode-switch" data-tour="mode-switch">
          <button
            type="button"
            :class="{ on: uiMode === 'expert' }"
            @click="setUiMode('expert')"
          >专家</button>
          <button
            type="button"
            :class="{ on: uiMode === 'wish' }"
            @click="setUiMode('wish')"
          >快速</button>
        </div>

        <nav class="side-nav" data-tour="nav-main">
          <template v-for="item in menuItems" :key="item.index || item.group || item.section">
            <div v-if="item.section" class="nav-section">{{ item.section }}</div>
            <div v-else-if="item.group" class="nav-group">
              <button
                type="button"
                class="nav-item nav-group-btn"
                :data-tour="'nav-' + item.group"
                :aria-label="item.title"
                :aria-expanded="isGroupOpen(item) ? 'true' : 'false'"
                :class="{
                  active: isGroupActive(item),
                  open: isGroupOpen(item)
                }"
                @click.stop="onGroupClick(item)"
              >
                <span class="nav-ico"><component :is="NAV_ICONS[item.icon] || NAV_ICONS.Menu" :size="16" /></span>
                <span class="nav-label">{{ item.title }}</span>
                <span class="nav-chev" :class="{ flip: isGroupOpen(item) }"><component :is="NAV_ICONS.ArrowDown" :size="14" /></span>
              </button>
              <div v-show="isGroupOpen(item)" class="nav-children">
                <button
                  v-for="child in item.children"
                  :key="child.index"
                  type="button"
                  class="nav-item child"
                  :data-tour="'nav-' + child.index"
                  :aria-label="child.title"
                  :class="{ active: page === child.index }"
                  @click="go(child.index)"
                >
                  <span class="nav-ico"><component :is="NAV_ICONS[child.icon] || NAV_ICONS.Document" :size="16" /></span>
                  <span class="nav-label">{{ child.title }}</span>
                </button>
              </div>
            </div>
            <button
              v-else
              type="button"
              class="nav-item"
              :data-tour="'nav-' + item.index"
              :aria-label="item.title"
              :class="{ active: page === item.index }"
              @click="go(item.index)"
            >
              <span class="nav-ico"><component :is="NAV_ICONS[item.icon] || NAV_ICONS.Menu" :size="16" /></span>
              <span class="nav-label">{{ item.title }}</span>
            </button>
          </template>
        </nav>

        <div class="side-foot">
          <span class="side-version">FWGraph v{{ APP_VERSION }}</span>
        </div>
      </aside>

      <div class="main-col">
      <header class="topbar">
        <button type="button" class="tb-icon tb-menu" aria-label="打开导航菜单" @click="mobileNavOpen = true">
          <component :is="NAV_ICONS.Menu" :size="18" />
        </button>
        <div class="tb-right">
          <button type="button" class="tb-search" @click="paletteOpen = true">
            <component :is="NAV_ICONS.Search" :size="14" />
            <span class="tb-search-text">搜索</span>
            <kbd class="tb-kbd">⌘K</kbd>
          </button>
          <el-popover placement="bottom-end" :width="264" trigger="click">
            <template #reference>
              <button type="button" class="tb-icon" aria-label="运行通知">
                <component :is="NAV_ICONS.Tickets" :size="17" />
                <span v-if="runningSessions" class="tb-dot">{{ runningSessions > 9 ? '9+' : runningSessions }}</span>
              </button>
            </template>
            <div class="bell-card">
              <p class="bell-title">挖掘动态</p>
              <p v-if="runningSessions" class="bell-line">
                <span class="fx-dot" /> {{ runningSessions }} 个挖掘会话运行中
              </p>
              <p v-else class="bell-line muted">当前没有运行中的会话</p>
              <button type="button" class="bell-go" @click="go('jobs')">前往工作台</button>
            </div>
          </el-popover>
          <button
            type="button"
            class="tb-icon"
            :aria-label="themePref === 'dark' ? '切换到浅色主题' : '切换到深色主题'"
            @click="toggleTheme"
          >
            <component :is="themePref === 'dark' ? NAV_ICONS.Sun : NAV_ICONS.Moon" :size="17" />
          </button>
          <el-dropdown trigger="click" @command="onUserCommand" placement="bottom-end">
            <span class="user-chip">
              <span class="user-avatar">{{ (principal?.username || '用').slice(0, 1) }}</span>
              <span class="user-meta">
                <span class="user-name">{{ principal?.username || '用户' }}</span>
                <span class="user-role">{{ principal?.role === 'admin' ? '管理员' : '普通用户' }}</span>
              </span>
              <span class="muted"><component :is="NAV_ICONS.ArrowDown" :size="13" /></span>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="tour">
                  <span class="menu-ico"><component :is="NAV_ICONS.Guide" :size="15" /></span>新手教程
                </el-dropdown-item>
                <el-dropdown-item command="password">
                  <span class="menu-ico"><component :is="NAV_ICONS.Key" :size="15" /></span>修改密码
                </el-dropdown-item>
                <el-dropdown-item command="logout" divided>
                  <span class="menu-ico"><component :is="NAV_ICONS.SwitchButton" :size="15" /></span>退出登录
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </header>

      <main class="content" :class="{ 'chat-home': isChatHome, 'ops-home': isOpsHome, 'dash-home': page === 'dashboard' }">
            <div :key="page + ':' + wbNavSeq" class="page-pane">
              <WishView v-if="page === 'wish'" />
              <DashboardView v-else-if="page === 'dashboard'" @goto="go" />
              <ProtocolView v-else-if="page === 'protocol'" @goto="go" />
              <DecryptView v-else-if="page === 'decrypt'" @goto="go" />
              <BackdoorView v-else-if="page === 'backdoor'" />
              <EmulView v-else-if="page === 'emul'" />
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
              <VulnlibView v-else-if="page === 'vulnlib'" />
              <ReportsView v-else-if="page === 'reports'" />
              <UsersView v-else-if="page === 'users'" />
              <LogsView v-else-if="page === 'logs'" :is-admin="isAdmin" />
              <SettingsView v-else-if="page === 'settings'" :is-admin="isAdmin" />
            </div>
        </main>
      </div>
    </div>

    <CommandPalette
      :open="paletteOpen"
      :pages="palettePages"
      @close="paletteOpen = false"
      @navigate="onPaletteNav"
    />

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

    <OnboardingTour
      :open="tourOpen"
      :username="principal?.username || ''"
      @navigate="go"
      @close="onTourClose"
    />
  </div>
</template>

<script setup>
import { computed, defineAsyncComponent, nextTick, onMounted, provide, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import {
  getToken, setToken, clearToken, api,
  login as apiLogin, logout as apiLogout, fetchMe, changePassword,
  setUnauthorizedHandler, startSessionWatch
} from './api'
import BrandMark from './components/BrandMark.vue'
import OnboardingTour from './components/OnboardingTour.vue'
import CommandPalette from './components/CommandPalette.vue'
import ParticleField from './components/fx/ParticleField.vue'
import { version as APP_VERSION } from '../package.json'
import { onboardAuto, refreshOnboardPref } from './onboardPref'
import { readMode, writeMode } from './productMode'
import { themePref, initTheme, toggleTheme } from './themePrefs'
import { NAV_ICONS } from './workbench/icons.js'

initTheme()


const WishView = defineAsyncComponent(() => import('./views/WishView.vue'))
const DashboardView = defineAsyncComponent(() => import('./views/DashboardView.vue'))
const ProtocolView = defineAsyncComponent(() => import('./views/ProtocolView.vue'))
const DecryptView = defineAsyncComponent(() => import('./views/DecryptView.vue'))
const BackdoorView = defineAsyncComponent(() => import('./views/BackdoorView.vue'))
const EmulView = defineAsyncComponent(() => import('./views/EmulView.vue'))
const JobsView = defineAsyncComponent(() => import('./views/JobsView.vue'))
const PrepareView = defineAsyncComponent(() => import('./views/PrepareView.vue'))
const FunctionsView = defineAsyncComponent(() => import('./views/FunctionsView.vue'))
const AttackView = defineAsyncComponent(() => import('./views/AttackView.vue'))
const InputsView = defineAsyncComponent(() => import('./views/InputsView.vue'))
const EventsView = defineAsyncComponent(() => import('./views/EventsView.vue'))
const ProtofuzzView = defineAsyncComponent(() => import('./views/ProtofuzzView.vue'))
const GraphView = defineAsyncComponent(() => import('./views/GraphView.vue'))
const ReportsView = defineAsyncComponent(() => import('./views/ReportsView.vue'))
const VulnlibView = defineAsyncComponent(() => import('./views/VulnlibView.vue'))
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

const ALL_PAGES = ['wish', 'jobs', 'prepare', 'decrypt', 'events', 'dashboard', 'functions', 'attack', 'inputs',
  'graph', 'protocol', 'protofuzz', 'vulnlib', 'reports', 'users', 'logs', 'settings', 'backdoor', 'emul']
const PAGE_TITLES = {
  wish: '快速挖掘', jobs: '工作台', prepare: '分析任务', decrypt: '固件解密', events: '事件流', backdoor: '后门检测', emul: '固件模拟', dashboard: '仪表盘', functions: '函数',
  attack: '攻击面', inputs: '输入面', graph: '图谱', protocol: '入口风险评估', protofuzz: '协议挖掘',
  vulnlib: '漏洞库', reports: '报告中心', users: '用户管理', logs: '日志审计', settings: '系统设置'
}
const USER_PAGES = ['wish', 'jobs', 'prepare', 'decrypt', 'events', 'dashboard', 'functions', 'attack', 'inputs',
  'graph', 'protocol', 'protofuzz', 'vulnlib', 'reports', 'backdoor', 'emul']
const ADMIN_PAGES = ['users', 'logs', 'settings']

const qsMode = qs.get('mode')
const uiMode = ref((qsMode === 'wish' || qsMode === 'expert') ? qsMode : readMode())
const qsPageRaw = qs.get('page') || qs.get('tab')
const qsPage = qsPageRaw === 'vuln' ? 'events' : qsPageRaw
const page = ref(ALL_PAGES.includes(qsPage) ? qsPage : '')

const token = ref(getToken())
const principal = ref(null)
provide('wbAccount', principal)
const loginForm = ref({ username: '', password: '' })
const tokenInput = ref('')
const loginError = ref(deepLinkError)
const loginLoading = ref(false)
const functionsView = ref(null)
const pendingFunctionJob = ref('')

const isAdmin = computed(() => principal.value?.role === 'admin')
// 登录落地页：专家模式直接进态势总览，快速模式进快速挖掘向导
const defaultPage = computed(() => (uiMode.value === 'wish' ? 'wish' : 'dashboard'))
const isChatHome = computed(() => page.value === 'jobs' || page.value === 'prepare')
const isOpsHome = computed(() => ['dashboard', 'wish', 'protocol', 'decrypt'].includes(page.value))

const MENUS = {
  main: [
    { index: 'dashboard', title: '仪表盘', icon: 'Odometer' },
    {
      group: 'chat', title: '新对话', icon: 'ChatDotRound', index: 'jobs',
      children: [
        { index: 'prepare', title: '分析任务', icon: 'Upload' }
      ]
    },
    {
      group: 'tools', title: '固件工具', icon: 'Cpu',
      children: [
        { index: 'decrypt', title: '固件解密', icon: 'Unlock' },
        { index: 'backdoor', title: '后门检测', icon: 'ScanSearch' },
        { index: 'emul', title: '固件模拟', icon: 'Monitor' },
        { index: 'protocol', title: '入口风险评估', icon: 'Aim' },
        { index: 'events', title: '事件流', icon: 'Tickets' }
      ]
    },
    {
      group: 'analysis', title: '代码洞察', icon: 'Search',
      children: [
        { index: 'functions', title: '函数', icon: 'Document' },
        { index: 'attack', title: '攻击面', icon: 'Aim' },
        { index: 'inputs', title: '输入面', icon: 'Download' },
        { index: 'graph', title: '图谱', icon: 'Share' }
      ]
    },
    { index: 'vulnlib', title: '漏洞库', icon: 'Collection' },
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
  const all = isAdmin.value ? MENUS.main.concat(MENUS.admin) : MENUS.main
  const base = uiMode.value !== 'wish' ? all : [
    { index: 'wish', title: '快速挖掘', icon: 'Star' },
    ...all.filter((item) => item.index === 'dashboard' || item.index === 'reports' || item.index === 'vulnlib' || item.group === 'tools' || item.group === 'system')
  ]
  const items = [{ section: '工作区' }, ...base]
  if (isAdmin.value) {
    const sysIdx = items.findIndex((it) => it.group === 'system')
    if (sysIdx >= 0) items.splice(sysIdx, 0, { section: '管理' })
  }
  return items
})

// ---- 命令面板 / 顶栏 ----
const PAGE_ICONS = {
  wish: 'Star', jobs: 'ChatDotRound', prepare: 'Upload', decrypt: 'Unlock', protocol: 'Share', backdoor: 'ScanSearch', emul: 'Monitor',
  events: 'Tickets', dashboard: 'Odometer', functions: 'Document', attack: 'Aim', inputs: 'Download',
  graph: 'Share', protofuzz: 'Share', vulnlib: 'Collection', reports: 'Notebook',
  users: 'User', logs: 'Tickets', settings: 'Setting'
}
const paletteOpen = ref(false)
const wbNavSeq = ref(0)
const palettePages = computed(() => {
  const pages = allowedPages().map((index) => ({ index, title: PAGE_TITLES[index], icon: PAGE_ICONS[index] }))
  return pages
})
function onPaletteNav ({ kind, page, protoTab, sid }) {
  if (kind === 'page' && page) {
    if (protoTab) {
      try { sessionStorage.setItem('fwgraph_proto_tab', protoTab) } catch { /* private mode */ }
      wbNavSeq.value += 1
    }
    go(page)
    return
  }
  if (kind === 'job') go('prepare')
  else if (kind === 'session' && sid) {
    try { sessionStorage.setItem('fwgraph_wb_sid', sid) } catch { /* private mode */ }
    wbNavSeq.value += 1
    go('jobs')
  } else if (kind === 'finding') go('vulnlib')
}
function onGlobalKey (e) {
  if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
    e.preventDefault()
    if (token.value) paletteOpen.value = !paletteOpen.value
    return
  }
}

// 铃铛：运行中会话数（60s 刷新）
const runningSessions = ref(0)
async function refreshBell () {
  try {
    const list = await api('/vulnagent/sessions')
    runningSessions.value = Array.isArray(list)
      ? list.filter((x) => x.status === 'running' || x.status === 'awaiting_continue').length
      : 0
  } catch { /* keep last known */ }
}

function allowedPages () {
  return isAdmin.value ? USER_PAGES.concat(ADMIN_PAGES) : USER_PAGES
}

function ensurePageAllowed () {
  if (!page.value || !allowedPages().includes(page.value)) {
    page.value = defaultPage.value
  }
}

// 分组展开状态：localStorage 持久化，刷新/重进不丢
const NAV_OPEN_KEY = 'fwgraph_nav_open'
function readOpenGroups () {
  try {
    const saved = JSON.parse(localStorage.getItem(NAV_OPEN_KEY) || 'null')
    if (Array.isArray(saved)) return new Set(saved)
  } catch { /* ignore */ }
  return new Set(['chat'])
}
const openGroups = ref(readOpenGroups())
const mobileNavOpen = ref(false)

// 侧栏迷你模式：进工作台自动收起，把宽度让给会话区；手动切换优先
const sideMini = ref(false)
let sideMiniManual = false
try {
  sideMini.value = localStorage.getItem('fwgraph_side_mini') === '1'
  sideMiniManual = sideMini.value
} catch { /* ignore */ }
function toggleSideMini () {
  sideMini.value = !sideMini.value
  sideMiniManual = true
  try { localStorage.setItem('fwgraph_side_mini', sideMini.value ? '1' : '0') } catch { /* ignore */ }
}
watch(page, (p) => {
  if (sideMiniManual) return
  sideMini.value = p === 'jobs'
}, { immediate: true })

// 笔记本等比缩放只作用于常规页面；仪表盘（态势大屏）有自己的断点适配
watch(page, (p) => {
  document.body.classList.toggle('fit', p !== 'dashboard')
}, { immediate: true })
function isGroupActive (item) {
  if (item.index && item.index === page.value) return true
  return (item.children || []).some((c) => c.index === page.value)
}
function isGroupOpen (item) {
  return openGroups.value.has(item.group) || isGroupActive(item)
}
function toggleGroup (group) {
  const next = new Set(openGroups.value)
  if (next.has(group)) next.delete(group)
  else next.add(group)
  openGroups.value = next
  try { localStorage.setItem(NAV_OPEN_KEY, JSON.stringify([...next])) } catch { /* ignore */ }
}
function onGroupClick (item) {
  if (item.index) {
    if (page.value === item.index) toggleGroup(item.group)
    else go(item.index)
  } else {
    toggleGroup(item.group)
  }
}

function go (p) {
  if (p === 'vuln') p = 'events'
  if (!ALL_PAGES.includes(p)) return
  if (!allowedPages().includes(p)) return
  page.value = p
  mobileNavOpen.value = false
}

function setUiMode (next) {
  const mode = next === 'wish' ? 'wish' : 'expert'
  uiMode.value = mode
  writeMode(mode)
  if (mode === 'wish' && page.value !== 'wish') go('wish')
  if (mode === 'expert' && page.value === 'wish') go('dashboard')
}

// keep the address bar shareable (?page=), drop the token once consumed
watch([page, uiMode], ([p, mode]) => {
  const url = new URL(window.location.href)
  url.searchParams.delete('token')
  if (p) url.searchParams.set('page', p)
  else url.searchParams.delete('page')
  url.searchParams.set('mode', mode)
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
    await afterAuthReady()
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
    await afterAuthReady()
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
  tourOpen.value = false
}

onMounted(async () => {
  window.addEventListener('keydown', onGlobalKey)
  if (!token.value) return
  startSessionWatch(() => {
    token.value = ''
    principal.value = null
    loginError.value = '长时间未操作，已自动退出登录'
  })
  refreshBell()
  window.setInterval(refreshBell, 60000)
  try {
    principal.value = await fetchMe()
  } catch (e) {
    clearToken()
    token.value = ''
    loginError.value = '登录状态已失效，请重新登录'
    return
  }
  await afterAuthReady()
})

// ---- user menu ---------------------------------------------------------------
const pwdVisible = ref(false)
const pwdLoading = ref(false)
const pwdForced = ref(false)
const pwdForm = ref({ old: '', new: '', confirm: '' })
const tourOpen = ref(false)


function onboardKey () {
  return `fwgraph_onboard_v2:${principal.value?.username || 'anon'}`
}
function onboardSeen () {
  try { return localStorage.getItem(onboardKey()) === 'done' } catch { return false }
}
function startTour () {
  setUiMode('expert')
  tourOpen.value = false
  nextTick(() => { tourOpen.value = true })
}
function scheduleTour () {
  if (!token.value || !principal.value || pwdForced.value || !onboardAuto.value || onboardSeen()) return
  // 深链进入（?page=xxx）说明用户带着明确目的地，教程不要抢导航
  try {
    if (new URLSearchParams(window.location.search).get('page')) return
  } catch { /* ignore */ }
  startTour()
}
async function afterAuthReady () {
  ensurePageAllowed()
  await refreshOnboardPref()
  if (principal.value?.must_change_password) openPasswordDialog(true)
  else scheduleTour()
}
function onTourClose () {
  tourOpen.value = false
}

function openPasswordDialog (forced) {
  pwdForm.value = { old: '', new: '', confirm: '' }
  pwdForced.value = forced
  pwdVisible.value = true
}

function onUserCommand (cmd) {
  if (cmd === 'logout') doLogout()
  if (cmd === 'password') openPasswordDialog(false)
  if (cmd === 'tour') startTour()
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
    scheduleTour()
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


</script>

<style>
.app-root {
  min-height: 100vh;
  background: transparent;
}
/* 正文背景保持干净：装饰只出现在登录页（.login-wrap）；底色半透明，
   让全局粒子层在卡片之外透出来 */
.login-wrap {
  position: relative;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 32px 16px;
  box-sizing: border-box;
  background:
    linear-gradient(160deg, rgba(248, 250, 252, .82) 0%, rgba(240, 253, 250, .4) 50%, rgba(241, 245, 249, .78) 100%);
  overflow: hidden;
}
/* 青色氛围光斑 */
.login-wrap::before,
.login-wrap::after {
  content: '';
  position: absolute;
  border-radius: 50%;
  filter: blur(64px);
  pointer-events: none;
}
.login-wrap::before {
  width: 420px;
  height: 420px;
  right: -120px;
  top: -140px;
  background: rgba(91, 140, 255, .2);
}
.login-wrap::after {
  width: 420px;
  height: 420px;
  left: -140px;
  bottom: -160px;
  background: rgba(91, 140, 255, .12);
}
/* 细网格 */
.login-grid {
  position: absolute;
  inset: 0;
  pointer-events: none;
  background-image:
    linear-gradient(rgba(91, 140, 255, .05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(91, 140, 255, .05) 1px, transparent 1px);
  background-size: 64px 64px;
}
.login-wrap .login-grid { display: block; }
html[data-fw-theme='dark'] .login-wrap {
  background: linear-gradient(160deg, rgba(2, 6, 23, .78) 0%, rgba(15, 23, 42, .66) 60%, rgba(2, 6, 23, .78) 100%);
}
html[data-fw-theme='dark'] .login-wrap::before { background: rgba(91, 140, 255, .1); }
html[data-fw-theme='dark'] .login-wrap::after { background: rgba(99, 102, 241, .09); }

.login-panel {
  position: relative;
  z-index: 1;
  width: min(420px, 100%);
  display: flex;
  flex-direction: column;
  align-items: center;
}
.login-brand {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 26px;
}
.login-logo {
  display: grid;
  place-items: center;
  width: 56px;
  height: 56px;
  border-radius: 18px;
  background: var(--fw-surface);
  color: var(--fw-brand);
  box-shadow:
    0 8px 24px rgba(47, 107, 255, .3),
    inset 0 1px 0 rgba(255, 255, 255, .6);
}
.login-title {
  margin: 0;
  font-size: 26px;
  font-weight: 750;
  letter-spacing: -0.02em;
  line-height: 1.2;
  background: linear-gradient(120deg, #101828 30%, #2f6bff 90%);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}
html[data-fw-theme='dark'] .login-title {
  background: linear-gradient(120deg, #eef2f9 30%, #93b4ff 90%);
  -webkit-background-clip: text;
  background-clip: text;
}
.login-slogan { margin: 3px 0 0; color: var(--fw-text-3); font-size: 13px; }
.login-card {
  width: 100%;
  border: 1px solid var(--fw-line);
  border-radius: 20px;
  background: color-mix(in srgb, var(--fw-surface) 92%, transparent);
  backdrop-filter: blur(12px);
  box-shadow:
    var(--fw-shadow-lg),
    0 0 0 1px rgba(91, 140, 255, .07);
}
.login-card .el-card__body { padding: 28px 28px 22px; }
.login-card h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 700;
  letter-spacing: -0.02em;
  text-align: center;
  color: var(--fw-text);
}
.login-card-sub {
  margin: 4px 0 20px;
  text-align: center;
  color: var(--fw-text-3);
  font-size: 13px;
}
.login-field { margin-bottom: 12px; }
.login-btn { width: 100%; margin: 8px 0 12px; height: 42px; font-weight: 600; border-radius: 12px; }
.token-collapse { margin-top: 4px; --el-collapse-header-bg-color: transparent; --el-collapse-content-bg-color: transparent; }
.token-collapse .el-collapse-item__header { font-size: 13px; color: var(--fw-text-3); }
.login-stats {
  margin: 26px 0 0;
  padding: 0;
  list-style: none;
  display: flex;
  gap: 32px;
}
.login-stats li { display: flex; flex-direction: column; align-items: center; gap: 3px; }
.login-stats b {
  font-size: 20px;
  font-weight: 750;
  color: var(--fw-text);
  font-variant-numeric: tabular-nums;
}
.login-stats i { font-style: normal; font-size: 11.5px; color: var(--fw-text-3); }
.login-hint {
  margin: 14px 0 0;
  color: var(--fw-text-3);
  font-size: 12px;
  letter-spacing: .12em;
}
.login-card {
  width: 100%;
  border: 1px solid var(--fw-line);
  border-radius: 18px;
  background: var(--fw-surface);
  box-shadow:
    var(--fw-shadow-lg),
    0 0 0 1px rgba(91, 140, 255, .07);
}
.login-card .el-card__body { padding: 28px 28px 22px; }
.login-card h2 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  letter-spacing: -0.02em;
  text-align: left;
  color: var(--fw-text);
}
.login-card-sub {
  margin: 4px 0 20px;
  color: var(--fw-text-3);
  font-size: 13px;
}
.login-field { margin-bottom: 12px; }
.login-btn { width: 100%; margin: 8px 0 12px; height: 40px; font-weight: 600; }
.token-collapse { margin-top: 4px; --el-collapse-header-bg-color: transparent; --el-collapse-content-bg-color: transparent; }
.token-collapse .el-collapse-item__header { font-size: 13px; color: var(--fw-text-3); }
.pwd-alert { margin-bottom: 14px; }

/* 主壳：侧栏贴满最左一列、全高；去掉登录页带来的留白与居中 */
.shell {
  position: relative;
  display: flex;
  align-items: stretch;
  justify-content: flex-start;
  height: 100vh;
  min-height: 100vh;
  padding: 0;
  box-sizing: border-box;
  overflow: hidden;
  background: transparent;
}
.sidebar {
  position: relative;
  width: var(--fw-sidebar-w);
  flex: none;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background:
    radial-gradient(120% 120px at 50% 0%, rgba(91, 140, 255, .07), transparent 70%),
    #0a0e16;
  border-right: 1px solid #1a2233;
  color: #cbd5e1;
}
/* 侧栏缓慢下行的微光带 */
.sidebar::after {
  content: '';
  position: absolute;
  left: 0;
  right: 0;
  top: 0;
  height: 34%;
  pointer-events: none;
  background: linear-gradient(180deg, transparent, rgba(91, 140, 255, .045), transparent);
  animation: fw-side-glow 22s linear infinite;
}
@keyframes fw-side-glow {
  from { transform: translateY(-120%); }
  to { transform: translateY(420%); }
}
html[data-fw-theme='light'] .sidebar::after {
  background: linear-gradient(180deg, transparent, rgba(47, 107, 255, .035), transparent);
}
@media (prefers-reduced-motion: reduce) {
  .sidebar::after { animation: none !important; display: none; }
}
.sidebar.mini { width: 64px; }
.sidebar.mini .side-brand-copy,
.sidebar.mini .nav-label,
.sidebar.mini .nav-chev,
.sidebar.mini .nav-section,
.sidebar.mini .mode-switch,
.sidebar.mini .side-close { display: none; }
/* 迷你模式：logo 与折叠按钮竖排堆叠，各占各的空间，互不遮挡 */
.sidebar.mini .side-brand {
  flex-direction: column;
  justify-content: center;
  height: auto;
  gap: 8px;
  padding: 14px 0 10px;
}
.sidebar.mini .side-collapse {
  position: static;
  margin: 0;
}
.sidebar.mini .nav-item { justify-content: center; padding-left: 0; padding-right: 0; }
.sidebar.mini .nav-item.child { justify-content: center; padding-left: 0; }
.side-collapse {
  display: grid; place-items: center;
  width: 26px; height: 26px; margin-left: auto;
  border: 1px solid #22304c; border-radius: 8px;
  background: #131c2e;
  color: #93b4ff;
  cursor: pointer;
  transition: color .16s ease, border-color .16s ease, box-shadow .16s ease, background-color .16s ease;
}
.side-collapse:hover {
  color: #c3d6ff;
  border-color: rgba(91, 140, 255, .55);
  background: #1a2740;
  box-shadow: 0 0 0 3px rgba(91, 140, 255, .14);
}
.side-collapse svg { transform: rotate(-90deg); transition: transform .18s ease; }
.side-collapse svg.flip { transform: rotate(90deg); }
html[data-fw-theme='light'] .side-collapse {
  border-color: var(--fw-line-strong);
  background: var(--fw-bg-2);
  color: var(--fw-text-2);
}
html[data-fw-theme='light'] .side-collapse:hover {
  color: var(--fw-brand);
  border-color: rgba(91, 140, 255, .45);
  background: var(--fw-fill);
  box-shadow: 0 0 0 3px rgba(91, 140, 255, .12);
}
html[data-fw-theme='light'] .sidebar {
  background: var(--fw-surface);
  border-right: 1px solid var(--fw-line);
  color: var(--fw-text-2);
}
.side-brand {
  position: relative;
  display: flex;
  align-items: center;
  gap: 10px;
  flex: none;
  height: 64px;
  padding: 0 16px;
  cursor: pointer;
  overflow: hidden;
}
.top-mark {
  color: #93b4ff;
  flex: none;
  display: grid;
  place-items: center;
  width: 36px;
  height: 36px;
  border-radius: 12px;
  background: rgba(91, 140, 255, .12);
  box-shadow: 0 0 16px rgba(91, 140, 255, .22);
}
html[data-fw-theme='light'] .top-mark {
  color: var(--fw-brand);
  background: var(--fw-fill);
}
.side-brand-copy { display: flex; flex-direction: column; min-width: 0; }
.side-brand-text {
  font-size: 16px;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: #f1f5f9;
  line-height: 1.2;
}
html[data-fw-theme='light'] .side-brand-text { color: var(--fw-text); }
.side-brand-sub {
  font-size: 11px;
  color: #64748b;
  margin-top: 2px;
}
html[data-fw-theme='light'] .side-brand-sub { color: var(--fw-text-3); }
.mode-switch {
  display: flex;
  margin: 0 12px 10px;
  padding: 3px;
  border: 1px solid #1e293b;
  border-radius: 999px;
  background: #0b1222;
}
html[data-fw-theme='light'] .mode-switch {
  border-color: var(--fw-line);
  background: var(--fw-bg);
}
.mode-switch button {
  flex: 1;
  height: 28px;
  padding: 0 8px;
  border: none;
  border-radius: 999px;
  background: transparent;
  color: #64748b;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all .16s ease;
}
html[data-fw-theme='light'] .mode-switch button { color: var(--fw-text-3); }
.mode-switch button.on {
  background: #1e293b;
  color: #a9c3ff;
}
html[data-fw-theme='light'] .mode-switch button.on {
  background: var(--fw-surface);
  color: var(--fw-brand);
  box-shadow: 0 1px 3px rgba(0, 0, 0, .08);
}
.side-nav {
  flex: 1;
  min-height: 0;
  overflow: auto;
  padding: 4px 10px 16px;
}
.nav-group { margin-bottom: 2px; }
.nav-section {
  padding: 14px 12px 6px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: .08em;
  color: #475569;
  text-transform: uppercase;
  user-select: none;
}
html[data-fw-theme='light'] .nav-section { color: var(--fw-text-3); }
.nav-item {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
  height: 38px;
  margin-bottom: 2px;
  padding: 0 14px;
  border: none;
  border-radius: 12px;
  background: transparent;
  color: #94a3b8;
  font-size: 14px;
  font-weight: 500;
  line-height: 20px;
  text-align: left;
  cursor: pointer;
  transition: background-color .16s ease, color .16s ease;
}
.nav-item:hover { background: #1e293b; color: #e2e8f0; }
html[data-fw-theme='light'] .nav-item { color: var(--fw-text-2); }
html[data-fw-theme='light'] .nav-item:hover { background: var(--fw-bg-2); color: var(--fw-text); }
.nav-item.active {
  color: #a9c3ff;
  font-weight: 600;
  background: rgba(91, 140, 255, .13);
  box-shadow: inset 2px 0 0 #5b8cff;
}
html[data-fw-theme='light'] .nav-item.active {
  color: var(--fw-brand);
  background: var(--fw-fill);
  box-shadow: inset 2px 0 0 var(--fw-brand);
}
.nav-item.active .nav-ico { color: #a9c3ff; }
html[data-fw-theme='light'] .nav-item.active .nav-ico { color: var(--fw-brand); }
.nav-item.child { height: 34px; padding-left: 18px; font-size: 13px; }
.nav-ico { color: inherit; flex: none; display: inline-flex; width: 20px; height: 20px; }
.nav-label { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.nav-chev { color: #475569; transition: transform .15s ease; flex: none; display: inline-flex; }
html[data-fw-theme='light'] .nav-chev { color: var(--fw-text-3); }
.field-ico, .menu-ico { display: inline-flex; color: inherit; }
.menu-ico { margin-right: 6px; vertical-align: -3px; }
.nav-chev.flip { transform: rotate(180deg); }
.nav-children { padding: 2px 0 6px; }
.side-foot {
  flex: none;
  padding: 10px 14px 12px;
  border-top: 1px solid #1e293b;
}
html[data-fw-theme='light'] .side-foot { border-top-color: var(--fw-line); }
.side-version {
  font-size: 11px;
  color: #475569;
  letter-spacing: .04em;
  font-family: var(--fw-font-mono);
}
html[data-fw-theme='light'] .side-version { color: var(--fw-text-3); }

/* ---- 顶栏 ---- */
.main-col {
  position: relative;
  flex: 1;
  min-width: 0;
  min-height: 0;
  display: flex;
  flex-direction: column;
  height: 100vh;
}
/* 页头极光带：两个双色柔光缓慢漂移，向下渐隐，只作氛围不作干扰 */
.main-col::before {
  content: '';
  position: absolute;
  top: -6%;
  left: -8%;
  right: -8%;
  height: 380px;
  pointer-events: none;
  z-index: 0;
  background:
    radial-gradient(120% 90% at 18% 0%, rgba(91, 140, 255, .06), transparent 55%),
    radial-gradient(90% 85% at 88% -12%, rgba(129, 102, 255, .05), transparent 52%);
  animation: fw-aurora 38s ease-in-out infinite alternate;
}
html[data-fw-theme='dark'] .main-col::before {
  background:
    radial-gradient(120% 90% at 18% 0%, rgba(91, 140, 255, .09), transparent 55%),
    radial-gradient(90% 85% at 88% -12%, rgba(129, 102, 255, .06), transparent 52%);
}
@keyframes fw-aurora {
  from { transform: translate3d(-1.5%, -1%, 0) scale(1); }
  to { transform: translate3d(2%, 2.5%, 0) scale(1.07); }
}
@media (prefers-reduced-motion: reduce) {
  .main-col::before { animation: none !important; }
}
.topbar {
  position: relative;
  flex: none;
  display: flex;
  align-items: center;
  gap: 10px;
  height: 64px;
  padding: 0 20px 0 12px;
  border-bottom: 1px solid rgba(30, 41, 59, .7);
  background: rgba(15, 23, 42, .78);
  backdrop-filter: blur(16px) saturate(1.2);
  -webkit-backdrop-filter: blur(16px) saturate(1.2);
  z-index: 700;
}
html[data-fw-theme='light'] .topbar {
  border-bottom-color: color-mix(in srgb, var(--fw-line) 60%, transparent);
  background: color-mix(in srgb, var(--fw-surface) 75%, transparent);
}
.tb-right { margin-left: auto; display: flex; align-items: center; gap: 8px; }
.tb-icon {
  position: relative;
  display: grid;
  place-items: center;
  width: 36px;
  height: 36px;
  border: none;
  border-radius: 10px;
  background: transparent;
  color: var(--fw-text-2);
  cursor: pointer;
}
.tb-icon:hover { background: var(--fw-bg-2); color: var(--fw-text); }
.tb-menu { display: none; }
.tb-dot {
  position: absolute;
  top: 3px;
  right: 3px;
  min-width: 15px;
  height: 15px;
  padding: 0 3px;
  border-radius: 999px;
  background: var(--fw-brand);
  color: #fff;
  font-size: 9.5px;
  font-weight: 700;
  line-height: 15px;
  box-shadow: 0 0 0 2px var(--fw-surface);
}
.tb-search {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 220px;
  height: 34px;
  padding: 0 6px 0 11px;
  border: 1px solid var(--fw-line-strong);
  border-radius: 10px;
  background: var(--fw-bg);
  color: var(--fw-text-3);
  font-size: 13px;
  cursor: pointer;
  font-family: inherit;
  transition: border-color .15s ease, box-shadow .15s ease;
}
.tb-search:hover,
.tb-search:focus-visible {
  border-color: rgba(91, 140, 255, .45);
  box-shadow: 0 0 0 3px rgba(91, 140, 255, .09);
  color: var(--fw-text-2);
}
.tb-kbd {
  border: 1px solid var(--fw-line);
  border-radius: 5px;
  padding: 0 5px;
  font-size: 10.5px;
  font-family: var(--fw-font-mono);
  background: var(--fw-surface);
  line-height: 16px;
}
.bell-card { display: flex; flex-direction: column; gap: 8px; }
.bell-title { margin: 0; font-size: 13px; font-weight: 650; color: var(--fw-text); }
.bell-line { margin: 0; font-size: 12.5px; color: var(--fw-text-2); display: flex; align-items: center; gap: 7px; }
.bell-go {
  align-self: flex-start;
  border: none;
  border-radius: 8px;
  padding: 5px 12px;
  background: var(--fw-fill);
  color: var(--fw-brand);
  font-size: 12.5px;
  font-weight: 600;
  cursor: pointer;
  font-family: inherit;
}
.bell-go:hover { background: var(--fw-fill-strong); }
.user-chip {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: var(--fw-text-2);
  padding: 4px 8px 4px 4px;
  border: 1px solid transparent;
  border-radius: 10px;
  background: transparent;
  outline: none;
  box-sizing: border-box;
}
.user-chip:hover { background: var(--fw-bg-2); }
.user-avatar {
  position: relative;
  width: 30px;
  height: 30px;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, rgba(91, 140, 255, .16), rgba(129, 140, 255, .24));
  color: var(--fw-brand);
  font-size: 12px;
  font-weight: 650;
  letter-spacing: 0;
  text-transform: uppercase;
  flex: none;
}
.user-avatar::after {
  content: '';
  position: absolute;
  right: -1px;
  bottom: -1px;
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--fw-ok);
  box-shadow: 0 0 0 2px var(--fw-surface);
}
.user-meta { display: flex; flex-direction: column; min-width: 0; flex: 1; }
.user-name { font-size: 13px; font-weight: 600; color: var(--fw-text); line-height: 1.2; }
.user-role { font-size: 11px; color: var(--fw-text-3); margin-top: 2px; }
.content {
  position: relative;
  z-index: 1;
  flex: 1;
  min-width: 0;
  min-height: 0;
  overflow: auto;
  overflow-x: hidden;
  padding: 0;
  scrollbar-gutter: stable;
  background: transparent;
}
.main-col .content { height: auto; }
.content.chat-home {
  overflow: hidden;
  display: flex;
  flex-direction: column;
}
.content.chat-home .page-pane {
  max-width: none;
  margin: 0;
  padding: 0;
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  height: 100%;
}
.content.ops-home .page-pane {
  max-width: none;
  margin: 0;
  padding: 0;
  min-height: 100%;
}
/* 仪表盘大屏：把视口剩余高度精确传导给 .screen（fr 行才有确定高度可分配），
   否则屏幕按内容自增高，宽屏下方留白、窄屏溢出滚动 */
.content.dash-home {
  overflow: hidden;
  display: flex;
  flex-direction: column;
}
.content.dash-home .page-pane {
  flex: 1;
  min-height: 0;
  max-width: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
}
.page-pane {
  max-width: 1440px;
  margin: 0 auto;
  padding: 20px 24px 40px;
  box-sizing: border-box;
  animation: fw-page-in .22s ease both;
}

/* ---- 窄屏：侧栏转抽屉，顶栏收纳 ---- */
.nav-mask {
  position: fixed;
  inset: 0;
  z-index: 900;
  background: rgba(9, 12, 20, .5);
}
.side-close { display: none; }
@media (max-width: 900px) {
  .tb-menu { display: grid; }
  .shell { display: flex; }
  .sidebar {
    position: fixed;
    inset: 0 auto 0 0;
    z-index: 1000;
    width: min(300px, 84vw);
    transform: translateX(-102%);
    transition: transform .22s ease;
    box-shadow: var(--fw-shadow-lg);
  }
  .sidebar.open { transform: translateX(0); }
  .side-close {
    display: grid;
    place-items: center;
    width: 34px;
    height: 34px;
    margin-left: auto;
    margin-right: 2px;
    border: none;
    border-radius: 8px;
    background: transparent;
    color: var(--fw-text-3);
    cursor: pointer;
  }
  .side-close:hover { background: var(--fw-bg-2); color: var(--fw-text); }
  .page-pane { padding: 12px 10px 32px; }
}
@media (max-width: 640px) {
  .tb-search-text, .tb-kbd { display: none; }
  .tb-search { padding: 0 9px; }
  .user-meta { display: none; }
  .user-chip { padding: 4px; }
}

.el-card {
  --el-card-border-color: var(--fw-line);
  --el-card-bg-color: var(--fw-surface);
  border: 1px solid var(--el-card-border-color);
  border-radius: var(--fw-radius);
  background-color: var(--fw-surface);
  box-shadow: var(--fw-shadow);
}
.el-card__header {
  letter-spacing: -0.01em;
  color: var(--fw-text);
  font-weight: 600;
  font-size: 14px;
  border-bottom: 1px solid var(--fw-line);
}
.el-button--primary {
  --el-button-text-color: #fff;
  --el-button-hover-text-color: #fff;
  --el-button-active-text-color: #fff;
  background: var(--fw-brand);
  border-color: var(--fw-brand);
  color: #fff;
  font-weight: 600;
  border-radius: var(--fw-radius-sm);
}
.el-button--primary:hover,
.el-button--primary:focus {
  background: var(--fw-brand-hover);
  border-color: var(--fw-brand-hover);
  color: #fff;
}
.el-button { border-radius: var(--fw-radius-sm); font-weight: 500; }
.el-button--primary.is-link,
.el-button--primary.is-text { background: none; color: var(--fw-brand); }
.el-table { --el-table-row-hover-bg-color: var(--fw-fill); --el-table-bg-color: transparent; --el-table-tr-bg-color: transparent; --el-table-header-bg-color: transparent; }

.md-body { line-height: 1.75; color: var(--fw-text-2); font-size: 14px; }
.md-body h1, .md-body h2, .md-body h3, .md-body h4 {
  color: var(--fw-text);
  letter-spacing: -0.02em;
  font-weight: 650;
}
.md-body h1 {
  font-size: 22px;
  border-bottom: 1px solid var(--fw-line);
  padding-bottom: 10px;
}
.md-body h2 {
  font-size: 17px;
  margin-top: 28px;
  padding-left: 10px;
  border-left: 3px solid var(--fw-brand);
}
.md-body h3 { font-size: 15px; margin-top: 20px; color: var(--fw-text); }
.md-body table { border-collapse: collapse; width: 100%; font-size: 13px; margin: 10px 0 16px; }
.md-body th, .md-body td { border: 1px solid var(--fw-line); padding: 8px 12px; text-align: left; }
.md-body th {
  background: var(--fw-bg);
  color: var(--fw-text);
  font-weight: 600;
}
.md-body tr:nth-child(even) td { background: var(--fw-bg); }
.md-body td:first-child { color: var(--fw-text); font-weight: 500; white-space: nowrap; }
.md-body code {
  background: var(--fw-fill);
  color: var(--fw-brand);
  border-radius: 4px;
  padding: 1px 6px;
  font-family: var(--fw-font-mono);
  font-size: 12.5px;
}
.md-body pre {
  background: var(--fw-surface-2);
  border: 1px solid var(--fw-line);
  border-radius: 10px;
  padding: 14px 16px;
  overflow: auto;
  color: var(--fw-text);
}
.md-body pre code { background: none; padding: 0; color: var(--fw-text); }
.md-body a { color: var(--fw-brand); }
.md-body blockquote {
  border-left: 3px solid var(--fw-brand);
  margin: 12px 0;
  padding: 8px 14px;
  background: var(--fw-fill);
  color: var(--fw-text-2);
  border-radius: 0 8px 8px 0;
}
.md-body strong { color: var(--fw-text); }

/* ---- 深色主题下的壳层微调 ---- */
html[data-fw-theme='dark'] .login-card {
  border-color: #262c37;
}
html[data-fw-theme='dark'] .nav-mask { background: rgba(0, 0, 0, .55); }

</style>

