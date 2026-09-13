// 全站主题偏好：light / dark。
// 挂在 <html data-fw-theme> 上，theme.css 的深色令牌块据此生效；
// 工作台（dsh-web）有自己的一套 data-wb-theme 令牌，切换时同步写
// fwgraph_wb_theme，两套体系保持一致。
import { ref } from 'vue'

const KEY = 'fwgraph_theme'
const WB_KEY = 'fwgraph_wb_theme'

export const themePref = ref('light')

function resolveInitial () {
  try {
    const saved = localStorage.getItem(KEY)
    if (saved === 'light' || saved === 'dark') return saved
    // 深色为默认体验
  } catch { /* private mode */ }
  return 'dark'
}

function apply (mode) {
  document.documentElement.setAttribute('data-fw-theme', mode)
}

export function initTheme () {
  themePref.value = resolveInitial()
  apply(themePref.value)
  try {
    // 工作台 dsh 令牌跟随同一默认（用户单独设置过则尊重）
    if (!localStorage.getItem(WB_KEY)) localStorage.setItem(WB_KEY, themePref.value)
  } catch { /* ignore */ }
}

export function setTheme (mode) {
  const next = mode === 'dark' ? 'dark' : 'light'
  themePref.value = next
  apply(next)
  try {
    localStorage.setItem(KEY, next)
    // 工作台 dsh 令牌同步（WorkbenchView 初始化时读取这个 key）
    localStorage.setItem(WB_KEY, next)
  } catch { /* ignore */ }
  // 已挂载的工作台根节点即时跟随
  document.querySelectorAll('.wb-root').forEach((el) => el.setAttribute('data-wb-theme', next))
}

export function toggleTheme () {
  setTheme(themePref.value === 'dark' ? 'light' : 'dark')
}
