/** 对话流 / Markdown 共用：数字、地址、符号高亮。 */

import { marked } from 'marked'
import DOMPurify from 'dompurify'

marked.setOptions({ breaks: true, gfm: true })

// 挖掘会话会回显固件里的攻击者可控内容（路径/报文/字符串），
// marked 输出必须先过白名单净化再进 v-html。
DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'A') {
    node.setAttribute('target', '_blank')
    node.setAttribute('rel', 'noopener noreferrer nofollow')
  }
})
function sanitizeHtml (html) {
  return DOMPurify.sanitize(html, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ['style', 'form', 'input', 'button', 'iframe', 'object', 'embed', 'script'],
    FORBID_ATTR: ['style']
  })
}

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }

export function escapeHtml (s) {
  return String(s || '').replace(/[&<>"']/g, (c) => ESC[c])
}

const TOKEN = /CWE-\d+|CVE-\d{4}-\d+|CNVD-\d{4}-\d+|CNNVD-\d{8}-\d+|0x[0-9a-fA-F]+|\b\d+(?:\.\d+)?%?|-&gt;|=&gt;|→|←|::|[@#%^*~$|]/g

export function highlightPlain (escaped) {
  return String(escaped || '').replace(TOKEN, (m) => {
    if (/^CWE-|^CVE-|^CNVD-|^CNNVD-/.test(m)) return `<span class="hl-cwe">${m}</span>`
    if (/^0x/i.test(m)) return `<span class="hl-hex">${m}</span>`
    if (/^\d/.test(m)) return `<span class="hl-num">${m}</span>`
    return `<span class="hl-sym">${m}</span>`
  })
}

export function highlightText (raw) {
  return highlightPlain(escapeHtml(raw))
}

const SEV = [
  [/严重/g, 'critical'],
  [/高危/g, 'high'],
  [/中危/g, 'medium'],
  [/低危/g, 'low'],
  [/提示/g, 'info'],
]

export function enhanceMarkdownHtml (html) {
  let skip = 0
  return String(html || '').replace(
    /(<pre\b[^>]*>|<\/pre>|<code\b[^>]*>|<\/code>|<[^>]+>|[^<]+)/gi,
    (all) => {
      const lower = all.toLowerCase()
      if (/^<pre\b/.test(lower) || /^<code\b/.test(lower)) {
        skip += 1
        return all
      }
      if (/^<\/pre/.test(lower) || /^<\/code/.test(lower)) {
        skip = Math.max(0, skip - 1)
        return all
      }
      if (all.startsWith('<') || skip) return all
      let out = highlightPlain(all)
      for (const [re, cls] of SEV) {
        out = out.replace(re, `<span class="hl-sev hl-sev-${cls}">$&</span>`)
      }
      return out
    }
  )
}

export function renderMarkdown (text) {
  try {
    return enhanceMarkdownHtml(sanitizeHtml(marked.parse(String(text || ''))))
  } catch {
    return highlightText(text)
  }
}
