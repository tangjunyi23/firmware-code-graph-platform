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

// 在原文上分词（不是在转义后的文本上！否则 &#39; 里的 # 和 39 会被当成
// token 拆碎，实体失效后用户直接看到 "&#39;" 字样），逐段转义再拼回。
const TOKEN = /CWE-\d+|CVE-\d{4}-\d+|CNVD-\d{4}-\d+|CNNVD-\d{8}-\d+|0x[0-9a-fA-F]+|\b\d+(?:\.\d+)?%?|->|=>|→|←|::|[@#%^*~$|]/g

export function highlightText (raw) {
  const s = String(raw || '')
  let out = ''
  let last = 0
  let m
  TOKEN.lastIndex = 0
  while ((m = TOKEN.exec(s)) !== null) {
    out += escapeHtml(s.slice(last, m.index))
    const tok = m[0]
    const cls = /^(CWE|CVE|CNVD|CNNVD)-/.test(tok) ? 'hl-cwe'
      : /^0x/i.test(tok) ? 'hl-hex'
      : /^\d/.test(tok) ? 'hl-num' : 'hl-sym'
    out += `<span class="${cls}">${escapeHtml(tok)}</span>`
    last = m.index + tok.length
    if (m.index === TOKEN.lastIndex) TOKEN.lastIndex += 1
  }
  out += escapeHtml(s.slice(last))
  return out
}

/** 兼容旧签名（输入是已转义文本）：还原成原文后走同一 tokenizer。 */
export function highlightPlain (escaped) {
  const un = String(escaped || '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&')
  return highlightText(un)
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
