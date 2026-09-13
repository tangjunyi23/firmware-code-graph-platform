// Token store + fetch wrapper. The token lives in localStorage and is
// mirrored into a cookie so browser contexts that cannot set headers
// (the /cbmui iframe and the CBM UI's own same-origin fetches) still
// authenticate against the orchestrator proxy.

const TOKEN_KEY = 'fwgraph_token'
const COOKIE = 'fwgraph_token'

export function getToken () {
  return localStorage.getItem(TOKEN_KEY) || ''
}

export function setToken (token) {
  localStorage.setItem(TOKEN_KEY, token)
  document.cookie = `${COOKIE}=${encodeURIComponent(token)};path=/;SameSite=Lax`
}

export function clearToken () {
  localStorage.removeItem(TOKEN_KEY)
  document.cookie = `${COOKIE}=;path=/;max-age=0`
}

export class ApiError extends Error {
  constructor (status, message) {
    const text = (message && typeof message === 'object')
      ? (message.message || JSON.stringify(message))
      : message
    super(text)
    this.status = status
    this.detail = message
  }
}

// The shell registers a handler that drops the session and returns to the
// login page whenever any request is rejected with 401.
let onUnauthorized = null
export function setUnauthorizedHandler (fn) {
  onUnauthorized = fn
}

export async function api (path, { method = 'GET', body, formData, signal } = {}) {
  const headers = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const resp = await fetch(path, {
    method,
    headers,
    signal,
    body: formData || (body !== undefined ? JSON.stringify(body) : undefined)
  })
  if (resp.status === 401) {
    if (path.startsWith('/auth/login')) {
      // Login failure: surface the backend detail (bad credentials etc.) and
      // never trip the session-expiry handler — there is no session to drop,
      // and the form the user just typed into must stay put.
      let detail = '用户名或密码错误'
      try {
        const j = await resp.json()
        if (j && j.detail) detail = j.detail
      } catch { /* non-JSON error body */ }
      throw new ApiError(401, detail)
    }
    if (onUnauthorized) onUnauthorized()
    throw new ApiError(401, '登录状态已失效，请重新登录')
  }
  if (!resp.ok) {
    let detail = `${resp.status}`
    try {
      const j = await resp.json()
      if (j && j.detail) detail = j.detail
    } catch { /* non-JSON error body */ }
    throw new ApiError(resp.status, detail)
  }
  const ct = resp.headers.get('content-type') || ''
  return ct.includes('application/json') ? resp.json() : resp.text()
}

function _xhrDetail (xhr) {
  let detail = `${xhr.status}`
  try {
    const j = JSON.parse(xhr.responseText)
    if (j && j.detail) detail = j.detail
  } catch { /* non-JSON */ }
  return detail
}

/** Multipart firmware upload with progress. Job is created only after the
 *  body is fully received, so callers should show percent until resolve. */
export function uploadFirmware (file, { auto = true, onProgress, task = '', profile } = {}) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    const q = new URLSearchParams()
    if (auto) q.set('auto', '1')
    if (profile) q.set('profile', profile)
    const qs = q.toString()
    xhr.open('POST', `/firmware${qs ? '?' + qs : ''}`)
    const token = getToken()
    if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`)
    xhr.upload.onprogress = (ev) => {
      if (onProgress && ev.lengthComputable) onProgress(ev.loaded, ev.total)
    }
    xhr.onload = () => {
      if (xhr.status === 401) {
        if (onUnauthorized) onUnauthorized()
        reject(new ApiError(401, '登录状态已失效，请重新登录'))
        return
      }
      if (xhr.status < 200 || xhr.status >= 300) {
        reject(new ApiError(xhr.status, _xhrDetail(xhr)))
        return
      }
      try {
        resolve(JSON.parse(xhr.responseText))
      } catch {
        reject(new ApiError(xhr.status, '上传响应无法解析'))
      }
    }
    xhr.onerror = () => reject(new ApiError(0, '网络错误，固件未上传完成'))
    xhr.onabort = () => reject(new ApiError(0, '上传已取消'))
    const fd = new FormData()
    fd.append('file', file)
    if (task) fd.append('task', task)
    xhr.send(fd)
  })
}

// ---- SSE streaming ---------------------------------------------------------

/**
 * SSE reader with the Authorization header (EventSource cannot set headers).
 * Parses `event:`/`data:` frames; `data` is JSON-parsed when possible.
 * `onFrame(parsed, {event, raw})` fires per frame; resolves when the stream
 * ends; rejects on HTTP/network errors (ApiError) or AbortError via signal.
 */
export async function streamSse (path, { signal, onFrame } = {}) {
  const headers = { Accept: 'text/event-stream' }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  const resp = await fetch(path, { headers, signal })
  if (resp.status === 401) {
    if (onUnauthorized) onUnauthorized()
    throw new ApiError(401, '登录状态已失效，请重新登录')
  }
  if (!resp.ok || !resp.body) {
    let detail = `${resp.status}`
    try {
      const j = await resp.json()
      if (j && j.detail) detail = j.detail
    } catch { /* non-JSON error body */ }
    throw new ApiError(resp.status, detail)
  }
  const reader = resp.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''
  const dispatch = (block) => {
    let event = 'message'
    const dataLines = []
    for (const line of block.split('\n')) {
      if (line.startsWith(':') || line === '') continue
      if (line.startsWith('event:')) event = line.slice(6).trim()
      else if (line.startsWith('data:')) dataLines.push(line.slice(5).replace(/^ /, ''))
    }
    if (!dataLines.length) return
    const raw = dataLines.join('\n')
    let parsed = raw
    try { parsed = JSON.parse(raw) } catch { /* keep raw text */ }
    if (onFrame) onFrame(parsed, { event, raw })
  }
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buf += decoder.decode(value, { stream: true })
    let idx
    while ((idx = buf.indexOf('\n\n')) !== -1) {
      const block = buf.slice(0, idx)
      buf = buf.slice(idx + 2)
      dispatch(block)
    }
  }
  if (buf.trim()) dispatch(buf)
}

// ---- auth helpers ----------------------------------------------------------

// 会话空闲看护：共享机器/实验室场景下，长时间无操作自动收回凭证，
// 缩短 localStorage token 的实际暴露窗口。
const IDLE_TIMEOUT_MS = 4 * 60 * 60 * 1000
let lastActiveAt = Date.now()
export function touchSession () {
  lastActiveAt = Date.now()
}
export function startSessionWatch (onIdle, intervalMs = 60 * 1000) {
  for (const ev of ['pointerdown', 'keydown', 'visibilitychange']) {
    document.addEventListener(ev, touchSession, { passive: true })
  }
  window.setInterval(() => {
    if (!getToken()) return
    if (document.visibilityState === 'visible' && Date.now() - lastActiveAt > IDLE_TIMEOUT_MS) {
      clearToken()
      onIdle()
    }
  }, intervalMs)
}

export async function login (username, password) {
  return api('/auth/login', { method: 'POST', body: { username, password } })
}

export async function logout () {
  try {
    await api('/auth/logout', { method: 'POST' })
  } catch { /* best effort: local session is dropped regardless */ }
}

export async function fetchMe () {
  return api('/auth/me')
}

export async function changePassword (oldPassword, newPassword) {
  return api('/auth/password', {
    method: 'POST',
    body: { old_password: oldPassword, new_password: newPassword }
  })
}
