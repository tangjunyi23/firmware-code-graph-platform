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
    super(message)
    this.status = status
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

// ---- auth helpers ----------------------------------------------------------

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
