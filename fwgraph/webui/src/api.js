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
    throw new ApiError(401, 'token 无效或缺失')
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
