import { api } from './api.js'

let cache = []
let fetchedAt = 0
let cacheToken = ''
let pending = null

export function loadJobs({ force = false } = {}) {
  const token = localStorage.getItem('fwgraph_token') || ''
  if (token !== cacheToken) {
    cache = []
    fetchedAt = 0
    pending = null
    cacheToken = token
  }
  if (pending) return pending
  if (!force && Date.now() - fetchedAt < 5000) return Promise.resolve(cache)
  const request = api('/jobs').then(rows => {
    const next = Array.isArray(rows) ? rows : []
    if (token === cacheToken) {
      cache = next
      fetchedAt = Date.now()
    }
    return next
  }).finally(() => { if (pending === request) pending = null })
  pending = request
  return request
}

export function readSelectedJob() {
  try { return sessionStorage.getItem('fwgraph_selected_job') || '' } catch { return '' }
}

export function rememberSelectedJob(id) {
  try {
    if (id) sessionStorage.setItem('fwgraph_selected_job', id)
    else sessionStorage.removeItem('fwgraph_selected_job')
  } catch { /* storage unavailable */ }
}
