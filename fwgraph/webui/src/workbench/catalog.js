import { computed, reactive } from 'vue'
import { api } from '../api.js'
import { loadJobs } from '../jobCatalog.js'

function sameRows (a, b, idKey) {
  if (a === b) return true
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    const x = a[i]
    const y = b[i]
    if (!x || !y) return false
    if (x[idKey] !== y[idKey] || x.status !== y.status
        || x.turns !== y.turns || x.archived !== y.archived
        || x.firmware !== y.firmware || x.task !== y.task
        || x.progress !== y.progress || x.error !== y.error
        || x.await_note !== y.await_note || x.managed !== y.managed
        || x.updated_at !== y.updated_at || x.max_turns !== y.max_turns
        || JSON.stringify(x.findings || []) !== JSON.stringify(y.findings || [])) {
      return false
    }
  }
  return true
}

export function createCatalog () {
  const state = reactive({ jobs: [], sessions: [], loading: false, error: '', updatedAt: null })
  let pending = null

  function refresh ({ silent = false } = {}) {
    if (pending) return pending
    pending = performRefresh(silent).finally(() => { pending = null })
    return pending
  }

  async function performRefresh(silent) {
    if (!silent) state.loading = true
    try {
      const [jobs, sessions] = await Promise.all([
        loadJobs({ force: true }),
        api('/vulnagent/sessions')
      ])
      const nextJobs = Array.isArray(jobs) ? jobs : []
      const nextSessions = Array.isArray(sessions) ? sessions : []
      if (!sameRows(state.jobs, nextJobs, 'job_id')) state.jobs = nextJobs
      if (!sameRows(state.sessions, nextSessions, 'session_id')) {
        state.sessions = nextSessions
      }
      state.error = ''
      state.updatedAt = Date.now()
    } catch {
      state.error = '任务列表暂时无法更新，已保留最近数据。'
    } finally {
      if (!silent) state.loading = false
    }
  }

  const groups = computed(() => {
    const byJob = new Map()
    for (const job of state.jobs) {
      byJob.set(job.job_id, { job, sessions: [] })
    }
    const ungrouped = []
    for (const sess of state.sessions) {
      const jid = sess.job_id
      if (jid && byJob.has(jid)) byJob.get(jid).sessions.push(sess)
      else if (jid) {
        byJob.set(jid, {
          job: { job_id: jid, firmware: sess.firmware || jid, status: '' },
          sessions: [sess]
        })
      } else ungrouped.push(sess)
    }
    return { folders: [...byJob.values()], ungrouped }
  })

  function jobById (id) {
    return state.jobs.find((j) => j.job_id === id) || null
  }

  return { state, refresh, groups, jobById }
}
