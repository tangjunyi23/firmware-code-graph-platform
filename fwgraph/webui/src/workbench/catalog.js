import { computed, reactive } from 'vue'
import { api } from '../api.js'

function sameRows (a, b, idKey) {
  if (a === b) return true
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    const x = a[i]
    const y = b[i]
    if (!x || !y) return false
    if (x[idKey] !== y[idKey] || x.status !== y.status
        || x.turns !== y.turns || x.archived !== y.archived
        || x.firmware !== y.firmware || x.task !== y.task) {
      return false
    }
  }
  return true
}

export function createCatalog () {
  const state = reactive({ jobs: [], sessions: [], loading: false })

  async function refresh ({ silent = false } = {}) {
    if (!silent) state.loading = true
    try {
      const [jobs, sessions] = await Promise.all([
        api('/jobs'),
        api('/vulnagent/sessions')
      ])
      const nextJobs = Array.isArray(jobs) ? jobs : []
      const nextSessions = Array.isArray(sessions) ? sessions : []
      if (!sameRows(state.jobs, nextJobs, 'job_id')) state.jobs = nextJobs
      if (!sameRows(state.sessions, nextSessions, 'session_id')) {
        state.sessions = nextSessions
      }
    } catch {
      /* ignore: sidebar stays at last known list */
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
