import { computed, reactive } from 'vue'
import { api } from '../api.js'

export function createCatalog () {
  const state = reactive({ jobs: [], sessions: [], loading: false })

  async function refresh () {
    state.loading = true
    try {
      const [jobs, sessions] = await Promise.all([
        api('/jobs'),
        api('/vulnagent/sessions')
      ])
      state.jobs = Array.isArray(jobs) ? jobs : []
      state.sessions = Array.isArray(sessions) ? sessions : []
    } catch {
      /* ignore: sidebar stays at last known list */
    } finally {
      state.loading = false
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
