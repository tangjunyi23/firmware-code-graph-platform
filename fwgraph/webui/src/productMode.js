const KEY = 'fwgraph_ui_mode'

export function readMode () {
  try {
    const value = localStorage.getItem(KEY)
    if (value === 'wish' || value === 'expert') return value
  } catch { /* private mode */ }
  return 'expert'
}

export function writeMode (mode) {
  try { localStorage.setItem(KEY, mode === 'wish' ? 'wish' : 'expert') } catch { /* ignore */ }
}
