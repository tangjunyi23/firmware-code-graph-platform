import { ref } from 'vue'
import { api } from './api'

export const UI_ONBOARD_TOUR = 'UI_ONBOARD_TOUR'
export const onboardAuto = ref(true)

export function parseOnboardAuto (value) {
  if (value == null || value === '') return true
  const s = String(value).trim().toLowerCase()
  return s !== '0' && s !== 'false' && s !== 'off' && s !== 'no'
}

export function applyOnboardConfig (cfg) {
  onboardAuto.value = parseOnboardAuto(cfg?.[UI_ONBOARD_TOUR])
}

export async function refreshOnboardPref () {
  try {
    applyOnboardConfig(await api('/system/config'))
  } catch {
    // keep last known / default
  }
}
