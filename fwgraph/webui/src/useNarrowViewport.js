import { onMounted, onUnmounted, ref } from 'vue'

export function useNarrowViewport () {
  const isNarrow = ref(false)
  let mediaQuery = null

  function update (event) {
    isNarrow.value = event.matches
  }

  onMounted(() => {
    mediaQuery = window.matchMedia('(max-width: 720px)')
    update(mediaQuery)
    mediaQuery.addEventListener('change', update)
  })

  onUnmounted(() => mediaQuery?.removeEventListener('change', update))
  return isNarrow
}
