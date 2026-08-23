<template>
  <div class="wb-md" v-html="html" />
</template>

<script setup>
import { computed } from 'vue'
import { marked } from 'marked'
import './markdown.css'

marked.setOptions({ breaks: true, gfm: true })

const props = defineProps({ text: { type: String, default: '' } })
const html = computed(() => {
  try {
    return marked.parse(props.text || '')
  } catch {
    return escapeHtml(props.text || '')
  }
})
function escapeHtml (s) {
  return s.replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]))
}
</script>
