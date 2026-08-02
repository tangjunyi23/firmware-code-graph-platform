<template>
  <div v-loading="loading" class="code-viewer">
    <pre v-if="code"><code class="hljs language-c" v-html="highlighted"></code></pre>
    <el-empty v-else description="暂无代码" :image-size="60" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import hljs from 'highlight.js/lib/core'
import c from 'highlight.js/lib/languages/c'
import 'highlight.js/styles/atom-one-dark.css'

hljs.registerLanguage('c', c)

const props = defineProps({
  code: { type: String, default: '' },
  loading: { type: Boolean, default: false }
})

const highlighted = computed(() => {
  if (!props.code) return ''
  try {
    return hljs.highlight(props.code, { language: 'c' }).value
  } catch {
    return props.code.replace(/&/g, '&amp;').replace(/</g, '&lt;')
  }
})
</script>

<style scoped>
.code-viewer pre {
  margin: 0;
  background: #282c34;
  border-radius: 6px;
  padding: 12px;
  overflow: auto;
  max-height: 72vh;
  font-size: 13px;
  line-height: 1.5;
}
.code-viewer code { font-family: 'JetBrains Mono', Consolas, 'Courier New', monospace; }
</style>
