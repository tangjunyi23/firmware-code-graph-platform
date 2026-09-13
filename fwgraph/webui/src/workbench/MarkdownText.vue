<template>
  <div class="wb-md" v-html="html" />
</template>

<script setup>
import { computed } from 'vue'
import { renderMarkdown } from '../highlight.js'
import './markdown.css'

const props = defineProps({ text: { type: String, default: '' } })
const html = computed(() => renderMarkdown(props.text || ''))
</script>
