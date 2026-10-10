<template>
  <svg :width="size" :height="size" viewBox="0 0 40 40" fill="none" class="brand-mark" aria-hidden="true">
    <rect width="40" height="40" rx="12" fill="currentColor" />
    <path d="M12 12H28M12 12V28M12 20H23M23 20L28 28" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" />
    <circle cx="12" cy="12" r="3" fill="white"/><circle cx="28" cy="12" r="3" fill="white"/><circle cx="12" cy="28" r="3" fill="white"/><circle cx="28" cy="28" r="3" fill="#83eed5"/>
  </svg>
</template>
<script setup>
defineProps({ size: { type: Number, default: 28 } })
</script>
