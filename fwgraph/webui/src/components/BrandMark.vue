<template>
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 32 32"
    fill="none"
    class="brand-mark"
    aria-hidden="true"
  >
    <rect width="32" height="32" rx="8" fill="currentColor" />
    <path
      fill="#fff"
      d="M9.6 8.4h10.1c3.28 0 5.5 2.02 5.5 5.02 0 2.22-1.22 3.86-3.36 4.52L24.9 23.6h-3.5l-3.2-5.2h-5.4v5.2H9.6V8.4zm3.2 2.52v4.58h5.7c1.82 0 2.86-.96 2.86-2.3 0-1.32-1.04-2.28-2.86-2.28h-5.7z"
    />
  </svg>
</template>

<script setup>
defineProps({ size: { type: Number, default: 28 } })
</script>
