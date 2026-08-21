<template>
  <div class="jobs-chat">
    <HomeChat @goto="emit('goto', $event)" />
  </div>
</template>

<script setup>
import HomeChat from './HomeChat.vue'

defineEmits(['open-functions', 'goto'])
</script>

<style scoped>
.jobs-chat { height: 100%; min-height: 0; display: flex; flex-direction: column; }
.jobs-chat :deep(.home-chat) { flex: 1; min-height: 0; }
</style>
