<template>
  <ul class="bars">
    <li v-for="row in rows" :key="row.key">
      <span class="name" :title="row.label">{{ row.label }}</span>
      <span class="track">
        <span class="fill" :style="{ width: row.pct + '%', background: row.color }" />
      </span>
      <b>{{ row.display }}</b>
    </li>
    <li v-if="!rows.length" class="empty">暂无分类数据</li>
  </ul>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  items: { type: Array, default: () => [] }
})

const rows = computed(() => {
  const max = Math.max(
    1,
    ...props.items.map((i) => Number(i.total ?? i.value) || 0)
  )
  return props.items.map((item) => {
    const value = Number(item.value) || 0
    const total = Number(item.total)
    const denom = Number.isFinite(total) && total > 0 ? total : max
    return {
      key: item.key,
      label: item.label,
      value,
      display: Number.isFinite(total) && total > 0 ? `${value}/${total}` : String(value),
      color: item.color,
      pct: Math.round((value / denom) * 100)
    }
  })
})
</script>

<style scoped>
.bars { list-style: none; margin: 0; padding: 4px 0 0; display: flex; flex-direction: column; gap: 12px; }
.bars li {
  display: grid;
  grid-template-columns: minmax(72px, 108px) 1fr 48px;
  gap: 10px;
  align-items: center;
}
.name { color: var(--fw-text-3); font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.track {
  height: 8px;
  border-radius: 99px;
  background: var(--fw-bg-2);
  overflow: hidden;
}
.fill {
  display: block;
  height: 100%;
  border-radius: 99px;
  box-shadow: 0 0 12px color-mix(in srgb, currentColor 40%, transparent);
}
b {
  color: var(--fw-text);
  font-variant-numeric: tabular-nums;
  font-size: 12px;
  text-align: right;
}
.empty { color: var(--fw-text-3); font-size: 12px; display: block; }
</style>
