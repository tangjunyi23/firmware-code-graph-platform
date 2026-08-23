<template>
  <div class="mask" @click.self="$emit('close')">
    <div class="dialog" role="dialog" aria-modal="true">
      <div class="head">
        <span>{{ t('settings.title') }}</span>
        <button type="button" class="x" :aria-label="t('settings.close')" @click="$emit('close')">
          <IconCloseOutline16 :size="16" />
        </button>
      </div>
      <div class="body">
        <div class="row">
          <span class="label">{{ t('settings.theme') }}</span>
          <div class="seg">
            <button
              type="button"
              :class="{ on: theme === 'light' }"
              @click="$emit('update:theme', 'light')"
            >{{ t('settings.theme.light') }}</button>
            <button
              type="button"
              :class="{ on: theme === 'dark' }"
              @click="$emit('update:theme', 'dark')"
            >{{ t('settings.theme.dark') }}</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { IconCloseOutline16 } from './icons.js'
import { t } from './locales.js'
defineProps({ theme: { type: String, default: 'light' }, session: { type: Object, default: null } })
defineEmits(['close', 'update:theme'])
</script>

<style scoped>
.mask {
  position: absolute;
  inset: 0;
  z-index: 30;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--dsw-alias-bg-mask-1);
}
.dialog {
  width: min(420px, calc(100% - 32px));
  border-radius: 16px;
  background: var(--dsw-alias-bg-layer-1);
  box-shadow: var(--dsw-shadow-lv3);
  color: var(--dsw-alias-label-primary);
}
.head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 16px 8px;
  font-size: 16px;
  font-weight: 500;
}
.x {
  width: 28px;
  height: 28px;
  border: none;
  border-radius: 999px;
  background: transparent;
  color: var(--dsw-alias-label-secondary);
  cursor: pointer;
}
.x:hover { background: var(--dsw-alias-interactive-bg-hover); }
.body { padding: 8px 16px 20px; }
.row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.label { font-size: 14px; }
.seg {
  display: flex;
  padding: 2px;
  border-radius: 10px;
  background: var(--dsw-specific-selector);
}
.seg button {
  height: 28px;
  padding: 0 12px;
  border: none;
  border-radius: 8px;
  background: transparent;
  color: var(--dsw-alias-label-secondary);
  font-size: 13px;
  cursor: pointer;
}
.seg button.on {
  background: var(--dsw-alias-button-elevated-fill);
  color: var(--dsw-alias-label-primary);
  box-shadow: var(--dsw-shadow-lv1);
}
</style>
