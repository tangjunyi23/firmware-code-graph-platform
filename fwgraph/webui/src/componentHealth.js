/** 组件健康展示：中文名 + 分组图数据。API 字段名（ida/dsh/llm）不改。 */

const CORE = [
  { key: 'ida', label: '反编译器', hint: 'IDA / rootfs_elf' },
  { key: 'emba', label: '固件解包', hint: 'EMBA' },
  { key: 'cbm', label: '代码图谱', hint: '图谱索引' },
  { key: 'frida', label: '动态插桩', hint: 'x86 hook' },
  { key: 'dsh', label: '固件漏洞挖掘引擎', hint: '工作台挖掘会话' }
]

const AFL_LABEL = {
  arm: 'ARM',
  aarch64: 'ARM64',
  mips: 'MIPS',
  mipsel: 'MIPSel'
}

export function componentHealth (components) {
  const c = components || {}
  const items = CORE.map((row) => ({
    key: row.key,
    label: row.label,
    hint: row.hint,
    ok: !!c[row.key],
    group: 'core'
  }))
  for (const [arch, ok] of Object.entries(c.afl_qemu || {})) {
    items.push({
      key: `afl-${arch}`,
      label: `模糊测试 ${AFL_LABEL[arch] || arch}`,
      hint: 'AFL++ qemu',
      ok: !!ok,
      group: 'fuzz'
    })
  }
  items.push({
    key: 'llm',
    label: '大模型接口',
    hint: c.llm?.api_key ? '密钥已配置' : '未配置密钥',
    ok: !!(c.llm && c.llm.api_key),
    group: 'llm'
  })
  return items
}

export function healthDonutItems (items) {
  const online = items.filter((row) => row.ok).length
  const offline = items.length - online
  return [
    { key: 'online', label: '在线', value: online, color: '#34d399' },
    { key: 'offline', label: '离线', value: offline, color: '#fb7185' }
  ]
}

export function healthGroupBars (items) {
  const groups = [
    { key: 'core', label: '核心管线', color: '#38bdf8' },
    { key: 'fuzz', label: '模糊测试', color: '#a78bfa' },
    { key: 'llm', label: '大模型接口', color: '#fbbf24' }
  ]
  return groups.map((g) => {
    const rows = items.filter((row) => row.group === g.key)
    const online = rows.filter((row) => row.ok).length
    return {
      key: g.key,
      label: g.label,
      value: online,
      total: rows.length,
      color: g.color
    }
  }).filter((g) => g.total > 0)
}
