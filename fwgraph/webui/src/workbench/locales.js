const zh = {
  'session.new': '新建对话',
  'session.new.label': '新建对话',
  'session.heading': '对话',
  'session.stop': '停止对话',
  'session.delete': '删除对话',
  'session.deleteConfirm': '删除后无法恢复这条对话，确定删除？',
  'session.more': '更多',
  'session.archive': '归档',
  'session.unarchive': '取消归档',
  'session.archived': '已归档',
  'session.purgeArchived': '删除已归档',
  'session.purgeConfirm': '将永久删除所有已归档对话，确定？',
  'toggle.open': '打开侧边栏',
  'toggle.collapse': '收起侧边栏',
  'hero.chooseWorkspace': '选择已完成的分析任务',
  'placeholder.hero': '描述要挖的漏洞类型或入口',
  'placeholder.default': '给挖掘智能体发消息',
  'placeholder.workspace': '先选择一个已完成的分析任务',
  'placeholder.prepare': '描述这次前置分析要关注的方向，例如优先 HTTP 管理面',
  'prepare.new': '新建分析任务',
  'prepare.heading': '分析任务',
  'prepare.empty': '还没有分析任务',
  'prepare.startHunt': '开始挖掘',
  'placeholder.unavailable': '会话不可用',
  'placeholder.steerQueue': 'Cmd/Ctrl+Enter 插话发送全部排队消息',
  'input.commands': '命令',
  'input.stop': '停止生成',
  'input.send': '发送消息',
  'input.upload': '上传固件',
  'details.title': '详情',
  'details.close': '关闭详情',
  'details.empty': '点击消息流中的工具行查看详情',
  'details.input': '输入',
  'details.output': '输出',
  'details.running': '运行中…',
  'chat.toBottom': '回到底部',
  'chat.loadOlder': '加载更早',
  'row.running': '运行中',
  'row.failed': '失败',
  'row.stopped': '已停止',
  'queue.count': '{n} 条排队消息',
  'queue.remove': '删除排队消息',
  'queue.steer': '插话发送',
  'approval.waiting': '等待审批',
  'approval.reject': '拒绝',
  'approval.allowOnce': '允许一次',
  'approval.policy': '审批策略',
  'approval.auto': '全部同意',
  'approval.ask': '需要审批',
  'cap.waiting': '轮次上限',
  'cap.headline': '已达 {turns}/{maxTurns} 轮，是否继续挖掘？',
  'cap.detail': '继续会再放宽 80 轮；结束则完成本轮并生成报告。',
  'cap.continue': '继续挖掘',
  'cap.end': '结束本轮',
  'settings.title': '设置',
  'settings.theme': '外观',
  'settings.theme.light': '浅色',
  'settings.theme.dark': '深色',
  'settings.close': '关闭',
  'mode.static': '只读分析',
  'mode.dynamic': '动静结合',
  'pipeline.title': '固件分析',
  'trajectory.title': '轨迹',
  'inspect': '查看',
  'firmware.search': '搜索',
  'firmware.empty': '还没有固件任务',
  'firmware.upload': '上传固件',
  'duration.seconds': '{seconds}秒',
  'duration.minutes': '{minutes}分{seconds}秒'
}

export function t (key, vars = {}) {
  let s = zh[key] || key
  for (const [k, v] of Object.entries(vars)) s = s.replaceAll(`{${k}}`, String(v))
  return s
}

export function formatRunDuration (ms) {
  const sec = Math.max(0, Math.floor(ms / 1000))
  const m = Math.floor(sec / 60)
  const s = sec % 60
  if (m <= 0) return t('duration.seconds', { seconds: s })
  return t('duration.minutes', { minutes: m, seconds: String(s).padStart(2, '0') })
}
