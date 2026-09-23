/**
 * @fwgraph/dsh-fwgraph-emul-tools — 固件模拟 agent 的工具面（fwgraph-emul
 * profile 专用，与漏洞挖掘的 fwgraph-tools 物理隔离）。
 *
 * 设计约束（用户拍板的四条红线 + 平台纪律）：
 *  - 子代理：广度 ≤3 并发、每会话累计 ≤12、深度由 profile maxDepth=1 封死；
 *  - 磁盘：bash/write/edit 写盘前查会话工作区 du，超额拒绝（服务端另有
 *    build 配额兜底）；
 *  - 联网：profile 放开 web 行（查 qemu/nvram/架构知识），本插件不拦；
 *  - 真实性：不注册任何能对外 serve 页面的工具；环境是否就绪由编排器
 *    publish 复探说了算，AI 不能自证。
 * 工具全部是对编排器 /emul/* 端点的薄转发，重活（rootfs 拷贝、docker
 * 常驻容器、探活）都在平台侧确定性执行。
 */
export const name = 'fwgraph-emul-tools'
export const inject = ['tools']

const MAX_RESULT = 16000
const SUBAGENT_MAX_ACTIVE = 3
const SUBAGENT_MAX_TOTAL = 12
const QUOTA_RECHECK_EVERY = 5 // 每 N 次写盘类工具调一次 du

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

function isRetryable(err) {
  const msg = String(err?.message || err)
  return /HTTP 5\d\d|fetch failed|aborted|timeout|ECONNRESET|ECONNREFUSED/i.test(msg)
}

async function fw(config, method, urlPath, body, timeoutMs = 120_000) {
  let last
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const resp = await fetch(config.baseUrl.replace(/\/+$/, '') + urlPath, {
        method,
        headers: {
          Authorization: `Bearer ${config.token}`,
          'Content-Type': 'application/json',
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      })
      const text = await resp.text()
      if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${text.slice(0, 600)}`)
      try { return JSON.parse(text) } catch { return text }
    } catch (err) {
      last = err
      if (!isRetryable(err) || attempt === 2) throw err
      await sleep(800 * (attempt + 1))
    }
  }
  throw last
}

function params(properties, required = []) {
  return { type: 'object', properties, required, additionalProperties: false }
}

function jsonTool(def) {
  return {
    timeoutMs: 180_000,
    ...def,
    output: {
      schema: { type: 'object', additionalProperties: true, properties: {} },
      render: (_args, value) => [{
        type: 'text',
        text: typeof value === 'string'
          ? value.slice(0, MAX_RESULT)
          : JSON.stringify(value, null, 1).slice(0, MAX_RESULT),
      }],
    },
  }
}

/** Strip undefined for dsh snapshotJsonValue. */
function asJson(value) {
  if (value === undefined) return null
  return JSON.parse(JSON.stringify(value))
}

async function duBytes(dir) {
  const { promises: fsp } = await import('node:fs')
  const path = await import('node:path')
  let total = 0
  async function walk(d, depth) {
    if (depth > 12 || total > 64 * 1024 ** 3) return
    let entries
    try { entries = await fsp.readdir(d, { withFileTypes: true }) } catch { return }
    for (const e of entries) {
      const p = path.join(d, e.name)
      if (e.isDirectory()) await walk(p, depth + 1)
      else if (e.isFile()) {
        try { total += (await fsp.stat(p)).size } catch { /* raced */ }
      }
    }
  }
  await walk(String(dir), 0)
  return total
}

export function apply(ctx, config) {
  const sessionId = config.sessionId || process.env.FWGRAPH_SESSION_ID || ''
  const jobId = config.jobId || process.env.FWGRAPH_JOB_ID || ''
  if (!jobId) throw new Error('fwgraph-emul-tools: jobId 未配置（FWGRAPH_JOB_ID）')

  const currentEnv = { envId: '' }

  async function needEnvId(input) {
    const want = String(input?.env_id || currentEnv.envId || '')
    if (!want) {
      const envs = await fw(config, 'GET', `/emul/envs?job_id=${encodeURIComponent(jobId)}`)
      const usable = (envs || []).find((e) => !['stopped', 'failed'].includes(e.status))
      if (!usable) throw new Error('还没有环境：先 fw_emul_build')
      currentEnv.envId = usable.env_id
      return usable.env_id
    }
    currentEnv.envId = want
    return want
  }

  // ---- 守卫 1：子代理广度/总量 ----
  let subActive = 0
  let subTotal = 0
  ctx.tools.guard((exec) => {
    if ((exec.name === 'subagent' || exec.name === 'subagent_fork')
        && subActive >= SUBAGENT_MAX_ACTIVE) {
      return `并发子代理已达上限 ${SUBAGENT_MAX_ACTIVE}；等现有子代理完成再开新`
    }
    return undefined
  })
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (exec.name === 'subagent' || exec.name === 'subagent_fork') {
      if (subTotal >= SUBAGENT_MAX_TOTAL) {
        return `本会话子代理预算（${SUBAGENT_MAX_TOTAL} 次）已用完；改为顺序自己完成`
      }
      subActive += 1
      subTotal += 1
      try { return await next() } finally { subActive -= 1 }
    }
    return next()
  })

  // ---- 守卫 2：写盘类工具的磁盘配额（会话工作区 du 抽查） ----
  let writesSinceCheck = QUOTA_RECHECK_EVERY
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (!['bash', 'write', 'edit'].includes(exec.name)) return next()
    writesSinceCheck += 1
    if (writesSinceCheck < QUOTA_RECHECK_EVERY) return next()
    writesSinceCheck = 0
    const bytes = await duBytes(process.cwd())
    const gb = bytes / 1024 ** 3
    if (gb > 18) {
      return `会话工作区已用 ${gb.toFixed(1)}GB（上限 20GB）。先删大文件或 fw_emul_stop 释放，禁止继续写盘。`
    }
    return next()
  })

  const register = (def) => ctx.tools.register(jsonTool(def))

  register({
    name: 'fw_emul_binaries',
    description: '列出固件 ELF 的 md5+path（boot 前用它拿 binary_md5）。' +
      '列表很长会被截断——务必带 filter 子串（如 "httpd"）精确匹配。',
    parameters: params({
      filter: { type: 'string', description: '路径子串过滤，如 httpd/ipcserver' },
      job_id: { type: 'string', description: '默认取配置的 job' },
    }),
    async execute(args) {
      const man = await fw(config, 'GET',
        `/jobs/${encodeURIComponent(args.job_id || jobId)}/manifest`)
      let bins = (man.binaries ?? []).map((b) => ({ md5: b.md5, path: b.path }))
      if (args.filter) {
        const f = String(args.filter).toLowerCase()
        bins = bins.filter((b) => String(b.path).toLowerCase().includes(f))
      }
      return asJson({
        job_id: args.job_id || jobId,
        total: (man.binaries ?? []).length,
        matched: bins.length,
        binaries: bins.slice(0, 120),
        hint: bins.length > 120 ? '结果截断，加更精确的 filter' : undefined,
      })
    },
  })

  register({
    name: 'fw_emul_build',
    description: '把固件 rootfs 拷进本会话工作区建成可写模拟底座（新环境）。' +
      '收到 [模拟请求 ...] 任务时必须带 request_id。budget_gb 默认 20 上限。',
    parameters: params({
      budget_gb: { type: 'number', description: '本环境磁盘预算 GB（0.5~20）' },
      request_id: { type: 'string', description: '模拟请求 id（挖掘 agent 发起的任务必填）' },
    }),
    async execute(args) {
      const env = await fw(config, 'POST', '/emul/build', {
        job_id: jobId, session_id: sessionId,
        budget_gb: args.budget_gb, request_id: args.request_id || '',
      })
      currentEnv.envId = env.env_id
      return asJson(env)
    },
  })

  register({
    name: 'fw_emul_boot',
    description: '在当前环境里常驻拉起一个固件服务进程（qemu-user + docker）。' +
      '优先用 binary_path（如 /usr/bin/httpd，尾缀匹配即可）；md5 可选。' +
      '返回就绪状态与 console 尾部；未就绪时读 console 诊断再 patch/reset。',
    parameters: params({
      binary_path: { type: 'string', description: 'rootfs 内路径（优先用这个，如 /usr/bin/httpd）' },
      binary_md5: { type: 'string', description: '可选 md5（与 path 二选一）' },
      argv: { type: 'array', items: { type: 'string' }, description: 'guest argv（不含程序本身）' },
      port: { type: 'integer', description: '服务监听端口（guest 侧）' },
      argv0: { type: 'string', description: 'busybox 多呼叫名（-0 伪造 argv[0]）' },
      name: { type: 'string', description: '服务名（默认取二进制名；同名重启）' },
      ready_timeout: { type: 'number', description: '就绪等待秒数（默认 20）' },
    }, ['port']),
    async execute(args) {
      const envId = await needEnvId(args)
      return asJson(await fw(config, 'POST',
        `/emul/envs/${envId}/boot`, {
          binary_md5: args.binary_md5 || '',
          binary_path: args.binary_path || null,
          argv: args.argv || [], port: args.port,
          argv0: args.argv0 || null, name: args.name || null,
          ready_timeout: args.ready_timeout,
        }))
    },
  })

  register({
    name: 'fw_emul_console',
    description: '读服务 console（docker 日志）尾部。boot 未就绪/崩溃诊断的第一入口。',
    parameters: params({
      service: { type: 'string', description: '服务名（空=全部服务）' },
      tail: { type: 'integer', description: '尾部行数（默认 120）' },
    }),
    async execute(args) {
      const envId = await needEnvId(args)
      return asJson(await fw(config, 'POST', `/emul/envs/${envId}/console`,
        { service: args.service || null, tail: args.tail }))
    },
  })

  register({
    name: 'fw_emul_probe',
    description: '对模拟服务做一次真实探活/请求：TCP/UDP/HTTP 用 port；'
      + 'guest 内 AF_UNIX 域套接字服务（如只 bind /tmp/ipc 不监听 TCP 端口的二进制）'
      + '用 path（guest 绝对路径），宿主经 rootfs 挂载直连。返回原始响应字节。',
    parameters: params({
      port: { type: 'integer', description: 'guest 端口（TCP/UDP 探活用）' },
      path: { type: 'string', description: 'guest 内 unix socket 绝对路径（AF_UNIX 服务探活用，如 /tmp/ipc）' },
      proto: { type: 'string', enum: ['tcp', 'udp'] },
      http_path: { type: 'string', description: '给定时发 GET 请求' },
      payload_hex: { type: 'string', description: '原始字节（hex）' },
    }, []),
    async execute(args) {
      const envId = await needEnvId(args)
      return asJson(await fw(config, 'POST', `/emul/envs/${envId}/probe`, {
        port: args.port, proto: args.proto || 'tcp',
        http_path: args.http_path, payload_hex: args.payload_hex,
        path: args.path,
      }))
    },
  })

  register({
    name: 'fw_emul_patch',
    description: '修改模拟 rootfs 内文件（write/delete/chmod）。patch 后要 reset 让服务重读。',
    parameters: params({
      op: { type: 'string', enum: ['write', 'delete', 'chmod'] },
      path: { type: 'string', description: 'rootfs 内绝对路径，如 /etc/init.d/x' },
      content: { type: 'string', description: '写入文本（与 content_b64 二选一）' },
      content_b64: { type: 'string', description: '写入字节（base64）' },
      mode: { type: 'string', description: '八进制权限，如 0755' },
    }, ['op', 'path']),
    async execute(args) {
      const envId = await needEnvId(args)
      return asJson(await fw(config, 'POST', `/emul/envs/${envId}/patch`, {
        op: args.op, path: args.path,
        content: args.content, content_b64: args.content_b64,
        mode: args.mode,
      }))
    },
  })

  register({
    name: 'fw_emul_read',
    description: '读模拟 rootfs 内文件（校对 patch 结果/nvram 落盘）。',
    parameters: params({ path: { type: 'string' } }, ['path']),
    async execute(args) {
      const envId = await needEnvId(args)
      return asJson(await fw(config, 'POST', `/emul/envs/${envId}/read`,
        { path: args.path }))
    },
  })

  register({
    name: 'fw_emul_reset',
    description: '杀掉全部服务容器并按原配置重启（rootfs 的 patch 保留）。',
    parameters: params({}),
    async execute(args) {
      const envId = await needEnvId(args)
      return asJson(await fw(config, 'POST', `/emul/envs/${envId}/reset`, {}))
    },
  })

  register({
    name: 'fw_emul_stop',
    description: '停掉整个环境（释放容器与端口；rootfs 保留在工作区）。',
    parameters: params({}),
    async execute(args) {
      const envId = await needEnvId(args)
      return asJson(await fw(config, 'POST', `/emul/envs/${envId}/stop`, {}))
    },
  })

  register({
    name: 'fw_emul_report',
    description: '向漏洞挖掘 agent 上报模拟进展（跨 agent 通信，平台会转投给发起'
      + '请求的挖掘会话）：环境就绪并在 publish 之后调 ready（写明 env_id 与可用'
      + '端点）；阶段性重要进展调 progress；受阻或放弃调 blocked（写明原因与已'
      + '完成的诊断）。text 用中文、具体、面向挖掘方消费。',
    parameters: params({
      kind: { type: 'string', enum: ['progress', 'ready', 'blocked'] },
      text: { type: 'string', description: '上报内容（中文）' },
      env_id: { type: 'string', description: '关联环境（有则填）' },
    }, ['kind', 'text']),
    async execute(args) {
      let envId = args.env_id
      if (!envId) { try { envId = await needEnvId(args) } catch { envId = '' } }
      return asJson(await fw(config, 'POST', '/emul/report', {
        kind: args.kind, text: args.text, env_id: envId || undefined,
      }))
    },
  },
  {
    name: 'fw_emul_publish',
    description: '声明环境就绪。编排器会亲自复探每个端点——探不通会拒绝，' +
      '这是真实性闸门；只声明真实拉起并探通的服务，禁止虚报。',
    parameters: params({
      endpoints: {
        type: 'array',
        description: '[{port, proto?, http_path?}（TCP/UDP）或 {path}（guest 内 unix socket 绝对路径）]',
        items: { type: 'object', additionalProperties: true },
      },
      note: { type: 'string', description: '一句话说明环境能做什么' },
    }, ['endpoints']),
    async execute(args) {
      const envId = await needEnvId(args)
      return asJson(await fw(config, 'POST', `/emul/envs/${envId}/publish`, {
        endpoints: args.endpoints, note: args.note || '',
      }))
    },
  })

  ctx.on('dispose', () => {})
}
