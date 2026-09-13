# fwgraph — 固件代码图谱系统

固件上传 → 解包 → IDA 反编译 → 代码图谱与攻击面路径，为上游分析 AI 提供保真的反编译证据、可检索关系和紧凑上下文。fwgraph 不判定漏洞；source/sink、评分和 trace 覆盖只用于证据召回、排序与降误报。

```
固件.bin ─▶ [S1 解包]      EMBA docker（unblob/binwalk/厂商解密）→ rootfs + 架构清单
         ─▶ [S2 反编译]    IDA Pro 9.1 无头批处理（FLIRT 签名 + 规则命名）→ 伪 C + symbols.json
         ─▶ [S4 图谱]      伪 C 文件树 → codebase-memory-mcp 索引 → SQLite 图（节点/边/向量/元数据）
         │                     └─▶ 上游分析 AI（POST /graph/query 或 CBM MCP stdio）
         ─▶ [S4b 图谱扩展] 函数级 CFG（含跳表 indirect_jump 建模）+ AST（tree-sitter）→ cfg/ast op
         ─▶ [S5 动态追踪]  qemu-user + chroot 单二进制覆盖率（baseline/trigger 差分）→ 请求处理路径函数
         ─▶ [AS 攻击面]    source/sink + ≤8 跳 Top50 + trace 交叉验证 + URL→handler ROUTE 边
         ─▶ [M6a/b]        外部输入识别（identification.json，证据四级分级）→ 逐输入攻击面导出（AS-*.json）
         ─▶ [DYN 动态]     x86=frida hook（本机/远程）；ARM/MIPS=AFL++ qemu persistent 函数级 fuzz
         ─▶ [ICS 协议]     协议模板变异 fuzz（Modbus/S7/OPC UA/DNP3/MQTT/HTTP）→ 故障确认+复播复现 → 报告
```

## 1. 部署

前置（VM 上已就绪）：

| 依赖 | 位置/方式 |
|---|---|
| IDA Pro 9.1 | `/home/tankuku/ida-pro-9.1/`（无头需 `TVHEADLESS=1`） |
| EMBA | `~/firmware-graph/emba` + docker 镜像 `embeddedanalyzer/emba:2.0.3a` |
| codebase-memory-mcp | `~/.local/bin/codebase-memory-mcp`（0.9.0） |
| qemu-user（M7） | `apt-get install qemu-user-binfmt`（提供 `/usr/bin/qemu-mips` 等，static-pie 可直接进 chroot） |
| Python venv | `fwgraph/.venv`（`bash setup.sh` 可重建） |
| FLIRT 签名资产 | `fwgraph/libc-sigs/`（`build_sig.sh` 制作，装到 `<ida>/sig/<proc>/`） |
| AFL++（可选，ARM/MIPS fuzz） | 按架构构建 `afl-qemu-trace-<arch>`（`~/AFLplusplus`），runner 自动建 per-arch 链接目录 |
| frida（可选，x86 hook） | venv 内 `pip install frida`（≥17）；远程目标需 `frida-server` :27042 |
| LibreOffice（可选） | `apt-get install libreoffice-writer`（报告导出 PDF；缺了只影响 PDF，DOCX 不受影响） |
| Node.js | ≥ 20（webui 构建 / vulnagent）；dsh 引擎需 Node 22 + pnpm（`vulnagent/dsh/setup.sh` 一键装） |

环境变量（`fwgraph/.env`，模板见 `.env.example`）：

| 键 | 含义 |
|---|---|
| `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` | OpenAI 兼容网关（开发环境用 opencode go `https://opencode.ai/zen/go/v1`）/ `deepseek-v4-flash` / key |
| `LLM_MAX_CONCURRENCY` | 挖矿 AI 请求并发（默认 16） |
| `AUTO_ATTACK` / `AUTO_ROUTES` | graph 后自动生成攻击路径 / 扫描静态路由（默认 1） |
| `AUTO_ATTACK_AI` / `ATTACK_AI_MAX_PATHS` | 规则路径算完后对 Top-N 做 LLM 分诊 overlay（有 LLM_API_KEY 时默认开；`0` 关闭） |
| `CBM_GIT` / `CBM_GIT_MAX_FILES` | 摄入时是否 git 快照（默认开；文件数超过阈值或 `CBM_GIT=0` 则跳过） |
| `IDA_DIR` / `IDA_DROP_DIR` / `IDA_WORKERS` / `IDA_TIMEOUT` | IDA 路径；投放目录自动识别；rootfs_elf 并发 / 超时 |
| `EMBA_BACKEND` / `EMBA_IMAGE` / `EMBA_DIR` / `EMBA_PROFILE` / `EMBA_TIMEOUT` / `EMBA_SUDO_PASSWORD` | `docker` 走官方镜像；`script` 走本机 `./emba` |
| `TRACE_RUN_TIMEOUT` / `TRACE_HOLD_SECONDS` / `TRACE_SUDO_PASSWORD` | M7 单次覆盖率运行硬超时（默认 60s）/ 触发前后驻留（默认 2s）/ chroot 所需 sudo 密码 |
| `ORCH_HOST` / `ORCH_PORT` / `ORCH_TOKEN` | 服务绑定（0.0.0.0:8000）/ API token |
| `FLIRT_SIGS` | `1`=应用全部 `fwgraph_*.sig`；逗号列表=指定 |
| `LUMINA_ENABLED` | 保持 `0`（当前 license 被 Lumina 服务器拒绝） |
| `CBM_FULL_INDEX_MAX_FILES` | FULL 索引最大伪 C 文件数（默认 50000）；超过后使用 FAST，保留结构节点/调用/usage，省略相似性与语义边 |
| `ORCH_SSL` | 默认 `1`：HTTPS 自签（`data/tls/{cert,key}.pem`，SAN 含主机 IP/127.0.0.1/localhost）；`0` 退回明文 |
| `AUTO_INPUTS` / `AUTO_SURFACES` / `AUTO_GRAPHEXT` / `AUTO_FULL` | 自动链开关：输入识别 / 攻击面导出 / CFG·AST / 上传即全自动（默认见 .env 注释） |
| `TRACE_DAILY_PER_JOB` / `FUZZ_DAILY_PER_JOB` / `FRIDA_DAILY_PER_JOB` / `PROTOFUZZ_DAILY` / `ATTACK_AI_DAILY_PER_JOB` | 按 job×日配额（默认 10/6/6/8/8，429 中文 detail） |
| `PROTOFUZZ_ALLOW_PUBLIC` | 默认禁 fuzz 公网目标；`1` 解锁（授权自担） |
| `FUZZ_SECONDS` / `FRIDA_*` | 函数级 fuzz 时长 / frida 远程 host:port 等（见 .env 注释） |
| `VULNAGENT_COMPACT_THRESHOLD` / `VULNAGENT_COMPACT_KEEP_RECENT` | builtin 挖掘会话历史压缩：旧工具结果超阈值换首尾摘录（默认 1200 字符 / 保最近 6 条） |

PX4/NuttX raw 镜像会使用 manifest 中经过校验的 ARM loader profile：IDA 命令采用 `-pARM:ARMv7-M`，`-b` 传 16-byte paragraph（真实镜像基址除以 16），并从向量表验证的 reset entry bootstrap 函数。raw 输入若导出 0 个函数会被标记为失败；旧完成标记不会在重试中复用。这样保留的是可审计的真实反编译证据，而不是空图谱成功状态。

## 2. 启动 / 停止

```bash
bash fwgraph/scripts/run_orchestrator.sh   # :8000 = SPA 前端 + API + /cbmui 反代
bash fwgraph/scripts/run_cbm_ui.sh         # CBM UI 127.0.0.1:9749（被 /cbmui 反代）
# 停止：kill $(cat fwgraph/data/orchestrator.pid) / $(cat fwgraph/data/cbm_ui.pid)
```

前端入口：`https://192.168.141.135:8000/`（默认 HTTPS 自签，浏览器确认证书即可；账号密码登录，初始 `admin/admin123`，**首登强制改密**；主 token 仅 Bearer header，`?token=` 只收 fws- 会话 token）。
回归测试：`bash fwgraph/scripts/e2e_regression.sh`（约 15~20 分钟，报告落 `docs/e2e-report.txt`）。
单测：`fwgraph/.venv/bin/python -m pytest orchestrator/tests -q`（当前 482 个，481 通过 + 1 个已知测试间污染项）；vulnagent `npm test` 29 个全过。

## 3. 使用流程（curl 示例）

```bash
TOKEN=<fws- 会话 token 或主 token>; H="Authorization: Bearer $TOKEN"; B=https://192.168.141.135:8000
# HTTPS 自签：curl 统一加 -k（示例从略）
# 1. 上传固件（提取+反编译自动接力）
JOB=$(curl -s -X POST -H "$H" -F "file=@firmware.bin" $B/firmware | python3 -c 'import json,sys;print(json.load(sys.stdin)["job_id"])')
# 2. 轮询状态到 decompiled，然后建图
curl -s -H "$H" $B/jobs/$JOB            # pending→extracting→decompiling→decompiled
# 3. 触发图谱构建；默认自动接力攻击面和静态路由
curl -s -X POST -H "$H" $B/jobs/$JOB/graph     # → graphing → attacking → routing → routed
# 4. 浏览
curl -s -H "$H" $B/jobs/$JOB/manifest                  # 二进制清单（架构/位数/大小端/md5）
curl -s -H "$H" $B/jobs/$JOB/graph                     # nodes/edges/元数据注入统计
curl -s -H "$H" $B/jobs/$JOB/attack                    # source/sink/Top50/trace 覆盖统计
curl -s -H "$H" $B/jobs/$JOB/routes                    # IDA 路由扫描与 ROUTE 边统计
curl -s -H "$H" "$B/jobs/$JOB/functions"               # 函数列表（原名/domain/libc/trace 标签）
curl -s -H "$H" "$B/jobs/$JOB/functions/<md5>/<addr>/source"   # 单函数伪 C
# 5. M7 动态追踪：busybox httpd 收到一个包实际走过哪些函数（qemu-user + chroot，非整系统仿真）
MD5=9e39391af855fd996cdd90437e2eeb7b   # manifest 里的二进制 md5
TID=$(curl -s -X POST -H "$H" -H 'Content-Type: application/json' \
  -d "{\"binary_md5\":\"$MD5\",\"argv\":[\"httpd\",\"-f\",\"-p\",\"8080\",\"-h\",\"/www\"],\"port\":8080,\"request_path\":\"/index.html\"}" \
  $B/jobs/$JOB/trace | python3 -c 'import json,sys;print(json.load(sys.stdin)["trace_id"])')
curl -s -H "$H" $B/jobs/$JOB/traces/$TID        # 轮询到 status=ok（约 7s）
curl -s -H "$H" $B/jobs/$JOB/traces             # 该 job 全部 trace 摘要
```

M7 说明：tracer 把对应架构的 qemu-user 拷进 rootfs，`chroot` 内以 `-d exec` 跑两遍目标——baseline（启动→驻留→kill）与 trigger（启动→就绪→发一个 HTTP GET→驻留→kill），执行地址映射回 symbols.json 函数后做差分，得到"这个包的处理路径函数"（按首次执行排序）。请求体字段：`binary_md5`（必填）、`argv`（applet 参数，不含二进制自身）、`port`（服务端口，探活+发包用）、`request_path`（HTTP GET 路径；缺省则只做一次 TCP connect）、`argv0`（伪造 guest argv[0]——busybox 多合一二进制按 argv[0] 分发，如 `busybox-arm` 副本需 `"argv0":"busybox"`）。若服务已接受请求但在完整 HTTP 响应前断开，覆盖仍保留为 `ok_trigger_error`，具体传输异常写入 `trigger.trigger_result.error`；这表示请求路径被观察到，不表示业务响应成功。

## 4. 给上游分析 AI 的接入说明

接口返回的是反编译与运行证据，不是漏洞 verdict：函数地址、原始 IDA 名称、伪 C、调用边和字符串是主数据；source/sink 与路径评分是带置信度的候选索引。`verified_reachable` 仅表示同一条成功 trace 观测到完整静态函数链，不表示该链可利用或存在漏洞。上游应按需拉取路径和单函数伪 C，以更少上下文完成自己的分析。

### 方式 A：HTTP（推荐）`POST /graph/query`

函数级证据优先走 `GET /jobs/{id}/functions/{md5}/{addr}/brief`（约 1KB 分诊卡：攻击面元数据 + 伪代码头 8 行 + 危险调用行号 + callees），命中疑点再拉 `/source` 全文——批量筛查别把每个函数的全文都灌进上下文。

请求体：`{"job_id": "...", "op": "search|cypher|trace|snippet|dangerous|trace_flow|attack_surface|routes", ...}`

| op | 额外参数 | 说明 |
|---|---|---|
| `search` | `pattern`, `label=Function` | 按名字模式搜函数节点 |
| `cypher` | `query` | CBM openCypher 只读子集直查 |
| `trace` | `function`, `direction=both`, `depth` | 调用链 BFS（重名返回 suggestions，换 qualified_name 重试） |
| `snippet` | `name` 或 `qualified_name` | 取函数伪 C 全文 |
| `dangerous` | `functions=["strcpy",...]` | 查候选敏感函数的全部调用点（同时匹配节点名与 `libc_equiv`） |
| `trace_flow` | `trace_id` | M7：该 trace 差分出的有序函数路径 + 敏感 libc_equiv 高亮 |
| `attack_surface` | `source?`, `sink?`, `verified_only?`, `limit?`, `brief?` | 排序后的 source→sink 静态候选路径及 trace 覆盖状态；`brief=true` 掉链节点只留分诊字段（广扫用） |
| `routes` | `pattern?`, `method?`, `binary_md5?`, `min_confidence?` | IDA 数据段恢复的 URL→handler 映射 |
| `cfg` / `ast` | `md5`, `addr`, `max_nodes?`, `max_depth?` | M4b 控制流图 / 抽象语法树；截断参数防爆上下文 |

常用查询模板：

```jsonc
// 候选敏感函数调用点（g.name 与 g.libc_equiv 双匹配，stripped 静态二进制的
// libc 实现靠 libc_equiv 命中，如 busybox 里的 util_strcpy）
{"job_id":"X","op":"dangerous","functions":["strcpy","sprintf","system","popen","execve"]}
// 候选数据流链：网络面入口 → 候选汇（先 dangerous 找调用者，再 trace 追上游）
{"job_id":"X","op":"trace","function":"<bin>_9e39391a.http_send_response","direction":"in","depth":5}
// 攻击面函数清单（元数据已注入 nodes.properties，可直接过滤）
{"job_id":"X","op":"cypher","query":"MATCH (f:Function) WHERE f.tags CONTAINS 'auth_related' RETURN f.name, f.file_path LIMIT 50"}
// 低置信度人工复核队列（注意：缺失键按 0 处理，必须带 > 0）
{"job_id":"X","op":"cypher","query":"MATCH (f:Function) WHERE f.ai_confidence > 0 AND f.ai_confidence < 0.7 RETURN f.name, f.ai_confidence"}
// libc 等价层：直查某个 libc 函数的全部等价实现（含 SIMILAR_TO 传播来的克隆）
{"job_id":"X","op":"cypher","query":"MATCH (f:Function) WHERE f.libc_equiv = 'strcpy' RETURN f.name, f.file_path, f.libc_equiv_propagated"}
// M7 动态路径：一个请求观测到的函数（按首次执行排序），含敏感函数高亮
{"job_id":"X","op":"trace_flow","trace_id":"aa5f5273609f"}
// → sequence: [... http_handle_request → ... → util_strcpy ...]，dangerous: [{name: util_strcpy, matched: strcpy}]
// Top 攻击路径，仅返回同一 trace 覆盖完整函数链的路径
{"job_id":"X","op":"attack_surface","verified_only":true,"limit":20}
// 静态 Web 路由到处理函数
{"job_id":"X","op":"routes","pattern":"goform","min_confidence":0.9}
```

`trace_flow` 数据来自 `data/traces/<job>/<trace_id>/trace.json`（权威存储）。trace 同时也会 best-effort 喂给 CBM `ingest_traces`——CBM 0.9.0 该接口是占位桩（应答 `traces_received` 但注明 "Runtime edge creation from traces not yet implemented"），不产生运行时边，应答原文记录在 trace.json 的 `cbm_ingest` 字段。

### 方式 B：MCP stdio

CBM 本身是 MCP 服务器（15 个工具），上游 Agent 可直接挂：
`codebase-memory-mcp`（stdio），项目名 `fwgraph_<job_id>`。工具：`search_graph` / `query_graph` / `trace_path` / `get_code_snippet` 等。

## 5. 目录与数据

```
fwgraph/
├── orchestrator/app/     # FastAPI：main/extractor/decompiler/webui
├── pipeline/             # extract/decompile/graph/trace/attack/routes
├── config/naming_spec.yaml   # domain 封闭词表
├── config/attack_surface.yaml # 工控/防火墙兼容的 source/sink 分类与评分
├── libc-sigs/            # FLIRT 签名制作（build_sig.sh + docs/m2b-notes.md）
├── webui/                # Vue3 前端（npm run build → dist 由 FastAPI 托管）
├── scripts/              # run_orchestrator / run_cbm_ui / e2e_regression / m1_smoke
└── data/                 # ⚠️ 必须持久保留：CBM get_code_snippet 查询时从磁盘读伪 C
    ├── firmware/<job>/   # 上传件 + job.json
    ├── extracted/<job>/  # EMBA 解包结果（rootfs）
    ├── idb/<job>/        # IDA 数据库（回写/复用）
    ├── pseudocode/<job>/ # 伪 C + symbols.json + registry
    ├── cbm/<job>/        # CBM 目录树（含 git）+ graph_done.json
    ├── attack/<job>/     # attack_paths.json + attack_done.json
    ├── routes/<job>/     # routes_raw/routes.json/routes_done.json
    ├── inputs/<job>/     # M6a identification.json（外部输入清单，证据分级）
    ├── surfaces/<job>/   # M6b information/AS-*.json + AS-AUTH-*.json
    ├── graphext/<job>/   # M4b cfg|ast/<md5>.json
    ├── fuzz|frida/<job>/<run_id>/   # 函数级 fuzz / frida hook 运行
    ├── protofuzz/<run_id>/          # 协议 fuzz 运行（run.json + cases/faults.jsonl）
    ├── reports/          # job-*.md / pf-*.md（+ 导出缓存 docx/pdf）
    ├── tls/              # HTTPS 自签证书（ORCH_SSL=1）
    ├── users.json / sessions.json / audit.jsonl / quotas.json  # 账户/会话/审计/配额
    └── traces/<job>/<trace_id>/  # M7 覆盖率 trace（权威 trace.json）
```

## 6. 已知限制

- **函数级 fuzz 要求启动可达**：AFL++ persistent 模式要求目标函数在正常启动流程中可达（forkserver 在该地址初始化），固件 daemon 若依赖 init/chroot/网络环境会如实失败并给中文提示；PIE 目标需加加载基址。
- **协议 fuzz 是纯软件实现**：博智式硬件能力（RS232/485/CAN 业务卡、DI/AI 监视、继电器电源托管）不在范围；故障定位为监视器确认+复播复现的软件近似；默认只许私网/回环目标。
- **Lumina 不可用**：当前 IDA license 被 Lumina 服务器拒绝（`bad signature`），已预留 `LUMINA_ENABLED=1` 开关，换 license 即启用。详见 `docs/m2b-notes.md`。
- **FLIRT 年代敏感**：签名命中要求"年代×ISA×字节序×配置"四元匹配，单点 sig 对老固件收益有限（+2~+6）；签名库扩矩阵的方法见 `docs/m2b-notes.md` §4。
- **CBM cypher 陷阱**：properties 缺失键在数值比较中按 0 处理——`ai_confidence < 0.7` 会把无 AI 函数全选进来，必须 `> 0 AND < 0.7`。
- **静态 stripped 二进制**没有 libc 真名节点：图谱 ingest 仍沿 SIMILAR_TO 边传播已有 `libc_equiv`（历史任务若已写入 symbols.json 会继续被消费）。函数真实 `name` 和一遍反编译伪 C 始终不改。
- **AS-3 路由表是保守启发式**：只接受数据段 `{URL字符串指针, 函数入口指针}`；阳性样本 2/2 命中，busybox 双架构没有这种静态表所以结果为 0。不同厂商的多字段/哈希路由表需要扩展适配器，不能靠放宽规则制造命中。
- **M7 覆盖率粒度是 TB（翻译块）**：qemu `-d exec` 记录的是执行过的 TB 首地址，基本块级；函数归属靠 symbols.json 的 addr+size 区间映射，未落入任何函数的地址计为 unknown（PLT 残桩、IDA 未识别的代码）。多线程/信号时序会影响差分纯度——baseline 与 trigger 的调度差异可能把偶发路径算进差分，结果宜按"路径超集"理解。baseline 不做端口探活（探活连接本身会被 accept，曾把 `http_handle_request` 对冲掉），因此 baseline=纯启动路径，差分含 accept→读请求→响应全链路。chroot 两个坑已内置处理：rootfs 需挂 `/proc`（qemu 启动读 `mmap_min_addr`，缺失时静默退出），EMBA 解出的二进制常无执行位（qemu 同样静默失败）。rootfs 的 `/proc` 挂载会保留（幂等，供后续 trace 复用）。动态链接二进制当前未自动补 `-L`/解释器，静态链接样本（busybox）已验证。
- CBM 图索引重跑会覆盖元数据注入——`pipeline/graph/ingest.py` 幂等，重放即可。
