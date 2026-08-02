# 2026-08-03 单位电脑续开发交接

本文档用于明天在单位电脑上克隆仓库后继续开发。以本文所在提交和
`项目介绍.md` v1.5 为当前事实来源，不要根据早期历史计划重新启用 AI 改名、
IDA 回写或二遍反编译。

## 1. 项目目标

项目不是漏洞自动判定器。目标是尽量忠实、可追溯地还原反编译代码和攻击面
关系，让上游 AI 用更少上下文、更低误报率完成自己的分析。

核心证据是：函数地址、原始 IDA 名称、伪 C、调用/usage、字符串、静态路由、
候选 source/sink 和运行时 trace。AILIFT 的 `domain/libc_equiv` 属于可选兼容
字段，真实小米、PX4 和后续任务默认不运行 AILIFT。

## 2. 明天首先执行

```powershell
git clone https://github.com/tangjunyi23/firmware-code-graph-platform.git
cd firmware-code-graph-platform
git status --short --branch
git log -1 --oneline
```

不要把旧电脑的 `.env`、固件、IDB、CBM DB 或 trace 提交到 Git。单位电脑如需
访问分析 VM，通过环境变量、SSH agent 或交互式安全输入配置凭据；不要把密码或
token 写入脚本、命令历史、文档或仓库。

本地源码回归：

```powershell
cd fwgraph
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m pytest orchestrator/tests -q
cd webui
npm ci
npm run build
```

最新已验证基线为本地 `217 passed`、远端 Ubuntu Python 3.14 `217 passed`，仅有
既有 FastAPI/Starlette 弃用警告。前端 Vite 8.2.0 构建成功。

## 3. 分析 VM 当前状态

- VM：`192.168.141.135`，用户 `tankuku`
- 项目：`/home/tankuku/firmware-graph/fwgraph`
- 服务：`http://192.168.141.135:8000`
- 当前记录 PID：`78062`，PID 会漂移，操作前必须重新验证
- 当前健康检查：`{"status":"ok","jobs":12}`
- 根盘：约 98 GB，剩余约 16 GB，84% 使用
- 不得为释放空间擅自删除 IDB、伪代码、CBM DB、trace 或历史失败证据

仓库中的 `tools/remote_exec.py` 和 `tools/sftp_upload.py` 从环境变量读取连接配置。
先用只读命令确认实际进程、监听和健康状态：

```powershell
python tools/remote_exec.py 'cd /home/tankuku/firmware-graph/fwgraph; cat data/orchestrator.pid; ps -p "$(cat data/orchestrator.pid)" -o pid=,ppid=,etimes=,rss=,cmd=; ss -ltnp | grep ":8000 "; curl -fsS http://127.0.0.1:8000/healthz'
```

若修改 Python 服务代码，先在本地和 VM 跑测试，再按精确 PID `SIGTERM` 并使用
`scripts/run_orchestrator.sh` 重启。不要按进程名批量 kill。

## 4. 小米 R3 已完成证据

正式任务：`56c105fd7b9a`，最终状态 `routed`。

- IDA：274/274 binaries 成功，0 failed，0 timeout
- 函数：132,618 total，111,148 decompiled
- 图谱：337,245 nodes，1,253,251 edges，CBM skipped_count=0
- 文件覆盖：111,148 个伪 C 全部建立 Module/File 节点
- Function 节点：100,762；其余文件保留但未被 CBM 解析为完整函数定义
- 结构边：CALLS 228,637；USAGE 488,996；WRITES 198,157
- FAST 模式不生成 SIMILAR_TO/SEMANTICALLY_RELATED
- SQLite：trace 注入后再次 `PRAGMA integrity_check=ok`
- 攻击面：1,585 source，6,875 sink，Top50 paths
- routes：274/274 IDB 扫描成功，0 route，作为保守负结果保留
- AILIFT：未运行；ai_named/domain/libc_equiv 均为 0

FAST 大图修复在：

- `fwgraph/pipeline/graph/query.py`
- `fwgraph/pipeline/graph/ingest.py`
- `fwgraph/orchestrator/tests/test_graph_query.py`
- `fwgraph/orchestrator/tests/test_graph_ingest.py`

大于 `CBM_FULL_INDEX_MAX_FILES`（默认 50,000）的任务显式使用 CBM
`index_repository --mode fast`。FAST 保留节点、calls、usages 和结构解析，只省略
全局相似性/语义边，解决 7.2 GB VM 在 `semantic_edges` 阶段被 SIGKILL 的问题。

## 5. 小米动态 trace 现状

固件启动证据已经确认：

- `/etc/config/misc` 设置 `uhttpd=0`
- 实际服务是 `/usr/sbin/sysapihttpd`
- 真实 argv：`-c /tmp/sysapihttpdconf/sysapihttpd.conf`
- 真实配置监听 80、8098、5081、8195 等端口
- 动态解释器：`/lib/ld-uClibc.so.0`
- 13 个 `DT_NEEDED` 直接依赖均从同一 rootfs 解析成功

保留三条 trace：

- `8387e00e990d`：failed，缺少 chroot 内 `/tmp/run`
- `cfd371f5c054`：failed，服务接受请求后 `RemoteDisconnected`，旧 runner 丢弃覆盖
- `1a70349a5a08`：`ok_trigger_error`，覆盖成功保留

成功保留的 trace 对 8098 发送 `GET /`：baseline 418 functions、trigger 440、
diff 22。差分序列包含 `accept4`、`getsockopt`、`inet_addr`、`recv` 和原始
`sub_*`。服务在完整 HTTP 响应前主动断开，错误保存在
`trigger.trigger_result.error`，不能解释为 HTTP 响应成功。

trace 错误保真修复在：

- `fwgraph/pipeline/trace/tracer.py`
- `fwgraph/orchestrator/tests/test_trace.py`

HTTP 传输错误现在作为 `ok_trigger_error` 的子证据保存，不再抛弃已经获得的 qemu
覆盖。trace 后攻击面交叉验证结果为 1 trace / 22 observed / 1 verified function /
1 verified path。

唯一 verified path 是 `sub_41D85C` 的单节点链，`edge_count=0`。该函数调用
`accept/accept4` 和 `memcpy`，因此同时被标为 network source 与 memunsafe 候选
sink。它是 socket accept/连接对象初始化函数，只表示运行时观察到该函数，绝不
表示发现漏洞。

## 6. 明天的最高优先级

1. 先验证 VM、服务、磁盘和三条 trace 仍在，不要重新跑 IDA/graph/AILIFT。
2. 研究 sysapihttpd 完整 HTTP 响应所缺的厂商运行环境：USB root、
   `RR_PATH_STUB`、FastCGI/Lua 后端及相关运行目录。
3. 保留当前 `ok_trigger_error` 作为基线；新实验使用新 trace_id，不覆盖旧证据。
4. 建议增强 qemu runner，持久化受控大小的 guest stdout/stderr 或尾部摘要，避免
   只能通过额外 `sysapihttpd -t` 诊断早退。
5. 若获得完整 HTTP 响应，重新自动交叉验证 attack，并比较 observed/verified，
   不得为了得到更多路径放宽 source/sink 或 route 规则。
6. 最后执行远端全量 pytest、前端 build、API 检查和浏览器桌面/移动端复验，更新
   `项目介绍.md` 与本交接文档。

## 7. PX4 保留基线

正式任务 `aaae7834a0cd`，最终状态 `routed`：

- board ID 35，`px4_fmu-v6xrt`，MIMXRT1176，NuttX
- base `0x30020000`，vector offset `0x2000`，reset entry `0x300223a8`
- IDA：12,754 functions，12,750 decompiled，4 个真实失败保留
- 图谱：38,540 nodes，168,885 edges
- 攻击面：6 source，14 sink，0 path，0 route

旧失败 PX4 job 是 raw loader 回归证据，不删除。raw loader 的关键约束是 IDA `-b`
使用 16-byte paragraph、ARMv7-M、32-bit bitness、reset entry bootstrap、重试前删除
旧完成标记，以及 raw 0 functions 必须失败。

## 8. 安全与数据边界

- Git 只保存代码、测试、模板和文档。
- `.env`、API key、token、sudo/SSH 密码绝不提交。
- 固件、`.m8-inputs`、提取 rootfs、IDB、伪代码语料、CBM DB、trace 和备份只在
  受控机器保存。
- 不删除小米/PX4/历史 e2e 与两个攻击面基线数据。
- 不运行小米或 PX4 AILIFT，不做 AI 改名、IDB 回写或二遍反编译。
- source/sink、评分、observed、verified 都是证据索引，不是漏洞 verdict。
- 遇到 0 route、0 path、空差分或失败 trace 时原样保留，不制造阳性结果。

## 9. 关键文档

- `项目介绍.md`：完整状态、架构、证据统计与约束
- `fwgraph/README.md`：部署、API、运维与上游 AI 接入
- `开发计划.md`：历史方案，仅作背景；顶部现行目标说明优先
- `fwgraph/docs/m2b-notes.md`：FLIRT/Lumina/IDA 专项记录
