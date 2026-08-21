# Phase 1: Attack Surface Locking

## fwgraph 平台路径（固件任务）

对 fwgraph job：先 `fw_get_identification` / `fw_list_surfaces`，再用 `fw_attack_surface brief=true`。identification 的 `processing_chain.unresolved_needed` 只是 DT_NEEDED 质量缺口，不要另换固件树。路径节点用 `evidence_address`（job_id + md5 + 规范地址）跨工具连接，不要用路径或符号名。动态结果 `observed_in_window` ≠ 请求导致，也不要报覆盖率百分比；`verified` 必须是同一条 trace 覆盖整条链。若返回 `ai_review`，把 `priority=P0/P1` 当作分诊提示（不是漏洞结论）；必须再用 `fw_get_function_source` 的 Hex-Rays 伪代码核实。禁止把 hint 写入 finding，禁止引用臆造符号。`decompile_gap` 只表示缺伪代码。

---

## Phase 1 条件执行（Round 2+ 且 snapshot 存在时）

当 Phase 0.5 成功恢复了 snapshot 状态时，以下步骤可跳过或简化：

- **跳过 §1.1（文件枚举）和 §1.2（文件分级）**：目标目录的文件在轮次间不会变化，无需重新枚举和分级
- **跳过 §1.2.5（权限架构枚举）**：若 snapshot 中 `permission_architecture.enumeration_complete` 为 `true`。若为 `false`，则继续执行枚举
- **§1.3 和 §1.4 仅针对 pending 攻击面执行**：仅对 snapshot 中 `attack_surface.surfaces` 里 `status: "pending"` 的攻击面执行多层分析和调用链追踪。`analyzed` 和 `excluded` 状态的攻击面不重复分析
- **§1.5 更新模式**：更新 `attack-surface.md` 时，追加新发现的攻击面条目，不重写已分析的条目

若 Phase 0.5 未执行（Round 1 或 snapshot 不存在/损坏），Phase 1 按完整流程执行，不跳过任何步骤。

## 1.1 文件枚举
使用 shell 工具 (`rg --files`, `file`) 枚举目标目录下所有文件。

> **禁止**：不得对 ELF/PE/SO 等二进制文件使用 `strings` 或 `objdump` 分析 sink 语义。`strings` 仅允许用于提取 URL 路径、协议字符串等路由信息，**不得作为判断 sink 是否存在或 sink 语义是否安全的依据**。二进制 sink 分析必须通过 `references/phase1_binary_analysis.md` 的反编译流程完成。

> **二进制目标**：当目标包含二进制文件（ELF/PE/SO 等）或存在 `decompile/` 目录时，**必须加载 `references/phase1_binary_analysis.md`** 执行反编译和逆向增强分析。

## 1.1.2 依赖分析与 Sink 扩展（MANDATORY — Round 1）

**此步骤不可跳过。** 文件枚举完成后、路由提取之前，必须读取目标的依赖声明文件，根据实际使用的库动态扩展当前漏洞类型的 sink 列表。

### 步骤

1. **定位依赖声明文件**（按优先级）：
   - Rust: `Cargo.toml`
   - Python: `requirements.txt` / `pyproject.toml` / `setup.py` / `Pipfile`
   - Node.js/TS: `package.json`
   - Java/Kotlin: `pom.xml` / `build.gradle` / `build.gradle.kts`
   - Go: `go.mod`
   - PHP: `composer.json`
   - Ruby: `Gemfile`

   **Fallback（依赖声明文件不存在时，MANDATORY）**：当以上文件均不存在（如 fat jar 解包产物、反编译代码）时，**不得直接跳过**，改为从 import 语句推断依赖：
   ```bash
   # Java 反编译产物
   rg -l "import javax.naming" --type java          # → JNDI 可用
   rg -l "import org.apache.directory\|import com.unboundid" --type java  # → LDAP client
   rg -l "import com.mongodb\|import org.bson" --type java   # → MongoDB
   rg -l "import org.springframework.expression" --type java # → SpEL
   rg -l "import ognl\." --type java                         # → OGNL
   rg -l "import freemarker\|import org.thymeleaf" --type java  # → 模板引擎
   ```
   发现上述 import 后，按步骤 2 的规则追加对应 sink。在 `attack-surface.md` 的"技术栈 Sink 扩展"节标注"来源：import 推断（无依赖声明文件）"。

2. **识别库并追加 Sink**：发现以下库时，向当前漏洞类型的 sink 列表**追加**对应 sink（不替代策略文件默认 sink）：

   | 依赖库关键词 | 注入类型 | 追加的 Sink 关键词 |
   |------------|---------|-----------------|
   | `ldap3` / `python-ldap` / `openldap` / `ldap` | LDAP 注入 | `LdapConn` / `ldap_search` / `ldap_add` / `ldap_modify` / `search_s` / `simple_bind` |
   | `pymongo` / `motor` / `mongoengine` | NoSQL 注入 | `find(` / `aggregate(` / `$where` / `mapReduce` / `eval(` |
   | `redis` / `ioredis` / `redis-py` | Redis 注入 | `eval(` / `script` / 拼接 key 后 `execute_command` |
   | `jinja2` / `mako` / `chameleon` / `tornado` | SSTI | `Template(` / `render_template_string(` / `Environment(` |
   | `PyYAML` / `ruamel.yaml` | 不安全反序列化 | `yaml.load(` （非 `safe_load`） |
   | `elasticsearch` / `opensearch` | ES 注入 | query string 拼接 / `_search` script 字段 |
   | `spring-expression` / `ognl` / `mvel` | EL 注入 | `parseExpression(` / `Ognl.getValue(` / `MVEL.eval(` |
   | `pyyaml` / `snakeyaml` | 反序列化 | `yaml.load` / `Yaml().load(` |
   | `subprocess` / `os` (Python) | 命令注入 | `shell=True` 时的 `subprocess.run/call/Popen` / `os.system` / `os.popen` |
   | `ldap` / `Net::LDAP` (Ruby/Go/PHP) | LDAP 注入 | `search(` / `bind(` / `modify(` |

3. **输出**：在 `attack-surface.md` 开头增加 `## 技术栈 Sink 扩展` 节，记录：
   - 发现的依赖库列表
   - 追加的 sink 类型和关键词
   - 若未发现任何需要扩展的库，记录"无额外 sink 扩展"

4. **Round 2+ 跳过条件**：若 snapshot 中 `attack_surface.sink_extension_done` 为 `true`，跳过此步骤。

## 1.1.5 强制全量路由/入口提取（MANDATORY — Web 应用）

**此步骤不可跳过、不可简化、不可被记忆覆盖。** 对 Web 应用（PHP/Python/Java/Node.js/Go/Ruby 等），在做文件分级之前，必须先提取完整的前台路由表：

### 步骤

1. **定位路由分发入口**：找到主入口文件（`index.php`、`urls.py`、`routes.js`、`Application.java`、`main.go` 等）中的路由分发逻辑（switch-case、路由注册表、URL pattern 映射）。

2. **提取全量路由列表**：逐一列出所有路由分支及其对应的控制器/处理函数，不允许遗漏。格式：

   ```
   | 路由 | 控制器/处理函数 | 文件位置 | 是否需要认证 |
   |------|---------------|---------|------------|
   | page=search | CWebSearch::doModel | controller/search.php | 否 |
   | page=language | CWebLanguage::doModel | controller/language.php | 否 |
   | ... | ... | ... | ... |
   ```

3. **前台可达性标注**：对每个路由判断是否需要认证。不需要认证的路由全部标记为前台攻击面候选。

4. **逐路由 sink 快筛**：按漏洞类型选择搜索范围：

   - **效果型目标**（"认证前RCE"/"Pre-auth RCE"/"远程代码执行"）：**必须同时**搜索以下四类 sink：

   | Sink 类型 | 关键词（跨语言） |
   |----------|----------------|
   | 命令执行 | `system/exec/popen/proc_open/subprocess/spawn/Runtime.exec/os.system` |
   | SQL 注入 | `query/execute/prepare/cursor/where.*\$/sprintf.*SELECT/string.*concat.*sql/QueryBuilder` |
   | 反序列化 | `unserialize/readObject/ObjectInputStream/pickle.loads/yaml.load/marshal.loads/JSON.parse.*eval` |
   | SSRF | `curl/file_get_contents/requests.get/http.get/fetch.*url/HttpClient.*uri` |
   | JNDI / 动态类加载 | `InitialContext.lookup/InitialDirContext/NamingManager/URLClassLoader/Class.forName.*loader` |
   | 外向网络调用（次级） | `new URL(.*).openConnection/InetAddress.getByName/OkHttpClient/WebClient.*uri` |

   - **明确类型目标**（"SQL注入"/"缓冲区溢出"/"命令注入"等）：**只搜对应类型的 sink**，参照 §1.2 分级策略表中该类型的关键词，不展开其他类型。

   对发现的每个 sink，标记为 P0 候选并记录文件:行号。

5. **输出完整路由表**到 `attack-surface.md` 开头，作为后续 P0/P1/P2 分级的基础。P0 的分母必须基于此完整路由表，而非仅已深入分析的路由。

### 覆盖率要求

- Phase 4 Challenge Agent 验证 `attack_surface_coverage` 时，**分母必须等于全量路由表中前台可达路由的总数**
- 若存在未分析的前台路由，verdict 必须为 LOOP
- 声称"P0 覆盖率 100%"时，必须列出分母来源（如"全量路由表 10 条前台路由，已分析 10 条"）

### analyzed 标记约束（MANDATORY）

将攻击面入口标记为 `status: "analyzed"` 必须同时满足以下所有条件，否则保持 `status: "pending"`：

1. **已识别 security_decision_function**：具体函数名（如 `check_session`、`AuthenticatorBase.invoke`），不可写"存在认证检查"等模糊描述
2. **给出明确 pre-auth 可达性结论**：`preauth_reachable` 必须为 `YES` / `NO` / `CONDITIONAL` 之一，不可留 `UNKNOWN`
3. **analysis_depth >= 3**：已完成三层分析（Entry → Security Decision → 初步 Sink 方向）

**不满足以上条件时**：保持 `status: "pending"`，在 `next_round_directive.priority_targets` 中列为下轮优先目标。

**深度分析额外要求**（status=analyzed 后继续推进）：
- 若 `preauth_reachable` 为 `YES` 或 `CONDITIONAL`，必须在后续轮次继续追踪到 `analysis_depth >= 4`（完整 source→sink + guard 分析），推进为 `deep_analyzed`
- `analysis_depth >= 4` 的入口计入 `deep_analyzed_p0` 和 `deep_coverage_pct`

## 1.1.8 测试/示例/模糊测试代码降级（MANDATORY）

以下目录中的代码文件**默认降级为 P2**，不作为主要漏洞候选的来源：

| 目录模式 | 说明 |
|---------|------|
| `test/`, `tests/`, `testing/`, `t/` | 测试代码 |
| `examples/`, `example/`, `samples/`, `sample/`, `demo/` | 示例代码 |
| `fuzz/`, `fuzzing/`, `fuzzers/`, `afl/`, `libfuzzer/` | 模糊测试代码 |
| `benchmarks/`, `benchmark/`, `perf/` | 性能测试代码 |
| `testdata/`, `test_data/`, `fixtures/` | 测试数据 |
| `vendor/`, `third_party/`, `external/` | 第三方代码（除非用户明确指定） |

**例外条件**：
1. 当用户明确指定分析测试代码时，可提升为 P0/P1
2. 当 P0 生产代码中存在对测试目录文件的直接 import/include 时，被引用的文件按正常规则分级
3. 第三方代码若为自行修改的 fork 版本（有本地 diff），可提升为 P1

**红队视角规则**：红队关注的是生产环境中可利用的漏洞。测试代码中的漏洞即使真实存在，在生产部署中通常不可达，因此不具有红队价值。

**Phase 4 硬校验**：如果 FINAL.md 中主要发现的代码证据（文件路径）位于上述目录中，Challenge Agent 的 verdict 必须为 LOOP，并指示下一轮转向生产代码分析。

## 1.2 漏洞类型驱动的文件分级

根据用户指定的漏洞类型，对文件进行优先级分级。文件数量较多时（>15个源文件），必须执行分级以控制后续分析范围。

**分级策略（按漏洞类型）：**

| 漏洞类型 | P0 最高优先（必须深入分析） | P1 次优先 | P2 低优先 |
|----------|---------------------------|----------|----------|
| SQL注入 | 含数据库操作的文件（query/exec/prepare/cursor/ORM调用） | 路由/控制器/API端点 | 纯工具类/配置/静态资源 |
| 缓冲区溢出 | 含 memcpy/strcpy/sprintf/sscanf/recv 的C/C++文件 | 含指针运算和数组操作的文件 | 纯头文件/常量定义 |
| 整数溢出/整型溢出 | 含算术运算(乘法/加法/减法/位移)且操作数来自外部输入的文件 | 含类型转换(cast)和大小计算的文件 | 无外部输入处理的内部工具 |
| 认证绕过 | 认证/登录/session相关文件 | 中间件/过滤器/权限检查文件 | 业务逻辑/数据处理文件 |
| 命令注入 | 含 system/exec/popen/eval/subprocess 的文件 | 含用户输入处理和过滤逻辑的文件 | 纯数据处理文件 |
| 文件上传 | 含上传处理/文件保存/路径拼接的文件 | 含文件名过滤/扩展名检查的文件 | 非文件操作文件 |
| 任意文件读取/文件读取 | 含文件读取/路径拼接/include/forward的文件 | 含URL路由/路径解析的文件 | 非IO操作文件 |
| 任意文件写入 | 含文件写入/模板渲染/归档解压的文件 | 含路径处理/配置操作的文件 | 只读操作文件 |
| 反序列化 | 含 readObject/unserialize/pickle.loads/yaml.load 的文件 | 含网络IO/数据解码的文件 | 纯POJO/数据结构定义 |
| 内存溢出 | 含偏移计算/缓冲区操作/MDL/NBL处理的文件 | 含数据包解析的文件 | 纯定义/常量文件 |
| 路径穿越 | 含路径拼接/normalize/resolve操作的文件 | 含用户输入到文件系统操作链路的文件 | 无路径操作的文件 |
| 格式化字符串 | 含 printf/sprintf/snprintf/fprintf/syslog 且参数来自外部输入的文件 | 含自定义日志/输出封装函数的文件 | 无格式化输出的文件 |

### 1.2.3 大型二进制全局子系统枚举（>50MB 反编译文件 MANDATORY）

当目标为单个大型反编译文件（>50MB）时，禁止直接锚定某一子系统开始分析。必须先执行全局枚举：

1. **协议/服务入口枚举**：
   - 搜索所有网络监听相关函数（socket/bind/listen/accept/SSL_accept）
   - 搜索所有 HTTP 路由注册（URL 字符串、路由表、handler 注册）
   - 搜索所有私有协议标识（magic number、protocol version、handshake 字符串）
   - 对每个入口记录：协议类型、监听端口/路径、入口函数地址

2. **子系统分级**：
   - 对识别到的每个子系统独立做 P0/P1/P2 分级
   - 预认证可达的子系统一律为 P0
   - 不同子系统的分析不可互相替代（分析了子系统 A 不等于覆盖了子系统 B）

3. **覆盖率要求**：
   - Phase 4 Challenge Agent 必须验证所有 P0 子系统是否都已被分析
   - 若存在未分析的 P0 子系统，verdict 必须为 LOOP

### 1.2.5 权限架构枚举（MANDATORY — 认证前RCE / 认证绕过 / 协议分析专用）

当目标涉及自定义协议、命令分发器或认证框架时，必须在攻击面分析前完成权限架构枚举：

1. **命令/操作码清单构建**：
   - 枚举分发器（dispatcher/handler table/switch-case）中所有命令ID/操作码
   - 对每个命令记录：命令ID、处理函数、功能描述

2. **权限策略提取**：
   - 搜索所有 `set_policy`、`check_auth`、`requires_auth`、`policy=`、`auth_level=` 等权限设置调用
   - 对每个命令标注其权限策略值（如 `policy=0` 表示免认证，`policy=1` 表示需认证）
   - **特别关注**：`policy=0` / `auth_required=false` / `no_auth` 等标记的命令——这些是真正的预认证攻击面

3. **预认证命令集确定**：
   - 从步骤 2 的结果中筛选出所有免认证命令
   - 对每个免认证命令，分析其处理函数的功能和可达的危险操作（文件读写、命令执行、配置修改等）
   - **关键区分**：仅返回会话ID/连接标识的命令（如 connect/bridge）vs 直接执行敏感操作的命令（如文件操作、配置修改）——后者才是高价值攻击面

4. **输出**：权限架构表，包含命令ID、处理函数、权限策略、是否预认证、可达危险操作摘要。此表供后续 Phase 2 精确定位使用。

**子代理派发**：当命令数量 > 20 时，建议使用 `permission-model-enumerator` 子代理自动化枚举。

## 1.3 多层攻击面分析（MANDATORY）

攻击面分析必须覆盖以下三个层次，不可只做 sink 关键词搜索：

**层次 1：数据入口层（Entry Layer）**
- 识别所有外部数据进入程序的入口点（网络监听、文件读取、API端点、协议解析入口）
- 对每个入口点标注其数据格式和可控性

**层次 2：安全决策层（Security Decision Layer）**
- 识别所有做安全决策的函数（认证检查、权限验证、输入过滤、路径校验、大小校验）
- **特别注意**：安全决策函数**之前**的路由/分发函数——这些函数决定请求是否需要经过安全检查
- 对认证绕过类型：必须识别认证检查前的 URL 路由/白名单/分发逻辑
- 对缓冲区溢出类型：必须识别所有长度计算和边界检查函数

**层次 3：危险操作层（Sink Layer）**
- 识别所有 sink 函数（参照对应漏洞类型策略文件中的 Sinks 列表）
- 回溯每个 sink 的调用链到入口层

**跨层覆盖检查**：分析完成后，验证三个层次之间的映射关系。如果存在"入口层有数据流入但安全决策层无对应检查"的情况，该路径为高优先候选攻击面。

对 P0 文件做完整阅读和分析，对 P1 文件做关键函数扫描，P2 文件仅在 P0/P1 中发现跨文件调用链时才深入。

> **认证流程分析**：当目标漏洞类型涉及"认证前RCE"/"认证绕过"或目标为 Web 应用时，**必须加载 `references/phase1_auth_analysis.md`** 执行认证管线分析、认证机制分析和 Auth Bypass 路径评估。

### 1.3.5 工厂/策略/分发模式强制枚举（MANDATORY）

**此规则解决动态分发导致的系统性遗漏。** 当调用链中遇到以下任意模式时，**不得在接口/抽象层停止分析**，必须枚举所有具体实现并逐一追踪：

#### 触发条件（遇到以下任一即触发）

- `createXxxConnector(type)` / `getHandler(type)` / `factory.create(type)` — 工厂方法
- `switch(type) { case A: ... case B: ... }` — 枚举分发
- `registry.get(key)` / `handlerMap.get(cmd)` — 注册表查找
- `@Component("ldapCert")` + `@Autowired List<IConnector>` — Spring 多实现注入
- 接口 `I.method()` 的调用，且代码库中存在多个实现类 `ImplA`, `ImplB`...

#### 强制执行步骤

1. **枚举所有 case/实现类**：搜索 `implements IXxx` / `extends BaseXxx` / `case TYPE_A`，列出全部具体类名
2. **逐类独立分析**：对每个具体实现类的目标方法执行独立的 source->sink 路径分析
3. **特别关注高危实现类型**：
   - 认证 Connector：`LdapCertificate` / `Ldap` / `Saml` / `Oidc` 类型往往含外部网络调用
   - 文件处理器：各格式 Parser 往往含路径操作或反序列化
   - 脚本执行器：各语言 Evaluator 往往含 EL/命令执行
4. **在 call_graphs.md 中记录**：每个分支的分析状态（已分析 / 排除及原因）

#### 禁止行为

- **禁止**以"`IConnector.authenticateUser()` 接口层无 sink"作为排除整个分发路径的理由
- **禁止**仅分析"最明显"或"命名最相关"的实现类而跳过其他实现类

## 1.4 跨文件/跨函数调用链追踪

当候选攻击面涉及跨文件调用时：
1. 必须追踪完整的调用链，不能因为跨文件就停止分析
2. 对每个跨文件调用，记录调用者和被调用者的参数传递关系
3. 特别关注：函数 A 在文件 X 中分配内存/计算大小，函数 B 在文件 Y 中使用该内存/大小——这种跨文件的"分配-使用不一致"是常见漏洞模式

## 1.5 输出
按风险排序的攻击面列表，保存到 `attack-surface.md`。列表需标注：
- 每个攻击面与用户指定漏洞类型的相关度
- 所属层次（Entry / Security Decision / Sink）
- 跨文件调用链（如有）
- 认证流程分析（`phase1_auth_analysis.md` 的输出，含认证后高危功能和 Auth Bypass 路径评估）
- 每个入口的 `analysis_depth`（1-5）和 `preauth_reachable`（YES/NO/CONDITIONAL/UNKNOWN）

每轮 Phase 1 结束时，在 `attack-surface.md` 末尾更新覆盖率摘要块：

```
## 覆盖率摘要（Round N）
- total_p0: X
- analyzed_p0 (depth≥3): Y  （coverage_pct: Y/X * 100%）
- deep_analyzed_p0 (depth≥4): Z  （deep_coverage_pct: Z/X * 100%）
- pending: X-Y 个（列出 ID）
```
