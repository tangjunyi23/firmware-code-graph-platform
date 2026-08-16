# 命令注入 专项分析策略

**Sources：**
- HTTP 表单字段、查询参数
- API 请求 body
- 文件名/路径
- 用户可控的配置值

**Sinks：**
- os.system / os.popen / subprocess.Popen(shell=True) / subprocess.call(shell=True)
- Runtime.getRuntime().exec（当参数为单字符串时经 shell 解释）
- child_process.exec（Node.js）
- eval / exec / eval_js / Function() 构造器
- popen / system / backtick（反引号）执行

**Key Check：**
1. **黑名单不完整**：过滤了 `;|&` 但是否遗漏了 `$()`、反引号、`\n`、`\r`、`\t`、`{}`？
2. **参数拼接后 shell=True**：`" ".join(args)` 或字符串拼接后以 shell 模式执行。
3. **eval 类直接执行**：`eval(user_input)` / `eval_js(user_input)` / `exec(user_code)` — 任意代码执行。
4. **参数注入**：即使不经 shell，是否可通过 `--option=value` 形式注入危险参数？
5. **环境变量注入**：是否可通过设置 `LD_PRELOAD`、`PATH` 等影响子进程？
6. **多步过滤绕过**：过滤器是否只执行一次？`;;` 过滤 `;` 后变成 `;`？

**Common Patterns：**
- 黑名单过滤 `& ; | \`` 但遗漏 `$()` 和 `\n`（换行符）
- `subprocess.Popen(f"cmd {user_input}", shell=True)` — 直接拼接
- `eval_js(f"{user_input}.someMethod()")` — 用户输入进入 JS eval
- `cmd = base_cmd + " " + filename; os.system(cmd)` — filename 可注入
