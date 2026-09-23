# 文件上传 专项分析策略

**Sources：**
- multipart/form-data 上传的文件名和内容
- 上传路径/目录参数
- Content-Type 头
- 分块上传的各块

**Sinks：**
- move_uploaded_file / copy / rename
- 文件保存到 web 可访问目录
- 文件保存到 .git/config 等特殊位置
- 解压/解码后保存

**Key Check：**
1. **过滤顺序问题**：替换链的顺序是否可被利用？
2. **basename() 不足**：不同语言/平台下处理编码/路径分隔符的行为不同。
3. **扩展名绕过**：黑名单是否覆盖 `.php5/.phtml/.shtml/.phar/.jsp/.jspx` 等？
4. **Content-Type 伪造**：是否仅依赖 Content-Type 头判断文件类型？
5. **特殊文件位置**：上传到 `.git/config` 可注入 `core.sshCommand` 实现 RCE。
6. **双重扩展名**：`shell.php.jpg` 在特定服务器配置下可执行。
7. **TreePath/目录参数控制**：上传函数是否允许用户通过目录路径参数控制存储位置？检查过滤是针对文件名还是目录路径。
8. **多上传点排序**：优先报告有防护但可绕过的上传点，而非完全无防护的简单上传。

**Common Patterns：**
- 路径过滤 `str_replace("..", "")` + `str_replace("/", "")` 可通过 `./.` 绕过
- 上传 TreePath 参数允许 `.git/config` 路径 → 注入 sshCommand
- 扩展名白名单检查后保存时使用原始文件名（TOCTOU）
- `dirPath = path.Join(localPath, opts.TreePath)` — TreePath 可控时可创建 `.git/` 子目录
