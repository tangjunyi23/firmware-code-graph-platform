# 路径穿越 专项分析策略

**Sources：**
- URL 路径段 / 请求路径
- 归档文件内的路径名
- git submodule / 子项目路径
- 配置文件中的路径引用
- API 请求中的文件路径参数

**Sinks：**
- 文件创建/写入（open/write/mkdir）
- 文件读取（open/read）
- 文件删除（unlink/rmdir）
- 路径拼接函数（path.join/os.path.join/Path.resolve）
- git clone/checkout 操作

**Key Check：**
1. **../逃逸**：路径中的 `../` 是否被完全过滤？是否有编码绕过？
2. **路径标准化 vs 验证顺序**：先验证再标准化，还是先标准化再验证？
3. **submodule/子项目路径逃逸**：submodule_path 含 `../` 可逃逸 work_tree。
4. **符号链接穿越**：先创建合法符号链接再利用其指向目标外文件。
5. **is_absolute_path 检查**：是否只检查了绝对路径但未检查相对路径中的 `../`？
6. **平台差异**：Windows 使用 `\`，某些检查只过滤 `/` 而遗漏 `\`。

**Common Patterns：**
- `path = work_tree + "/" + user_path` — user_path 含 `../../` 逃逸
- git submodule path 未充分验证 `..` 分量
- `if(!path.startsWith(base)) deny` — path 未 normalize 可绕过
- zip 解压时 entry.getName() 含 `../` 未校验
