# 任意文件写入 专项分析策略

**Sources：**
- 上传文件名（Content-Disposition filename）
- API 请求中的路径/文件名参数
- 归档文件（zip/tar）内的文件条目名
- XSLT/模板输入
- 日志内容和路径参数

**Sinks：**
- open(path, 'w') / fopen / fwrite / file_put_contents
- move_uploaded_file / shutil.copy / fs.writeFile
- zipfile.extractall / tar.extractall（无路径检查）
- XSLT exsl:document / xsl:result-document
- 模板引擎输出到可控路径

**Key Check：**
1. **os.path.join 绝对路径覆盖**：Python 的 os.path.join 遇到绝对路径参数会丢弃前面的 base_dir。
2. **归档解压路径穿越（ZipSlip）**：解压时是否检查文件名中的 `../`？
3. **XSLT 写文件**：`exsl:document` 或 `xsl:result-document` 可指定任意输出路径。
4. **文件名净化不充分**：是否只检查了扩展名但未检查路径穿越字符？
5. **竞争条件**：先写临时文件再移动——临时文件是否写在可被利用的位置？

**Common Patterns：**
- `os.path.join(base_dir, user_filename)` — user_filename 以 `/` 开头时覆盖 base_dir
- XSLT: `<exsl:document href="{user_controlled_path}">` — 写任意文件
- `ZipFile.extractall(target_dir)` — zip 内含 `../../etc/cron.d/evil` 条目
