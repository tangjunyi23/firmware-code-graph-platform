# SQL注入 专项分析策略

**Sources（输入源）：**
- HTTP 请求参数（GET/POST/Cookie/Header）
- JSON/XML body 字段
- URL 路径参数
- 配置文件或数据库中用于构造后续查询的值

**Sinks（危险操作）：**
- 直接执行 SQL 的函数：sqlite3_exec, cursor.execute, Statement.execute, db.Query, db.Exec
- ORM 的 raw/extra/where/order_by 接受原始字符串的方法
- 字符串拼接后传入 SQL 执行函数的路径
- MyBatis/iBatis 中 `${}` 替换（而非 `#{}` 参数绑定）

**Key Check（关键检查点）：**
1. 用户输入是否直接拼接进 SQL 字符串（通过 sprintf/format/+/concat/f-string）？
2. 是否使用了参数化查询但在表名/列名/ORDER BY 部分仍使用拼接？
3. ORM 框架中 Order/Where/Having 子句是否接受了原始用户输入？
4. 是否存在多层封装但内层仍使用字符串拼接的情况？
5. 存储过程中是否使用 EXECUTE/EXEC 拼接动态 SQL？

**Common Patterns：**
- `sprintf(sql, "SELECT * FROM t WHERE id='%s'", user_input)` → `sqlite3_exec(db, sql, ...)`
- `db.Order(user_input)` — ORM 的排序参数直接传入用户输入
- `query = "SELECT ... WHERE name='" + request.getParameter("name") + "'"`
- `cursor.execute(f"SELECT * FROM users WHERE id={uid}")`
- MyBatis XML: `<select>SELECT * FROM ${tableName}</select>`
