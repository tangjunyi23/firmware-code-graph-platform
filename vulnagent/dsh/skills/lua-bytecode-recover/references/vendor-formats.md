# 厂商定制 Lua 字节码格式与识别指南

本 skill 打包的 lua_dec 工具把厂商改过的 Lua 5.1 字节码转回标准 luac(32 位、LE、
`size_size_t=4`),转换结果用 unluac / luadec 反编译。本文给出各厂商定制点、识别方法和实测坑。

## 标准格式基线(Lua 5.1 luac)

- 魔数 `1B 4C 75 61`(`\x1bLua`),版本字节 0x51
- 头 12 字节:signature(4) + version(1) + format(1) + endian(1) + size_int(1) +
  size_size_t(1) + size_instruction(1) + size_lua_number(1) + lua_num_valid(1)
- 之后是顶层 Proto:source 字符串、linedefined/lastlinedefined、nups/numparams/is_vararg/
  maxstacksize、code 段(sizecode + N×4 字节指令)、constants、嵌套 protos、lineinfo、
  locvars、upvalues

## 各厂商定制点(与标准的差异)

| `-n` 取值 | 魔数 | 操作码 | 字符串 | 其他 |
|-----------|------|--------|--------|------|
| `tplink` | 标准 `\x1bLua` | **重排**(查表置换,非标准 opcode 编号) | 明文 | 无 |
| `teltonika` | 标准 `\x1bLua` | 标准 | 明文 | 与 ubiquiti 模块逐字节相同 |
| `ubiquiti` | 标准 `\x1bLua` | 标准 | 明文 | 与 teltonika 模块逐字节相同 |
| `xiaomi` | **`\x1bFate/Z\x1b`** | **重排** | **按长度 XOR**:每字节异或 `(size*13+55)&0xff` | 头部解析兼容该魔数 |

注:解析器内部用"4 字节反转 + 大端位流"解析指令字段,这是对标准 LE u32 的正确解析方式,
不是厂商定制;teltonika/ubiquiti 实测可直接往返标准格式。

## 如何识别文件属于哪个厂商

1. **看魔数**:`1B 46 61 74 65 2F 5A 1B`(`\x1bFate/Z\x1b`)→ 小米,用 `-n xiaomi`。
2. **标准魔数 `\x1bLua`** → 来自固件厂商上下文判断:
   - TP-Link 固件解包出的 `.lua`/luac → `-n tplink`
   - Teltonika / Ubiquiti 固件 → `-n teltonika` / `-n ubiquiti`(两者等价)
   - 不确定时先用 `-n teltonika` 转换(等价于标准解析),再用 unluac 反编译;
     若反编译结果大量报错/opcode 异常,换 `-n tplink` 再试(操作码重排文件用标准解析会得到
     语义错乱的指令,但解析本身不报错——**不会自动失败,必须看反编译结果质量**)。
3. **文件以 `#!` 开头**:工具会自动跳过首行(`head_strip`),无需预处理。

## 转换后反编译

```bash
# unluac(推荐,对 5.1 支持最好)
java -jar unluac.jar file.dec > file.lua
# 或 luadec(注意用 5.1 分支)
luadec -s file.dec
```

`-d` 参数只解析并打印结构树(construct 对象),用于人工检查常量表/函数嵌套,不产出文件。

## 已知坑(实测确认)

1. **只支持 32 位(size_size_t==4)**。原版遇到 64 位文件**静默不写任何输出**(无报错);
   本 skill 打包版已改为显式报错退出。运行后若没有 `.dec` 文件,先看头部的 size 字节。
2. 原版 `-n` 缺失会抛 KeyError、文件不存在会抛 NameError;打包版改为 argparse 清晰报错
   (`-n` 现为必填,取值限四个厂商名)。
3. 操作码重排文件(tplink/xiaomi)用错误厂商名转换**不会报错**,只会产出语义错误的 luac——
   务必以 unluac 反编译结果是否可读作为最终判据。
4. 常量表出现 `LUA_TINT`(类型 9)时是厂商魔改(Lua 5.1 标准无常量整数类型),工具会把它
   当 number 转换并打 warning "translate may not success"——转换后需人工核对数值常量。
5. 工具不做源码级反编译,只做字节码格式归一化;反编译依赖 unluac/luadec(需本机有 Java
   或 luadec 5.1)。

## 模块清单(scripts/lua_dec/)

- `main.py` — CLI 入口(本 skill 打包版,含错误处理补丁;原版见上游压缩包)
- `lua_ori.py` — 标准 Lua 5.1 格式(转换目标)
- `lua_tplink.py` / `lua_teltonika.py` / `lua_ubiquiti.py` / `lua_xiaomi.py` — 各厂商解析器
- 依赖:`construct>=2.9,<3`(2.10.70 实测通过;3.x API 不兼容)
