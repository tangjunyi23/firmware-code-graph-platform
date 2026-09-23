---
name: lua-bytecode-recover
description: >
  恢复/转换 IoT 固件中厂商定制的 Lua 5.1 字节码(TP-Link、Teltonika、Ubiquiti、小米):
  把改过魔数/操作码/字符串混淆的 luac 转回标准 Lua 5.1 字节码,再用 unluac/luadec 反编译出源码。
  当用户提到 TP-Link lua 反编译/恢复、lua 字节码恢复、luac 解密/转换、Fate/Z 魔数、
  小米/路由器固件 .lua 文件无法读取、固件里的 Lua 脚本加密等场景时使用本 skill。
  Use when firmware Lua 5.1 bytecode fails standard tools due to vendor customization.
---

# IoT 厂商定制 Lua 字节码恢复(TP-Link/Teltonika/Ubiquiti/小米)

路由器/IoT 固件常见把 Lua 5.1 字节码做厂商魔改(改魔数、重排操作码、字符串 XOR),
导致 unluac/luadec 直接报错。本 skill 用打包的 lua_dec 工具把这些格式**转回标准 luac**,
之后用常规反编译器恢复源码。只做字节码格式归一化,反编译本身交给 unluac/luadec。

## 依赖

- Python 3 + `construct` 2.x:`python -m pip install "construct<3"`(3.x API 不兼容;2.10.70 实测通过)
- 反编译:Java + unluac.jar(推荐)或 luadec 5.1 分支(可选,只转换不反编译时不需要)

## 使用

```bash
# 转换:厂商定制 luac -> 标准 Lua 5.1 luac(32位),输出 <infile>.dec
python <本skill目录>/scripts/lua_dec/main.py <infile> -n <tplink|teltonika|ubiquiti|xiaomi> [-o <outfile>]

# 只解析打印结构树(检查常量/函数嵌套,不产出文件)
python <本skill目录>/scripts/lua_dec/main.py <infile> -n tplink -d

# 转换后反编译
java -jar unluac.jar <infile>.dec > <infile>.lua
```

## 选厂商名(-n)

- 文件头是 `1B 46 61 74 65 2F 5A 1B`(`\x1bFate/Z\x1b`)→ 小米,`-n xiaomi`
- 标准 `\x1bLua` 魔数 → 按固件来源:TP-Link → `-n tplink`;Teltonika/Ubiquiti → `-n teltonika`
  /`-n ubiquiti`(两者等价)
- 来源不确定:先 `-n teltonika`(≈标准解析)转换,unluac 反编译结果语义错乱再换 `-n tplink`
  ——操作码重排的文件用错误厂商名转换**不报错但产出错误结果**,必须以反编译可读性为判据

完整的厂商定制点对照表、文件识别流程、已知坑见 [references/vendor-formats.md](references/vendor-formats.md)——
转换失败或结果可疑时先读它。

## 关键限制(先看这个再跑)

1. **只支持 32 位字节码**(头部 `size_size_t==4`)。64 位文件无法转换,本打包版会显式报错
   (原版工具静默不输出——若在别处运行原版,没有 `.dec` 产出多半是这个原因)。
2. 常量出现 `LUA_TINT`(魔改整数类型)时转换带 warning,数值常量需人工核对。
3. 固件解包出的 `.lua` 若首行是 `#!` 注释,工具自动跳过,无需预处理。
