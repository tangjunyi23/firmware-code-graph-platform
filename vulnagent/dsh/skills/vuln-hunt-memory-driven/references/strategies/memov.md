# 内存溢出（OOB 读写） 专项分析策略

**Sources：**
- 网络数据包中的字段（长度、偏移、类型标识）
- 设备驱动接收的缓冲区描述符（MDL/NBL/sk_buff）
- 文件格式头部字段
- 用户态传入内核的参数

**Sinks：**
- 指针偏移后的解引用 (`*(ptr + offset)`)
- memcpy/memmove 使用计算偏移
- 数组索引访问 (`buf[calculated_index]`)
- 结构体成员赋值（经偏移计算定位）
- NdisAdvanceNetBufferListDataStart / NdisRetreatNetBufferListDataStart

**Key Check：**
1. **偏移计算与边界检查不匹配**：`if(pkt_len >= HDR_SIZE)` 但实际访问 `buf[HDR_SIZE + conditional_offset]`。
2. **条件分支额外偏移**：某代码分支对指针做了额外加法，但边界检查在分支外。
3. **有符号/无符号混用**：偏移量为有符号类型，负值导致向前越界。
4. **realloc 后旧指针**：缓冲区缩小后仍用原大小范围访问。
5. **结构体对齐陷阱**：packed struct 的 sizeof 与编译器实际分配不一致。

**Common Patterns：**
- `offset = base_hdr_size; if(has_vlan) offset += 4; if(pkt_len >= base_hdr_size + 8) memcpy(buf, pkt+offset, 8)` — 有 VLAN 时 offset 超过检查范围
- 驱动中 `NdisAdvanceNetBufferListDataStart(nbl, calculated_offset)` — calculated_offset 因条件分支变大超过 DataLength
- 内核结构体解析：`header->field` 访问超出实际分配的 sk_buff 数据区
