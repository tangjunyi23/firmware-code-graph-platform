# 反序列化 专项分析策略

**Sources：**
- HTTP POST body / Request body
- WebSocket 数据帧
- TCP/UDP 网络流
- Cookie / ViewState / Session 数据
- 消息队列消费
- 文件上传内容

**Sinks：**
- ObjectInputStream.readObject() / readResolve()
- PHP unserialize()
- pickle.loads() / yaml.unsafe_load() / yaml.load(Loader=FullLoader)
- XMLDecoder.readObject()
- JSON 反序列化带类型推断（Fastjson autotype、Jackson enableDefaultTyping）

**Key Check：**
1. **白名单/过滤器深度**：resolveClass 是否只检查外层类？嵌套字段引用的类是否也受限？
2. **自动触发方法**：反序列化后哪些方法会被自动调用？`readObject / readResolve / hashCode / equals / toString / compareTo / finalize`。
3. **延迟执行链**：LazyList 首次访问时触发计算 → 调用用户控制的函数对象。
4. **gadget chain 可用性**：classpath 中是否有已知 gadget 库？
5. **无前置校验的网络流**：WebSocket/TCP 直接将接收数据传入反序列化？

**Common Patterns：**
- WebSocket codec.decode → ObjectInputStream.readObject — 直接从网络流反序列化
- Scala LazyList.readResolve → state.head() → 触发延迟计算 → 执行任意 Function0
- resolveClass 仅检查 `!= dangerous_class` 但 LazyList 不在黑名单中
- Cookie 中的序列化对象无签名校验直接 unserialize
