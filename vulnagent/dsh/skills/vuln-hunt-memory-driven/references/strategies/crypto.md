# 密码学实现漏洞 专项分析策略

**红队视角**：密码学实现漏洞可导致认证绕过、数据泄露或 RCE（如 IV 溢出→栈溢出→代码执行）。在审计密码学库（OpenSSL/GnuTLS/BoringSSL 等）时尤为重要。

**Sources：**
- 证书/消息中的 IV/Nonce 字段
- ASN.1 结构中的长度/大小字段（keyLength、saltLength）
- PKCS 标准中的参数字段
- TLS 握手消息中的扩展数据
- 密钥交换消息中的公钥/参数

**Sinks：**
- IV/Nonce 到固定大小缓冲区的拷贝（memcpy/memset）
- KDF 输出缓冲区分配（malloc/alloc）
- HMAC/MAC 密钥使用（密钥长度影响安全性）
- 加密/解密操作的输入缓冲区
- 签名验证中的哈希计算

**Key Check：**
1. **IV/Nonce 长度验证**：加密 API 接受的 IV 数据是否验证长度与算法期望一致？AES-GCM 期望 12 字节 IV，若接受任意长度且直接 memcpy 到栈缓冲区 → 栈溢出。
2. **KDF 密钥长度溢出**：PBKDF2/HKDF/scrypt 的输出密钥长度是否来自外部输入且无上界？极大长度可导致 OOM 或整数溢出。
3. **填充 Oracle**：解密失败时是否返回不同的错误消息（区分填充错误 vs 解密错误）？
4. **时序侧信道**：密钥/MAC 比较是否使用恒定时间函数（`CRYPTO_memcmp`/`constant_time_compare`）？
5. **TLS 证书验证禁用**：HTTP 客户端连接外部服务时，是否存在配置项/环境变量可禁用 TLS 证书验证？默认值是否安全？
6. **弱随机数**：密钥/IV/Nonce 生成是否使用 CSPRNG？是否存在回退到 `rand()`/`Math.random()` 的路径？
7. **ASN.1 解析深度**：嵌套的 ASN.1 结构解析是否有深度限制？是否存在递归解析导致栈溢出？

**Common Patterns：**
- `memcpy(iv_buf, asn1_iv->data, asn1_iv->length)` — iv_buf 为固定 12/16 字节，asn1_iv->length 未验证
- `key_len = asn1_integer_to_long(params->keyLength); key = malloc(key_len)` — key_len 来自证书/消息
- `if (decrypt_result == PADDING_ERROR) return -1; else if (decrypt_result == OTHER_ERROR) return -2;` — 填充 oracle
- `HttpClient::builder().danger_accept_invalid_certs(true)` — TLS 验证禁用
- `ACCEPT_INVALID_CERTS=true` 环境变量控制 TLS 验证行为

**Combo Chain Patterns：**
- IV 溢出 → 栈溢出 → 控制流劫持 → RCE
- KDF 长度溢出 → 截断密钥 → 认证绕过
- 填充 Oracle → 解密任意密文 → 伪造认证 token
- TLS 验证禁用 → MITM → 凭据窃取 → 横向移动
