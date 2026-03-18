# SSL/TLS 协议与加密套件合规基线

## 1. 目的与适用范围

本文档用于统一 ARL 在 `SSL证书` 扫描与导出报告中的 TLS 合规判定口径，解决“哪些安全、哪些不安全、哪些虽然能用但不符合当前互联网基线”的判断不一致问题。

适用范围：

- 互联网 Web 服务、API 网关、反向代理、负载均衡入口
- 常规主机部署（Nginx / Apache / 其他基于 OpenSSL 的服务）
- Kubernetes 集群入口（尤其是 `ingress-nginx`）

本文档对应当前导出基线版本：

- 基线名称：`ARL TLS 基线`
- 基线版本：`2026.03`

## 2. 扫描结果如何解读

ARL 当前 SSL 证书扫描会重点输出以下字段：

- `支持协议`：目标开启了哪些 TLS/SSL 协议版本
- `最弱强度`：扫描器给出的最弱等级（A-F）
- `加密套件`：每一行通常是 `[协议] 套件名 (附加参数) (评分)`

示例：

```text
[TLSv1.2] TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (dh 1024) (D)
[TLSv1.2] TLS_RSA_WITH_AES_128_GCM_SHA256 (rsa 2048) (A)
[TLSv1.3] TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519) (A)
```

说明：

- `(dh 1024)` 表示服务端有限域 DH 参数仅 1024 位，这本身就是风险点
- `(rsa 2048)` 这里表示证书/密钥信息，不等于“密钥交换方式安全”；`TLS_RSA_WITH_*` 仍然是静态 RSA 密钥交换，不提供前向保密
- 扫描器字母等级只能作为参考，最终是否合规以“协议版本 + 密钥交换方式 + 加密算法 + 摘要算法 + DH 参数”联合判定

## 3. ARL 当前合规基线

### 3.1 协议基线

| 协议 | 结论 | 说明 |
| --- | --- | --- |
| `TLSv1.3` | 合规 | 推荐优先启用 |
| `TLSv1.2` | 合规 | 允许启用，但必须配合推荐套件 |
| `TLSv1.1` | 不合规 | 已废弃，不应继续对公网提供 |
| `TLSv1.0` | 不合规 | 已废弃，不应继续对公网提供 |
| `SSLv3` / `SSLv2` | 不合规 | 高风险旧协议，必须关闭 |

### 3.2 推荐套件基线

#### TLS 1.3 允许的标准套件

以下视为合规：

- `TLS_AES_128_GCM_SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_CCM_SHA256`
- `TLS_AES_128_CCM_8_SHA256`

说明：

- `TLS_AKE_WITH_AES_128_GCM_SHA256` 这类扫描结果会在分析时归一化为 TLS 1.3 标准套件名
- TLS 1.3 不再使用旧版 `TLS_RSA_WITH_*` / `TLS_ECDHE_RSA_WITH_*` 这一类命名

#### TLS 1.2 允许的基线套件

以下模式视为合规：

- `ECDHE_RSA` 或 `ECDHE_ECDSA` + `AES_GCM`
- `ECDHE_RSA` 或 `ECDHE_ECDSA` + `CHACHA20_POLY1305`
- `DHE_RSA` + `AES_GCM / CHACHA20_POLY1305`，且 `DH >= 2048`
- `ECDHE_*` / `DHE_RSA` + `AES_CCM`，且满足上述前向保密与位数要求

实践上，公网入口建议优先只保留以下几类：

- `ECDHE-ECDSA-AES128-GCM-SHA256`
- `ECDHE-RSA-AES128-GCM-SHA256`
- `ECDHE-ECDSA-AES256-GCM-SHA384`
- `ECDHE-RSA-AES256-GCM-SHA384`
- `ECDHE-ECDSA-CHACHA20-POLY1305`
- `ECDHE-RSA-CHACHA20-POLY1305`

### 3.3 判定为不合规的内容

以下内容一律标记为不合规：

- 旧协议：`SSLv2`、`SSLv3`、`TLSv1.0`、`TLSv1.1`
- 弱算法：`RC4`、`3DES`、`DES`
- 弱摘要：`MD5`
- 空套件或导出套件：`NULL`、`EXPORT`
- 匿名套件：`ADH`、`AECDH`、`anon`
- 静态密钥交换：`TLS_RSA_WITH_*`、`TLS_DH_*`、`TLS_ECDH_*`
- `CBC` 套件：例如 `AES_128_CBC`、`AES_256_CBC`、`3DES_EDE_CBC`
- 弱 DHE 参数：如 `(dh 1024)`、`ffdhe1024`
- 不属于当前推荐基线的 TLS 1.2/TLS 1.3 套件

### 3.4 关于“不合规”与“可连接”的区别

本基线中的“不合规”不完全等于“立刻可被利用”，而是表示：

- 不符合当前互联网公开服务的推荐加固基线
- 可能缺少前向保密
- 可能使用已被弃用或不再推荐的算法族
- 会在监管、测评、等保、渗透、审计中成为高频扣分项

例如：

- `TLS_RSA_WITH_AES_128_GCM_SHA256`
  说明：虽然用了 `AES-GCM`，但仍属于静态 RSA 密钥交换，不提供前向保密，因此判定为不合规
- `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (dh 1024)`
  说明：算法模式本身可接受，但 `dh 1024` 低于最小基线，因此判定为不合规
- `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`
  说明：`ECDHE` 提供前向保密，但 `CBC` 不在当前公网基线内，因此判定为不合规

## 4. 导出报告中的判定规则

`SSL证书` 工作表新增两列：

- `不合规项（协议/套件）`
- `修复建议`

写入规则：

- 若未发现不合规项，这两列保持为空
- 若发现不合规项，会按“协议优先、套件其次”的顺序写入
- 同一套件如果同时命中多条规则，会合并为一行，避免重复刷屏

导出示例：

```text
[协议] TLSv1.0 -> 旧版协议已淘汰，应仅保留 TLSv1.2/TLSv1.3
[TLSv1.2] TLS_RSA_WITH_AES_128_GCM_SHA256 -> 静态密钥交换不提供前向保密
[TLSv1.2] TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (dh 1024) -> 使用 RC4/3DES/DES 等弱加密算法；CBC 套件不在当前互联网 TLS 加固基线内；DHE 参数仅 1024 位，低于 2048 位基线
```

## 5. 常规部署模式加固方法

### 5.1 通用加固原则

- 仅启用 `TLSv1.2` 和 `TLSv1.3`
- 优先 `ECDHE + AES-GCM / CHACHA20`
- 若必须保留 `DHE`，DH 参数至少使用 `2048` 位
- 关闭 `TLSv1.0`、`TLSv1.1`、`RC4`、`3DES`、`DES`、`MD5`、`CBC`、`NULL`、`EXPORT`
- 避免 `TLS_RSA_WITH_*` 这类静态 RSA 密钥交换套件

### 5.2 Nginx 示例

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
ssl_ecdh_curve X25519:secp256r1:secp384r1;
ssl_dhparam /etc/nginx/ssl/dhparam.pem;
```

生成更强 DH 参数：

```bash
openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048
```

说明：

- 如果业务与客户端兼容性允许，建议优先保留 `ECDHE` 套件，逐步移除 `DHE`
- `ssl_prefer_server_ciphers on` 主要对 TLS 1.2 及以下生效

### 5.3 Apache HTTPD 示例

```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
SSLHonorCipherOrder on
SSLOpenSSLConfCmd Curves X25519:secp256r1:secp384r1
```

说明：

- Apache 上如需保留 DHE，同样应配套 2048 位以上 DH 参数
- TLS 1.3 套件选择主要由底层 OpenSSL 能力决定，如需更细粒度控制，应先确认运行时 OpenSSL 版本与指令支持情况
- 如果后端 OpenSSL 版本较旧，应优先升级运行时，再收紧套件配置

## 6. Kubernetes 集群部署加固方法

### 6.1 ingress-nginx ConfigMap 示例

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ingress-nginx-controller
  namespace: ingress-nginx
data:
  ssl-protocols: TLSv1.2 TLSv1.3
  ssl-ciphers: ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
  ssl-prefer-server-ciphers: "true"
  ssl-dh-param: "ingress-nginx/lb-dhparam"
```

若集群中仍需 `DHE`，建议显式提供高强度 DH 参数：

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: lb-dhparam
  namespace: ingress-nginx
type: Opaque
stringData:
  dhparam.pem: |
    -----BEGIN DH PARAMETERS-----
    ...
    -----END DH PARAMETERS-----
```

并在 `ingress-nginx` ConfigMap 中通过 `ssl-dh-param: ingress-nginx/lb-dhparam` 关联该 Secret。

### 6.2 Ingress 层分业务定制

当某个业务需要单独收紧策略时，可在 Ingress 注解中覆盖：

```yaml
metadata:
  annotations:
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
    nginx.ingress.kubernetes.io/ssl-prefer-server-ciphers: "true"
```

### 6.3 集群场景额外注意项

- 云厂商 LB、Gateway API、Service Mesh、Istio、Envoy 入口如果终止 TLS，也必须同步套用同等策略
- 只改 Pod 内应用，不改集群入口 TLS 策略，通常无法真正消除风险
- 若 TLS 在外部负载均衡层终止，最终应以外部 LB 的协议与套件配置为准进行核验

## 7. 修复优先级建议

推荐按以下顺序整改：

1. 先关闭 `SSLv2/SSLv3/TLSv1.0/TLSv1.1`
2. 再移除 `RC4/3DES/DES/MD5/NULL/EXPORT/匿名套件`
3. 再移除 `TLS_RSA_WITH_*`、`TLS_DH_*`、`TLS_ECDH_*`
4. 再移除 `CBC` 套件
5. 最后清理“不在基线内但暂未构成立即高危”的剩余套件，并统一到推荐套件列表

## 8. 变更后的验证方法

建议在整改后重新执行以下验证：

```bash
nmap --script ssl-enum-ciphers -p 443 <host>
```

或：

```bash
openssl s_client -connect <host>:443 -tls1_2
openssl s_client -connect <host>:443 -tls1_3
```

验证目标：

- 仅剩 `TLSv1.2` / `TLSv1.3`
- 不再出现 `RC4/3DES/DES/MD5/CBC/TLS_RSA_WITH_*`
- 若存在 `DHE`，参数不低于 `2048`
- 导出报告中 `不合规项（协议/套件）` 为空

## 9. 参考基线

- RFC 9325, Recommendations for Secure Use of TLS and DTLS
- RFC 8996, Deprecating TLS 1.0 and TLS 1.1
- RFC 8446, The Transport Layer Security (TLS) Protocol Version 1.3
- NIST SP 800-52 Rev.2, Guidelines for the Selection, Configuration, and Use of TLS Implementations
- OWASP Transport Layer Security Cheat Sheet
- Nginx `ngx_http_ssl_module` 官方文档
- Apache `mod_ssl` 官方文档
- ingress-nginx 官方文档（`ssl-protocols` / `ssl-ciphers` / `ssl-dh-param`）
