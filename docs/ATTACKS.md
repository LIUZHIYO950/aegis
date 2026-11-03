# SSDS 可防御攻击全景

> 准确率优先策略：每条攻击类型标注判定信号与误报控制手段。

## 一、网络层 (L3)

| 攻击 | 防御机制 | 判定信号 | 误报控制 |
|---|---|---|---|
| SYN Flood | tcp_syncookies=1、syn 限速 300/s、半连接队列调优 | 内核半连接计数、iptables limit | 限速阈值远高于正常峰值 |
| UDP Flood | UDP 新连接限速 20/s/IP | 连接状态 NEW | 业务 UDP 端口可在 firewall.sh 中放行 |
| ICMP Flood / Smurf | ICMP echo 限速 5/s、忽略广播 | ICMP 类型 | 正常 ping 不受影响 |
| 畸形包 (XMAS/NULL/FIN) | 特征 flag 组合直接 DROP | tcp flags 匹配 | 合法流量无这些组合 |
| 端口扫描 | recent 模块 30s/15 次连接触发封禁 | 新 SYN 频率 | 扫描器必然触发 |
| DDoS 放大攻击 (NTP/DNS/SSDP) | 默认关闭非必要 UDP 端口；业务需用时在 firewall.sh 显式放行并限速 | 端口 + 速率 | 配置式控制 |

## 二、传输层 (L4)

| 攻击 | 防御机制 | 判定信号 | 误报控制 |
|---|---|---|---|
| TCP 连接耗尽 | 单 IP 并发连接上限 200、keepalive 调优 | 并发连接数 | 阈值可配 |
| Slowloris | client_header_timeout 10s、连接上限 | 头部发送超时 | 正常用户不受影响 |
| Slow POST | client_body_timeout 10s、send_timeout 10s | body 发送超时 | 大文件上传可在配置中调大 |
| 连接资源耗尽 | netdev_max_backlog、somaxconn 65535 | 内核队列 | 内核参数 |

## 三、应用层流量 (L7-CC)

| 攻击 | 防御机制 | 判定信号 | 误报控制 |
|---|---|---|---|
| HTTP Flood / CC | 全局 1s/3s/10s 三窗口熔断 + 30s 冷却 | 无签名 Cookie 流量计数 | 持证用户全程不受影响 |
| 恶意爬虫 / 无头浏览器 | 高置信 UA 直接拦截；可疑 UA 转 JS 挑战 | UA 指纹 + PoW 挑战结果 | 真人浏览器几秒通过 |
| 扫描器探测 | UA 指纹拦截 + 路径探测频率封禁 | 特征 + 频率 | 低置信只记录不拦截 |
| 撞库 / 登录爆破 | 单 IP 限流 5s/80 次 + WAF 登录路径频率 | 请求频率 | 限流阈值可配 |

## 四、Web 层漏洞 (L7-WAF)

| 攻击 | 覆盖规则 | 说明 |
|---|---|---|
| SQL 注入 | 10001-10008 | union/经典/注释/时间盲注/报错/十六进制/函数调用 |
| XSS | 10008-10012 | script 标签/事件处理器/编码绕过/DOM 对象 |
| 命令注入 | 10013-10015 | 命令拼接/反引号/编码变体 |
| 路径遍历 | 10016 | ../ 变体/敏感路径/伪协议 |
| 文件包含 LFI/RFI | 10017 | include/require 参数化 |
| XXE | 10018 | DOCTYPE SYSTEM/PUBLIC |
| SSRF | 10019 | 内网地址/云元数据 |
| 恶意文件上传 | 10020 | 可执行扩展名 |
| 模板注入 SSTI | 10021 | Jinja2/Twig/EL |
| LDAP 注入 | 10022 | 通配/逻辑组合 |
| JSON 注入 / 原型链污染 | 10023 / 10036 | __proto__/constructor |
| HTTP 走私 | 10024 | CL/TE 冲突 |
| CRLF 注入 | 10029 | 响应头注入 |
| 开放重定向 | 10030 | // 跳转 |
| 已知 CVE | 10039-10042 | Log4Shell/Spring4Shell/ShellShock |
| 敏感文件泄露 | 10026 / 10038 | .git/.env/actuator 等 |

## 五、系统层 (OS)

| 攻击 | 防御机制 |
|---|---|
| SSH 暴力破解 | ssh-guard.sh：auth 日志 2min 窗口 ≥5 次失败 → 持久黑名单 + 内核级 DROP |
| 撞库 / 接口爆破 | 登录接口独立限流（60s/10 次，超限封禁 30min） |
| 文件篡改 / 植入后门 | fwmon.sh：关键路径 hash 基线，每小时比对，变更即告警 |
| 挖矿木马 | WAF 规则拦截矿池/矿机特征；fwmon 检测新增文件 |
| fork 炸弹 / 进程耗尽 | limits.d nproc 上限（4096/8192）、pid_max 调优 |
| 磁盘 / 内存耗尽 | hardening.sh：根分区 >85%、PSI 压力、日志增长自动告警 |
| 提权尝试 | 安全基线：SSH 禁 root 登录（可选）、审计增强（HISTTIMEFORMAT） |

## 六、v1.1 新增攻击覆盖 (WAF 规则 10045-10064)

| 攻击 | 规则 | 说明 |
|---|---|---|
| JWT none 算法 / kid 注入 | 10045/10046 | 伪造签名算法绕过、kid 路径注入 |
| GraphQL Introspection | 10047 | `__schema`/`__type` 探测 |
| Java/PHP 反序列化 | 10048/10061 | ysoserial、rO0AB、O: 前缀 gadget |
| FastCGI / PHP 协议 | 10049 | php://input、/proc/self/environ |
| Redis / Memcached 命令 | 10050/10051 | 未授权 CONFIG/SLAVEOF/FLUSHALL |
| 云元数据 SSRF | 10052 | 169.254.169.254 等内网地址 |
| CORS 滥用 / DNS Rebinding | 10053/10054 | origin 反射、八进制/十六进制 IP |
| 2FA/验证码绕过 | 10055 | captcha=off 等参数绕过 |
| 价格/优惠券篡改 | 10056 | price=0、discount=100 |
| 后台路径枚举 | 10057 | wp-admin/phpmyadmin/actuator 等探测 |
| file:// 参数注入 | 10058 | url/file 参数指向本地文件 |
| Log4Shell 混淆变体 | 10059 | ${jndi:${::-j}...} 嵌套混淆 |
| SpEL 模板注入 | 10060 | ${T(java.lang...)} |
| 邮件头注入 | 10062 | %0d%0aBcc 注入 |
| 密钥/凭证路径探测 | 10063 | /vault/、/secret/ 等 |
| WebShell 变体 | 10064 | .php5/.phtml/.jspx/.war 等 |

## 局限说明 / Honest Limits

1. **超大带宽洪泛**（数十 Gbps+）：需运营商 / 云高防 / CDN 配合（SSDS 部署在源站前置）。
2. **业务逻辑漏洞**（越权、竞态、流程缺陷）：WAF 无法覆盖，需安全编码与渗透测试。
3. **0day 漏洞**：规则集 30 秒热更新机制（替换 rules JSON + reload 即生效），社区可提交规则。
4. **分布式慢速攻击**：单 IP 限流不适用时，需配合熔断阈值调低。
