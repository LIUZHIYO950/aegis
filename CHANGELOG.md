# Changelog

## [1.1.0] - 2026-11-02

### 新增 / Added
- WAF 规则从 44 条扩至 64 条：新增 JWT（none 算法 / kid 注入）、GraphQL Introspection、
  反序列化 Gadget（Java/PHP）、FastCGI 协议、Redis/Memcached 命令注入、云元数据 SSRF、
  CORS 滥用、IP 混淆/DNS Rebinding、2FA/验证码绕过、价格/优惠券篡改、后台路径枚举、
  file:// 参数注入、Log4Shell 混淆变体、SpEL/模板注入、邮件头注入、密钥路径探测、
  WebShell 变体扩展名 等 20 类
- 登录/认证接口独立限流（撞库爆破防护）：60s/10 次，超限封禁 30 分钟
- UA 聚合熔断：多 IP 同 UA 的分布式 CC 检测
- 蜜罐路径模块：诱捕后台扫描者，命中即记录并拦截（默认关闭）
- 系统资源加固：fork 炸弹防护（nproc 限制）、PID 上限、OOM 保护、审计增强
- 磁盘/内存压力监控：根分区 >85%、PSI 压力、日志增长自动告警
- TLS/HTTPS 安全模板：TLS1.2/1.3、强套件、HSTS、会话票据关闭
- 安全响应头：Permissions-Policy、server_tokens off 全局化

### 修复 / Fixed
- alert_threshold 配置项取值错误（on → 100）
- WAF 规则 JSON 正则转义修复

## [1.0.0] - 2026-11-02

### 新增 / Added
- 五层纵深防御架构：网络层(L3) / 传输层(L4) / 应用层(L7 流量) / Web 层(L7 漏洞) / 系统层(OS)
- WAF 规则引擎：44 条内置规则，覆盖 SQLi / XSS / 命令注入 / 路径遍历 / LFI-RFI / XXE / SSRF / 恶意文件上传 / 模板注入 / LDAP / JSON / HTTP 走私 / 原型链污染 / Log4Shell / ShellShock / Spring RCE / Actuator 暴露 / 扫描器 UA / 敏感文件 等 40+ 攻击类别
- 单 IP 滑动窗口限流 + 全局多窗口熔断（CC / HTTP Flood）
- JS 工作量证明挑战 + HMAC-SHA256 无状态签名 Cookie（拦截无头机器人，真人无感通过）
- 静态 + 动态双层黑名单（秒级生效，跨重启持久化）
- 恶意爬虫 / 扫描器指纹识别（高置信直接拦截，可疑 UA 转挑战）
- 慢速攻击防护（Slowloris / Slow POST）nginx 层配置
- 内核网络参数自动调优（SYN Cookie / 队列 / 畸形包防护）
- iptables / nftables 自适应防火墙（SYN/UDP/ICMP 限速、端口扫描抑制、畸形包丢弃）
- SSH 暴力破解自动封禁（auth 日志分析 + 双重封禁）
- 文件完整性监控（轻量 AIDE，基线比对 + 变更告警）
- Python 分析守护进程：攻击聚合、自动持久封禁、Webhook（钉钉/飞书/企业微信）与 SMTP 告警
- 一键部署脚本，自动识别 12+ Linux 发行版；源码部署 / 发布包部署双通道
- `aegis` CLI 管理命令（status / ban / unban / log / key）

### 修复 / Fixed
- （相对 LADS）修正分布式部署下 X-Forwarded-For 取源逻辑
- 挑战页 PoW 算法改为轻量哈希（防机器人但不拖慢真人）
- 防火墙规则幂等化，重复执行不产生重复规则

### 说明 / Notes
- 本版本为防护系统 v1，Tbps 级带宽洪泛仍需云高防 / CDN 配合
