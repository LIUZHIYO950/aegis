# SSDS — 超级服务器防御系统 / Super Server Defense System

> 中文名：**超级服务器防御系统** ｜ 英文名：**Super Server Defense System** ｜ 缩写：**SSDS**（工程代号 `aegis`）

> 继 LADS 之后的下一代开源防御系统：面向大、中、小型任意 Linux 服务器。
> The next-generation open-source defense system after LADS: built for any Linux server, from tiny VPS to large bare-metal.

SSDS 是一个**全攻击面、多层纵深**的服务器防御系统。基于 OpenResty/Lua 的纳秒级请求防护 + Python 守护进程的深度分析 + 内核/防火墙的系统级加固，一套代码适配所有主流发行版，两种部署方式任选。

SSDS is a **full-attack-surface, multi-layer defense** system: nanosecond request protection (OpenResty/Lua) + deep analysis daemon (Python) + OS-level hardening (kernel/firewall). One codebase, all mainstream distros, two deployment modes.

---

## 核心特性 / Key Features

- **全攻击面覆盖** — 网络层 / 传输层 / 应用层 / Web 层 / 系统层五层纵深防御，覆盖 40+ 类攻击。
- **不计文件大小** — 功能完整优先，规则库、日志、黑名单全量内置。
- **任何服务器都能部署** — 自动识别 CentOS / Ubuntu / Debian / TencentOS / OpenCloudOS / AlmaLinux / Rocky / Fedora 等发行版，一键部署。
- **两种部署方式** — 源码 `git clone` + `bash deploy.sh`，或发布包解压 + `bash deploy.sh`。
- **毫秒级响应** — 请求级防护跑在 OpenResty 请求处理阶段（Lua JIT，微秒级判定）；动态封禁秒级生效。
- **高准确率** — 分层多信号判定 + 可配置白名单 + 规则分级（拦截/记录），大幅降低误杀。
- **零云厂商依赖** — 纯开源组件，无 SaaS 绑定，数据完全自持。

---

## 可防御攻击矩阵 / Attack Coverage Matrix

| 层级 Layer | 攻击类型 Attacks | 防御机制 Defense |
|---|---|---|
| 网络层 L3 | SYN Flood、UDP Flood、ICMP Flood、Smurf、端口扫描、畸形包(XMAS/NULL)、DDoS 放大(NTP/DNS/SSDP) | 内核参数调优、iptables/nftables 限速、半连接限制、畸形包丢弃 |
| 传输层 L4 | TCP Flood、Slowloris、Slow POST、连接耗尽、TCP 重放 | 连接超时、连接数限制、慢速请求超时 |
| 应用层 L7-流量 | HTTP Flood/CC、恶意爬虫、无头浏览器流量、扫描器、分布式同 UA 洪水 | 全局多窗口熔断、单 IP 滑动窗口限流、UA 聚合熔断、JS 工作量证明挑战、HMAC 签名 Cookie |
| Web 层 L7-漏洞 | SQLi、XSS、路径遍历、命令注入、文件包含、XXE、SSRF、恶意文件上传、模板注入、LDAP/JSON 注入、HTTP 走私、JWT 攻击、GraphQL 探测、反序列化 Gadget、FastCGI、Redis/Memcached 命令、Log4Shell 混淆变体、SpEL、开放重定向、CRLF 注入 | WAF 规则引擎（64 条规则，正则 + 关键词多模式） |
| 系统层 OS | SSH/Web 暴力破解、撞库、文件篡改、挖矿木马、fork 炸弹、磁盘/内存耗尽 | SSH 防护器、登录失败自动封禁、登录接口独立限流、文件完整性监控、资源限制、磁盘/内存压力告警 |

---

## 架构 / Architecture

```
                 ┌────────────────────────────────────────────┐
  客户端请求 ───▶ │ SSDS 防护层 (OpenResty + Lua, 纳秒级)        │
                 │  黑名单 → WAF规则 → 限流 → 熔断 → JS挑战 → 放行 │
                 └───────────────┬────────────────────────────┘
                                 │ 正常流量转发
                 ┌───────────────▼────────────────────────────┐
                 │ 业务后端 (Nginx / Node / Java / PHP ...)     │
                 └────────────────────────────────────────────┘

  系统加固层 (install 阶段执行)：
    iptables/nftables 防火墙规则 · 内核网络参数 · SSH 防护 · 系统更新建议

  分析守护层 (Python aegisd, 每 5 秒)：
    攻击日志聚合 → 自动持久化封禁 → 告警通知(Webhook/邮件) → 文件完整性扫描
```

## 快速开始 / Quick Start

SSDS 提供两种部署方式：**源码部署**（跟随上游更新）与**发布包一键部署**（快速上手）。两种方式最终都执行同一个 `deploy.sh`，安装到 `/opt/aegis`，差别只在文件来源。

> 部署前置条件：root 权限、可联网（apt / yum / dnf）、内存 ≥ 512MB。参见下方「环境要求」。

---

### 方式一：源码部署 / From Source

适用：想跟随 GitHub 上游持续更新、自己 fork 改造的情况。部署的是仓库最新代码。

**第 1 步：拉取源码**

```bash
git clone https://github.com/liuzhiyo950/aegis.git
cd aegis
```

**第 2 步：一键部署**

```bash
sudo bash deploy.sh <后端Host> <后端端口>
```

- `<后端Host>` `<后端端口>`：你的业务后端地址（SSDS 会把通过防护的流量转发给它）。
- 示例：`sudo bash deploy.sh 127.0.0.1 8080`（本机 Nginx/Node/Java 后端）
- 也支持不指定参数：`sudo bash deploy.sh`，自动把本机任意正在监听的 HTTP 端口识别为后端并接入。

`deploy.sh` 会自动完成：识别发行版（CentOS/Ubuntu/Debian/TencentOS/AlmaLinux/Rocky/Fedora 等）→ 安装 OpenResty → 生成随机 HMAC 密钥 → 渲染配置文件 → 写入防火墙/内核加固规则 → 启动 SSDS 防护层与守护进程。

**第 3 步：更新到最新版**

```bash
git pull            # 拉取上游更新
sudo bash deploy.sh # 重新部署（幂等，可重复执行）
```

---

### 方式二：发布包一键部署 / From Release Package

适用：不想装 Git、追求最快上手；或从 Release 附件/文叔叔链接直接下载的场景。部署的是固定发布版本。

**第 1 步：下载并解压发布包**

从 GitHub Releases 或文叔叔链接下载 `aegis-1.1.0.tar.gz`，然后：

```bash
tar -xzf aegis-1.1.0.tar.gz
cd aegis
```

**第 2 步：一键部署**（与方式一完全一致）

```bash
sudo bash deploy.sh <后端Host> <后端端口>
# 示例: sudo bash deploy.sh 127.0.0.1 8080
# 或不指定参数自动识别后端: sudo bash deploy.sh
```

**第 3 步：升级到新版本**

下载新版 tar.gz → 解压到新目录 → 再次执行 `sudo bash deploy.sh`（配置与密钥在 `/opt/aegis` 保持不变，规则库与脚本覆盖更新，黑名单等运行数据保留）。

---

### 两种方式对比 / Comparison

| 维度 | 源码部署 | 发布包一键部署 |
|------|----------|----------------|
| 文件来源 | `git clone` 拉仓库最新代码 | Release 附件 tar.gz |
| 前置工具 | 需装 Git | 无需 Git，有 tar 即可 |
| 更新方式 | `git pull` + 重新部署 | 下载新版 tar.gz 重新部署 |
| 适合场景 | 开发/跟随上游/fork 改造 | 生产快速上线、离线分发 |
| 部署入口 | `sudo bash deploy.sh` | 同左（完全相同） |

### 部署后检查 / Post-install Check

```bash
sudo aegis status         # 防护状态总览（模块、规则数、封禁数）
sudo aegis log tail       # 查看攻击日志
sudo aegis ban 1.2.3.4    # 手动封禁某 IP
sudo aegis unban 1.2.3.4  # 手动解封某 IP
```

验证防护生效：从另一台机器发起 `ab -n 2000 -c 100 http://你的服务器/` 或普通 CC 脚本，`sudo aegis log tail` 应看到熔断/限流/封禁记录；正常浏览器访问业务网站不受影响。

---

## 环境要求 / Requirements

- 任意 Linux 发行版（CentOS 7+ / Ubuntu 18.04+ / Debian 10+ / TencentOS / OpenCloudOS / AlmaLinux / Rocky / Fedora 等），x86_64 或 aarch64
- root 权限，可联网安装依赖（apt / yum / dnf）
- 内存 ≥ 512MB 即可运行防护层（建议 ≥1GB 用于完整功能）

## 许可证 / License

MIT © 2026 SSDS Contributors

## 免责声明 / Disclaimer

SSDS 能拦截绝大多数自动化与流量型攻击，极大提高服务器生存率。对于 Tbps 级超大带宽洪泛攻击，仍需运营商/云高防/CDN 侧配合；应用自身的业务逻辑漏洞（如越权、逻辑缺陷）需结合安全开发规范修复。
