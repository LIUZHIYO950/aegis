# SSDS 架构说明

## 总体结构

```
                 ┌────────────────────────────────────────────┐
  客户端请求 ───▶ │ SSDS 防护层 (OpenResty + Lua)              │
                 │  白名单 → 黑名单 → 恶意UA → WAF → 限流        │
                 │  → 熔断 → JS挑战/签名 → body检测 → 放行        │
                 └───────────────┬────────────────────────────┘
                                 │ proxy_pass
                 ┌───────────────▼────────────────────────────┐
                 │ 业务后端 (任意框架/语言)                       │
                 └────────────────────────────────────────────┘

系统加固层                         分析守护层 (aegisd.py)
  kernel-tune.sh                    每 5 秒:
  firewall.sh                       1. tail attack.log
  ssh-guard.sh (cron 2min)          2. 高频 IP 持久封禁
  fwmon.sh (cron 1h)                3. Webhook/邮件告警
                                    4. 日志压缩
```

## 请求处理流水线 (src/lua/aegis/init.lua)

| 阶段 | 模块 | 作用 | 代价 |
|---|---|---|---|
| 0 | common | IP 解析（XFF 回源链） | 微秒 |
| 1 | blacklist | 白名单 / 静态黑名单 / 动态封禁字典 | 微秒 |
| 2 | bot | 恶意 UA 指纹（高置信拦截 / 可疑转挑战） | 微秒 |
| 3 | waf | 44 条规则扫描 URI+参数（正则预编译，最多 64 条/请求） | 亚毫秒 |
| 4 | ratelimit | 单 IP 5s 窗口计数，超限拉黑 | 微秒 |
| 5 | flow | 无签名流量多窗口计数，超限熔断 30s | 微秒 |
| 6 | challenge | HMAC 签名验证；无签名发 JS PoW 挑战页 | 微秒~毫秒 |
| 7 | waf.scan_body | POST/PUT 内容检测（≤64KB） | 亚毫秒 |

持证（通过挑战）用户跳过阶段 5/6 的挑战部分，但仍过 WAF/限流，防止持证攻击者滥用。

## 关键设计决策

1. **无状态签名 Cookie**：HMAC-SHA256(key, ip|expiry)，服务器零存储，验证 O(1)；
   密钥 32 字节随机，存放 `/opt/aegis/conf/hmac.key`（0600 权限）。
2. **双层封禁**：
   - 动态封禁：Lua `lua_shared_dict`，秒级生效，进程内存活；
   - 持久封禁：aegisd 聚合后写入 `blacklist.txt`，Lua 每 30s 重载，跨重启保留。
3. **熔断 vs 限流**：限流针对单 IP；熔断针对全局无签名流量（CC 特征），
   避免单点计数被攻击者分散绕过，也避免误伤持证用户。
4. **规则分级**：高置信规则 `action=deny` 直接拦截；低置信 `action=log`
   仅记录（如登录路径探测），由 aegisd 按频率决定是否封禁——**准确率优先**。
5. **性能**：全部逻辑跑在 `access` 阶段（无 body 缓冲开销），正则预编译缓存 30s，
   共享内存计数（`incr` 原子操作），单请求开销平均 < 0.5ms。

## 攻击日志格式 (logs/attack.log)

每行一条 JSON：
```json
{"time":1769966400,"type":"waf","ip":"1.2.3.4","rule":"10001","uri":"/search?q=...","ua":"...","extra":"name=SQLi-union-select sev=high"}
```

## 目录约定

```
/opt/aegis/
├── conf/        # aegis.conf 主配置 / hmac.key / blacklist.txt / file-baseline.txt
├── lua/         # Lua 防护模块
├── rules/       # WAF 规则 JSON
├── scripts/     # 内核/防火墙/SSH/文件完整性脚本
├── logs/        # attack.log / ban.log / fwmon.log / ssh-guard.log
└── aegisd.py    # 分析守护进程
```
