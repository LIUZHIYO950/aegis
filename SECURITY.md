# Security Policy

## 报告漏洞 / Reporting a Vulnerability

如果你发现 SSDS 的安全漏洞，请通过以下方式私下报告（不要公开讨论）：

1. 创建 GitHub Issue 时选择 "Security" 模板，或
2. 发送邮件至维护者邮箱（见仓库主页）。

请在报告包含：
- 影响版本
- 漏洞描述与复现步骤
- 建议修复方案（可选）

我们承诺 7 个工作日内响应，修复后发布补丁版本并致谢。

## 支持的版本 / Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |

## 安全使用建议 / Security Best Practices

- 使用 root 之外的最小权限部署；如可能，限制管理 SSH 来源 IP。
- 定期更新 WAF 规则集（替换 `rules/waf-rules.json` 后 `nginx -s reload` 热生效）。
- 监控 `/opt/aegis/logs/attack.log` 增长与告警推送。
- 超大带宽洪泛场景请叠加云高防 / CDN。
