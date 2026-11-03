# Contributing Guide / 贡献指南

感谢你愿意为 SSDS 贡献力量！所有贡献者应遵守本指南。

## 如何贡献 / How to Contribute

1. **报告问题**：使用 GitHub Issues，包含复现步骤、环境信息、日志片段。
2. **提交规则**：`rules/waf-rules.json` 是社区最欢迎的贡献点——
   新规则需注明攻击类别、样例载荷、误报评估。
3. **提交代码**：Fork → 分支 → PR（说明改动动机与测试结果）。

## 规则提交模板 / Rule Submission Template

```json
{"id": 1xxxx, "name": "Attack-Name", "severity": "high|medium|low",
 "patterns": ["(?i)regex-pattern"], "action": "deny|log"}
```

- id 在 10045+ 段内自增，避免与内置规则冲突
- patterns 必须是 JSON 合法转义（`\\s` 而非 `\s`）
- 新规则默认 `action=log` 观察一周无大量误报再升级为 `deny`

## 开发环境 / Dev Environment

```bash
# 语法机检
bash -n deploy.sh install/*.sh src/scripts/*.sh
python3 -m py_compile src/python/aegisd.py
python3 -c "import json; json.load(open('src/rules/waf-rules.json'))"

# 本地起一个测试后端验证
python3 -m http.server 8080
sudo bash deploy.sh 127.0.0.1 8080
curl -s http://127.0.0.1/aegis-health
curl -s "http://127.0.0.1/?q=union+select"   # 期望 403
```

## 代码规范 / Code Style

- Lua：2 空格缩进、显式 `local`、禁止全局污染
- Bash：`set -euo pipefail`、幂等可重复执行
- Python：兼容 3.6+、无第三方依赖（零依赖是特性）

## 行为准则 / Code of Conduct

友善、专业、就事论事。禁止人身攻击与歧视性言论。
