# SSDS 开源发布完全教程（双版）

> 项目：**SSDS** — Super Server Defense System / 超级服务器防御系统（工程代号 `aegis`）
> 版本：v1.1.0　协议：MIT

本教程分两个版本，**默认阅读小白版**。

- 👉 [专业版入口（跳转）](#专业版-pro-版)

---

# 小白版（零基础，照做即可）

> 账号信息已替你填好：用户名 `liuzhiyo950` ｜ 昵称 刘之遥 ｜ 邮箱 `3986095470@qq.com` ｜ 仓库 `github.com/liuzhiyo950/aegis`

## 第 1 步：注册 GitHub 账号（已有账号跳过）

github.com → **Sign up** → 填邮箱 `3986095470@qq.com`、自己设密码、用户名 `liuzhiyo950` → 人机验证 → 去邮箱点验证邮件 **Verify email address**。

## 第 2 步：安装 Git

Windows 电脑：打开 `https://git-scm.com/downloads` → 下载 → 双击安装，一路 Next 默认。验证：按 Win 键搜 **Git Bash** 打开，输入 `git --version` 回车，出现版本号即成功。

> **发行版安装命令（单独隔开）**——Mac / Linux 在终端执行，选你系统对应的一条：
>
> ```bash
> sudo apt install -y git      # Debian / Ubuntu
> sudo yum install -y git      # CentOS / RHEL
> sudo dnf install -y git      # Fedora / Rocky / AlmaLinux
> ```

## 第 3 步：全部发布命令（整合在一块，按顺序整体复制执行）

打开 Git Bash（Windows）或终端（Mac/Linux），先进入解压出的 `aegis` 文件夹（Windows 可在文件夹地址栏输 `cmd` 回车直达），然后整体复制下面命令块，逐段回车：

```bash
# ---------- 身份配置（全局，仅首次/换机需要） ----------
git config --global user.name "刘之遥"
git config --global user.email "3986095470@qq.com"

# ---------- 初始化并提交 ----------
cd 你的aegis文件夹路径
git init
git add .
git commit -m "feat: SSDS v1.1.0"
git branch -M main

# ---------- 关联远程仓库 ----------
git remote add origin https://github.com/liuzhiyo950/aegis.git

# ---------- 推送代码 ----------
git push -u origin main

# ---------- 打标签并推送 Release 版本 ----------
git tag v1.1.0
git push origin v1.1.0
```

**第 3 步说明：**

- 网页建仓（第 4 步）要在推送前完成；仓库名填 `aegis`、Public、四个勾选框全不勾。
- 第一次 `git push` 会要求登录：自动弹窗登录 GitHub，或输 Username `liuzhiyo950` + Password 处粘 **Personal Access Token**（Settings → Developer settings → Personal access tokens → Tokens (classic) → Generate new token → 勾 `repo` → Generate → 复制 `ghp_...`，存好备用）。
- 推送失败/超时（国内网络）：先执行 `git remote set-url origin https://ghproxy.com/https://github.com/liuzhiyo950/aegis.git`，再重跑 `git push -u origin main` 和 `git push origin v1.1.0`。

## 第 4 步：网页创建 GitHub 仓库（在推送前完成）

github.com → 右上角 **+** → **New repository** → Repository name 填 `aegis` → Description 填 `SSDS - Super Server Defense System / 超级服务器防御系统` → 选 **Public** → 四个勾选框（README/.gitignore/LICENSE）**全不勾** → 绿色 **Create repository**。

## 第 5 步：发布 Release（让别人能下载）

标签已在第 3 步推送，这里只做网页操作：

仓库主页 → **Releases** → **Create a new release** → 选标签 `v1.1.0` → 标题 `SSDS v1.1.0` → 正文粘贴：

```
SSDS (Super Server Defense System / 超级服务器防御系统) v1.1.0
任意 Linux 服务器一键部署的全攻击面多层纵深防御系统。
```

→ 把 `aegis-1.1.0.tar.gz` 拖到附件区 → **Publish release**。

## 第 6 步：验证

打开仓库主页确认：README 正常渲染、License 显示 MIT、Releases 区有附件可下载。

## 报错对照表

| 报错 | 原因 | 解决 |
|------|------|------|
| `fatal: not a git repository` | 没执行 git init 或不在项目文件夹 | 确认位置在 `aegis` 文件夹，重跑 `git init` |
| `fatal: 'origin' does not appear...` | 没执行 remote add | 重跑 `git remote add origin https://github.com/liuzhiyo950/aegis.git` |
| `remote: Repository not found` | 仓库名/用户名不对 | 确认网页仓库叫 `aegis`，用户名 `liuzhiyo950` |
| `Permission denied (publickey)` | 走了 SSH | `git remote set-url origin https://github.com/liuzhiyo950/aegis.git` 切回 HTTPS |
| 推送超时 / `Failed to connect` | 网络不稳 | 用 ghproxy 镜像（见第 3 步说明） |

---

# 专业版（Pro 版）

> 面向有 git 经验开发者。全部命令整合在一块，发行版安装命令单独隔开，术语不再解释。

## 发行版安装命令（单独隔开）

```bash
sudo apt install -y git   # Debian / Ubuntu
sudo yum install -y git   # CentOS / RHEL
sudo dnf install -y git   # Fedora / Rocky / AlmaLinux
```

## 整合命令块（除发行版安装外全部命令）

```bash
# 身份（全局，首次/换机才需）
git config --global user.name "刘之遥"
git config --global user.email "3986095470@qq.com"

# 初始化 → 提交 → 推送
cd aegis
git init && git add . && git commit -m "feat: SSDS v1.1.0"
git branch -M main
git remote add origin https://github.com/liuzhiyo950/aegis.git
git push -u origin main

# Release 标签
git tag v1.1.0 && git push origin v1.1.0

# 国内加速（推送失败时执行后重推）
git remote set-url origin https://ghproxy.com/https://github.com/liuzhiyo950/aegis.git
```

## 后续维护（发新版本）

```bash
git add . && git commit -m "fix: ..."
git push
git tag v1.1.1 && git push origin v1.1.1
# 网页 Release 发布 v1.1.1
```

## Token 认证

HTTPS 推送提示输入密码时使用 PAT（`ghp_...`）而非登录密码；生成路径见小白版第 3 步说明。

---

MIT © 2026 SSDS Contributors
