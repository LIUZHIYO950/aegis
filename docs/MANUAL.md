# SSDS 手动部署指南（deploy.sh 自动失败时的兜底方案）

## 1. 手动安装 OpenResty

### Debian / Ubuntu
```bash
wget -qO - https://openresty.org/package/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/openresty.gpg
echo "deb [signed-by=/usr/share/keyrings/openresty.gpg] http://openresty.org/package/debian $(. /etc/os-release && echo $VERSION_CODENAME) openresty" > /etc/apt/sources.list.d/openresty.list
apt-get update
apt-get install -y openresty
```

### CentOS / RHEL / AlmaLinux / Rocky / TencentOS
```bash
curl -fsSL https://openresty.org/package/openresty.repo -o /etc/yum.repos.d/openresty.repo
yum install -y openresty
```

### 兜底：发行版 Nginx + Lua 模块
```bash
# Debian/Ubuntu
apt-get install -y nginx libnginx-mod-http-lua lua-resty-core

# CentOS/RedHat 系
yum install -y nginx nginx-mod-http-lua   # 若仓库提供
# 或使用 openresty 官方静态编译包
```

## 2. 手动放置文件

```bash
SSDS_HOME=/opt/aegis
mkdir -p $SSDS_HOME/{lua,rules,conf,scripts,logs}
cp -r src/lua/.    $SSDS_HOME/lua/
cp -r src/rules/.  $SSDS_HOME/rules/
cp -r src/scripts/ $SSDS_HOME/scripts/
cp conf/aegis.conf $SSDS_HOME/conf/aegis.conf
chmod +x $SSDS_HOME/scripts/*.sh
openssl rand -hex 32 > $SSDS_HOME/conf/hmac.key
chmod 600 $SSDS_HOME/conf/hmac.key
```

## 3. 渲染 Nginx 配置

把 `src/nginx/nginx-aegis.conf.tmpl` 中的占位符替换为实际值后，放入
`/etc/nginx/conf.d/`（或 openresty 的 `/etc/openresty/conf.d/`）：

- `__SSDS_HOME__` → `/opt/aegis`
- `__SSDS_KEY__` → `cat $SSDS_HOME/conf/hmac.key`
- `__BACKEND_HOST__` / `__BACKEND_PORT__` → 你的后端地址

## 4. 启动

```bash
nginx -t && systemctl restart nginx    # 或 systemctl restart openresty
```

## 5. 部署守护进程与定时任务

```bash
pip3 install --no-cache-dir -r requirements.txt 2>/dev/null || true  # 无第三方依赖，可跳过
nohup python3 /opt/aegis/aegisd.py --home /opt/aegis >/dev/null 2>&1 &

# SSH 防护每 2 分钟
echo "*/2 * * * * root bash /opt/aegis/scripts/ssh-guard.sh" >> /etc/crontab
# 文件完整性每小时
echo "0 * * * * root bash /opt/aegis/scripts/fwmon.sh check" >> /etc/crontab
# 初始化文件基线
bash /opt/aegis/scripts/fwmon.sh init
```

## 6. 验证

```bash
curl -s http://127.0.0.1/aegis-health        # 期望 SSDS-OK
curl -s "http://127.0.0.1/search?q=union+select"  # 期望 403
sudo aegis status
```
