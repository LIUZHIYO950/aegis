#!/usr/bin/env bash
# ============================================================
# SSDS — 超级服务器防御系统 一键部署脚本
# 用法:
#   sudo bash deploy.sh [后端Host] [后端端口]
#   sudo bash deploy.sh                      # 自动识别本机 HTTP 后端
#   sudo bash deploy.sh 127.0.0.1 8080       # 显式指定
# ============================================================
set -euo pipefail

AEGIS_HOME="/opt/aegis"
AEGIS_VER="1.1.0"
LOG="/var/log/aegis-deploy.log"
mkdir -p "$(dirname "$LOG")" /opt

# ---------- 日志 ----------
info()  { echo "[AEGIS] $*"; echo "[$(date '+%F %T')] [INFO] $*" >> "$LOG"; }
warn()  { echo "[AEGIS][WARN] $*"; echo "[$(date '+%F %T')] [WARN] $*" >> "$LOG"; }
die()   { echo "[AEGIS][ERROR] $*" >&2; echo "[$(date '+%F %T')] [ERROR] $*" >> "$LOG"; exit 1; }

# ---------- 权限检查 ----------
[ "$(id -u)" -ne 0 ] && die "请以 root 运行: sudo bash deploy.sh ..."

# ---------- 加载发行版检测 ----------
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "$SRC_DIR/install/detect-distro.sh" || source /dev/stdin <<< "$(bash "$SRC_DIR/install/detect-distro.sh")"
eval "$(bash "$SRC_DIR/install/detect-distro.sh")"
[ "$PM" = "unknown" ] && die "无法识别发行版，请手动安装 OpenResty 后重试或参考 docs/MANUAL.md"

BACKEND_HOST="${1:-}"
BACKEND_PORT="${2:-}"

# ---------- 自动识别后端 ----------
if [ -z "$BACKEND_HOST" ]; then
    BACKEND_HOST="127.0.0.1"
    # 找本机正在监听的 http 端口（排除 80/443 与 ssh 等常用非 http 端口）
    CAND=$(ss -ltnp 2>/dev/null | awk -F'[: ]+' '/LISTEN/ && $0 !~ /:80 |:443 |:22 |:3306 |:6379 |:25 |:5432 / {print $4}' | head -1)
    [ -n "$CAND" ] && BACKEND_PORT="$CAND" || BACKEND_PORT=""
fi
if [ -z "$BACKEND_PORT" ]; then
    warn "未检测到后端端口，默认 8080。如后端不同请手动指定: sudo bash deploy.sh <host> <port>"
    BACKEND_PORT="8080"
fi
info "后端目标: $BACKEND_HOST:$BACKEND_PORT"

# ---------- 0. 安装依赖工具 ----------
info "更新软件源..."
$PKG_UPDATE >/dev/null 2>&1 || true
for pkg in curl tar gawk cronie crontabs wget; do
    command -v "$pkg" >/dev/null 2>&1 || $PKG_INSTALL "$pkg" >/dev/null 2>&1 || true
done
command -v python3 >/dev/null 2>&1 || $PKG_INSTALL python3 >/dev/null 2>&1 || true

# ---------- 1. 安装 OpenResty（官方仓库优先，发行版 nginx+lua 兜底） ----------
install_openresty() {
    command -v openresty >/dev/null 2>&1 && return 0
    command -v nginx >/dev/null 2>&1 && return 0
    info "安装 OpenResty..."
    local ok=0
    case "$PM" in
        yum|dnf)
            $PKG_INSTALL yum-utils >/dev/null 2>&1 || true
            if curl -fsSL https://openresty.org/package/openresty.repo -o /etc/yum.repos.d/openresty.repo 2>/dev/null; then
                $PKG_UPDATE >/dev/null 2>&1 || true
                $PKG_INSTALL openresty >/dev/null 2>&1 && ok=1
            fi
            ;;
        apt)
            if command -v lsb_release >/dev/null 2>&1 || true; then
                local code="$(. /etc/os-release && echo "$VERSION_CODENAME")"
                [ -z "$code" ] && code="$(lsb_release -cs)"
                apt-get install -y wget gnupg ca-certificates lsb-release >/dev/null 2>&1 || true
                if wget -qO - https://openresty.org/package/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/openresty.gpg 2>/dev/null; then
                    echo "deb [signed-by=/usr/share/keyrings/openresty.gpg] http://openresty.org/package/debian $code openresty" > /etc/apt/sources.list.d/openresty.list
                    apt-get update >/dev/null 2>&1 || true
                    apt-get install -y openresty >/dev/null 2>&1 && ok=1
                fi
            fi
            ;;
    esac
    if [ "$ok" -eq 1 ]; then
        return 0
    fi
    warn "OpenResty 官方仓库安装失败，尝试发行版 Nginx+Lua 模块..."
    case "$PM" in
        yum|dnf)
            $PKG_INSTALL nginx nginx-mod-stream lua-resty-core lua-resty-lrucache >/dev/null 2>&1 || \
            $PKG_INSTALL nginx nginx-mod-http-lua >/dev/null 2>&1 || \
            $PKG_INSTALL nginx >/dev/null 2>&1 || true
            ;;
        apt)
            $PKG_INSTALL nginx libnginx-mod-http-lua lua-resty-core lua-resty-lrucache >/dev/null 2>&1 || \
            $PKG_INSTALL nginx-extras >/dev/null 2>&1 || \
            $PKG_INSTALL nginx >/dev/null 2>&1 || true
            ;;
    esac
    command -v nginx >/dev/null 2>&1
}

if ! install_openresty; then
    die "Nginx/OpenResty 安装失败。请检查网络后重试，或参考 docs/MANUAL.md 手动安装。"
fi

# ---------- 2. 复制项目文件 ----------
info "安装文件到 $AEGIS_HOME ..."
mkdir -p "$AEGIS_HOME"/{lua,rules,conf,scripts,logs}
cp -rf "$SRC_DIR/src/lua/." "$AEGIS_HOME/lua/"
cp -rf "$SRC_DIR/src/rules/." "$AEGIS_HOME/rules/"
cp -rf "$SRC_DIR/src/scripts/." "$AEGIS_HOME/scripts/"
cp -f  "$SRC_DIR/conf/aegis.conf" "$AEGIS_HOME/conf/aegis.conf"
chmod +x "$AEGIS_HOME/scripts/"*.sh
mkdir -p "$AEGIS_HOME/logs" && chmod 777 "$AEGIS_HOME/logs"

# ---------- 3. 生成随机 HMAC 密钥 ----------
KEY_FILE="$AEGIS_HOME/conf/hmac.key"
if [ ! -s "$KEY_FILE" ]; then
    openssl rand -hex 32 > "$KEY_FILE" 2>/dev/null || head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$KEY_FILE"
    chmod 600 "$KEY_FILE"
fi
AEGIS_KEY="$(cat "$KEY_FILE")"
info "HMAC 密钥已生成: $AEGIS_HOME/conf/hmac.key"

# ---------- 4. 渲染 Nginx 配置 ----------
NGINX_ETC="/etc/openresty"
command -v nginx >/dev/null 2>&1 && command -v openresty >/dev/null 2>&1 || NGINX_ETC="/etc/openresty"
if [ -d /etc/nginx ] && [ ! -d /etc/openresty ]; then NGINX_ETC="/etc/nginx"; fi
mkdir -p "$NGINX_ETC/conf.d" "$NGINX_ETC/lua"

cp -rf "$SRC_DIR/src/lua/." "$NGINX_ETC/lua/"
cp -rf "$SRC_DIR/src/rules/." "$NGINX_ETC/conf.d/rules" 2>/dev/null || { mkdir -p "$NGINX_ETC/conf.d/rules"; cp -rf "$SRC_DIR/src/rules/." "$NGINX_ETC/conf.d/rules/"; }
cp -f  "$SRC_DIR/conf/aegis.conf" "$NGINX_ETC/conf.d/aegis.conf"

TMPL="$SRC_DIR/src/nginx/nginx-aegis.conf.tmpl"
OUT="/etc/nginx/conf.d/aegis-site.conf"
[ -d /etc/openresty ] && OUT="/etc/openresty/conf.d/aegis-site.conf"
[ -f /etc/nginx/nginx.conf ] && ! grep -q "include /etc/nginx/conf.d" /etc/nginx/nginx.conf 2>/dev/null && OUT="/etc/nginx/conf.d/aegis-site.conf"

sed -e "s|__AEGIS_HOME__|$AEGIS_HOME|g" \
    -e "s|__AEGIS_KEY__|$AEGIS_KEY|g" \
    -e "s|__BACKEND_HOST__|$BACKEND_HOST|g" \
    -e "s|__BACKEND_PORT__|$BACKEND_PORT|g" \
    -e "s|__AEGIS_VER__|$AEGIS_VER|g" \
    "$TMPL" > "$OUT"
info "Nginx 防护配置: $OUT"

# ---------- 5. 系统加固 ----------
info "应用内核网络参数与防火墙规则..."
bash "$AEGIS_HOME/scripts/kernel-tune.sh" || warn "内核参数应用跳过（可手动执行）"
bash "$AEGIS_HOME/scripts/firewall.sh"    || warn "防火墙规则应用跳过（可手动执行）"
bash "$AEGIS_HOME/scripts/hardening.sh"   || warn "系统资源加固跳过（可手动执行）"

# ---------- 6. 启动 Nginx/OpenResty ----------
NGINX_BIN="$(command -v openresty || command -v nginx)"
info "启动 $NGINX_BIN ..."
if command -v systemctl >/dev/null 2>&1; then
    if command -v openresty >/dev/null 2>&1; then
        systemctl enable openresty >/dev/null 2>&1 || true
        systemctl restart openresty || { nginx -t && $NGINX_BIN -s reload || true; }
    else
        systemctl enable nginx >/dev/null 2>&1 || true
        systemctl restart nginx || { nginx -t && $NGINX_BIN -s reload || true; }
    fi
else
    $NGINX_BIN -t || true
    $NGINX_BIN -s reload 2>/dev/null || $NGINX_BIN
fi

# ---------- 7. 部署分析守护进程 ----------
info "部署 aegisd 分析守护进程..."
cp -f "$SRC_DIR/src/python/aegisd.py" "$AEGIS_HOME/aegisd.py"
command -v python3 >/dev/null 2>&1 || $PKG_INSTALL python3 >/dev/null 2>&1 || true

if command -v systemctl >/dev/null 2>&1; then
    cat > /etc/systemd/system/aegisd.service <<EOF
[Unit]
Description=AEGIS Analysis & Defense Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $AEGIS_HOME/aegisd.py --home $AEGIS_HOME
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable aegisd >/dev/null 2>&1 || true
    systemctl restart aegisd || true
else
    nohup python3 "$AEGIS_HOME/aegisd.py" --home "$AEGIS_HOME" >/dev/null 2>&1 &
fi

# ---------- 8. CLI ----------
cat > /usr/local/bin/aegis <<'CLI'
#!/usr/bin/env bash
# AEGIS 管理命令
AEGIS_HOME="/opt/aegis"
case "${1:-}" in
    status)
        echo "== 防火墙规则 =="; iptables -L AEGIS-IN -n 2>/dev/null | head -20 || true
        echo "== 动态封禁 (最近) =="; tail -n 5 "$AEGIS_HOME/logs/ban.log" 2>/dev/null || echo "(无)"
        echo "== 攻击事件统计 =="; wc -l "$AEGIS_HOME/logs/attack.log" 2>/dev/null || echo "(无)"
        echo "== 守护进程 =="; pgrep -af aegisd || echo "aegisd 未运行"
        ;;
    ban)   shift; for ip in "$@"; do echo "$ip" >> "$AEGIS_HOME/conf/blacklist.txt"; done; echo "已加入持久黑名单（30 秒内生效）";;
    unban) shift; for ip in "$@"; do sed -i "/^$ip$/d" "$AEGIS_HOME/conf/blacklist.txt"; done; echo "已移除（30 秒内生效）";;
    log)   shift; tail -n "${1:-20}" "$AEGIS_HOME/logs/attack.log" 2>/dev/null || echo "(无攻击日志)";;
    key)   cat "$AEGIS_HOME/conf/hmac.key";;
    *)
        echo "用法: aegis {status|ban <ip...>|unban <ip...>|log [n]|key}"
        ;;
esac
CLI
chmod +x /usr/local/bin/aegis

# ---------- 完成 ----------
info "======================================================"
info "AEGIS v$AEGIS_VER 部署完成!"
info "  前端入口:  http://$(hostname -I 2>/dev/null | awk '{print $1}')  (80/443)"
info "  后端目标:  $BACKEND_HOST:$BACKEND_PORT"
info "  管理命令:  sudo aegis status / log / ban / unban"
info "  配置目录:  $AEGIS_HOME/conf/aegis.conf"
info "======================================================"
