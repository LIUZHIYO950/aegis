#!/usr/bin/env bash
# ============================================================
# AEGIS 定时任务安装：SSH 防护 + 文件完整性 + 日志压缩
# 用法: sudo bash install/cron.sh
# ============================================================
set -euo pipefail

AEGIS_HOME="${AEGIS_HOME:-/opt/aegis}"
CRON_SSH="*/2 * * * * root bash $AEGIS_HOME/scripts/ssh-guard.sh"
CRON_FW="0 * * * * root bash $AEGIS_HOME/scripts/fwmon.sh check"

install() {
    if [ -d /etc/cron.d ]; then
        cat > /etc/cron.d/aegis <<EOF
$CRON_SSH
$CRON_FW
$CRON_HARD
EOF
        chmod 644 /etc/cron.d/aegis
    else
        (crontab -l 2>/dev/null | grep -v aegis; echo "$CRON_SSH"; echo "$CRON_FW"; echo "$CRON_HARD") | crontab -
    fi
    # 初始化文件完整性基线（若未建）
    [ -f "$AEGIS_HOME/conf/file-baseline.txt" ] || bash "$AEGIS_HOME/scripts/fwmon.sh" init
    echo "[AEGIS] 定时任务已安装"
}

install
