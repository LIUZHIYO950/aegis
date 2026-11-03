#!/usr/bin/env bash
# ============================================================
# AEGIS 文件完整性监控 (轻量 AIDE)
# 基线: 首次运行生成 hash 基线；之后检测变更/新增/删除并告警
# 用法: sudo bash fwmon.sh init   (初始化基线)
#       sudo bash fwmon.sh check  (检查变更，建议 cron 每小时)
# ============================================================
set -uo pipefail

AEGIS_HOME="${AEGIS_HOME:-/opt/aegis}"
BASELINE="$AEGIS_HOME/conf/file-baseline.txt"
LOG="$AEGIS_HOME/logs/fwmon.log"
ALERT_LOG="$AEGIS_HOME/logs/attack.log"

# 监控的关键路径（默认系统关键区；可按业务自行增删）
WATCH_DIRS=(
    /etc/passwd
    /etc/shadow
    /etc/group
    /etc/ssh/sshd_config
    /etc/sudoers
    /etc/crontab
    /etc/nginx
    /etc/openresty
    /etc/iptables
    /etc/aegis
    /opt/aegis/lua
    /usr/local/bin
)
mkdir -p "$(dirname "$BASELINE")" "$(dirname "$LOG")"

hash_file() {
    [ -f "$1" ] && sha256sum "$1" 2>/dev/null
    [ -d "$1" ] && find "$1" -type f -newer /dev/null 2>/dev/null | sort | xargs sha256sum 2>/dev/null
}

do_init() {
    : > "$BASELINE"
    for p in "${WATCH_DIRS[@]}"; do
        hash_file "$p" >> "$BASELINE"
    done
    echo "[AEGIS] 文件完整性基线已建立: $BASELINE ($(wc -l < "$BASELINE") 条)"
}

do_check() {
    [ -f "$BASELINE" ] || { echo "请先执行: sudo bash fwmon.sh init"; exit 1; }
    CUR=$(mktemp)
    for p in "${WATCH_DIRS[@]}"; do
        hash_file "$p" >> "$CUR"
    done
    changed=$(diff <(sort "$BASELINE") <(sort "$CUR") | grep '^[<>]' || true)
    rm -f "$CUR"
    if [ -n "$changed" ]; then
        n=$(echo "$changed" | wc -l)
        echo "[$(date '+%F %T')] 检测到 $n 处文件变更:" >> "$LOG"
        echo "$changed" | head -20 >> "$LOG"
        # 写入攻击日志供告警
        echo "{\"time\":$(date +%s),\"type\":\"file_integrity\",\"ip\":\"LOCAL\",\"rule\":\"FW\",\"uri\":\"$n 处变更\",\"extra\":\"$(echo "$changed" | head -3 | tr '\n' ';')\"}" >> "$ALERT_LOG" 2>/dev/null || true
        echo "[AEGIS][WARN] 检测到文件变更，详情: $LOG"
    else
        echo "[AEGIS] 文件完整性 OK ($(date '+%F %T'))"
    fi
}

case "${1:-check}" in
    init)  do_init ;;
    check) do_check ;;
    *) echo "用法: sudo bash fwmon.sh {init|check}" ;;
esac
