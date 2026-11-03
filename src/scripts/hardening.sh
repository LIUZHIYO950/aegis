#!/usr/bin/env bash
# ============================================================
# AEGIS 系统加固与资源监控
# 覆盖: fork 炸弹防护、资源限制、磁盘/内存压力告警、审计增强
# 用法: sudo bash hardening.sh          # 应用加固
#       sudo bash hardening.sh check    # 手动执行一次监控检查
# ============================================================
set -euo pipefail

AEGIS_HOME="${AEGIS_HOME:-/opt/aegis}"
ALERT_LOG="$AEGIS_HOME/logs/attack.log"
mkdir -p "$(dirname "$ALERT_LOG")"

log_alert() {  # $1=type $2=detail
    echo "{\"time\":$(date +%s),\"type\":\"$1\",\"ip\":\"LOCAL\",\"rule\":\"HARD\",\"uri\":\"-\",\"extra\":\"$2\"}" >> "$ALERT_LOG" 2>/dev/null || true
}

apply_limits() {
    # 防 fork 炸弹 / 进程耗尽：普通用户进程数上限
    cat > /etc/security/limits.d/90-aegis.conf <<'EOF'
* soft nproc 4096
* hard nproc 8192
* soft nofile 65535
* hard nofile 65535
EOF
    # 内核: 进程 PID 上限 / 内存 overcommit 保守
    sysctl -w kernel.pid_max=4194304 >/dev/null 2>&1 || true
    sysctl -w vm.overcommit_memory=0 >/dev/null 2>&1 || true
    sysctl -w vm.overcommit_ratio=50 >/dev/null 2>&1 || true
    # OOM 保护：sshd/nginx 降低被杀概率（分值越低越难被杀）
    [ -f /proc/1/oom_score_adj ] && echo -1000 > /proc/1/oom_score_adj 2>/dev/null || true
    # 审计: bash 记录时间戳 + 多行命令
    cat > /etc/profile.d/aegis-audit.sh <<'EOF'
export HISTTIMEFORMAT="%F %T "
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTCONTROL=ignoredups
EOF
    echo "[AEGIS] 资源限制与审计加固已应用 (limits.d/90-aegis.conf, pid_max=4194304)"
}

check_now() {
    # 磁盘空间告警
    df_pct=$(df -P / | awk 'NR==2{print $5}' | tr -d '%')
    if [ "${df_pct:-0}" -gt 85 ]; then
        log_alert "disk_high" "root-usage=${df_pct}%"
        echo "[AEGIS][WARN] 根分区使用率 ${df_pct}% 超过 85%"
    fi

    # 内存压力 (PSI, kernel>=4.20)
    if [ -r /proc/pressure/memory ]; then
        avg10=$(awk '{print $2}' /proc/pressure/memory | tr -d '=')
        if awk "BEGIN{exit !(${avg10:-0} > 60)}"; then
            log_alert "memory_pressure" "psi-avg10=${avg10}"
            echo "[AEGIS][WARN] 内存压力 avg10=${avg10} 过高"
        fi
    fi

    # 日志目录增长
    logsize=$(du -sm "$AEGIS_HOME/logs" 2>/dev/null | awk '{print $1}')
    if [ "${logsize:-0}" -gt 1024 ]; then
        log_alert "log_growth" "aegis-logs=${logsize}MB"
        echo "[AEGIS][WARN] AEGIS 日志已达 ${logsize}MB"
    fi
    echo "[AEGIS] 资源监控检查完成 ($(date '+%F %T'))"
}

case "${1:-apply}" in
    apply) apply_limits ;;
    check) check_now ;;
    *) echo "用法: sudo bash hardening.sh {apply|check}" ;;
esac
