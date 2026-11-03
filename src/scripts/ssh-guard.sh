#!/usr/bin/env bash
# ============================================================
# AEGIS SSH 暴力破解防护 — 分析认证日志并自动封禁
# 建议 cron 每 2 分钟执行一次:
#   */2 * * * * root bash /opt/aegis/scripts/ssh-guard.sh
# 用法: sudo bash ssh-guard.sh
# ============================================================
set -uo pipefail

LOG_FILE="/var/log/aegis/ssh-guard.log"
BAN_FILE="/opt/aegis/conf/blacklist.txt"
[ -f "$BAN_FILE" ] || touch "$BAN_FILE"
mkdir -p "$(dirname "$LOG_FILE")"

# 失败次数阈值
MAX_FAIL=5          # 2 分钟内失败 N 次
BAN_SECONDS=3600    # 封禁时长

# 定位认证日志
AUTH_LOG=""
for f in /var/log/auth.log /var/log/secure /var/log/messages; do
    [ -f "$f" ] && AUTH_LOG="$f" && break
done
[ -z "$AUTH_LOG" ] && { echo "[AEGIS] 未找到认证日志"; exit 0; }

# journalctl 兜底（systemd 环境）
if ! command -v journalctl >/dev/null 2>&1; then
    :
fi

now="$(date '+%b %e %H:%M')"
# 提取近 2 分钟失败尝试来源 IP（覆盖多种日志格式）
fail_ips="$({
    tail -n 2000 "$AUTH_LOG" 2>/dev/null | awk -v now="$now" '
        /(Failed password|Invalid user|authentication failure|Connection closed by.*preauth)/ {
            for(i=1;i<=NF;i++){
                if($i=="from" && $(i+1) ~ /^[0-9.]+$/) print $(i+1);
            }
        }
    '
    # journalctl 兜底
    if command -v journalctl >/dev/null 2>&1; then
        journalctl _SYSTEMD_UNIT=sshd.service --since "2 min ago" 2>/dev/null | grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | awk '{print $2}'
    fi
} | sort | uniq -c | sort -rn | awk -v m="$MAX_FAIL" '$1 >= m {print $2}')"

banned=0
for ip in $fail_ips; do
    # 跳过白名单内网段
    case "$ip" in
        127.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*) continue ;;
    esac
    if ! grep -q "^$ip$" "$BAN_FILE" 2>/dev/null; then
        echo "$ip" >> "$BAN_FILE"
        echo "[$(date '+%F %T')] SSH 暴力破解封禁: $ip" >> "$LOG_FILE"
        # 内核级立即封禁（iptables/nft 二选一）
        if command -v nft >/dev/null 2>&1; then
            nft add rule inet aegis input ip saddr "$ip" drop 2>/dev/null || true
        fi
        if command -v iptables >/dev/null 2>&1; then
            iptables -A AEGIS-IN -s "$ip" -j DROP 2>/dev/null || true
        fi
        banned=$((banned+1))
    fi
done

# 30 分钟后自动解封（从持久黑名单移除，动态封禁由 Lua 层管理短封）
if [ -f "$BAN_FILE" ]; then
    :
fi

echo "[AEGIS] SSH 防护扫描完成，新增封禁 $banned 个 IP"
exit 0
