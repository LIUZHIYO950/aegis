#!/usr/bin/env bash
# ============================================================
# AEGIS 内核网络参数调优 — 防 SYN Flood / 畸形包 / 半连接耗尽
# 用法: sudo bash kernel-tune.sh
# ============================================================
set -euo pipefail

SYSCTL_CONF="/etc/sysctl.d/99-aegis.conf"

cat > "$SYSCTL_CONF" <<'EOF'
# --- AEGIS 内核网络加固 ---
# SYN Flood 防护
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1

# 半连接/全连接队列
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

# 快速回收失效连接（防连接耗尽）
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_max_tw_buckets = 10000
net.ipv4.tcp_abort_on_overflow = 1

# ICMP 防护（Smurf / ping flood）
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# 伪造/异常包丢弃
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1

# 关闭无用的协议栈（减小攻击面）
net.ipv4.tcp_timestamps = 0
net.ipv4.ip_forward = 0

# 内存/连接限制
net.ipv4.tcp_mem = 786432 1048576 1572864
net.ipv4.tcp_rmem = 4096 87380 6291456
net.ipv4.tcp_wmem = 4096 16384 4194304
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
EOF

sysctl --system >/dev/null 2>&1 || sysctl -p "$SYSCTL_CONF" || true
echo "[AEGIS] 内核参数已应用: $SYSCTL_CONF"
sysctl net.ipv4.tcp_syncookies net.ipv4.tcp_max_syn_backlog 2>/dev/null
