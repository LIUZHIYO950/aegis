#!/usr/bin/env bash
# ============================================================
# AEGIS 防火墙规则 — iptables/nftables 自适应
# 覆盖: SYN/UDP/ICMP 洪水限速、畸形包丢弃、端口扫描抑制、SSH 保护
# 用法: sudo bash firewall.sh
# 注意: 默认放行 22/80/443；如需改 SSH 端口请先修改下方 SSH_PORT
# ============================================================
set -euo pipefail

SSH_PORT="${SSH_PORT:-22}"
WEB_PORTS="80,443"

mkdir -p /etc/aegis

# ---------- 选择后端: nftables 优先 ----------
if command -v nft >/dev/null 2>&1 && systemctl is-active nftables >/dev/null 2>&1; then
    USE_NFT=1
else
    USE_NFT=0
fi

if [ "$USE_NFT" -eq 1 ]; then
    echo "[AEGIS] 使用 nftables"
    cat > /etc/aegis/firewall.nft <<'NFTEOF'
# AEGIS nftables 规则 (由 firewall.sh 生成)
table inet aegis {
    chain input {
        type filter hook input priority 0; policy accept;

        # 已建立连接 + 回环放行
        ct state established,related accept
        iif "lo" accept

        # 放行 SSH / Web
        tcp dport { __SSH_PORT__, 80, 443 } accept

        # 畸形包丢弃 (XMAS / NULL / FIN-only / SYN+FIN / SYN+RST)
        tcp flags fin,psh,urg fin,psh,urg drop
        tcp flags & (fin|syn|rst|ack) != syn ct state new drop
        tcp flags & (syn|fin) == (syn|fin) drop
        tcp flags & (syn|rst) == (syn|rst) drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop

        # SYN Flood: 每秒新 SYN 限 300，超限 drop
        tcp flags syn limit rate 300/second burst 400 accept
        tcp flags syn drop

        # ICMP 限速 (防 ping flood / Smurf)
        icmp type echo-request limit rate 5/second accept
        icmp type echo-request drop
        icmpv6 type echo-request limit rate 5/second accept
        icmpv6 type echo-request drop

        # UDP 洪水: 新连接每 5 秒 20 包
        udp ct state new limit rate 20/second burst 40 accept
        udp ct state new drop

        # 端口扫描抑制: 30 秒内 15 次新连接即封禁 300 秒
        tcp flags syn ct state new meter scan_guard { ip saddr timeout 300s limit rate 15/second } drop
    }
}
NFTEOF
    # 替换 SSH 端口占位符
    sed -i "s/__SSH_PORT__/$SSH_PORT/g" /etc/aegis/firewall.nft

    nft -f /etc/aegis/firewall.nft

    cat > /etc/systemd/system/aegis-firewall.service <<EOF
[Unit]
Description=AEGIS Firewall Rules
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/aegis/firewall.nft
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable aegis-firewall >/dev/null 2>&1 || true
else
    echo "[AEGIS] 使用 iptables"
    command -v iptables >/dev/null 2>&1 || { echo "缺少 iptables"; exit 1; }

    # 建链（幂等）
    iptables -N AEGIS-IN 2>/dev/null || iptables -F AEGIS-IN

    # 接入 INPUT（幂等）
    iptables -C INPUT -j AEGIS-IN >/dev/null 2>&1 || iptables -A INPUT -j AEGIS-IN

    # 已建立连接 + 回环
    iptables -A AEGIS-IN -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A AEGIS-IN -i lo -j ACCEPT

    # 放行 SSH/Web
    iptables -A AEGIS-IN -p tcp --dport "$SSH_PORT" -j ACCEPT
    iptables -A AEGIS-IN -p tcp -m multiport --dports "$WEB_PORTS" -j ACCEPT

    # 畸形包丢弃
    iptables -A AEGIS-IN -p tcp --tcp-flags FIN,PSH,URG FIN,PSH,URG -j DROP
    iptables -A AEGIS-IN -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A AEGIS-IN -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    iptables -A AEGIS-IN -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    iptables -A AEGIS-IN -p tcp --tcp-flags ALL FIN -j DROP

    # SYN 限速（防 SYN Flood）
    iptables -A AEGIS-IN -p tcp --syn -m limit --limit 300/s --limit-burst 400 -j ACCEPT
    iptables -A AEGIS-IN -p tcp --syn -j DROP

    # ICMP 限速
    iptables -A AEGIS-IN -p icmp --icmp-type echo-request -m limit --limit 5/s -j ACCEPT
    iptables -A AEGIS-IN -p icmp --icmp-type echo-request -j DROP

    # UDP 限速
    iptables -A AEGIS-IN -p udp -m state --state NEW -m limit --limit 20/s --limit-burst 40 -j ACCEPT
    iptables -A AEGIS-IN -p udp -m state --state NEW -j DROP

    # 端口扫描抑制（recent）
    iptables -A AEGIS-IN -p tcp --syn -m recent --name AEGIS-SCAN --set
    iptables -A AEGIS-IN -p tcp --syn -m recent --name AEGIS-SCAN --update --seconds 30 --hitcount 15 -j DROP

    # 其余默认 ACCEPT（防护层在 Web 入口，不锁死其他业务端口）
    iptables -A AEGIS-IN -j ACCEPT

    # 持久化
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/aegis/firewall.rules
        cat > /etc/systemd/system/aegis-firewall.service <<EOF
[Unit]
Description=AEGIS Firewall Rules
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables-restore < /etc/aegis/firewall.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable aegis-firewall >/dev/null 2>&1 || true
    fi
fi

echo "[AEGIS] 防火墙规则已应用（放行: SSH $SSH_PORT / 80 / 443）"
echo "[AEGIS] 查看规则: sudo nft list ruleset  或  sudo iptables -L AEGIS-IN -n -v"
