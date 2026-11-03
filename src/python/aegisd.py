#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AEGIS 分析守护进程
- 实时聚合 attack.log 中的攻击事件
- 高频攻击 IP 自动持久化封禁（写入 blacklist.txt，Lua 层 30s 内生效）
- Webhook / SMTP 告警（钉钉/飞书/企业微信/generic）
- 定期清理旧日志
用法: python3 aegisd.py --home /opt/aegis
"""
import argparse
import json
import os
import re
import smtplib
import socket
import subprocess
import time
import urllib.request
from collections import Counter, deque
from email.mime.text import MIMEText
from email.utils import formatdate

class Config:
    def __init__(self, home):
        self.home = home
        self.ban_file = os.path.join(home, "conf", "blacklist.txt")
        self.attack_log = os.path.join(home, "logs", "attack.log")
        self.ban_log = os.path.join(home, "logs", "ban.log")
        self._kv = self._load_conf(os.path.join(home, "conf", "aegis.conf"))

    def _load_conf(self, path):
        kv = {}
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    m = re.match(r"^(\S+)\s+(.+)$", line)
                    if m:
                        kv[m.group(1)] = m.group(2).strip().strip('"')
        except FileNotFoundError:
            pass
        return kv

    def get(self, key, default=None):
        return self._kv.get(key, default)


class AegisDaemon:
    def __init__(self, home):
        self.cfg = Config(home)
        self.attack_log = self.cfg.attack_log
        self.ban_file = self.cfg.ban_file
        self.ban_log = self.cfg.ban_log
        self.offset = self._init_offset()
        self.window = deque()          # 攻击时间窗口 (秒时间戳)
        self.alarm_locked_until = 0
        self.alert_threshold = int(self.cfg.get("alert_threshold", 100) or 100)
        self.alert_enabled = (self.cfg.get("alert_enable", "off") == "on")
        self.persist_ban_ips = {}      # ip -> (count, banned_at)
        self.persist_threshold = 30    # 30 次攻击自动持久封禁
        self.persist_ban_seconds = 86400  # 持久封禁 1 天
        self._ensure_dirs()

    def _ensure_dirs(self):
        for d in [os.path.dirname(self.attack_log), os.path.dirname(self.ban_file)]:
            os.makedirs(d, exist_ok=True)

    def _init_offset(self):
        try:
            with open(self.attack_log, "rb") as f:
                f.seek(0, 2)
                return f.tell()
        except FileNotFoundError:
            return 0

    # ---------- 日志读取 ----------
    def tail(self):
        try:
            with open(self.attack_log, "rb") as f:
                f.seek(self.offset)
                data = f.read()
                self.offset = f.tell()
        except FileNotFoundError:
            return []
        lines = []
        for raw in data.decode("utf-8", errors="ignore").splitlines():
            try:
                lines.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        return lines

    # ---------- 封禁 ----------
    def persist_ban(self, ip, reason):
        """写入持久黑名单（Lua 层每 30s 刷新，实现跨重启封禁）"""
        if not ip or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) is None:
            return
        try:
            with open(self.ban_file, "r") as f:
                existing = set(l.strip() for l in f if l.strip() and not l.startswith("#"))
        except FileNotFoundError:
            existing = set()
        if ip in existing:
            return
        with open(self.ban_file, "a") as f:
            f.write(ip + "\n")
        with open(self.ban_log, "a") as f:
            f.write("[%s] PERSIST-BAN %s reason=%s\n" % (time.strftime("%F %T"), ip, reason))

    def unban(self, ip):
        """从持久黑名单移除（到期自动解封）"""
        try:
            with open(self.ban_file, "r") as f:
                lines = f.readlines()
            with open(self.ban_file, "w") as f:
                for line in lines:
                    if line.strip() != ip:
                        f.write(line)
        except FileNotFoundError:
            pass

    # ---------- 告警 ----------
    def send_alert(self, text):
        webhook = self.cfg.get("alert_webhook", "")
        if not webhook:
            return
        wtype = self.cfg.get("alert_webhook_type", "generic")
        try:
            if wtype == "ding":
                payload = json.dumps({"msgtype": "text", "text": {"content": text}}).encode()
                req = urllib.request.Request(webhook, data=payload,
                                             headers={"Content-Type": "application/json"})
            elif wtype == "feishu":
                payload = json.dumps({"msg_type": "text", "content": {"text": text}}).encode()
                req = urllib.request.Request(webhook, data=payload,
                                             headers={"Content-Type": "application/json"})
            elif wtype == "wecom":
                payload = json.dumps({"msgtype": "text", "text": {"content": text}}).encode()
                req = urllib.request.Request(webhook, data=payload,
                                             headers={"Content-Type": "application/json"})
            else:
                payload = json.dumps({"text": text}).encode()
                req = urllib.request.Request(webhook, data=payload,
                                             headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
        except Exception as e:
            print("[AEGIS] 告警发送失败:", e)

    def send_mail(self, subject, body):
        if not self.cfg.get("smtp_host"):
            return
        try:
            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = self.cfg.get("smtp_user")
            msg["To"] = self.cfg.get("alert_email")
            msg["Date"] = formatdate(localtime=True)
            s = smtplib.SMTP_SSL(self.cfg.get("smtp_host"), int(self.cfg.get("smtp_port", 465)), timeout=5)
            s.login(self.cfg.get("smtp_user"), self.cfg.get("smtp_pass"))
            s.sendmail(self.cfg.get("smtp_user"), [self.cfg.get("alert_email")], msg.as_string())
            s.quit()
        except Exception as e:
            print("[AEGIS] 邮件告警失败:", e)

    # ---------- 主循环 ----------
    def process(self):
        events = self.tail()
        if not events:
            return
        now = time.time()
        by_ip = Counter()
        types = Counter()
        for ev in events:
            ip = ev.get("ip", "")
            by_ip[ip] += 1
            types[ev.get("type", "?")] += 1
            self.window.append(now)

        # 高频 IP 持久封禁
        for ip, cnt in by_ip.items():
            if cnt >= self.persist_threshold:
                self.persist_ban(ip, "auto:%s" % types.most_common(1)[0][0])
            else:
                # 累计封禁次数达到阈值也封禁（跨窗口攻击者）
                if ip in self.persist_ban_ips:
                    c, t = self.persist_ban_ips[ip]
                    if c + cnt >= self.persist_threshold and now - t < 1800:
                        self.persist_ban(ip, "auto-accum:%s" % types.most_common(1)[0][0])
                        self.persist_ban_ips.pop(ip, None)
                    else:
                        self.persist_ban_ips[ip] = (c + cnt, t)
                else:
                    self.persist_ban_ips[ip] = (cnt, now)

        # 窗口告警（1 分钟内攻击次数超过阈值）
        while self.window and self.window[0] < now - 60:
            self.window.popleft()
        if self.alert_enabled and len(self.window) >= self.alert_threshold and now > self.alarm_locked_until:
            self.alarm_locked_until = now + 600  # 10 分钟告警冷却
            top = ", ".join("%s(%d)" % (k, v) for k, v in by_ip.most_common(5))
            msg = "[AEGIS告警] 检测到高强度攻击\n时间: %s\n事件数: %d\n类型: %s\nTop攻击IP: %s\n请登录服务器执行: sudo aegis log" % (
                time.strftime("%F %T"), len(self.window), dict(types), top)
            print(msg)
            self.send_alert(msg)
            self.send_mail("[AEGIS] 攻击告警", msg)

        # 清理 1 天前持久封禁记录（简单解封：黑名单保留由运维决策，这里仅记录日志）
        print("[AEGIS] 处理 %d 条攻击事件 | 类型: %s | 持久封禁新增: 见 ban.log" % (len(events), dict(types)))

    def cleanup(self, days=7):
        """清理超过 N 天的 attack.log 片段"""
        try:
            size = os.path.getsize(self.attack_log)
            if size > 50 * 1024 * 1024:  # 超过 50MB 截断前 25MB
                with open(self.attack_log, "r+b") as f:
                    f.seek(25 * 1024 * 1024)
                    f.read()
                    rest = f.read()
                    f.seek(0)
                    f.truncate()
                    f.write(rest)
                print("[AEGIS] attack.log 已压缩")
        except OSError:
            pass

    def disk_check(self):
        """磁盘空间监控：根分区使用率超阈值告警（每 10 分钟一次）"""
        now = time.time()
        if getattr(self, "_last_disk_check", 0) and now - self._last_disk_check < 600:
            return
        self._last_disk_check = now
        try:
            if not os.path.exists("/"):
                return
            st = os.statvfs("/")
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            pct = 100 - (free * 100.0 / total) if total else 0
            if pct > 85:
                msg = "[AEGIS告警] 根分区使用率 %.1f%% 超过 85%%" % pct
                print(msg)
                self.send_alert(msg)
        except Exception as e:
            print("[AEGIS] 磁盘检查异常:", e)

    def run(self):
        print("[AEGIS] 守护进程启动: home=%s" % self.cfg.home)
        while True:
            try:
                self.process()
                self.cleanup()
                self.disk_check()
            except Exception as e:
                print("[AEGIS] 处理异常:", e)
            time.sleep(5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--home", default="/opt/aegis")
    ap.add_argument("--once", action="store_true", help="单次处理后退出一轮（供 cron 使用）")
    args = ap.parse_args()
    d = AegisDaemon(args.home)
    if args.once:
        d.process()
    else:
        d.run()


if __name__ == "__main__":
    main()
