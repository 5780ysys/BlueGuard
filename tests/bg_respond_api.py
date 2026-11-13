# -*- coding: utf-8 -*-
"""验证人工处置端点 /api/guard/events/{id}/respond。"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:18080"
fails = []


def ok(name, cond, extra=""):
    print(("  PASS " if cond else "  FAIL ") + name + ("  " + str(extra) if extra else ""))
    if not cond:
        fails.append(name)


def call(path, method="GET", body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


print("[1] 准备：block 档 + 放宽限速")
call("/api/guard/policy", "PUT", {"mode": "block", "max_actions_per_min": 40})
s, b = call("/api/guard/policy")
pol = b.get("policy") or b
ok("mode=block", pol.get("mode") == "block", pol.get("mode"))

print("[2] 找一个有远端 IP 的事件")
s, b = call("/api/guard/events?size=50")
items = b.get("items") or []
ev = next((x for x in items if x.get("remote_ip")), None)
ok("存在带 remote_ip 的事件", ev is not None, ev.get("remote_ip") if ev else "-")

print("[3] 人工下发阻断 IP")
if ev:
    s, r = call("/api/guard/events/%s/respond" % ev["id"], "POST", {"action": "block_ip"})
    ok("respond ok", s == 200 and r.get("ok") is True, r)
    rid = r.get("response_id")
    time.sleep(0.5)
    s, fw = call("/api/guard/firewall")
    names = [x.get("DisplayName") for x in (fw.get("host_rules") or [])]
    ok("防火墙已出现规则", any(ev["remote_ip"] in str(n or "") for n in names), names[:3])
    print("[4] 回滚")
    s, rb = call("/api/guard/responses/%s/revert" % rid, "POST")
    ok("revert ok", s == 200, rb)
    time.sleep(0.5)
    s, fw = call("/api/guard/firewall")
    names = [x.get("DisplayName") for x in (fw.get("host_rules") or [])]
    ok("规则已移除", not any(ev["remote_ip"] in str(n or "") for n in names), names[:3])

print("[5] 无远端 IP 的事件应 400")
posture = next((x for x in items if not x.get("remote_ip")), None)
if posture:
    s, r = call("/api/guard/events/%s/respond" % posture["id"], "POST", {"action": "block_ip"})
    ok("400 明确原因", s == 400 and "远端 IP" in str(r.get("detail") or r), r)

print("[6] 非法动作应 400")
s, r = call("/api/guard/events/%s/respond" % (posture or ev)["id"], "POST", {"action": "format_disk"})
ok("400 非法动作", s == 400, r)

print("[7] 收尾")
call("/api/guard/policy", "PUT", {"mode": "monitor", "max_actions_per_min": 12})
s, b = call("/api/guard/policy")
ok("模式复原 monitor", (b.get("policy") or b).get("mode") == "monitor")

print("\n失败：%d" % len(fails))
sys.exit(1 if fails else 0)
