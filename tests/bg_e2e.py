# -*- coding: utf-8 -*-
"""端到端：造一个到 TEST-NET 的真实 TCP 候选 + 临时规则 -> 引擎命中 -> 真下发防火墙 -> 对账 -> 回滚 -> 清理。"""
import json
import os
import socket
import sqlite3
import sys
import threading
import time
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:18080"
DATA = os.path.join(os.environ.get("TEMP", "."), "bg_e2e_data")
DB = os.path.join(DATA, "blueguard.db")
TEST_IP = "198.51.100.9"
TEST_PORT = 4444
RULE_ID = "E2E-CONN-TEST"
fails = []


def ok(name, cond, extra=""):
    print(("  PASS " if cond else "  FAIL ") + name + ("  " + str(extra) if extra else ""))
    if not cond:
        fails.append(name)
    return cond


def call(path, method="GET", body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            raw = r.read().decode() or "{}"
            return r.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def hold_conn(stop):
    socks = []
    while not stop.is_set():
        try:
            while len(socks) < 3:
                s = socket.socket()
                s.setblocking(False)
                s.connect_ex((TEST_IP, TEST_PORT))   # 不可达，停在 SYN_SENT
                socks.append(s)
            time.sleep(1)
        except Exception:
            time.sleep(1)
    for s in socks:
        try:
            s.close()
        except Exception:
            pass


print("[1] 临时规则入库")
conn = sqlite3.connect(DB, timeout=20)
conn.execute("DELETE FROM guard_rules WHERE rule_id=?", (RULE_ID,))
conn.execute(
    "INSERT INTO guard_rules(rule_id,name,category,severity,technique,condition,actions,enabled,builtin,note)"
    " VALUES(?,?,?,?,?,?,?,1,0,?)",
    (RULE_ID, "E2E 到 TEST-NET 的外连", "conn", "high", "T1041",
     json.dumps({"all": [{"field": "remote_ip", "op": "eq", "value": TEST_IP}]}),
     json.dumps({"block_ip": 1}), "自动化端到端自测，跑完即删"))
conn.commit()
conn.close()
ok("插入临时规则", True)

print("[2] 制造一个真实 TCP 候选（SYN_SENT，指向保留网段）")
stop = threading.Event()
t = threading.Thread(target=hold_conn, args=(stop,), daemon=True)
t.start()
time.sleep(2)

print("[3] 切 block 档")
s, b = call("/api/guard/policy")
mode0 = (b.get("policy") or b or {}).get("mode")
s, b = call("/api/guard/policy", "PUT", {"mode": "block"})
ok("mode=block", s == 200, b.get("mode") or b)

print("[4] 跑一轮")
s, b = call("/api/guard/run", "POST", {"deep": False})
ok("run ok", s == 200, "hits=%s" % (b.get("hits") if isinstance(b, dict) else b))

print("[5] 找到事件")
s, b = call("/api/guard/events?q=" + TEST_IP)
evs = b.get("items") or b.get("events") or []
ev = None
for x in evs:
    if x.get("remote_ip") == TEST_IP or (x.get("rule_name") or "").startswith("E2E"):
        ev = x
        break
ok("事件已生成", ev is not None, "总数 %s" % len(evs))
if not ev:
    stop.set()
    sys.exit(1)

print("[6] 系统防火墙真实下发")
s, b = call("/api/guard/firewall")
hosts = [r.get("DisplayName") for r in (b.get("host_rules") or [])]
ok("主机规则含 " + TEST_IP, any(TEST_IP in str(h or "") for h in hosts), hosts[:4])
s, b2 = call("/api/guard/events/" + str(ev["id"]))
resps = b2.get("responses") or []
applied = [r for r in resps if r.get("applied")]
ok("处置记录 applied", len(applied) >= 1, [(r["action"], r["result"]) for r in resps])

print("[7] 回滚")
rev_ok = True
for r in applied:
    if r.get("revert_action") and not r.get("reverted"):
        s, rb = call("/api/guard/responses/%s/revert" % r["id"], "POST")
        rev_ok = rev_ok and s == 200
ok("回滚接口", rev_ok)
time.sleep(1)
s, b = call("/api/guard/firewall")
hosts = [r.get("DisplayName") for r in (b.get("host_rules") or [])]
ok("主机规则已消失", not any(TEST_IP in str(h or "") for h in hosts), hosts[:4])

print("[8] 清理")
stop.set()
conn = sqlite3.connect(DB, timeout=20)
conn.execute("DELETE FROM guard_rules WHERE rule_id=?", (RULE_ID,))
conn.commit()
conn.close()
call("/api/guard/policy", "PUT", {"mode": mode0 or "monitor"})
s, b = call("/api/guard/rules")
left = [r for r in (b.get("items") or []) if r.get("rule_id") == RULE_ID]
ok("临时规则已删", len(left) == 0)
s, b = call("/api/guard/policy")
ok("模式已复原", (b.get("policy") or b).get("mode") == (mode0 or "monitor"), (b.get("policy") or b).get("mode"))

print("\n失败：%d" % len(fails))
if fails:
    print("FAILED: " + ", ".join(fails))
    sys.exit(1)
