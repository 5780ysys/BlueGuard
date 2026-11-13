# -*- coding: utf-8 -*-
"""自噬检测：本程序派生的 powershell 不该被自己的规则打中；普通开发机不该校出攻击链。"""
import json
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:18080"

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

PASS, FAIL = [], []


def ck(n, ok, extra=""):
    (PASS if ok else FAIL).append(n)
    print("%s %s%s" % ("PASS" if ok else "FAIL", n, ("  " + str(extra)) if extra else ""))


def get(p):
    return json.load(urllib.request.urlopen(BASE + p, timeout=120))


def post(p, b=None):
    req = urllib.request.Request(BASE + p, data=json.dumps(b or {}).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=300))


for i in (1, 2, 3):
    r = post("/api/guard/run", {"deep": i == 1})
    print("round%d hits=%s merged=%s chains=%s self_skipped=%s elapsed=%sms"
          % (i, r.get("hits"), r.get("merged"), r.get("chains"),
             r.get("self_skipped"), r.get("elapsed_ms")))
    time.sleep(1)

ev = get("/api/guard/events?size=100")
items = ev["items"]
names = [x["rule_name"] for x in items]

ck("没有把自己打中（无编码命令事件）", not any("编码命令" in n for n in names),
   [n for n in names if "编码命令" in n])
ch = get("/api/guard/events?category=chain")
ck("开发机不误报攻击链", (ch.get("total") or 0) == 0, ch.get("total"))
ck("仍有真实事件", len(items) > 0, len(items))
print("\n当前事件：")
for x in items:
    print("  [%s] %-26s %s" % (x["severity"], x["rule_name"][:26], (x["subject"] or "")[:60]))

print("\nPASS %d / FAIL %d" % (len(PASS), len(FAIL)))
sys.exit(1 if FAIL else 0)
