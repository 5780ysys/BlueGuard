# -*- coding: utf-8 -*-
"""打包版 V3.1 冒烟：规则数、攻击链模板、链路字段、首页文案、深扫。"""
import json
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18091"

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

PASS, FAIL = [], []


def ck(name, ok, extra=""):
    (PASS if ok else FAIL).append(name)
    print("%s %s%s" % ("PASS" if ok else "FAIL", name, ("  " + str(extra)) if extra else ""))


def get(path):
    return json.load(urllib.request.urlopen(BASE + path, timeout=60))


def post(path, body=None):
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(BASE + path, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=180))


h = get("/api/health")
ck("health V3.1", h.get("version") == "V3.1" and h.get("tagline") == "终端防护引擎", h.get("version"))

r = get("/api/guard/rules")
ck("规则总数 69", r["total"] == 69, r["total"])
ck("类别含 chain", "chain" in r.get("categories", []), r.get("categories"))

ch = get("/api/guard/rules?category=chain")
ck("链模板 5 条", ch["total"] == 5, ch["total"])
ck("链模板带 chain_req", all(x.get("chain_req") for x in ch["items"]),
   [x.get("chain_req") for x in ch["items"]])

en = get("/api/guard/rules?enabled=1")
ck("启用规则 67", en["total"] == 67, en["total"])

m = get("/api/guard/mitre")
ck("ATT&CK 技术 53", m.get("total") == 53, m.get("total"))

rs = post("/api/guard/run", {"deep": True})
ck("深扫完成", "hits" in rs and rs.get("rules") == 67, "hits=%s errors=%s" % (rs.get("hits"), rs.get("errors")))
ev = get("/api/guard/events?size=50")
ck("深扫产出事件", (ev.get("total") or 0) > 0, ev.get("total"))

# 攻击链在真实主机上通常不成立（要 3 个战术），所以这里只验接口可查不报错
cc = get("/api/guard/events?category=chain")
ck("链事件查询可用", "total" in cc, cc.get("total"))

page = urllib.request.urlopen(BASE + "/", timeout=30).read().decode("utf-8", "ignore")
ck("首页含攻击链类别", "chain:'攻击链'" in page)
ck("首页含链模板动作文案", "跨事件关联" in page)
ck("首页标题 V3.1", "终端防护引擎" in page and "V3.1" in page)

print("\nPASS %d / FAIL %d" % (len(PASS), len(FAIL)))
sys.exit(1 if FAIL else 0)

