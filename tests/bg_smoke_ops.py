# -*- coding: utf-8 -*-
"""运营侧冒烟：health / 资产自动发现 / 日志采集 / 日志统计 / 级别检索。

用法（先起服务）：
    python tests/bg_smoke_ops.py http://127.0.0.1:18092
"""
import json
import sys
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18092").rstrip("/")
FAIL = []


def call(path, method="GET", body=None, timeout=180):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8")
        return r.status, (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)


def check(name, cond, detail=""):
    print(("  PASS " if cond else "  FAIL ") + name + (("  " + str(detail)) if detail else ""))
    if not cond:
        FAIL.append(name)


print("BASE =", BASE)

st, health = call("/api/health")
check("health", st == 200 and health.get("ok") is True, "ver=%s auth=%s" % (health.get("version"), health.get("auth_mode")))
check("health.guard", isinstance(health.get("guard"), dict))
check("health.tagline", health.get("tagline") == "终端防护引擎", health.get("tagline"))

st, me = call("/api/auth/me")
check("/api/auth/me 免登录", st == 200 and (me.get("open_access") is True or me.get("user")), "")

st, d1 = call("/api/assets/discover", "POST", {})
check("资产自动发现", st == 200 and d1.get("ok") is True, "created=%s ip_new=%s ip_updated=%s svc_new=%s" % (d1.get("created"), d1.get("ip_new"), d1.get("ip_updated"), d1.get("service_new")))
check("发现到监听端口", (d1.get("service_new") or 0) >= 1, d1.get("service_new"))
st, d2 = call("/api/assets/discover", "POST", {})
check("二次发现幂等", st == 200 and d2.get("created") is False and (d2.get("ip_new") or 0) == 0, "created=%s ip_new=%s" % (d2.get("created"), d2.get("ip_new")))

st, assets = call("/api/assets")
items = assets.get("items") if isinstance(assets, dict) else assets
check("资产列表", st == 200 and isinstance(items, list) and len(items) >= 1, "n=%s" % (len(items) if isinstance(items, list) else "?"))
if isinstance(items, list) and items:
    aid = items[0].get("id")
    st, ad = call("/api/assets/%s" % aid)
    svc = ad.get("services") or []
    check("资产详情带端口", st == 200 and isinstance(svc, list) and len(svc) >= 1, "ports=%s" % len(svc))

st, lc = call("/api/logs/collect", "POST", {"log_names": ["System"], "max_events": 60, "since_hours": 48})
check("采集 System 日志", st == 200 and lc.get("ok") is True, "inserted=%s skipped=%s" % (lc.get("inserted"), lc.get("skipped")))
check("日志带 host", bool(lc.get("host")), lc.get("host"))
st, lc2 = call("/api/logs/collect", "POST", {"log_names": ["System"], "max_events": 60, "since_hours": 48})
check("二次采集去重", st == 200 and (lc2.get("inserted") or 0) == 0, "inserted=%s skipped=%s" % (lc2.get("inserted"), lc2.get("skipped")))

st, stats = call("/api/logs/stats")
check("日志统计", st == 200 and (stats.get("total") or 0) >= 1, "total=%s by_level=%s" % (stats.get("total"), stats.get("by_level")))

st, logs = call("/api/logs?size=5")
lit = logs.get("items") if isinstance(logs, dict) else logs
check("日志列表（size=5）", st == 200 and isinstance(lit, list) and len(lit) == 5, "n=%s" % (len(lit) if isinstance(lit, list) else "?"))
if isinstance(lit, list) and lit:
    ts = str(lit[0].get("ts") or "")
    check("时间戳可排序（非 /Date 原生）", ts[:2] == "20", ts[:24])

st, lv = call("/api/logs?level=error&size=5")
check("级别过滤可用", st == 200, "status=%s" % st)

st, gs = call("/api/guard/status")
a = gs.get("assessment") or {}
check("体检结论卡", isinstance(a, dict) and a.get("level") in ("ok", "attention", "risk"), "level=%s %s" % (a.get("level"), a.get("headline")))
st, dash = call("/api/dashboard")
check("总览带体检", isinstance(dash.get("assessment"), dict))

print("\n失败项：%d" % len(FAIL))
if FAIL:
    for f in FAIL:
        print("  -", f)
sys.exit(1 if FAIL else 0)
