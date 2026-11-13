# -*- coding: utf-8 -*-
"""API 端到端测试：登录 -> 各模块 CRUD -> 审计校验。"""
import sys, io, json, os, urllib.request, urllib.error, urllib.parse
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def _port():
    d = os.environ.get("BLUEGUARD_DATA") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    p = os.path.join(d, "port.txt")
    try:
        return open(p, encoding="utf-8").read().strip()
    except Exception:
        return "18083"


BASE = "http://127.0.0.1:" + _port()
TOKEN = None


def call(method, path, body=None, token=True, expect=200):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token and TOKEN:
        headers["Authorization"] = "Bearer " + TOKEN
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        r = urllib.request.urlopen(req, timeout=30)
        raw = r.read().decode()
        return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


def step(title):
    print("\n=== %s ===" % title)


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    return cond


fails = []

step("1) 登录")
st, res = call("POST", "/api/auth/login", {"username": "admin", "password": "BlueGuard@2026"}, token=False)
if not check(st == 200 and res and res.get("token"), "登录成功 status=%s" % st):
    print(res); sys.exit(1)
TOKEN = res["token"]
print("  must_change_password =", res["user"]["must_change_password"])

step("2) 健康 + 审计链")
st, h = call("GET", "/api/health")
check(h["ok"], "健康检查 ok")
check(h["audit"]["ok"], "审计链完整 rows=%d" % h["audit"]["rows"])
check(h["admin"], "当前有管理员权限")

step("3) 资产 CRUD")
st, a = call("POST", "/api/assets", {"name": "web-01", "asset_type": "host", "os": "Windows Server 2019",
                                      "owner": "ops", "importance": 5, "ip": "192.168.77.8"})
check(st == 200 and a.get("id"), "创建资产 id=%s" % (a.get("id") if isinstance(a, dict) else a))
aid = a["id"] if isinstance(a, dict) else None
st, lst = call("GET", "/api/assets")
check(st == 200 and lst["total"] >= 1, "资产列表 total=%s" % (lst.get("total") if isinstance(lst, dict) else lst))
st, d = call("GET", "/api/assets/%d" % aid)
check(st == 200, "资产详情 200")
st, u = call("PUT", "/api/assets/%d" % aid, {"owner": "sec-team"})
check(st == 200, "更新资产 200")
st, q = call("GET", "/api/assets?q=web")
check(st == 200 and q["total"] >= 1, "搜索资产 q=web -> %s" % q.get("total"))

step("4) 漏洞 + 状态流转 + SLA")
st, v = call("POST", "/api/vulns", {"title": "Apache Log4j RCE", "cve": "CVE-2021-44228",
                                     "severity": "critical", "cvss": 10.0, "asset_ids": [aid]})
check(st == 200 and v.get("id"), "创建漏洞 id=%s" % (v.get("id") if isinstance(v, dict) else v))
vid = v["id"] if isinstance(v, dict) else None
st, vr = call("POST", "/api/vulns/%d/transition" % vid, {"to_status": "fixing", "note": "已派单"})
check(st == 200, "状态流转 -> fixing")
st, vr2 = call("POST", "/api/vulns/%d/transition" % vid, {"to_status": "fixed", "note": "已修复"})
check(st == 200, "状态流转 -> fixed")
st, vd = call("GET", "/api/vulns/%d" % vid)
check(st == 200 and vd["events"] and len(vd["events"]) >= 2, "漏洞变更历史 %d 条" % len(vd.get("events", [])))

step("5) 日志采集 + 检索（中文两字词 + IP）")
st, src = call("POST", "/api/logs/sources", {"name": "本地演示源", "source_type": "demo"})
check(st == 200, "创建采集源")
st, ing = call("POST", "/api/logs/ingest", {"count": 200})
check(st == 200 and ing.get("inserted", 0) > 0, "注入日志 %s 条" % (ing.get("inserted") if isinstance(ing, dict) else ing))
for kw in ["登录", "失败", "登录失败", "203.0.113"]:
    st, s = call("GET", "/api/logs?q=" + urllib.parse.quote(kw))
    ok = st == 200 and isinstance(s, dict) and "items" in s
    check(ok, "检索 %-8s -> mode=%s total=%s" % (kw, s.get("mode") if isinstance(s, dict) else "?", s.get("total") if isinstance(s, dict) else "?"))

step("6) 告警 -> 事件")
st, al = call("POST", "/api/alerts/scan")
check(st == 200, "规则扫描生成告警 %s 条" % (al.get("created") if isinstance(al, dict) else al))
st, alerts = call("GET", "/api/alerts?triage=pending")
has_alert = st == 200 and alerts["total"] >= 1
check(has_alert, "待研判告警 %s 条" % (alerts.get("total") if isinstance(alerts, dict) else 0))
if has_alert:
    alert_id = alerts["items"][0]["id"]
    st, tri = call("POST", "/api/alerts/%d/triage" % alert_id, {"triage": "true_positive"})
    check(st == 200, "研判为真实告警")
    st, inc = call("POST", "/api/alerts/%d/to-incident" % alert_id, {"title": "可疑登录爆破", "priority": "P2"})
    check(st == 200 and inc.get("id"), "转为事件 id=%s" % (inc.get("id") if isinstance(inc, dict) else inc))

step("7) 防火墙封禁（真实调用）")
st, bl = call("POST", "/api/incidents/1/block", {"ip": "203.0.113.99", "reason": "测试封禁"})
if isinstance(bl, dict):
    check(bl.get("ok") or bl.get("error"), "封禁返回 ok=%s error=%s" % (bl.get("ok"), bl.get("error")))
    st, rc = call("GET", "/api/firewall/reconcile")
    check(st == 200, "防火墙对账 200")

step("8) 基线核查")
st, bp = call("POST", "/api/baseline/policies/seed")
check(st == 200, "初始化基线策略 项=%s" % (bp.get("items") if isinstance(bp, dict) else bp))
st, run = call("POST", "/api/baseline/run", {"asset_ids": [aid]})
check(st == 200 and run.get("run_id"), "执行核查 run_id=%s 合规率=%s" % (
    run.get("run_id", "")[:8] if isinstance(run, dict) else "", run.get("compliance") if isinstance(run, dict) else ""))

step("9) 值班 / 任务 / 报表 / 通知")
st, ds = call("POST", "/api/duty/shifts", {"duty_date": "2026-11-04", "shift": "day",
                                            "primary_user": "admin", "backup_user": "ops"})
check(st == 200, "创建值班班次")
st, tk = call("POST", "/api/tasks", {"title": "修复 Log4j", "assignee": "ops",
                                      "task_type": "remediation", "priority": "P1"})
check(st == 200 and tk.get("id"), "创建任务")
st, rp = call("GET", "/api/reports/preview?period=weekly")
check(st == 200 and "summary" in rp, "报表预览生成")
st, nc = call("POST", "/api/notify/channels", {"name": "测试WebHook", "channel_type": "webhook",
                                                "config": {"url": "http://127.0.0.1:9/hook"}})
check(st == 200, "创建通知渠道")
st, nt = call("POST", "/api/notify/test", {"channel_id": nc.get("id") if isinstance(nc, dict) else 1})
check(st == 200, "通知测试（预期失败但已记录）result=%s" % (nt.get("result") if isinstance(nt, dict) else "?"))

step("10) 审计链最终校验")
st, au = call("GET", "/api/audit/verify")
check(st == 200 and au["ok"], "审计链完整 rows=%d" % (au.get("rows") if isinstance(au, dict) else 0))
st, al2 = call("GET", "/api/audit?limit=10")
check(st == 200 and al2["total"] >= 10, "审计日志 %s 条" % (al2.get("total") if isinstance(al2, dict) else 0))
print("  最近动作:", [x["action"] for x in (al2.get("items", [])[:8] if isinstance(al2, dict) else [])])

print("\n" + "=" * 50)
print("测试完成")



