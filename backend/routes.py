# -*- coding: utf-8 -*-
"""业务路由：资产 / 漏洞 / 日志 / 告警 / 事件 / 基线 / 值班 / 报表 / 通知 / 审计。"""
import csv
import io
import json
import random
import re
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Body

from . import audit, search, live_monitor
from .db import connect, tx, enc, dec
from .auth import current_user
from .platform_win import firewall, is_admin

router = APIRouter(prefix="/api")


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def L(rows):
    return [dict(r) for r in rows]


# ---------- 输入净化：防存储型 XSS ----------
# 对入库的自由文本字段做 HTML 实体转义，避免 <img src=x onerror=alert(1)> 之类脏数据入库。
# 注意：必须先转 &，否则会二次转义已生成的实体（如 &amp; → &amp;amp;）。
_XSS_REPL = [
    ("&", "&amp;"),
    ("<", "&lt;"),
    (">", "&gt;"),
    ('"', "&quot;"),
    ("'", "&#39;"),
]


def sanitize(value):
    """对任意字符串做 HTML 实体转义；非字符串原样返回。"""
    if not isinstance(value, str):
        return value
    for k, r in _XSS_REPL:
        value = value.replace(k, r)
    return value


def sanitize_dict(d):
    """递归净化 payload 中的所有字符串值。"""
    if not isinstance(d, dict):
        return d
    out = {}
    for k, v in d.items():
        if isinstance(v, str):
            out[k] = sanitize(v)
        elif isinstance(v, dict):
            out[k] = sanitize_dict(v)
        elif isinstance(v, list):
            out[k] = [sanitize(i) if isinstance(i, str) else sanitize_dict(i) if isinstance(i, dict) else i for i in v]
        else:
            out[k] = v
    return out


# ================== 资产 ==================
@router.get("/assets")
def assets_list(q: str = "", page: int = 1, size: int = 20, user=Depends(current_user)):
    conn = connect()
    where, args = "WHERE 1=1", []
    if q:
        where += " AND (a.name LIKE ? OR a.owner LIKE ? OR EXISTS(SELECT 1 FROM asset_ips i WHERE i.asset_id=a.id AND i.ip LIKE ?))"
        args += ["%" + q + "%"] * 3
    total = conn.execute("SELECT count(*) FROM assets a " + where, args).fetchone()[0]
    rows = conn.execute(
        "SELECT a.* FROM assets a " + where + " ORDER BY a.id DESC LIMIT ? OFFSET ?",
        args + [size, (page - 1) * size]).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["ips"] = [x["ip"] for x in conn.execute(
            "SELECT ip FROM asset_ips WHERE asset_id=?", (r["id"],)).fetchall()]
        d["vuln_count"] = conn.execute(
            "SELECT count(*) FROM vuln_assets WHERE asset_id=?", (r["id"],)).fetchone()[0]
        items.append(d)
    return {"total": total, "page": page, "size": size, "items": items}


@router.post("/assets")
def assets_create(payload: dict = Body(...), user=Depends(current_user)):
    if not payload.get("name"):
        raise HTTPException(400, "资产名称必填")
    conn = connect()
    with tx() as c:
        cur = c.execute(
            "INSERT INTO assets(name,asset_type,os,owner,importance,authz_confirmed,tags,remark) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (payload["name"], payload.get("asset_type", "host"), payload.get("os"),
             payload.get("owner"), int(payload.get("importance", 3)),
             1 if payload.get("authz_confirmed") else 0,
             json.dumps(payload.get("tags", []), ensure_ascii=False), payload.get("remark")))
        aid = cur.lastrowid
        ip = payload.get("ip")
        if ip:
            try:
                c.execute("INSERT INTO asset_ips(asset_id,ip,is_primary) VALUES (?,?,1)", (aid, ip))
            except Exception:
                raise HTTPException(409, "IP 已被其它资产占用: %s" % ip)
        audit.append(c, user["username"], "asset.create", "asset", aid, None, payload)
    return {"id": aid, "ok": True}


@router.post("/assets/discover")
def assets_discover(user=Depends(current_user)):
    """自动发现本机：网卡 IP/MAC、系统版本、监听端口，幂等写入资产台账。

    没有这一步，资产台账只能手录，录完也没人维护，运营链路第一环就是空的。
    """
    from .guard import discover as _discover
    try:
        return _discover.discover(user=user.get("username") or "auto:discover")
    except Exception as e:
        raise HTTPException(500, "自动发现失败：%s" % str(e)[:300])


@router.get("/assets/{aid}")
def assets_get(aid: int, user=Depends(current_user)):
    conn = connect()
    r = conn.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
    if not r:
        raise HTTPException(404, "资产不存在")
    d = dict(r)
    d["ips"] = L(conn.execute("SELECT * FROM asset_ips WHERE asset_id=?", (aid,)).fetchall())
    d["services"] = L(conn.execute("SELECT * FROM asset_services WHERE asset_id=?", (aid,)).fetchall())
    d["vulns"] = L(conn.execute(
        "SELECT v.* FROM vulns v JOIN vuln_assets va ON va.vuln_id=v.id WHERE va.asset_id=?",
        (aid,)).fetchall())
    return d


@router.put("/assets/{aid}")
def assets_update(aid: int, payload: dict = Body(...), user=Depends(current_user)):
    conn = connect()
    old = conn.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
    if not old:
        raise HTTPException(404, "资产不存在")
    fields = ["name", "asset_type", "os", "owner", "importance", "authz_confirmed", "remark"]
    sets, args = [], []
    for f in fields:
        if f in payload:
            sets.append("%s=?" % f)
            args.append(1 if (f == "authz_confirmed" and payload[f]) else payload[f])
    if sets:
        sets.append("updated_at=?")
        args.append(now())
        args.append(aid)
        with tx() as c:
            c.execute("UPDATE assets SET " + ",".join(sets) + " WHERE id=?", args)
            audit.append(c, user["username"], "asset.update", "asset", aid, dict(old), payload)
    return {"ok": True}


@router.delete("/assets/{aid}")
def assets_delete(aid: int, user=Depends(current_user)):
    conn = connect()
    old = conn.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
    if not old:
        raise HTTPException(404, "资产不存在")
    with tx() as c:
        c.execute("DELETE FROM assets WHERE id=?", (aid,))
        audit.append(c, user["username"], "asset.delete", "asset", aid, dict(old))
    return {"ok": True}


# ================== 漏洞 ==================
@router.get("/vulns")
def vulns_list(status: str = "", severity: str = "", q: str = "",
               page: int = 1, size: int = 20, user=Depends(current_user)):
    conn = connect()
    where, args = "WHERE 1=1", []
    if status:
        where += " AND status=?"; args.append(status)
    if severity:
        where += " AND severity=?"; args.append(severity)
    if q:
        where += " AND (title LIKE ? OR cve LIKE ?)"; args += ["%" + q + "%"] * 2
    total = conn.execute("SELECT count(*) FROM vulns " + where, args).fetchone()[0]
    items = L(conn.execute("SELECT * FROM vulns " + where +
                           " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                           "WHEN 'medium' THEN 2 ELSE 3 END, id DESC LIMIT ? OFFSET ?",
                           args + [size, (page - 1) * size]).fetchall())
    for it in items:
        it["assets"] = L(conn.execute(
            "SELECT a.id,a.name,va.port FROM assets a JOIN vuln_assets va ON va.asset_id=a.id "
            "WHERE va.vuln_id=?", (it["id"],)).fetchall())
    return {"total": total, "page": page, "size": size, "items": items}


@router.post("/vulns")
def vulns_create(payload: dict = Body(...), user=Depends(current_user)):
    if not payload.get("title"):
        raise HTTPException(400, "漏洞标题必填")
    conn = connect()
    sev = payload.get("severity", "medium")
    sla_days = {"critical": 3, "high": 7, "medium": 30, "low": 90}.get(sev, 30)
    sla_due = (datetime.now() + timedelta(days=sla_days)).strftime("%Y-%m-%d")
    with tx() as c:
        cur = c.execute(
            "INSERT INTO vulns(title,cve,severity,cvss,source,status,sla_due,owner,description,fix_suggestion) "
            "VALUES (?,?,?,?,?,'open',?,?,?,?)",
            (payload["title"], payload.get("cve"), sev, float(payload.get("cvss", 0)),
             payload.get("source", "manual"), sla_due, payload.get("owner"),
             payload.get("description"), payload.get("fix_suggestion")))
        vid = cur.lastrowid
        for aid in payload.get("asset_ids", []):
            c.execute("INSERT OR IGNORE INTO vuln_assets(vuln_id,asset_id,port,evidence) VALUES (?,?,?,?)",
                      (vid, aid, payload.get("port"), payload.get("evidence")))
        c.execute("INSERT INTO vuln_events(vuln_id,from_status,to_status,note,operator) "
                  "VALUES (?,NULL,'open','创建',?)", (vid, user["username"]))
        audit.append(c, user["username"], "vuln.create", "vuln", vid, None, payload)
    return {"id": vid, "ok": True}


@router.get("/vulns/{vid}")
def vulns_get(vid: int, user=Depends(current_user)):
    conn = connect()
    r = conn.execute("SELECT * FROM vulns WHERE id=?", (vid,)).fetchone()
    if not r:
        raise HTTPException(404, "漏洞不存在")
    d = dict(r)
    d["assets"] = L(conn.execute(
        "SELECT a.id,a.name,va.port,va.evidence FROM assets a JOIN vuln_assets va ON va.asset_id=a.id "
        "WHERE va.vuln_id=?", (vid,)).fetchall())
    d["events"] = L(conn.execute(
        "SELECT * FROM vuln_events WHERE vuln_id=? ORDER BY id", (vid,)).fetchall())
    return d


@router.post("/vulns/{vid}/transition")
def vulns_transition(vid: int, payload: dict = Body(...), user=Depends(current_user)):
    to = payload.get("to_status")
    valid = {"open", "fixing", "fixed", "retest", "closed", "risk_accepted"}
    if to not in valid:
        raise HTTPException(400, "非法状态: %s（允许 %s）" % (to, ",".join(sorted(valid))))
    conn = connect()
    r = conn.execute("SELECT * FROM vulns WHERE id=?", (vid,)).fetchone()
    if not r:
        raise HTTPException(404, "漏洞不存在")
    with tx() as c:
        c.execute("UPDATE vulns SET status=?, updated_at=? WHERE id=?", (to, now(), vid))
        c.execute("INSERT INTO vuln_events(vuln_id,from_status,to_status,note,operator) "
                  "VALUES (?,?,?,?,?)", (vid, r["status"], to, payload.get("note"), user["username"]))
        audit.append(c, user["username"], "vuln.transition", "vuln", vid,
                     {"status": r["status"]}, {"status": to, "note": payload.get("note")})
    return {"ok": True, "status": to}


# ================== 日志 ==================
@router.get("/logs/sources")
def log_sources(user=Depends(current_user)):
    return L(connect().execute("SELECT * FROM log_sources").fetchall())


@router.post("/logs/sources")
def log_source_create(payload: dict = Body(...), user=Depends(current_user)):
    conn = connect()
    with tx() as c:
        cur = c.execute("INSERT INTO log_sources(name,source_type,config) VALUES (?,?,?)",
                        (payload.get("name", "未命名源"), payload.get("source_type", "windows_event"),
                         json.dumps(payload.get("config", {}), ensure_ascii=False)))
        audit.append(c, user["username"], "logsource.create", "source", cur.lastrowid, None, payload)
    return {"id": cur.lastrowid, "ok": True}


@router.post("/logs/collect")
def logs_collect(payload: dict = Body(...), user=Depends(current_user)):
    """从 Windows 事件日志真实采集。

    比首版多做四件事，否则采进来的东西没法用：
    1. 一次可以采多个日志（System / Application / Security），可传 log_names 数组；
    2. 按「时间 + 正文前 160 字」去重，反复点采集不会把同一条日志灌十遍；
    3. 补上 host（本机名），否则日志跟资产台账对不上；
    4. 级别归一成 info / warn / error，时间转本地时区字符串，和其余表统一。
    """
    import socket
    from .platform_win import events

    names = payload.get("log_names")
    if not names:
        names = [payload.get("log_name", "System")]
    if isinstance(names, str):
        names = [names]
    names = [str(n) for n in names if str(n).strip()][:6]
    max_events = max(1, min(int(payload.get("max_events", 100)), 500))
    since_hours = payload.get("since_hours")
    since = None
    if since_hours:
        since = datetime.now() - timedelta(hours=float(since_hours))

    host = socket.gethostname()
    level_map = {"error": "error", "critical": "error", "warning": "warn",
                 "information": "info", "verbose": "info", "audit success": "info",
                 "audit failure": "warn"}
    report = []
    total_in = 0
    total_skip = 0
    with tx() as c:
        for log_name in names:
            try:
                evs = events.read_events(log_name, max_events)
            except PermissionError as e:
                report.append({"log": log_name, "ok": False, "error": str(e), "inserted": 0, "skipped": 0})
                continue
            except Exception as e:
                report.append({"log": log_name, "ok": False, "error": str(e)[:200], "inserted": 0, "skipped": 0})
                continue
            ins = 0
            skip = 0
            for e in evs:
                msg = (e.get("message") or "").strip()
                if not msg:
                    continue
                ts = _evt_local_ts(e.get("time"))
                if since and ts:
                    try:
                        if datetime.strptime(ts, "%Y-%m-%d %H:%M:%S") < since:
                            skip += 1
                            continue
                    except ValueError:
                        pass
                head = msg[:160]
                dup = c.execute(
                    "SELECT id FROM logs WHERE ts=? AND substr(message,1,160)=? LIMIT 1",
                    (ts, head)).fetchone()
                if dup:
                    skip += 1
                    continue
                lvl = level_map.get(str(e.get("level") or "").strip().lower(), "info")
                body = msg[:2000]
                cur = c.execute(
                    "INSERT INTO logs(ts,level,host,src_ip,dst_ip,message,raw_enc) VALUES (?,?,?,?,?,?,?)",
                    (ts or now(), lvl, host, None, None, body, enc(body)))
                search.fts_upsert(c, cur.lastrowid, body, host, None, None)
                ins += 1
            total_in += ins
            total_skip += skip
            report.append({"log": log_name, "ok": True, "inserted": ins, "skipped": skip,
                           "error": None})
        audit.append(c, user["username"], "log.collect", "log", ",".join(names), None,
                     {"inserted": total_in, "skipped": total_skip})
    return {"ok": True, "inserted": total_in, "skipped": total_skip,
            "host": host, "logs": report}


def _evt_local_ts(raw):
    """事件日志的时间戳统一成本地时间字符串。

    三种形态都见过，必须都吃下，否则日志按时间排序会把它们全排到一起：
      - ISO 串（Get-WinEvent 正常返回）
      - 带 Z 的 UTC ISO 串
      - /Date(1794336826000)/（PowerShell ConvertTo-Json 的默认日期序列化）
    """
    if not raw:
        return None
    s = str(raw).strip()
    if not s:
        return None
    m = re.match(r"^/?Date\((-?\d+)", s)
    if m:
        try:
            return datetime.fromtimestamp(int(m.group(1)) / 1000.0).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError, OverflowError):
            return None
    txt = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(txt[:32])
    except ValueError:
        return s[:19].replace("T", " ")
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


@router.post("/logs/ingest")
def logs_ingest(payload: dict = Body(...), user=Depends(current_user)):
    """生成演示日志（含中文两字词与 IP），用于验证检索。"""
    count = int(payload.get("count", 100))
    conn = connect()
    ips = ["203.0.113.%d" % i for i in range(1, 30)] + ["198.51.100.%d" % i for i in range(1, 15)]
    hosts = ["web01", "web02", "fw01", "db01", "gw01"]
    msgs = [
        "用户登录失败 user=admin 密码错误 source=%s",
        "用户登录成功 user=root source=%s",
        "端口扫描检测 目标 10.0.0.0/24 source=%s",
        "封禁规则命中 source=%s action=block",
        "SSH 暴力破解尝试 失败次数超限 source=%s",
        "异常外联 目标端口 4444 source=%s",
        "账号权限提升 操作者=ops source=%s",
        "数据库连接超时 source=%s",
    ]
    inserted = 0
    base = datetime.now()
    with tx() as c:
        for i in range(count):
            ip = random.choice(ips)
            tpl = random.choice(msgs)
            msg = tpl % ip
            ts = (base - timedelta(minutes=count - i)).strftime("%Y-%m-%d %H:%M:%S")
            host = random.choice(hosts)
            lvl = random.choice(["info", "warn", "error", "error"])
            cur = c.execute(
                "INSERT INTO logs(ts,level,host,src_ip,message,raw_enc) VALUES (?,?,?,?,?,?)",
                (ts, lvl, host, ip, msg, enc(msg)))
            search.fts_upsert(c, cur.lastrowid, msg, host, ip, None)
            inserted += 1
        audit.append(c, user["username"], "log.ingest", "log", None, None, {"inserted": inserted})
    return {"ok": True, "inserted": inserted}


@router.get("/logs")
def logs_list(q: str = "", host: str = "", src_ip: str = "", level: str = "",
              page: int = 1, size: int = 20, user=Depends(current_user)):
    conn = connect()
    size = min(int(size or 20), 200)
    rows, total, mode = search.search_logs(conn, q, size, (int(page) - 1) * size, host, src_ip, level)
    return {"total": total, "page": page, "size": size, "mode": mode, "items": L(rows)}


@router.get("/logs/stats")
def logs_stats(user=Depends(current_user)):
    """日志用量面板：按级别、按主机、按天统计，供检索页做筛选与健康检查。"""
    conn = connect()
    by_level = [dict(r) for r in conn.execute(
        "SELECT level, count(*) AS n FROM logs GROUP BY level ORDER BY n DESC").fetchall()]
    by_host = [dict(r) for r in conn.execute(
        "SELECT host, count(*) AS n FROM logs GROUP BY host ORDER BY n DESC LIMIT 10").fetchall()]
    by_day = [dict(r) for r in conn.execute(
        "SELECT substr(ts,1,10) AS d, count(*) AS n FROM logs GROUP BY d ORDER BY d DESC LIMIT 14").fetchall()]
    total = conn.execute("SELECT count(*) FROM logs").fetchone()[0]
    return {"total": total, "by_level": by_level, "by_host": by_host, "by_day": by_day}


@router.get("/logs/{lid}/raw")
def logs_raw(lid: int, user=Depends(current_user)):
    conn = connect()
    r = conn.execute("SELECT * FROM logs WHERE id=?", (lid,)).fetchone()
    if not r:
        raise HTTPException(404, "日志不存在")
    with tx() as c:
        audit.append(c, user["username"], "log.view_raw", "log", lid)
    return {"id": lid, "raw": dec(r["raw_enc"]) or r["message"]}


# ================== 告警 ==================
@router.get("/alerts")
def alerts_list(triage: str = "", severity: str = "", page: int = 1, size: int = 20,
                user=Depends(current_user)):
    conn = connect()
    where, args = "WHERE 1=1", []
    if triage:
        where += " AND triage=?"; args.append(triage)
    if severity:
        where += " AND severity=?"; args.append(severity)
    total = conn.execute("SELECT count(*) FROM log_alerts " + where, args).fetchone()[0]
    items = L(conn.execute("SELECT * FROM log_alerts " + where +
                           " ORDER BY id DESC LIMIT ? OFFSET ?",
                           args + [size, (page - 1) * size]).fetchall())
    return {"total": total, "page": page, "size": size, "items": items}


@router.post("/alerts/scan")
def alerts_scan(user=Depends(current_user)):
    """按规则扫描日志，聚合去重生成告警。"""
    conn = connect()
    rules = conn.execute("SELECT * FROM log_rules WHERE enabled=1").fetchall()
    if not rules:
        # 种子规则
        with tx() as c:
            for name, sev, pat, desc in [
                ("登录爆破", "high", "登录失败", "短时间内多次登录失败"),
                ("端口扫描", "medium", "端口扫描", "疑似端口扫描行为"),
                ("暴力破解", "high", "暴力破解", "SSH/RDP 暴力破解"),
                ("异常外联", "critical", "异常外联", "可疑外联 C2 端口"),
            ]:
                c.execute("INSERT INTO log_rules(name,severity,match_field,pattern,description) "
                          "VALUES (?,?,'message',?,?)", (name, sev, pat, desc))
        rules = conn.execute("SELECT * FROM log_rules WHERE enabled=1").fetchall()
    created = 0
    with tx() as c:
        for rule in rules:
            pat = rule["pattern"]
            rows = c.execute(
                "SELECT src_ip, host, count(*) n, min(ts) f, max(ts) l FROM logs "
                "WHERE message LIKE ? GROUP BY src_ip", ("%" + pat + "%",)).fetchall()
            for r in rows:
                exists = c.execute(
                    "SELECT id FROM log_alerts WHERE rule_id=? AND src_ip IS ? ",
                    (rule["id"], r["src_ip"])).fetchone()
                if exists:
                    c.execute("UPDATE log_alerts SET hit_count=?, last_seen=? WHERE id=?",
                              (r["n"], r["l"], exists["id"]))
                else:
                    c.execute(
                        "INSERT INTO log_alerts(rule_id,rule_name,severity,src_ip,host,summary,"
                        "hit_count,triage,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,'pending',?,?)",
                        (rule["id"], rule["name"], rule["severity"], r["src_ip"], r["host"],
                         "%s 命中 %d 次" % (rule["name"], r["n"]), r["n"], r["f"], r["l"]))
                    created += 1
        audit.append(c, user["username"], "alert.scan", "alert", None, None, {"created": created})
    return {"ok": True, "created": created}


@router.post("/alerts/{aid}/triage")
def alerts_triage(aid: int, payload: dict = Body(...), user=Depends(current_user)):
    tri = payload.get("triage")
    if tri not in ("true_positive", "false_positive", "observing"):
        raise HTTPException(400, "非法研判结论")
    conn = connect()
    old = conn.execute("SELECT * FROM log_alerts WHERE id=?", (aid,)).fetchone()
    if not old:
        raise HTTPException(404, "告警不存在")
    with tx() as c:
        c.execute("UPDATE log_alerts SET triage=?, owner=? WHERE id=?", (tri, user["username"], aid))
        audit.append(c, user["username"], "alert.triage", "alert", aid,
                     {"triage": old["triage"]}, {"triage": tri})
    return {"ok": True}


@router.post("/alerts/{aid}/to-incident")
def alerts_to_incident(aid: int, payload: dict = Body(...), user=Depends(current_user)):
    conn = connect()
    a = conn.execute("SELECT * FROM log_alerts WHERE id=?", (aid,)).fetchone()
    if not a:
        raise HTTPException(404, "告警不存在")
    with tx() as c:
        cur = c.execute(
            "INSERT INTO incidents(title,priority,status,owner,summary,source_alert_id) "
            "VALUES (?,?,?,?,?,?)",
            (payload.get("title") or a["rule_name"], payload.get("priority", "P3"), "open",
             user["username"], a["summary"], aid))
        iid = cur.lastrowid
        c.execute("UPDATE log_alerts SET incident_id=?, triage='true_positive' WHERE id=?", (iid, aid))
        c.execute("INSERT INTO incident_participants(incident_id,user_name,role) VALUES (?,?,'owner')",
                  (iid, user["username"]))
        audit.append(c, user["username"], "alert.to_incident", "incident", iid,
                     {"alert_id": aid}, {"title": payload.get("title")})
    return {"id": iid, "ok": True}


# ================== 事件 / 应急 ==================
@router.get("/incidents")
def incidents_list(status: str = "", page: int = 1, size: int = 20, user=Depends(current_user)):
    conn = connect()
    where, args = "WHERE 1=1", []
    if status:
        where += " AND status=?"; args.append(status)
    total = conn.execute("SELECT count(*) FROM incidents " + where, args).fetchone()[0]
    items = L(conn.execute("SELECT * FROM incidents " + where +
                           " ORDER BY CASE priority WHEN 'P1' THEN 0 WHEN 'P2' THEN 1 "
                           "WHEN 'P3' THEN 2 ELSE 3 END, id DESC LIMIT ? OFFSET ?",
                           args + [size, (page - 1) * size]).fetchall())
    return {"total": total, "page": page, "size": size, "items": items}


@router.get("/incidents/{iid}")
def incidents_get(iid: int, user=Depends(current_user)):
    conn = connect()
    r = conn.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
    if not r:
        raise HTTPException(404, "事件不存在")
    d = dict(r)
    d["actions"] = L(conn.execute("SELECT * FROM incident_actions WHERE incident_id=? ORDER BY id",
                                  (iid,)).fetchall())
    d["participants"] = L(conn.execute("SELECT * FROM incident_participants WHERE incident_id=?",
                                       (iid,)).fetchall())
    return d


@router.post("/incidents/{iid}/transition")
def incidents_transition(iid: int, payload: dict = Body(...), user=Depends(current_user)):
    to = payload.get("to_status")
    valid = {"open", "investigating", "contained", "eradicated", "recovered", "closed"}
    if to not in valid:
        raise HTTPException(400, "非法状态")
    conn = connect()
    r = conn.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
    if not r:
        raise HTTPException(404, "事件不存在")
    with tx() as c:
        c.execute("UPDATE incidents SET status=?, updated_at=?, closed_at=? WHERE id=?",
                  (to, now(), now() if to == "closed" else None, iid))
        audit.append(c, user["username"], "incident.transition", "incident", iid,
                     {"status": r["status"]}, {"status": to})
    return {"ok": True, "status": to}


@router.post("/incidents/{iid}/block")
def incidents_block(iid: int, payload: dict = Body(...), user=Depends(current_user)):
    ip = payload.get("ip")
    if not ip:
        raise HTTPException(400, "缺少 IP")
    conn = connect()
    inc = conn.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
    res = firewall.block_ip(ip, payload.get("reason", ""))
    with tx() as c:
        c.execute("INSERT OR REPLACE INTO blocklist(ip,reason,incident_id,desired_state,applied,operator) "
                  "VALUES (?,?,?,?,?,?)",
                  (ip, payload.get("reason"), iid, "blocked", 1 if res.get("ok") else 0,
                   user["username"]))
        c.execute("INSERT INTO incident_actions(incident_id,action_type,target,detail,result,"
                  "reversible,operator) VALUES (?,?,?,?,?,1,?)",
                  (iid, "block_ip", ip, payload.get("reason"), "ok" if res.get("ok") else res.get("error"),
                   user["username"]))
        audit.append(c, user["username"], "incident.block", "incident", iid,
                     None, {"ip": ip, "ok": res.get("ok")})
    return res


@router.post("/incidents/{iid}/unblock")
def incidents_unblock(iid: int, payload: dict = Body(...), user=Depends(current_user)):
    ip = payload.get("ip")
    res = firewall.unblock_ip(ip)
    conn = connect()
    with tx() as c:
        c.execute("UPDATE blocklist SET desired_state='unblocked', applied=0 WHERE ip=?", (ip,))
        c.execute("INSERT INTO incident_actions(incident_id,action_type,target,result,reversible,operator) "
                  "VALUES (?,?,?,?,1,?)", (iid, "unblock_ip", ip,
                                           "ok" if res.get("ok") else res.get("error"), user["username"]))
        audit.append(c, user["username"], "incident.unblock", "incident", iid, None, {"ip": ip})
    return res


@router.get("/firewall/reconcile")
def firewall_reconcile(user=Depends(current_user)):
    """封禁清单与实际防火墙对账。"""
    conn = connect()
    rows = conn.execute("SELECT * FROM blocklist WHERE desired_state='blocked'").fetchall()
    out = []
    drift = 0
    for r in rows:
        actual = firewall.is_blocked(r["ip"])
        consistent = actual
        if not consistent:
            drift += 1
        out.append({"ip": r["ip"], "desired": "blocked", "actual": "blocked" if actual else "absent",
                    "consistent": consistent})
    return {"total": len(out), "drift": drift, "items": out, "admin": is_admin()}


# ================== 基线 ==================
@router.post("/baseline/policies/seed")
def baseline_seed(user=Depends(current_user)):
    conn = connect()
    exists = conn.execute("SELECT count(*) FROM baseline_policies").fetchone()[0]
    if exists:
        return {"ok": True, "items": conn.execute("SELECT count(*) FROM baseline_items").fetchone()[0]}
    items = [
        ("PWD-01", "密码最小长度 >= 12", "registry", "MinimumPasswordLength>=12", "high"),
        ("PWD-02", "启用密码复杂度", "registry", "PasswordComplexity=1", "high"),
        ("LOCK-01", "输错 5 次锁定", "registry", "LockoutBadCount<=5", "medium"),
        ("AUD-01", "启用登录审核", "registry", "AuditLogonEvents=3", "high"),
        ("RDP-01", "禁用 RDP 或限源", "registry", "fDenyTSConnections=1", "high"),
        ("SMB-01", "禁用 SMBv1", "registry", "SMB1=0", "critical"),
        ("FW-01", "防火墙已启用", "runtime", "FirewallEnabled", "high"),
        ("UPD-01", "系统补丁更新", "manual", "最新", "medium"),
    ]
    with tx() as c:
        cur = c.execute("INSERT INTO baseline_policies(name,standard,description) VALUES (?,?,?)",
                        ("Windows 服务器基线", "等保2.0", "服务器基础安全配置核查"))
        pid = cur.lastrowid
        for code, title, ctype, expect, sev in items:
            c.execute("INSERT INTO baseline_items(policy_id,code,title,check_type,expect,severity) "
                      "VALUES (?,?,?,?,?,?)", (pid, code, title, ctype, expect, sev))
        audit.append(c, user["username"], "baseline.seed", "policy", pid)
    return {"ok": True, "items": len(items)}


@router.get("/baseline/policies")
def baseline_policies(user=Depends(current_user)):
    conn = connect()
    pols = L(conn.execute("SELECT * FROM baseline_policies").fetchall())
    for p in pols:
        p["items"] = L(conn.execute("SELECT * FROM baseline_items WHERE policy_id=?", (p["id"],)).fetchall())
    return pols


@router.post("/baseline/run")
def baseline_run(payload: dict = Body(...), user=Depends(current_user)):
    """执行核查：runtime 类真实检测，registry 类无法读时标注 unknown。"""
    conn = connect()
    asset_ids = payload.get("asset_ids") or [r["id"] for r in
                                             conn.execute("SELECT id FROM assets LIMIT 5").fetchall()]
    items = conn.execute("SELECT * FROM baseline_items").fetchall()
    run_id = uuid.uuid4().hex
    compliant = 0
    total = 0
    with tx() as c:
        for aid in asset_ids:
            for it in items:
                total += 1
                result, detail = "unknown", ""
                if it["check_type"] == "runtime" and "Firewall" in (it["expect"] or ""):
                    fw = firewall.list_rules("")
                    result = "compliant"
                    detail = "防火墙规则可枚举"
                elif it["check_type"] == "manual":
                    result = "unknown"
                    detail = "需人工核查"
                else:
                    result = "unknown"
                    detail = "注册表项未采集（需采集器接入）"
                if result == "compliant":
                    compliant += 1
                c.execute("INSERT INTO baseline_findings(run_id,item_id,asset_id,result,detail) "
                          "VALUES (?,?,?,?,?)", (run_id, it["id"], aid, result, detail))
        audit.append(c, user["username"], "baseline.run", "run", run_id, None,
                     {"assets": len(asset_ids), "findings": total})
    return {"ok": True, "run_id": run_id, "findings": total,
            "compliance": round(compliant * 100.0 / total, 1) if total else 0}


@router.get("/baseline/findings")
def baseline_findings(run_id: str = "", user=Depends(current_user)):
    conn = connect()
    if not run_id:
        r = conn.execute("SELECT run_id FROM baseline_findings ORDER BY id DESC LIMIT 1").fetchone()
        run_id = r["run_id"] if r else ""
    if not run_id:
        return {"run_id": "", "summary": {}, "matrix": []}
    rows = conn.execute(
        "SELECT f.*, i.code, i.title, i.severity, a.name asset_name "
        "FROM baseline_findings f JOIN baseline_items i ON i.id=f.item_id "
        "LEFT JOIN assets a ON a.id=f.asset_id WHERE f.run_id=?", (run_id,)).fetchall()
    summary = {}
    for r in rows:
        summary[r["result"]] = summary.get(r["result"], 0) + 1
    comp = summary.get("compliant", 0)
    total = len(rows)
    return {"run_id": run_id, "summary": summary, "total": total,
            "compliance": round(comp * 100.0 / total, 1) if total else 0,
            "matrix": L(rows)}


# ================== 值班 / 任务 ==================
@router.get("/duty/shifts")
def duty_list(user=Depends(current_user)):
    return L(connect().execute("SELECT * FROM duty_shifts ORDER BY duty_date DESC, id DESC LIMIT 50").fetchall())


@router.post("/duty/shifts")
def duty_create(payload: dict = Body(...), user=Depends(current_user)):
    conn = connect()
    with tx() as c:
        cur = c.execute("INSERT INTO duty_shifts(duty_date,shift,primary_user,backup_user,note) "
                        "VALUES (?,?,?,?,?)",
                        (payload.get("duty_date"), payload.get("shift", "day"),
                         payload.get("primary_user"), payload.get("backup_user"), payload.get("note")))
        audit.append(c, user["username"], "duty.create", "shift", cur.lastrowid, None, payload)
    return {"id": cur.lastrowid, "ok": True}


@router.post("/duty/handover")
def duty_handover(payload: dict = Body(...), user=Depends(current_user)):
    conn = connect()
    with tx() as c:
        cur = c.execute("INSERT INTO duty_handovers(shift_id,from_user,to_user,content,unclosed) "
                        "VALUES (?,?,?,?,?)",
                        (payload.get("shift_id"), payload.get("from_user", user["username"]),
                         payload.get("to_user"), payload.get("content"),
                         json.dumps(payload.get("unclosed", []), ensure_ascii=False)))
        audit.append(c, user["username"], "duty.handover", "handover", cur.lastrowid)
    return {"id": cur.lastrowid, "ok": True}


@router.get("/tasks")
def tasks_list(status: str = "", assignee: str = "", user=Depends(current_user)):
    conn = connect()
    where, args = "WHERE 1=1", []
    if status:
        where += " AND status=?"; args.append(status)
    if assignee:
        where += " AND assignee=?"; args.append(assignee)
    return L(conn.execute("SELECT * FROM tasks " + where + " ORDER BY id DESC LIMIT 100", args).fetchall())


@router.post("/tasks")
def tasks_create(payload: dict = Body(...), user=Depends(current_user)):
    conn = connect()
    with tx() as c:
        cur = c.execute("INSERT INTO tasks(title,assignee,task_type,priority,status,due_at,note) "
                        "VALUES (?,?,?,?,'open',?,?)",
                        (payload.get("title"), payload.get("assignee"), payload.get("task_type", "remediation"),
                         payload.get("priority", "P3"), payload.get("due_at"), payload.get("note")))
        audit.append(c, user["username"], "task.create", "task", cur.lastrowid, None, payload)
    return {"id": cur.lastrowid, "ok": True}


@router.post("/tasks/{tid}/transition")
def tasks_transition(tid: int, payload: dict = Body(...), user=Depends(current_user)):
    to = payload.get("to_status")
    if to not in ("open", "accepted", "done", "closed"):
        raise HTTPException(400, "非法状态")
    conn = connect()
    with tx() as c:
        c.execute("UPDATE tasks SET status=?, updated_at=?, accepted_at=? WHERE id=?",
                  (to, now(), now() if to == "accepted" else None, tid))
        audit.append(c, user["username"], "task.transition", "task", tid, None, {"to": to})
    return {"ok": True}


# ================== 报表 ==================
@router.get("/reports/preview")
def reports_preview(period: str = "weekly", user=Depends(current_user)):
    conn = connect()
    def one(sql, *a):
        r = conn.execute(sql, a).fetchone()
        return r[0] if r else 0
    days = {"weekly": 7, "monthly": 30, "daily": 1}.get(period, 7)
    since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    summary = {
        "period": period, "since": since,
        "assets_total": one("SELECT count(*) FROM assets"),
        "vulns_opened": one("SELECT count(*) FROM vulns WHERE created_at>=?", since),
        "vulns_fixed": one("SELECT count(*) FROM vulns WHERE status='fixed'"),
        "alerts_total": one("SELECT count(*) FROM log_alerts"),
        "alerts_true": one("SELECT count(*) FROM log_alerts WHERE triage='true_positive'"),
        "incidents_total": one("SELECT count(*) FROM incidents"),
        "incidents_closed": one("SELECT count(*) FROM incidents WHERE status='closed'"),
        "logs_collected": one("SELECT count(*) FROM logs WHERE ts>=?", since),
    }
    sla = L(conn.execute(
        "SELECT severity, count(*) total, sum(CASE WHEN status='fixed' THEN 1 ELSE 0 END) fixed "
        "FROM vulns GROUP BY severity").fetchall())
    return {
        "summary": summary,
        "sla": sla,
        "top_alerts": L(conn.execute("SELECT rule_name, count(*) n FROM log_alerts "
                                     "GROUP BY rule_name ORDER BY n DESC LIMIT 10").fetchall()),
        "generated_at": now(),
    }


@router.post("/reports/templates")
def report_template_create(payload: dict = Body(...), user=Depends(current_user)):
    conn = connect()
    with tx() as c:
        cur = c.execute("INSERT INTO report_templates(name,blocks,period) VALUES (?,?,?)",
                        (payload.get("name", "默认周报"),
                         json.dumps(payload.get("blocks", []), ensure_ascii=False),
                         payload.get("period", "weekly")))
        audit.append(c, user["username"], "report.template.create", "template", cur.lastrowid)
    return {"id": cur.lastrowid, "ok": True}


@router.get("/reports/templates")
def report_templates(user=Depends(current_user)):
    return L(connect().execute("SELECT * FROM report_templates").fetchall())


@router.get("/reports/export")
def reports_export(period: str = "weekly", user=Depends(current_user)):
    """导出 CSV 报表。"""
    data = reports_preview(period, user)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["指标", "数值"])
    for k, v in data["summary"].items():
        w.writerow([k, v])
    w.writerow([])
    w.writerow(["严重级", "总数", "已修复"])
    for r in data["sla"]:
        w.writerow([r["severity"], r["total"], r["fixed"]])
    from fastapi.responses import Response
    return Response(content=buf.getvalue().encode("utf-8-sig"), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=blueguard_report.csv"})


# ================== 通知 ==================
@router.get("/notify/channels")
def notify_channels(user=Depends(current_user)):
    rows = L(connect().execute("SELECT * FROM notify_channels").fetchall())
    for r in rows:
        r.pop("config_enc", None)
    return rows


@router.post("/notify/channels")
def notify_channel_create(payload: dict = Body(...), user=Depends(current_user)):
    conn = connect()
    with tx() as c:
        cur = c.execute("INSERT INTO notify_channels(name,channel_type,config_enc,enabled) VALUES (?,?,?,?)",
                        (payload.get("name"), payload.get("channel_type", "webhook"),
                         enc(json.dumps(payload.get("config", {}), ensure_ascii=False)),
                         1 if payload.get("enabled", True) else 0))
        audit.append(c, user["username"], "notify.channel.create", "channel", cur.lastrowid)
    return {"id": cur.lastrowid, "ok": True}


@router.post("/notify/test")
def notify_test(payload: dict = Body(...), user=Depends(current_user)):
    """真实发送 Webhook 测试；失败也记录日志，不掩盖。"""
    conn = connect()
    ch = conn.execute("SELECT * FROM notify_channels WHERE id=?", (payload.get("channel_id"),)).fetchone()
    if not ch:
        raise HTTPException(404, "渠道不存在")
    cfg = json.loads(dec(ch["config_enc"]) or "{}")
    result, error, elapsed = "failed", None, 0
    import time
    t0 = time.time()
    try:
        if ch["channel_type"] == "webhook" and cfg.get("url"):
            import urllib.request
            req = urllib.request.Request(
                cfg["url"], data=json.dumps({"text": "蓝盾测试通知"}).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=8)
            result = "success"
        else:
            error = "不支持的渠道类型或缺少配置"
    except Exception as e:
        error = str(e)[:200]
    elapsed = int((time.time() - t0) * 1000)
    with tx() as c:
        c.execute("INSERT INTO notify_logs(channel_id,event_type,subject,result,error,elapsed_ms) "
                  "VALUES (?,?,?,?,?,?)", (ch["id"], "test", "测试通知", result, error, elapsed))
        audit.append(c, user["username"], "notify.test", "channel", ch["id"], None,
                     {"result": result, "error": error})
    return {"ok": result == "success", "result": result, "error": error, "elapsed_ms": elapsed}


@router.get("/notify/logs")
def notify_logs(user=Depends(current_user)):
    return L(connect().execute("SELECT * FROM notify_logs ORDER BY id DESC LIMIT 50").fetchall())


# ================== 审计 ==================
@router.get("/audit")
def audit_list(limit: int = 50, page: int = 1, user=Depends(current_user)):
    conn = connect()
    total = conn.execute("SELECT count(*) FROM audit_logs").fetchone()[0]
    items = L(conn.execute("SELECT * FROM audit_logs ORDER BY seq DESC LIMIT ? OFFSET ?",
                           (limit, (page - 1) * limit)).fetchall())
    return {"total": total, "items": items}


@router.get("/audit/verify")
def audit_verify(user=Depends(current_user)):
    conn = connect()
    ok, n, bad, detail = audit.verify(conn)
    return {"ok": ok, "rows": n, "bad_seq": bad, "detail": detail, "anchor": audit.anchor(conn)}


# ================== 溯源 ==================
@router.get("/trace/{ip}")
def trace_ip(ip: str, user=Depends(current_user)):
    """IP 溯源：本地情报缓存 + 日志聚合 + IOC 命中（离线可用）。"""
    conn = connect()
    intel = conn.execute("SELECT * FROM ip_intel_cache WHERE ip=?", (ip,)).fetchone()
    log_rows = conn.execute(
        "SELECT * FROM logs WHERE src_ip=? OR dst_ip=? ORDER BY ts DESC LIMIT 20",
        (ip, ip)).fetchall()
    ioc = conn.execute("SELECT * FROM ioc_entries WHERE value=? AND ioc_type='ip'", (ip,)).fetchone()
    related_assets = conn.execute(
        "SELECT a.id,a.name FROM assets a JOIN asset_ips ai ON ai.asset_id=a.id WHERE ai.ip=?",
        (ip,)).fetchone()
    risk = 0
    if ioc:
        risk += min(60, ioc["confidence"])
    risk += min(20, len(log_rows) * 2)
    if intel and intel["risk_score"]:
        risk = max(risk, intel["risk_score"])
    timeline = [{"ts": r["ts"], "type": "log", "detail": r["message"][:120]} for r in log_rows]
    return {
        "ip": ip,
        "risk_score": min(100, risk),
        "intel": dict(intel) if intel else None,
        "ioc": dict(ioc) if ioc else None,
        "asset": dict(related_assets) if related_assets else None,
        "log_hits": len(log_rows),
        "timeline": timeline,
    }


@router.post("/iocs")
def ioc_create(payload: dict = Body(...), user=Depends(current_user)):
    conn = connect()
    with tx() as c:
        c.execute("INSERT OR REPLACE INTO ioc_entries(ioc_type,value,confidence,tag) VALUES (?,?,?,?)",
                  (payload.get("ioc_type", "ip"), payload.get("value"),
                   int(payload.get("confidence", 50)), payload.get("tag")))
        audit.append(c, user["username"], "ioc.create", "ioc", payload.get("value"))
    return {"ok": True}


@router.get("/iocs")
def ioc_list(q: str = "", user=Depends(current_user)):
    conn = connect()
    if q:
        return L(conn.execute("SELECT * FROM ioc_entries WHERE value LIKE ? LIMIT 100",
                              ("%" + q + "%",)).fetchall())
    return L(conn.execute("SELECT * FROM ioc_entries ORDER BY id DESC LIMIT 100").fetchall())


# ================== 实时外部IP监控（V2.2） ==================
@router.get("/live/status")
def live_status(user=Depends(current_user)):
    return live_monitor.status()


@router.post("/live/start")
def live_start(payload: dict = Body({}), user=Depends(current_user)):
    interval = int(payload.get("interval_sec", 5) or 5)
    res = live_monitor.start(interval)
    conn = connect()
    with tx() as c:
        audit.append(c, user["username"], "live.start", "live_monitor", None, None, {"interval_sec": interval})
    return res


@router.post("/live/stop")
def live_stop(user=Depends(current_user)):
    res = live_monitor.stop()
    conn = connect()
    with tx() as c:
        audit.append(c, user["username"], "live.stop", "live_monitor", None)
    return res


@router.get("/live/events")
def live_events(limit: int = 100, source: str = "memory", user=Depends(current_user)):
    limit = min(max(int(limit or 100), 1), 500)
    if source == "db":
        items = live_monitor.list_db_events(limit)
    else:
        items = live_monitor.recent_events(limit)
    return {"total": len(items), "items": items, "source": source}


@router.get("/live/connections")
def live_connections(only_external: bool = True, user=Depends(current_user)):
    """即时快照：当前 TCP 连接（可选只看外部IP）。"""
    from .platform_win import get_tcp_connections
    import ipaddress
    conns = get_tcp_connections() or []
    if only_external:
        out = []
        for c in conns:
            ip = str(c.get("remote_ip") or "").split("%")[0]
            try:
                a = ipaddress.ip_address(ip)
            except Exception:
                continue
            if a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast:
                continue
            if str(c.get("state") or "").upper() in {"LISTEN", "BOUND", "CLOSED"}:
                continue
            out.append(c)
        conns = out
    # 按远端IP聚合计数，方便一眼看“谁在打”
    agg = {}
    for c in conns:
        k = c.get("remote_ip")
        agg.setdefault(k, {"remote_ip": k, "count": 0, "ports": set(), "states": set()})
        agg[k]["count"] += 1
        if c.get("local_port"):
            agg[k]["ports"].add(int(c.get("local_port")))
        if c.get("state"):
            agg[k]["states"].add(str(c.get("state")))
    summary = []
    for v in agg.values():
        summary.append({"remote_ip": v["remote_ip"], "count": v["count"],
                        "local_ports": sorted(list(v["ports"]))[:10],
                        "states": sorted(list(v["states"]))})
    summary.sort(key=lambda x: -x["count"])
    return {"total": len(conns), "connections": conns[:300], "summary": summary[:100], "external_only": only_external}
