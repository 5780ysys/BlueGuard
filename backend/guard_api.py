# -*- coding: utf-8 -*-
"""防护中心 API：状态 / 事件 / 规则 / 策略 / 白名单 / 响应 / 对账 / 导出。

所有写操作都进审计哈希链（actor = 当前登录用户），
所有响应动作都走 respond.py 的护栏（管理员 + 限速 + 白名单 + 自保护）。
"""
import csv
import io
import json
from datetime import datetime

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import Response

from . import audit
from .auth import current_user
from .db import connect, tx
from .guard import advice, engine, mitre, policy, respond, rules
from .platform_win import firewall, is_admin

router = APIRouter(prefix="/api/guard", tags=["guard"])


def L(rows):
    return [dict(r) for r in rows]


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _int(v, d=0):
    try:
        return int(v)
    except Exception:
        return d


# ================== 总览 ==================
@router.get("/status")
def guard_status(user=Depends(current_user)):
    conn = connect()
    pol = policy.get_policy(refresh=True)
    st = engine.status()
    today = datetime.now().strftime("%Y-%m-%d")
    sev_rows = conn.execute(
        "SELECT severity, count(*) n FROM guard_events WHERE substr(ts,1,10)=? GROUP BY severity",
        (today,)).fetchall()
    by_sev = {r["severity"]: r["n"] for r in sev_rows}
    cat_rows = conn.execute(
        "SELECT category, count(*) n FROM guard_events WHERE substr(ts,1,10)=? GROUP BY category",
        (today,)).fetchall()
    top = conn.execute(
        "SELECT rule_name, severity, count(*) n, max(ts) last_ts FROM guard_events "
        "WHERE substr(ts,1,10)=? GROUP BY rule_name ORDER BY n DESC LIMIT 6", (today,)).fetchall()
    resp = conn.execute(
        "SELECT action, applied, count(*) n FROM guard_responses WHERE substr(ts,1,10)=? "
        "GROUP BY action, applied", (today,)).fetchall()
    return {
        "engine": st,
        "policy": pol,
        "admin": is_admin(),
        "today": {
            "events": sum(by_sev.values()),
            "by_severity": by_sev,
            "by_category": {r["category"] or "?": r["n"] for r in cat_rows},
            "open_incidents": conn.execute(
                "SELECT count(*) n FROM incidents WHERE status!='closed' AND title LIKE '[防护]%'").fetchone()["n"],
            "blocked_ips": conn.execute(
                "SELECT count(*) n FROM blocklist WHERE desired_state='blocked'").fetchone()["n"],
            "pending_alerts": conn.execute(
                "SELECT count(*) n FROM log_alerts WHERE triage='pending' AND rule_name LIKE '[防护]%'").fetchone()["n"],
        },
        "top_rules": L(top),
        "responses_today": L(resp),
        "rates": respond.rate_state(),
        "assessment": advice.assess(conn),
    }


@router.post("/start")
def guard_start(user=Depends(current_user)):
    r = engine.start()
    with tx() as c:
        audit.append(c, user["username"], "guard.start", "guard", "engine")
    return r


@router.post("/stop")
def guard_stop(user=Depends(current_user)):
    r = engine.stop()
    with tx() as c:
        audit.append(c, user["username"], "guard.stop", "guard", "engine")
    return r


@router.post("/run")
def guard_run(payload: dict = Body(default={}), user=Depends(current_user)):
    """手动跑一轮（deep=true 会强制刷新启动项/主机姿态等慢速项）。"""
    deep = bool(payload.get("deep"))
    st = engine.run_once(deep=deep, trigger="manual:%s" % user["username"])
    with tx() as c:
        audit.append(c, user["username"], "guard.run", "guard", "engine", None,
                     {"hits": st.get("hits"), "elapsed_ms": st.get("elapsed_ms"), "deep": deep})
    return st


# ================== 事件 ==================
@router.get("/events")
def guard_events(sev: str = "", status: str = "", category: str = "", q: str = "",
                 page: int = 1, size: int = Query(default=20, le=200),
                 user=Depends(current_user)):
    conn = connect()
    where, args = [], []
    if sev:
        where.append("severity=?"); args.append(sev)
    if status:
        where.append("status=?"); args.append(status)
    if category:
        where.append("category=?"); args.append(category)
    if q:
        where.append("(rule_name LIKE ? OR subject LIKE ? OR detail LIKE ? OR remote_ip LIKE ?)")
        args += ["%%%s%%" % q] * 4
    w = (" WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute("SELECT count(*) c FROM guard_events" + w, args).fetchone()["c"]
    rows = conn.execute("SELECT * FROM guard_events" + w + " ORDER BY id DESC LIMIT ? OFFSET ?",
                        args + [size, (max(1, page) - 1) * size]).fetchall()
    out = L(rows)
    for d in out:
        d["mitre_label"] = mitre.label(d.get("mitre"))
        try:
            d["evidence"] = json.loads(d.get("evidence") or "{}")
        except Exception:
            d["evidence"] = {}
        d["responses"] = conn.execute(
            "SELECT id,action,target,applied,result,reverted,expire_at FROM guard_responses "
            "WHERE event_id=? ORDER BY id", (d["id"],)).fetchall()
        d["responses"] = L(d["responses"])
    return {"total": total, "page": page, "size": size, "items": out}


@router.get("/events/{eid}")
def guard_event_detail(eid: int, user=Depends(current_user)):
    conn = connect()
    row = conn.execute("SELECT * FROM guard_events WHERE id=?", (eid,)).fetchone()
    if not row:
        raise HTTPException(404, "事件不存在")
    d = dict(row)
    d["mitre_label"] = mitre.label(d.get("mitre"))
    d["mitre_tactic"] = mitre.tactic(d.get("mitre"))
    try:
        d["evidence"] = json.loads(d.get("evidence") or "{}")
    except Exception:
        d["evidence"] = {}
    d["responses"] = L(conn.execute(
        "SELECT * FROM guard_responses WHERE event_id=? ORDER BY id", (eid,)).fetchall())
    rule = conn.execute("SELECT * FROM guard_rules WHERE id=?", (d.get("rule_id"),)).fetchone()
    d["rule"] = dict(rule) if rule else None
    if d.get("alert_id"):
        d["alert"] = dict(conn.execute("SELECT id,rule_name,severity,triage,hit_count FROM log_alerts WHERE id=?",
                                       (d["alert_id"],)).fetchone() or {})
    if d.get("incident_id"):
        d["incident"] = dict(conn.execute("SELECT id,title,priority,status FROM incidents WHERE id=?",
                                          (d["incident_id"],)).fetchone() or {})
    return d


@router.post("/events/{eid}/respond")
def guard_event_respond(eid: int, payload: dict = Body(...), user=Depends(current_user)):
    """人工处置：把某条事件变成真实动作（受全部护栏约束，可回滚）。"""
    action = (payload.get("action") or "").strip()
    if action not in ("block_ip", "block_program", "block_port", "kill_process"):
        raise HTTPException(400, "非法动作，可选 block_ip / block_program / block_port / kill_process")
    conn = connect()
    row = conn.execute("SELECT * FROM guard_events WHERE id=?", (eid,)).fetchone()
    if not row:
        raise HTTPException(404, "事件不存在")
    ev = dict(row)
    target = None
    if action == "block_ip":
        target = ev.get("remote_ip")
        if not target:
            raise HTTPException(400, "该事件没有远端 IP，改不了防火墙入站规则")
    elif action == "block_program":
        target = ev.get("process_path")
        if not target:
            raise HTTPException(400, "该事件没有进程完整路径（系统进程常见），无法阻断出站")
    elif action == "block_port":
        target = ev.get("local_port")
        if not target:
            raise HTTPException(400, "该事件没有本地端口")
    elif action == "kill_process":
        target = ev.get("pid")
        if not target:
            raise HTTPException(400, "该事件没有进程号")
    # 记录"谁点的"，事件本身仍归属引擎
    ev["rule_name"] = ev.get("rule_name") or "人工处置"
    r = respond.execute(eid, action, target, ev)
    return {"ok": bool(r.get("ok")), "error": r.get("error"), "target": target,
            "response_id": r.get("response_id"), "detail": r.get("detail")}


@router.delete("/events/{eid}")
def guard_event_delete(eid: int, user=Depends(current_user)):
    """删一条事件。

    刻意只删事件本身：guard_responses 里的处置留痕（包括还挂着的防火墙规则）
    必须留着，否则"谁在什么时候封了哪个 IP"就无从追溯，回滚也无从下手。
    """
    conn = connect()
    row = conn.execute("SELECT rule_name,severity,subject,status FROM guard_events WHERE id=?",
                       (eid,)).fetchone()
    if not row:
        raise HTTPException(404, "事件不存在")
    live = conn.execute("SELECT COUNT(*) c FROM guard_responses WHERE event_id=? AND applied=1 "
                        "AND reverted=0 AND action<>'kill_process'", (eid,)).fetchone()["c"]
    with tx() as c:
        c.execute("DELETE FROM guard_events WHERE id=?", (eid,))
        audit.append(c, user["username"], "guard.event.delete", "guard_event", eid,
                     dict(row), {"deleted": True, "responses_kept": live})
    return {"ok": True, "deleted": 1, "live_responses": live}


@router.post("/events/purge")
def guard_event_purge(payload: dict = Body(default={}), user=Depends(current_user)):
    """批量删事件。

    mode: closed（已关闭）/ false_positive（误报）/ listed（按 ids）/ all（全部）
    """
    mode = (payload.get("mode") or "closed").strip()
    ids = payload.get("ids") or []
    conn = connect()
    if mode == "listed":
        ids = [_int(x) for x in ids if _int(x) > 0]
        if not ids:
            raise HTTPException(400, "没有要删除的事件 id")
        q = "DELETE FROM guard_events WHERE id IN (%s)" % ",".join("?" * len(ids))
        args = tuple(ids)
        cnt = conn.execute("SELECT COUNT(*) c FROM guard_events WHERE id IN (%s)"
                           % ",".join("?" * len(ids)), args).fetchone()["c"]
    elif mode == "all":
        cnt = conn.execute("SELECT COUNT(*) c FROM guard_events").fetchone()["c"]
        q, args = "DELETE FROM guard_events", ()
    elif mode == "false_positive":
        cnt = conn.execute("SELECT COUNT(*) c FROM guard_events WHERE status='false_positive'").fetchone()["c"]
        q, args = "DELETE FROM guard_events WHERE status='false_positive'", ()
    elif mode == "closed":
        cnt = conn.execute("SELECT COUNT(*) c FROM guard_events WHERE status='closed'").fetchone()["c"]
        q, args = "DELETE FROM guard_events WHERE status='closed'", ()
    else:
        raise HTTPException(400, "非法模式，可选 closed / false_positive / listed / all")
    if not cnt:
        return {"ok": True, "deleted": 0}
    with tx() as c:
        c.execute(q, args)
        audit.append(c, user["username"], "guard.event.purge", "guard_event", 0,
                     None, {"mode": mode, "deleted": cnt, "ids": ids[:100]})
    return {"ok": True, "deleted": cnt}


@router.post("/events/{eid}/status")
def guard_event_status(eid: int, payload: dict = Body(...), user=Depends(current_user)):
    to = (payload.get("status") or "").strip()
    if to not in ("new", "ack", "closed", "false_positive", "escalated"):
        raise HTTPException(400, "非法状态")
    conn = connect()
    row = conn.execute("SELECT status FROM guard_events WHERE id=?", (eid,)).fetchone()
    if not row:
        raise HTTPException(404, "事件不存在")
    with tx() as c:
        c.execute("UPDATE guard_events SET status=? WHERE id=?", (to, eid))
        audit.append(c, user["username"], "guard.event.status", "guard_event", eid,
                     {"from": row["status"]}, {"to": to})
    return {"ok": True}


# ================== 规则 ==================
@router.get("/rules")
def guard_rules(category: str = "", enabled: str = "", user=Depends(current_user)):
    conn = connect()
    where, args = [], []
    if category:
        where.append("category=?"); args.append(category)
    if enabled in ("0", "1"):
        where.append("enabled=?"); args.append(int(enabled))
    w = (" WHERE " + " AND ".join(where)) if where else ""
    rows = L(conn.execute("SELECT * FROM guard_rules" + w + " ORDER BY category, severity DESC",
                          tuple(args)).fetchall())
    for r in rows:
        try:
            r["cond"] = json.loads(r.get("condition") or "{}")
        except Exception:
            r["cond"] = {}
        try:
            r["acts"] = json.loads(r.get("actions") or "{}")
        except Exception:
            r["acts"] = {}
        r["mitre_label"] = mitre.label(r.get("technique"))
        if r.get("category") == "chain":
            # 链模板不是对单个对象求值，前端要显示"它要求哪些战术同时出现"
            req = (r.get("cond") or {}).get("require") or []
            r["chain_req"] = " + ".join(req) if req else "多战术"
    return {"total": len(rows), "items": rows, "categories": list(rules.CATEGORIES)}


@router.patch("/rules/{rid}")
def guard_rule_update(rid: int, payload: dict = Body(...), user=Depends(current_user)):
    conn = connect()
    row = conn.execute("SELECT * FROM guard_rules WHERE id=?", (rid,)).fetchone()
    if not row:
        raise HTTPException(404, "规则不存在")
    sets, args = [], []
    if "enabled" in payload:
        sets.append("enabled=?"); args.append(1 if payload["enabled"] else 0)
    if "severity" in payload:
        if payload["severity"] not in rules.SEV_SCORE:
            raise HTTPException(400, "非法严重度")
        sets.append("severity=?"); args.append(payload["severity"])
    if "actions" in payload:
        acts = payload["actions"] or {}
        if not isinstance(acts, dict):
            raise HTTPException(400, "actions 必须是对象")
        sets.append("actions=?"); args.append(json.dumps(acts, ensure_ascii=False))
    if "condition" in payload:
        cond = payload["condition"]
        if not isinstance(cond, dict):
            raise HTTPException(400, "condition 必须是对象")
        sets.append("condition=?"); args.append(json.dumps(cond, ensure_ascii=False))
    if not sets:
        return {"ok": True, "changed": 0}
    sets.append("updated_at=?")
    args.append(now())
    with tx() as c:
        c.execute("UPDATE guard_rules SET %s WHERE id=?" % ",".join(sets), args + [rid])
        audit.append(c, user["username"], "guard.rule.update", "guard_rule", rid,
                     dict(row), {k: payload.get(k) for k in ("enabled", "severity", "actions", "condition")})
    return {"ok": True, "changed": len(sets) - 1}


@router.post("/rules/{rid}/test")
def guard_rule_test(rid: int, payload: dict = Body(default={}), user=Depends(current_user)):
    """规则自测：把一条合成对象喂给规则，返回命中与否 + 命中字段。

    用于上线前验证“这条规则到底能不能被打中”，不依赖真实攻击行为。
    """
    conn = connect()
    row = conn.execute("SELECT * FROM guard_rules WHERE id=?", (rid,)).fetchone()
    if not row:
        raise HTTPException(404, "规则不存在")
    try:
        cond = json.loads(row["condition"] or "{}")
    except Exception:
        raise HTTPException(400, "规则条件不是合法 JSON")
    sample = payload.get("sample")
    if not sample:
        raise HTTPException(400, "缺少 sample（合成的对象样本）")
    hit = rules.evaluate(cond, sample)
    return {"ok": True, "hit": bool(hit), "rule": row["name"], "sample": sample}


# ================== 策略 ==================
@router.get("/policy")
def guard_policy(user=Depends(current_user)):
    pol = policy.get_policy(refresh=True)
    return {"policy": pol, "modes": list(policy.VALID_MODES)}


@router.put("/policy")
def guard_policy_update(payload: dict = Body(...), user=Depends(current_user)):
    conn = connect()
    old = dict(conn.execute("SELECT * FROM guard_policy WHERE id=1").fetchone() or {})
    try:
        r = policy.update_policy(payload)
    except ValueError as e:
        raise HTTPException(400, str(e))
    with tx() as c:
        audit.append(c, user["username"], "guard.policy.update", "guard_policy", 1, old,
                     {k: payload.get(k) for k in payload})
    return r


# ================== 白名单 ==================
@router.get("/whitelist")
def guard_whitelist(user=Depends(current_user)):
    conn = connect()
    return {"items": L(conn.execute("SELECT * FROM guard_whitelist ORDER BY kind, value").fetchall())}


@router.post("/whitelist")
def guard_whitelist_add(payload: dict = Body(...), user=Depends(current_user)):
    kind = (payload.get("kind") or "").strip()
    value = (payload.get("value") or "").strip()
    if kind not in ("process", "ip", "port", "domain"):
        raise HTTPException(400, "kind 只允许 process/ip/port/domain")
    if not value:
        raise HTTPException(400, "value 不能为空")
    with tx() as c:
        try:
            c.execute("INSERT INTO guard_whitelist(kind,value,note,source) VALUES(?,?,?,'user')",
                      (kind, value, (payload.get("note") or "")[:200]))
        except Exception:
            raise HTTPException(409, "该条目已存在")
        audit.append(c, user["username"], "guard.whitelist.add", "guard_whitelist", value,
                     None, {"kind": kind})
    policy.invalidate()
    return {"ok": True}


@router.delete("/whitelist/{wid}")
def guard_whitelist_del(wid: int, user=Depends(current_user)):
    conn = connect()
    row = conn.execute("SELECT * FROM guard_whitelist WHERE id=?", (wid,)).fetchone()
    if not row:
        raise HTTPException(404, "条目不存在")
    if row["source"] == "default":
        raise HTTPException(400, "内置条目不可删除，可改为停用")
    with tx() as c:
        c.execute("DELETE FROM guard_whitelist WHERE id=?", (wid,))
        audit.append(c, user["username"], "guard.whitelist.delete", "guard_whitelist", wid, dict(row))
    policy.invalidate()
    return {"ok": True}


# ================== 响应与回滚 ==================
@router.get("/responses")
def guard_responses(event_id: int = 0, limit: int = Query(default=50, le=200),
                    user=Depends(current_user)):
    conn = connect()
    if event_id:
        rows = conn.execute("SELECT * FROM guard_responses WHERE event_id=? ORDER BY id DESC",
                            (event_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM guard_responses ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return {"items": L(rows)}


@router.post("/responses/{rid}/revert")
def guard_revert(rid: int, user=Depends(current_user)):
    r = respond.revert(rid, operator=user["username"])
    with tx() as c:
        audit.append(c, user["username"], "guard.response.revert", "guard_response", rid, None, r)
    if not r.get("ok"):
        raise HTTPException(400, r.get("error") or r.get("detail") or "回滚失败")
    return r


# ================== 防火墙对账 ==================
@router.get("/firewall")
def guard_firewall(user=Depends(current_user)):
    """列出本引擎在系统防火墙上留下的所有规则，和库里的记录对账。"""
    rules_on_host = firewall.list_guard_rules()
    conn = connect()
    rows = L(conn.execute(
        "SELECT id,action,target,applied,reverted,firewall_rule,expire_at FROM guard_responses "
        "WHERE applied=1 AND reverted=0 ORDER BY id DESC LIMIT 200").fetchall())
    host_names = {r.get("DisplayName") for r in rules_on_host}
    for r in rows:
        r["on_host"] = r.get("firewall_rule") in host_names
    orphan = [n for n in host_names if n and not any(
        x.get("firewall_rule") == n for x in rows)]
    return {"admin": is_admin(), "host_rules": rules_on_host,
            "db_responses": rows, "orphan_rules": orphan, "count": len(rules_on_host)}


@router.post("/firewall/purge")
def guard_firewall_purge(payload: dict = Body(default={}), user=Depends(current_user)):
    """清理本引擎创建的防火墙规则。默认只清“库里已无对应活动记录”的孤儿规则。"""
    all_rules = bool(payload.get("all"))
    conn = connect()
    host = firewall.list_guard_rules()
    if not all_rules:
        keep = {r["firewall_rule"] for r in conn.execute(
            "SELECT firewall_rule FROM guard_responses WHERE applied=1 AND reverted=0").fetchall()}
        host = [n for n in host if (n.get("DisplayName") or "") not in keep]
    removed, failed = 0, []
    for n in host:
        dn = n.get("DisplayName") or ""
        if not dn.startswith("BlueGuard-"):
            continue
        r = firewall.remove_rule_by_name(dn)
        if r.get("ok"):
            removed += 1
        else:
            failed.append({"name": dn, "error": r.get("error")})
    with tx() as c:
        audit.append(c, user["username"], "guard.firewall.purge", "guard", "firewall",
                     None, {"removed": removed, "failed": len(failed), "all": all_rules})
    return {"ok": True, "removed": removed, "failed": failed}


# ================== ATT&CK 覆盖 & 基线 ==================
@router.get("/mitre")
def guard_mitre(user=Depends(current_user)):
    return {"tactics": mitre.summary(), "total": len(mitre.TECHNIQUES)}


@router.get("/baseline")
def guard_baseline(kind: str = "", limit: int = Query(default=100, le=500),
                   user=Depends(current_user)):
    conn = connect()
    if kind:
        rows = conn.execute("SELECT * FROM guard_baseline WHERE kind=? ORDER BY last_seen DESC LIMIT ?",
                            (kind, limit)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM guard_baseline ORDER BY last_seen DESC LIMIT ?",
                            (limit,)).fetchall()
    stats = L(conn.execute("SELECT kind, count(*) n FROM guard_baseline GROUP BY kind").fetchall())
    return {"items": L(rows), "stats": stats}


@router.delete("/baseline")
def guard_baseline_reset(user=Depends(current_user)):
    """重建基线：清空后下一轮会把当前进程全部当“新面孔”重新学习。"""
    with tx() as c:
        c.execute("DELETE FROM guard_baseline")
        audit.append(c, user["username"], "guard.baseline.reset", "guard", "baseline")
    return {"ok": True}


# ================== 导出（给周报/复盘用） ==================
@router.get("/export")
def guard_export(sev: str = "", days: int = 7, user=Depends(current_user)):
    conn = connect()
    args = []
    w = " WHERE ts >= datetime('now','localtime','-%d days')" % max(1, min(days, 90))
    if sev:
        w += " AND severity=?"
        args.append(sev)
    rows = conn.execute("SELECT ts,severity,category,rule_name,subject,mitre,detail,status "
                        "FROM guard_events" + w + " ORDER BY id DESC LIMIT 5000", args).fetchall()
    buf = io.StringIO()
    wr = csv.writer(buf)
    wr.writerow(["时间", "严重度", "类别", "规则", "对象", "ATT&CK", "详情", "状态"])
    for r in rows:
        wr.writerow([r["ts"], r["severity"], r["category"], r["rule_name"], r["subject"],
                     mitre.label(r["mitre"]), (r["detail"] or "")[:500], r["status"]])
    with tx() as c:
        audit.append(c, user["username"], "guard.export", "guard", "events", None, {"rows": len(rows)})
    return Response(
        content="\ufeff" + buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=guard_events_%s.csv" %
                 datetime.now().strftime("%Y%m%d_%H%M")})
