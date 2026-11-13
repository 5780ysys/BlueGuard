# -*- coding: utf-8 -*-
"""防护引擎主循环：采集 -> 判定 -> 去重 -> 落库 -> 联动 -> 响应。

一轮 run_once() 做的事：
  1. probes.collect() 取快照；
  2. 对每条启用规则、每类候选对象求值；
  3. 同 (rule, subject) 在 dedup 窗口内合并，避免刷屏；
  4. 写 guard_events（主表）；
  5. 联动：log_alerts（告警台）-> incidents（应急）/ blocklist（封禁对账）/ audit（哈希链）；
  6. 命中动作意图且策略允许时，交给 respond 执行，并把结果写回 guard_responses。
"""
import json
import os
import threading
import time
import traceback
from datetime import datetime

from .. import config
from .. import platform_win
from ..db import connect, tx
from ..platform_win import is_admin
from . import chain, policy, probes, respond, rules, watcher

DEDUP_SEC = 300                # 默认 5 分钟：同一规则 + 同一对象只留一条事件
DEDUP_BY_CATEGORY = {"posture": 3600, "persist": 1800, "listen": 900, "chain": 1800}


def _dedup_window(category):
    return DEDUP_BY_CATEGORY.get(category, DEDUP_SEC)


def _dedup_check(rule_db_id, subject, category):
    """去重判定（落库版）：重启后不会把同一件事再报一遍，多进程也共享同一份台账。

    返回 (是否窗口内重复, 上次事件 id, 上次合并次数)
    """
    try:
        conn = connect()
        row = conn.execute(
            "SELECT last_ts, hits, last_event_id FROM guard_dedup WHERE rule_db_id=? AND subject=?",
            (rule_db_id, (subject or "")[:200])).fetchone()
    except Exception:
        return False, None, 0
    if not row:
        return False, None, 0
    hits = int(row["hits"] or 1)
    try:
        age = (datetime.now() - datetime.strptime(row["last_ts"], "%Y-%m-%d %H:%M:%S")).total_seconds()
    except Exception:
        age = 1e9
    if age < _dedup_window(category):
        return True, row["last_event_id"], hits
    return False, row["last_event_id"], hits


def _dedup_upsert(rule_db_id, subject, category, event_id=None):
    """登记命中（有则累加 hits，无则插入）。event_id 为空表示只是合并计数。"""
    try:
        with tx() as c:
            c.execute(
                "INSERT INTO guard_dedup(rule_db_id,subject,category,first_ts,last_ts,hits,last_event_id)"
                " VALUES(?,?,?,?,?,1,?)"
                " ON CONFLICT(rule_db_id,subject) DO UPDATE SET last_ts=excluded.last_ts,"
                " hits=hits+1, category=excluded.category,"
                " last_event_id=COALESCE(excluded.last_event_id, guard_dedup.last_event_id)",
                (rule_db_id, (subject or "")[:200], category, _now(), _now(), event_id))
    except Exception:
        pass


_STATE = {
    "running": False,
    "thread": None,
    "rounds": 0,
    "last_run": None,
    "last_error": None,
    "last_stats": {},
    "started_at": None,
    "stop": False,
    "lock_pid": None,
}
_LOCK = threading.Lock()
_LOCK_FH = {"fh": None}



def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ---------------- 事件字段抽取 ----------------
def _event_fields(category, obj, rule):
    """把命中对象摊平成 guard_events 的列。"""
    ev = {
        "category": category,
        "rule_id": rule.get("id"),
        "rule_name": rule.get("name"),
        "severity": rule.get("severity") or "medium",
        "mitre": rule.get("technique"),
        "subject": rules.subject_of(category, obj),
        "subject_ip": None, "pid": None, "process_name": None, "process_path": None,
        "local_port": None, "remote_ip": None, "remote_port": None,
        "detail": "",
        "evidence": {},
    }
    if category == "process":
        ev.update({
            "pid": obj.get("pid"), "process_name": obj.get("name"),
            "process_path": obj.get("exe"), "detail": obj.get("cmdline") or obj.get("name"),
            "evidence": {"cmdline": obj.get("cmdline"), "user": obj.get("user"),
                         "ppid": obj.get("ppid")},
        })
    elif category == "conn":
        ev.update({
            "remote_ip": obj.get("remote_ip"), "remote_port": obj.get("remote_port"),
            "local_port": obj.get("local_port"), "pid": obj.get("pid"),
            "process_name": obj.get("process_name"), "subject_ip": obj.get("remote_ip"),
            "detail": "%s -> %s:%s (%s)" % (obj.get("local_port"), obj.get("remote_ip"),
                                            obj.get("remote_port"), obj.get("state")),
            "evidence": dict(obj),
        })
    elif category == "listen":
        ev.update({
            "local_port": obj.get("local_port"), "pid": obj.get("pid"),
            "process_name": obj.get("process_name"),
            "subject_ip": obj.get("local_ip"),
            "detail": "监听 %s:%s pid=%s %s" % (obj.get("local_ip"), obj.get("local_port"),
                                               obj.get("pid"), obj.get("process_name")),
            "evidence": dict(obj),
        })
    elif category == "persist":
        ev.update({
            "detail": "%s %s = %s" % (obj.get("kind"), obj.get("name"), str(obj.get("value"))[:200]),
            "evidence": dict(obj),
        })
    elif category == "posture":
        ev.update({
            "detail": json.dumps(obj, ensure_ascii=False)[:600],
            "evidence": obj,
        })
    ev["score"] = rules.score_of(ev["severity"])
    return ev


# ---------------- 联动 ----------------
def _link_alert(ev):
    """写告警台（同一规则+同一来源的待研判告警合并，只加计数）。"""
    conn = connect()
    row = conn.execute(
        "SELECT id, hit_count FROM log_alerts WHERE rule_name=? AND IFNULL(src_ip,'')=IFNULL(?,'') "
        "AND triage='pending' ORDER BY id DESC LIMIT 1",
        ("[防护] " + (ev["rule_name"] or ""), ev.get("subject_ip"))).fetchone()
    if row:
        with tx() as c:
            c.execute("UPDATE log_alerts SET hit_count=hit_count+1, last_seen=? WHERE id=?",
                      (_now(), row["id"]))
        return row["id"]
    with tx() as c:
        cur = c.execute(
            "INSERT INTO log_alerts(rule_name,severity,src_ip,host,summary,hit_count,triage,first_seen,last_seen)"
            " VALUES(?,?,?,?,?,1,'pending',?,?)",
            ("[防护] " + (ev["rule_name"] or "检测规则"), ev["severity"], ev.get("subject_ip"),
             ev.get("process_name") or "localhost", (ev.get("detail") or "")[:400], _now(), _now()))
        return cur.lastrowid


def _link_incident(ev, alert_id):
    """高危及以上的事件自动开应急单（同规则未关闭则复用，避免短时间刷单）。"""
    pol = policy.get_policy()
    if not pol.get("auto_incident"):
        return None
    if rules.SEV_ORDER.get(ev["severity"], 0) < 3:      # high / critical
        return None
    title = "[防护] %s" % (ev["rule_name"] or "")[:80]
    conn = connect()
    row = conn.execute("SELECT id FROM incidents WHERE status!='closed' AND title=? LIMIT 1",
                       (title,)).fetchone()
    if row:
        with tx() as c:
            c.execute("UPDATE incidents SET updated_at=?, summary=? WHERE id=?",
                      (_now(), (ev.get("detail") or "")[:600], row["id"]))
            c.execute("INSERT INTO incident_actions(incident_id,action_type,target,detail,result,reversible,operator)"
                      " VALUES(?,?,?,?,?,0,'auto:guard')",
                      (row["id"], "guard_detect", ev.get("subject"), (ev.get("detail") or "")[:300],
                       ev["rule_name"]))
        return row["id"]
    pri = "P1" if ev["severity"] == "critical" else "P2"
    with tx() as c:
        cur = c.execute(
            "INSERT INTO incidents(title,priority,status,owner,summary,source_alert_id,updated_at)"
            " VALUES(?,?,'open','auto:guard',?,?,?)",
            (title[:200], pri, (ev.get("detail") or "")[:600], alert_id, _now()))
        iid = cur.lastrowid
        c.execute("INSERT INTO incident_actions(incident_id,action_type,target,detail,result,reversible,operator)"
                  " VALUES(?,?,?,?,?,0,'auto:guard')",
                  (iid, "guard_detect", ev.get("subject"), (ev.get("detail") or "")[:300], ev["rule_name"]))
    return iid


def _baseline_touch(snap):
    """记录进程/外联基线，返回“新面孔”数量。"""
    n_new = 0
    try:
        with tx() as c:
            for p in (snap.get("processes") or [])[:400]:
                key = (p.get("name") or "").lower()
                if not key:
                    continue
                cur = c.execute("UPDATE guard_baseline SET last_seen=?, seen_count=seen_count+1"
                                " WHERE kind='process' AND key=?", (_now(), key))
                if cur.rowcount == 0:
                    c.execute("INSERT OR IGNORE INTO guard_baseline(kind,key) VALUES('process',?)", (key,))
                    n_new += 1
    except Exception:
        pass
    return n_new


# ---------------- 主流程 ----------------
def _consume(rule, cat, obj, stats, created):
    """对单个候选对象做判定之后的全部动作：去重、落库、联动、处置。

    轮询快照和 WMI 进程创建事件都走这里，保证两条数据源行为完全一致。
    """
    ev = _event_fields(cat, obj, rule)

    # 可信名单：进程名/路径命中则跳过（白名单是"不要打扰我"，不是"不要记录"）
    if cat == "process" and (
            policy.is_whitelisted("process", ev.get("process_name")) or
            policy.is_whitelisted("process", ev.get("process_path"))):
        return
    # 自己人：本程序的进程，以及本程序派生的子进程（采集用的 powershell -EncodedCommand
    # 本身就是一条"编码命令执行"，不排掉会把自己当攻击者）
    if cat == "process" and (
            policy.is_self_process(obj.get("pid"), obj.get("name"), obj.get("exe")) or
            platform_win.is_self_spawned(obj.get("pid")) or
            (obj.get("ppid") and policy.is_self_process(
                obj.get("ppid"), obj.get("parent_name"), obj.get("parent_exe")))):
        stats["self_skipped"] = stats.get("self_skipped", 0) + 1
        return
    if cat == "conn" and policy.is_whitelisted("ip", ev.get("remote_ip")):
        return

    key_subject = (ev["subject"] or "")[:200]
    dup, prev_id, prev_hits = _dedup_check(rule.get("id"), key_subject, cat)
    if dup and prev_id:
        stats["merged"] += 1
        try:
            with tx() as c:
                c.execute("UPDATE guard_events SET evidence=? WHERE id=?",
                          (json.dumps(dict(ev["evidence"], hits=prev_hits + 1),
                                      ensure_ascii=False)[:2000], prev_id))
        except Exception:
            pass
        _dedup_upsert(rule.get("id"), key_subject, cat, None)
        return

    # 落库
    with tx() as c:
        cur = c.execute(
            "INSERT INTO guard_events(ts,rule_id,rule_name,category,severity,subject,subject_ip,pid,"
            "process_name,process_path,local_port,remote_ip,remote_port,mitre,detail,evidence,status)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'new')",
            (_now(), ev["rule_id"], ev["rule_name"], ev["category"], ev["severity"],
             ev["subject"][:200], ev.get("subject_ip"), ev.get("pid"),
             ev.get("process_name"), ev.get("process_path"), ev.get("local_port"),
             ev.get("remote_ip"), ev.get("remote_port"), ev.get("mitre"),
             (ev.get("detail") or "")[:1000],
             json.dumps(ev.get("evidence") or {}, ensure_ascii=False)[:2000]))
        event_id = cur.lastrowid
        c.execute("UPDATE guard_rules SET hits=hits+1, last_hit_at=? WHERE id=?",
                  (_now(), ev["rule_id"]))
    _dedup_upsert(rule.get("id"), key_subject, cat, event_id)
    stats["hits"] += 1

    # 联动：告警台 / 应急单 / 响应
    alert_id = _link_alert(ev)
    incident_id = _link_incident(ev, alert_id)
    acts = rule.get("acts") or {}
    n_resp = 0
    for action, target in respond.plan(ev, acts):
        if not target:
            continue
        r = respond.execute(event_id, action, target, ev)
        n_resp += 1
        if r.get("ok"):
            stats["blocked"] += 1
    with tx() as c:
        c.execute("UPDATE guard_events SET alert_id=?, incident_id=? WHERE id=?",
                  (alert_id, incident_id, event_id))
    stats["responses"] += n_resp
    created.append({"id": event_id, "rule": ev["rule_name"], "severity": ev["severity"],
                    "subject": ev["subject"], "alert_id": alert_id, "incident_id": incident_id})


def _consume_watch(active_rules, stats, created):
    """消费 WMI 进程创建事件：短命进程只有这条路能抓到。

    轮询间隔 8 秒，存活不到 8 秒的进程主循环永远看不到；WMI 的
    __InstanceCreationEvent 粒度 1 秒，抓到的进程在这里立刻按 process 规则判定，
    后续去重/落库/联动/处置与轮询完全共用 _consume，行为一致。
    """
    try:
        objs = watcher.drain()
    except Exception as e:
        stats["errors"].append("watch-drain: %s" % e)
        return
    stats["watched"] = len(objs)
    if not objs:
        return
    proc_rules = [r for r in active_rules if (r.get("category") or "process") == "process"]
    hit = 0
    for obj in objs:
        for rule in proc_rules:
            try:
                if not rules.evaluate(rule.get("cond"), obj):
                    continue
            except Exception:
                continue
            _consume(rule, "process", obj, stats, created)
            hit += 1
    stats["watch_hits"] = hit


def run_once(deep=False, trigger="loop"):
    """跑一轮检测。可被 API 手动触发（trigger='manual'）。"""
    t0 = time.time()
    pol = policy.get_policy(refresh=deep)
    active_rules = rules.load_rules()
    snap = probes.collect(deep=deep)
    stats = {"trigger": trigger, "rules": len(active_rules), "processes": len(snap["processes"]),
             "conns": len(snap["conns"]), "listens": len(snap["listens"]),
             "persist": len(snap["persist"]), "hits": 0, "merged": 0, "chains": 0,
             "responses": 0, "blocked": 0, "errors": list(snap.get("errors") or [])}

    created = []
    # 第一遍：WMI 进程创建事件（1 秒粒度，覆盖两次轮询之间生灭的短命进程）
    _consume_watch(active_rules, stats, created)

    # 第二遍：轮询快照（全量，覆盖连接、监听、启动项、姿态）
    for rule in active_rules:
        cat = rule.get("category") or "process"
        objs = rules.candidates(snap, cat)
        if not objs:
            continue
        for obj in objs:
            try:
                if not rules.evaluate(rule.get("cond"), obj):
                    continue
            except Exception:
                continue
            _consume(rule, cat, obj, stats, created)

    if pol.get("mode") == "block":
        try:
            stats["expired"] = respond.expire_due()
        except Exception as e:
            stats["errors"].append("expire: %s" % e)

    stats["new_faces"] = _baseline_touch(snap)

    # 攻击链关联（在所有单条规则落库之后跑）
    _run_chains(stats)

    # 每天最多归档一次（把处理完的老事件搬进归档表，热表保持小）
    if time.time() - _STATE.get("archived_at", 0) > 86400:
        try:
            stats["archive"] = archive_once(refresh_policy=False)
            _STATE["archived_at"] = time.time()
        except Exception as e:
            stats["errors"].append("archive: %s" % e)

    stats["elapsed_ms"] = int((time.time() - t0) * 1000)
    _STATE["last_stats"] = {k: v for k, v in stats.items() if k != "events"}
    stats["events"] = created[:50]

    # 修剪去重台账（每小时最多一次），避免长跑把表撑大
    if time.time() - _STATE.get("dedup_pruned", 0) > 3600:
        try:
            with tx() as c:
                c.execute("DELETE FROM guard_dedup WHERE last_ts < "
                          "datetime('now','localtime','-2 days')")
            _STATE["dedup_pruned"] = time.time()
        except Exception as e:
            stats["errors"].append("dedup-prune: %s" % e)

    _STATE["rounds"] += 1
    _STATE["last_run"] = _now()
    _STATE["last_stats"] = stats
    _STATE["last_error"] = None
    return stats


def _run_chains(stats):
    """攻击链关联：把窗口内的散点事件拼成意图，命中则产出一条结论事件。

    位置放在单条规则全部跑完之后 —— 它读的是刚落库的事件，不是快照。
    """
    try:
        hits = chain.evaluate(window_sec=chain.WINDOW_SEC)
    except Exception as e:
        stats["errors"].append("chain: %s" % e)
        return
    for h in hits:
        rule = h["rule"]
        subject = "chain:%s" % rule.get("rule_id")
        dup, prev_id, prev_hits = _dedup_check(rule.get("id"), subject, "chain")
        if dup and prev_id:
            stats["merged"] += 1
            _dedup_upsert(rule.get("id"), subject, "chain", None)
            continue
        ev = {
            "category": "chain", "rule_id": rule.get("id"), "rule_name": rule.get("name"),
            "severity": rule.get("severity") or "critical", "mitre": rule.get("technique") or "",
            "subject": subject, "subject_ip": None, "pid": None, "process_name": None,
            "process_path": None, "local_port": None, "remote_ip": None, "remote_port": None,
            "detail": chain.summary_line(h),
            "evidence": {"tactics": h["tactics"], "rules": h["rules"],
                         "window_min": chain.WINDOW_SEC // 60},
            "score": rules.score_of(rule.get("severity") or "critical"),
        }
        try:
            with tx() as c:
                cur = c.execute(
                    "INSERT INTO guard_events(ts,rule_id,rule_name,category,severity,subject,"
                    "mitre,detail,evidence,status) VALUES(?,?,?,?,?,?,?,?,?,'new')",
                    (_now(), ev["rule_id"], ev["rule_name"], "chain", ev["severity"],
                     subject, ev["mitre"], ev["detail"][:1000],
                     json.dumps(ev["evidence"], ensure_ascii=False)[:4000]))
                event_id = cur.lastrowid
                c.execute("UPDATE guard_rules SET hits=hits+1, last_hit_at=? WHERE id=?",
                          (_now(), ev["rule_id"]))
        except Exception as e:
            stats["errors"].append("chain-insert: %s" % e)
            continue
        _dedup_upsert(rule.get("id"), subject, "chain", event_id)
        stats["hits"] += 1
        stats["chains"] = stats.get("chains", 0) + 1
        alert_id = _link_alert(ev)
        incident_id = _link_incident(ev, alert_id)
        with tx() as c:
            c.execute("UPDATE guard_events SET alert_id=?, incident_id=? WHERE id=?",
                      (alert_id, incident_id, event_id))
        stats.setdefault("chain_events", []).append(
            {"id": event_id, "rule": ev["rule_name"], "tactics": h["tactics"],
             "alert_id": alert_id, "incident_id": incident_id})


def archive_once(refresh_policy=True):
    """把超过保留期、且已经处理完的事件搬进归档表，然后收掉热表空间。

    * 只归档 status in (closed, false_positive) 的 —— 没处理的绝不丢；
    * 分批 500 条，避免一次性把大表读进内存；
    * 归档是搬运不是删除，归档表用同一个 id，随时能捞回来。
    """
    pol = policy.get_policy(refresh=refresh_policy)
    if not int(pol.get("archive_enabled", 1) or 0):
        return {"ok": True, "skipped": "归档已关闭", "archived": 0}
    days = int(pol.get("retention_days") or 90)
    cols = ("id,ts,rule_id,rule_name,category,severity,subject,subject_ip,pid,process_name,"
            "process_path,local_port,remote_ip,remote_port,mitre,detail,evidence,status,"
            "alert_id,incident_id")
    cond = ("ts < datetime('now','localtime','-%d days') "
            "AND status IN ('closed','false_positive')" % days)
    conn = connect()
    total = 0
    while True:
        rows = conn.execute("SELECT id FROM guard_events WHERE " + cond + " LIMIT 500").fetchall()
        if not rows:
            break
        ids = [r["id"] for r in rows]
        with tx() as c:
            for i in ids:
                c.execute("INSERT OR IGNORE INTO guard_events_archive(%s) "
                          "SELECT %s FROM guard_events WHERE id=?" % (cols, cols), (i,))
                c.execute("DELETE FROM guard_events WHERE id=?", (i,))
        total += len(ids)
    if total:
        try:
            with tx() as c:
                pass
        except Exception:
            pass
    return {"ok": True, "archived": total, "retention_days": days}


def _loop():
    while not _STATE["stop"]:
        try:
            pol = policy.get_policy(refresh=True)
            interval = max(3, int(pol.get("interval_sec") or 8))
            run_once(deep=False, trigger="loop")
        except Exception as e:
            _STATE["last_error"] = "%s: %s" % (e.__class__.__name__, e)
            _STATE["last_stats"] = {"error": _STATE["last_error"],
                                    "trace": traceback.format_exc()[-800:]}
            interval = 15
        # 可中断休眠
        for _ in range(interval * 2):
            if _STATE["stop"]:
                break
            time.sleep(0.5)


def _acquire_instance_lock():
    """同一 data 目录只允许一个引擎循环在跑。

    多 worker 部署时每个进程都会 start()，没有这把锁就会各自判定、各自下发
    防火墙动作 —— 重复写规则只是浪费，重复 kill 就是事故。
    """
    path = str(config.DATA_DIR / "guard_engine.lock")
    try:
        fh = open(path, "a+")
    except Exception as e:
        return False, "打不开锁文件: %s" % e
    try:
        import msvcrt
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
    except Exception:
        try:
            fh.close()
        except Exception:
            pass
        return False, "已有另一个实例持有引擎锁（%s）" % path
    try:
        fh.seek(0)
        fh.truncate()
        fh.write("%d @ %s\n" % (os.getpid(), _now()))
        fh.flush()
    except Exception:
        pass
    _LOCK_FH["fh"] = fh
    return True, None


def _release_instance_lock():
    fh = _LOCK_FH.get("fh")
    if not fh:
        return
    try:
        import msvcrt
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
    except Exception:
        pass
    try:
        fh.close()
    except Exception:
        pass
    _LOCK_FH["fh"] = None


def start():
    with _LOCK:
        if _STATE["running"]:
            return {"ok": True, "already": True}
        got, why = _acquire_instance_lock()
        if not got:
            _STATE["last_error"] = why
            return {"ok": False, "error": "INSTANCE_LOCKED", "detail": why}
        _STATE["stop"] = False
        t = threading.Thread(target=_loop, name="guard-engine", daemon=True)
        _STATE["thread"] = t
        _STATE["running"] = True
        _STATE["started_at"] = _now()
        _STATE["lock_pid"] = os.getpid()
        t.start()
    # 进程创建事件源：能补上轮询漏掉的短命进程；起不来不影响主循环
    try:
        _STATE["watch"] = watcher.start()
    except Exception as e:
        _STATE["watch"] = {"ok": False, "detail": str(e)}
    try:
        conn = connect()
        audit_log(conn, "guard.start")
    except Exception:
        pass
    return {"ok": True, "started": True, "pid": os.getpid()}


def stop():
    with _LOCK:
        _STATE["stop"] = True
        _STATE["running"] = False
    try:
        watcher.stop()
    except Exception:
        pass
    _release_instance_lock()
    try:
        audit_log(connect(), "guard.stop")
    except Exception:
        pass
    return {"ok": True, "stopped": True}


def audit_log(conn, action):
    """引擎自身的启停也进哈希链（conn 参数保留以兼容调用点）。"""
    from .. import audit
    try:
        with tx() as c:
            audit.append(c, "auto:guard", action, "guard", "engine", None,
                         json.dumps({"ts": _now()}))
    except Exception:
        pass


def status():
    pol = policy.get_policy(refresh=True)
    s = dict(_STATE)
    s.pop("thread", None)
    s.update({
        "mode": pol.get("mode"),
        "interval_sec": pol.get("interval_sec"),
        "autostart": pol.get("autostart"),
        "rate": respond.rate_state(),
        "admin": is_admin(),
    })
    try:
        s["watch"] = watcher.status()
    except Exception:
        s["watch"] = None
    return s
