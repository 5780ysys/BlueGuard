# -*- coding: utf-8 -*-
"""实时外联/外部IP监控（本地准实时）。

能力边界（诚实）：
- 不抓包、不做内核驱动；基于 Windows Get-NetTCPConnection + 事件日志轮询。
- 只能发现「在本机产生可观测痕迹」的外部连接/事件（活动 TCP、失败登录等）。
- 适合单机值班的“尽快发现”场景；不是企业级 NDR/EDR。

实现：
- 后台线程按间隔轮询活动 TCP 连接，识别非内网/非回环的远端 IP；
- 轮询 Windows Security/System 事件日志（4625/4624/5152/5157 等线索）增量入库；
- 新发现外部 IP / 新连接 / 可疑登录失败时写入 live_events + logs，并触发告警扫描；
- 前端通过 /api/live/* 轮询获取状态与事件。
"""
import ipaddress
import json
import re
import threading
import time
from collections import deque
from datetime import datetime

from . import audit, search
from .db import connect, tx, enc

_lock = threading.Lock()
_state = {
    "running": False,
    "started_at": None,
    "last_poll_at": None,
    "last_error": None,
    "polls": 0,
    "external_seen": 0,
    "events_created": 0,
    "interval_sec": 5,
}
_thread = None
_stop = threading.Event()
_recent_events = deque(maxlen=500)  # 内存快照，前端可快速拉取
_seen_conn_keys = set()  # (local,local_port,remote,remote_port,state,pid)
_seen_eventlog_ids = {}  # log_name -> last RecordId/high-water heuristic (ts+id)


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _is_external_ip(ip):
    if not ip:
        return False
    ip = str(ip).strip()
    # Get-NetTCPConnection 可能返回 IPv6 映射或 scope
    ip = ip.split("%")[0]
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return False
    if addr.is_private:
        return False
    # IPv4 保留段/文档段也视为非外部攻击面（但 TEST-NET 很少见）
    return True


def _is_suspicious_port(port):
    try:
        p = int(port)
    except Exception:
        return False
    # 常见管理/敏感/横向端口；仅作提示，不等于恶意
    return p in {22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}


def _push_event(ev):
    ev.setdefault("ts", _now())
    ev.setdefault("id", "%d-%s" % (int(time.time() * 1000), ev.get("remote_ip", "x")))
    with _lock:
        _recent_events.appendleft(ev)
        _state["events_created"] = _state.get("events_created", 0) + 1
    # 落库（best-effort）
    try:
        conn = connect()
        with tx() as c:
            c.execute(
                "INSERT INTO live_events(ts,kind,severity,remote_ip,remote_port,local_port,process_name,pid,detail,raw) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (ev.get("ts"), ev.get("kind"), ev.get("severity", "info"),
                 ev.get("remote_ip"), ev.get("remote_port"), ev.get("local_port"),
                 ev.get("process_name"), ev.get("pid"), ev.get("detail"),
                 json.dumps(ev, ensure_ascii=False)),
            )
            # 同步写入 logs，便于现有检索/告警/溯源复用
            msg = ev.get("detail") or ("外部连接 %s:%s -> 本机:%s" % (
                ev.get("remote_ip"), ev.get("remote_port"), ev.get("local_port")))
            level = {"critical": "error", "high": "error", "medium": "warn"}.get(ev.get("severity"), "info")
            cur = c.execute(
                "INSERT INTO logs(ts,level,host,src_ip,dst_ip,message,raw_enc) VALUES (?,?,?,?,?,?,?)",
                (ev.get("ts"), level, ev.get("host") or "localhost",
                 ev.get("remote_ip"), ev.get("local_ip"), msg[:2000], enc(msg)),
            )
            search.fts_upsert(c, cur.lastrowid, msg, ev.get("host") or "localhost",
                              ev.get("remote_ip"), ev.get("local_ip"))
    except Exception as e:
        with _lock:
            _state["last_error"] = "live_events persist: %s" % e


def _scan_connections():
    from .platform_win import get_tcp_connections
    try:
        conns = get_tcp_connections() or []
    except Exception as e:
        with _lock:
            _state["last_error"] = "tcp poll: %s" % e
        return
    new_external = 0
    for c in conns:
        rip = str(c.get("remote_ip") or "").strip()
        if not _is_external_ip(rip):
            continue
        state = str(c.get("state") or "")
        # 关注已建立/正在进入的连接；忽略纯监听占位
        if state.upper() in {"LISTEN", "BOUND", "CLOSED"}:
            continue
        key = (c.get("local_ip"), c.get("local_port"), rip, c.get("remote_port"), state, c.get("pid"))
        with _lock:
            if key in _seen_conn_keys:
                continue
            _seen_conn_keys.add(key)
            # 防止集合无限增长：保留最近 5000
            if len(_seen_conn_keys) > 5000:
                for _ in range(1000):
                    try:
                        _seen_conn_keys.pop()
                    except KeyError:
                        break
            _state["external_seen"] = _state.get("external_seen", 0) + 1
        new_external += 1
        sev = "high" if _is_suspicious_port(c.get("local_port")) else "medium"
        if state.upper() == "SYN_RECEIVED":
            sev = "high"
        detail = "发现外部IP连接: %s:%s -> 本机 %s:%s (状态:%s, PID:%s, 进程:%s)" % (
            rip, c.get("remote_port"), c.get("local_ip"), c.get("local_port"),
            state, c.get("pid"), c.get("process_name") or "?")
        _push_event({
            "kind": "external_connection",
            "severity": sev,
            "remote_ip": rip,
            "remote_port": c.get("remote_port"),
            "local_ip": c.get("local_ip"),
            "local_port": c.get("local_port"),
            "pid": c.get("pid"),
            "process_name": c.get("process_name"),
            "state": state,
            "detail": detail,
        })
    if new_external:
        _auto_scan_alerts()


def _scan_eventlog_auth():
    """增量检查 Security 登录失败(4625)等，提取外部源IP。"""
    from .platform_win import events
    if not getattr(events, "_can_read", lambda x: False)("Security"):
        return
    try:
        evs = events.read_events("Security", 30) or []
    except Exception:
        return
    for e in evs:
        msg = (e.get("message") or "")
        eid = str(e.get("event_id") or "")
        ts = str(e.get("time") or "")
        dedup = (ts, eid, msg[:80])
        with _lock:
            prev = _seen_eventlog_ids.get("Security")
            if prev == dedup:
                continue
        # 简单提取 IP
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
        ext = [ip for ip in ips if _is_external_ip(ip)]
        if not ext:
            continue
        # 4625 登录失败 / 4624 登录成功等
        if eid in {"4625", "4771", "4776"} or "失败" in msg or "failed" in msg.lower():
            sev = "high" if eid == "4625" else "medium"
            detail = "安全日志发现外部IP活动(事件%s): 源IP %s — %s" % (eid or "?", ", ".join(ext[:3]), msg[:180])
            _push_event({
                "kind": "security_eventlog",
                "severity": sev,
                "remote_ip": ext[0],
                "detail": detail,
                "event_id": eid,
            })
    with _lock:
        if evs:
            e0 = evs[0]
            _seen_eventlog_ids["Security"] = (str(e0.get("time") or ""), str(e0.get("event_id") or ""), (e0.get("message") or "")[:80])


def _auto_scan_alerts():
    """发现新外部活动后自动跑一遍告警规则扫描（复用 routes 逻辑的简化版）。"""
    try:
        conn = connect()
        rules = conn.execute("SELECT * FROM log_rules WHERE enabled=1").fetchall()
        if not rules:
            return
        with tx() as c:
            for rule in rules:
                pat = rule["pattern"]
                rows = c.execute(
                    "SELECT src_ip, host, count(*) n, min(ts) f, max(ts) l FROM logs "
                    "WHERE message LIKE ? AND ts >= datetime('now','localtime','-10 minutes') "
                    "GROUP BY src_ip", ("%" + pat + "%",)).fetchall()
                for r in rows:
                    if not r["src_ip"]:
                        continue
                    exists = c.execute(
                        "SELECT id FROM log_alerts WHERE rule_id=? AND src_ip IS ? AND triage='pending'",
                        (rule["id"], r["src_ip"])).fetchone()
                    if exists:
                        c.execute("UPDATE log_alerts SET hit_count=?, last_seen=? WHERE id=?",
                                  (r["n"], r["l"], exists["id"]))
                    else:
                        c.execute(
                            "INSERT INTO log_alerts(rule_id,rule_name,severity,src_ip,host,summary,"
                            "hit_count,triage,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,'pending',?,?)",
                            (rule["id"], rule["name"], rule["severity"], r["src_ip"], r["host"],
                             "[实时] %s 命中 %d 次" % (rule["name"], r["n"]), r["n"], r["f"], r["l"]))
                        _push_event({
                            "kind": "alert_generated",
                            "severity": rule["severity"],
                            "remote_ip": r["src_ip"],
                            "detail": "实时告警: %s (源IP %s, 命中%s次)" % (rule["name"], r["src_ip"], r["n"]),
                        })
    except Exception as e:
        with _lock:
            _state["last_error"] = "auto alert: %s" % e


def _loop(interval):
    # 启动时先跑一次，尽快给出可见结果
    while not _stop.is_set():
        t0 = time.time()
        try:
            _scan_connections()
            _scan_eventlog_auth()
        except Exception as e:
            with _lock:
                _state["last_error"] = "loop: %s" % e
        with _lock:
            _state["last_poll_at"] = _now()
            _state["polls"] = _state.get("polls", 0) + 1
        # 等待 interval，但可被 stop 打断
        elapsed = time.time() - t0
        wait = max(1.0, float(interval) - elapsed)
        _stop.wait(wait)


def start(interval_sec=5):
    global _thread
    with _lock:
        if _state.get("running"):
            _state["interval_sec"] = int(interval_sec)
            return {"ok": True, "already": True, "state": dict(_state)}
        _stop.clear()
        _state["running"] = True
        _state["started_at"] = _now()
        _state["interval_sec"] = int(max(2, min(60, interval_sec)))
        _state["last_error"] = None
    _thread = threading.Thread(target=_loop, args=(_state["interval_sec"],), daemon=True, name="blueguard-live")
    _thread.start()
    return {"ok": True, "state": dict(_state)}


def stop():
    with _lock:
        _state["running"] = False
    _stop.set()
    return {"ok": True, "state": dict(_state)}


def status():
    with _lock:
        s = dict(_state)
        s["recent_count"] = len(_recent_events)
        s["tracked_conn_keys"] = len(_seen_conn_keys)
    return s


def recent_events(limit=100):
    limit = max(1, min(int(limit or 100), 500))
    with _lock:
        return list(_recent_events)[:limit]


def list_db_events(limit=100):
    limit = max(1, min(int(limit or 100), 500))
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT * FROM live_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return recent_events(limit)