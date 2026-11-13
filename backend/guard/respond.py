# -*- coding: utf-8 -*-
"""响应层：把“判定”变成“动作”，并且保证每个动作都能精确回滚。

四类动作：
  block_ip      —— 防火墙入站阻断远端 IP（复用已有 BlueGuard-Block-* 规则）
  block_program —— 防火墙阻断某 exe 的出站（比重命名/删文件温和，可回滚）
  block_port    —— 阻断本机端口
  kill_process  —— 结束进程（最后手段，受自保护与关键进程保护约束）

安全约束（缺一不可）：
  * mode=monitor 只记录；mode=alert 只告警；mode=block 才真正下发；
  * 单分钟动作数超 max_actions_per_min 后全部降级为“仅记录”；
  * 命中可信名单 / 系统关键进程 / 自身进程的对象，一律不动。
"""
import json
import time

from .. import audit
from ..db import connect, tx
from ..platform_win import firewall, is_admin
from . import policy

_ACT_WINDOW = {"ts": [], }     # 滑动窗口，存动作时间戳


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _after_minutes(m):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + int(m) * 60))


def _rate_ok():
    """令牌式限速：一分钟窗口内最多 max_actions_per_min 次真实下发。"""
    pol = policy.get_policy()
    limit = int(pol.get("max_actions_per_min") or 12)
    now = time.time()
    _ACT_WINDOW["ts"] = [t for t in _ACT_WINDOW["ts"] if now - t < 60]
    if len(_ACT_WINDOW["ts"]) >= limit:
        return False
    _ACT_WINDOW["ts"].append(now)
    return True


def rate_state():
    now = time.time()
    used = len([t for t in _ACT_WINDOW["ts"] if now - t < 60])
    pol = policy.get_policy()
    return {"used": used, "limit": int(pol.get("max_actions_per_min") or 12),
            "window_sec": 60}


def _record(conn, event_id, action, target, mode, applied, result, revert_action="",
            firewall_rule="", expire_at=None, operator="auto"):
    with tx() as c:
        cur = c.execute(
            "INSERT INTO guard_responses(ts,event_id,action,target,mode,applied,result,"
            "revert_action,reverted,operator,firewall_rule,expire_at) VALUES(?,?,?,?,?,?,?,?,0,?,?,?)",
            (_now(), event_id, action, str(target)[:400], mode, 1 if applied else 0,
             str(result)[:900], revert_action, operator, firewall_rule, expire_at))
        return cur.lastrowid


def plan(event, acts):
    """把规则上的动作意图展开成待执行列表（受 mode/开关/阈值约束）。"""
    pol = policy.get_policy()
    mode = pol.get("mode") or "monitor"
    score = int(event.get("score") or 0)
    threshold = int(pol.get("score_threshold") or 60)
    out = []
    if mode != "block" or score < threshold:
        return out
    if acts.get("block_ip") and pol.get("auto_block_ip") and event.get("remote_ip"):
        out.append(("block_ip", event["remote_ip"]))
    if acts.get("block_program") and pol.get("auto_block_program") and event.get("process_path"):
        out.append(("block_program", event["process_path"]))
    if acts.get("block_port") and pol.get("auto_block_ip") and event.get("local_port"):
        out.append(("block_port", event["local_port"]))
    if acts.get("kill") and pol.get("auto_kill_process") and event.get("pid"):
        out.append(("kill_process", event["pid"]))
    return out


def _precheck(action, target, event):
    """对象级校验：只判“该不该动”，不判“能不能动”。

    放在权限检查之前，是为了让“关键进程不能杀”这类结论不被“没提权”掩盖——
    否则未提权时什么都报 ELEVATION_REQUIRED，用户看不出规则到底对不对。
    """
    event = event or {}
    if action == "block_ip":
        ip = str(target)
        if policy.is_internal_ip(ip):
            return ("INTERNAL_IP", "内网/回环/保留地址不做封禁")
        if policy.is_whitelisted("ip", ip):
            return ("WHITELISTED", "命中 IP 白名单")
        return None

    if action == "block_program":
        path = str(target)
        base = path.rsplit("\\", 1)[-1]
        if policy.is_self_process(path=path):
            return ("SELF_PROTECTED", "自保护：拒绝阻断 BlueGuard 自身")
        if policy.is_protected_process(name=base, path=path):
            return ("PROTECTED", "系统关键程序不做出站阻断")
        if policy.is_whitelisted("process", path) or policy.is_whitelisted("process", base):
            return ("WHITELISTED", "命中进程白名单")
        return None

    if action == "block_port":
        port = int(target)
        if port in (53, 80, 443):
            return ("PROTECTED_PORT", "DNS/HTTP/HTTPS 端口不做阻断，否则整机断网")
        if policy.is_whitelisted("port", str(port)):
            return ("WHITELISTED", "命中端口白名单")
        return None

    if action == "kill_process":
        pid = int(target)
        name = event.get("process_name") or ""
        path = event.get("process_path") or ""
        if not name or not path:
            try:
                import psutil
                p = psutil.Process(pid)
                name = name or (p.name() or "")
                path = path or (p.exe() or "")
            except Exception:
                pass
        if policy.is_protected_process(name=name, path=path, pid=pid):
            return ("PROTECTED", "自保护/系统关键进程：拒绝结束")
        if policy.is_whitelisted("process", name) or policy.is_whitelisted("process", path):
            return ("WHITELISTED", "命中进程白名单")
        return None

    return None


def _kill_tree(pid, name=""):
    """先取证、再杀整棵树。

    只 kill 父进程是最常见的处置错误：真正的 payload 往往是子进程，
    杀掉 loader 之后子进程继续跑，还丢掉了唯一的线索。
    取证内容（命令行/路径/用户/启动时间/活动连接/子进程）随结果一起落库。
    """
    try:
        import psutil
    except Exception:
        return False, "psutil 不可用，无法安全结束进程", {}
    try:
        p = psutil.Process(pid)
    except Exception as e:
        return False, "进程不存在或已退出: %s" % e, {"pid": pid, "name": name}
    fx = {"pid": pid, "name": name}
    try:
        fx.update({
            "exe": p.exe(),
            "cmdline": (" ".join(p.cmdline()) or "")[:500],
            "cwd": p.cwd(),
            "user": p.username(),
            "created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.create_time())),
            "conns": len(p.net_connections(kind="inet") or []),
        })
    except Exception:
        pass
    kids = []
    try:
        kids = p.children(recursive=True)
        fx["children"] = [{"pid": k.pid, "name": k.name()} for k in kids][:20]
    except Exception:
        pass
    killed, failed = [], []
    for k in kids:                      # 先子后父
        try:
            k.kill()
            killed.append(k.pid)
        except Exception as e:
            failed.append("%s:%s" % (k.pid, e))
    try:
        p.kill()
        p.wait(timeout=5)
        killed.append(pid)
    except Exception as e:
        return (False,
                "结束失败: %s｜已取证: %s" % (e, json.dumps(fx, ensure_ascii=False)[:300]), fx)
    msg = "已结束 %d 个进程（含 %d 个子进程）" % (len(killed), len(kids))
    if failed:
        msg += "；%d 个子进程结束失败" % len(failed)
    msg += "｜取证: " + json.dumps(fx, ensure_ascii=False)[:400]
    return True, msg, fx


def execute(event_id, action, target, event=None):
    """执行单个动作，返回结果字典（并落库 guard_responses）。"""
    event = event or {}
    pol = policy.get_policy()
    mode = pol.get("mode") or "monitor"
    expire_at = _after_minutes(pol.get("expire_minutes") or 30)
    conn = connect()

    # ---- 第零层：模式 ----
    if mode != "block":
        rid = _record(conn, event_id, action, target, mode, False, "当前为 %s 模式，不下发动作" % mode)
        return {"ok": False, "error": "MODE_%s" % mode.upper(), "response_id": rid}

    # ---- 第一层：该不该动这个对象（与权限无关，先判，错误信息才准）----
    pre = _precheck(action, target, event)
    if pre:
        rid = _record(conn, event_id, action, target, mode, False, pre[1])
        return {"ok": False, "error": pre[0], "response_id": rid}

    # ---- 第二层：能不能动（权限 + 限速）----
    if not is_admin():
        rid = _record(conn, event_id, action, target, mode, False, "需管理员权限，未下发")
        return {"ok": False, "error": "ELEVATION_REQUIRED", "response_id": rid}
    if not _rate_ok():
        rid = _record(conn, event_id, action, target, mode, False, "触发限速，降级为仅记录")
        return {"ok": False, "error": "RATE_LIMITED", "response_id": rid}

    if action == "block_ip":
        ip = str(target)
        r = firewall.block_ip(ip, note=(event.get("rule_name") or "guard")[:40])
        with tx() as c:
            c.execute("INSERT INTO blocklist(ip,reason,desired_state,applied,operator) VALUES(?,?,'blocked',?, 'auto:guard')"
                      " ON CONFLICT(ip) DO UPDATE SET desired_state='blocked', applied=excluded.applied, reason=excluded.reason",
                      (ip, "防护引擎: %s" % (event.get("rule_name") or action), 1 if r.get("ok") else 0))
        rid = _record(conn, event_id, action, ip, mode, r.get("ok"), r.get("error") or "已下发入站阻断",
                      revert_action="unblock_ip", firewall_rule=firewall.RULE_PREFIX + ip, expire_at=expire_at)
        _audit("guard.block_ip", "ip", ip, r)
        return {"ok": bool(r.get("ok")), "response_id": rid, "detail": r}

    if action == "block_program":
        path = str(target)
        r = firewall.block_program(path, note=(event.get("rule_name") or "guard")[:40])
        rid = _record(conn, event_id, action, path, mode, r.get("ok"), r.get("error") or "已阻断出站",
                      revert_action="unblock_program", firewall_rule=r.get("rule"), expire_at=expire_at)
        _audit("guard.block_program", "process", path, r)
        return {"ok": bool(r.get("ok")), "response_id": rid, "detail": r}

    if action == "block_port":
        port = int(target)
        r = firewall.block_port(port, "Inbound", note=(event.get("rule_name") or "guard")[:40])
        rid = _record(conn, event_id, action, port, mode, r.get("ok"), r.get("error") or "已阻断入站端口",
                      revert_action="unblock_port", firewall_rule=r.get("rule"), expire_at=expire_at)
        _audit("guard.block_port", "port", str(port), r)
        return {"ok": bool(r.get("ok")), "response_id": rid, "detail": r}

    if action == "kill_process":
        pid = int(target)
        name = event.get("process_name") or ""
        ok, msg, fx = _kill_tree(pid, name)
        rid = _record(conn, event_id, action, "pid:%s %s" % (pid, name), mode, ok, msg,
                      revert_action="", expire_at=None)
        # 取证内容单独存一份，方便事后复盘（result 里只留摘要）
        try:
            with tx() as c:
                c.execute("UPDATE guard_responses SET args=? WHERE id=?",
                          (json.dumps(fx, ensure_ascii=False)[:1500], rid))
        except Exception:
            pass
        _audit("guard.kill_process", "process", "pid:%s %s" % (pid, name),
               {"ok": ok, "error": msg, "forensics": fx})
        return {"ok": ok, "response_id": rid, "detail": msg, "forensics": fx}

    rid = _record(conn, event_id, action, target, mode, False, "未知动作")
    return {"ok": False, "error": "UNKNOWN_ACTION", "response_id": rid}


def _audit(action, obj_type, obj_id, payload):
    try:
        import json as _json
        with tx() as c:
            audit.append(c, "auto:guard", action, obj_type, str(obj_id),
                         None, _json.dumps(payload, ensure_ascii=False)[:800])
    except Exception:
        pass


def revert(response_id, operator="auto:guard"):
    """回滚一条响应记录。防火墙类动作可完全回滚，结束进程不可。"""
    conn = connect()
    row = conn.execute("SELECT * FROM guard_responses WHERE id=?", (response_id,)).fetchone()
    if not row:
        return {"ok": False, "error": "记录不存在"}
    if row["reverted"]:
        return {"ok": False, "error": "已回滚过"}
    action, target = row["action"], row["target"]
    ok, detail = False, ""
    if action == "block_ip":
        r = firewall.unblock_ip(target)
        ok, detail = bool(r.get("ok")), r.get("error") or "已解除阻断"
        with tx() as c:
            c.execute("UPDATE blocklist SET desired_state='allowed', applied=0 WHERE ip=?", (target,))
    elif action == "block_program":
        r = firewall.unblock_program(target)
        ok, detail = bool(r.get("ok")), r.get("error") or "已解除出站阻断"
    elif action == "block_port":
        r = firewall.unblock_port(int(target), "Inbound")
        ok, detail = bool(r.get("ok")), "已解除端口阻断"
    elif action == "kill_process":
        return {"ok": False, "error": "结束进程不可回滚（进程已终止）"}
    else:
        return {"ok": False, "error": "未知动作类型"}

    with tx() as c:
        c.execute("UPDATE guard_responses SET reverted=1, reverted_at=?, result=? WHERE id=?",
                  (_now(), (detail + " / 已回滚")[:900], response_id))
    _audit("guard.revert", "response", str(response_id), {"ok": ok, "detail": detail})
    return {"ok": ok, "detail": detail}


def expire_due():
    """清理到期的临时阻断（expire_at < now 且未回滚）。"""
    conn = connect()
    now = _now()
    rows = conn.execute(
        "SELECT id FROM guard_responses WHERE reverted=0 AND applied=1 AND expire_at IS NOT NULL "
        "AND expire_at <= ?", (now,)).fetchall()
    n = 0
    for r in rows:
        res = revert(r["id"], operator="auto:expire")
        if res.get("ok"):
            n += 1
    return n
