# -*- coding: utf-8 -*-
"""网卡变更五层兜底（项目生死线，设计文档 §8.1）。

五层：
  1. 快照     —— 变更前完整保存网卡配置（密文入库 + 明细表）
  2. 三级验证 —— ①配置落地 ②网关可达 ③外网/自定目标可达
  3. 自动回滚 —— 验证失败立即按快照还原
  4. 看门狗   —— 变更成功后启动 N 秒定时器，未确认则自动还原
  5. 崩溃补扫 —— 进程重启时扫描未确认变更，执行还原

关键：任何一步失败都要能把自己救回来。改 IP 最大的风险是"改完就失联"。
"""
import json
import threading
import time
import uuid
from datetime import datetime, timedelta

from .db import connect, tx, enc, dec
from . import config, audit
from .platform_win import iface as iface_adapter, netcfg

_lock = threading.Lock()
_timers = {}


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------- 第 1 层：快照 ----------
def take_snapshot(conn, iface_name: str, reason: str = "") -> int:
    state = iface_adapter.get_iface_state(iface_name)
    payload = json.dumps(state, ensure_ascii=False)
    checksum = uuid.uuid5(uuid.NAMESPACE_OID, payload).hex
    cur = conn.execute(
        "INSERT INTO net_iface_snapshots(iface, payload_enc, checksum, reason) VALUES (?,?,?,?)",
        (iface_name, enc(payload), checksum, reason),
    )
    sid = cur.lastrowid
    for a in state.get("ipv4", []):
        conn.execute(
            "INSERT INTO net_snapshot_items(snapshot_id, iface, ip, prefix, gateway, dns, dhcp) "
            "VALUES (?,?,?,?,?,?,?)",
            (sid, iface_name, a.get("ip"), a.get("prefix"), state.get("gateway"),
             None, 1 if state.get("dhcp") else 0),
        )
    if not state.get("ipv4"):
        conn.execute(
            "INSERT INTO net_snapshot_items(snapshot_id, iface, ip, prefix, gateway, dns, dhcp) "
            "VALUES (?,?,?,?,?,?,?)",
            (sid, iface_name, None, None, state.get("gateway"), None, 1 if state.get("dhcp") else 0),
        )
    return sid


def get_snapshot(conn, snapshot_id: int) -> dict:
    row = conn.execute("SELECT * FROM net_iface_snapshots WHERE id=?", (snapshot_id,)).fetchone()
    if not row:
        return {}
    return json.loads(dec(row["payload_enc"]))


# ---------- 第 2 层：三级验证 ----------
def _ping(host: str, timeout_ms: int = 1200) -> bool:
    import subprocess
    try:
        _cf = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        _si = None
        try:
            _si = subprocess.STARTUPINFO()
            _si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            _si.wShowWindow = 0
        except Exception:
            pass
        p = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), host],
            capture_output=True, timeout=5, creationflags=_cf, startupinfo=_si,
        )
        out = p.stdout.decode("utf-8", "replace").lower()
        return ("ttl=" in out) or ("来自" in out and "字节" in out)
    except Exception:
        return False


def _tcp(host: str, port: int = 53, timeout: float = 2.0) -> bool:
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def verify_three_level(conn, iface_name: str, expect_ip: str,
                       expect_gateway: str = None, probes=None) -> dict:
    """三级验证：配置落地 -> 网关可达 -> 外部可达。"""
    result = {"level1": False, "level2": False, "level3": False,
              "detail": {}, "ok": False}

    # 级别 1：IP 是否真的落到网卡上
    state = iface_adapter.get_iface_state(iface_name)
    actual_ips = [a.get("ip") for a in state.get("ipv4", [])]
    result["detail"]["expected_ip"] = expect_ip
    result["detail"]["actual_ips"] = actual_ips
    result["level1"] = expect_ip in actual_ips or (expect_ip is None and not actual_ips)

    # 级别 2：网关可达
    gw = expect_gateway or state.get("gateway")
    result["detail"]["gateway"] = gw
    if gw:
        result["level2"] = _ping(gw)
    else:
        # 无网关（如仅主机网络）视为跳过
        result["level2"] = True
        result["detail"]["level2_note"] = "无默认网关，跳过"

    # 级别 3：外部可达（配置的探测目标，默认公网 DNS）
    targets = probes or [("223.5.5.5", 53), ("1.1.1.1", 53)]
    reachable = any(_tcp(h, p) for h, p in targets)
    result["level3"] = reachable
    result["detail"]["probes"] = ["%s:%d" % t for t in targets]
    result["detail"]["level3_note"] = "至少一个探测目标可达" if reachable else "全部不可达"

    result["ok"] = result["level1"] and result["level2"] and result["level3"]
    return result


# ---------- 第 3 层：自动回滚 ----------
def rollback(conn, snapshot_id: int, operator: str, reason: str) -> dict:
    snap = get_snapshot(conn, snapshot_id)
    if not snap:
        return {"ok": False, "error": "快照不存在"}
    iface_name = snap.get("name")
    ips = snap.get("ipv4", [])
    primary = ips[0] if ips else {}

    if snap.get("dhcp"):
        res = netcfg.apply(iface_name, None, 0, None, None, dhcp=True)
    else:
        res = netcfg.apply(
            iface_name,
            primary.get("ip"),
            primary.get("prefix") or 24,
            snap.get("gateway"),
            None,
            dhcp=False,
        )

    verify = verify_three_level(
        conn, iface_name, primary.get("ip"), snap.get("gateway")
    ) if res.get("ok") else {"ok": False, "detail": {"rollback_apply_failed": res.get("error")}}

    conn.execute(
        "UPDATE net_change_log SET rolled_back=1, status='rolled_back', verify_result=? "
        "WHERE snapshot_id=? AND rolled_back=0",
        (json.dumps(verify, ensure_ascii=False), snapshot_id),
    )
    audit.append(conn, operator, "network.rollback", "snapshot", snapshot_id,
                 None, {"reason": reason, "verify": verify})
    return {"ok": res.get("ok") and verify.get("ok"), "apply": res, "verify": verify}


# ---------- 第 4 层：看门狗 ----------
def _watchdog_fire(change_id: int, snapshot_id: int):
    """定时器到期：若变更仍未确认，自动回滚。"""
    with _lock:
        _timers.pop(change_id, None)
    conn = connect()
    row = conn.execute("SELECT status FROM net_change_log WHERE id=?", (change_id,)).fetchone()
    if not row or row["status"] != "pending":
        return
    with tx() as c:
        res = rollback(c, snapshot_id, "watchdog", "看门狗超时未确认，自动还原")
        c.execute("UPDATE net_change_log SET status='auto_reverted' WHERE id=?", (change_id,))
    return res


def arm_watchdog(change_id: int, snapshot_id: int, seconds: int = None):
    secs = seconds or config.WATCHDOG_SECONDS
    t = threading.Timer(secs, _watchdog_fire, args=(change_id, snapshot_id))
    t.daemon = True
    with _lock:
        _timers[change_id] = t
    t.start()
    return secs


def confirm_change(change_id: int) -> bool:
    """人工确认变更成功，撤掉看门狗。"""
    with _lock:
        t = _timers.pop(change_id, None)
        if t:
            t.cancel()
    with tx() as c:
        row = c.execute("SELECT status FROM net_change_log WHERE id=?", (change_id,)).fetchone()
        if not row:
            return False
        c.execute("UPDATE net_change_log SET status='confirmed', watchdog_until=NULL WHERE id=?",
                  (change_id,))
    return True


# ---------- 主流程：变更 + 五层兜底 ----------
def change_ip(conn, iface_name: str, ip: str, prefix: int, gateway: str,
              dns: str, operator: str, watchdog_seconds: int = None) -> dict:
    # 1) 快照
    snapshot_id = take_snapshot(conn, iface_name, reason="变更前自动快照")
    conn.commit()

    change_id = None
    # 记录 pending 变更
    cur = conn.execute(
        "INSERT INTO net_change_log(iface, snapshot_id, to_state, operator, status) "
        "VALUES (?,?,?,?, 'pending')",
        (iface_name, snapshot_id,
         json.dumps({"ip": ip, "prefix": prefix, "gateway": gateway, "dns": dns},
                    ensure_ascii=False),
         operator),
    )
    change_id = cur.lastrowid
    conn.commit()

    # 2) 执行
    apply_res = netcfg.apply(iface_name, ip, prefix, gateway, dns, dhcp=False)
    if not apply_res.get("ok"):
        # 执行就失败 -> 不需要改，直接标记
        conn.execute(
            "UPDATE net_change_log SET status='failed', verify_result=? WHERE id=?",
            (json.dumps({"apply": apply_res}, ensure_ascii=False), change_id),
        )
        conn.commit()
        code = apply_res.get("error")
        audit.append(conn, operator, "network.change_ip.failed", "iface", iface_name,
                     None, {"ip": ip, "error": code})
        conn.commit()
        return {"ok": False, "stage": "apply", "error": code,
                "snapshot_id": snapshot_id, "change_id": change_id,
                "hint": "需要管理员权限" if code == "ELEVATION_REQUIRED" else None}

    # 3) 三级验证
    verify = verify_three_level(conn, iface_name, ip, gateway)

    if not verify["ok"]:
        # 4) 验证失败 -> 立即回滚
        rb = rollback(conn, snapshot_id, operator, "三级验证未通过")
        conn.execute(
            "UPDATE net_change_log SET status='rolled_back', verify_result=? WHERE id=?",
            (json.dumps({"verify": verify, "rollback": rb}, ensure_ascii=False), change_id),
        )
        conn.commit()
        return {"ok": False, "stage": "verify", "verify": verify, "rollback": rb,
                "snapshot_id": snapshot_id, "change_id": change_id}

    # 5) 成功 -> 布防看门狗
    secs = arm_watchdog(change_id, snapshot_id, watchdog_seconds)
    until = (datetime.now() + timedelta(seconds=secs)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "UPDATE net_change_log SET verify_result=?, watchdog_until=? WHERE id=?",
        (json.dumps(verify, ensure_ascii=False), until, change_id),
    )
    audit.append(conn, operator, "network.change_ip", "iface", iface_name,
                 None, {"ip": ip, "prefix": prefix, "gateway": gateway,
                        "verify_ok": True, "watchdog_seconds": secs})
    conn.commit()
    return {"ok": True, "stage": "done", "verify": verify, "snapshot_id": snapshot_id,
            "change_id": change_id, "watchdog_seconds": secs, "watchdog_until": until}


# ---------- 第 5 层：崩溃补扫 ----------
def recover_on_boot(conn) -> dict:
    """进程启动时：任何仍处 pending 的变更，说明上次没确认就崩了 -> 回滚。"""
    rows = conn.execute(
        "SELECT id, snapshot_id, iface FROM net_change_log "
        "WHERE status='pending' AND rolled_back=0"
    ).fetchall()
    recovered = []
    for r in rows:
        try:
            rb = rollback(conn, r["snapshot_id"], "system", "进程重启补扫：变更未确认")
            conn.execute("UPDATE net_change_log SET status='recovered' WHERE id=?", (r["id"],))
            conn.commit()
            recovered.append({"change_id": r["id"], "iface": r["iface"], "ok": rb.get("ok")})
        except Exception as e:
            recovered.append({"change_id": r["id"], "error": str(e)})
    return {"scanned": len(rows), "recovered": recovered}


def list_changes(conn, limit: int = 50):
    return conn.execute(
        "SELECT * FROM net_change_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
