# -*- coding: utf-8 -*-
"""采样层：把主机状态压成一份可 diff 的快照。

设计原则：
  * 单轮采集目标 < 400ms（psutil），慢速采集（启动项/姿态）由 engine 降频调用；
  * 任何一项失败都不抛异常，退化成空集合并打上 `errors` 标记，避免一轮采集失败让整个引擎停摆；
  * 只读，不做任何修改——响应动作全部在 respond.py。
"""
import time

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from ..platform_win import guardsrc

_LAST_PERSIST = {"t": 0.0, "items": []}
_LAST_POSTURE = {"t": 0.0, "data": {}}
PERSIST_TTL = 30      # 启动项 30 秒刷一次
POSTURE_TTL = 60      # 主机姿态 60 秒刷一次


def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default


def collect_processes():
    """进程表。

    Windows 上 psutil 逐进程取 cmdline/exe 需要 390 次 OpenProcess，实测 9 秒；
    改用一次 CIM 查询（~0.8 秒）拿全量，psutil 仅在 CIM 不可用时兜底。
    """
    rows = []
    try:
        from ..platform_win import _ps
        script = ("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,"
                  "ExecutablePath,CommandLine | ConvertTo-Json -Depth 2 -Compress")
        data, err, rc = _ps(script, timeout=40)
        if isinstance(data, dict):
            data = [data]
        for d in (data or []):
            try:
                rows.append({
                    "pid": int(d.get("ProcessId") or 0),
                    "name": d.get("Name") or "",
                    "exe": d.get("ExecutablePath") or "",
                    "ppid": int(d.get("ParentProcessId") or 0),
                    "user": "",
                    "created": 0,
                    "cmdline": (d.get("CommandLine") or "")[:1200],
                })
            except Exception:
                continue
    except Exception:
        rows = []
    if rows:
        return rows

    # 兜底：psutil
    if psutil is None:
        return rows
    for p in psutil.process_iter(["pid", "name", "exe", "ppid", "username", "create_time", "cmdline"]):
        info = p.info
        try:
            cmd = info.get("cmdline") or []
            if isinstance(cmd, str):
                cmd = [cmd]
            rows.append({
                "pid": int(info.get("pid") or 0),
                "name": info.get("name") or "",
                "exe": info.get("exe") or "",
                "ppid": int(info.get("ppid") or 0),
                "user": info.get("username") or "",
                "created": info.get("create_time") or 0,
                "cmdline": " ".join(str(x) for x in cmd)[:1200],
            })
        except Exception:
            continue
    return rows


def collect_connections(proc_names=None):
    """TCP/UDP 连接表。state 统一成 LISTEN/ESTABLISHED/... 字符串。"""
    if psutil is None:
        return []
    raw = _safe(lambda: psutil.net_connections(kind="inet"), [])
    names = proc_names or {}
    out = []
    for c in raw:
        try:
            laddr, raddr = c.laddr, c.raddr
            lip = getattr(laddr, "ip", "") if laddr else ""
            lport = int(getattr(laddr, "port", 0)) if laddr else 0
            rip = getattr(raddr, "ip", "") if raddr else ""
            rport = int(getattr(raddr, "port", 0)) if raddr else 0
            pid = int(c.pid or 0)
            out.append({
                "local_ip": lip, "local_port": lport,
                "remote_ip": rip, "remote_port": rport,
                "state": (c.status or "").upper(),
                "pid": pid,
                "process_name": names.get(pid, ""),
            })
        except Exception:
            continue
    return out


def collect_listens(conns):
    return [c for c in conns if c["state"] == "LISTEN"]


def collect_persist(force=False):
    """启动项（慢，带 TTL）。"""
    now = time.time()
    if not force and now - _LAST_PERSIST["t"] < PERSIST_TTL:
        return _LAST_PERSIST["items"]
    items = _safe(guardsrc.get_autostart, []) or []
    _LAST_PERSIST["t"] = now
    _LAST_PERSIST["items"] = items
    return items


def collect_posture(force=False):
    """主机防护姿态（慢，带 TTL）。"""
    now = time.time()
    if not force and now - _LAST_POSTURE["t"] < POSTURE_TTL and _LAST_POSTURE["data"]:
        return _LAST_POSTURE["data"]
    data = _safe(guardsrc.get_host_posture, {}) or {}
    _LAST_POSTURE["t"] = now
    _LAST_POSTURE["data"] = data
    return data


def collect(deep=False):
    """一整轮快照。deep=True 时强制刷新慢速项。"""
    errors = []
    procs = []
    conns = []
    try:
        procs = collect_processes()
    except Exception as e:
        errors.append("process: %s" % e)
    names = {p["pid"]: p["name"] for p in procs}
    # 父子关系：攻击方视角最值钱的字段。
    # Office/浏览器/资源管理器 拉起 powershell、rundll32 拉起 mshta —— 单看子进程都很正常，
    # 只有把父进程填上才能看出"谁生的谁"，所以这里一次性 O(n) 补齐，不额外调系统接口。
    by_pid = {}
    for p in procs:
        try:
            by_pid[p.get("pid")] = p
        except Exception:
            continue
    for p in procs:
        par = by_pid.get(p.get("ppid") or -1) or {}
        p["parent_name"] = par.get("name") or ""
        p["parent_exe"] = par.get("exe") or ""
        p["parent_cmdline"] = (par.get("cmdline") or "")[:400]
    try:
        conns = collect_connections(names)
    except Exception as e:
        errors.append("conn: %s" % e)
    snap = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "processes": procs,
        "conns": conns,
        "listens": collect_listens(conns),
        "persist": collect_persist(force=deep),
        "posture": collect_posture(force=deep),
        "errors": errors,
    }
    return snap


def host_metrics():
    """引擎自检用的轻量主机指标（CPU/内存/运行时长）。"""
    if psutil is None:
        return {}
    m = {}
    try:
        m["cpu_percent"] = psutil.cpu_percent(interval=None)
        m["mem_percent"] = psutil.virtual_memory().percent
        m["uptime_sec"] = int(time.time() - psutil.boot_time())
        m["proc_count"] = len(psutil.pids())
    except Exception:
        pass
    return m
