# -*- coding: utf-8 -*-
"""防护策略与可信名单。

两条不可绕过的红线（否则所谓“防护软件”会先把自己的机器打死）：
  1. 自保护：BlueGuard 自身进程/路径/服务永远不在阻断或结束的候选里；
  2. 系统关键进程：lsass/csrss/services 等一旦被封或被杀，机器直接蓝屏或断网。
"""
import json
import os
import re
import sys
import time

from ..db import connect, tx

DEFAULT_MODE = "monitor"          # monitor | alert | block
VALID_MODES = ("monitor", "alert", "block")

# ---------- 系统关键进程（永不结束、永不按程序阻断） ----------
PROTECTED_PROCESS_NAMES = {
    "system", "system idle process", "idle", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe",
    "explorer.exe", "dwm.exe", "fontdrvhost.exe", "spoolsv.exe", "sihost.exe",
    "audiodg.exe", "conhost.exe", "ctfmon.exe", "taskhostw.exe", "runtimebroker.exe",
    "searchindexer.exe", "securityhealthservice.exe", "msmpeng.exe", "mpdefendercoreservice.exe",
    "wuauserv", "trustedinstaller.exe", "msiexec.exe", "wininit", "registry",
    "nissrv.exe", "wmiprvse.exe", "dllhost.exe", "logonui.exe", "useroinit.exe",
}

# ---------- 默认可信进程（可告警，但默认不主动阻断/结束） ----------
DEFAULT_WHITELIST = [
    ("process", "svchost.exe", "系统服务宿主"),
    ("process", "explorer.exe", "桌面外壳"),
    ("process", "chrome.exe", "主流浏览器"),
    ("process", "msedge.exe", "主流浏览器"),
    ("process", "firefox.exe", "主流浏览器"),
    ("process", "Code.exe", "开发编辑器"),
    ("process", "python.exe", "运行时（本平台依赖）"),
    ("process", "WeChat.exe", "即时通讯"),
    ("process", "QQ.exe", "即时通讯"),
    ("process", "DingTalk.exe", "即时通讯"),
    ("process", "svchost", "系统服务宿主"),
    ("ip", "127.0.0.1", "回环"),
    ("port", "53", "DNS"),
    ("port", "80", "HTTP"),
    ("port", "443", "HTTPS"),
]

# 常见端口：新监听端口不在其中时按“非常规监听”提示
COMMON_LISTEN_PORTS = {
    53, 80, 135, 139, 443, 445, 5353, 5355, 7680, 8000, 8080, 8443, 9000, 9418,
    17500, 3306, 5432, 6379, 27017, 49152, 49664, 49665, 49666, 49667, 49668,
}

_CACHE = {"t": 0.0, "policy": None, "wl": None}


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def self_paths():
    """BlueGuard 自身的可执行文件集合（真实路径 + 打包后的 exe）。"""
    out = set()
    try:
        out.add(os.path.abspath(sys.executable).lower())
    except Exception:
        pass
    try:
        out.add(os.path.abspath(sys.argv[0]).lower())
    except Exception:
        pass
    try:
        import __main__  # noqa: F401
        main_file = getattr(sys.modules.get("__main__"), "__file__", None)
        if main_file:
            out.add(os.path.abspath(main_file).lower())
    except Exception:
        pass
    return out


def is_self_process(pid=None, name=None, path=None):
    """判断目标是否就是 BlueGuard 自己（进程号 / 名称 / 路径三重判定）。"""
    if pid and int(pid) == os.getpid():
        return True
    n = (name or "").lower()
    if n in ("blueguard.exe", "blueguard", "packed_launcher.exe"):
        return True
    p = (path or "").lower()
    for sp in self_paths():
        if p and sp and (p == sp or os.path.basename(p) == os.path.basename(sp)):
            return True
    if p and ("blueguard" in p or "bluerguard" in p):
        return True
    return False


def is_protected_process(name=None, path=None, pid=None):
    if is_self_process(pid=pid, name=name, path=path):
        return True
    n = (name or "").lower()
    if n in PROTECTED_PROCESS_NAMES:
        return True
    p = (path or "").lower()
    if p.endswith("\\windows\\system32\\lsass.exe") or p.endswith("\\windows\\system32\\csrss.exe"):
        return True
    return False


def ensure_seed(conn=None):
    """默认策略行 + 默认白名单。幂等。"""
    with tx() as c:
        c.execute("INSERT OR IGNORE INTO guard_policy(id) VALUES(1)")
        for kind, value, note in DEFAULT_WHITELIST:
            c.execute("INSERT OR IGNORE INTO guard_whitelist(kind,value,note,source) VALUES (?,?,?,'default')",
                      (kind, value, note))


def get_policy(refresh=False):
    """返回策略字典（带 5 秒缓存，避免每轮都查库）。"""
    now = time.time()
    if not refresh and _CACHE["policy"] and now - _CACHE["t"] < 5:
        return _CACHE["policy"]
    conn = connect()
    ensure_seed(conn)
    row = conn.execute("SELECT * FROM guard_policy WHERE id=1").fetchone()
    p = dict(row) if row else {"mode": DEFAULT_MODE, "interval_sec": 8}
    try:
        p["probes"] = json.loads(p.get("probes") or "{}")
    except Exception:
        p["probes"] = {}
    _CACHE["policy"] = p
    _CACHE["t"] = now
    return p


def update_policy(patch):
    """更新策略；只接受已知字段，mode 非法直接拒绝。"""
    fields = ("mode", "autostart", "interval_sec", "score_threshold", "max_actions_per_min",
              "auto_incident", "auto_notify", "auto_block_ip", "auto_block_program",
              "auto_kill_process", "expire_minutes", "probes",
              "retention_days", "archive_enabled")
    sets, args = [], []
    for k in fields:
        if k not in patch:
            continue
        v = patch[k]
        if k == "mode":
            if v not in VALID_MODES:
                raise ValueError("非法模式: %s（只允许 monitor/alert/block）" % v)
        if k in ("interval_sec",):
            v = max(3, min(120, int(v)))
        if k == "max_actions_per_min":
            v = max(1, min(120, int(v)))
        if k == "score_threshold":
            v = max(1, min(200, int(v)))
        if k == "expire_minutes":
            v = max(1, min(1440, int(v)))
        if k == "retention_days":
            v = max(7, min(3650, int(v)))
        if k == "archive_enabled":
            v = 1 if v else 0
        if k == "probes" and not isinstance(v, str):
            v = json.dumps(v, ensure_ascii=False)
        sets.append("%s=?" % k)
        args.append(v)
    if not sets:
        return {"ok": True, "changed": 0}
    with tx() as c:
        c.execute("UPDATE guard_policy SET %s, updated_at=? WHERE id=1" % ",".join(sets),
                  args + [_now()])
    get_policy(refresh=True)
    return {"ok": True, "changed": len(sets)}


def whitelist_set(refresh=False):
    now = time.time()
    if not refresh and _CACHE["wl"] is not None and now - _CACHE["t"] < 5:
        return _CACHE["wl"]
    conn = connect()
    rows = conn.execute("SELECT kind,value FROM guard_whitelist WHERE enabled=1").fetchall()
    wl = {}
    for r in rows:
        wl.setdefault(r["kind"], set()).add((r["value"] or "").lower())
    _CACHE["wl"] = wl
    return wl


def is_whitelisted(kind, value):
    v = (value or "").lower()
    if not v:
        return False
    s = whitelist_set().get(kind) or set()
    if v in s:
        return True
    # IP 类支持网段：白名单里写 192.168.0.0/24 就整段放行
    if kind == "ip":
        import ipaddress
        try:
            a = ipaddress.ip_address(v.split("%")[0])
        except Exception:
            a = None
        if a is not None:
            for item in s:
                if "/" not in item:
                    continue
                try:
                    if a in ipaddress.ip_network(item, strict=False):
                        return True
                except Exception:
                    continue
    # 域名类支持通配：*.corp.local
    if kind == "domain":
        for item in s:
            if item.startswith("*.") and v.endswith(item[1:]):
                return True
    # 路径类：按 basename 也认一次（同一程序不同安装目录）
    if "\\" in v:
        base = v.rsplit("\\", 1)[-1]
        if base in s:
            return True
    return False


# 内网/保留段：只有这些地址不参与自动封锁（封了也没意义，还容易把自己网络切了）。
# 注意不能用 ipaddress.is_private —— Python 把 198.51.100.0/24 这类文档保留段也算 private，
# 会让自测样本与真实公网样本一起被误判为内网。
_INTERNAL_NETS = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "0.0.0.0/32", "255.255.255.255/32",
    "::1/128", "fc00::/7", "fe80::/10",
]


def is_internal_ip(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(str(ip).split("%")[0])
    except Exception:
        return True
    for net in _INTERNAL_NETS:
        try:
            if a in ipaddress.ip_network(net, strict=False):
                return True
        except Exception:
            continue
    return False


def invalidate():
    """白名单/策略变更后清缓存。"""
    _CACHE["t"] = 0.0
    _CACHE["policy"] = None
    _CACHE["wl"] = None
