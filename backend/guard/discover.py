"""资产自动发现：把本机真实信息灌进 assets / asset_ips / asset_services。

资产台账原本只能一条条手录，录完也没人维护，等于一张空表 —— 运营那半段的
第一环就断在这里。这个模块把网卡、监听端口、系统信息一次采出来，按 IP 幂等
写入：重复发现只更新，不新增，也不覆盖你手工改过的字段（重要性、责任人）。

只用 Python 内置 + 已有的 platform_win / probes，不额外起进程。
"""
from __future__ import annotations

import socket
import platform as _platform

from ..db import tx
from .. import audit
from ..platform_win import iface as _iface
from . import probes

# 常见端口 -> 服务名。只用来给资产端口打标签，不参与判定。
PORT_SERVICE = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "rpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 1433: "mssql", 1521: "oracle", 2181: "zookeeper", 2375: "docker",
    2376: "docker-tls", 3000: "dev-server", 3306: "mysql", 3389: "rdp",
    5000: "dev-server", 5432: "postgres", 5900: "vnc", 5985: "winrm",
    5986: "winrm-tls", 6379: "redis", 6443: "k8s-api", 8000: "http-alt",
    8080: "http-alt", 8081: "http-alt", 8888: "http-alt", 9000: "http-alt",
    9090: "prometheus", 9200: "elasticsearch", 9418: "git", 10250: "kubelet",
    11211: "memcached", 27017: "mongodb",
}


def host_facts() -> dict:
    """本机身份：主机名、系统、架构。不起任何子进程。"""
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown-host"
    try:
        fqdn = socket.getfqdn()
    except Exception:
        fqdn = hostname
    os_name = "%s %s" % (_platform.system(), _platform.release())
    return {
        "hostname": hostname,
        "fqdn": fqdn,
        "os": os_name.strip(),
        "os_version": _platform.version(),
        "arch": _platform.machine(),
    }


def _collect_ips():
    """启用的网卡上的 IPv4（排除回环）。"""
    try:
        ifaces = _iface.list_ifaces()
    except Exception:
        ifaces = []
    out = []
    for a in ifaces or []:
        if (a.get("status") or "").lower() != "up":
            continue
        for v in a.get("ipv4") or []:
            ip = (v.get("ip") or "").strip()
            if not ip or ip.startswith("127.") or ip == "0.0.0.0":
                continue
            out.append({
                "ip": ip,
                "mac": a.get("mac"),
                "iface": a.get("name"),
                "prefix": v.get("prefix"),
                "dhcp": bool(a.get("dhcp")),
                "speed": a.get("link_speed"),
                "primary": 1 if a.get("is_default_route") else 0,
            })
    return out


def _collect_services():
    """监听端口 + 监听进程 + 绑定地址。"""
    procs = probes.collect_processes()
    names = {p.get("pid"): p.get("name") for p in procs}
    conns = probes.collect_connections(names)
    agg = {}
    for c in probes.collect_listens(conns):
        port = int(c.get("local_port") or 0)
        if not port:
            continue
        proc = str(c.get("process_name") or "")
        # psutil 拿不到 owner 时会回落到 System Idle Process，配合 49152 以上的
        # 动态端口就是一堆临时端口噪音（实测一台机器能刷 8 条），对资产没有意义。
        if port >= 49152 and proc in ("", "System Idle Process"):
            continue
        item = agg.setdefault(port, {"port": port, "process": "", "binds": set()})
        if proc and proc != "System Idle Process" and not item["process"]:
            item["process"] = proc
        binds = str(c.get("local_ip") or "").strip()
        if binds:
            item["binds"].add(binds)
    out = []
    for port, v in sorted(agg.items()):
        out.append({
            "port": port,
            "process": v["process"],
            "binds": ",".join(sorted(v["binds"]))[:200],
        })
    return out


def discover(user: str = "auto:discover") -> dict:
    """发现本机并写库。幂等：同 IP 只更新，同主机名只复用一个资产。"""
    facts = host_facts()
    ips = _collect_ips()
    services = _collect_services()

    created = False
    new_ips = 0
    upd_ips = 0
    new_svc = 0
    asset_id = None

    with tx() as c:
        row = c.execute("SELECT id FROM assets WHERE name=?", (facts["hostname"],)).fetchone()
        if row:
            asset_id = row["id"]
            c.execute(
                "UPDATE assets SET os=?, updated_at=datetime('now','localtime') WHERE id=?",
                (facts["os"], asset_id),
            )
        else:
            cur = c.execute(
                "INSERT INTO assets(name,asset_type,os,owner,importance,authz_confirmed,tags,remark)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (facts["hostname"], "host", facts["os"], None, 3, 0,
                 '["自动发现","本机"]', "由「自动发现本机」写入，随扫描更新 IP 与端口"),
            )
            asset_id = cur.lastrowid
            created = True

        for x in ips:
            # asset_ips.ip 全局唯一：同一个 IP 不可能属于两台机器
            hit = c.execute("SELECT id FROM asset_ips WHERE ip=?", (x["ip"],)).fetchone()
            if hit:
                c.execute("UPDATE asset_ips SET mac=COALESCE(?, mac), asset_id=? WHERE ip=?",
                          (x["mac"], asset_id, x["ip"]))
                upd_ips += 1
            else:
                c.execute(
                    "INSERT INTO asset_ips(asset_id,ip,mac,is_primary) VALUES (?,?,?,?)",
                    (asset_id, x["ip"], x["mac"], x["primary"]),
                )
                new_ips += 1

        have = {r["port"] for r in c.execute(
            "SELECT port FROM asset_services WHERE asset_id=? AND protocol='tcp'", (asset_id,))}
        # 本次没监听到的端口要清掉，否则台账只会越积越多，
        # 三个月后你看到的是一个早就不存在的端口清单。
        if services:
            keep = [s["port"] for s in services]
            ph = ",".join("?" * len(keep))
            c.execute(
                "DELETE FROM asset_services WHERE asset_id=? AND protocol='tcp' AND port NOT IN (%s)" % ph,
                [asset_id] + keep,
            )
        for s in services:
            if s["port"] in have:
                c.execute(
                    "UPDATE asset_services SET service=COALESCE(NULLIF(service,''),?),"
                    " banner=? WHERE asset_id=? AND port=? AND protocol='tcp'",
                    (PORT_SERVICE.get(s["port"]), ("%s @ %s" % (s["process"], s["binds"])).strip()[:200],
                     asset_id, s["port"]),
                )
                continue
            c.execute(
                "INSERT INTO asset_services(asset_id,port,protocol,service,banner) VALUES (?,?,?,?,?)",
                (asset_id, s["port"], "tcp", PORT_SERVICE.get(s["port"]),
                 ("%s @ %s" % (s["process"], s["binds"])).strip()[:200]),
            )
            new_svc += 1

        audit.append(c, user, "asset.discover", "asset", asset_id, None, {
            "hostname": facts["hostname"], "ips": len(ips),
            "services": len(services), "created": created,
        })

    return {
        "ok": True,
        "asset_id": asset_id,
        "created": created,
        "hostname": facts["hostname"],
        "os": facts["os"],
        "ips": ips,
        "ip_new": new_ips,
        "ip_updated": upd_ips,
        "services": services,
        "service_new": new_svc,
        "summary": "%s 已有 %d 个 IP、%d 个监听端口" % (facts["hostname"], len(ips), len(services)),
    }
