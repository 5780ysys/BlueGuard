# -*- coding: utf-8 -*-
"""OS 适配层：所有系统调用收口在此，业务层不得直接调 netsh/PowerShell。

设计文档 §1.3：`netsh` / PowerShell / `ip` / `nmcli` 只出现在 platform/，
业务层依赖 IfaceAdapter / FirewallAdapter / LogSourceAdapter 三个协议。

关键实测约束（评估报告 §3）：
  - netsh 输出随系统语言变化 -> 一律用 Get-Net* 的 JSON 输出，不用文本解析
  - 非管理员读不到 Security 日志 -> 显式返回 ELEVATION_REQUIRED
  - 非管理员改不了 IP -> 显式返回 ELEVATION_REQUIRED
"""
import collections
import json
import subprocess
import time
from typing import Protocol, Optional

PS = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command"]

# 本进程 spawn 出去的子进程 pid 台账。
# 用途：平台层用 powershell -EncodedCommand 采集，这些子进程的命令行天然就是
# "一条编码命令执行"，只看命令行会把它们当成攻击者。除了父进程判定之外，
# 再按 pid 精确剔除（父进程可能已退出，那时父信息查不到）。
_SPAWNED = collections.deque(maxlen=800)


def note_spawned(pid):
    """登记一个"本程序自己 spawn 的子进程"，供自噬防护使用。"""
    try:
        _SPAWNED.append(int(pid))
    except Exception:
        pass


def is_self_spawned(pid):
    try:
        return int(pid) in _SPAWNED
    except Exception:
        return False


def _ps(script: str, timeout: int = 30):
    """执行 PowerShell，强制 UTF-8 输出并返回解析后的 JSON。"""
    wrapper = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "$ProgressPreference='SilentlyContinue';"
        + script
    )
    _cf = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    _si = None
    try:
        _si = subprocess.STARTUPINFO()
        _si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        _si.wShowWindow = 0
    except Exception:
        pass
    p = subprocess.Popen(PS + [wrapper], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         creationflags=_cf, startupinfo=_si)
    note_spawned(p.pid)
    try:
        _out, _err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        _out, _err = p.communicate()
        return None, "timeout after %ss" % timeout, -1
    out = _out.decode("utf-8", "replace").strip()
    err = _err.decode("utf-8", "replace").strip()
    if not out:
        return None, err or "empty output", p.returncode
    try:
        return json.loads(out), err, p.returncode
    except Exception:
        return out, err, p.returncode


_ADMIN_CACHE = {"t": 0.0, "v": False, "info": {}}

# 完整性级别：只有 High(12288) / System(16384) 才能改防火墙、结束受保护进程。
# 只看 IsInRole(Administrator) 会误报——UAC 过滤后的令牌仍"属于"管理员组，
# 但实际写防火墙会拿到 Windows System Error 5 (Access is denied)。
HIGH_INTEGRITY = ("S-1-16-12288", "S-1-16-16384")
_LEVEL_LABEL = {"S-1-16-4096": "低", "S-1-16-8192": "中", "S-1-16-12288": "高", "S-1-16-16384": "系统"}


def _truthy(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def elevation_info(refresh: bool = False) -> dict:
    """当前进程的真实提权状态（含完整性级别），缓存 60 秒。

    坑：完整性标签不在 WindowsIdentity.Groups 集合里（那里只有组 SID），
    必须从 whoami /groups 的原始输出里抓 S-1-16-*，否则永远读不到级别。
    """
    now = time.time()
    if not refresh and _ADMIN_CACHE["info"] and now - _ADMIN_CACHE["t"] < 60:
        return _ADMIN_CACHE["info"]
    script = (
        "$raw = (whoami /groups) -join \"`n\";"
        "$integ = '';"
        "if ($raw -match 'S-1-16-(4096|8192|12288|16384)') { $integ = 'S-1-16-' + $matches[1] };"
        "$adminGroup = $false;"
        "if ($raw -match 'S-1-5-32-544') { $adminGroup = -not ($raw -match 'S-1-5-32-544[^\\n]*(deny|仅用于拒绝)') };"
        "$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name;"
        "[pscustomobject]@{in_admin_group=$adminGroup;integrity=$integ;user=$user}|ConvertTo-Json -Compress"
    )
    data, err, rc = _ps(script)
    info = {"in_admin_group": False, "integrity": "", "level": "", "user": "",
            "can_modify_system": False, "error": None}
    if isinstance(data, dict):
        info["in_admin_group"] = _truthy(data.get("in_admin_group"))
        info["integrity"] = str(data.get("integrity") or "")
        info["user"] = str(data.get("user") or "")
    else:
        info["error"] = err or "无法获取令牌信息"
    info["level"] = _LEVEL_LABEL.get(info["integrity"], info["integrity"] or "未知")
    info["can_modify_system"] = info["integrity"] in HIGH_INTEGRITY
    info["needs_elevation"] = not info["can_modify_system"]
    info["hint"] = ("" if info["can_modify_system"]
                    else "当前进程未提权（完整性级别=%s）：防护引擎可正常检测与告警，"
                         "但阻断/结束进程会被拒绝。请右键『以管理员身份运行』启动本程序。"
                         % (info["level"],))
    _ADMIN_CACHE["info"] = info
    _ADMIN_CACHE["v"] = info["can_modify_system"]
    _ADMIN_CACHE["t"] = now
    return info


def is_admin() -> bool:
    """是否具备改系统状态的真实权限（管理员组 + 高完整性级别）。"""
    return bool(elevation_info().get("can_modify_system"))


# ============ 网卡适配器 ============
class IfaceAdapter(Protocol):
    def list_ifaces(self) -> list: ...
    def get_iface_state(self, name: str) -> dict: ...


class WindowsIface:
    _CACHE = {"t": 0.0, "v": None}

    def list_ifaces(self) -> list:
        """枚举网卡要起 PowerShell + CIM 查询（约 3 秒），缓存 5 秒。"""
        _now = time.time()
        if self._CACHE["v"] is not None and _now - self._CACHE["t"] < 5:
            return self._CACHE["v"]
        script = (
            "$a = Get-NetAdapter | Select-Object Name,InterfaceIndex,Status,MacAddress,"
            "InterfaceDescription,LinkSpeed;"
            "$ips = Get-NetIPAddress -AddressFamily IPv4 | "
            "Select-Object InterfaceAlias,IPAddress,PrefixLength,PrefixOrigin;"
            "$gw = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object InterfaceAlias,NextHop;"
            "[pscustomobject]@{adapters=$a;ips=$ips;gateways=$gw} | ConvertTo-Json -Depth 5 -Compress"
        )
        data, err, rc = _ps(script)
        if not isinstance(data, dict):
            raise RuntimeError("枚举网卡失败: %s" % err)
        adapters = data.get("adapters") or []
        if isinstance(adapters, dict):
            adapters = [adapters]
        ips = data.get("ips") or []
        if isinstance(ips, dict):
            ips = [ips]
        gws = data.get("gateways") or []
        if isinstance(gws, dict):
            gws = [gws]

        gw_map = {}
        for g in gws:
            gw_map.setdefault(g.get("InterfaceAlias"), g.get("NextHop"))

        result = []
        for a in adapters:
            name = a.get("Name")
            my_ips = [i for i in ips if i.get("InterfaceAlias") == name]
            result.append({
                "name": name,
                "index": a.get("InterfaceIndex"),
                "status": a.get("Status"),
                "mac": a.get("MacAddress"),
                "description": a.get("InterfaceDescription"),
                "link_speed": a.get("LinkSpeed"),
                "ipv4": [{
                    "ip": i.get("IPAddress"),
                    "prefix": i.get("PrefixLength"),
                    "origin": i.get("PrefixOrigin"),
                } for i in my_ips],
                "gateway": gw_map.get(name),
                # PrefixOrigin 在不同系统上可能是字符串或数字枚举，统一转字符串判断
                "dhcp": any(str(i.get("PrefixOrigin") or "").lower() in ("dhcp", "3") for i in my_ips),
                # 有默认网关且状态 Up 的视为主要上网网卡
                "is_default_route": bool(gw_map.get(name)),
            })
        result.sort(key=lambda x: (not x["is_default_route"], x["status"] != "Up", x["name"]))
        self._CACHE["v"] = result
        self._CACHE["t"] = time.time()
        return result

    def get_iface_state(self, name: str) -> dict:
        for a in self.list_ifaces():
            if a["name"] == name:
                return a
        return {}


# ============ 防火墙适配器 ============
class FirewallAdapter(Protocol):
    def list_rules(self, ip: str) -> list: ...
    def block_ip(self, ip: str, note: str = "") -> dict: ...
    def unblock_ip(self, ip: str) -> dict: ...


class WindowsFirewall:
    RULE_PREFIX = "BlueGuard-Block-"

    def list_rules(self, ip: str = "") -> list:
        name = self.RULE_PREFIX + (ip or "")
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "Get-NetFirewallRule -DisplayName '%s*' | "
            "Select-Object DisplayName,Enabled,Direction,Action,"
            "@{n='RemoteAddress';e={(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress}} | "
            "ConvertTo-Json -Depth 4 -Compress" % name
        )
        data, err, rc = _ps(script)
        if not data:
            return []
        if isinstance(data, dict):
            data = [data]
        return data

    def is_blocked(self, ip: str) -> bool:
        rules = self.list_rules(ip)
        for r in rules:
            if r.get("DisplayName") == self.RULE_PREFIX + ip and str(r.get("Enabled", "")).lower() in ("true", "1"):
                return True
        return False

    def block_ip(self, ip: str, note: str = "") -> dict:
        if not is_admin():
            return {"ok": False, "error": "ELEVATION_REQUIRED", "ip": ip}
        name = self.RULE_PREFIX + ip
        script = (
            "Remove-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue;"
            "New-NetFirewallRule -DisplayName '%s' -Direction Inbound -Action Block "
            "-RemoteAddress '%s' -Protocol Any -Description 'BlueGuard %s' | "
            "Select-Object DisplayName,Enabled,Direction,Action | ConvertTo-Json -Compress"
        ) % (name, name, ip, note.replace("'", " "))
        data, err, rc = _ps(script)
        ok = self.is_blocked(ip)
        return {"ok": ok, "ip": ip, "rule": data, "error": None if ok else (err or "规则未生效")}

    def unblock_ip(self, ip: str) -> dict:
        if not is_admin():
            return {"ok": False, "error": "ELEVATION_REQUIRED", "ip": ip}
        name = self.RULE_PREFIX + ip
        script = "Remove-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue; 'done'" % name
        _ps(script)
        still = self.is_blocked(ip)
        return {"ok": not still, "ip": ip, "error": None if not still else "规则未移除"}

    # ---------- V3.0：程序出站阻断 / 端口阻断 ----------
    PROG_PREFIX = "BlueGuard-Prog-"
    PORT_PREFIX = "BlueGuard-Port-"

    @classmethod
    def prog_rule_name(cls, path: str) -> str:
        import hashlib
        h = hashlib.sha1((path or "").lower().encode("utf-8", "ignore")).hexdigest()[:12]
        return cls.PROG_PREFIX + h

    @classmethod
    def port_rule_name(cls, port: int, direction: str = "Inbound") -> str:
        return "%s%s-%s" % (cls.PORT_PREFIX, direction, int(port))

    def is_program_blocked(self, path: str) -> bool:
        name = self.prog_rule_name(path)
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "Get-NetFirewallRule -DisplayName '%s' | "
            "Select-Object DisplayName,Enabled,Direction,Action | ConvertTo-Json -Depth 3 -Compress" % name
        )
        data, err, rc = _ps(script)
        if not data:
            return False
        if isinstance(data, dict):
            data = [data]
        return any(str(r.get("Enabled", "")).lower() in ("true", "1") for r in data)

    def block_program(self, path: str, note: str = "") -> dict:
        """阻断某个 exe 的全部出站连接（比结束进程温和，可回滚）。"""
        if not is_admin():
            return {"ok": False, "error": "ELEVATION_REQUIRED", "target": path}
        import os as _os
        if not path or not _os.path.isfile(path):
            return {"ok": False, "error": "路径不存在或不可执行: %s" % path, "target": path}
        name = self.prog_rule_name(path)
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "Remove-NetFirewallRule -DisplayName '%s';"
            "New-NetFirewallRule -DisplayName '%s' -Direction Outbound -Action Block "
            "-Program '%s' -Protocol Any -Description 'BlueGuard %s'" % (
                name, name, path.replace("'", "''"), (note or "guard").replace("'", " "))
        )
        _ps(script)
        ok = self.is_program_blocked(path)
        return {"ok": ok, "target": path, "rule": name,
                "error": None if ok else "出站规则未生效"}

    def unblock_program(self, path: str) -> dict:
        if not is_admin():
            return {"ok": False, "error": "ELEVATION_REQUIRED", "target": path}
        name = self.prog_rule_name(path)
        _ps("$ErrorActionPreference='SilentlyContinue'; Remove-NetFirewallRule -DisplayName '%s'; 'done'" % name)
        still = self.is_program_blocked(path)
        return {"ok": not still, "target": path, "error": None if not still else "规则未移除"}

    def block_port(self, port: int, direction: str = "Inbound", note: str = "") -> dict:
        """封禁本机某端口（入站默认）。"""
        if not is_admin():
            return {"ok": False, "error": "ELEVATION_REQUIRED", "port": port}
        direction = "Outbound" if str(direction).lower().startswith("out") else "Inbound"
        name = self.port_rule_name(port, direction)
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "Remove-NetFirewallRule -DisplayName '%s';"
            "New-NetFirewallRule -DisplayName '%s' -Direction %s -Action Block "
            "-Protocol TCP -LocalPort %d -Description 'BlueGuard %s'" % (
                name, name, direction, int(port), (note or "guard").replace("'", " "))
        )
        data, err, rc = _ps(script)
        script2 = ("$ErrorActionPreference='SilentlyContinue';"
                   "Get-NetFirewallRule -DisplayName '%s' | Select-Object DisplayName,Enabled | "
                   "ConvertTo-Json -Compress" % name)
        chk, _e, _r = _ps(script2)
        ok = bool(chk)
        return {"ok": ok, "port": int(port), "direction": direction, "rule": name,
                "error": None if ok else (err or "端口规则未生效")}

    def unblock_port(self, port: int, direction: str = "Inbound") -> dict:
        if not is_admin():
            return {"ok": False, "error": "ELEVATION_REQUIRED", "port": port}
        direction = "Outbound" if str(direction).lower().startswith("out") else "Inbound"
        name = self.port_rule_name(port, direction)
        _ps("$ErrorActionPreference='SilentlyContinue'; Remove-NetFirewallRule -DisplayName '%s'; 'done'" % name)
        return {"ok": True, "port": int(port), "direction": direction}

    def list_guard_rules(self) -> list:
        """列出所有 BlueGuard 创建的规则，用于对账/一键回滚。"""
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "Get-NetFirewallRule -DisplayName 'BlueGuard-*' | "
            "Select-Object DisplayName,Enabled,Direction,Action,Description | "
            "ConvertTo-Json -Depth 3 -Compress"
        )
        data, err, rc = _ps(script)
        if not data:
            return []
        if isinstance(data, dict):
            data = [data]
        return data

    def remove_rule_by_name(self, name: str) -> dict:
        """按显示名精确删除一条防火墙规则（对账清理用）。"""
        if not is_admin():
            return {"ok": False, "error": "ELEVATION_REQUIRED", "name": name}
        safe = (name or "").replace("'", "''")
        if not safe.startswith("BlueGuard-"):
            return {"ok": False, "error": "只允许删除 BlueGuard- 前缀规则", "name": name}
        _ps("$ErrorActionPreference='SilentlyContinue'; Remove-NetFirewallRule -DisplayName '%s'; 'done'" % safe)
        left = [r for r in self.list_guard_rules() if r.get("DisplayName") == name]
        return {"ok": not left, "name": name}


# ============ 日志源适配器 ============
class LogSourceAdapter(Protocol):
    def read_events(self, log_name: str, max_events: int) -> list: ...


class WindowsEventLog:
    _AVAIL_CACHE = {"t": 0.0, "v": None}

    def available(self) -> dict:
        """三个日志可用性探测各起一次 PowerShell（合计约 2.4 秒），缓存 60 秒。"""
        now = time.time()
        if self._AVAIL_CACHE["v"] is not None and now - self._AVAIL_CACHE["t"] < 60:
            return self._AVAIL_CACHE["v"]
        value = {
            "admin": is_admin(),
            "security_readable": self._can_read("Security"),
            "system_readable": self._can_read("System"),
            "application_readable": self._can_read("Application"),
        }
        self._AVAIL_CACHE["v"] = value
        self._AVAIL_CACHE["t"] = now
        return value

    def _can_read(self, log_name: str) -> bool:
        script = (
            "$ErrorActionPreference='Stop';"
            "try{ Get-WinEvent -LogName '%s' -MaxEvents 1 | Out-Null; 'yes' }catch{ 'no' }" % log_name
        )
        res, err, rc = _ps(script, timeout=20)
        return str(res).strip().lower().endswith("yes")

    def read_events(self, log_name: str, max_events: int = 50) -> list:
        if not self._can_read(log_name):
            raise PermissionError("ELEVATION_REQUIRED: 无法读取 %s 日志（需管理员）" % log_name)
        script = (
            "Get-WinEvent -LogName '%s' -MaxEvents %d -ErrorAction Stop | "
            "Select-Object Id,LevelDisplayName,TimeCreated,ProviderName,"
            "@{n='Message';e={($_.Message -replace '\\s+',' ').Substring(0,[Math]::Min(300,$_.Message.Length))}} | "
            "ConvertTo-Json -Depth 4 -Compress"
        ) % (log_name, max(1, min(int(max_events), 500)))
        data, err, rc = _ps(script, timeout=45)
        if data is None:
            raise RuntimeError(err or "读取事件日志失败")
        if isinstance(data, dict):
            data = [data]
        out = []
        for e in data:
            out.append({
                "event_id": e.get("Id"),
                "level": e.get("LevelDisplayName"),
                "time": e.get("TimeCreated"),
                "provider": e.get("ProviderName"),
                "message": e.get("Message"),
            })
        return out


# ============ 网卡变更执行器 ============
class WindowsNetConfig:
    """真正的改 IP 执行器。必须管理员。"""

    def apply(self, iface: str, ip: str, prefix: int, gateway: Optional[str],
              dns: Optional[str], dhcp: bool) -> dict:
        if not is_admin():
            return {"ok": False, "error": "ELEVATION_REQUIRED"}
        try:
            if dhcp:
                script = (
                    "Set-NetIPInterface -InterfaceAlias '%s' -Dhcp Enabled -ErrorAction Stop;"
                    "Set-DnsClientServerAddress -InterfaceAlias '%s' -ResetServerAddresses "
                    "-ErrorAction SilentlyContinue; 'ok'" % (iface, iface)
                )
            else:
                parts = [
                    "-InterfaceAlias '%s'" % iface,
                    "-IPAddress '%s'" % ip,
                    "-PrefixLength %d" % int(prefix),
                ]
                if gateway:
                    parts.append("-DefaultGateway '%s'" % gateway)
                # 静态配置前先关 DHCP，并清理旧地址/路由，避免 DHCP/残留配置导致新 IP 不落地或验证读到旧地址
                pre = (
                    "Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 -Dhcp Disabled "
                    "-ErrorAction SilentlyContinue;" % iface
                )
                pre += (
                    "Get-NetIPAddress -InterfaceAlias '%s' -AddressFamily IPv4 "
                    "-ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false "
                    "-ErrorAction SilentlyContinue;" % iface
                )
                pre += (
                    "Get-NetRoute -InterfaceAlias '%s' -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
                    "-ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false "
                    "-ErrorAction SilentlyContinue;" % iface
                )
                script = (
                    pre
                    + "New-NetIPAddress " + " ".join(parts) + " -ErrorAction Stop | Out-Null;"
                )
                if dns:
                    script += ("Set-DnsClientServerAddress -InterfaceAlias '%s' "
                               "-ServerAddresses '%s' -ErrorAction SilentlyContinue;" % (iface, dns))
                else:
                    script += ("Set-DnsClientServerAddress -InterfaceAlias '%s' "
                               "-ResetServerAddresses -ErrorAction SilentlyContinue;" % iface)
                script += "'ok'"
            res, err, rc = _ps(script, timeout=45)
            if str(res).strip().lower().endswith("ok"):
                return {"ok": True, "error": None}
            return {"ok": False, "error": err or "执行失败"}
        except Exception as e:
            return {"ok": False, "error": str(e)}


# ============ 实时连接监控 ============
def get_tcp_connections():
    """获取当前 TCP 连接表（含进程名），用于外部IP监控。"""
    script = (
        "$map=@{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $map[$_.Id] = $_.ProcessName }; "
        "Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | "
        "ForEach-Object { [pscustomobject]@{local_ip=$_.LocalAddress;local_port=$_.LocalPort;remote_ip=$_.RemoteAddress;remote_port=$_.RemotePort;state=if($_.State){$_.State.ToString()}else{''};pid=$_.OwningProcess;process_name=$map[$_.OwningProcess]} } | "
        "ConvertTo-Json -Depth 3 -Compress"
    )
    data, err, rc = _ps(script, timeout=20)
    if data is None:
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    return data


# ============ 防护引擎用：启动项 / 主机姿态 / DNS 归因 ============
class WindowsGuardSource:
    """V3.0 防护引擎的系统侧采集（持久化点、主机安全姿态、域名归因）。

    全部走 PowerShell + JSON，不解析本地化文本（与 §1.3 的收口原则一致）。
    """

    def get_autostart(self) -> list:
        """注册表 Run/RunOnce + 启动文件夹 + 计划任务（只取非 Microsoft 的计划任务）。"""
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$out=@();"
            "$keys=@("
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',"
            "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',"
            "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',"
            "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce');"
            "foreach($k in $keys){ if(Test-Path $k){ $p=Get-ItemProperty $k; "
            "$p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { "
            "$out += [pscustomobject]@{kind='registry';location=$k;name=$_.Name;value=[string]$_.Value} } } };"
            "foreach($d in @(\"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\","
            "\"$env:ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\")){ "
            "if(Test-Path $d){ Get-ChildItem $d -File | ForEach-Object { "
            "$out += [pscustomobject]@{kind='startup_folder';location=$d;name=$_.Name;value=$_.FullName} } } };"
            "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled' } | "
            "ForEach-Object { $out += [pscustomobject]@{kind='scheduled_task';location=$_.TaskPath;name=$_.TaskName;value=$_.TaskPath+$_.TaskName} };"
            "$out | ConvertTo-Json -Depth 3 -Compress"
        )
        data, err, rc = _ps(script, timeout=45)
        if data is None:
            return []
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return []
        return data

    def get_host_posture(self) -> dict:
        """本机安全姿态：防火墙三档 / Defender 实时保护 / SMBv1 / 远程桌面。"""
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "$f=Get-NetFirewallProfile | Select-Object Name,Enabled;"
            "$d=Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled;"
            "$s=(Get-SmbServerConfiguration).EnableSMB1Protocol;"
            "$rdp=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections;"
            "[pscustomobject]@{firewall=$f;defender=$d;smb1=$s;rdp_deny=$rdp} | ConvertTo-Json -Depth 4 -Compress"
        )
        data, err, rc = _ps(script, timeout=40)
        if not isinstance(data, dict):
            return {"error": err or "posture unavailable"}
        fw = data.get("firewall") or []
        if isinstance(fw, dict):
            fw = [fw]
        d = data.get("defender") or {}
        if isinstance(d, list):
            d = d[0] if d else {}
        return {
            "firewall_profiles": [{"name": x.get("Name"), "enabled": bool(x.get("Enabled"))} for x in fw],
            "firewall_all_on": bool(fw) and all(bool(x.get("Enabled")) for x in fw),
            "defender_realtime": bool(d.get("RealTimeProtectionEnabled")),
            "defender_enabled": bool(d.get("AntivirusEnabled")),
            "smb1": bool(data.get("smb1")),
            "rdp_deny": str(data.get("rdp_deny")),
        }

    def get_dns_cache(self, limit: int = 400) -> list:
        """本机 DNS 客户端缓存 -> IP/域名归因（离线，不外发请求）。"""
        script = (
            "$ErrorActionPreference='SilentlyContinue';"
            "Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry } | "
            "Select-Object -First %d Entry,Data,Type | ConvertTo-Json -Depth 3 -Compress" % max(1, min(int(limit), 2000))
        )
        data, err, rc = _ps(script, timeout=30)
        if data is None:
            return []
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return []
        return [{"name": x.get("Entry"), "data": x.get("Data"), "type": x.get("Type")} for x in data]


# 单例
iface = WindowsIface()
firewall = WindowsFirewall()
events = WindowsEventLog()
netcfg = WindowsNetConfig()
guardsrc = WindowsGuardSource()

# ============ 实时连接监控 ============
def get_tcp_connections():
    """获取当前 TCP 连接表（含进程名），用于外部IP监控。"""
    script = (
        "$map=@{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $map[$_.Id] = $_.ProcessName }; "
        "Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | "
        "ForEach-Object { [pscustomobject]@{local_ip=$_.LocalAddress;local_port=$_.LocalPort;remote_ip=$_.RemoteAddress;remote_port=$_.RemotePort;state=if($_.State){$_.State.ToString()}else{''};pid=$_.OwningProcess;process_name=$map[$_.OwningProcess]} } | "
        "ConvertTo-Json -Depth 3 -Compress"
    )
    data, err, rc = _ps(script, timeout=20)
    if data is None:
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    return data

