# -*- coding: utf-8 -*-
"""检测规则：条件 DSL + 内置 Sigma 化规则集。

DSL 形如：
    {"all":[{"field":"process.name","op":"in","value":["powershell.exe"]},
            {"any":[{"field":"process.cmdline","op":"contains","value":"-enc"}]}]}

支持 all / any / not 任意嵌套，叶子为 {field, op, value}。
op: eq ne contains startswith endswith regex in not_in gt lt exists

规则对“一个对象”求值（对象来自 probes 快照），返回一张事件卡。
所有内置规则都可以在界面上停用/改严重度/改动作，不写死在代码里。
"""
import json
import re

from . import policy

SEV_SCORE = {"critical": 90, "high": 70, "medium": 45, "low": 20}
SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CATEGORIES = ("process", "conn", "listen", "persist", "posture", "log", "chain")

_RE_CACHE = {}


def _rx(pattern):
    r = _RE_CACHE.get(pattern)
    if r is None:
        r = re.compile(pattern, re.I)
        _RE_CACHE[pattern] = r
    return r


_NS = ("process.", "conn.", "listen.", "persist.", "posture.", "host.", "log.")


def _get(obj, path):
    """按点路径取值。规则里可以写 process.name 也可以写 name——
    前缀只是给人看的分组标记，取值前会剥掉一层。"""
    for ns in _NS:
        if path.startswith(ns):
            path = path[len(ns):]
            break
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


def _cmp(actual, op, value):
    if op == "exists":
        return (actual is not None and actual != "") == bool(value)
    # 内外网算子：规则里不用手写 10./192.168. 这类网段，
    # 否则规则库会变成一堆硬编码，换环境就错。判定交给 policy.is_internal_ip。
    if op in ("internal", "external"):
        if not actual:
            return False
        inside = policy.is_internal_ip(str(actual))
        return inside == bool(value) if op == "internal" else inside != bool(value)
    if op == "eq":
        return _norm(actual) == _norm(value)
    if op == "ne":
        return _norm(actual) != _norm(value)
    if op == "in":
        vals = value if isinstance(value, (list, tuple)) else [value]
        return _norm(actual) in [_norm(v) for v in vals]
    if op == "not_in":
        vals = value if isinstance(value, (list, tuple)) else [value]
        return _norm(actual) not in [_norm(v) for v in vals]
    if actual is None:
        return False
    a = str(actual)
    if op == "contains":
        return _norm(value) in _norm(a)
    if op == "startswith":
        return _norm(a).startswith(_norm(value))
    if op == "endswith":
        return _norm(a).endswith(_norm(value))
    if op == "regex":
        try:
            return bool(_rx(str(value)).search(a))
        except Exception:
            return False
    if op in ("gt", "lt"):
        try:
            x, y = float(actual), float(value)
        except Exception:
            return False
        return x > y if op == "gt" else x < y
    return False


def _norm(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return ""
    return str(v).lower()


def evaluate(cond, obj):
    """对一个对象求值条件树。"""
    if not cond:
        return False
    if isinstance(cond, str):
        try:
            cond = json.loads(cond)
        except Exception:
            return False
    if "all" in cond:
        items = cond["all"] or []
        return all(evaluate(c, obj) for c in items) if items else True
    if "any" in cond:
        items = cond["any"] or []
        return any(evaluate(c, obj) for c in items)
    if "not" in cond:
        return not evaluate(cond["not"], obj)
    field = cond.get("field")
    if not field:
        return False
    return _cmp(_get(obj, field), cond.get("op", "eq"), cond.get("value"))


# ---------------- 内置规则 ----------------
def builtin_rules():
    """(rule_id, name, category, severity, technique, condition, actions, note)"""
    P = "process."
    R = []

    def add(rid, name, cat, sev, tech, cond, actions=None, note="", enabled=1):
        R.append({
            "rule_id": rid, "name": name, "category": cat, "severity": sev,
            "technique": tech, "condition": json.dumps(cond, ensure_ascii=False),
            "actions": json.dumps(actions or {}, ensure_ascii=False),
            "note": note, "enabled": enabled,
        })

    # ---- 进程行为 ----
    add("PS-ENCODED", "PowerShell 编码命令执行", "process", "high", "T1059.001",
        {"all": [{"field": P + "name", "op": "in", "value": ["powershell.exe", "pwsh.exe"]},
                 {"field": P + "cmdline", "op": "regex",
                  "value": r"^(?:(?!-command|-file).)*?(-enc\b|-encodedcommand|-e\s+[A-Za-z0-9+/=]{40,})"}]},
        {"kill": True},
        "常见于无文件落地攻击，也常见于合法运维脚本，故默认只告警。")
    add("PS-DOWNLOAD", "PowerShell 下载执行", "process", "high", "T1105",
        {"all": [{"field": P + "name", "op": "in", "value": ["powershell.exe", "pwsh.exe"]},
                 {"field": P + "cmdline", "op": "regex",
                  "value": r"(downloadstring|downloadfile|invoke-webrequest|iwr\s|wget\s|curl\s).*(http|ftp)"}]},
        {"kill": True})
    add("LOLBIN-MSHTA", "Mshta 远程脚本执行", "process", "high", "T1218.005",
        {"all": [{"field": P + "name", "op": "eq", "value": "mshta.exe"},
                 {"field": P + "cmdline", "op": "regex", "value": r"(https?:|cscript|javascript:|vbscript:)"}]},
        {"kill": True})
    add("LOLBIN-REGSVR32", "Regsvr32 远程组件加载", "process", "high", "T1218.010",
        {"all": [{"field": P + "name", "op": "eq", "value": "regsvr32.exe"},
                 {"field": P + "cmdline", "op": "regex", "value": r"(/i:http|scrobj\.dll|/i:\s*http)"}]},
        {"kill": True})
    add("LOLBIN-RUNDLL32", "Rundll32 脚本宿主执行", "process", "high", "T1218.011",
        {"all": [{"field": P + "name", "op": "eq", "value": "rundll32.exe"},
                 {"field": P + "cmdline", "op": "regex", "value": r"(javascript:|http://|https://|\.js,)"}]},
        {"kill": True})
    add("CERTUTIL-DOWNLOAD", "Certutil 下载/解码载荷", "process", "medium", "T1105",
        {"all": [{"field": P + "name", "op": "eq", "value": "certutil.exe"},
                 {"field": P + "cmdline", "op": "regex", "value": r"(-urlcache|-decode|-decodehex|-f\s+http)"}]})
    add("BITSADMIN-TRANSFER", "Bitsadmin 传输作业", "process", "medium", "T1105",
        {"all": [{"field": P + "name", "op": "eq", "value": "bitsadmin.exe"},
                 {"field": P + "cmdline", "op": "contains", "value": "/transfer"}]})
    add("WMI-EXEC", "WMI 远程创建进程", "process", "medium", "T1047",
        {"all": [{"field": P + "name", "op": "in", "value": ["wmic.exe"]},
                 {"field": P + "cmdline", "op": "regex", "value": r"process\s+call\s+create"}]})
    add("CRED-DUMP", "凭据转储工具特征", "process", "critical", "T1003",
        {"any": [{"field": P + "name", "op": "regex", "value": r"^(mimikatz|procdump.*|pwdump.*)\.exe$"},
                 {"field": P + "cmdline", "op": "regex", "value": r"(sekurlsa::|lsass\.exe.*dump|comsvcs\.dll.*MiniDump)"}]},
        {"kill": True})
    add("MINER", "挖矿程序特征", "process", "critical", "T1496",
        {"any": [{"field": P + "name", "op": "regex", "value": r"^(xmrig|minerd|cpuminer|ethminer).*"},
                 {"field": P + "cmdline", "op": "regex", "value": r"(stratum\+tcp|--donate-level|nicehash)"}]},
        {"kill": True})
    add("SHADOW-DELETE", "删除卷影/关闭恢复", "process", "critical", "T1490",
        {"any": [{"field": P + "cmdline", "op": "regex", "value": r"vssadmin(\.exe)?\s+delete\s+shadows"},
                 {"field": P + "cmdline", "op": "regex", "value": r"bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"},
                 {"field": P + "cmdline", "op": "regex", "value": r"wbadmin.*delete\s+(catalog|backup)"}]},
        {"kill": True})
    add("NET-USER-ADD", "本地账户创建", "process", "high", "T1136",
        {"all": [{"field": P + "name", "op": "in", "value": ["net.exe", "net1.exe", "powershell.exe", "pwsh.exe"]},
                 {"field": P + "cmdline", "op": "regex",
                  "value": r"(net(1)?\.exe\s+user\s+\S+\s+\S+\s+/add|new-localuser|net\s+localgroup\s+administrators\s+\S+\s+/add)"}]})

    # ---- 网络连接 ----
    add("C2-COMMON-PORT", "连接常见 C2 端口", "conn", "medium", "T1571",
        {"all": [{"field": "conn.state", "op": "eq", "value": "ESTABLISHED"},
                 {"field": "conn.remote_ip", "op": "external", "value": True},
                 {"field": "conn.remote_port", "op": "in",
                  "value": [4444, 4445, 5555, 6666, 7777, 8888, 9001, 1337, 31337, 12345]}]},
        {"block_ip": True})
    add("SMB-EXTERNAL", "向公网发起 SMB 连接", "conn", "high", "T1021.002",
        {"all": [{"field": "conn.remote_port", "op": "eq", "value": 445},
                 {"field": "conn.remote_ip", "op": "external", "value": True},
                 {"field": "conn.state", "op": "in", "value": ["ESTABLISHED", "SYN_SENT"]}]},
        {"block_ip": True})
    add("RDP-EXTERNAL", "向公网发起 RDP 连接", "conn", "medium", "T1021.001",
        {"all": [{"field": "conn.remote_port", "op": "eq", "value": 3389},
                 {"field": "conn.remote_ip", "op": "external", "value": True},
                 {"field": "conn.state", "op": "in", "value": ["ESTABLISHED", "SYN_SENT"]}]})
    add("DB-EXTERNAL", "访问公网数据库端口", "conn", "medium", "T1071",
        {"all": [{"field": "conn.state", "op": "eq", "value": "ESTABLISHED"},
                 {"field": "conn.remote_ip", "op": "external", "value": True},
                 {"field": "conn.remote_port", "op": "in", "value": [1433, 3306, 5432, 6379, 27017, 9200]}]})
    add("TELNET-FTP-PLAIN", "明文协议外连", "conn", "low", "T1071",
        {"all": [{"field": "conn.remote_port", "op": "in", "value": [21, 23, 25, 110, 143]},
                 {"field": "conn.state", "op": "eq", "value": "ESTABLISHED"}]})

    # ---- 监听 ----
    add("LISTEN-PORT-HIJACK", "高危端口被非系统进程监听", "listen", "high", "T1205",
        {"all": [{"field": "local_port", "op": "in", "value": [135, 139, 445, 3389]},
                 {"field": "process_name", "op": "not_in",
                  "value": ["System", "Idle", "svchost.exe", "lsass.exe", ""]}]},
        None, "System/svchost 监听 445、139 是 Windows 常态，只有被别人占了才可疑。")
    add("LISTEN-ADMIN-EXPOSED", "管理/数据端口对外暴露", "listen", "medium", "T1205",
        {"all": [{"field": "local_ip", "op": "in", "value": ["0.0.0.0", "::", ""]},
                 {"field": "local_port", "op": "in",
                  "value": [1433, 3306, 5432, 6379, 9200, 27017, 3389, 5900, 5985, 5986]}]},
        None, "本机数据库/远程管理端口没有只监听回环，局域网内可直接连。")
    add("LISTEN-UNKNOWN", "非常规端口新增监听", "listen", "low", "T1205",
        {"all": [{"field": "local_port", "op": "not_in", "value": sorted(policy.COMMON_LISTEN_PORTS)}]},
        None, "默认关闭：单机冷启动一次会刷出 10+ 条低价值记录，需要时再打开。", enabled=0)

    # ---- 持久化 ----
    add("PERSIST-TEMP", "启动项指向临时目录", "persist", "high", "T1547.001",
        {"all": [{"field": "persist.value", "op": "regex",
                  "value": r"(\\temp\\|\\appdata\\local\\temp\\|\\downloads\\|\\public\\)"}]})
    add("PERSIST-LOLBIN", "启动项调用系统 LOLBin", "persist", "high", "T1547.001",
        {"all": [{"field": "persist.value", "op": "regex",
                  "value": r"(mshta|rundll32|regsvr32|wscript|cscript|powershell.*-enc|cmd\s*/c)"}]})
    add("PERSIST-SCHTASK-TEMP", "计划任务指向临时目录", "persist", "medium", "T1053.005",
        {"all": [{"field": "persist.kind", "op": "eq", "value": "scheduled_task"},
                 {"field": "persist.value", "op": "regex", "value": r"(temp|downloads|public)"}]})

    # ==================== 攻击方视角：真实入侵链上的手印 ====================
    # 这一组不是"系统配置检查"，而是按攻击者实际敲下去的命令来写的。
    # 判定依据分三类：父子进程关系（谁生的谁）、命令行语法特征、工具指纹。
    # 单独一条只说明"可能"，真正的定性交给 engine 的攻击链评分。

    SHELL = ["cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe",
             "cscript.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"]

    # ---- 执行：钓鱼落地后的第一跳 ----
    add("OFFICE-CHILD-SHELL", "办公软件拉起命令行（宏/漏洞落地）", "process", "critical",
        "T1566.001",
        {"all": [{"field": "parent_name", "op": "in",
                  "value": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                            "wps.exe", "et.exe", "wpp.exe", "acrobat.exe", "acrord32.exe"]},
                 {"field": "name", "op": "in", "value": SHELL}]},
        None,
        "Word/Excel/WPS 正常不会去调 shell。命中基本等于宏病毒或文档漏洞利用，误报极低。")
    add("EXPLORER-CHILD-LOLBIN", "explorer 拉起可疑子进程", "process", "high", "T1059",
        {"all": [{"field": "parent_name", "op": "eq", "value": "explorer.exe"},
                 {"field": "name", "op": "in",
                  "value": ["mshta.exe", "certutil.exe", "bitsadmin.exe", "regsvr32.exe",
                            "rundll32.exe"]}]},
        None, "用户双击一般只会拉起 exe/文档；explorer 直接生 mshta、certutil 多是快捷方式投毒。")
    add("BROWSER-CHILD-SHELL", "浏览器拉起命令行（水坑/漏洞）", "process", "high", "T1189",
        {"all": [{"field": "parent_name", "op": "in",
                  "value": ["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "360se.exe"]},
                 {"field": "name", "op": "in",
                  "value": ["powershell.exe", "mshta.exe", "rundll32.exe"]}]},
        None,
        "浏览器进程只该起渲染进程。这里不把 cmd.exe 算进来：下载插件/迅雷这类会借 cmd 拉起外部程序，"
        "实测噪声大；powershell/mshta 从浏览器出来才真正没正当理由。")
    add("EXEC-FROM-TEMP", "从临时/公共目录直接执行", "process", "medium", "T1204.002",
        {"all": [{"field": "exe", "op": "regex",
                  "value": r"(\\appdata\\local\\temp\\|\\users\\public\\|\\downloads\\|\\programdata\\)"},
                 {"field": "name", "op": "not_in",
                  "value": ["explorer.exe", "chrome.exe", "msedge.exe", "firefox.exe",
                            "7zfm.exe", "winrar.exe", "code.exe"]}]},
        None, "正规软件装在 Program Files；从 temp/public 直接跑的可执行文件是投递落地的典型位置。")
    add("PS-HIDDEN", "PowerShell 隐藏窗口执行", "process", "high", "T1564.003",
        {"all": [{"field": "name", "op": "in", "value": ["powershell.exe", "pwsh.exe"]},
                 {"field": "cmdline", "op": "regex",
                  "value": r"^(?:(?!-command|-file|-enc).)*?-w(indowstyle|w)?\s+(hidden|h)\b"}]},
        None,
        "只认真正的 hidden 窗口。-NoProfile/-NonInteractive 是几乎所有后台调用的标配（本程序自己也在用），"
        "拿它当特征会把自己吵死 —— 实测过。")
    add("PS-FROM-STRING", "PowerShell 反射加载（IEX/Assembly.Load）", "process", "critical",
        "T1620",
        {"all": [{"field": "name", "op": "in", "value": ["powershell.exe", "pwsh.exe"]},
                 {"field": "cmdline", "op": "regex",
                  "value": r"(iex\s*\(|\|\s*iex\b|invoke-expression|\[ref\]\.assembly\.load|\[system\.reflection\.assembly\]::load)"}]},
        None, "把远程字符串直接当代码跑，是无文件攻击最典型的写法。")
    add("RUNDLL32-ORDINAL", "rundll32 按序号调用导出函数", "process", "high", "T1218.011",
        {"all": [{"field": "name", "op": "eq", "value": "rundll32.exe"},
                 {"field": "cmdline", "op": "regex",
                  "value": r"(,\s*#\d+|javascript:|vbscript:|\\temp\\|\\appdata\\)"}]})
    add("SCRIPT-HOST-REMOTE", "脚本宿主从网络取脚本", "process", "high", "T1059.005",
        {"all": [{"field": "name", "op": "in", "value": ["cscript.exe", "wscript.exe"]},
                 {"field": "cmdline", "op": "regex", "value": r"(https?:\\\\|https?://|\\\\[a-z0-9_.-]+\\[a-z]\$)"}]})
    add("CERTUTIL-DECODE", "certutil 解码载荷", "process", "high", "T1140",
        {"all": [{"field": "name", "op": "eq", "value": "certutil.exe"},
                 {"field": "cmdline", "op": "regex", "value": r"(-decode|-decodehex|-urlcache)"}]},
        None, "证书工具被当成 base64 解码器和下载器，是公认的 LOLBin 滥用。")

    # ---- 持久化：重启后还在 ----
    add("PERSIST-SERVICE-CREATE", "创建/修改系统服务", "process", "high", "T1543.003",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(sc(\.exe)?\s+(create|config)\b|new-service\b|binpath\s*=)"}]})
    add("PERSIST-SCHTASK-SYSTEM", "创建 SYSTEM 权限计划任务", "process", "high", "T1053.005",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(schtasks.*(/ru\s+(system|\\\\?nt authority)|/sc\s+(minute|onlogon|onstart))|register-scheduledtask)"}]})
    add("PERSIST-WMI-SUBSCRIPTION", "注册 WMI 永久事件订阅", "process", "critical", "T1546.003",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(__eventfilter|commandlineeventconsumer|activescripteventconsumer|__filtertoconsumerbinding)"}]},
        None, "WMI 订阅是无文件持久化的经典手法：没有文件、没有服务、重启仍在。")
    add("PERSIST-IFEO", "篡改 IFEO 调试器劫持", "process", "high", "T1546.012",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(image file execution options|\\ifeo\\|debugger\s+)"}]})
    add("PERSIST-LNK-LOLBIN", "启动目录里有脚本类启动项", "persist", "low", "T1547.001",
        {"all": [{"field": "persist.kind", "op": "eq", "value": "startup_folder"},
                 {"field": "persist.name", "op": "regex", "value": r"\.(vbs|js|jse|bat|cmd|ps1)$"}]},
        None,
        "只到 low：实测一台开发机上启动目录就有 6 个 .vbs（都是用户自己装的工具），"
        "看不到脚本内容之前它证明不了恶意。要判恶意得读文件正文，这一版没做。")

    # ---- 提权 ----
    add("UAC-BYPASS-PARENT", "UAC 绕过链（自动提升宿主拉起子进程）", "process", "critical",
        "T1548.002",
        {"all": [{"field": "parent_name", "op": "in",
                  "value": ["fodhelper.exe", "eventvwr.exe", "sdclt.exe", "computerdefaults.exe",
                            "wusa.exe", "slui.exe", "dccw.exe", "msconfig.exe"]},
                 {"field": "name", "op": "in", "value": SHELL + ["reg.exe", "mmc.exe"]}]},
        None, "这些程序会自动提升权限并读取 HKCU 配置，被用来借壳提权。父进程是它们、子进程是 shell，基本可定案。")
    add("PRIVESC-TOOL", "提权工具落地", "process", "critical", "T1068",
        {"all": [{"field": "name", "op": "regex",
                  "value": r"(juicy|sweet|god|rogue|efs|lonely|hot)?potato(e)?\.exe|printspoofer|sharpup|seatbelt|winpeas|linpeas|beacon\.exe"}]},
        {"kill": True}, "Potato 家族/WinPEAS 只在渗透现场出现，命中即杀是合理的默认。")

    # ---- 凭据访问 ----
    add("LSASS-DUMP", "转储 LSASS 内存", "process", "critical", "T1003.001",
        {"any": [{"field": "cmdline", "op": "regex",
                  "value": r"(procdump.*lsass|comsvcs.*minidump|sekurlsa|lsass\.exe\s+\S+\.dmp|rundll32.*comsvcs)"},
                 {"field": "name", "op": "regex",
                  "value": r"(mimikatz|dumpert|nanodump|pwdump|wce\.exe)"}]},
        {"kill": True},
        "LSASS 里有明文/哈希凭据，dump 出来就能横向。procdump 本身是微软工具，只在命令行指向 lsass 时才算。")
    add("SAM-DUMP", "导出 SAM/SECURITY 注册表", "process", "critical", "T1003.002",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(reg(\.exe)?\s+save\s+hklm\\(sam|security|system)|esentutl.*(sam|ntds\.dit)|ntdsutil.*(ifm|ac i ntds))"}]},
        None, "离线破解本地账号哈希的前置动作。")
    add("BROWSER-CRED-ACCESS", "读取浏览器凭据库", "process", "high", "T1555.003",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(login data|\\user data\\default\\(login|cookies)|web data|\\logins\.json)"}]})

    # ---- 发现：人在主机上摸环境 ----
    add("HOST-RECON", "主机信息侦察命令", "process", "medium", "T1082",
        {"all": [{"field": "name", "op": "in",
                  "value": ["whoami.exe", "systeminfo.exe", "nltest.exe", "net.exe", "net1.exe",
                            "qwinsta.exe", "quser.exe", "wmic.exe", "dsquery.exe", "adfind.exe"]},
                 {"field": "cmdline", "op": "regex",
                  "value": r"(/all\b|/priv\b|/groups\b|/domain\b|/dclist|/delight|user\s+/domain|group\s+.*admin|computersysinfo|dsquery|quser|qwinsta)"}]},
        None, "单条命令运维也会用，所以给 medium；连续多条侦察命令会由链评分升级。")
    add("AV-ENUM", "枚举杀软/防护状态", "process", "medium", "T1518.001",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(get-mpcomputerstatus|get-mppreference|get-mpthreat|wmic.*antivirus|sc\s+query\s+(windefend|sense)|tasklist.*(defender|360|huorong|kingsoft))"}]},
        None, "打之前先看对手是谁，是标准动作。")
    add("SHARE-ENUM", "枚举共享与网络资源", "process", "medium", "T1135",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(net\s+(view|share)\b|get-smbshare|invoke-sharefinder|net\s+use\b)"}]})

    # ---- 防御规避 ----
    add("LOG-CLEAR", "清除系统日志", "process", "critical", "T1070.001",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(wevtutil(\.exe)?\s+(cl\b|clear-log)|clear-eventlog|remove-eventlog)"}]},
        None, "清日志是入侵收尾的标准动作，正常运维不用命令行清。")
    add("DEFENDER-EXCLUSION", "给 Defender 加排除项/关实时保护", "process", "critical",
        "T1562.001",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(add-mppreference\s+-exclusion|set-mppreference.*(disable|exclusion))"}]},
        None, "加排除 = 让杀软对指定目录永久闭眼，是攻击者拿到权限后第一件事。")
    add("AMSI-BYPASS", "AMSI 绕过特征", "process", "critical", "T1562.001",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(amsiinitfailed|amsiscanbuffer|amsiutils|amsi\.dll.*(patch|bypass))"}]},
        None, "PowerShell 的攻击面在上游 AMSI，绕过它就是让脚本检测彻底失效。")
    add("FIREWALL-OPEN-HOLE", "防火墙放行规则被添加", "process", "high", "T1562.004",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(netsh.*advfirewall.*(add|set)\s+rule.*allow|new-netfirewallrule.*-action\s+allow|set-netfirewallrule.*-action\s+allow)"}]},
        None, "攻击者为 C2 回连或横向开洞。注意：本程序自己的 BlueGuard- 规则不算，走的是系统 API 不是命令行。")
    add("AV-SERVICE-STOP", "停止安全软件服务", "process", "high", "T1562.001",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(sc(\.exe)?\s+stop\s+(windefend|wdnissvc|sense|mpssvc)|stop-service\s+(windefend|sharedaccess|mpssvc))"}]})
    add("TIMESTOMP", "修改文件时间戳", "process", "medium", "T1070.006",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(set-itemproperty.*lastwritetime|setfiletime|touch\s+-[trd])"}]})

    # ---- 横向移动 ----
    add("LATERAL-TOOL", "横向移动工具落地", "process", "critical", "T1021.002",
        {"all": [{"field": "name", "op": "regex",
                  "value": r"(psexec(64)?|paexec|wmiexec|smbexec|atexec|dcomexec|smbmap|xfreerdp)"},
                 # 运维自己放在 Program Files 的 psexec 不算；只认"从用户目录跑"或"命令行连着远端主机"
                 {"any": [{"field": "cmdline", "op": "regex", "value": r"(\\\\[a-z0-9_.-]+|\s-[a-z]\s)"},
                          {"field": "exe", "op": "regex",
                           "value": r"(\\users\\|\\temp\\|\\downloads\\|\\public\\)"}]}]},
        {"kill": True}, "这些工具在办公机上鲜有正当用途；来源目录和命令行远端地址用来区分运维工具与攻击者投放。")
    add("LATERAL-ADMIN-SHARE", "访问远程管理共享", "process", "high", "T1021.002",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(\\\\[a-z0-9_.-]+\\admin\$|\\\\[a-z0-9_.-]+\\c\$\s|copy\s+\S+\s+\\\\[a-z0-9_.-]+\\[a-z]\$)"}]})
    add("LATERAL-WINRM", "通过 WinRM/PSSession 远程执行", "process", "high", "T1021.006",
        {"any": [{"field": "name", "op": "in", "value": ["winrs.exe", "wsmprovhost.exe"]},
                 {"field": "cmdline", "op": "regex",
                  "value": r"(enter-pssession|new-pssession.*-computername|winrs\s+-r)"}]})
    add("PASS-THE-HASH", "哈希传递特征", "process", "critical", "T1550.002",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(sekurlsa::pth|/ntlm:[0-9a-f]{16,}|-hashes\s+[0-9a-f]{16,}|runas\s+/netonly)"}]})

    # ---- 收集与外传 ----
    add("STAGING-ARCHIVE", "打包用户数据（外传前置）", "process", "high", "T1560.001",
        {"all": [{"field": "name", "op": "regex", "value": r"(7z|7za|rar|winrar|zip|tar)\.exe"},
                 {"field": "cmdline", "op": "regex",
                  "value": r"(c:\\users\\|desktop|documents|downloads|pictures)"}]},
        None, "先压缩再外传是标配；但用户自己备份也会命中，所以不自动处置。")
    add("EXFIL-UPLOAD", "命令行上传数据", "process", "high", "T1041",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(invoke-restmethod.*-method\s+post|curl(\.exe)?\s+(\S+\s+)*-f\s|curl(\.exe)?.*(--upload-file|-t\s)|ftp\s+-s:|rclone\s+(copy|sync)|bitsadmin.*\/transfer)"},
                 {"not": {"field": "cmdline", "op": "regex",
                          "value": r"(127\.0\.0\.1|localhost|\[::1\]|::1\b)"}}]},
        None, "命令行把文件推到外部端点，是脚本化外传的典型形态；只打本机回环地址的不算——"
              "本程序自己的 API 调用、本地调试脚本都是这种形状，实测会把它们报成外传。")
    add("EXFIL-DNS-TOOL", "DNS 隧道工具", "process", "critical", "T1071.004",
        {"all": [{"field": "name", "op": "regex", "value": r"(dnscat2?|iodine|dns2tcp|tuns)\.exe"}]},
        {"kill": True}, "DNS 隧道能在只放行 53 的网络里把数据带出去。")

    # ---- 影响 ----
    add("RANSOM-RECOVERY-KILL", "破坏系统恢复能力", "process", "critical", "T1490",
        {"all": [{"field": "cmdline", "op": "regex",
                  "value": r"(bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|wbadmin\s+delete\s+(catalog|systemstatebackup)|cipher\s+/w)"}]},
        None, "勒索加密前必做：关掉恢复环境、删掉备份目录，让受害者无法自救。")

    # ---- 主机姿态 ----
    add("DEFENDER-SERVICE-OFF", "Defender 整体关闭", "posture", "high", "T1562.001",
        {"all": [{"field": "posture.defender_enabled", "op": "eq", "value": False}]},
        None, "和「Defender 实时保护关闭」是同一件事的两面，同时开会让同一台机器刷两条。默认关。",
        enabled=0)
    add("FIREWALL-OFF", "系统防火墙被关闭", "posture", "high", "T1562.004",
        {"all": [{"field": "posture.firewall_all_on", "op": "eq", "value": False}]},
        None, "任一防火墙配置档关闭即触发；实体机常见于域策略覆盖。")
    add("DEFENDER-OFF", "Defender 实时保护关闭", "posture", "high", "T1562.001",
        {"all": [{"field": "posture.defender_realtime", "op": "eq", "value": False}]})
    add("SMB1-ON", "SMBv1 协议仍启用", "posture", "medium", "T1021.002",
        {"all": [{"field": "posture.smb1", "op": "eq", "value": True}]})
    add("RDP-OPEN", "远程桌面处于开放状态", "posture", "medium", "T1021.001",
        {"all": [{"field": "posture.rdp_deny", "op": "eq", "value": "0"}]})

    # ==================== 攻击链模板（category='chain'）====================
    # 这些不是对某个对象求值的规则，主循环会跳过（candidates 返回空）。
    # 它们只给 chain.py 用：condition 描述"必须同时出现哪些战术"。
    add("CHAIN-INTRUSION", "疑似主机入侵链（落地 → 驻留）", "chain", "critical", "",
        {"require": ["执行", "持久化"], "boost": ["初始访问", "防御规避", "命令与控制"],
         "min_tactics": 3},
        None, "执行 + 持久化，且至少凑够 3 个不同战术。单机环境里这基本等于真被打进来了。")
    add("CHAIN-CRED-LATERAL", "凭据窃取后横向移动", "chain", "critical", "",
        {"require": ["凭据访问", "横向移动"], "boost": ["发现"], "min_tactics": 2},
        None, "先偷凭据、再连其它主机，内网被打穿的标志性组合。")
    add("CHAIN-RECON-PRIVESC", "侦察后提权", "chain", "high", "",
        {"require": ["发现", "权限提升"], "boost": ["防御规避"], "min_tactics": 2},
        None, "系统性摸环境之后出现提权动作，人的意图已经很明显。")
    add("CHAIN-EXFIL", "收集后外传", "chain", "critical", "",
        {"require": ["收集", "外泄"], "boost": ["命令与控制"], "min_tactics": 2},
        None, "打包 + 上传，数据被带走的最后一段路。")
    add("CHAIN-DEFENSE-TAMPER", "防御削弱后执行载荷", "chain", "high", "",
        {"require": ["防御规避", "执行"], "boost": ["持久化", "凭据访问"], "min_tactics": 3},
        None, "先关日志/关杀软再加载荷，说明对方知道这台机器有防护。要求第三个战术在场："
              "「防御规避 + 执行」两桶太容易凑，单独出现只是可疑，不构成链。")

    return R


def ensure_seed(conn=None):
    """把内置规则写进库里。

    语义：内置规则的定义（条件/动作/严重度/说明）随版本升级自动同步，
    但用户改过的 `enabled` 与计数（hits/last_hit_at）必须保留——
    否则每次升级都会把用户手工停用的规则又打开。
    """
    from ..db import tx
    import time as _t
    rows = builtin_rules()
    now = _t.strftime("%Y-%m-%d %H:%M:%S")
    for r in rows:
        with tx() as c:
            c.execute(
                "INSERT OR IGNORE INTO guard_rules(rule_id,name,category,severity,technique,condition,"
                "actions,enabled,builtin,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,1,?,?,?)",
                (r["rule_id"], r["name"], r["category"], r["severity"], r["technique"],
                 r["condition"], r["actions"], r.get("enabled", 1), r["note"], now, now))
            c.execute(
                "UPDATE guard_rules SET name=?,category=?,severity=?,technique=?,condition=?,"
                "actions=?,note=?,updated_at=? WHERE rule_id=? AND builtin=1 AND "
                "(IFNULL(condition,'')<>? OR IFNULL(actions,'')<>? OR IFNULL(severity,'')<>? "
                "OR IFNULL(name,'')<>?)",
                (r["name"], r["category"], r["severity"], r["technique"], r["condition"],
                 r["actions"], r["note"], now, r["rule_id"],
                 r["condition"], r["actions"], r["severity"], r["name"]))
    # 策略与白名单种子（独立事务，避免嵌套 commit）
    policy.ensure_seed(conn)


def load_rules(conn=None):
    """读启用的规则，返回带解析后 condition 的列表。"""
    from ..db import connect
    c = conn or connect()
    rows = c.execute("SELECT * FROM guard_rules WHERE enabled=1 ORDER BY category, severity DESC").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["cond"] = json.loads(d.get("condition") or "{}")
        except Exception:
            continue
        try:
            d["acts"] = json.loads(d.get("actions") or "{}")
        except Exception:
            d["acts"] = {}
        out.append(d)
    return out


def subject_of(category, obj):
    """一个对象的稳定身份串，用于去重与响应定位。"""
    if category == "process":
        return "%s:%s" % (obj.get("name", "?"), obj.get("pid", 0))
    if category == "conn":
        return "%s:%s" % (obj.get("remote_ip", ""), obj.get("remote_port", 0))
    if category == "listen":
        return "port:%s" % obj.get("local_port", 0)
    if category == "persist":
        return "%s@%s" % (obj.get("name", ""), obj.get("location", ""))
    if category == "posture":
        return "posture"
    return str(obj)[:120]


def candidates(snap, category):
    """从快照里取该类规则要评估的对象集。"""
    if category == "process":
        return snap.get("processes") or []
    if category == "conn":
        return [c for c in (snap.get("conns") or []) if c.get("state") in ("ESTABLISHED", "SYN_SENT")]
    if category == "listen":
        return snap.get("listens") or []
    if category == "persist":
        return snap.get("persist") or []
    if category == "posture":
        return [snap.get("posture") or {}]
    return []


def score_of(sev):
    return SEV_SCORE.get(sev, 20)
