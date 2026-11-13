# -*- coding: utf-8 -*-
"""体检结论（advice）

把规则命中翻译成不懂安全的人也能看懂的话：
    「这是什么」+「你该干什么」+「现在整体怎么样」

设计原则：
- 不吓人。级别用「健康 / 留意 / 需要处理」三档，不用 critical/high 吓小白。
- 每条都给动作。只说「发现高危漏洞」不告诉人怎么改，等于没说。
- 拿不准就说不准。看不到脚本内容就说「证明不了恶意」，不硬扣帽子。
"""

from datetime import datetime

LEVEL_META = {
    "ok":        ("健康",     "没有发现需要你动手的问题"),
    "attention": ("留意",     "有几件事值得看一眼，不着急"),
    "risk":      ("需要处理", "有必须先处理的问题"),
}

# rule_id -> (这是什么，你该干什么)
ADVICE = {
    # ---- 主机姿态：最常见、也最好修 ----
    "FIREWALL-OFF": (
        "Windows 防火墙至少有一个档位是关的。这三个档位分别是域、专用、公用网络。",
        "打开「Windows 安全中心 → 防火墙和网络保护」，把三个档位都打开。关着的时候，别人连你这台机器的连接不会被检查。",
    ),
    "DEFENDER-OFF": (
        "Windows 自带的杀毒（Defender）实时保护是关的。",
        "打开「Windows 安全中心 → 病毒和威胁防护」，开启实时保护。如果你装了别的杀毒软件，确认它真的在跑。",
    ),
    "DEFENDER-SERVICE-OFF": (
        "Defender 的后台服务被停掉了。",
        "同上，把 Defender 服务恢复为自动启动。系统被优化工具「精简」过的话，这条路可能走不通，那就装一个第三方杀毒。",
    ),
    "SMB1-ON": (
        "SMB1 这个老旧的局域网共享协议还开着。它有著名的远程漏洞（永恒之蓝就是打它）。",
        "控制面板 → 程序和功能 → 启用或关闭 Windows 功能 → 取消勾选「SMB 1.0/CIFS 文件共享支持」。",
    ),
    "RDP-OPEN": (
        "远程桌面（RDP）是开着的，别人可以从网络连到你的桌面。",
        "如果你不用远程桌面，关掉它：设置 → 系统 → 远程桌面 → 关闭。要用的话，至少改强密码，别用默认端口。",
    ),
    "RDP-EXTERNAL": (
        "有外网地址正在尝试连接你的远程桌面端口（3389）。",
        "这是被扫描/爆破的典型迹象。不用就关掉远程桌面；要用就限制来源 IP。",
    ),

    # ---- 端口暴露 ----
    "LISTEN-ADMIN-EXPOSED": (
        "一个数据库或管理端口在所有网卡上都开着（0.0.0.0），同一个 WiFi 里的设备都能连。",
        "如果你不需要从别的机器连这个服务，把它绑到 127.0.0.1；需要的话，用防火墙限制只允许特定 IP，并确认密码够强。",
    ),
    "DB-EXTERNAL": (
        "有外网地址正在连你的数据库端口。",
        "数据库不该直接暴露在公网。查一下这条连接是不是你自己发起的；不是的话，立刻在防火墙封掉这个 IP。",
    ),
    "LISTEN-PORT-HIJACK": (
        "135/139/445/3389 这类管理端口被一个来路不明的程序占着。",
        "正常的系统服务不会这样。到「防护中心 → 事件」看这个进程的完整路径，不认识就结束它。",
    ),
    "LISTEN-UNKNOWN": (
        "有个程序在监听端口，但不在已知清单里。",
        "看一眼进程路径，是你自己装的开发/服务工具就加白名单；不认识就结束。",
    ),
    "TELNET-FTP-PLAIN": (
        "在用 telnet 或 ftp 这种明文协议，密码在网络上是裸奔的。",
        "换成 ssh / sftp / https。",
    ),

    # ---- 执行 ----
    "PS-ENCODED": (
        "有一个 PowerShell 用「编码命令」方式执行（-EncodedCommand），外面看不出来它到底跑了什么。",
        "正规运维很少这么用，攻击者爱用（躲日志）。到事件详情看进程路径与父进程；不是你自己跑的脚本就结束它。",
    ),
    "PS-HIDDEN": (
        "有一个 PowerShell 在隐藏窗口里跑（-WindowStyle Hidden）。",
        "很多工具都这么干（比如你自己的桌面图标守护）。确认这个脚本是你装的，不是就查清楚。",
    ),
    "PS-FROM-STRING": (
        "PowerShell 从一段字符串里直接解码执行代码（-EncodedCommand / IEX / FromBase64String）。",
        "这是无文件攻击的标准手法。除非你自己在跑这类脚本，否则当可疑处理。",
    ),
    "PS-DOWNLOAD": (
        "PowerShell 正在从网上拉文件。",
        "看它拉的地址是不是你认识的。不认识的域名，基本可以判定为木马下载器。",
    ),
    "OFFICE-CHILD-SHELL": (
        "Word/Excel/WPS 这类办公软件启动了命令行。",
        "正常办公绝不会这样。这是钓鱼文档带宏的典型特征，几乎可以直接判定为攻击。",
    ),
    "EXPLORER-CHILD-LOLBIN": (
        "资源管理器（explorer）直接启动了一个系统工具来执行命令。",
        "正常操作不会这样走。多半是有人在你机器上手动执行了可疑命令。",
    ),
    "BROWSER-CHILD-SHELL": (
        "浏览器拉起了一个会执行命令的组件。",
        "可能是恶意扩展或挂马网页。先关掉浏览器，再看事件里的进程路径。",
    ),
    "EXEC-FROM-TEMP": (
        "有个程序是从临时目录启动的。",
        "正规软件很少从 Temp 跑。看一眼路径，不认识就结束并删掉。",
    ),
    "LOLBIN-MSHTA": (
        "mshta 被用来执行命令。它是 Windows 自带组件，常被攻击者「借刀杀人」绕过杀软。",
        "你不需要 mshta 的话，直接在事件里结束它；这类组件被调用基本没有善意场景。",
    ),
    "LOLBIN-REGSVR32": (
        "regsvr32 被用来加载远程脚本。",
        "同样属于「系统自带工具被借用」，正常软件不会这么加载。",
    ),
    "LOLBIN-RUNDLL32": (
        "rundll32 执行了可疑调用。",
        "看参数：调用的是系统 DLL 还是某个临时目录里的文件？后者基本可以判定为恶意。",
    ),
    "RUNDLL32-ORDINAL": (
        "rundll32 用序号方式调用导出函数——这是为了躲开检测的写法。",
        "正常软件会用函数名。这种写法直接当可疑处理。",
    ),
    "CERTUTIL-DECODE": (
        "certutil 被用来解码文件。它本来是管理证书的工具，常被攻击者拿来还原 payload。",
        "你自己没在用证书工具的话，这就是恶意行为。",
    ),
    "SCRIPT-HOST-REMOTE": (
        "脚本宿主在跑远程脚本。",
        "把远程脚本下载到本地执行，是恶意软件常见的第一步。",
    ),
    "AMSI-BYPASS": (
        "有命令试图关掉 Windows 的脚本扫描（AMSI）。",
        "这是攻击者动手前的标准动作——先弄瞎监控。正常软件绝不会这么干。",
    ),
    "LSASS-DUMP": (
        "有程序在读取 LSASS 进程的内存——那是 Windows 存放登录密码哈希的地方。",
        "mimikatz 一类工具的标准行为。除了你正在做安全测试，否则立刻结束它并检查账号。",
    ),
    "SAM-DUMP": (
        "有程序在导出本地账号数据库（SAM）。",
        "同上，拿到它就能离线破解所有本地账号密码。",
    ),
    "BROWSER-CRED-ACCESS": (
        "有程序在访问浏览器的密码存储文件。",
        "除了密码管理器本身，没有软件该读这个。",
    ),
    "LOG-CLEAR": (
        "有人在清空 Windows 事件日志。",
        "这是入侵者抹痕迹的标准动作。如果没有 IT 在做运维，基本可以确认有人进来过。",
    ),
    "DEFENDER-EXCLUSION": (
        "有人给 Defender 添加了「排除路径」——让杀毒软件不扫描某个目录。",
        "攻击者常这么干，好让木马待在那个目录里不被发现。除非你自己加过，否则立刻删掉这条排除。",
    ),
    "FIREWALL-OPEN-HOLE": (
        "有人往防火墙里加了放行规则。",
        "确认是不是你自己开的。不认识就删——这可能是攻击者在给自己开门。",
    ),
    "AV-SERVICE-STOP": (
        "杀毒软件的进程/服务被停掉了。",
        "正常操作不会停杀毒。查一下是谁停的。",
    ),
    "TIMESTOMP": (
        "有程序在改文件的修改时间（时间戳伪造）。",
        "为了藏住「这个文件是什么时候落地的」。正常软件不会这么干。",
    ),
    "UAC-BYPASS-PARENT": (
        "一个 Windows 自带的「白名单程序」启动了一个高权限进程——这是绕 UAC 提权的经典手法。",
        "普通人不会遇到这个。基本可以判定有人在提权。",
    ),
    "PRIVESC-TOOL": (
        "检测到已知的本地提权工具。",
        "立刻结束进程；如果它已经跑完，检查这台机器上有没有新增的管理员账号。",
    ),
    "LATERAL-TOOL": (
        "检测到横向移动工具（psexec 一类），正被用来连别的机器。",
        "这台机器可能已经成了跳板。断网、取证、再排查。",
    ),
    "PASS-THE-HASH": (
        "检测到「哈希传递」痕迹——不用知道密码，直接用密码哈希登录。",
        "域环境里的高危行为。查这条连接是谁发起的，立刻隔离。",
    ),
    "SHARE-ENUM": (
        "有程序在枚举局域网共享。",
        "攻击者在内网踩点时会这么干。单个行为不算实锤，配合其他异常一起看。",
    ),
    "HOST-RECON": (
        "有程序在收集本机信息（系统版本、补丁、账号）。",
        "踩点行为。单独看不一定恶意，和其他异常一起出现就要重视。",
    ),
    "AV-ENUM": (
        "有程序在查询装了哪个杀毒软件。",
        "攻击者在动手前先看对手是谁，好选免杀方案。",
    ),
    "STAGING-ARCHIVE": (
        "有程序在打包压缩文件——可能是准备把数据带走。",
        "如果不是你自己在备份，查一下这个压缩包是从哪儿来的。",
    ),
    "EXFIL-UPLOAD": (
        "有程序正在向外网上传文件。",
        "确认这个上传是你自己发起的（网盘同步、代码提交都会这样）。不是的话，立刻断网。",
    ),
    "EXFIL-DNS-TOOL": (
        "检测到 DNS 隧道工具——把数据藏在 DNS 查询里偷偷传出去。",
        "这种手法能绕过大部分防火墙。可以直接判定为恶意。",
    ),
    "RANSOM-RECOVERY-KILL": (
        "有程序在删除系统备份/关闭恢复功能。",
        "勒索软件加密前的第一步就是让你没法恢复。看到这个立刻断网。",
    ),
    "SHADOW-DELETE": (
        "有程序在删除卷影副本（系统还原点）。",
        "勒索软件的标准动作。立刻断网。",
    ),
    "MINER": (
        "检测到挖矿程序特征。",
        "它会占满你的显卡/CPU 耗电。结束进程，并找到是谁把它装进来的。",
    ),
    "CRED-DUMP": (
        "检测到凭据转储工具的典型命令行。",
        "有人在偷密码。结束进程，改所有密码。",
    ),
    "NET-USER-ADD": (
        "有人在添加系统账号（net user /add）。",
        "攻击者留后门的常见做法。到「计算机管理 → 本地用户」看看多了谁。",
    ),
    "WMI-EXEC": (
        "有人通过 WMI 远程执行命令。",
        "这是横向移动的常用通道。确认是不是你自己的运维脚本。",
    ),
    "BITSADMIN-TRANSFER": (
        "bitsadmin 被用来下载文件。",
        "它藏在系统后台传输里，不容易被防火墙发现。",
    ),

    # ---- 持久化 ----
    "PERSIST-TEMP": (
        "临时目录里的程序被设成了开机自启动。",
        "正规软件不会把自启动项放在 Temp。直接删掉这条启动项。",
    ),
    "PERSIST-LOLBIN": (
        "有人用系统自带工具做成了开机自启动。",
        "这是为了躲开「可疑启动项」检测。到「任务管理器 → 启动」或注册表 Run 项删掉它。",
    ),
    "PERSIST-SCHTASK-TEMP": (
        "计划任务指向了临时目录里的程序。",
        "正规计划任务不会这样。到「任务计划程序」里删掉这条。",
    ),
    "PERSIST-SERVICE-CREATE": (
        "有程序把新建的系统服务指向了可疑路径。",
        "服务是权限最高的自启动方式。查这个路径，不认识就停掉并删除服务。",
    ),
    "PERSIST-SCHTASK-SYSTEM": (
        "有 SYSTEM 权限的计划任务被创建。",
        "SYSTEM 是最高权限账号，普通软件装不了这种任务。",
    ),
    "PERSIST-WMI-SUBSCRIPTION": (
        "有程序注册了 WMI 事件订阅——一种很隐蔽的自启动方式。",
        "WMI 永久订阅连安全软件都容易漏。除非你自己写监控脚本，否则当恶意处理。",
    ),
    "PERSIST-IFEO": (
        "有人改了「映像劫持」（IFEO）——让某个程序一启动就换成另一个程序跑。",
        "这是恶意的经典手法，会导致杀毒软件打不开。到注册表 Image File Execution Options 下检查。",
    ),
    "PERSIST-LNK-LOLBIN": (
        "启动目录里有脚本类文件（.vbs/.js/.bat 等）。",
        "看不到脚本内容前证明不了恶意——很多正常工具也这么装。你确认是自己装的就行；不认识就打开看一眼再删。",
    ),

    # ---- 网络 ----
    "C2-COMMON-PORT": (
        "有程序在连外网的 4444/1337/31337 这类端口——木马控制端的常用端口。",
        "看是不是你自己在测东西。否则立刻封掉这个 IP 并结束对应进程。",
    ),
    "SMB-EXTERNAL": (
        "有外网地址在连你的文件共享端口（445）。",
        "这是勒索病毒横向传播的主要入口。除非你在做共享，否则该端口不该对公网开放。",
    ),
    "CHAIN-INTRUSION": (
        "多个不同阶段的可疑行为串在了一起（比如「执行 + 持久化」），构成了入侵链条。",
        "单看每一条都还能解释，连起来就是攻击。这是最该认真看的一类，进事件详情按时间顺序过一遍。",
    ),
    "CHAIN-CRED-LATERAL": (
        "偷密码的行为 + 横向移动的行为串在了一起。",
        "说明可能已经有账号失守、正在往别的机器扩散。立刻隔离这台机器。",
    ),
    "CHAIN-RECON-PRIVESC": (
        "踩点 + 提权的行为串在了一起。",
        "有人在系统性摸这台机器找突破口。",
    ),
    "CHAIN-EXFIL": (
        "收集数据 + 向外传输的行为串在了一起。",
        "数据可能正在被打包带走。查清传的是什么、传给谁。",
    ),
    "CHAIN-DEFENSE-TAMPER": (
        "关掉防护 + 干别的事串在了一起。",
        "先把监控弄瞎再动手，是攻击者的标准流程。",
    ),
}

# 没有专门建议时按严重度给通用说法
_GENERIC = {
    "critical": ("检测到一个严重级别的可疑行为。",
                 "进「防护中心 → 事件」看这条的进程路径和命令行，不认识就结束它，并检查最近装了什么。"),
    "high":     ("检测到一个高级别的可疑行为。",
                 "看一眼事件详情。能解释就标记「误报」，解释不了就处置。"),
    "medium":   ("检测到一个中等级别的可疑项。",
                 "多半是配置问题，不着急，有空再改。"),
    "low":      ("检测到一个低级别提示。",
                 "通常是环境差异，可以忽略。"),
}

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def advice_for(rule_id, severity, name=""):
    """返回 (这是什么, 你该干什么)。"""
    hit = ADVICE.get(rule_id or "")
    if hit:
        return hit
    what, how = _GENERIC.get(severity or "medium", _GENERIC["medium"])
    if name:
        what = "「%s」：%s" % (name, what)
    return what, how


def assess(conn, limit=4):
    """给整台机器下一个「人话结论」。

    只看今天、未关闭、非误报的事件；同一规则合并成一条（带出现次数）。
    """
    rows = conn.execute(
        "SELECT e.id, e.rule_id, e.rule_name, e.severity, e.category, e.subject, e.ts, "
        "COALESCE(r.rule_id, '') AS rule_key "
        "FROM guard_events e LEFT JOIN guard_rules r ON r.id = e.rule_id "
        "WHERE e.status NOT IN ('closed','false_positive','escalated') "
        "AND substr(e.ts,1,10)=? ORDER BY e.ts DESC LIMIT 400",
        (datetime.now().strftime("%Y-%m-%d"),)).fetchall()

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    grouped = {}
    for r in rows:
        sev = r["severity"] or "medium"
        counts[sev] = counts.get(sev, 0) + 1
        key = r["rule_key"] or str(r["rule_id"])
        if key not in grouped:
            grouped[key] = {
                "rule_id": r["rule_key"] or "",
                "name": r["rule_name"],
                "severity": sev,
                "category": r["category"],
                "count": 0,
                "event_id": r["id"],
                "subject": r["subject"] or "",
                "ts": r["ts"],
            }
        grouped[key]["count"] += 1
        # 保留最严重的一条作为入口
        if SEV_RANK.get(sev, 3) < SEV_RANK.get(grouped[key]["severity"], 3):
            grouped[key]["severity"] = sev
            grouped[key]["event_id"] = r["id"]

    items = sorted(grouped.values(), key=lambda x: (SEV_RANK.get(x["severity"], 3), -x["count"]))
    for it in items:
        it["what"], it["hint"] = advice_for(it["rule_id"], it["severity"], it["name"])

    total = sum(counts.values())
    if counts["critical"] > 0:
        level = "risk"
    elif counts["high"] >= 3:
        level = "risk"
    elif counts["high"] >= 1 or counts["medium"] >= 3:
        level = "attention"
    else:
        level = "ok"

    label, sub = LEVEL_META[level]
    if level == "ok":
        headline = "这台机器目前没有发现需要你动手的问题。"
    elif level == "risk":
        kinds = len([x for x in items if x["severity"] in ("critical", "high")]) or len(items)
        headline = "有 %d 类问题需要先处理，共 %d 条命中。" % (
            kinds, counts["critical"] + counts["high"])
    else:
        headline = "有 %d 件事值得看一眼，不着急。" % len(items)

    nxt = {"label": "打开事件列表逐条看", "page": "guard", "tab": "events"}
    if items:
        first = items[0]
        if first["rule_id"] in ("FIREWALL-OFF", "DEFENDER-OFF", "DEFENDER-SERVICE-OFF", "SMB1-ON", "RDP-OPEN"):
            nxt = {"label": "先修这条：" + first["name"], "page": "guard", "tab": "events"}
        else:
            nxt = {"label": "先看这条：" + first["name"], "page": "guard", "tab": "events"}

    return {
        "level": level,
        "label": label,
        "sub": sub,
        "headline": headline,
        "counts": counts,
        "total": total,
        "items": items[:limit],
        "more": max(0, len(items) - limit),
        "next": nxt,
    }
