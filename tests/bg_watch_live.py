# -*- coding: utf-8 -*-
"""事件源 + 内置规则联合实测：一个只活 2 秒的编码命令，轮询看不见，事件源判出来了。

跑法：
    set BLUEGUARD_DATA=%TEMP%\bg_watch_live
    python tests\bg_watch_live.py
"""
import base64
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import schema  # noqa: E402
from backend.db import connect  # noqa: E402
from backend.guard import engine, policy, rules, watcher  # noqa: E402

FAIL = []
# 可选：一个 GUI 子系统的启动器，用来让被测进程的父进程不是本测试脚本。
# 不设置也没关系，脚本会退回用 cmd /c start 的方式起子进程。
SILENTRUN = os.environ.get("BG_SILENTRUN", "")
PWSH = r"C:\Program Files\PowerShell\7\pwsh.exe"


def check(name, cond, detail=""):
    print(("  PASS " if cond else "  FAIL ") + name + (("  " + str(detail)) if detail else ""))
    if not cond:
        FAIL.append(name)


def main():
    schema.migrate()
    rules.ensure_seed()
    policy.ensure_seed()
    policy.update_policy({"mode": "alert", "interval_sec": 8})

    print("== 起引擎（真实循环，8 秒一轮）==")
    engine.stop()
    time.sleep(0.5)
    r = engine.start()
    check("引擎启动", r.get("ok") is True, r)
    time.sleep(3)
    check("事件源随引擎启动", (engine.status().get("watch") or {}).get("running") is True)

    print("\n== 造一个只活 2.2 秒的编码命令 ==")
    enc = base64.b64encode("Start-Sleep -Milliseconds 2200".encode("utf-16-le")).decode()
    if os.path.exists(SILENTRUN):
        cmd = [SILENTRUN, PWSH, "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", enc]
    else:
        cmd = [PWSH, "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", enc]
    subprocess.Popen(cmd, creationflags=0x08000000, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    kid = None
    deadline = time.time() + 8
    while time.time() < deadline and not kid:
        for o in watcher.peek(400):
            if (o.get("name") or "").lower().startswith("pwsh") and enc in (o.get("cmdline") or ""):
                kid = o.get("pid")
                break
        if not kid:
            time.sleep(0.2)
    check("事件源捕获到这个进程", bool(kid), "pid=%s" % kid)
    if not kid:
        engine.stop()
        print("失败项：%d" % len(FAIL))
        return 1

    print("\n== 等引擎跑完一轮（12 秒）==")
    time.sleep(13)
    conn = connect()
    rows = conn.execute(
        "SELECT rule_id, rule_name, severity, detail FROM guard_events WHERE pid=? ORDER BY id",
        (kid,)).fetchall()
    check("短命进程被内置规则判出来了", len(rows) >= 1, "%d 条" % len(rows))
    for r in rows:
        print("     - [%s] %s（%s）" % (r["severity"], r["rule_name"], r["rule_id"]))
    names = {r["rule_name"] for r in rows}
    check("命中包含编码命令规则", any("编码命令" in n for n in names), names)

    print("\n== 对照：轮询快照里已经没有它了 ==")
    from backend.guard import probes
    snap = probes.collect(deep=False)
    pids = {x.get("pid") for x in snap.get("processes") or []}
    check("快照不含该 pid", kid not in pids, "snapshot=%d 个进程" % len(pids))

    st = engine.status()
    check("引擎至少跑过两轮", (st.get("rounds") or 0) >= 2, "rounds=%s" % st.get("rounds"))
    engine.stop()
    time.sleep(0.5)
    check("引擎停止后事件源归零", (watcher.status().get("running") is False))

    print("\n失败项：%d" % len(FAIL))
    for f in FAIL:
        print("  -", f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
