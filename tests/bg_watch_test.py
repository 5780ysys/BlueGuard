# -*- coding: utf-8 -*-
"""WMI 进程创建事件源实测：短命进程轮询看不见，watcher 能看见并判出来。

用一条临时规则（进程名 = timeout.exe）做判定，避免依赖内置规则的具体条件，
这样测的是"事件源 → 规则引擎 → 落库"这条链路本身。

跑法：
    set BLUEGUARD_DATA=%TEMP%\bg_watch
    python tests\bg_watch_test.py
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import schema  # noqa: E402
from backend.db import connect, tx  # noqa: E402
from backend.guard import engine, policy, probes, rules, watcher  # noqa: E402

FAIL = []
RULE_ID = "WATCH-TEST"
CREATE_NO_WINDOW = 0x08000000


def check(name, cond, detail=""):
    print(("  PASS " if cond else "  FAIL ") + name + (("  " + str(detail)) if detail else ""))
    if not cond:
        FAIL.append(name)


def install_rule():
    cond = {"all": [{"field": "name", "op": "eq", "value": "ping.exe"}]}
    with tx() as c:
        c.execute("DELETE FROM guard_rules WHERE rule_id=?", (RULE_ID,))
        c.execute(
            "INSERT INTO guard_rules(rule_id,name,category,severity,technique,condition,actions,"
            "enabled,builtin,note) VALUES(?,?,?,?,?,?,?,1,0,?)",
            (RULE_ID, "事件源自测：ping.exe 出现", "process", "low", "T1059",
             json.dumps(cond), json.dumps({}), "临时规则，仅用于验证 WMI 事件源"))


def drop_rule():
    with tx() as c:
        c.execute("DELETE FROM guard_rules WHERE rule_id=?", (RULE_ID,))
        c.execute("DELETE FROM guard_events WHERE rule_id=(SELECT 0)")  # no-op，保证语句合法


def spawn_short_lived():
    """起一个存活约 2 秒的 ping.exe：父进程是 cmd.exe，不是本进程。

    用 ping 不用 timeout：timeout 在无 console 时立刻报错退出。
    """
    p = subprocess.Popen(["cmd.exe", "/c", "ping -n 3 127.0.0.1 >nul"], creationflags=CREATE_NO_WINDOW,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # psutil 在父进程里抓子进程不稳（进程可能已经在退），改用事件源自己的队列找 pid，
    # 这才是"事件源看见了什么"的第一手证据。
    kid = None
    deadline = time.time() + 6
    while time.time() < deadline and not kid:
        for o in watcher.peek(400):
            if (o.get("name") or "").lower() == "ping.exe" and "127.0.0.1" in (o.get("cmdline") or ""):
                kid = o.get("pid")
                break
        if not kid:
            time.sleep(0.2)
    return p, kid


def pid_alive(pid):
    if not pid:
        return False
    try:
        import psutil
        return psutil.pid_exists(pid) and psutil.Process(pid).is_running()
    except Exception:
        return False


def main():
    print("== 1) 事件源可用性 ==")
    av = watcher.available()
    check("PowerShell 可用", av.get("ok") is True, av.get("powershell"))
    if not av.get("ok"):
        print("失败项：%d" % len(FAIL))
        return 1

    schema.migrate()
    rules.ensure_seed()
    policy.ensure_seed()
    policy.update_policy({"mode": "alert", "interval_sec": 8})
    install_rule()

    print("\n== 2) 只起事件源（不起引擎循环，避免它抢着消费队列）==")
    engine.stop()
    watcher.stop()
    time.sleep(0.3)
    r = watcher.start()
    check("事件源启动", r.get("ok") is True, "pid=%s" % r.get("pid"))
    time.sleep(2.5)
    w = watcher.status()
    check("事件源在跑", w.get("running") is True, "pid=%s seen=%s err=%s" % (w.get("pid"), w.get("seen"), w.get("error")))

    print("\n== 3) 造一个活 2 秒的进程 ==")
    before = watcher.status().get("seen") or 0
    holder, kid = spawn_short_lived()
    check("找到那个短命子进程", bool(kid), "pid=%s" % kid)
    holder.wait(timeout=10)
    time.sleep(1.2)
    check("它已经退出了（轮询此刻看不到）", pid_alive(kid) is False, "pid=%s" % kid)
    w2 = watcher.status()
    check("事件源捕获到新进程", (w2.get("seen") or 0) > before, "seen %s -> %s" % (before, w2.get("seen")))

    print("\n== 4) 让引擎判定这批事件 ==")
    stats = engine.run_once(deep=False, trigger="manual")
    check("本轮有事件源数据参与", (stats.get("watched") or 0) >= 1,
          "watched=%s watch_hits=%s" % (stats.get("watched"), stats.get("watch_hits")))
    check("本轮无错误", not stats.get("errors"), stats.get("errors"))

    print("\n== 5) 库里是否留下了这个已死进程的事件 ==")
    conn = connect()
    row = conn.execute(
        "SELECT id, rule_id, rule_name, severity, subject, pid, detail, evidence FROM guard_events "
        "WHERE rule_id=(SELECT id FROM guard_rules WHERE rule_id=?) ORDER BY id DESC LIMIT 1",
        (RULE_ID,)).fetchone()
    if row:
        d = dict(row)
        check("事件的 pid 正是那个已退出的进程", d.get("pid") == kid, "库里 pid=%s / 实际 %s" % (d.get("pid"), kid))
        ev = json.loads(d.get("evidence") or "{}")
        check("证据里保留了命令行", bool(ev.get("cmdline")), str(ev.get("cmdline"))[:90])
        check("证据里带父进程", ev.get("ppid") is not None, "ppid=%s" % ev.get("ppid"))
    else:
        check("事件的 pid 正是那个已退出的进程", False, "库里没有 %s 的事件" % RULE_ID)

    print("\n== 6) 对照：轮询快照里确实没有这个 pid ==")
    snap = probes.collect(deep=False)
    pids = {x.get("pid") for x in snap.get("processes") or []}
    check("轮询快照不含该 pid（证明是事件源补的）", kid not in pids, "snapshot=%d 个进程" % len(pids))

    print("\n== 7) 稳定性 ==")
    wl = engine.run_once(deep=False, trigger="manual")
    check("第二轮仍稳定", not wl.get("errors"), wl.get("errors"))
    watcher.stop()
    time.sleep(0.5)
    check("停止后事件源确实停了", watcher.status().get("running") is False)

    drop_rule()
    print("\n失败项：%d" % len(FAIL))
    for f in FAIL:
        print("  -", f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
