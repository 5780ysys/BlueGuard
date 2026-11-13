# -*- coding: utf-8 -*-
"""进程创建事件监听器（WMI 事件源，V3.2）。

为什么需要它
------------
主循环按 `interval_sec`（默认 8 秒）轮询进程表。存活不到 8 秒的进程在两次采样
之间生灭，轮询永远看不到——而这恰恰是大量攻击行为的特征：编码命令、一次性下载器、
`cmd /c` 横向工具、脚本 host 的短命子进程。

本模块用 WMI 的 `__InstanceCreationEvent` 订阅进程创建（WQL 轮询间隔 1 秒，
由 WMI 服务在进程内完成，不需要管理员权限，也不需要改任何系统审核策略），
把捕获到的进程立刻交给规则引擎判定。

实测（普通权限 S-1-16-8192）：能抓到存活约 1 秒的 `cmd.exe /c ping ...` 与
其子进程 `PING.EXE`，并带完整命令行；同一时刻的 8 秒轮询完全看不到这些进程。

边界：WQL 的 `WITHIN 1` 是 1 秒粒度，存活 < 1 秒的进程仍可能漏；这是「从 8 秒
降到 1 秒」的改善，不是 ETW 那种零漏报。要彻底解决需要 ETW
（Microsoft-Windows-Kernel-Process），那条路要管理员权限。
"""
import base64
import collections
import json
import os
import shutil
import subprocess
import threading
import time

_PWSH_CANDIDATES = (
    r"C:\Program Files\PowerShell\7\pwsh.exe",
    r"C:\Program Files\PowerShell\7-preview\pwsh.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
)

CREATE_NO_WINDOW = 0x08000000

# WQL 1 秒粒度；只订阅进程创建，不做进程结束（结束不参与判定）
_SCRIPT = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$q = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
$w = New-Object System.Management.ManagementEventWatcher($q)
while ($true) {
  try {
    $ev = $w.WaitForNextEvent()
    $t = $ev.TargetInstance
    $o = [ordered]@{
      pid     = [int]$t.ProcessId
      ppid    = [int]$t.ParentProcessId
      name    = [string]$t.Name
      exe     = [string]$t.ExecutablePath
      cmdline = [string]$t.CommandLine
      at      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }
    # 必须走 Console.Out + 显式 Flush：Write-Output 到管道是块缓冲，
    # 十几条短 JSON 会一直卡在缓冲区里，父进程读不到（实测踩过）。
    [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress))
    [Console]::Out.Flush()
  } catch {
    Start-Sleep -Milliseconds 500
  }
}
"""

_QUEUE = collections.deque(maxlen=4000)
_QLOCK = threading.Lock()
_STATE = {
    "running": False,
    "pid": None,
    "seen": 0,
    "dropped": 0,
    "restarts": 0,
    "orphans_killed": 0,
    "started_at": None,
    "last_event": None,
    "error": None,
}
_PROC = {"p": None}
_STOP = threading.Event()
_LT = {"t": None}


def _pwsh_path():
    for p in _PWSH_CANDIDATES:
        if p and os.path.exists(p):
            return p
    found = shutil.which("pwsh") or shutil.which("powershell")
    return found


def available():
    """事件源是否可用：依赖 PowerShell + System.Management（Win8 起内置）。"""
    p = _pwsh_path()
    return {"ok": bool(p), "powershell": p}


def _parent_of(ppid):
    """尽力补父进程名/路径 —— 大量规则靠父进程定性（Office→shell 等）。"""
    if not ppid:
        return None, None
    name = exe = None
    try:
        import psutil
        p = psutil.Process(int(ppid))
        try:
            name = p.name() or None
        except Exception:
            pass
        try:
            exe = p.exe() or None
        except Exception:
            pass
    except Exception:
        pass
    return name, exe


def _push(obj):
    with _QLOCK:
        if len(_QUEUE) >= _QUEUE.maxlen:
            _STATE["dropped"] += 1
        _QUEUE.append(obj)
    _STATE["seen"] += 1
    _STATE["last_event"] = obj.get("at")


def _reader(proc):
    """读子进程 stdout：每行一个 JSON 对象。"""
    try:
        for line in proc.stdout:
            line = (line or "").strip()
            if not line or not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            name, exe = d.get("name"), d.get("exe")
            if not name:
                continue
            pn, pe = _parent_of(d.get("ppid"))
            _push({
                "pid": d.get("pid"),
                "ppid": d.get("ppid"),
                "name": name,
                "exe": exe,
                "cmdline": d.get("cmdline") or "",
                "parent_name": pn,
                "parent_exe": pe,
                "source": "wmi",
                "at": d.get("at"),
            })
    except Exception as e:  # 管道被关掉是正常停机
        _STATE["error"] = "reader: %s" % e


def _enc():
    """本次订阅要用的 -EncodedCommand 串。"""
    import base64
    return base64.b64encode(_SCRIPT.encode("utf-16-le")).decode("ascii")


def _looks_like_subscription(cmd):
    """命令行是不是一个 WMI 进程订阅（而不是别的 powershell）。

    只比对本次的 base64 不够用：脚本改过一版，旧孤儿串就不同了，
    结果"上一版自己的采集器"反而漏掉。所以解码后看特征。
    """
    tokens = cmd.split()
    for i, tok in enumerate(tokens):
        low = tok.lower()
        if low in ("-encodedcommand", "-enc", "-e") and i + 1 < len(tokens):
            try:
                blob = tokens[i + 1]
                raw = base64.b64decode(blob).decode("utf-16-le", "ignore")
            except Exception:
                try:
                    raw = base64.b64decode(blob).decode("utf-8", "ignore")
                except Exception:
                    continue
            if "__InstanceCreationEvent" in raw or "ManagementEventWatcher" in raw:
                return True
    return "__InstanceCreationEvent" in cmd or "ManagementEventWatcher" in cmd


def _cleanup_orphans():
    """清掉上一次异常退出留下的订阅进程。

    真实踩坑：程序被强杀（Stop-Process / 任务管理器 / 崩溃）时，事件源的
    PowerShell 收不到停止信号，会卡在 WaitForNextEvent() 上一直活着。
    它的命令行就是一条 -EncodedCommand，界面重启后新引擎不认识这个 pid，
    于是"上一个自己的采集器"会被当成"编码命令执行"报出来。
    这里按"解码后是 WMI 订阅 + 父进程已死"双重确认，只杀自己家的，不碰别人的终端。
    """
    killed = 0
    try:
        import psutil
    except Exception:
        return 0
    for p in psutil.process_iter(["pid", "name", "cmdline", "ppid"]):
        try:
            info = p.info
            if (info.get("name") or "").lower() not in ("pwsh.exe", "powershell.exe"):
                continue
            cmd = " ".join(info.get("cmdline") or [])
            if not cmd or not _looks_like_subscription(cmd):
                continue
            ppid = info.get("ppid") or 0
            if ppid:
                try:
                    if psutil.Process(ppid).is_running():
                        continue          # 父进程还活着，说明是别人的在跑的订阅
                except Exception:
                    pass
            subprocess.run(["taskkill", "/PID", str(info["pid"]), "/T", "/F"],
                           capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=10)
            killed += 1
        except Exception:
            continue
    if killed:
        _STATE["orphans_killed"] = killed
    return killed


def _supervise():
    """起子进程 + 读线程；异常退出后自动重启（限频），直到 stop()。"""
    while not _STOP.is_set():
        pwsh = _pwsh_path()
        if not pwsh:
            _STATE["error"] = "找不到 PowerShell"
            return
        try:
            enc = _enc()
            proc = subprocess.Popen(
                [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-EncodedCommand", enc],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
                creationflags=CREATE_NO_WINDOW,
            )
        except Exception as e:
            _STATE["error"] = "spawn: %s" % e
            time.sleep(5)
            continue
        _PROC["p"] = proc
        _STATE["pid"] = proc.pid
        _STATE["error"] = None
        # 事件源自己的 PowerShell 命令行同样是"一条编码命令执行"，也会出现在
        # WMI 事件流里 —— 登记进自噬台账，别把自己的采集器当攻击者报出来。
        try:
            from .. import platform_win
            platform_win.note_spawned(proc.pid)
        except Exception:
            pass
        t = threading.Thread(target=_reader, args=(proc,), daemon=True, name="guard-wmi-reader")
        t.start()
        _LT["t"] = t
        t.join()
        if _PROC["p"] is None:      # stop() 已经收回
            return
        try:
            proc.terminate()
        except Exception:
            pass
        _STATE["pid"] = None
        if _STOP.is_set():
            return
        _STATE["restarts"] += 1
        time.sleep(3)


def start():
    if _STATE["running"]:
        return {"ok": True, "already": True, "pid": _STATE["pid"]}
    info = available()
    if not info["ok"]:
        return {"ok": False, "error": "NO_POWERSHELL", "detail": "找不到 PowerShell，无法订阅进程创建事件"}
    _STOP.clear()
    _STATE["running"] = True
    _STATE["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        _cleanup_orphans()
    except Exception:
        pass
    th = threading.Thread(target=_supervise, daemon=True, name="guard-wmi")
    th.start()
    time.sleep(0.6)          # 给子进程一点时间起来，首轮就能报真实状态
    return {"ok": True, "pid": _STATE["pid"], "powershell": info["powershell"]}


def stop():
    """停事件源，并且**确保子 PowerShell 真的死了**。

    踩坑：PowerShell 卡在 WaitForNextEvent() 时 terminate() 不一定能结束它，
    残留的孤儿 pwsh 命令行还是一条"编码命令执行"，下一轮就会被自己的规则报出来
    —— 既是误报，也是进程泄漏。所以 terminate 之后还要用 taskkill /T /F 兜底。
    """
    _STOP.set()
    p = _PROC.get("p")
    pid = _STATE["pid"]
    _PROC["p"] = None
    if p is not None:
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
                p.wait(timeout=2)
            except Exception:
                pass
    if pid:
        try:
            import psutil
            if psutil.pid_exists(int(pid)):
                subprocess.run(["taskkill", "/PID", str(int(pid)), "/T", "/F"],
                               capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=10)
        except Exception:
            pass
    _STATE["running"] = False
    _STATE["pid"] = None
    return {"ok": True}


def drain(limit=500):
    """取走队列里的进程创建事件（最多 limit 条），交规则引擎判定。"""
    out = []
    with _QLOCK:
        while _QUEUE and len(out) < limit:
            out.append(_QUEUE.popleft())
    return out


def peek(limit=200):
    """只看不取（诊断/自测用）：返回队列里最近的事件副本。"""
    with _QLOCK:
        items = list(_QUEUE)
    return items[-limit:]


def status():
    return {
        "available": available(),
        "running": _STATE["running"],
        "pid": _STATE["pid"],
        "seen": _STATE["seen"],
        "dropped": _STATE["dropped"],
        "queued": len(_QUEUE),
        "restarts": _STATE["restarts"],
        "orphans_killed": _STATE["orphans_killed"],
        "started_at": _STATE["started_at"],
        "last_event": _STATE["last_event"],
        "error": _STATE["error"],
        "granularity_sec": 1,
        "sample": [{"pid": x.get("pid"), "name": x.get("name"), "at": x.get("at")}
                   for x in peek(5)],
    }
