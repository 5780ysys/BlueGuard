# -*- coding: utf-8 -*-
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["BLUEGUARD_DATA"] = os.path.join(os.environ.get("TEMP", "."), "bg_guard_test")

import psutil  # noqa: E402
from backend.platform_win import _ps, guardsrc  # noqa: E402
from backend.guard import probes  # noqa: E402


def t(label, fn):
    s = time.time()
    r = fn()
    print("%-24s %6d ms  n=%s" % (label, (time.time() - s) * 1000,
                                  len(r) if hasattr(r, "__len__") else r))


t("process_iter(full)", lambda: [p.info for p in psutil.process_iter(["pid", "name", "exe", "ppid", "username", "create_time", "cmdline"])])
t("process_iter(light)", lambda: [p.info for p in psutil.process_iter(["pid", "name", "ppid"])])
t("net_connections", lambda: psutil.net_connections(kind="inet"))


def cim():
    script = ("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | "
              "ConvertTo-Json -Depth 2 -Compress")
    d, e, rc = _ps(script, timeout=40)
    return d or []


t("CIM Win32_Process", cim)
t("autostart", guardsrc.get_autostart)
t("posture", guardsrc.get_host_posture)
t("collect(deep)", lambda: probes.collect(deep=True))
