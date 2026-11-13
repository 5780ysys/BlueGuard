# -*- coding: utf-8 -*-
"""防护引擎冒烟测试：清库重建 -> 跑一轮 -> 看命中/耗时/联动。"""
import json
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA = os.path.join(os.environ.get("TEMP", "."), "bg_guard_test")
if "--fresh" in sys.argv and os.path.isdir(DATA):
    shutil.rmtree(DATA, ignore_errors=True)
os.environ["BLUEGUARD_DATA"] = DATA

from backend import schema          # noqa: E402
schema.migrate()

from backend.db import connect      # noqa: E402
from backend import guard           # noqa: E402

print("init:", guard.init())
c = connect()
print("rules in db:", c.execute("select count(*) n from guard_rules").fetchone()["n"],
      "enabled:", c.execute("select count(*) n from guard_rules where enabled=1").fetchone()["n"])

t = time.time()
st = guard.run_once(deep=("--deep" in sys.argv))
print("round1 %.2fs" % (time.time() - t))
print("stats:", json.dumps({k: v for k, v in st.items() if k != "events"}, ensure_ascii=False))

rows = c.execute("SELECT rule_name,severity,count(*) n FROM guard_events GROUP BY rule_name ORDER BY n DESC").fetchall()
for r in rows:
    print("  HIT", r["n"], r["severity"], r["rule_name"])

t = time.time()
st2 = guard.run_once(deep=False)
print("round2 %.2fs hits=%s merged=%s" % (time.time() - t, st2["hits"], st2["merged"]))
print("alerts:", c.execute("select count(*) n from log_alerts").fetchone()["n"],
      "incidents:", c.execute("select count(*) n from incidents").fetchone()["n"],
      "baseline:", c.execute("select count(*) n from guard_baseline").fetchone()["n"])
print("posture sample:", c.execute("select detail from guard_events where category='posture' limit 2").fetchall())
