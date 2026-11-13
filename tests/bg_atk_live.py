# -*- coding: utf-8 -*-
"""真实主机一轮扫描：跑扩充后的规则集，看耗时、命中、有没有噪声爆炸。"""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ["BLUEGUARD_DATA"] = os.path.join(os.environ["TEMP"], "bg_atk_live")

from backend import schema                     # noqa: E402
from backend.db import connect                 # noqa: E402
from backend.guard import engine, policy, rules  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

schema.migrate()
info = engine.init() if hasattr(engine, "init") else None
rules.ensure_seed()
policy.ensure_seed()

db = connect()
print("规则总数:", db.execute("SELECT COUNT(*) FROM guard_rules").fetchone()[0],
      "启用:", db.execute("SELECT COUNT(*) FROM guard_rules WHERE enabled=1").fetchone()[0],
      "链模板:", db.execute("SELECT COUNT(*) FROM guard_rules WHERE category='chain'").fetchone()[0])
print("策略:", policy.get_policy())

for i, deep in enumerate((True, False), 1):
    t0 = time.time()
    st = engine.run_once(deep=deep, trigger="selftest")
    cost = time.time() - t0
    print("\n--- round %d (deep=%s) %.2fs ---" % (i, deep, cost))
    print("采集: proc=%s conn=%s listen=%s persist=%s" % (
        st.get("proc"), st.get("conn"), st.get("listen"), st.get("persist")))
    print("命中=%s 合并=%s 链=%s 响应=%s new_faces=%s errors=%s" % (
        st.get("hits"), st.get("merged"), st.get("chains"), st.get("responses"),
        st.get("new_faces"), st.get("errors")))

rows = db.execute(
    "SELECT id, rule_name, severity, category, subject, detail FROM guard_events ORDER BY id").fetchall()
print("\n事件数 %d:" % len(rows))
for r in rows:
    print("  [%s] %-28s %s" % (r["severity"], r["rule_name"][:28], (r["detail"] or "")[:90]))
print("\n告警:", db.execute("SELECT COUNT(*) FROM log_alerts WHERE rule_name LIKE '[防护]%'").fetchone()[0],
      " 事件单:", db.execute("SELECT COUNT(*) FROM incidents WHERE title LIKE '[防护]%'").fetchone()[0])
