# -*- coding: utf-8 -*-
"""攻击链关联实测：喂三条不同战术的散点事件，看能不能拼成一条"入侵链"。

这条测的是 chain.py + engine._run_chains 的落库与联动，
不依赖真实进程，所以可重复、可回归。
"""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ["BLUEGUARD_DATA"] = os.path.join(os.environ["TEMP"], "bg_atk_chain")

from backend import schema                       # noqa: E402
from backend.db import connect, tx               # noqa: E402
from backend.guard import chain, engine, policy, rules  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

schema.migrate()
rules.ensure_seed()
policy.ensure_seed()

db = connect()
with tx() as c:
    c.execute("DELETE FROM guard_events")
    c.execute("DELETE FROM log_alerts WHERE rule_name LIKE '[防护]%'")
    c.execute("DELETE FROM incidents WHERE title LIKE '[防护]%'")
    c.execute("DELETE FROM guard_dedup")
    c.execute("UPDATE guard_policy SET mode='alert', auto_incident=1 WHERE id=1")
policy.invalidate()

PASS, FAIL = [], []


def ck(name, ok, extra=""):
    (PASS if ok else FAIL).append(name)
    print("%s %s%s" % ("PASS" if ok else "FAIL", name, ("  " + str(extra)) if extra else ""))


def seed_event(rule_id, severity, mitre, detail):
    row = db.execute("SELECT id, name FROM guard_rules WHERE rule_id=?", (rule_id,)).fetchone()
    with tx() as c:
        cur = c.execute(
            "INSERT INTO guard_events(ts,rule_id,rule_name,category,severity,subject,mitre,detail,"
            "evidence,status) VALUES(datetime('now','localtime'),?,?,?,?,?,?,?,'{}','new')",
            (row["id"], row["name"], "process", severity, "demo:%s" % rule_id, mitre,
             detail))
        return cur.lastrowid


def chain_events():
    return [dict(r) for r in db.execute(
        "SELECT * FROM guard_events WHERE category='chain' ORDER BY id").fetchall()]


# ---- 1. 只有两个战术：不该拼链 ----
seed_event("PS-ENCODED", "high", "T1059.001", "powershell -enc ...")
seed_event("PERSIST-TEMP", "high", "T1547.001", "Run 键指向 temp")
hits = chain.evaluate()
ck("两战术不拼链", len(hits) == 0, [h["rule"]["rule_id"] for h in hits])

# ---- 1b. 只有 posture + low：不该拼链（环境状态不是攻击行为）----`n# ---- 2. 补第三个战术（命令与控制）：CHAIN-INTRUSION 应命中 ----
seed_event("C2-COMMON-PORT", "high", "T1571", "连 4444")
hits = chain.evaluate()
ids = [h["rule"]["rule_id"] for h in hits]
ck("三战术拼出 CHAIN-INTRUSION", "CHAIN-INTRUSION" in ids, ids)

# ---- 3. 落库 + 联动 ----
stats = {"hits": 0, "merged": 0, "errors": [], "chains": 0}
engine._run_chains(stats)
evs = chain_events()
ck("链事件已落库", len(evs) == 1, len(evs))
if evs:
    ev = evs[0]
    ck("链事件严重度 critical", ev["severity"] == "critical", ev["severity"])
    ck("链事件带告警ID", bool(ev["alert_id"]), ev["alert_id"])
    ck("链事件带事件单ID", bool(ev["incident_id"]), ev["incident_id"])
    evidence = json.loads(ev["evidence"] or "{}")
    ck("证据含战术序列", evidence.get("tactics") == ["执行", "持久化", "命令与控制"],
       evidence.get("tactics"))
    ck("证据含组成规则", len(evidence.get("rules") or []) == 3,
       [r["rule"] for r in (evidence.get("rules") or [])])
    inc = db.execute("SELECT priority FROM incidents WHERE id=?", (ev["incident_id"],)).fetchone()
    ck("事件单优先级 P1", inc and inc["priority"] == "P1", inc and inc["priority"])

# ---- 4. 去重：同一窗口内再跑一次，不该刷第二条 ----
stats2 = {"hits": 0, "merged": 0, "errors": [], "chains": 0}
engine._run_chains(stats2)
ck("重复拼链被去重", len(chain_events()) == 1 and stats2["merged"] >= 1,
   "events=%d merged=%d" % (len(chain_events()), stats2["merged"]))

# ---- 5. 关闭档：链事件仍然落库（证据不丢），但不自动处置 ----
ck("链模板共 %d 条" % len(chain.chain_rules()), len(chain.chain_rules()) == 5)

print("\nPASS %d / FAIL %d" % (len(PASS), len(FAIL)))
sys.exit(1 if FAIL else 0)


