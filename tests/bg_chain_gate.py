# -*- coding: utf-8 -*-
"""链的证据门槛实测：姿态/低危/below-high 事件不得参与拼链。

背景（真实发生过的误报）：一台普通开发机上，防火墙本来就关着、启动目录里有 6 个用户自己的
.vbs，旧逻辑把这些算进战术桶，直接拼出一条 critical 的「疑似主机入侵链」。
现在链只吃 high/critical 且排除 posture，这里逐级验证门槛确实生效。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["BLUEGUARD_DATA"] = os.path.join(os.environ["TEMP"], "bg_chain_gate")

from backend import schema                        # noqa: E402
from backend.db import connect, tx                # noqa: E402
from backend.guard import chain, policy, rules    # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

schema.migrate()
rules.ensure_seed()
policy.ensure_seed()

# 统一在一个临时库里做，先清空事件
db = connect()
with tx() as c:
    c.execute("DELETE FROM guard_events")
policy.invalidate()

PASS, FAIL = [], []


def ck(n, ok, extra=""):
    (PASS if ok else FAIL).append(n)
    print("%s %s%s" % ("PASS" if ok else "FAIL", n, ("  " + str(extra)) if extra else ""))


def seed(rule_id, severity, mitre, category="process", detail=""):
    row = db.execute("SELECT id, name FROM guard_rules WHERE rule_id=?", (rule_id,)).fetchone()
    with tx() as c:
        c.execute(
            "INSERT INTO guard_events(ts,rule_id,rule_name,category,severity,subject,mitre,"
            "detail,evidence,status) VALUES(datetime('now','localtime'),?,?,?,?,?,?,?,'{}','new')",
            (row["id"], row["name"], category, severity, "t:%s" % rule_id, mitre, detail))


def ids():
    return [h["rule"]["rule_id"] for h in chain.evaluate()]


# 1) 只有姿态类（firewall off / defender off，都是 high）+ 低危启动项 + 监听暴露（medium）
seed("FIREWALL-OFF", "high", "T1562.004", "posture")
seed("DEFENDER-OFF", "high", "T1562.001", "posture")
seed("PERSIST-LNK-LOLBIN", "low", "T1547.001", "persist")
seed("LISTEN-ADMIN-EXPOSED", "medium", "T1205", "listen")
ck("姿态+低危+中危 不拼链", ids() == [], ids())

# 2) 加一条 high 的执行事件 → 只剩「执行」一个战术，仍不拼
seed("PS-ENCODED", "high", "T1059.001")
ck("单个 high 执行 不拼链", ids() == [], ids())

# 3) 再加一条 high 的防御规避 → 执行 + 防御规避 = 2 战术，但 CHAIN-DEFENSE-TAMPER 要求 3 个
seed("PS-HIDDEN", "high", "T1564.003")
ck("两战术（执行+规避）不拼链", ids() == [], ids())

# 4) 补第三个战术（命令与控制）→ CHAIN-DEFENSE-TAMPER 命中
seed("C2-COMMON-PORT", "high", "T1571", "conn")
got = ids()
ck("三战术拼出 CHAIN-DEFENSE-TAMPER", "CHAIN-DEFENSE-TAMPER" in got, got)

# 5) 已定性（false_positive）的事件退出链路
with tx() as c:
    c.execute("UPDATE guard_events SET status='false_positive' WHERE mitre='T1571'")
ck("误报定性后链随之消失", ids() == [], ids())

print("\nPASS %d / FAIL %d" % (len(PASS), len(FAIL)))
sys.exit(1 if FAIL else 0)
