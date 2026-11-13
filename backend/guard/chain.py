# -*- coding: utf-8 -*-
"""攻击链关联：把散点事件拼成意图。

为什么要这一层：
    单条事件只说明「这一步可疑」。HOST-RECON 单看是运维，LSASS-DUMP 单看是管理员在排查，
    LATERAL-TOOL 单看可能是测试同事。但三者在半小时里依次出现，就不是巧合了 ——
    **攻击是序列，不是点**。判定一个人想干什么，靠的是战术覆盖，不是那条告警本身多严重。

实现：
    链模板存在 guard_rules 里（category='chain'），condition 描述「必须出现哪些战术」。
    主循环不会对它们求值（candidates 返回空），它们只给这一层用。
    本模块只做判定、不写库 —— 落库与联动交给 engine，避免循环引用。
"""
import json
import time

from ..db import connect
from . import mitre

WINDOW_SEC = 1800          # 30 分钟滑窗：短于真实的攻击节奏，长于一次运维脚本
MAX_EVENTS = 2000          # 单轮最多回看的事件数，防止大库拖慢
DEAD_STATUS = ("closed", "false_positive", "escalated")   # 已定性的事件不再参与拼链

# 什么样的证据才有资格参与拼链：
#   - 只认 high / critical：low 级的"启动目录有个 .vbs"能凑齐战术，但它证明不了任何意图
#   - 排除 posture：防火墙本来就没开、Defender 本来就被关，这是环境状态不是攻击行为；
#     实测把它们算进去，一台普通开发机就能拼出一条 critical 的"疑似主机入侵链"假阳性
CHAIN_MIN_SEV = ("high", "critical")
CHAIN_EXCLUDE_CATEGORY = ("posture",)


def recent_events(conn, window_sec=WINDOW_SEC):
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - window_sec))
    sql = (
        "SELECT id, ts, rule_name, category, severity, mitre, subject, remote_ip, pid "
        "FROM guard_events WHERE ts >= ? AND status NOT IN (%s) "
        "AND severity IN (%s) AND category NOT IN (%s) ORDER BY id DESC LIMIT %d"
        % (",".join("?" * len(DEAD_STATUS)),
           ",".join("?" * len(CHAIN_MIN_SEV)),
           ",".join("?" * len(CHAIN_EXCLUDE_CATEGORY)),
           MAX_EVENTS))
    args = (since,) + DEAD_STATUS + CHAIN_MIN_SEV + CHAIN_EXCLUDE_CATEGORY
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def chain_rules(conn=None):
    conn = conn or connect()
    return [dict(r) for r in conn.execute(
        "SELECT * FROM guard_rules WHERE category='chain' AND enabled=1 ORDER BY id").fetchall()]


def _tactic_buckets(events):
    """按战术分桶。未分类的（没配 ATT&CK 的）不参与，避免噪声抬高链分。"""
    buckets = {}
    for e in events:
        tac = mitre.tactic(e.get("mitre"))
        if tac == "未分类":
            continue
        buckets.setdefault(tac, []).append(e)
    return buckets


def evaluate(conn=None, window_sec=WINDOW_SEC):
    """返回命中的链（只判定不落库）。

    每条命中: {rule(链规则行), tactics[命中战术], rules[组成事件摘要], event_count}
    """
    conn = conn or connect()
    events = recent_events(conn, window_sec)
    if len(events) < 2:
        return []
    buckets = _tactic_buckets(events)
    if len(buckets) < 2:
        return []

    out = []
    for rule in chain_rules(conn):
        try:
            cond = json.loads(rule.get("condition") or "{}")
        except Exception:
            continue
        require = cond.get("require") or []
        boost = cond.get("boost") or []
        min_tactics = int(cond.get("min_tactics") or max(2, len(require)))
        if not require:
            continue
        if any(t not in buckets for t in require):
            continue
        if len(buckets) < min_tactics:
            continue

        chosen = [t for t in require]
        for t in boost:
            if t in buckets and t not in chosen:
                chosen.append(t)
        # 按战术顺序排，报告里读起来就是一条时间线
        chosen.sort(key=lambda t: mitre.TACTIC_ORDER.index(t)
                    if t in mitre.TACTIC_ORDER else 99)

        seen, composed = set(), []
        for tac in chosen:
            for e in buckets[tac]:
                if e["rule_name"] in seen:
                    continue
                seen.add(e["rule_name"])
                composed.append({
                    "rule": e["rule_name"], "severity": e["severity"], "tactic": tac,
                    "event_id": e["id"], "ts": e.get("ts"),
                    "subject": e.get("subject"), "remote_ip": e.get("remote_ip"),
                })
        out.append({
            "rule": rule,
            "tactics": chosen,
            "rules": composed[:30],
            "event_count": sum(len(buckets[t]) for t in chosen),
        })
    return out


def summary_line(hit):
    """给事件 detail 用的一句话。"""
    return "%d 个战术 / %d 条事件：%s" % (
        len(hit["tactics"]), hit["event_count"], " → ".join(hit["tactics"]))
