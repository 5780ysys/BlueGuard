# -*- coding: utf-8 -*-
"""BlueGuard Guard Core —— 主机主动防护引擎（V3.0）。

分层：
    probes  —— 只读采集（进程/连接/监听/启动项/主机姿态）
    rules   —— 条件 DSL + 内置 Sigma 化规则
    policy  —— 模式、白名单、自保护、限速
    respond —— 可回滚的响应动作（防火墙封 IP / 阻断程序出站 / 封端口 / 结束进程）
    engine  —— 主循环 + 去重 + 联动（告警台 / 应急 / 封禁对账 / 审计）

对外只暴露 init()/start()/stop()/status()/run_once()。
"""
from . import engine, mitre, policy, probes, respond, rules  # noqa: F401
from .engine import run_once, start, status, stop  # noqa: F401


def init():
    """应用启动时调用：建表种子 + 策略种子 + 白名单 + 规则。"""
    from ..db import connect
    conn = connect()
    policy.ensure_seed(conn)
    rules.ensure_seed(conn)
    pol = policy.get_policy(refresh=True)
    if pol.get("autostart"):
        start()
    return {"mode": pol.get("mode"), "autostart": bool(pol.get("autostart")),
            "rules": len(rules.load_rules(conn))}


__all__ = ["init", "start", "stop", "status", "run_once",
           "engine", "mitre", "policy", "probes", "respond", "rules"]
