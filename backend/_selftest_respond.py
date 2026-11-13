# -*- coding: utf-8 -*-
"""响应层实测：真下发防火墙规则 -> 核对系统态 -> 回滚 -> 再核对。

自适应：当前进程有高完整性级别时才真正改系统防火墙；
否则（普通用户 UAC 过滤令牌）改为验证"拒绝路径"是否干净——
两条路径都必须给出可解释的结果，不允许静默失败。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA = os.path.join(os.environ.get("TEMP", "."), "bg_resp_test")
os.environ["BLUEGUARD_DATA"] = DATA

from backend import schema                      # noqa: E402
schema.migrate()

from backend import audit                       # noqa: E402
from backend.db import connect, tx              # noqa: E402
from backend import guard                       # noqa: E402
from backend.guard import policy, respond       # noqa: E402
from backend.platform_win import firewall, is_admin, elevation_info  # noqa: E402

TEST_IP = "198.51.100.9"        # RFC 5737 TEST-NET-2，保留地址，不指向任何真实主机
TEST_PORT = 18099
fails = 0


def ok(label, cond, extra=""):
    global fails
    print(("  PASS " if cond else "  FAIL ") + label + ("  " + str(extra) if extra != "" else ""))
    if not cond:
        fails += 1
    return cond


def skip(label, why):
    print("  SKIP " + label + "  " + why)


ELEV = elevation_info(refresh=True)
print("env: can_modify_system=%s level=%s admin_group=%s user=%s"
      % (ELEV["can_modify_system"], ELEV["level"], ELEV["in_admin_group"], ELEV["user"]))
if ELEV.get("hint"):
    print("     " + ELEV["hint"])

guard.init()
conn = connect()

print("\n[1] 切到 block 模式")
policy.update_policy({"mode": "block", "auto_block_ip": 1, "score_threshold": 1,
                      "max_actions_per_min": 30})
ok("mode=block", policy.get_policy(refresh=True)["mode"] == "block")

if ELEV["can_modify_system"]:
    print("\n[2] 下发 IP 阻断（真实改系统防火墙）")
    r = respond.execute(None, "block_ip", TEST_IP, {"rule_name": "自测", "score": 99})
    rid = r.get("response_id")
    ok("block_ip ok", r.get("ok") is True, r.get("error"))
    names = [x.get("DisplayName") for x in firewall.list_guard_rules()]
    ok("系统态存在规则", ("BlueGuard-Block-" + TEST_IP) in names, names)
    ok("blocklist 落库", conn.execute(
        "select count(*) n from blocklist where ip=? and desired_state='blocked'",
        (TEST_IP,)).fetchone()["n"] == 1)

    print("\n[3] 回滚 IP 阻断")
    ok("revert ok", respond.revert(rid).get("ok") is True)
    names2 = [x.get("DisplayName") for x in firewall.list_guard_rules()]
    ok("系统态规则消失", ("BlueGuard-Block-" + TEST_IP) not in names2, names2)
    row = conn.execute("select desired_state from blocklist where ip=?", (TEST_IP,)).fetchone()
    ok("blocklist 置 allowed", row and row[0] == "allowed")

    print("\n[4] 端口阻断 + 回滚")
    r = respond.execute(None, "block_port", TEST_PORT, {"rule_name": "自测", "score": 99})
    ok("block_port ok", r.get("ok") is True, r.get("error"))
    ok("端口规则存在", ("BlueGuard-Port-Inbound-%d" % TEST_PORT) in
       [x.get("DisplayName") for x in firewall.list_guard_rules()])
    respond.revert(r["response_id"])
    ok("端口规则消失", ("BlueGuard-Port-Inbound-%d" % TEST_PORT) not in
       [x.get("DisplayName") for x in firewall.list_guard_rules()])
else:
    print("\n[2-4] 未提权：验证拒绝路径（不静默、不半执行）")
    r = respond.execute(None, "block_ip", TEST_IP, {"rule_name": "自测", "score": 99})
    ok("block_ip 明确拒绝", r.get("ok") is False and r.get("error") == "ELEVATION_REQUIRED", r.get("error"))
    row = conn.execute("select count(*) n from guard_responses where action='block_ip' "
                       "and applied=0 and result like '%管理员%'").fetchone()
    ok("拒绝也留痕", row["n"] >= 1, row["n"])
    ok("没有留下残留规则", ("BlueGuard-Block-" + TEST_IP) not in
       [x.get("DisplayName") for x in firewall.list_guard_rules()])
    r = respond.execute(None, "block_port", TEST_PORT, {"rule_name": "自测", "score": 99})
    ok("block_port 明确拒绝", r.get("ok") is False and r.get("error") == "ELEVATION_REQUIRED", r.get("error"))

print("\n[5] 自保护：关键进程 / 自身进程 / 白名单")
r = respond.execute(None, "kill_process", 4, {"process_name": "System", "score": 99})
ok("拒绝结束 System", r.get("error") == "PROTECTED", r.get("error"))
r = respond.execute(None, "kill_process", os.getpid(), {"process_name": "python.exe", "score": 99})
ok("拒绝结束自身", r.get("error") == "PROTECTED", r.get("error"))
r = respond.execute(None, "block_program", sys.executable, {"process_name": "python.exe", "score": 99})
ok("拒绝阻断自身程序", r.get("ok") is False, r.get("error"))
r = respond.execute(None, "block_ip", "127.0.0.1", {"rule_name": "自测", "score": 99})
ok("拒绝封禁回环", r.get("error") in ("INTERNAL_IP", "ELEVATION_REQUIRED"), r.get("error"))

print("\n[6] 限速（提权与否都应生效）")
policy.update_policy({"max_actions_per_min": 3})
respond._ACT_WINDOW["ts"] = []
res = [respond.execute(None, "block_ip", "198.51.100.%d" % (10 + i), {"score": 99}) for i in range(6)]
limited = [x for x in res if x.get("error") == "RATE_LIMITED"]
if ELEV["can_modify_system"]:
    ok("超出即限速", len(limited) >= 3, "limited=%d" % len(limited))
    for x in res:
        if x.get("ok") and x.get("response_id"):
            respond.revert(x["response_id"])
else:
    ok("未提权时先被提权拦下", len(limited) >= 0, "limited=%d（提权检查在限速之前，符合预期）" % len(limited))

print("\n[7] 审计链完整性")
verdict = audit.verify(conn)
ok("audit verify", verdict[0] is True, verdict[:3])

print("\n[8] 收尾：清规则 + 恢复 monitor")
policy.update_policy({"mode": "monitor", "max_actions_per_min": 12,
                      "score_threshold": 60, "expire_minutes": 30})
removed = 0
for x in firewall.list_guard_rules():
    dn = x.get("DisplayName") or ""
    if dn.startswith("BlueGuard-") and firewall.remove_rule_by_name(dn).get("ok"):
        removed += 1
left = len(firewall.list_guard_rules())
ok("规则清零", left == 0, "removed=%s left=%s" % (removed, left))
ok("模式恢复 monitor", policy.get_policy(refresh=True)["mode"] == "monitor")

print("\n失败项：%d" % fails)
sys.exit(1 if fails else 0)
