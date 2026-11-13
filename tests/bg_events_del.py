# -*- coding: utf-8 -*-
"""事件的删除与批量清理：单条删、按状态批量删、清空，以及审计是否还站得住。

为什么要单独测：删除和"审计哈希链"是天生对立的两个需求——
台账要求可追溯、界面要求能清干净。这里的取舍是：
  - 事件本身可以删（它是引擎的观察结果，不是法律凭证）
  - 处置留痕 guard_responses 一律保留（那是"谁在什么时候封了哪个 IP"）
  - 每次删除都写一条审计，且不能把哈希链写坏

最后一条踩过真坑：audit.append 用 `str(target_id or "")` 拼哈希，
遇到 target_id=0（批量操作没有具体对象）时，`0 or ""` 变成空串，
而库里存的是 "0"，于是写入时算一次、校验时算一次，两个哈希对不上，
整条链报"内容被篡改"。现在统一走 audit._s()。

跑法（需要先起服务）：
    set BLUEGUARD_DATA=%TEMP%\\bg_evdel
    python -m uvicorn backend.app:app --host 127.0.0.1 --port 18100
    python tests\\bg_events_del.py
"""
import json
import os
import sys
import urllib.error
import urllib.request
import http.cookiejar

BASE = os.environ.get("BASE", "http://127.0.0.1:18100")
FAIL = []

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def call(path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with op.open(req, timeout=90) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def ck(label, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + label + (("  " + str(extra)) if extra else ""))
    if not cond:
        FAIL.append(label)


def main():
    call("/api/guard/run", "POST", {"deep": True})
    st, ev = call("/api/guard/events?size=50")
    total0 = ev["total"]
    ids = [x["id"] for x in ev["items"]]
    ck("有事件可删", total0 > 0, "total=%d" % total0)
    if not total0:
        print("\n失败项：1")
        return 1

    # 单条删除
    one = ids[0]
    st, r = call("/api/guard/events/%d" % one, "DELETE")
    ck("删单条 200", st == 200 and r.get("deleted") == 1, r)
    st, ev = call("/api/guard/events?size=50")
    ck("总数减一", ev["total"] == total0 - 1, "now=%d" % ev["total"])
    ck("删掉的 id 不在了", one not in [x["id"] for x in ev["items"]])
    st, r = call("/api/guard/events/%d" % one, "DELETE")
    ck("重复删返回 404", st == 404, r)

    # 按状态批量删
    for i, s in enumerate(["closed", "false_positive"]):
        call("/api/guard/events/%d/status" % ids[1 + i], "POST", {"status": s})
    st, r = call("/api/guard/events/purge", "POST", {"mode": "closed"})
    ck("删已关闭", st == 200 and r.get("deleted") >= 1, r)
    st, r = call("/api/guard/events/purge", "POST", {"mode": "false_positive"})
    ck("删误报", st == 200 and r.get("deleted") >= 1, r)
    st, r = call("/api/guard/events/purge", "POST", {"mode": "bogus"})
    ck("非法 mode 400", st == 400, r.get("detail"))

    # listed 模式
    st, ev = call("/api/guard/events?size=50")
    left = [x["id"] for x in ev["items"]]
    if left:
        st, r = call("/api/guard/events/purge", "POST", {"mode": "listed", "ids": [left[0]]})
        ck("按 id 列表删", st == 200 and r.get("deleted") == 1, r)
    st, r = call("/api/guard/events/purge", "POST", {"mode": "listed", "ids": []})
    ck("空 id 列表 400", st == 400, r.get("detail"))

    # 清空
    st, r = call("/api/guard/events/purge", "POST", {"mode": "all"})
    ck("清空全部", st == 200 and r.get("deleted") > 0, r)
    st, ev = call("/api/guard/events?size=10")
    ck("列表已空", ev["total"] == 0, "total=%d" % ev["total"])

    # 删除不能打断审计链（这里就是踩坑点）
    st, a = call("/api/audit?size=20")
    acts = [x.get("action") for x in (a.get("items") or [])]
    ck("审计有删除留痕", any(x in acts for x in ("guard.event.delete", "guard.event.purge")), acts[:5])
    st, h = call("/api/health")
    au = h.get("audit") or {}
    ck("审计链仍完整", au.get("ok") is True, "rows=%s bad=%s %s" % (au.get("rows"), au.get("bad"), au.get("detail")))

    print("\n失败项：%d" % len(FAIL))
    for f in FAIL:
        print("  -", f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
