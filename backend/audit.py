# -*- coding: utf-8 -*-
"""审计哈希链。

每行：payload_hash = sha256(seq|ts|actor|action|target_type|target_id|before|after|prev_hash)
链式串接 prev_hash -> payload_hash。配合 schema 里的只增触发器，实现：
  - 改任何一行的业务字段 -> 该行 payload_hash 校验失败
  - 删任何一行 -> 后继行的 prev_hash 断链
  - 数据库层面 UPDATE/DELETE 直接被 RAISE(ABORT) 拒绝

能力边界（诚实说明，对应设计文档 §9.7）：
  - 只防"库内篡改"，不防"整个库被替换"。链尾需每日锚点外存才能防整体重放。
  - 因此提供 anchor() 输出链尾摘要，供外部留存。
"""
import hashlib
import json

GENESIS = "0" * 64


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _s(v) -> str:
    """把参与哈希的字段统一成字符串。

    不能写成 `str(v or "")`：`0`、`False`、`""` 都是 falsy，会被 `or` 换成空串，
    而库里存的却是 "0" / "False" —— 于是写入时算一次、校验时算一次，两个哈希
    对不上，整条链报"内容被篡改"。这个坑是被 target_id=0（批量操作没有具体对象）
    触发的，实测 8 行审计里 6 行校验失败。
    """
    return "" if v is None else str(v)


def _payload(seq, ts, actor, action, target_type, target_id, before_val, after_val, prev_hash) -> str:
    raw = "|".join([
        _s(seq), _s(ts), _s(actor), _s(action),
        _s(target_type), _s(target_id),
        _s(before_val), _s(after_val), _s(prev_hash),
    ])
    return _sha(raw)


def tail(conn):
    row = conn.execute(
        "SELECT seq, payload_hash FROM audit_logs ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    if not row:
        return 0, GENESIS
    return row["seq"], row["payload_hash"]


def append(conn, actor, action, target_type=None, target_id=None,
           before_val=None, after_val=None, trace_id=None):
    """追加一条审计记录。不发 commit，由调用方事务控制。"""
    seq, prev_hash = tail(conn)
    seq += 1
    ts_row = conn.execute("SELECT datetime('now','localtime')").fetchone()[0]
    b = before_val if isinstance(before_val, str) else json.dumps(before_val, ensure_ascii=False, sort_keys=True) if before_val is not None else None
    a = after_val if isinstance(after_val, str) else json.dumps(after_val, ensure_ascii=False, sort_keys=True) if after_val is not None else None
    ph = _payload(seq, ts_row, actor, action, target_type, target_id, b, a, prev_hash)
    conn.execute(
        """INSERT INTO audit_logs(seq, ts, actor, action, target_type, target_id,
                                   before_val, after_val, prev_hash, payload_hash, trace_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (seq, ts_row, actor, action, target_type,
         None if target_id is None else str(target_id),
         b, a, prev_hash, ph, trace_id),
    )
    return seq, ph


def verify(conn):
    """全链校验。返回 (ok, 总行数, 首个断裂位置或 None, 详情)。"""
    rows = conn.execute(
        "SELECT id, seq, ts, actor, action, target_type, target_id, "
        "before_val, after_val, prev_hash, payload_hash FROM audit_logs ORDER BY seq ASC"
    ).fetchall()
    prev = GENESIS
    expect_seq = 1
    for r in rows:
        if r["seq"] != expect_seq:
            return False, len(rows), r["seq"], "序号断裂：期望 %d，实际 %d" % (expect_seq, r["seq"])
        if r["prev_hash"] != prev:
            return False, len(rows), r["seq"], "哈希链断裂：prev_hash 不匹配"
        calc = _payload(r["seq"], r["ts"], r["actor"], r["action"], r["target_type"],
                        r["target_id"], r["before_val"], r["after_val"], r["prev_hash"])
        if calc != r["payload_hash"]:
            return False, len(rows), r["seq"], "内容被篡改：payload_hash 不匹配"
        prev = r["payload_hash"]
        expect_seq += 1
    return True, len(rows), None, "全链完整"


def anchor(conn):
    """输出链尾锚点，供外部留存（防整库替换）。"""
    seq, ph = tail(conn)
    total = conn.execute("SELECT count(*) FROM audit_logs").fetchone()[0]
    return {
        "seq": seq,
        "head_hash": ph,
        "total_rows": total,
        "anchor_digest": _sha("%d|%s|%d" % (seq, ph, total)),
    }
