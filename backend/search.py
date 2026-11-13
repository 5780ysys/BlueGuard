# -*- coding: utf-8 -*-
"""检索层：FTS5 trigram + LIKE 兜底。

修复评估报告 §3.1 的两个真实缺陷：
  1. trigram 以 3 字符为窗口，中文两字词（登录/失败/告警）命中 0 —— 假阴性
  2. 含点号的 token（IP）直接进 MATCH 会抛 fts5 syntax error —— 接口 500

策略（确定性，无歧义）：
  - 关键词去引号后 len >= 3：先用 FTS5，命中则返回；未命中再 LIKE 兜底
  - len < 3：直接 LIKE 兜底（trigram 必然搜不到）
  - 所有 FTS5 查询强制包双引号
"""
import re

MIN_FTS_LEN = 3


def _clean(kw: str) -> str:
    return (kw or "").strip().replace('"', "")


def search_logs(conn, keyword: str = "", limit: int = 50, offset: int = 0,
                host: str = "", src_ip: str = "", level: str = ""):
    """返回 (rows, total, mode)。mode 说明走了哪条路，便于前端展示与排障。"""
    kw = _clean(keyword)
    limit = max(1, min(int(limit or 50), 500))
    offset = max(0, int(offset or 0))

    where = []
    params = []

    if kw:
        if len(kw) >= MIN_FTS_LEN:
            # 尝试 FTS5：强制加引号，规避点号语法错
            try:
                n = conn.execute(
                    "SELECT count(*) FROM logs_fts WHERE logs_fts MATCH ?",
                    ('"%s"' % kw,),
                ).fetchone()[0]
                if n:
                    base = ("SELECT l.* FROM logs l JOIN logs_fts f ON l.id=f.rowid "
                            "WHERE f.logs_fts MATCH ?")
                    args = ['"%s"' % kw]
                    if host:
                        base += " AND l.host LIKE ?"; args.append("%" + host + "%")
                    if src_ip:
                        base += " AND l.src_ip LIKE ?"; args.append("%" + src_ip + "%")
                    if level:
                        base += " AND l.level=?"; args.append(level)
                    total = conn.execute("SELECT count(*) FROM (%s)" % base, args).fetchone()[0]
                    rows = conn.execute(base + " ORDER BY l.ts DESC LIMIT ? OFFSET ?",
                                        args + [limit, offset]).fetchall()
                    return rows, total, "fts5"
            except Exception:
                pass  # 语法错/索引异常 -> 落到 LIKE

        # LIKE 兜底
        base = "SELECT l.* FROM logs l WHERE l.message LIKE ?"
        args = ["%" + kw + "%"]
        if host:
            base += " AND l.host LIKE ?"; args.append("%" + host + "%")
        if src_ip:
            base += " AND l.src_ip LIKE ?"; args.append("%" + src_ip + "%")
        if level:
            base += " AND l.level=?"; args.append(level)
        total = conn.execute("SELECT count(*) FROM (%s)" % base, args).fetchone()[0]
        rows = conn.execute(base + " ORDER BY l.ts DESC LIMIT ? OFFSET ?",
                            args + [limit, offset]).fetchall()
        return rows, total, "like"

    # 无关键词：纯条件过滤
    base = "SELECT l.* FROM logs l WHERE 1=1"
    args = []
    if host:
        base += " AND l.host LIKE ?"; args.append("%" + host + "%")
    if src_ip:
        base += " AND l.src_ip LIKE ?"; args.append("%" + src_ip + "%")
    if level:
        base += " AND l.level=?"; args.append(level)
    total = conn.execute("SELECT count(*) FROM (%s)" % base, args).fetchone()[0]
    rows = conn.execute(base + " ORDER BY l.ts DESC LIMIT ? OFFSET ?",
                        args + [limit, offset]).fetchall()
    return rows, total, "filter"


def fts_upsert(conn, rowid: int, message: str, host: str, src_ip: str, dst_ip: str):
    conn.execute("DELETE FROM logs_fts WHERE rowid=?", (rowid,))
    conn.execute(
        "INSERT INTO logs_fts(rowid, message, host, src_ip, dst_ip) VALUES (?,?,?,?,?)",
        (rowid, message or "", host or "", src_ip or "", dst_ip or ""),
    )


def extract_iocs(text: str):
    """从文本里提取 IP / 域名，便于自动建 IOC。"""
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text or "")
    domains = re.findall(r'\b[a-zA-Z0-9][a-zA-Z0-9\-]{1,62}\.[a-zA-Z]{2,}\b', text or "")
    return sorted(set(ips)), sorted(set(domains))
