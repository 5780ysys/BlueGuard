# -*- coding: utf-8 -*-
"""核心层自测：建库 / 检索 / 审计链防篡改。"""
import sys, os, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ['BLUEGUARD_DATA'] = os.path.join(os.environ['TEMP'], 'bg_test')

# 清干净
import shutil
if os.path.isdir(os.environ['BLUEGUARD_DATA']):
    shutil.rmtree(os.environ['BLUEGUARD_DATA'], ignore_errors=True)

from backend import schema
from backend.db import connect, tx
from backend import search, audit

print('=== 1) 迁移建表 ===')
print('schema_version =', schema.migrate())
conn = connect()
tables = [r[0] for r in conn.execute(
    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'logs_fts%'").fetchall()]
print('业务表数量 =', len(tables))

print('\n=== 2) 插入日志并建索引 ===')
logs = [
    ('2026-11-04 10:00:00', 'error', 'web01', '203.0.113.5', '10.0.0.8', '用户登录失败 user=admin 密码错误'),
    ('2026-11-04 10:05:00', 'info',  'web01', '203.0.113.5', '10.0.0.8', '用户登录成功 user=root'),
    ('2026-11-04 10:10:00', 'warn',  'fw01',  '198.51.100.7', '10.0.0.0', '端口扫描检测 目标 10.0.0.0/24'),
    ('2026-11-04 10:15:00', 'error', 'db01',  '203.0.113.5', '10.0.0.9', '封禁规则命中 source=203.0.113.5'),
]
with tx() as c:
    for ts, lvl, host, sip, dip, msg in logs:
        cur = c.execute("INSERT INTO logs(ts,level,host,src_ip,dst_ip,message) VALUES (?,?,?,?,?,?)",
                        (ts, lvl, host, sip, dip, msg))
        search.fts_upsert(c, cur.lastrowid, msg, host, sip, dip)
print('日志条数 =', conn.execute('SELECT count(*) FROM logs').fetchone()[0])
print('FTS 索引条数 =', conn.execute('SELECT count(*) FROM logs_fts').fetchone()[0])

print('\n=== 3) 检索（关键：中文两字词 + IP 点号）===')
for kw in ['登录失败', '登录', '失败', '203.0.113.5', '端口扫描', '不存在xyz']:
    rows, total, mode = search.search_logs(conn, kw)
    print('  %-12s mode=%-5s total=%d' % (kw, mode, total))

print('\n=== 4) 审计链 ===')
with tx() as c:
    audit.append(c, 'admin', 'asset.create', 'asset', 1, None, {'name': 'web01'})
    audit.append(c, 'admin', 'vuln.update', 'vuln', 1, {'status': 'open'}, {'status': 'fixed'})
    audit.append(c, 'ops', 'incident.close', 'incident', 7, {'status': 'open'}, {'status': 'closed'})
ok, n, bad, detail = audit.verify(conn)
print('  验证: ok=%s rows=%d detail=%s' % (ok, n, detail))
print('  锚点:', audit.anchor(conn))

print('\n=== 5) 篡改检测（模拟直接改库）===')
try:
    conn.execute("UPDATE audit_logs SET action='tampered' WHERE seq=2")
    conn.commit()
    print('  !! UPDATE 竟然成功了（触发器失效）')
except Exception as e:
    print('  UPDATE 被拒绝 ->', str(e)[:60])
    conn.rollback()

try:
    conn.execute("DELETE FROM audit_logs WHERE seq=1")
    conn.commit()
    print('  !! DELETE 竟然成功了')
except Exception as e:
    print('  DELETE 被拒绝 ->', str(e)[:60])
    conn.rollback()

print('\n=== 6) 绕过触发器直接改内容后校验（模拟磁盘篡改）===')
conn.execute("PRAGMA writable_schema=OFF")
try:
    # 用触发器之外的手段：先禁用触发器再看
    conn.execute("DROP TRIGGER trg_audit_no_update")
    conn.execute("UPDATE audit_logs SET action='HACKED' WHERE seq=2")
    conn.commit()
    ok2, n2, bad2, d2 = audit.verify(conn)
    print('  篡改后校验: ok=%s bad_seq=%s detail=%s' % (ok2, bad2, d2))
except Exception as e:
    print('  err', e)

print('\n完成。')
