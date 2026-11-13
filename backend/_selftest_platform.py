# -*- coding: utf-8 -*-
"""平台适配层只读自测（不改任何系统配置）。"""
import sys, os, io, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ['BLUEGUARD_DATA'] = os.path.join(os.environ['TEMP'], 'bg_test2')

from backend.platform_win import iface, firewall, events, is_admin
from backend import netmgr, schema
from backend.db import connect, tx

print('=== 权限 ===')
print('  is_admin =', is_admin())

print('\n=== 网卡枚举 ===')
ifaces = iface.list_ifaces()
print('  网卡数 =', len(ifaces))
for a in ifaces:
    ips = ','.join('%s/%s' % (i['ip'], i['prefix']) for i in a['ipv4']) or '-'
    print('  %-14s %-10s ip=%-22s gw=%-14s dhcp=%s' % (
        a['name'], a['status'], ips, a['gateway'] or '-', a['dhcp']))

print('\n=== 事件日志可用性 ===')
avail = events.available()
for k, v in avail.items():
    print('  %-22s %s' % (k, v))

print('\n=== 读 System 日志 3 条 ===')
try:
    evs = events.read_events('System', 3)
    for e in evs:
        print('  [%s] %s %s' % (e['event_id'], e['level'], (e['message'] or '')[:60]))
except Exception as e:
    print('  读取失败:', e)

print('\n=== 防火墙规则（BlueGuard 前缀）===')
print('  ', firewall.list_rules('')[:3] if firewall.list_rules('') else '无')

print('\n=== 快照功能 ===')
schema.migrate()
conn = connect()
# 选一块有 IP 的网卡
target = next((a for a in ifaces if a['ipv4']), None)
if target:
    with tx() as c:
        sid = netmgr.take_snapshot(c, target['name'], '自测快照')
    print('  快照 id =', sid, ' iface =', target['name'])
    snap = netmgr.get_snapshot(conn, sid)
    print('  回读快照 ipv4 =', snap.get('ipv4'), ' dhcp =', snap.get('dhcp'))
    items = conn.execute('SELECT * FROM net_snapshot_items WHERE snapshot_id=?', (sid,)).fetchall()
    print('  快照明细行数 =', len(items))
else:
    print('  没有带 IPv4 的网卡，跳过')

print('\n=== 三级验证（对现有网卡做只读验证，不修改）===')
if target:
    primary = target['ipv4'][0]
    v = netmgr.verify_three_level(conn, target['name'], primary['ip'], target['gateway'])
    print('  level1(配置落地) =', v['level1'])
    print('  level2(网关可达) =', v['level2'], v['detail'].get('gateway'))
    print('  level3(外部可达) =', v['level3'])
    print('  ok =', v['ok'])

print('\n=== 崩溃补扫（应无待处理变更）===')
print('  ', netmgr.recover_on_boot(conn))
print('\n完成。')
