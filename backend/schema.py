# -*- coding: utf-8 -*-
"""数据库迁移：建表 + 索引 + 只增触发器 + 审计哈希链。

设计原则（来自设计文档 §6.3）：
- 所有业务表带 created_at / updated_at
- 审计表 audit_logs 只增：用触发器禁 UPDATE / DELETE
- 审计哈希链：prev_hash + payload_hash，逐行串接
"""
from .db import connect, tx

SCHEMA_VERSION = 4

DDL = """
-- ========== 基础与账号 (7) ==========
CREATE TABLE IF NOT EXISTS departments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  parent_id INTEGER REFERENCES departments(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  permissions TEXT NOT NULL DEFAULT '[]',
  data_scope TEXT NOT NULL DEFAULT 'all',
  builtin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  role_id INTEGER REFERENCES roles(id),
  department_id INTEGER REFERENCES departments(id),
  totp_secret TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  permissions TEXT NOT NULL DEFAULT '[]',
  ip_whitelist TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  last_used_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  encrypted INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS backups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  checksum TEXT,
  result TEXT NOT NULL DEFAULT 'ok',
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- ========== 资产与风险 (6) ==========
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  asset_type TEXT NOT NULL DEFAULT 'host',
  os TEXT,
  owner TEXT,
  department_id INTEGER REFERENCES departments(id),
  importance INTEGER NOT NULL DEFAULT 3,
  authz_confirmed INTEGER NOT NULL DEFAULT 0,
  tags TEXT NOT NULL DEFAULT '[]',
  remark TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS asset_ips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  ip TEXT NOT NULL UNIQUE,
  mac TEXT,
  is_primary INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS asset_services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  port INTEGER NOT NULL,
  protocol TEXT NOT NULL DEFAULT 'tcp',
  service TEXT,
  banner TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS vulns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  cve TEXT,
  severity TEXT NOT NULL DEFAULT 'medium',
  cvss REAL NOT NULL DEFAULT 0,
  source TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  sla_due TEXT,
  owner TEXT,
  description TEXT,
  fix_suggestion TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS vuln_assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vuln_id INTEGER NOT NULL REFERENCES vulns(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  port INTEGER,
  evidence TEXT,
  UNIQUE(vuln_id, asset_id, port)
);

CREATE TABLE IF NOT EXISTS vuln_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vuln_id INTEGER NOT NULL REFERENCES vulns(id) ON DELETE CASCADE,
  from_status TEXT,
  to_status TEXT NOT NULL,
  note TEXT,
  operator TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- ========== 基线 (3) ==========
CREATE TABLE IF NOT EXISTS baseline_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  standard TEXT NOT NULL DEFAULT '等保2.0',
  description TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS baseline_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  policy_id INTEGER NOT NULL REFERENCES baseline_policies(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  title TEXT NOT NULL,
  check_type TEXT NOT NULL DEFAULT 'manual',
  expect TEXT,
  suggestion TEXT,
  severity TEXT NOT NULL DEFAULT 'medium'
);

CREATE TABLE IF NOT EXISTS baseline_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  item_id INTEGER NOT NULL REFERENCES baseline_items(id) ON DELETE CASCADE,
  asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
  result TEXT NOT NULL DEFAULT 'unknown',
  detail TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- ========== 网络配置 (4) ==========
CREATE TABLE IF NOT EXISTS net_iface_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  iface TEXT NOT NULL,
  payload_enc TEXT NOT NULL,
  checksum TEXT,
  reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS net_snapshot_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_id INTEGER NOT NULL REFERENCES net_iface_snapshots(id) ON DELETE CASCADE,
  iface TEXT NOT NULL,
  ip TEXT,
  prefix INTEGER,
  gateway TEXT,
  dns TEXT,
  dhcp INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS net_change_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  iface TEXT NOT NULL,
  snapshot_id INTEGER REFERENCES net_iface_snapshots(id),
  from_state TEXT,
  to_state TEXT,
  verify_result TEXT,
  watchdog_until TEXT,
  rolled_back INTEGER NOT NULL DEFAULT 0,
  operator TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS net_iface_state (
  iface TEXT PRIMARY KEY,
  desired_enabled INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- ========== 日志与告警 (8) ==========
CREATE TABLE IF NOT EXISTS log_sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  source_type TEXT NOT NULL DEFAULT 'windows_event',
  config TEXT NOT NULL DEFAULT '{}',
  cursor TEXT,
  health TEXT NOT NULL DEFAULT 'unknown',
  last_collect_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id INTEGER REFERENCES log_sources(id) ON DELETE SET NULL,
  ts TEXT NOT NULL,
  level TEXT,
  host TEXT,
  src_ip TEXT,
  dst_ip TEXT,
  message TEXT NOT NULL,
  raw_enc TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- logs_fts 由 migrate() 动态建：trigram 需 SQLite >= 3.34，低版本自动降级 unicode61

CREATE TABLE IF NOT EXISTS log_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  severity TEXT NOT NULL DEFAULT 'medium',
  match_field TEXT NOT NULL DEFAULT 'message',
  pattern TEXT NOT NULL,
  description TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS log_alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id INTEGER REFERENCES log_rules(id) ON DELETE SET NULL,
  rule_name TEXT,
  severity TEXT NOT NULL DEFAULT 'medium',
  src_ip TEXT,
  host TEXT,
  summary TEXT,
  hit_count INTEGER NOT NULL DEFAULT 1,
  triage TEXT NOT NULL DEFAULT 'pending',
  owner TEXT,
  incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
  first_seen TEXT,
  last_seen TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS ioc_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ioc_type TEXT NOT NULL DEFAULT 'ip',
  value TEXT NOT NULL,
  confidence INTEGER NOT NULL DEFAULT 50,
  tag TEXT,
  hit_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  UNIQUE(ioc_type, value)
);

CREATE TABLE IF NOT EXISTS ip_intel_cache (
  ip TEXT PRIMARY KEY,
  country TEXT,
  asn TEXT,
  org TEXT,
  risk_score INTEGER NOT NULL DEFAULT 0,
  source TEXT,
  ttl_expire TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS ip_trace_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  conclusion TEXT,
  risk_score INTEGER NOT NULL DEFAULT 0,
  evidence TEXT NOT NULL DEFAULT '[]',
  trace_id TEXT,
  operator TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- ========== 应急 (5) ==========
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'P3',
  status TEXT NOT NULL DEFAULT 'open',
  owner TEXT,
  summary TEXT,
  source_alert_id INTEGER,
  closed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS incident_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  action_type TEXT NOT NULL,
  target TEXT,
  detail TEXT,
  result TEXT,
  reversible INTEGER NOT NULL DEFAULT 0,
  reverted INTEGER NOT NULL DEFAULT 0,
  operator TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS incident_participants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  user_name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'owner'
);

CREATE TABLE IF NOT EXISTS blocklist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL UNIQUE,
  reason TEXT,
  incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
  desired_state TEXT NOT NULL DEFAULT 'blocked',
  applied INTEGER NOT NULL DEFAULT 0,
  operator TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS evidence_bundles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  checksum TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- ========== 协同 (3) ==========
CREATE TABLE IF NOT EXISTS duty_shifts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  duty_date TEXT NOT NULL,
  shift TEXT NOT NULL DEFAULT 'day',
  primary_user TEXT NOT NULL,
  backup_user TEXT,
  note TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS duty_handovers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shift_id INTEGER REFERENCES duty_shifts(id) ON DELETE SET NULL,
  from_user TEXT,
  to_user TEXT,
  content TEXT,
  unclosed TEXT NOT NULL DEFAULT '[]',
  confirmed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  assignee TEXT NOT NULL,
  task_type TEXT NOT NULL DEFAULT 'remediation',
  priority TEXT NOT NULL DEFAULT 'P3',
  status TEXT NOT NULL DEFAULT 'open',
  due_at TEXT,
  source_ref TEXT,
  note TEXT,
  accepted_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  updated_at TEXT
);

-- ========== 输出与外发 (5) ==========
CREATE TABLE IF NOT EXISTS report_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  blocks TEXT NOT NULL DEFAULT '[]',
  period TEXT NOT NULL DEFAULT 'weekly',
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS report_schedules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  template_id INTEGER REFERENCES report_templates(id) ON DELETE CASCADE,
  cron TEXT NOT NULL DEFAULT '0 8 * * 1',
  recipients TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_run_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS notify_channels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  channel_type TEXT NOT NULL DEFAULT 'webhook',
  config_enc TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS notify_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  event_type TEXT NOT NULL DEFAULT 'alert',
  min_severity TEXT NOT NULL DEFAULT 'high',
  channel_id INTEGER REFERENCES notify_channels(id) ON DELETE CASCADE,
  recipients TEXT,
  quiet_hours TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS notify_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_id INTEGER REFERENCES notify_channels(id) ON DELETE SET NULL,
  event_type TEXT,
  subject TEXT,
  result TEXT NOT NULL DEFAULT 'pending',
  error TEXT,
  elapsed_ms INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- ========== 审计与辅助 ==========
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  seq INTEGER NOT NULL,
  ts TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  actor TEXT,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  before_val TEXT,
  after_val TEXT,
  prev_hash TEXT,
  payload_hash TEXT NOT NULL,
  trace_id TEXT
);

CREATE TABLE IF NOT EXISTS confirm_tokens (
  token TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  actor TEXT,
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
  key TEXT PRIMARY KEY,
  action TEXT,
  result TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS export_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  path TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- ========== 实时监控 (V2.2) ==========
CREATE TABLE IF NOT EXISTS live_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  kind TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  remote_ip TEXT,
  remote_port INTEGER,
  local_port INTEGER,
  process_name TEXT,
  pid INTEGER,
  detail TEXT,
  raw TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- ========== 主机防护引擎 (V3.0 Guard) ==========
-- 检测规则：把 Sigma 思路落成本地可判定的条件 DSL（JSON 条件 + 动作）
CREATE TABLE IF NOT EXISTS guard_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'process',
  severity TEXT NOT NULL DEFAULT 'medium',
  technique TEXT,
  condition TEXT NOT NULL DEFAULT '{}',
  actions TEXT NOT NULL DEFAULT '{}',
  enabled INTEGER NOT NULL DEFAULT 1,
  builtin INTEGER NOT NULL DEFAULT 1,
  note TEXT,
  hits INTEGER NOT NULL DEFAULT 0,
  last_hit_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  updated_at TEXT
);

-- 可信名单：进程路径 / 签名主体 / IP / 端口 / 域名；source=default 不可删
CREATE TABLE IF NOT EXISTS guard_whitelist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  note TEXT,
  source TEXT NOT NULL DEFAULT 'user',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  UNIQUE(kind, value)
);

-- 检测事件（防护引擎的主干产出）
CREATE TABLE IF NOT EXISTS guard_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  rule_id INTEGER,
  rule_name TEXT,
  category TEXT,
  severity TEXT NOT NULL DEFAULT 'info',
  subject TEXT,
  subject_ip TEXT,
  pid INTEGER,
  process_name TEXT,
  process_path TEXT,
  local_port INTEGER,
  remote_ip TEXT,
  remote_port INTEGER,
  mitre TEXT,
  detail TEXT,
  evidence TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'new',
  alert_id INTEGER,
  incident_id INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- 响应动作（全部可回滚；applied 表示内核态是否真的生效）
CREATE TABLE IF NOT EXISTS guard_responses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  event_id INTEGER,
  action TEXT NOT NULL,
  target TEXT,
  args TEXT NOT NULL DEFAULT '{}',
  mode TEXT NOT NULL DEFAULT 'monitor',
  applied INTEGER NOT NULL DEFAULT 0,
  result TEXT,
  revert_action TEXT,
  reverted INTEGER NOT NULL DEFAULT 0,
  reverted_at TEXT,
  operator TEXT NOT NULL DEFAULT 'auto',
  firewall_rule TEXT,
  expire_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- 进程/外联快照基线：用于“新面孔”判定
CREATE TABLE IF NOT EXISTS guard_baseline (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  first_seen TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  last_seen TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  seen_count INTEGER NOT NULL DEFAULT 1,
  note TEXT,
  UNIQUE(kind, key)
);

-- 防护策略：单行配置（id=1），mode 决定“只记录 / 记录+告警 / 主动阻断”
CREATE TABLE IF NOT EXISTS guard_policy (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mode TEXT NOT NULL DEFAULT 'monitor',
  autostart INTEGER NOT NULL DEFAULT 0,
  interval_sec INTEGER NOT NULL DEFAULT 8,
  score_threshold INTEGER NOT NULL DEFAULT 60,
  max_actions_per_min INTEGER NOT NULL DEFAULT 12,
  auto_incident INTEGER NOT NULL DEFAULT 1,
  auto_notify INTEGER NOT NULL DEFAULT 1,
  auto_block_ip INTEGER NOT NULL DEFAULT 1,
  auto_block_program INTEGER NOT NULL DEFAULT 0,
  auto_kill_process INTEGER NOT NULL DEFAULT 0,
  expire_minutes INTEGER NOT NULL DEFAULT 30,
  probes TEXT NOT NULL DEFAULT '{}',
  retention_days INTEGER NOT NULL DEFAULT 90,
  archive_enabled INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);

-- 去重台账：落库而不是放内存，重启后不会把同一件事再报一遍；多进程也共享同一份
CREATE TABLE IF NOT EXISTS guard_dedup (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_db_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT '',
  first_ts TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  last_ts TEXT NOT NULL DEFAULT (datetime('now','localtime')),
  hits INTEGER NOT NULL DEFAULT 1,
  last_event_id INTEGER,
  UNIQUE(rule_db_id, subject)
);

-- 归档表：与 guard_events 同构，保留期内不查它，只为把热表压小
CREATE TABLE IF NOT EXISTS guard_events_archive (
  id INTEGER PRIMARY KEY,
  ts TEXT,
  rule_id INTEGER,
  rule_name TEXT,
  category TEXT,
  severity TEXT,
  subject TEXT,
  subject_ip TEXT,
  pid INTEGER,
  process_name TEXT,
  process_path TEXT,
  local_port INTEGER,
  remote_ip TEXT,
  remote_port INTEGER,
  mitre TEXT,
  detail TEXT,
  evidence TEXT,
  status TEXT,
  alert_id INTEGER,
  incident_id INTEGER,
  archived_at TEXT DEFAULT (datetime('now','localtime'))
);

-- ========== 索引 ==========
CREATE INDEX IF NOT EXISTS idx_guard_events_ts ON guard_events(ts);
CREATE INDEX IF NOT EXISTS idx_guard_events_sev ON guard_events(severity);
CREATE INDEX IF NOT EXISTS idx_guard_events_status ON guard_events(status);
CREATE INDEX IF NOT EXISTS idx_guard_events_remote ON guard_events(remote_ip);
CREATE INDEX IF NOT EXISTS idx_guard_resp_event ON guard_responses(event_id);
CREATE INDEX IF NOT EXISTS idx_guard_resp_target ON guard_responses(target);
CREATE INDEX IF NOT EXISTS idx_guard_dedup_rule ON guard_dedup(rule_db_id);
CREATE INDEX IF NOT EXISTS idx_guard_dedup_last ON guard_dedup(last_ts);
CREATE INDEX IF NOT EXISTS idx_guard_arch_ts ON guard_events_archive(ts);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
CREATE INDEX IF NOT EXISTS idx_logs_srcip ON logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_logs_host ON logs(host);
CREATE INDEX IF NOT EXISTS idx_alerts_triage ON log_alerts(triage);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON log_alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_assets_name ON assets(name);
CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulns(status);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON tasks(assignee);
CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_logs(seq);
CREATE INDEX IF NOT EXISTS idx_findings_run ON baseline_findings(run_id);
CREATE INDEX IF NOT EXISTS idx_live_events_ts ON live_events(ts);
CREATE INDEX IF NOT EXISTS idx_live_events_ip ON live_events(remote_ip);
"""

# 审计表只增触发器：禁止 UPDATE / DELETE
TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
BEFORE UPDATE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_logs is append-only: UPDATE forbidden');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
BEFORE DELETE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_logs is append-only: DELETE forbidden');
END;
"""


def _fts_trigram_supported(conn) -> bool:
    """trigram tokenizer 需要 SQLite >= 3.34。实测 Windows 自带 Python3.8 是 3.32，
    直接 executescript 会在建表处抛 "no such tokenizer: trigram" 并中断整个迁移。"""
    try:
        conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS _fts_probe USING fts5(x, tokenize='trigram')")
        conn.execute("DROP TABLE _fts_probe")
        conn.commit()
        return True
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        return False


FTS_MODE = {"tokenizer": None}


def _ensure_column(conn, table, column, decl):
    """老库补列：CREATE TABLE IF NOT EXISTS 不会给已存在的表加字段。"""
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(%s)" % table)}
    except Exception:
        return False
    if not cols or column in cols:
        return False
    conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, column, decl))
    conn.commit()
    return True


def migrate():
    conn = connect()
    trigram = _fts_trigram_supported(conn)
    tokenizer = "trigram" if trigram else "unicode61"
    FTS_MODE["tokenizer"] = tokenizer
    conn.executescript(DDL)
    conn.executescript(
        "CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5("
        "message, host, src_ip, dst_ip, tokenize='%s');" % tokenizer)
    conn.executescript(TRIGGERS)
    conn.commit()
    # V3.1：guard_policy 补两列（保留期 / 归档开关），老库平滑升级
    _ensure_column(conn, "guard_policy", "retention_days", "INTEGER NOT NULL DEFAULT 90")
    _ensure_column(conn, "guard_policy", "archive_enabled", "INTEGER NOT NULL DEFAULT 1")
    with tx() as c:
        c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('schema_version',?)",
                  (str(SCHEMA_VERSION),))
        c.execute("UPDATE settings SET value=? WHERE key='schema_version'", (str(SCHEMA_VERSION),))
        c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('fts_tokenizer',?)",
                  (tokenizer,))
    return SCHEMA_VERSION


def fts_tokenizer() -> str:
    return FTS_MODE.get("tokenizer") or "unknown"


if __name__ == "__main__":
    print("migrate ->", migrate())
