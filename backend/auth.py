# -*- coding: utf-8 -*-
"""认证：口令哈希、会话、RBAC 依赖。"""
import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, Header, Request

from . import config
from .db import connect, tx
from . import audit

ITERATIONS = 120000

# 会话令牌写入 HttpOnly Cookie 的名称（前端 JS 不可读）
COOKIE_NAME = "bg_token"


def hash_password(password: str, salt: str = None) -> tuple:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), ITERATIONS)
    return dk.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), ITERATIONS)
    return hmac.compare_digest(dk.hex(), password_hash)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def ensure_seed(conn):
    """首次启动：建内置角色与初始管理员（必须改密）。"""
    if conn.execute("SELECT count(*) FROM users").fetchone()[0] > 0:
        return None
    with tx() as c:
        c.execute("INSERT OR IGNORE INTO departments(id,name) VALUES (1,'默认部门')")
        c.execute(
            "INSERT OR IGNORE INTO roles(code,name,permissions,data_scope,builtin) VALUES "
            "('admin','管理员','[\"*\"]','all',1),"
            "('operator','处置员','[\"asset:*\",\"alert:*\",\"incident:*\",\"log:read\"]','all',1),"
            "('viewer','只读','[\"*:read\"]','self',1)"
        )
        role_id = c.execute("SELECT id FROM roles WHERE code='admin'").fetchone()[0]
        pw = "BlueGuard@2026"
        ph, salt = hash_password(pw)
        c.execute(
            "INSERT INTO users(username,display_name,password_hash,salt,role_id,department_id,must_change_password) "
            "VALUES (?,?,?,?,?,?,1)",
            ("admin", "初始管理员", ph, salt, role_id, 1),
        )
        audit.append(c, "system", "system.init", "user", "admin", None, {"initial_password": "***"})
    return {"username": "admin", "password": pw, "must_change_password": True}


def login(conn, username: str, password: str, ip: str = "", ua: str = ""):
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        raise HTTPException(401, "用户名或密码错误")
    if row["status"] != "active":
        raise HTTPException(403, "账号已停用")
    if row["locked_until"] and row["locked_until"] > datetime.now().strftime("%Y-%m-%d %H:%M:%S"):
        raise HTTPException(423, "账号已锁定，请稍后重试")
    if not verify_password(password, row["password_hash"], row["salt"]):
        with tx() as c:
            fails = row["failed_attempts"] + 1
            lock = None
            if fails >= 5:
                lock = (datetime.now() + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
            c.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                      (fails, lock, row["id"]))
        raise HTTPException(401, "用户名或密码错误")

    token = secrets.token_urlsafe(32)
    sid = uuid.uuid4().hex
    expires = (datetime.now() + timedelta(hours=12)).strftime("%Y-%m-%d %H:%M:%S")
    with tx() as c:
        c.execute("UPDATE users SET failed_attempts=0, locked_until=NULL, updated_at=datetime('now','localtime') WHERE id=?",
                  (row["id"],))
        c.execute(
            "INSERT INTO sessions(id,user_id,token_hash,ip,user_agent,expires_at) VALUES (?,?,?,?,?,?)",
            (sid, row["id"], hash_token(token), ip, ua, expires),
        )
        audit.append(c, username, "auth.login", "user", row["id"], None, {"ip": ip})
    return {
        "token": token,
        "expires_at": expires,
        "user": {
            "id": row["id"], "username": row["username"],
            "display_name": row["display_name"], "role_id": row["role_id"],
            "must_change_password": bool(row["must_change_password"]),
        },
    }


def open_access_user(conn=None):
    """免登录模式下的身份：取库里的管理员账号，取不到就给一个内存身份。

    这样审计、处置、报表里记录的仍是真实用户名，链路不断。
    """
    conn = conn or connect()
    row = None
    try:
        row = conn.execute(
            "SELECT id,username,display_name,role_id FROM users ORDER BY id LIMIT 1").fetchone()
    except Exception:
        row = None
    if row is None:
        return {"id": 0, "username": "admin", "display_name": "本机用户",
                "role_id": None, "permissions": '["*"]', "data_scope": "all",
                "via": "open"}
    return {
        "id": row["id"], "username": row["username"],
        "display_name": row["display_name"], "role_id": row["role_id"],
        "permissions": '["*"]', "data_scope": "all", "via": "open",
    }


def current_user(request: Request = None, authorization: str = Header(default=""), x_api_token: str = Header(default="")):
    """解析会话令牌或 API Token。令牌优先从 HttpOnly Cookie（bg_token）读，其次 Bearer 头，最后 x-api-token。

    BLUEGUARD_AUTH=open（默认）时直接返回本机身份，不要求任何凭据 —— 打开即用。
    """
    conn = connect()
    if config.OPEN_ACCESS and not x_api_token:
        return open_access_user(conn)
    if x_api_token:
        th = hash_token(x_api_token)
        row = conn.execute("SELECT * FROM api_tokens WHERE token_hash=? AND status='active'",
                           (th,)).fetchone()
        if row:
            conn.execute("UPDATE api_tokens SET last_used_at=datetime('now','localtime') WHERE id=?",
                         (row["id"],))
            conn.commit()
            return {"id": 0, "username": "api:" + row["name"], "role_id": None,
                    "permissions": row["permissions"], "data_scope": "all", "via": "token"}
    token = ""
    if request is not None:
        token = request.cookies.get(COOKIE_NAME, "")
    if not token and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not token:
        raise HTTPException(401, "未登录")
    th = hash_token(token)
    s = conn.execute(
        "SELECT s.*, u.username, u.display_name, u.role_id, u.status FROM sessions s "
        "JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked=0", (th,)
    ).fetchone()
    if not s:
        raise HTTPException(401, "会话无效")
    if s["expires_at"] < datetime.now().strftime("%Y-%m-%d %H:%M:%S"):
        raise HTTPException(401, "会话已过期")
    role = conn.execute("SELECT permissions, data_scope FROM roles WHERE id=?",
                        (s["role_id"],)).fetchone()
    return {
        "id": s["user_id"], "username": s["username"],
        "display_name": s["display_name"], "role_id": s["role_id"],
        "permissions": role["permissions"] if role else "[]",
        "data_scope": role["data_scope"] if role else "self",
        "via": "session",
    }


def logout(conn, token: str):
    with tx() as c:
        c.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (hash_token(token),))
