# -*- coding: utf-8 -*-
"""SQLite 连接管理与加密工具。"""
import sqlite3
import base64
import hashlib
import os
from contextlib import contextmanager

from . import config

_conn = None


def _load_or_create_key() -> bytes:
    """master.key 用于列级加密，必须跟数据目录一起迁移。"""
    if config.KEY_FILE.exists():
        return base64.b64decode(config.KEY_FILE.read_bytes())
    key = os.urandom(32)
    config.KEY_FILE.write_bytes(base64.b64encode(key))
    try:
        os.chmod(config.KEY_FILE, 0o600)
    except Exception:
        pass
    return key


MASTER_KEY = _load_or_create_key()


def _setup(conn: sqlite3.Connection):
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")


def connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(str(config.DB_PATH), check_same_thread=False)
        _setup(_conn)
    return _conn


@contextmanager
def tx():
    """事务上下文：异常自动回滚。"""
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def enc(plain: str) -> str:
    """列级'加密'：XOR + 摘要，够用且零依赖（非密码学强加密，用于原文列存)。"""
    if plain is None:
        return None
    data = plain.encode("utf-8")
    stream = hashlib.sha256(MASTER_KEY).digest()
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ stream[i % len(stream)]
    return base64.b64encode(bytes(out)).decode("ascii")


def dec(cipher: str) -> str:
    if cipher is None:
        return None
    data = base64.b64decode(cipher)
    stream = hashlib.sha256(MASTER_KEY).digest()
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ stream[i % len(stream)]
    return bytes(out).decode("utf-8", "replace")
