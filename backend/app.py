# -*- coding: utf-8 -*-
"""蓝盾 BlueGuard 后端主应用。

启动：python -m backend.app  （自动选随机端口并写 data/port.txt）
"""
import json
import os
import socket
import sys
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, Query, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import config, schema, audit, auth, netmgr, search
from .db import connect, tx, enc, dec
from .platform_win import iface, firewall, events, is_admin
from .routes import router as biz_router

app = FastAPI(title=config.APP_NAME, version=config.APP_VERSION)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


# ---------- 请求级 XSS 输入净化中间件 ----------
# 对所有 POST/PUT/PATCH 的 JSON 请求体中的字符串值做 HTML 实体转义，
# 从源头阻止存储型 XSS（脏数据入库）。
class _SanitizeBodyMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = scope.get("method", "")
        if method not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        ctype = headers.get(b"content-type", b"").decode("latin-1", "ignore")
        if "application/json" not in ctype:
            await self.app(scope, receive, send)
            return

        # 先完整缓冲请求体，再净化后重放
        body = b""
        more = True
        while more:
            m = await receive()
            if m["type"] == "http.request":
                body += m.get("body", b"")
                more = m.get("more_body", False)

        from .routes import sanitize_dict
        new_body = body
        try:
            data = json.loads(body.decode("utf-8"))
            data = sanitize_dict(data)
            new_body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        except Exception:
            pass

        sent = {"v": False}

        async def replay_receive():
            if not sent["v"]:
                sent["v"] = True
                return {"type": "http.request", "body": new_body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)


app.add_middleware(_SanitizeBodyMiddleware)
app.include_router(biz_router)

# V3.0 主机防护引擎 API
try:
    from .guard_api import router as guard_router
    app.include_router(guard_router)
except Exception as _e:  # 引擎缺失不应阻断主程序
    print("[guard] 路由加载失败:", _e)


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def rows_to_list(rows):
    return [dict(r) for r in rows]


@app.on_event("startup")
def _startup():
    schema.migrate()
    conn = connect()
    seed = auth.ensure_seed(conn)
    if seed:
        print("[init] 初始管理员 admin / %s （首次登录须改密）" % seed["password"])
    # 第 5 层：崩溃补扫
    rec = netmgr.recover_on_boot(conn)
    if rec["scanned"]:
        print("[recover] 补扫回滚:", rec)
    # V2.2：可选实时监控自启动（默认关闭，避免无感后台轮询）
    if os.environ.get("BLUEGUARD_LIVE_AUTOSTART", "").strip().lower() in ("1", "true", "yes"):
        try:
            from . import live_monitor
            live_monitor.start(int(os.environ.get("BLUEGUARD_LIVE_INTERVAL", "5") or 5))
            print("[live] 实时外部IP监控已自启动")
        except Exception as e:
            print("[live] 自启动失败:", e)

    # V3.0：防护引擎初始化（建规则种子；是否自动开跑由 guard_policy.autostart 决定）
    try:
        from . import guard
        info = guard.init()
        print("[guard] 防护引擎就绪:", info)
        if os.environ.get("BLUEGUARD_GUARD_AUTOSTART", "").strip().lower() in ("1", "true", "yes"):
            guard.start()
            print("[guard] 已按环境变量自启动")
    except Exception as e:
        print("[guard] 初始化失败:", e)


# ================= 健康 / 元信息 =================
def _guard_health():
    try:
        from . import guard
        st = guard.status()
        return {k: st.get(k) for k in ("running", "mode", "rounds", "last_run", "last_error")}
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/health")
def health(user=Depends(auth.current_user)):
    conn = connect()
    return {
        "ok": True,
        "app": config.APP_NAME,
        "tagline": config.APP_TAGLINE,
        "edition": config.APP_EDITION,
        "version": config.APP_VERSION,
        "mode": config.DEPLOY_MODE,
        "auth_mode": "open" if config.OPEN_ACCESS else "password",
        "admin": is_admin(),
        "tables": conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchone()[0],
        "eventlog": events.available(),
        "audit": dict(zip(["ok", "rows", "bad", "detail"], audit.verify(conn))),
        "guard": _guard_health(),
        "time": now(),
    }


@app.get("/api/ping")
def ping():
    """极简心跳，不暴露任何内部信息，无需鉴权。"""
    return {"ok": True}


# ================= 认证 =================
def _set_auth_cookie(resp, token: str):
    """把会话令牌写入 HttpOnly Cookie（前端 JS 不可读），SameSite=Lax，本地 http 不用 Secure。"""
    resp.set_cookie(auth.COOKIE_NAME, token, max_age=12 * 3600,
                    httponly=True, samesite="lax", path="/")


@app.post("/api/auth/login")
def api_login(payload: dict = Body(...), request: Request = None):
    conn = connect()
    ip = request.client.host if request and request.client else ""
    ua = request.headers.get("user-agent", "")[:200] if request else ""
    data = auth.login(conn, payload.get("username", ""), payload.get("password", ""), ip, ua)
    resp = JSONResponse(data)
    _set_auth_cookie(resp, data["token"])
    return resp


@app.post("/api/auth/logout")
def api_logout(request: Request, authorization: str = ""):
    from .auth import current_user
    token = request.cookies.get(auth.COOKIE_NAME, "")
    if not token:
        authorization = request.headers.get("authorization", "")
        token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    if token:
        auth.logout(connect(), token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE_NAME, path="/")
    return resp


@app.post("/api/auth/change-password")
def api_change_password(payload: dict = Body(...), user=Depends(auth.current_user)):
    conn = connect()
    old = payload.get("old_password", "")
    new = payload.get("new_password", "")
    if len(new) < 8:
        raise HTTPException(400, "新口令至少 8 位")
    row = conn.execute("SELECT * FROM users WHERE username=?", (user["username"],)).fetchone()
    if not row or not auth.verify_password(old, row["password_hash"], row["salt"]):
        raise HTTPException(400, "原口令错误")
    ph, salt = auth.hash_password(new)
    with tx() as c:
        c.execute("UPDATE users SET password_hash=?, salt=?, must_change_password=0, "
                  "updated_at=datetime('now','localtime') WHERE id=?", (ph, salt, row["id"]))
        audit.append(c, user["username"], "auth.change_password", "user", row["id"])
    return {"ok": True}


@app.get("/api/auth/me")
def api_me(user=Depends(auth.current_user)):
    """当前身份。免登录模式下直接给本机管理员，前端因此不会出现登录页。"""
    if config.OPEN_ACCESS:
        me = dict(user)
        me["must_change_password"] = False
        me["open_access"] = True
        return me
    return user


# ================= 总览仪表盘 =================
@app.get("/api/dashboard")
def api_dashboard(user=Depends(auth.current_user)):
    conn = connect()
    def one(sql, *args):
        r = conn.execute(sql, args).fetchone()
        return r[0] if r else 0
    return {
        "assets": one("SELECT count(*) FROM assets"),
        "authz_unconfirmed": one("SELECT count(*) FROM assets WHERE authz_confirmed=0"),
        "vulns_open": one("SELECT count(*) FROM vulns WHERE status!='fixed'"),
        "vulns_critical": one("SELECT count(*) FROM vulns WHERE severity='critical' AND status!='fixed'"),
        "alerts_pending": one("SELECT count(*) FROM log_alerts WHERE triage='pending'"),
        "incidents_open": one("SELECT count(*) FROM incidents WHERE status!='closed'"),
        "incidents_p1p2": one("SELECT count(*) FROM incidents WHERE status!='closed' AND priority IN ('P1','P2')"),
        "logs_total": one("SELECT count(*) FROM logs"),
        "blocked_ips": one("SELECT count(*) FROM blocklist WHERE desired_state='blocked'"),
        "tasks_open": one("SELECT count(*) FROM tasks WHERE status='open'"),
        "audit_rows": one("SELECT count(*) FROM audit_logs"),
        "severity_breakdown": rows_to_list(conn.execute(
            "SELECT severity, count(*) n FROM vulns WHERE status!='fixed' GROUP BY severity").fetchall()),
        "alert_trend": rows_to_list(conn.execute(
            "SELECT substr(last_seen,1,10) d, count(*) n FROM log_alerts "
            "GROUP BY d ORDER BY d DESC LIMIT 7").fetchall()),
        "recent_alerts": rows_to_list(conn.execute(
            "SELECT * FROM log_alerts ORDER BY id DESC LIMIT 5").fetchall()),
        "recent_incidents": rows_to_list(conn.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT 5").fetchall()),
        "assessment": _guard_assessment(conn),
    }


def _guard_assessment(conn):
    """首页体检结论（防护引擎没装起来时给空壳，不影响总览）。"""
    try:
        from .guard import advice
        return advice.assess(conn)
    except Exception:
        return None


# ================= 网络配置 =================
@app.get("/api/network/ifaces")
def api_ifaces(user=Depends(auth.current_user)):
    return {"admin": is_admin(), "ifaces": iface.list_ifaces()}


@app.get("/api/network/changes")
def api_net_changes(limit: int = 50, user=Depends(auth.current_user)):
    return rows_to_list(netmgr.list_changes(connect(), limit))


@app.post("/api/network/snapshot")
def api_net_snapshot(payload: dict = Body(...), user=Depends(auth.current_user)):
    name = payload.get("iface")
    if not name:
        raise HTTPException(400, "缺少 iface")
    conn = connect()
    with tx() as c:
        sid = netmgr.take_snapshot(c, name, payload.get("reason", "手动快照"))
        audit.append(c, user["username"], "network.snapshot", "iface", name, None, {"snapshot_id": sid})
    return {"ok": True, "snapshot_id": sid}


@app.get("/api/network/snapshot/{sid}")
def api_net_snapshot_get(sid: int, user=Depends(auth.current_user)):
    return netmgr.get_snapshot(connect(), sid)


@app.post("/api/network/change")
def api_net_change(payload: dict = Body(...), user=Depends(auth.current_user)):
    """改 IP —— 五层兜底。需管理员。"""
    conn = connect()
    if not is_admin():
        raise HTTPException(403, "ELEVATION_REQUIRED: 改网络配置需要管理员权限")
    res = netmgr.change_ip(
        conn,
        payload.get("iface"),
        payload.get("ip"),
        int(payload.get("prefix", 24)),
        payload.get("gateway"),
        payload.get("dns"),
        user["username"],
        int(payload["watchdog_seconds"]) if payload.get("watchdog_seconds") else None,
    )
    return res


@app.post("/api/network/confirm/{change_id}")
def api_net_confirm(change_id: int, user=Depends(auth.current_user)):
    ok = netmgr.confirm_change(change_id)
    conn = connect()
    with tx() as c:
        audit.append(c, user["username"], "network.confirm", "change", change_id)
    return {"ok": ok}


@app.post("/api/network/rollback")
def api_net_rollback(payload: dict = Body(...), user=Depends(auth.current_user)):
    conn = connect()
    with tx() as c:
        res = netmgr.rollback(c, int(payload["snapshot_id"]), user["username"],
                              payload.get("reason", "手动回滚"))
    return res


@app.get("/api/network/verify")
def api_net_verify(iface_name: str = Query(...), user=Depends(auth.current_user)):
    conn = connect()
    st = iface_adapter_state = iface.get_iface_state(iface_name)
    ips = st.get("ipv4") or []
    if not ips:
        raise HTTPException(400, "该网卡无 IPv4")
    return netmgr.verify_three_level(conn, iface_name, ips[0]["ip"], st.get("gateway"))


# ================= 前端托管 =================
# 必须放在模块级：用 `uvicorn backend.app:app` 直接跑 app 对象时也照样有页面，
# 不能只写在 __main__ 里（那样只有 python -m backend.app 才托管前端）。
def _mount_frontend(target):
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse

    fe_dir = config.BASE_DIR.parent / "frontend"
    if not fe_dir.exists():
        print("[web] 未找到前端目录:", fe_dir)
        return None

    @target.get("/", include_in_schema=False)
    def _index():
        return FileResponse(str(fe_dir / "index.html"))

    @target.get("/favicon.ico", include_in_schema=False)
    def _favicon():
        icon = fe_dir / "icon.png"
        if icon.exists():
            return FileResponse(str(icon))
        raise HTTPException(404, "no icon")

    target.mount("/static", StaticFiles(directory=str(fe_dir)), name="static")
    print("[web] 前端已托管:", fe_dir)
    return fe_dir


_mount_frontend(app)


if __name__ == "__main__":
    import uvicorn

    port = config.PORT
    if port == 0:
        s = socket.socket()
        s.bind((config.HOST, 0))
        port = s.getsockname()[1]
        s.close()
    (config.DATA_DIR / "port.txt").write_text(str(port), encoding="utf-8")
    print("=" * 56)
    print(" %s %s" % (config.APP_NAME, config.APP_VERSION))
    print(" Local:  http://%s:%d/" % (config.HOST, port))
    print("=" * 56)
    uvicorn.run(app, host=config.HOST, port=port, log_level="info")
