# -*- coding: utf-8 -*-
"""蓝盾 BlueGuard · 便携点击即用入口（PyInstaller 打包入口）。

双击 exe：
  1) （冻结态）把数据目录放到 exe 旁边 <exe目录>/data，绝不落在 PyInstaller 临时解冻目录；
  2) 起 uvicorn（随机端口，写 <data>/port.txt）；
  3) 用默认浏览器打开 http://127.0.0.1:<port>/；
  4) 关闭浏览器即可退出，端口随之释放（uvicorn 阻塞直到被关）。
"""
import os
import socket
import sys
import threading
import webbrowser

# ---- 必须在 import backend 之前决定数据目录 --------------------------
_FROZEN = bool(getattr(sys, "frozen", False))
if _FROZEN:
    _EXE_DIR = os.path.dirname(os.path.abspath(sys.executable))
    _DATA_DIR = os.path.join(_EXE_DIR, "data")
    _DATA_DIR = os.environ.get("BLUEGUARD_DATA", _DATA_DIR)
else:
    # 开发态：跟随项目 backend/data
    _DATA_DIR = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend", "data"))
os.environ.setdefault("BLUEGUARD_DATA", _DATA_DIR)
os.makedirs(_DATA_DIR, exist_ok=True)

import backend.config as config          # noqa: E402
# 让 FastAPI 自动发现 backend 路由：app 在 backend/app.py 定义，这里直接复用
import backend.app                         # noqa: E402
from backend.app import app                # noqa: E402


def _pick_port():
    s = socket.socket()
    s.bind((config.HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _prep_frontend():
    """定位并 mount 前端 index.html；返回 (fe_dir) 或 None。"""
    if _FROZEN:
        base = getattr(sys, "_MEIPASS", "") or _EXE_DIR
        fe_dir = os.path.join(base, "frontend")
    else:
        fe_dir = os.path.normpath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend"))
    if os.path.isdir(fe_dir):
        return fe_dir
    return None


def main():
    # 冻结为无控制台窗口(--noconsole)时，stdout/stderr 为 None，uvicorn/logging 写入会崩溃；
    # 重定向到 exe 旁 data/launcher.log，彻底避免黑框或闪退。
    if _FROZEN and (sys.stdout is None or sys.stderr is None):
        try:
            _log = open(os.path.join(_DATA_DIR, "launcher.log"), "a", encoding="utf-8", buffering=1)
            sys.stdout = _log
            sys.stderr = _log
        except Exception:
            pass

    # 前端托管已在 backend.app 模块级完成（/ 与 /static），此处不再重复 mount。

    port = config.PORT or _pick_port()
    os.makedirs(config.DATA_DIR, exist_ok=True)
    (config.DATA_DIR / "port.txt").write_text(str(port), encoding="utf-8")

    print("=" * 56)
    print(" %s %s" % (config.APP_NAME, config.APP_VERSION))
    print(" Local:  http://%s:%d/" % (config.HOST, port))
    print(" 数据目录: %s" % config.DATA_DIR)
    print("=" * 56)

    # 服务就绪后用「应用窗口」打开（独立桌面窗口，非浏览器标签页）
    def _open_browser():
        import subprocess
        import time
        time.sleep(0.6)  # 给 uvicorn 一点启动时间
        url = "http://%s:%d/" % (config.HOST, port)
        # 优先用 Edge/Chrome 的 --app 模式：弹独立应用窗口（无地址栏/标签/书签），
        # 且不动用户当前浏览器会话。
        broken = False
        for cand in (
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ):
            if os.path.isfile(cand):
                try:
                    # --app 模式：独立应用窗口；--no-first-run 避免引导页
                    _cf = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0
                    _si = None
                    if os.name == "nt":
                        _si = subprocess.STARTUPINFO()
                        _si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                        _si.wShowWindow = 0
                    subprocess.Popen(
                        [cand, "--app=" + url, "--no-first-run", "--disable-features=Translate"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        creationflags=_cf, startupinfo=_si)
                    broken = True
                    break
                except Exception:
                    continue
        if not broken:
            try:
                webbrowser.open(url)
            except Exception:
                pass
    # 无界面/服务化启动：BLUEGUARD_NOBROWSER=1 时不弹窗口，只起服务
    _nobrowser = os.environ.get("BLUEGUARD_NOBROWSER", "").strip().lower() in ("1", "true", "yes", "on")
    if not _nobrowser:
        threading.Thread(target=_open_browser, daemon=True).start()
    else:
        print(" BLUEGUARD_NOBROWSER=1：未自动打开窗口，请手动访问上面的地址")

    import uvicorn
    uvicorn.run(app, host=config.HOST, port=port, log_level="warning")


if __name__ == "__main__":
    main()