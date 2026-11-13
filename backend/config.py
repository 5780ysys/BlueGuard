# -*- coding: utf-8 -*-
"""蓝盾 BlueGuard · 统一配置。

单机便携版：所有数据跟在 data/ 目录下，零外部依赖。

访问控制两档（环境变量 BLUEGUARD_AUTH）：
  open     —— 打开即进入，不需要口令。适合本机/内网单用户使用，默认。
  password —— 保留口令登录页，适合多人共用一台机器的场景。
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("BLUEGUARD_DATA", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "blueguard.db"
KEY_FILE = DATA_DIR / "master.key"
LOG_DIR = DATA_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

APP_NAME = "蓝盾 BlueGuard"
APP_VERSION = "V3.2"
APP_EDITION = "Workstation"          # 部署形态标签：Workstation | Server（不写"单机版"）
APP_TAGLINE = "终端防护引擎"
DEPLOY_MODE = os.environ.get("BLUEGUARD_MODE", "standalone")  # standalone | team
HOST = os.environ.get("BLUEGUARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("BLUEGUARD_PORT", "0"))  # 0 = 随机端口

# 访问控制：默认打开即用
AUTH_MODE = (os.environ.get("BLUEGUARD_AUTH", "open") or "open").strip().lower()
OPEN_ACCESS = AUTH_MODE != "password"

# 危险操作看门狗默认秒数
WATCHDOG_SECONDS = int(os.environ.get("BLUEGUARD_WATCHDOG", "120"))
