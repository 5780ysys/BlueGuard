@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title 蓝盾 BlueGuard · 终端防护引擎
cd /d "%~dp0"

set PY=python
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
  set PY=%LOCALAPPDATA%\Programs\Python\Python311\python.exe
)

echo ============================================
echo   蓝盾 BlueGuard · 终端防护引擎 V3.2
echo ============================================
echo 正在启动（打开即用，无需登录）...
echo.

if exist "backend\data\port.txt" del /q "backend\data\port.txt" >nul 2>&1
start "" /b "%PY%" -m backend.app

set PORT=
for /l %%i in (1,1,30) do (
  if not defined PORT (
    if exist "backend\data\port.txt" (
      set /p PORT=<backend\data\port.txt
    ) else (
      timeout /t 1 >nul
    )
  )
)

if defined PORT (
  start "" "http://127.0.0.1:!PORT!/"
  echo 已打开 http://127.0.0.1:!PORT!/
) else (
  echo 端口文件未生成，请查看 backend\data\port.txt 或运行日志。
)
pause
