# tests/ — 防护引擎实测脚本

这些不是单元测试，是**打真枪**的验证脚本：真的起服务、真的读本机进程、真的往 Windows 防火墙写规则再撤销。
每个数字都能复现，README 里引用的结果全部来自这里。

## 先决条件

```powershell
cd 'D:\Work\BlueGuard'
$env:BLUEGUARD_DATA = "$env:TEMP\bg_test"     # 别污染 data\blueguard.db
```

阻断类脚本（`bg_e2e.py`、`bg_respond_api.py`、`_selftest_respond.py`）要求**管理员权限的终端**，
否则会在写防火墙时返回 `ELEVATION_REQUIRED`——那也是正确行为，脚本会自适应。

## 脚本清单

| 脚本 | 测什么 | 怎么跑 | 预期 |
|---|---|---|---|
| `bg_atk_rules.py` | 29 组「攻击者真命令 vs 运维相似行为」正反例，验证规则不误判 | `python tests\bg_atk_rules.py` | PASS 53 / FAIL 0 |
| `bg_atk_chain.py` | 喂散点事件测攻击链拼接、落库、开单、同窗口去重 | `python tests\bg_atk_chain.py` | PASS 11 / FAIL 0 |
| `bg_chain_gate.py` | 链的证据门槛：姿态类 / low / 单战术 / 两战术都不该拼 | `python tests\bg_chain_gate.py` | PASS 5 / FAIL 0 |
| `bg_selfcheck.py` | 引擎三轮连跑，验证不自噬（不把自己的 PowerShell 判成攻击） | 需先起服务，见下 | hits 9/0/1，无「编码命令」事件 |
| `bg_atk_live.py` | 真实主机两轮扫描：耗时、命中、噪声 | 需先起服务 | 深扫 ~5.3s / 常规 ~0.78s |
| `bg_e2e.py` | 端到端真阻断：造连接 → 命中 → 防火墙真出现规则 → 撤销 | 管理员 + 服务 | 失败 0 |
| `bg_respond_api.py` | 事件详情「人工处置」四类动作 + 错误分支 | 管理员 + 服务 | 失败 0 |
| `bg_smoke31.py` | 打包版冒烟 13 项（V3.1） | 起 exe 后传 BASE | 13/13 |
| `bg_probe.py` | 引擎单轮探测（`--fresh` / `--deep`） | 直接跑 | 打印 stats |
| `bg_bench.py` | 采集器性能基准（psutil vs CIM） | 直接跑 | 对照 ms 数 |

## 需要先起服务的三个

```powershell
# 终端 1
$env:BLUEGUARD_DATA="$env:TEMP\bg_test"
python -m uvicorn backend.app:app --host 127.0.0.1 --port 18080

# 终端 2
python tests\bg_selfcheck.py
python tests\bg_atk_live.py
```

`bg_e2e.py` 与 `bg_respond_api.py` 里 BASE 写死 `127.0.0.1:18080`，改端口需同步改脚本首行。

`bg_smoke31.py` 接受参数：

```powershell
$env:BLUEGUARD_NOBROWSER='1'; $env:BLUEGUARD_PORT='18091'; $env:BLUEGUARD_DATA="$env:TEMP\bg_exe"
Start-Process dist\BlueGuard.exe -WindowStyle Hidden
python tests\bg_smoke31.py http://127.0.0.1:18091
```

## 收尾

脚本自己会清理它造的防火墙规则和临时规则。万一中断，手工兜底：

```powershell
netsh advfirewall firewall show rule name=all | Select-String 'BlueGuard-'   # 应为 0
```

按 `BlueGuard-` 前缀命名的规则都是本程序造的，可安全删除（界面「防护中心 → 响应与对账 → 清理」也行）。
