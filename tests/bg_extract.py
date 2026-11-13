# -*- coding: utf-8 -*-
"""从 index.html 抽出内联 <script> 供 node --check 做语法校验，并统计 CSS 大括号配平。

用法：python tests\bg_extract.py  →  写出 %TEMP%\bg_front.js 并打印统计
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = os.path.join(ROOT, "frontend", "index.html")
OUT = os.path.join(os.environ.get("TEMP", "."), "bg_front.js")

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

h = io.open(HTML, encoding="utf-8").read()
m = re.search(r'<script nonce="bg2026">(.*?)</script>', h, re.S)
if not m:
    print("FAIL 没找到内联脚本")
    sys.exit(1)
js = m.group(1)
io.open(OUT, "w", encoding="utf-8").write(js)

print("html 行数      %d" % len(h.splitlines()))
print("js 字符数      %d" % len(js))
print("css 大括号     %d / %d %s" % (h.count("{"), h.count("}"), "OK" if h.count("{") == h.count("}") else "不配平"))
print("写出           %s" % OUT)
