import re, html, sys, io, os
import markdown

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CSS = """
:root{--bg:#fff;--ink:#1f2937;--ink2:#6b7280;--line:#e5e7eb;--blue:#2563eb;--blue-weak:#eff6ff}
*{box-sizing:border-box}
body{margin:0;background:#f7f8fa;color:var(--ink);
  font:400 14px/1.78 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1320px;margin:0 auto;padding:28px 24px 80px;
  display:grid;grid-template-columns:250px minmax(0,1fr);gap:36px;align-items:start}
.topbar{grid-column:1/3;display:flex;align-items:center;gap:12px;margin-bottom:4px}
.topbar .badge{background:var(--blue-weak);color:var(--blue);font-size:12px;padding:2px 8px;border-radius:3px;font-weight:500}
.topbar .meta{color:var(--ink2);font-size:12px;margin-left:auto}
.toc{position:sticky;top:20px;max-height:calc(100vh - 60px);overflow:auto;
  background:#fff;border:1px solid var(--line);border-radius:6px;padding:14px 12px;font-size:12.5px}
.toc .t{font-weight:600;color:var(--ink2);font-size:11px;letter-spacing:.5px;margin:0 0 8px 6px}
.toc ul{list-style:none;margin:0;padding:0}
.toc ul ul{padding-left:12px}
.toc li{margin:0}
.toc a{display:block;color:#374151;text-decoration:none;padding:3px 6px;border-radius:3px;line-height:1.5}
.toc a:hover{background:var(--blue-weak);color:var(--blue)}
.doc{background:#fff;border:1px solid var(--line);border-radius:6px;padding:44px 52px;min-width:0}
h1{font-size:27px;line-height:1.35;margin:0 0 22px;font-weight:600;letter-spacing:-.2px}
h2{font-size:20px;margin:44px 0 14px;padding-bottom:8px;border-bottom:1px solid var(--line);font-weight:600}
h3{font-size:16px;margin:28px 0 10px;font-weight:600}
h4{font-size:14px;margin:20px 0 8px;font-weight:600;color:#374151}
p{margin:10px 0}
ul,ol{margin:10px 0;padding-left:22px}
li{margin:4px 0}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
strong{font-weight:600}
hr{border:none;border-top:1px solid var(--line);margin:34px 0}
table{border-collapse:collapse;width:100%;margin:14px 0;font-size:13px;display:table}
th,td{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top;word-break:break-word}
th{background:#f8fafc;font-weight:600;color:#374151;font-size:12.5px;white-space:nowrap}
td:first-child{min-width:64px}
tr:nth-child(even) td{background:#fcfdfe}
code{background:#f3f4f6;padding:1px 5px;border-radius:3px;font-size:12.5px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#b91c1c}
pre{background:#0f172a;color:#e2e8f0;padding:14px 16px;border-radius:6px;overflow:auto;
  font-size:12.5px;line-height:1.7;margin:14px 0}
pre code{background:none;color:inherit;padding:0;font-size:12.5px}
blockquote{margin:14px 0;padding:10px 16px;background:var(--blue-weak);border-left:3px solid var(--blue);
  border-radius:0 4px 4px 0;color:#1e40af;font-size:13px}
pre.mermaid{background:#fff;border:1px solid var(--line);text-align:center;padding:18px;color:var(--ink);overflow-x:auto}
.mmd-warn{display:none;background:#fffbeb;border:1px solid #fde68a;color:#92400e;
  padding:10px 14px;border-radius:4px;font-size:12.5px;margin:12px 0}
@media (max-width:1000px){.wrap{grid-template-columns:1fr}.toc{display:none}}
@media print{body{background:#fff}.toc{display:none}.wrap{display:block;padding:0}
  .doc{border:none;padding:0}pre{white-space:pre-wrap}}
"""

TPL = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>__CSS__</style></head>
<body><div class="wrap">
<div class="topbar"><span class="badge">__BADGE__</span><span class="meta">__META__</span></div>
<nav class="toc"><div class="t">目录</div>__TOC__</nav>
<article class="doc">__BODY__</article>
</div>
<div class="mmd-warn" id="mmdWarn">当前环境未能加载图表渲染脚本（离线或网络受限）。下图中标注为「示例图」的代码块为 Mermaid 源码，可用 Typora / VS Code / GitHub 打开同一 Markdown 文件查看渲染效果；正文与表格不受影响。</div>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"></script>
<script>
(function(){
  if (!window.mermaid) { document.getElementById('mmdWarn').style.display='block'; return; }
  try {
    mermaid.initialize({ startOnLoad:false, theme:'base', securityLevel:'strict',
      themeVariables:{ primaryColor:'#eff6ff', primaryBorderColor:'#bfdbfe', primaryTextColor:'#1f2937',
        lineColor:'#9ca3af', fontSize:'13px' } });
    mermaid.run({ querySelector: 'pre.mermaid' }).catch(function(){});
  } catch(e) { document.getElementById('mmdWarn').style.display='block'; }
})();
</script>
</body></html>"""


def render(src, dst, title, badge, meta):
    raw = io.open(src, encoding='utf-8').read()
    md = markdown.Markdown(extensions=['tables', 'fenced_code', 'toc', 'sane_lists', 'attr_list'],
                           extension_configs={'toc': {'toc_depth': '2-3'}})
    body = md.convert(raw)
    toc = md.toc

    # 把 ```mermaid 代码块转成 mermaid 可识别的容器，并还原被转义的 HTML 实体
    def to_mmd(m):
        return '<pre class="mermaid">' + html.unescape(m.group(1)) + '</pre>'
    body = re.sub(r'<pre><code class="language-mermaid">(.*?)</code></pre>', to_mmd, body, flags=re.S)

    html_out = (TPL.replace('__TITLE__', title).replace('__CSS__', CSS)
                   .replace('__BADGE__', badge).replace('__META__', meta)
                   .replace('__TOC__', toc).replace('__BODY__', body))
    io.open(dst, 'w', encoding='utf-8').write(html_out)
    print('written:', dst, len(html_out), 'bytes')


render(os.path.join(BASE, '蓝盾蓝队平台_设计文档.md'), os.path.join(BASE, '设计文档_评审版.html'),
       '蓝盾 BlueGuard · 网络安全蓝队运营平台 设计文档 V2.0',
       '设计文档 V2.0',
       '14 模块 · 42 张表 · 96 个接口 · 14 个页面 · 单机 / 团队双模式')

render(os.path.join(BASE, '代码审查报告.md'), os.path.join(BASE, '代码审查报告_评审版.html'),
       '蓝盾 BlueGuard 原型 · 代码审查报告',
       '代码审查报告',
       'S/P/C 三类共 21 项发现 · 已修 7 项 · 7 项上线阻断要求')

render(os.path.join(BASE, '功能真实性与可行性评估.md'), os.path.join(BASE, '功能真实性与可行性评估.html'),
       '蓝盾 BlueGuard · 功能真实性与可行性评估',
       '评估报告',
       '三层判定 · 14 模块对照 · 7 项技术假设实测')
