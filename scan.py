#!/usr/bin/env python3
# Argulus - 小百眼巨人。轻量漏洞验证，只验证不利用，强度靠分析得准，不靠请求多。
# 它是 XenonYrgus 的前身，先睁一只眼。
#
# 强度控制写在最前面，免得我以后手贱：
# 只分析首页和首页直接链接，不爬深；POST 只测表单默认 action，不猜路径。
# 不加端口扫描、指纹库、利用链、反弹 shell、文件上传绕过。
# 默认延迟 0.8，请求上限 120，参数上限 6。

import argparse
import ipaddress
import json
import random
import re
import socket
import sys
import time
from datetime import datetime
from difflib import SequenceMatcher
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qsl, urlunparse, urljoin

try:
    import requests
except ImportError:
    # 跑单测的机器常常啥都没装，纯函数不该被这个卡住
    requests = None

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich import box
    from rich.prompt import Prompt, Confirm, IntPrompt, FloatPrompt
    from rich.table import Table
    from rich.rule import Rule
    from rich.text import Text
    from rich.align import Align
    console = Console()
except ImportError:
    # 这里偷懒了，没 rich 就素颜打印；交互模式会在入口把它拦下来
    console = None
    Panel = box = None
    Prompt = Confirm = IntPrompt = FloatPrompt = None
    Table = Rule = Text = Align = None

# 配色写死在这儿，想换主题改这五行就够了
C_MAIN = "#7DF9FF"   # logo、标题、选中项、分隔线
C_ACC = "#FF9E64"    # 输入提示、参数名
C_WARN = "#FF5555"   # 命中结果
C_DIM = "#6C7A89"    # 说明文字、状态行
C_OK = "#50FA7B"     # 完成提示、未命中

DELAY = 0.8
TIMEOUT = 6
LIMIT = 120          # 请求上限
MAX_PARAMS = 6       # 参数上限
USED = 0             # 这轮已经发了多少
LEFT = 0             # 当前参数还剩几个请求，按参数均分用的
_s = None

PASSWD = re.compile(r"root:[^:]*:0:0:", re.I)
WININI = re.compile(r"\[fonts\]|\[extensions\]", re.I)
DYN = re.compile(r"csrf|nonce|timestamp|_token|sessid|rand", re.I)

# (两个恒真, 两个恒假)，引号闭合和不闭合各来一组
SQL_PAIRS = [
    (["' AND '1'='1", "' AND '7'='7"], ["' AND '1'='2", "' AND '3'='9"]),
    ([" AND 1=1", " AND 7=7"], [" AND 1=2", " AND 3=9"]),
]
TRAVERSE = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "../../../../windows/win.ini",
]
FALLBACK = ["id", "page", "file", "q", "search", "cat"]
TAG = "argulus"
ITEMS = ("SQLi", "XSS", "遍历")

# 这些词当参数名基本都是解析噪音，不区分大小写一律丢掉
BLACK = set(
    "url uri href src action method type name value submit button input form html "
    "http https www com cn org net index php asp jsp aspx".split()
)
ORDER = {"URL query": 0, "form POST": 1, "form GET": 2, "链接发现": 3}
DEFAULT_TARGET = "http://127.0.0.1:8000/?id=1"
REPORT_DEFAULT = "argulus_report.json"
ACCURACY_NOTE = "脚本自评置信度，未经人工复核不计入准确率"
ACCURACY_TEXT = (
    "准确率声明：置信度只是脚本自评，未经人工复核不计入准确率。\n"
    "工具不给自己打分，不输出百分比，高 / 中 / 低也不是准确率。\n"
    "命中不等于可利用，未命中不等于安全，结论一律以人工复核为准。"
)

# 实心块字，8 行高、7 个字母各 7 列，加空格 55 列；只用 █ ▀ ▄ ╔ ╗ ╚ ╝ ═ ║
_BLOCKS = [
    ["  ▄▀▀▄ ", " █    █", "█     █", "███████",
     "█     █", "█     █", "█     █", "▀     ▀"],  # A
    ["██████▄", "█     █", "█     █", "███████",
     "█   ▀▄ ", "█    ▀▄", "█    ▀▄", "▀     ▀"],  # R
    [" ╔═══╗ ", "║      ", "║      ", "║  ═══╗",
     "║     ║", "║     ║", "║     ║", " ╚═══╝ "],  # G
    ["║     ║", "║     ║", "║     ║", "║     ║",
     "║     ║", "║     ║", "║     ║", " ╚═══╝ "],  # U
    ["█      ", "█      ", "█      ", "█      ",
     "█      ", "█      ", "█      ", "╚══════"],  # L
    ["║     ║", "║     ║", "║     ║", "║     ║",
     "║     ║", "║     ║", "║     ║", " ╚═══╝ "],  # U
    [" ╔═══╗ ", "║      ", "║      ", " ╚═══╗ ",
     "      ║", "      ║", "      ║", " ╚═══╝ "],  # S
]
LOGO = [" ".join(b[i] for b in _BLOCKS) for i in range(8)]


def out(msg, style=None):
    # markup 关掉，不然证据里的 [fonts] 会被 rich 当样式标签吞掉
    if console:
        console.print(msg, style=style, markup=False)
    else:
        print(msg)


def rule():
    if console:
        console.print(Rule(style=C_MAIN))
    else:
        print("-" * 60)


def rnd():
    return "".join(random.choice("0123456789abcdef") for _ in range(6))


def private_host(host):
    # 域名一律不放行，连 localhost 也一样：DNS 指去哪儿我可不想猜
    host = (host or "").strip()
    try:
        if "/" in host:
            net = ipaddress.ip_network(host, strict=False)
            # 这里偷懒了，只看网段头一个地址，够用就行
            return private_host(str(net.network_address))
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def sig(r):
    if r is None or r.status_code >= 500:
        return None
    # 抹掉数字和空白，带时间戳/nonce 的页面不然会一直给我报洞
    txt = re.sub(r"\s+", " ", re.sub(r"\d+", "0", r.text))
    return r.status_code, txt


def same(a, b):
    if a is None or b is None or a[0] != b[0]:
        return False
    # 长度差太多就别比内容了，SequenceMatcher 啃长文本挺慢
    if abs(len(a[1]) - len(b[1])) > 200:
        return False
    return SequenceMatcher(None, a[1][:4000], b[1][:4000]).ratio() > 0.97


def blind(b, ts, fs):
    # 双盲：恒真两个都回到基线，恒假两个都偏离，两组内部还得各自自洽。
    # WAF 拦截页最爱伪造这种差异，有一条对不上就当没洞
    if any(x is None for x in [b] + ts + fs):
        return False
    return (
        all(same(b, t) for t in ts)
        and same(ts[0], ts[1])
        and same(fs[0], fs[1])
        and all(not same(b, f) for f in fs)
    )


def find_params(html):
    # 单测还在用这个，留着别删；正式的自动分析走下面的 Page
    names = re.findall(r'<input[^>]+name=["\']?([\w\-]+)', html, re.I)
    names += re.findall(r"[?&]([\w\-]+)=", html)
    return list(dict.fromkeys(n for n in names if 1 < len(n) < 24))


def req(url, params=None, raw=None, data=None):
    global USED, LEFT, _s
    if LEFT <= 0 or USED >= LIMIT:
        return None
    LEFT -= 1
    USED += 1
    if _s is None:
        _s = requests.Session()
        _s.headers.update({"User-Agent": "argulus/0.1 (verification only)"})
    time.sleep(DELAY)
    try:
        if raw is not None:
            return _s.get(raw, timeout=TIMEOUT)
        if data is not None:
            return _s.post(url, data=data, timeout=TIMEOUT)
        return _s.get(url, params=params or {}, timeout=TIMEOUT)
    except requests.RequestException as e:
        out(f"[!] 请求挂了 ({type(e).__name__}: {e})，跳过", C_DIM)
        return None


def send(p, val, raw=False):
    # POST 走 form body，GET 走 query；带 %2f 的那条手工拼，别让 urlencode 把它吃掉
    q = dict(p["base"])
    q[p["name"]] = val
    if raw:
        txt = "&".join(f"{a}={b}" for a, b in q.items())
        if p["method"] == "POST":
            return req(p["url"], data=txt)
        return req(p["url"], raw=p["url"].split("?")[0] + "?" + txt)
    if p["method"] == "POST":
        return req(p["url"], data=q)
    return req(p["url"], q)


def dynamic(r):
    # 时间戳/token 这类动态内容，置信度就得压一档
    return bool(r is not None and DYN.search(r.text[:4000]))


def grade(b, ts, fs, codes, dyn):
    # 置信度规则写死，别以后偷偷放松：
    # 高：双盲四请求全部自洽，基线/恒真/恒假长度差异符合预期
    # 中：双盲成立但长度差异接近阈值，或响应含动态内容特征
    # 低：单条命中但另一组不成立，或响应状态码异常
    if any(c is None or c >= 400 for c in codes):
        return "低"
    if b is not None:
        if any(x is None for x in ts + fs):
            return "低"
        gap = max(abs(len(b[1]) - len(f[1])) for f in fs)
        return "中" if (dyn or gap < 12) else "高"
    return "中" if dyn else "高"


def check_sqli(p, b_resp):
    b = sig(b_resp)
    if b is None:
        return None
    v = p["value"]
    for trues, falses in SQL_PAIRS:
        tr = [send(p, v + x) for x in trues]
        fr = [send(p, v + x) for x in falses]
        ts = [sig(r) for r in tr]
        fs = [sig(r) for r in fr]
        if blind(b, ts, fs):
            ev = (
                f"payload: {v + trues[0]}  vs  {v + falses[0]}\n"
                f"响应长度: 基线 {len(b[1])} / 恒真 "
                f"{','.join(str(len(t[1])) for t in ts)} / 恒假 "
                f"{','.join(str(len(f[1])) for f in fs)}"
            )
            rs = [b_resp] + tr + fr
            return {
                "type": "SQLi (boolean-blind)", "evidence": ev,
                "confidence": grade(
                    b, ts, fs,
                    [r.status_code if r else None for r in rs],
                    any(dynamic(r) for r in rs),
                ),
            }
    return None


def check_xss(p):
    # 不发 <script>，就塞一个无害标记，能不能执行让人手工去看
    mark = TAG + "_" + rnd()
    payload = f'">{mark}<'
    r = send(p, payload)
    if r is None:
        return None
    # 只认 html。JSON 里回显个字符串不等于能执行，别给自己加戏
    ct = r.headers.get("Content-Type", "").lower()
    if "html" not in ct or payload not in r.text:
        return None
    return {
        "type": "XSS (reflected)",
        "evidence": f"payload: {payload}\n命中特征串: {mark!r} (原样未转义，Content-Type: {ct})",
        "confidence": grade(None, None, None, [r.status_code], dynamic(r)),
    }


def check_traverse(p):
    # 先打一个八竿子打不着的文件名，404 页里碰巧有 root: 的直接排掉
    noise = send(p, TAG + "_404_" + rnd() + ".txt")
    if noise is None:
        return None
    dirty = bool(PASSWD.search(noise.text) or WININI.search(noise.text))
    for x in TRAVERSE:
        r = send(p, x, raw=True)
        if r is None or r.status_code != 200:
            continue
        hit = PASSWD.search(r.text) or WININI.search(r.text)
        if hit and not dirty:
            return {
                "type": "Path traversal",
                "evidence": f"payload: {x}\n噪声基线: 未命中特征\n命中特征串: {hit.group()[:40]!r}",
                "confidence": grade(None, None, None,
                                    [noise.status_code, r.status_code], dynamic(r)),
            }
    return None


class Page(HTMLParser):
    # 只认首页这一张 HTML，链接只拆 href 里的 query，不跟着爬
    def __init__(self):
        super().__init__()
        self.forms = []
        self.links = []
        self.cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.cur = {"action": a.get("action", ""),
                        "method": (a.get("method") or "GET").upper(), "fields": []}
            self.forms.append(self.cur)
        elif self.cur is not None and tag in ("input", "select", "textarea"):
            n = a.get("name")
            if n:
                t = (a.get("type") or "text").lower()
                self.cur["fields"].append((n, a.get("value") or "1", t, "required" in a))
        elif tag == "a":
            self.links.extend(parse_qsl(urlparse(a.get("href", "")).query))

    def handle_endtag(self, tag):
        if tag == "form":
            self.cur = None


def mk(name, src, method, required, val, url, base):
    # 参数就一个 dict，懒得起 dataclass
    return {"name": name, "source": src, "method": method,
            "required": required, "value": val or "1",
            "url": url, "base": dict(base)}


def analyze(html, url, mp):
    pu = urlparse(url)
    clean = urlunparse(pu._replace(query="", fragment=""))
    q = dict(parse_qsl(pu.query))
    pg = Page()
    pg.feed(html)
    cs = [mk(k, "URL query", "GET", False, v, clean, q) for k, v in q.items()]
    for f in pg.forms:
        # 只测表单自己写的 action，猜路径这种事我不干
        action = urljoin(clean, f["action"] or clean)
        au = urlparse(action)
        action = urlunparse(au._replace(query="", fragment=""))
        method = "POST" if f["method"] == "POST" else "GET"
        src = "form POST" if method == "POST" else "form GET"
        base = dict(parse_qsl(au.query))
        base.update({n: v for n, v, _, _ in f["fields"]})
        for n, v, t, reqd in f["fields"]:
            # 隐藏字段也一起测，不因为看不见就跳过；它一律不算必填
            need = reqd and t not in ("hidden", "submit", "button", "reset", "image")
            cs.append(mk(n, src, method, need, v, action, base))
    for k, v in pg.links:
        cs.append(mk(k, "链接发现", "GET", False, v, clean, q))
    if not cs:
        # 页面上啥也没捞到，用那几个烂大街的顶上
        cs = [mk(k, "URL query", "GET", False, "1", clean, q) for k in FALLBACK]
    seen = {}
    for c in cs:
        key = c["name"].lower()
        if key in BLACK or not (1 < len(c["name"]) < 24):
            continue
        if key not in seen or ORDER[c["source"]] < ORDER[seen[key]["source"]]:
            seen[key] = c
    return sorted(seen.values(), key=lambda c: (ORDER[c["source"]], c["name"]))[:mp]


def manual(names, url, mp):
    pu = urlparse(url)
    clean = urlunparse(pu._replace(query="", fragment=""))
    q = dict(parse_qsl(pu.query))
    return [mk(k, "URL query", "GET", False, q.get(k, "1"), clean, q)
            for k in names[:mp]]


def hit_panel(f, name, title):
    if not Panel:
        print(f"{title} {f['type']}\n参数 {name}\n{f['evidence']}")
        return
    body = Text()
    body.append(f["type"] + "\n", style=f"bold {C_WARN}")
    body.append(name + "\n", style=C_ACC)
    body.append(f["evidence"], style="white")
    console.print(Panel(body, title=f"[bold {C_WARN}] {title} [/]",
                        border_style=C_WARN, box=box.HEAVY, expand=False))


def summary_table(rows):
    if not Table:
        # 没 rich 也得有这张表，素颜打一遍，命中时不能省
        for r in rows:
            print(" | ".join(str(r[k]) for k in (
                "param", "source", "method", "item", "verdict",
                "evidence", "confidence", "reality")))
        return
    # 8 列挤 80 列终端，列名和「待人工复核」得护住，只委屈证据摘要那列
    t = Table(show_header=True, header_style=C_MAIN, border_style=C_MAIN,
              box=box.SIMPLE, expand=False, padding=(0, 1))
    cols = (
        ("参数", dict(min_width=4, no_wrap=True)),
        ("来源", dict(min_width=9, no_wrap=True)),
        ("method", dict(min_width=6, no_wrap=True)),
        ("测试项", dict(min_width=6, no_wrap=True)),
        ("结论", dict(min_width=6, no_wrap=True)),
        ("证据摘要", dict(min_width=8, max_width=24, overflow="ellipsis", no_wrap=True)),
        ("置信度", dict(min_width=6, no_wrap=True)),
        ("真实性", dict(min_width=10, no_wrap=True)),
    )
    for c, kw in cols:
        t.add_column(c, style=C_DIM, **kw)
    for r in rows:
        v = r["verdict"]
        st = C_WARN if v == "命中" else (C_OK if v == "未命中" else C_DIM)
        t.add_row(Text(r["param"], style=C_ACC), r["source"], r["method"], r["item"],
                  Text(v, style=st), r["evidence"], r["confidence"],
                  Text(r["reality"], style=C_DIM))
    # 窗口太窄时宁可让行折一下，也别把「真实性」那一列整个挤没
    Console(width=max(console.width, 100),
            force_terminal=console.is_terminal).print(t)


def write_report(path, target, n, findings):
    data = {
        "target": target,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "params_total": n,
        "requests_used": USED,
        "findings": findings,
        "accuracy_note": ACCURACY_NOTE,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    out(f"报告已写入 {path}", C_DIM)


def scan(params, limit, ui=False):
    global LEFT
    rows, findings = [], []
    # 预算按参数均分，别让第一个参数把 120 个请求吃光
    per = max(1, (limit - USED) // max(1, len(params)))
    for p in params:
        LEFT = min(per, max(0, limit - USED))
        skipped = LEFT <= 0
        out(f"-- {p['name']} ({p['source']}/{p['method']})" if ui else f"-- {p['name']}",
            C_ACC if ui else C_DIM)
        got, err = {}, ""
        try:
            if not skipped:
                b_resp = send(p, p["value"])
                got["SQLi"] = check_sqli(p, b_resp)
                got["XSS"] = check_xss(p)
                got["遍历"] = check_traverse(p)
        except Exception as e:
            # 一个参数炸了不许拖垮整轮，但信息也别吞掉
            err = f" ({type(e).__name__}: {e})"
            if not ui:
                out(f"[!] {p['name']} 出错{err}", C_DIM)
        for item in ITEMS:
            g = got.get(item)
            verdict = "命中" if g else ("跳过" if skipped else "未命中")
            rows.append({
                "param": p["name"], "source": p["source"], "method": p["method"],
                "item": item, "verdict": verdict,
                "evidence": g["evidence"].splitlines()[0][:36] if g else "",
                "confidence": g["confidence"] if g else "—",
                "reality": "待人工复核",   # 工具不自打勾，这一列永远这个
            })
            if g:
                findings.append({
                    "param": p["name"], "source": p["source"], "method": p["method"],
                    "type": g["type"], "evidence": g["evidence"],
                    "confidence": g["confidence"], "verified": False, "reviewer": None,
                })
                hit_panel({"type": g["type"], "evidence": g["evidence"]},
                          p["name"], "命中" if ui else "有洞")
        if ui:
            out("已测" + err, C_DIM)
    return rows, findings


def finish(findings, rows, ui, target, report, n):
    # 命中了就得给表，光丢个红框让人自己猜不算结论；CLI 和交互一视同仁
    if ui or findings:
        summary_table(rows)
        out(ACCURACY_TEXT, C_DIM)
    if findings:
        out(f"{len(findings)} 处命中，手工复核后再写报告", f"bold {C_WARN}")
    elif ui:
        out("0 处命中。没弹框不等于安全。", C_OK)
    else:
        out("没弹框，就是没验到。别当成绝对安全", C_OK)
    out("自己手工复核一遍再写报告", C_DIM)
    if report:
        write_report(report, target, n, findings)


def ui_logo():
    console.clear()
    console.print(Align.center(Text("\n".join(LOGO), style=C_MAIN, justify="center")))
    console.print(Align.center(Text("small eye, sharp sight", style=C_DIM)))
    console.print(Align.center(Text("轻量漏洞验证 / 只验证不利用 / v0.1.0", style=C_DIM)))
    console.print()


def interactive():
    global DELAY, TIMEOUT, LIMIT, USED, LEFT
    if console is None or requests is None:
        print("交互模式要 requests + rich，先 pip install -r requirements.txt")
        sys.exit(1)
    ui_logo()
    out("直接回车用默认，输入 a 进高级选项", C_DIM)
    # 这里偷懒只问一次，别的全走默认；真想调的自己敲 a
    while True:
        ans = Prompt.ask(Text("目标 > ", style=C_ACC), default=DEFAULT_TARGET).strip()
        adv = ans.lower() == "a"
        target = DEFAULT_TARGET if adv else (ans or DEFAULT_TARGET)
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        host = urlparse(target).hostname or ""
        try:
            ipaddress.ip_address(host)   # IP 字面量就别费那个 DNS 了
            break
        except ValueError:
            try:
                socket.gethostbyname(host)
                break
            except socket.gaierror as e:
                out(f"host 解析不了: {host} ({e})，重来", C_WARN)

    if not private_host(host) and not Confirm.ask(
            Text("目标不在私网范围，确认已获得书面授权？", style=C_ACC), default=False):
        out("已退出，未发送任何请求", C_DIM)
        sys.exit(1)

    raw_p, mp, report = "", MAX_PARAMS, None
    if adv:
        out("留空自动发现，或填 id,page,file", C_DIM)
        raw_p = Prompt.ask(Text("参数 > ", style=C_ACC), default="")
        mp = max(1, IntPrompt.ask(Text("参数上限 > ", style=C_ACC), default=MAX_PARAMS))
        DELAY = max(0.2, FloatPrompt.ask(Text("延迟秒数 > ", style=C_ACC), default=DELAY))
        LIMIT = max(1, IntPrompt.ask(Text("请求上限 > ", style=C_ACC), default=LIMIT))
        if Confirm.ask(Text("输出报告 JSON？(y/N) > ", style=C_ACC),
                       default=False, show_choices=False):
            report = REPORT_DEFAULT
            out(f"报告会写到 {report}", C_DIM)

    pu = urlparse(target)
    clean = urlunparse(pu._replace(query="", fragment=""))
    q = dict(parse_qsl(pu.query))
    USED, LEFT = 0, LIMIT
    home = req(clean, q)
    if home is None:
        out("目标连不上，收工", C_WARN)
        return
    params = (manual([x.strip() for x in raw_p.split(",") if x.strip()], target, mp)
              if raw_p.strip() else analyze(home.text, target, mp))

    rule()
    out(f">> {target}", f"bold {C_MAIN}")
    out("参数: " + ", ".join(p["name"] for p in params), C_DIM)
    out(f"预算: {LIMIT} 请求 / 间隔 {DELAY} 秒", C_DIM)
    rule()

    rows, findings = scan(params, LIMIT, ui=True)
    finish(findings, rows, True, target, report, len(params))
    # 灰色等一下，别让窗口一闪就没了
    out("按回车退出", C_DIM)
    input()
    sys.exit(0)


def cli():
    global DELAY, TIMEOUT, LIMIT, USED, LEFT
    ap = argparse.ArgumentParser(description="Argulus - 轻量漏洞验证，只验证不利用")
    ap.add_argument("-u", "--url", required=True, help="目标 URL")
    ap.add_argument("-p", "--param", help="只测这几个参数，逗号分隔")
    ap.add_argument("-t", "--timeout", type=float, default=TIMEOUT,
                    help="单请求超时秒数，下限 1（默认 6）")
    ap.add_argument("-d", "--delay", type=float, default=DELAY,
                    help="请求间隔秒数，下限 0.2（默认 0.8）")
    ap.add_argument("--max-requests", type=int, default=LIMIT, help="请求上限（默认 120）")
    ap.add_argument("--max-params", type=int, default=MAX_PARAMS, help="参数上限（默认 6）")
    ap.add_argument("--report", help="把结构化结论写成 JSON")
    ap.add_argument("--authorized", action="store_true", help="我有书面授权，放行域名/公网 IP")
    a = ap.parse_args()

    DELAY = max(0.2, a.delay)
    TIMEOUT = max(1.0, a.timeout)
    LIMIT = max(1, a.max_requests)
    mp = max(1, a.max_params)
    USED = 0
    if requests is None:
        out("没装 requests，先 pip install -r requirements.txt", C_WARN)
        return

    target = a.url
    # 懒得每次敲 http://
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    pu = urlparse(target)
    host = pu.hostname or ""
    if not private_host(host):
        if not a.authorized:
            out(f"拦住了：{host} 不是私网/回环/链路本地，域名和公网 IP 要加 "
                "--authorized（且得真有书面授权）", C_WARN)
            return
        out(f"放行了外部目标 {host}，书面授权自己留好", C_DIM)

    clean = urlunparse(pu._replace(query="", fragment=""))
    q = dict(parse_qsl(pu.query))
    out(f">> {target}", f"bold {C_MAIN}")
    LEFT = LIMIT
    home = req(clean, q)
    if home is None:
        out("目标连不上，收工", C_WARN)
        return
    params = (manual([x.strip() for x in a.param.split(",") if x.strip()], target, mp)
              if a.param else analyze(home.text, target, mp))
    out("参数: " + ", ".join(p["name"] for p in params), C_DIM)
    rows, findings = scan(params, LIMIT)
    out("")
    finish(findings, rows, False, target, a.report, len(params))


def main():
    # 没带参数进交互，带参数走老 CLI，别把以前的用法弄坏了
    if len(sys.argv) == 1:
        interactive()
    else:
        cli()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        out("手停了，收工", C_DIM)
        sys.exit(0)
    except Exception as e:
        out(f"炸了: {type(e).__name__}: {e}", C_WARN)
        sys.exit(1)
