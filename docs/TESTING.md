# 本地测试（Windows CMD）

全程只用 127.0.0.1，别拿别人的站点练手。

## 1. 起本地靶场

开一个 CMD：

```
cd /d D:\Projects\Argulus
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m http.server 8000
```

这个窗口别关，它会一直打印访问日志。看到 `Serving HTTP on 127.0.0.1 port 8000` 就成了。

## 2. 跑一轮

另开一个 CMD：

```
cd /d D:\Projects\Argulus
venv\Scripts\activate
python scan.py -u http://127.0.0.1:8000/?id=1
```

想快一点（间隔压到下限、请求数收紧）：

```
python scan.py -u http://127.0.0.1:8000/?id=1 -d 0.2 --max-requests 60
```

URL 带 `&` 要用双引号包住，CMD 会把 `&` 当命令分隔符：

```
python scan.py -u "http://127.0.0.1:8000/?id=1&page=2"
```

### 预期输出格式

```
>> http://127.0.0.1:8000/?id=1
参数: id
-- id

没弹框，就是没验到。别当成绝对安全
自己手工复核一遍再写报告
```

参数是从首页解析出来的（URL query / form POST / form GET / 首页链接 query，按这个顺序排），`http.server` 的目录列表里没别的参数，所以只测 `id` 一个，不会硬凑到 6 个。目录列表既不会原样反射参数，也不含 `/etc/passwd` 特征，所以一轮下来应该是 0 命中。第一个窗口能看到一串 GET 日志，正常。跑完不崩、最后两行都打出来就算过。

想看命中长什么样，自己写个本地页面把 query 原样塞回 HTML，再用 `-p` 单独测那个参数。别在公网上试。

## 3. 纯函数单测

```
python -m unittest discover tests
```

预期 `Ran 9 tests ... OK`。不联网，也不需要装 requests、rich、PyQt5。

## 4. GUI 测试

```
pip install -r requirements-gui.txt
python neteyes.py
```

窗口里目标填 `127.0.0.1`，端口填 `8000`，线程保持 20，点开始扫描。表格里应出现 `127.0.0.1 / 8000 / HTTP / ...`，进度条走到 100%，日志有记录，导出 CSV 和 JSON 都能点。

授权拦截怎么验：目标改成 `8.8.8.8`，不勾选"我已获得书面授权"直接点开始，应该弹窗拦住、一个请求都不发；勾上才会放行。这一步只验拦不拦，别真去扫。

## 常见报错和排查

| 现象 | 排查 |
| --- | --- |
| `没装 requests，先 pip install -r requirements.txt` | 忘了 `venv\Scripts\activate`，或者没装依赖 |
| `ModuleNotFoundError: No module named 'rich'` | 同上，装 requirements.txt |
| 启动 GUI 时打印"没装 PyQt5" | 装 requirements-gui.txt；Python 太新没有对应轮子就换 3.10 到 3.12 |
| `ImportError: DLL load failed` | PyQt5 缺 VC 运行库，或者 Python 版本与轮子不匹配 |
| `目标连不上，收工` | 第一个 CMD 的 http.server 被关了，或端口不是 8000 |
| `OSError: [WinError 10048]` | 8000 被占用，换 `python -m http.server 8001`，命令里的端口跟着改 |
| `拦住了：example.com 不是私网/回环/链路本地` | 默认策略，要加 `--authorized`，且确认手里有书面授权 |
| 一轮跑得特别慢 | 默认间隔 0.8 秒；`-d 0.2` 是下限 |
| `Ran 0 tests` | 要在项目根目录跑，别进 tests 目录再跑 |
| CMD 里 URL 被截成两段 | URL 里有 `&`，用双引号包住整个 URL |
| 输出中文乱码 | 先 `chcp 65001` 再跑 |
| 想看 `-h` 有没有坏 | `python scan.py -h`，不需要靶场也不需要联网 |
| 结论表列被挤掉 | `mode con: cols=120` 把窗口调宽再跑 |

## 5. 交互模式和 JSON 报告

不带任何参数直接进交互模式，一路回车用默认值就行：

```
python scan.py
```

想验公网拦截：目标填 `8.8.8.8`，授权问句选 n，应该打印 `已退出，未发送任何请求` 并以退出码 1 结束，一个请求都不发。Ctrl+C 任意时刻打印 `手停了，收工`，退出码 0。

CLI 那边的结构化结论：

```
python scan.py -u http://127.0.0.1:8000/?id=1 -d 0.2 --report out.json
```

`out.json` 里有 target / scanned_at / params_total / requests_used / findings / accuracy_note；findings 里 `verified` 恒为 false、`reviewer` 恒为 null，没有"准确率 XX%"这种数字。
