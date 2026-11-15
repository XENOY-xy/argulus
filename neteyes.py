#!/usr/bin/env python3
# neteyes.py - 局域网资产自查。只看端口通不通、文本 banner 长啥样，不做利用

import sys
import socket
import ipaddress
import json
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
        QProgressBar, QTextEdit, QCheckBox, QMessageBox, QFileDialog,
        QFrame, QMenu, QSpinBox, QDoubleSpinBox,
    )
    from PyQt5.QtCore import QThread, pyqtSignal, Qt
    from PyQt5.QtGui import QFont
    QT_OK = True
    QT_ERR = ""
except ImportError as e:
    # 别把报错吞了，等下启动时要原样打出来
    QT_OK = False
    QT_ERR = f"{type(e).__name__}: {e}"

# 只留文本型探针。MySQL/RDP 那种二进制握手我删了，认不出还容易把服务弄烦
PROBES = {
    21: b"USER anonymous\r\n",
    22: b"",       # SSH 自己会先吐 banner，空着手等就行
    23: b"\r\n",
    25: b"EHLO argulus\r\n",
    80: b"GET / HTTP/1.0\r\n\r\n",
    8080: b"GET / HTTP/1.0\r\n\r\n",
    9200: b"GET / HTTP/1.0\r\n\r\n",
    6379: b"PING\r\n",
}
SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP",
    443: "HTTPS", 6379: "Redis", 8080: "HTTP-Alt", 9200: "Elasticsearch",
    27017: "MongoDB", 5432: "PostgreSQL",
}


def parse_ports(raw):
    # 端口写得再乱也尽量认，认不出来的丢掉就行
    ports = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.strip().isdigit() and hi.strip().isdigit():
                x, y = int(lo), int(hi)
                if x > y:
                    x, y = y, x
                ports.update(range(max(1, x), min(65535, y) + 1))
        elif part.isdigit() and 1 <= int(part) <= 65535:
            ports.add(int(part))
    return sorted(ports)


def private_host(host):
    # 域名一律当外部目标，DNS 指到哪儿我懒得猜
    host = (host or "").strip()
    try:
        if "/" in host:
            net = ipaddress.ip_network(host, strict=False)
            return private_host(str(net.network_address))
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def targets_of(raw):
    # 网段最多摊 256 个，再多我怕自己收不住
    hosts = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "/" in chunk:
            try:
                net = ipaddress.ip_network(chunk, strict=False)
                hosts.extend(str(ip) for ip in list(net.hosts())[:256])
            except ValueError as e:
                raise ValueError(f"网段 {chunk} 没看懂: {e}")
        else:
            hosts.append(chunk)
    return hosts


def banner_of(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect((ip, port))
        probe = PROBES.get(port)
        if probe:
            s.send(probe)
        data = s.recv(256)
        txt = data.decode("utf-8", errors="ignore").strip()[:80] or "(空响应)"
    except (OSError, socket.timeout) as e:
        # 超时太常见了，但类型带上，别吞得只剩一句"无指纹"
        txt = f"没读到 banner ({type(e).__name__}: {e})"
    finally:
        s.close()
    return f"{SERVICES.get(port, 'Unknown')} | {txt}"


# GUI 全拢在这块，纯函数在上面：没装 PyQt5 也能 import 这个模块跑单测
if QT_OK:

    class ScanWorker(QThread):
        log_signal = pyqtSignal(str)
        progress_signal = pyqtSignal(int)
        result_signal = pyqtSignal(dict)
        finished_signal = pyqtSignal()
        error_signal = pyqtSignal(str)

        def __init__(self, target, ports, timeout, threads):
            super().__init__()
            self.target = target
            self.ports = ports
            self.timeout = timeout
            self.threads = max(1, min(100, threads))
            self._running = True

        def run(self):
            try:
                hosts = targets_of(self.target)
                tasks = [(ip, p) for ip in hosts for p in self.ports]
                total = len(tasks)
                done = 0
                with ThreadPoolExecutor(max_workers=self.threads) as pool:
                    futures = {pool.submit(self._probe, ip, p): (ip, p)
                               for ip, p in tasks}
                    for f in as_completed(futures):
                        if not self._running:
                            for other in futures:
                                other.cancel()
                            break
                        ip, port = futures[f]
                        try:
                            r = f.result()
                        except Exception as e:
                            self.log_signal.emit(
                                f"[!] {ip}:{port} 探针异常 ({type(e).__name__}: {e})")
                            r = None
                        if r:
                            self.result_signal.emit(r)
                            self.log_signal.emit(
                                f"[+] {r['ip']}:{r['port']} 开放 | {r['banner']}")
                        done += 1
                        if total:
                            self.progress_signal.emit(int(done / total * 100))
            except Exception as e:
                self.error_signal.emit(f"{type(e).__name__}: {e}")
            finally:
                self.finished_signal.emit()

        def _probe(self, ip, port):
            if not self._running:
                return None
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                if sock.connect_ex((ip, port)) != 0:
                    return None
            finally:
                sock.close()
            return {
                "ip": ip, "port": port, "status": "open",
                "banner": banner_of(ip, port, self.timeout),
                "time": datetime.now().isoformat(),
            }

        def stop(self):
            self._running = False

    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("neteyes - 局域网资产自查")
            self.setMinimumSize(900, 650)
            self.worker = None
            self.rows = []
            self.setStyleSheet(
                "QLabel { font-size:12px; }"
                "QLineEdit, QSpinBox, QDoubleSpinBox, QTextEdit, QTableWidget "
                "{ border:1px solid #bcccd9; }"
                "QPushButton { padding:6px 14px; }"
                "QProgressBar { text-align:center; }"
            )
            self._ui()

        def _ui(self):
            root = QWidget()
            self.setCentralWidget(root)
            lay = QVBoxLayout(root)

            head = QLabel("neteyes  局域网资产自查")
            head.setStyleSheet("font-size:16px; font-weight:bold;")
            lay.addWidget(head)

            card = QFrame()
            card.setStyleSheet("QFrame { border:1px solid #dce4ec; }")
            box = QVBoxLayout(card)

            r1 = QHBoxLayout()
            r1.addWidget(QLabel("目标:"))
            self.target_input = QLineEdit()
            self.target_input.setPlaceholderText("127.0.0.1 或 192.168.1.0/24，多个用逗号隔开")
            r1.addWidget(self.target_input)
            box.addLayout(r1)

            r2 = QHBoxLayout()
            r2.addWidget(QLabel("端口:"))
            self.port_input = QLineEdit("21,22,25,80,443,6379,8080,9200")
            r2.addWidget(self.port_input)
            r2.addWidget(QLabel("超时(秒):"))
            self.timeout_input = QDoubleSpinBox()
            self.timeout_input.setRange(0.5, 5.0)
            self.timeout_input.setSingleStep(0.1)
            self.timeout_input.setValue(1.2)
            r2.addWidget(self.timeout_input)
            r2.addWidget(QLabel("线程:"))
            self.thread_input = QSpinBox()
            self.thread_input.setRange(1, 100)   # 默认 20，上限就 100，别一上来开满
            self.thread_input.setValue(20)
            r2.addWidget(self.thread_input)
            box.addLayout(r2)

            self.auth_box = QCheckBox("我已获得书面授权（放行公网目标）")
            box.addWidget(self.auth_box)
            lay.addWidget(card)

            btns = QHBoxLayout()
            self.scan_btn = QPushButton("开始扫描")
            self.stop_btn = QPushButton("停止")
            self.csv_btn = QPushButton("导出 CSV")
            self.json_btn = QPushButton("导出 JSON")
            self.stop_btn.setEnabled(False)
            self.csv_btn.setEnabled(False)
            self.json_btn.setEnabled(False)
            for b in (self.scan_btn, self.stop_btn, self.csv_btn, self.json_btn):
                btns.addWidget(b)
            self.scan_btn.clicked.connect(self._start_scan)
            self.stop_btn.clicked.connect(self._stop_scan)
            self.csv_btn.clicked.connect(self._export_csv)
            self.json_btn.clicked.connect(self._export_json)
            btns.addStretch()
            lay.addLayout(btns)

            self.progress = QProgressBar()
            self.progress.setFormat("就绪")
            lay.addWidget(self.progress)

            self.table = QTableWidget()
            self.table.setColumnCount(4)
            self.table.setHorizontalHeaderLabels(["IP地址", "端口", "服务", "Banner指纹"])
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.setSelectionBehavior(QTableWidget.SelectRows)
            self.table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.table.customContextMenuRequested.connect(self._menu)
            lay.addWidget(self.table, 1)

            self.log_area = QTextEdit()
            self.log_area.setReadOnly(True)
            self.log_area.setMaximumHeight(140)
            log_bar = QHBoxLayout()
            log_bar.addWidget(QLabel("日志"))
            log_bar.addStretch()
            clear = QPushButton("清空日志")
            clear.clicked.connect(self.log_area.clear)
            log_bar.addWidget(clear)
            lay.addLayout(log_bar)
            lay.addWidget(self.log_area)
            self.statusBar().showMessage("就绪")

        def _menu(self, pos):
            item = self.table.itemAt(pos)
            if item is None:
                return
            menu = QMenu(self)
            act = menu.addAction("复制 IP")
            if menu.exec_(self.table.viewport().mapToGlobal(pos)) == act:
                ip = self.table.item(item.row(), 0)
                if ip:
                    QApplication.clipboard().setText(ip.text())

        def _log(self, msg):
            self.log_area.append(f"[{datetime.now():%H:%M:%S}] {msg}")

        def _start_scan(self):
            raw = self.target_input.text().strip()
            ports = parse_ports(self.port_input.text())
            if not raw or not ports:
                QMessageBox.warning(self, "提示", "目标和端口都填一下，端口写法如 21,22,80-90")
                return
            outside = [t.strip() for t in raw.split(",")
                       if t.strip() and not private_host(t.strip())]
            if outside and not self.auth_box.isChecked():
                QMessageBox.warning(
                    self, "拦住了",
                    "这些目标不是私网/回环/链路本地：\n" + "\n".join(outside[:5]) +
                    "\n\n公网或域名目标要先勾选「我已获得书面授权」。")
                return
            if outside:
                self._log("按书面授权放行外部目标: " + ", ".join(outside))

            self.rows = []
            self.table.setRowCount(0)
            self.log_area.clear()
            self._log(f"开始：目标 {raw} / 端口 {len(ports)} 个 / 线程 {self.thread_input.value()}")
            self.scan_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.csv_btn.setEnabled(False)
            self.json_btn.setEnabled(False)
            self.progress.setValue(0)
            self.progress.setFormat("0%")

            self.worker = ScanWorker(raw, ports, self.timeout_input.value(),
                                     self.thread_input.value())
            self.worker.log_signal.connect(self._log)
            self.worker.progress_signal.connect(self._on_progress)
            self.worker.result_signal.connect(self._add_row)
            self.worker.error_signal.connect(self._on_error)
            self.worker.finished_signal.connect(self._done)
            self.worker.start()

        def _on_progress(self, val):
            self.progress.setValue(val)
            self.progress.setFormat(f"{val}%")

        def _on_error(self, msg):
            self._log("扫描异常: " + msg)
            QMessageBox.critical(self, "扫描错误", msg)

        def _add_row(self, r):
            row = self.table.rowCount()
            self.table.insertRow(row)
            vals = [r["ip"], str(r["port"]), r["banner"].split("|")[0].strip(), r["banner"]]
            for col, text in enumerate(vals):
                self.table.setItem(row, col, QTableWidgetItem(text))
            self.rows.append(r)

        def _done(self):
            self.scan_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.csv_btn.setEnabled(bool(self.rows))
            self.json_btn.setEnabled(bool(self.rows))
            self.progress.setFormat(f"完成 ({len(self.rows)} 个开放端口)")
            self._log(f"完成，共 {len(self.rows)} 个开放端口")
            self.statusBar().showMessage(f"完成，开放端口数: {len(self.rows)}")

        def _stop_scan(self):
            if self.worker:
                self.worker.stop()
            self._log("用户点了停止")
            self.progress.setFormat("已停止")

        def _export_csv(self):
            path, _ = QFileDialog.getSaveFileName(
                self, "保存 CSV", f"scan_report_{datetime.now():%Y%m%d_%H%M%S}.csv",
                "CSV Files (*.csv)")
            if not path:
                return
            try:
                with open(path, "w", newline="", encoding="utf-8-sig") as f:
                    w = csv.writer(f)
                    w.writerow(["IP地址", "端口", "状态", "Banner指纹", "时间"])
                    for r in self.rows:
                        w.writerow([r["ip"], r["port"], r["status"], r["banner"], r["time"]])
                self.statusBar().showMessage(f"已导出 CSV: {path}")
            except OSError as e:
                QMessageBox.critical(self, "导出失败", f"{type(e).__name__}: {e}")

        def _export_json(self):
            path, _ = QFileDialog.getSaveFileName(
                self, "保存 JSON", f"scan_report_{datetime.now():%Y%m%d_%H%M%S}.json",
                "JSON Files (*.json)")
            if not path:
                return
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump({"time": datetime.now().isoformat(),
                               "target": self.target_input.text().strip(),
                               "results": self.rows}, f, indent=2, ensure_ascii=False)
                self.statusBar().showMessage(f"已导出 JSON: {path}")
            except OSError as e:
                QMessageBox.critical(self, "导出失败", f"{type(e).__name__}: {e}")


if __name__ == "__main__":
    if not QT_OK:
        print("没装 PyQt5，先跑: pip install -r requirements-gui.txt")
        print("导入报错: " + QT_ERR)
        sys.exit(1)
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Microsoft YaHei", 10))
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
