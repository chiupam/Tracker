import sys
import os
import time
import json
from datetime import datetime

import requests
import pandas as pd
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
                             QPushButton, QTextEdit, QFileDialog, QHBoxLayout, QMessageBox)
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QIcon


# ================= Tracker 后端逻辑 =================
class Tracker(object):
    def __init__(self, auth, cookie, host, username, usercode,
                 interval, loop_interval, csv_filename, config_file):
        self.path = os.path.dirname(os.path.abspath(__file__))
        self.Authorization = auth
        self.cookie = cookie
        self.host = host
        self.username = username
        self.usercode = usercode
        self.interval = interval
        self.loop_interval = loop_interval
        self.csv_filename = csv_filename
        self.config_file = config_file

        self.session = requests.Session()
        self.headers = {
            'Cookie': self.cookie,
            'Authorization': self.Authorization,
            'sysnum': "CXLP"
        }
        self.data = {
            "userCodeSession": self.usercode,
            "userNameSession": self.username,
            "comCodeSession": "44030000"
        }

    def get_state(self, registNo, comcode):
        url = f"http://{self.host}/claimcar/api/applicationLayer/piccclaim/newFrame/bpm/viewFlowChart"
        headers = self.headers.copy()
        headers["comcode"] = comcode
        data = self.data.copy()
        data["registNo"] = registNo
        nodePKVoList = False
        try:
            response = self.session.post(url, json=data, headers=headers)
            response.encoding = "utf-8"
            nodePKVoList = response.json()['data']['nodePKVoList']
            nodePKVoList.sort(key=lambda x: x['wbusinessCmain']['indate'])
        finally:
            return nodePKVoList

    def check_claims(self, nodePKVoList, old_index, new_index):
        node_list = nodePKVoList[old_index:new_index]
        results = [
            item['nodeAddVo']['stat']
            for item in node_list
            if (isinstance(item, dict) and
                'nodeAddVo' in item and
                isinstance(item['nodeAddVo'], dict) and
                'nodeName' in item['nodeAddVo'] and
                '核赔' in str(item['nodeAddVo']['nodeName']) and
                'stat' in item['nodeAddVo'])
        ]
        return "核赔完成" if results else False

    def update_csv_data(self, logger=print):
        dtype_mapping = {'报案号': str, '机构代码': str, '节点长度': str, '核赔状态': str}  # 与csv表头对应映射
        csv_path = self.csv_filename
        df = pd.read_csv(csv_path, encoding='utf-8-sig', dtype=dtype_mapping)
        updated, claims = False, False
        for index, row in df.iterrows():
            registNo = str(row['报案号']).strip() if pd.notna(row['报案号']) else ''
            comcode = str(row['机构代码']).strip() if pd.notna(row['机构代码']) else ''
            current_length_str = str(row['节点长度']).strip() if pd.notna(row['节点长度']) else 0
            nodePKVoList = self.get_state(registNo, comcode)
            if nodePKVoList:
                new_length = len(nodePKVoList)
                current_length = int(current_length_str) if current_length_str.isdigit() else 0
                if new_length != current_length:
                    updated = True
                    claims = self.check_claims(nodePKVoList, current_length, new_length)
                    if claims:
                        claims = True
                    logger(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 序列: {index} -- 报案号: {registNo} -- 新增节点数: {new_length - current_length} -- 核赔状态: {claims}")
                    df.loc[index] = {'报案号': registNo, '机构代码': comcode, '节点长度': str(new_length), '核赔状态': claims}
                else:
                    logger(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 序列: {index} -- 报案号: {registNo} -- 节点数: 无变化")
            else:
                logger(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 序列: {index} -- 报案号: {registNo} -- 请检查鉴权")
            time.sleep(self.interval)

        if updated:
            try:
                df.to_csv(csv_path, index=False, encoding='utf-8-sig')
                if claims:
                    logger(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} CSV文件已成功更新并保存！请及时查看有核赔通过的案件情况！")
                    return True   # 有更新
            except Exception as e:
                logger(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 保存文件时出错: {e}")
        return False


# ================= 后台线程封装 =================
class TrackerWorker(QThread):
    log_signal = pyqtSignal(str)
    alert_signal = pyqtSignal(str)  # 新增：触发主窗口弹窗

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.running = True

    def log(self, msg):
        self.log_signal.emit(msg)

    def run(self):
        try:
            tracker = Tracker(
                self.config['auth'],
                self.config['cookie'],
                self.config['host'],
                self.config['username'],
                self.config['usercode'],
                int(self.config['interval']),
                int(self.config['loop_interval']),
                self.config['csv_filename'],
                self.config['config_file']
            )
            while self.running:
                updated = tracker.update_csv_data(self.log)
                if updated:
                    self.alert_signal.emit("监控文件有新的更新，请留意！")
                self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 间隔{self.config['loop_interval']}秒后再次扫描监控表")
                time.sleep(int(self.config['loop_interval']))
        except Exception as e:
            self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ❌ 程序错误: {str(e)}")

    def stop(self):
        self.running = False


# ================= GUI 主窗口 =================
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("理赔监控工具")
        self.resize(700, 600)

        layout = QVBoxLayout()
        self.inputs = {}

        # 主机地址
        hbox_host = QHBoxLayout()
        hbox_host.addWidget(QLabel("主机地址"))
        self.host_edit = QLineEdit()
        hbox_host.addWidget(self.host_edit)
        layout.addLayout(hbox_host)
        self.inputs["host"] = self.host_edit

        # Cookie + Authorization
        hbox_auth = QHBoxLayout()
        hbox_auth.addWidget(QLabel("Cookie"))
        self.cookie_edit = QLineEdit()
        hbox_auth.addWidget(self.cookie_edit)
        hbox_auth.addWidget(QLabel("Authorization"))
        self.auth_edit = QLineEdit()
        hbox_auth.addWidget(self.auth_edit)
        layout.addLayout(hbox_auth)
        self.inputs["cookie"] = self.cookie_edit
        self.inputs["auth"] = self.auth_edit

        # 用户名 + 用户代码
        hbox_user = QHBoxLayout()
        hbox_user.addWidget(QLabel("用户名"))
        self.username_edit = QLineEdit()
        hbox_user.addWidget(self.username_edit)
        hbox_user.addWidget(QLabel("用户代码"))
        self.usercode_edit = QLineEdit()
        hbox_user.addWidget(self.usercode_edit)
        layout.addLayout(hbox_user)
        self.inputs["username"] = self.username_edit
        self.inputs["usercode"] = self.usercode_edit

        # 每条间隔秒数 + 循环间隔秒数
        hbox_interval = QHBoxLayout()
        hbox_interval.addWidget(QLabel("每条间隔秒数"))
        self.interval_edit = QLineEdit()
        hbox_interval.addWidget(self.interval_edit)
        hbox_interval.addWidget(QLabel("循环间隔秒数"))
        self.loop_edit = QLineEdit()
        hbox_interval.addWidget(self.loop_edit)
        layout.addLayout(hbox_interval)
        self.inputs["interval"] = self.interval_edit
        self.inputs["loop_interval"] = self.loop_edit

        # CSV 文件选择
        hbox_csv = QHBoxLayout()
        hbox_csv.addWidget(QLabel("监控文件 (CSV)"))
        self.csv_edit = QLineEdit()
        btn_csv = QPushButton("选择文件")
        btn_csv.clicked.connect(self.choose_csv_file)
        hbox_csv.addWidget(self.csv_edit)
        hbox_csv.addWidget(btn_csv)
        layout.addLayout(hbox_csv)
        self.inputs["csv_filename"] = self.csv_edit

        # 控制按钮（同一行）
        hbox_btn = QHBoxLayout()
        self.start_button = QPushButton("运行")
        self.stop_button = QPushButton("停止")
        hbox_btn.addWidget(self.start_button)
        hbox_btn.addWidget(self.stop_button)
        layout.addLayout(hbox_btn)

        # 日志窗口
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output)
        self.setLayout(layout)

        self.worker = None
        self.start_button.clicked.connect(self.start_tracker)
        self.stop_button.clicked.connect(self.stop_tracker)

        # 程序启动时加载 config.json
        self.config_path = os.path.join(os.path.dirname(sys.argv[0]), "config.json")
        self.load_config_at_start()

    def choose_csv_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "选择监控 CSV 文件", "", "CSV 文件 (*.csv)")
        if file_name:
            self.csv_edit.setText(file_name)

    def save_config(self):
        """保存配置到当前目录下的 config.json"""
        cfg = {k: v.text().strip() for k, v in self.inputs.items()
               if k in ["host", "username", "usercode", "interval", "loop_interval", "csv_filename"]}
        try:
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=4)
            self.update_log("✅ 配置已保存 (config.json)")
        except Exception as e:
            self.update_log(f"❌ 保存配置失败: {e}")

    def load_config_at_start(self):
        """启动时自动加载 config.json"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                for k, v in cfg.items():
                    if k in self.inputs:
                        self.inputs[k].setText(str(v))
                self.update_log("✅ 已自动加载上次保存的配置")
            except Exception as e:
                self.update_log(f"❌ 自动加载配置失败: {e}")

    def start_tracker(self):
        config = {k: v.text().strip() for k, v in self.inputs.items()}
        if not config["csv_filename"]:
            self.update_log("⚠️ 请选择一个 CSV 文件！")
            return
        config["config_file"] = None

        # 保存一份配置
        self.save_config()

        self.worker = TrackerWorker(config)
        self.worker.log_signal.connect(self.update_log)
        self.worker.alert_signal.connect(self.show_alert)  # 连接弹窗信号
        self.worker.start()
        self.update_log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 任务已启动...")

    def stop_tracker(self):
        if self.worker:
            self.worker.stop()
            self.update_log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 任务已停止。")

    def update_log(self, msg):
        self.log_output.append(msg)
        self.log_output.moveCursor(self.log_output.textCursor().End)  # 自动滚动到底部

    def show_alert(self, message):
        # 非阻塞弹窗
        QMessageBox.information(self, "监控提醒", message)


# ================= 程序入口 =================
if __name__ == "__main__":
    import sys, os
    from PyQt5.QtGui import QIcon

    def resource_path(relative_path):
        """获取资源文件路径，兼容 PyInstaller 打包"""
        if hasattr(sys, "_MEIPASS"):
            return os.path.join(sys._MEIPASS, relative_path)
        return os.path.join(os.path.abspath("."), relative_path)

    app = QApplication(sys.argv)
    window = MainWindow()
    app.setWindowIcon(QIcon(resource_path("favicon.ico")))  # 这里就能兼容源码运行和打包运行
    window.show()
    sys.exit(app.exec_())

