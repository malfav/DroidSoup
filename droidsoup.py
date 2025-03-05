#!/usr/bin/env python3
import sys, subprocess, os, shutil
from PyQt5 import QtWidgets, QtCore, QtGui

######################################
# Suspicious Keyword Categories (all lowercase)
######################################
permissions_list = [
    "read_sms", "receive_sms", "send_sms", "read_call_log", "write_call_log",
    "process_outgoing_calls", "read_contacts", "write_contacts", "record_audio",
    "camera", "internet", "access_fine_location", "access_coarse_location",
    "system_alert_window", "request_install_packages", "read_external_storage",
    "write_external_storage", "receive_boot_completed", "bind_accessibility_service",
    "package_usage_stats", "manage_external_storage", "request_ignore_battery_optimizations",
    "read_phone_state", "answer_phone_calls", "modify_phone_state", "call_phone",
    "foreground_service", "request_delete_packages"
]

api_calls_list = [
    "runtime.getruntime().exec", "processbuilder", "dexclassloader", "pathclassloader",
    "loadclass", "defineclass", "class.forname", "getdeclaredmethod", "invoke",
    "cipher.getinstance", "secretkeyspec", "mac.getinstance", "messagedigest.getinstance",
    "keygenerator.getinstance", "securerandom", "keyfactory.getinstance",
    "base64.encodetostring", "base64.decode", "android.telephony.smsmanager.sendtextmessage",
    "telephonymanager.getdeviceid", "getimei", "getsubscriberid", "getline1number",
    "getsimserialnumber", "clipboardmanager.getprimaryclip", "mediarecorder.start",
    "camera.open", "webview.loadurl", "settings.secure.getstring", "accountmanager.getaccounts",
    "locationmanager.getlastknownlocation", "fileoutputstream", "fileinputstream",
    "url.openconnection", "httpurlconnection.connect", "socket.getoutputstream",
    "datagramsocket.send", "okhttpclient.newcall", "sslcontext.init"
]

obfuscation_list = [
    "obfusc", "debug", "stringbuilder.append", "string.replace", "new string(byte[])",
    "urlclassloader", "reflection", "native-lib", ".so", "payload.dex", "loader.dex",
    "update.dex", "unzip", "gzip", "proguard", "r8", "dalvik.system.dexfile",
    "hidden apis", "serialized objects", "embedded byte arrays"
]

networking_list = [
    "socket", "datagramsocket", "httpurlconnection", "websockets", "ftpclient",
    "hardcoded ip", "ip dynamic dns", "tor", ".onion", "reverse shell",
    "encrypted payload", "silent update", "/api/v1/collect", "/checkin", "/ping",
    "/command", "/exec", "/task", "/shell", "/config", "/update", "post", "get",
    "exfiltration", "dga", "fast flux", "custom tcp"
]

persistence_list = [
    "boot_completed", "alarmmanager", "jobscheduler", "workmanager",
    "foreground service", "accessibilityservice", "deviceadminreceiver", "startforeground"
]

sensitive_data_list = [
    "settings.secure", "accountmanager", "telephonymanager.getdeviceid",
    "telephonymanager.getsubscriberid", "telephonymanager.getline1number", "smsmanager",
    "clipboardmanager"
]

filenames_list = [
    "classes.dex", "update.dex", "temp.dex", "libnative.so", "libpayload.so",
    ".zip", ".jar", ".apk", ".tmp", ".dat", ".bin", "backup.apk", "config.json",
    "command.json", ".nomedia", "keylog.txt", "screenrecord.mp4"
]

suspicious_strings_list = [
    "http://", "https://", "base64", "blob", "hex string", "obfuscated url",
    "cmd.exe", "powershell.exe", "bash -i", "/dev/tcp", "eval", "chmod 777",
    "wget", "curl", "nc -e", "system("
]

privilege_escalation_list = [
    "su", "busybox", "/system/bin/sh", "/system/xbin/su", "/system/app/superuser.apk",
    "build.tags.contains(\"test-keys\")", "getprop", "/proc", "id", "whoami",
    "system.loadlibrary", "shell injection", "magisk", "selinux", "runtime hijack"
]

malware_behavior_list = [
    "overlay", "screen_capture", "stealth_mode", "hide_icon", "self_delete", "phishing",
    "dropper", "rat", "spyware", "banking", "inject", "hook", "exfiltrate", "keylogging",
    "credential_stealing", "fake_update", "code_injection", "bypass_root_detection",
    "accessibility_bypass", "webinject", "sms_intercept", "sim_swap", "clipboard_monitor",
    "crypto_stealer", "wallet_drain", "polymorphic", "worm", "ransomware", "locker",
    "click_fraud", "fake_ad", "adware", "silent_install", "update_injector"
]

######################################
# Get All Suspicious Patterns
######################################
def get_suspicious_patterns():
    # Note: keys must be in lowercase.
    patterns = {
        "ransom": "Possible ransomware behavior detected (keyword: ransom)",
        "encrypt": "Encryption routines detected",
        "lock": "Potential device lock functionality",
        "malware": "Malicious code signature detected",
        "extortion": "Possible extortion related code",
        "obfusc": "Obfuscation patterns detected; potential concealment of malicious behavior",
        "debug": "Debug routines present, may indicate bypass mechanisms",
        "shell": "Shell command execution detected",
        "exec": "Runtime execution call detected",
        "root": "Root access or privilege escalation routines identified",
        "trojan": "Trojan signature detected",
        "spy": "Potential spyware component identified",
        "keylogger": "Keylogger functionality detected",
        "backdoor": "Backdoor mechanism detected",
        "inject": "Code injection patterns detected",
        "exploit": "Exploit code detected",
        "vpn": "VPN or proxy bypass functionality detected",
        "admin": "Administrative privilege escalation identified",
        "monitor": "Monitoring functionality detected",
        "surveil": "Surveillance code detected",
        "payload": "Potential payload delivery mechanism identified",
    }
    # Add permissions
    for perm in permissions_list:
        patterns[perm] = f"Sensitive permission {perm.upper()} detected"
    # Add API calls
    for api in api_calls_list:
        patterns[api] = f"API call {api} detected"
    # Obfuscation/dynamic execution
    for obf in obfuscation_list:
        patterns[obf] = f"Potential obfuscation/dynamic execution: {obf} detected"
    # Networking / exfiltration
    for net in networking_list:
        patterns[net] = f"Networking/exfiltration indicator: {net} detected"
    # Persistence techniques
    for pers in persistence_list:
        patterns[pers] = f"Persistence mechanism: {pers} detected"
    # Sensitive data access
    for sens in sensitive_data_list:
        patterns[sens] = f"Sensitive data access: {sens} detected"
    # Suspicious filenames / extensions
    for fname in filenames_list:
        patterns[fname] = f"Suspicious file or extension detected: {fname}"
    # Suspicious strings / shell commands
    for sstr in suspicious_strings_list:
        patterns[sstr] = f"Suspicious string detected: {sstr}"
    # Privilege escalation / root indicators
    for pe in privilege_escalation_list:
        patterns[pe] = f"Privilege escalation indicator: {pe} detected"
    # Malware behavior keywords
    for mb in malware_behavior_list:
        patterns[mb] = f"Malware behavior indicator: {mb} detected"
    return patterns

######################################
# Determine Color for a Given Pattern
######################################
def get_color_for_pattern(pattern):
    lp = pattern.lower()
    if lp in permissions_list:
        return QtGui.QColor("yellow")
    elif lp in api_calls_list:
        return QtGui.QColor("orange")
    elif lp in obfuscation_list:
        return QtGui.QColor("magenta")
    elif lp in networking_list:
        return QtGui.QColor("darkGreen")
    elif lp in persistence_list:
        return QtGui.QColor("cyan")
    elif lp in sensitive_data_list:
        return QtGui.QColor("darkCyan")
    elif lp in filenames_list:
        return QtGui.QColor("blue")
    elif lp in suspicious_strings_list:
        return QtGui.QColor("darkRed")
    elif lp in privilege_escalation_list:
        return QtGui.QColor("brown")
    elif lp in malware_behavior_list:
        return QtGui.QColor("red")
    else:
        return QtGui.QColor("lightGray")

######################################
# Utility Functions for Decompilation and Scanning
######################################
def check_adb_connection():
    """Check if any device is connected via ADB."""
    try:
        result = subprocess.run(["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        devices = result.stdout.strip().splitlines()
        connected = [line for line in devices[1:] if line.strip() and "device" in line]
        return len(connected) > 0
    except Exception:
        return False

def run_apktool_decompile(apk_path, output_dir):
    """Execute APKTool decompilation of the given APK."""
    try:
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir, exist_ok=True)
        command = ["apktool", "d", apk_path, "-o", output_dir]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0
    except Exception as e:
        print("Error executing APKTool:", e)
        return False

def run_jadx_decompile(apk_path, output_dir):
    """Execute JADX decompilation of the given APK."""
    try:
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)
        os.makedirs(output_dir, exist_ok=True)
        command = ["jadx", "-d", output_dir, apk_path]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.returncode == 0
    except Exception as e:
        print("Error executing JADX:", e)
        return False

def scan_decompiled_code_for_malware(decompiled_dir):
    """Recursively scan decompiled code for suspicious patterns."""
    patterns = get_suspicious_patterns()
    flagged_results = []
    for root, dirs, files in os.walk(decompiled_dir):
        for file in files:
            if file.endswith(('.smali', '.java', '.xml', '.kt')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        lines = f.readlines()
                        for idx, line in enumerate(lines):
                            line_lower = line.lower()
                            for keyword, message in patterns.items():
                                if keyword in line_lower:
                                    flagged_results.append({
                                        "file": file_path,
                                        "line": idx + 1,
                                        "code": line.strip(),
                                        "message": message
                                    })
                except Exception as e:
                    print("Error reading file:", file_path, e)
    return flagged_results

def get_code_context(file_path, line_number, context_lines=2):
    """Return a snippet of code with context around the flagged line."""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            all_lines = f.readlines()
        idx = line_number - 1
        start = max(0, idx - context_lines)
        end = min(len(all_lines), idx + context_lines + 1)
        snippet = "".join(all_lines[start:end])
        return snippet
    except Exception:
        return "Error loading code context."

######################################
# Suspicious Highlighter for the Full Source Tab
######################################
class SuspiciousHighlighter(QtGui.QSyntaxHighlighter):
    def __init__(self, parent=None):
        super(SuspiciousHighlighter, self).__init__(parent)
        self.rules = []
        for pattern, _ in get_suspicious_patterns().items():
            regex = QtCore.QRegularExpression(pattern, QtCore.QRegularExpression.CaseInsensitiveOption)
            fmt = QtGui.QTextCharFormat()
            fmt.setForeground(get_color_for_pattern(pattern))
            fmt.setFontWeight(QtGui.QFont.Bold)
            self.rules.append((regex, fmt))
    
    def highlightBlock(self, text):
        for regex, fmt in self.rules:
            it = regex.globalMatch(text)
            while it.hasNext():
                match = it.next()
                start = match.capturedStart()
                length = match.capturedLength()
                self.setFormat(start, length, fmt)

######################################
# Full Source (Jadx) Tab
######################################
class FullSourceTab(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(FullSourceTab, self).__init__(parent)
        self.initUI()
    
    def initUI(self):
        layout = QtWidgets.QHBoxLayout()
        # Left: File Tree for navigating decompiled source.
        self.treeWidget = QtWidgets.QTreeWidget()
        self.treeWidget.setHeaderLabel("Files")
        self.treeWidget.itemClicked.connect(self.on_item_clicked)
        layout.addWidget(self.treeWidget, 1)
        # Right: Code Viewer with an intelligent highlighter.
        self.codeViewer = QtWidgets.QTextEdit()
        self.codeViewer.setReadOnly(True)
        self.highlighter = SuspiciousHighlighter(self.codeViewer.document())
        layout.addWidget(self.codeViewer, 2)
        self.setLayout(layout)
    
    def load_directory(self, directory):
        self.treeWidget.clear()
        self.directory = directory
        self.add_items(self.treeWidget.invisibleRootItem(), directory)
    
    def add_items(self, parent, path):
        try:
            items = sorted(os.listdir(path))
        except Exception:
            items = []
        for item in items:
            full_path = os.path.join(path, item)
            tree_item = QtWidgets.QTreeWidgetItem([item])
            tree_item.setData(0, QtCore.Qt.UserRole, full_path)
            parent.addChild(tree_item)
            if os.path.isdir(full_path):
                self.add_items(tree_item, full_path)
    
    def on_item_clicked(self, item, column):
        full_path = item.data(0, QtCore.Qt.UserRole)
        if os.path.isfile(full_path):
            try:
                with open(full_path, 'r', errors='ignore') as f:
                    content = f.read()
                self.codeViewer.setPlainText(content)
            except Exception as e:
                self.codeViewer.setPlainText("Error loading file: " + str(e))

######################################
# Static Analysis Widget (Main Dashboard)
######################################
class StaticAnalysisWidget(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(StaticAnalysisWidget, self).__init__(parent)
        self.jadx_output = None
        self.initUI()
    
    def initUI(self):
        layout = QtWidgets.QVBoxLayout()
        
        self.uploadBtn = QtWidgets.QPushButton("Upload APK for Static Analysis")
        self.uploadBtn.clicked.connect(self.upload_apk)
        layout.addWidget(self.uploadBtn)
        
        # Professional log area for progress and analysis messages.
        self.logText = QtWidgets.QTextEdit()
        self.logText.setReadOnly(True)
        layout.addWidget(self.logText)
        
        # Tab widget for Flagged Results and Full Source (Jadx)
        self.tabWidget = QtWidgets.QTabWidget()
        
        # Tab 1: Flagged Results Table
        self.resultsTable = QtWidgets.QTableWidget()
        self.resultsTable.setColumnCount(4)
        self.resultsTable.setHorizontalHeaderLabels(["File", "Line", "Indicator", "Code Snippet"])
        self.resultsTable.horizontalHeader().setStretchLastSection(True)
        self.resultsTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.resultsTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.resultsTable.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.resultsTable.doubleClicked.connect(self.show_code_detail)
        resultsTab = QtWidgets.QWidget()
        rLayout = QtWidgets.QVBoxLayout()
        rLayout.addWidget(self.resultsTable)
        resultsTab.setLayout(rLayout)
        self.tabWidget.addTab(resultsTab, "Flagged Results")
        
        # Tab 2: Full Source (Jadx)
        self.fullSourceTab = FullSourceTab()
        self.tabWidget.addTab(self.fullSourceTab, "Full Source (Jadx)")
        
        layout.addWidget(self.tabWidget)
        self.setLayout(layout)
    
    def upload_apk(self):
        apk_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select APK File", "", "APK Files (*.apk)")
        if apk_path:
            self.logText.append(f"<b>Selected APK:</b> {apk_path}")
            # Define output directories for decompilation.
            apktool_output = "decompiled_apktool"
            jadx_output = "decompiled_jadx"
            
            # Execute APKTool decompilation (executed silently).
            apktool_success = run_apktool_decompile(apk_path, apktool_output)
            
            # Execute JADX decompilation.
            self.logText.append("<b>Executing JADX decompilation process.</b>")
            jadx_success = run_jadx_decompile(apk_path, jadx_output)
            if jadx_success:
                self.logText.append("<span style='color: green;'>JADX decompilation completed successfully.</span>")
                self.jadx_output = jadx_output
                # Load the full source (JADX) into the file tree.
                self.fullSourceTab.load_directory(jadx_output)
            else:
                self.logText.append("<span style='color: red;'>JADX decompilation was not successful.</span>")
            
            # For flagged results, prefer APKTool output if available; otherwise use JADX output.
            if apktool_success:
                decompiled_dir = apktool_output
                self.logText.append("<b>Analyzing APKTool decompiled code for potential security issues.</b>")
            elif jadx_success:
                decompiled_dir = jadx_output
                self.logText.append("<b>Analyzing JADX decompiled code for potential security issues.</b>")
            else:
                self.logText.append("<span style='color: red;'>Decompilation unsuccessful by both methods. Analysis aborted.</span>")
                return
            
            flagged_results = scan_decompiled_code_for_malware(decompiled_dir)
            if flagged_results:
                self.logText.append(f"<span style='color: red;'>{len(flagged_results)} suspicious indicators identified.</span>")
                self.update_results_table(flagged_results)
            else:
                self.logText.append("<span style='color: green;'>No suspicious code patterns were detected.</span>")
                self.resultsTable.setRowCount(0)
    
    def update_results_table(self, results):
        """Update the table with flagged results including multi-line code snippets."""
        self.resultsTable.setRowCount(0)
        for result in results:
            row_position = self.resultsTable.rowCount()
            self.resultsTable.insertRow(row_position)
            file_item = QtWidgets.QTableWidgetItem(result["file"])
            line_item = QtWidgets.QTableWidgetItem(str(result["line"]))
            indicator_item = QtWidgets.QTableWidgetItem(result["message"])
            code_snippet = get_code_context(result["file"], result["line"], context_lines=2)
            code_item = QtWidgets.QTableWidgetItem(code_snippet)
            
            # Color coding: use a default scheme (you may adjust as needed).
            key = ""
            # Find a key that is in the result message (rough heuristic)
            for pat in get_suspicious_patterns().keys():
                if pat in result["message"].lower():
                    key = pat
                    break
            color = get_color_for_pattern(key) if key else QtGui.QColor("lightgray")
            for item in (file_item, line_item, indicator_item, code_item):
                item.setBackground(color)
            
            self.resultsTable.setItem(row_position, 0, file_item)
            self.resultsTable.setItem(row_position, 1, line_item)
            self.resultsTable.setItem(row_position, 2, indicator_item)
            self.resultsTable.setItem(row_position, 3, code_item)
    
    def show_code_detail(self):
        """Display a detailed view of the code around a flagged line."""
        selected_items = self.resultsTable.selectedItems()
        if selected_items:
            file_path = selected_items[0].text()
            line_number = int(selected_items[1].text())
            message = selected_items[2].text()
            
            detail_dialog = QtWidgets.QDialog(self)
            detail_dialog.setWindowTitle("Code Detail")
            layout = QtWidgets.QVBoxLayout()
            
            info_label = QtWidgets.QLabel(
                f"<b>File:</b> {file_path} <br> <b>Line:</b> {line_number} <br> <b>Indicator:</b> {message}"
            )
            layout.addWidget(info_label)
            
            code_view = QtWidgets.QPlainTextEdit()
            code_view.setReadOnly(True)
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    all_lines = f.readlines()
                    idx = line_number - 1
                    start = max(0, idx - 5)
                    end = min(len(all_lines), idx + 6)
                    context = "".join(all_lines[start:end])
                    code_view.setPlainText(context)
            except Exception:
                code_view.setPlainText("Error loading file content.")
            layout.addWidget(code_view)
            
            close_btn = QtWidgets.QPushButton("Close")
            close_btn.clicked.connect(detail_dialog.accept)
            layout.addWidget(close_btn)
            
            detail_dialog.setLayout(layout)
            detail_dialog.exec_()

######################################
# Main Application Window
######################################
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setWindowTitle("Advanced Android Malware Code Analyzer")
        self.setGeometry(100, 100, 900, 700)
        self.setCentralWidget(StaticAnalysisWidget(self))

######################################
# Main Entry Point
######################################
def main():
    app = QtWidgets.QApplication(sys.argv)
    # Apply advanced styling using the Fusion theme and a custom dark palette.
    app.setStyle("Fusion")
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor(53, 53, 53))
    palette.setColor(QtGui.QPalette.WindowText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Base, QtGui.QColor(25, 25, 25))
    palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(53, 53, 53))
    palette.setColor(QtGui.QPalette.ToolTipBase, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.ToolTipText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Text, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Button, QtGui.QColor(53, 53, 53))
    palette.setColor(QtGui.QPalette.ButtonText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.BrightText, QtCore.Qt.red)
    palette.setColor(QtGui.QPalette.Link, QtGui.QColor(42, 130, 218))
    palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(42, 130, 218))
    palette.setColor(QtGui.QPalette.HighlightedText, QtCore.Qt.black)
    app.setPalette(palette)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
