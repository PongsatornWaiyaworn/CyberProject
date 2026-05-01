"""Tkinter GUI for Fake Wi-Fi Risk Analyzer."""
import tkinter as tk
from tkinter import ttk
import threading
import queue
import platform
import subprocess
import re

from .scanner import WiFiScanner
from .analyzer import APAnalyzer
from .config import DEFAULT_SCAN_DURATION


class WiFiAnalyzerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Fake Wi-Fi Risk Analyzer (Evil Twin Detector)")
        self.root.geometry("1100x700")

        self._style()
        self._build_ui()

        self.scan_thread = None
        self.stop_event = threading.Event()
        self.result_queue = queue.Queue()
        self.root.after(100, self._poll_queue)

    def _style(self):
        style = ttk.Style()
        style.theme_use("vista" if platform.system() == "Windows" else "clam")

    def _build_ui(self):
        ctrl = ttk.Frame(self.root, padding=10)
        ctrl.pack(fill=tk.X)

        ttk.Label(ctrl, text="Duration (s):").grid(row=0, column=0)
        self.duration_var = tk.StringVar(value=str(DEFAULT_SCAN_DURATION))
        ttk.Entry(ctrl, textvariable=self.duration_var, width=6).grid(row=0, column=1)

        self.demo_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctrl, text="Demo mode", variable=self.demo_var).grid(row=0, column=2)

        ttk.Button(ctrl, text="Start Scan", command=self._start_scan).grid(row=0, column=3)
        self.btn_stop = ttk.Button(ctrl, text="Stop", command=self._stop_scan, state=tk.DISABLED)
        self.btn_stop.grid(row=0, column=4)

        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill=tk.X, padx=10)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var).pack(anchor=tk.W, padx=10)

        # ===== TABLE =====
        cols = ("ssid", "bssid", "vendor", "channel", "rssi", "encryption", "score", "level", "flags")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        headings = ["SSID", "BSSID", "Vendor", "Ch", "RSSI", "Encryption", "Score", "Risk", "Flags"]

        for i, c in enumerate(cols):
            self.tree.heading(c, text=headings[i])

            if c == "flags":
                self.tree.column(c, width=250)
            elif c == "ssid":
                self.tree.column(c, width=150)
            elif c == "bssid":
                self.tree.column(c, width=130)
            else:
                self.tree.column(c, width=80, anchor=tk.CENTER)

        # ===== DETAIL PANEL (แสดง Flags เต็ม) =====
        ttk.Label(self.root, text="Details (Full Flags):", font=("Segoe UI", 10, "bold"))\
            .pack(anchor=tk.W, padx=10)

        self.detail = tk.Text(self.root, height=6, wrap="word")
        self.detail.pack(fill=tk.X, padx=10, pady=(0, 10))

        # bind click
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # summary
        self.summary_var = tk.StringVar(value="Summary: 0 APs")
        ttk.Label(self.root, textvariable=self.summary_var).pack(anchor=tk.W, padx=10)

    # ===== INTERFACES =====
    def _get_interfaces(self):
        system = platform.system()
        try:
            if system == "Windows":
                out = subprocess.check_output("netsh wlan show interfaces", shell=True, encoding="utf-8")
                return re.findall(r"Name\s*:\s*(.+)", out)
            elif system == "Linux":
                out = subprocess.check_output("iw dev", shell=True, encoding="utf-8")
                return re.findall(r"Interface\s+(\w+)", out)
            elif system == "Darwin":
                out = subprocess.check_output("networksetup -listallhardwareports", shell=True, encoding="utf-8")
                return re.findall(r"Device: (.+)", out)
        except:
            return []

    # ===== SCAN =====
    def _start_scan(self):
        self.tree.delete(*self.tree.get_children())
        self.detail.delete("1.0", tk.END)

        self.stop_event.clear()
        self.progress.start()
        self.status_var.set("Scanning...")

        interfaces = self._get_interfaces()
        demo = self.demo_var.get()

        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(interfaces, demo),
            daemon=True
        )
        self.scan_thread.start()

    def _stop_scan(self):
        self.stop_event.set()

    def _scan_worker(self, interfaces, demo):
        try:
            all_aps = []

            if demo:
                scanner = WiFiScanner(demo=True, stop_event=self.stop_event)
                all_aps = scanner.scan(5)
            else:
                for iface in interfaces:
                    if self.stop_event.is_set():
                        break
                    try:
                        scanner = WiFiScanner(iface=iface, stop_event=self.stop_event)
                        all_aps += scanner.scan(5)
                    except:
                        pass

            if not all_aps:
                scanner = WiFiScanner(demo=True, stop_event=self.stop_event)
                all_aps = scanner.scan(5)

            report = APAnalyzer(all_aps).analyze()
            self.result_queue.put(("done", report))

        except Exception as e:
            self.result_queue.put(("error", str(e)))

    # ===== UPDATE UI =====
    def _poll_queue(self):
        try:
            msg, data = self.result_queue.get_nowait()
            if msg == "done":
                self._display(data)
                self.progress.stop()
                self.status_var.set("Done")
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _display(self, report):
        aps = report.get("aps", [])

        self.tree.tag_configure("high", background="#ff4444")
        self.tree.tag_configure("sus", background="#ffcc00")
        self.tree.tag_configure("safe", background="#44dd44")

        for row in aps:
            level = row.get("level", "").lower()

            if "high" in level:
                tag = "high"
            elif "suspicious" in level:
                tag = "sus"
            else:
                tag = "safe"

            flags_full = "; ".join(row.get("reasons", []))

            self.tree.insert(
                "",
                tk.END,
                values=(
                    row.get("ssid"),
                    row.get("bssid"),
                    row.get("vendor"),
                    row.get("channel"),
                    f"{row.get('rssi')} dBm",
                    row.get("encryption"),
                    row.get("score"),
                    row.get("level"),
                    flags_full  
                ),
                tags=(tag,)
            )

        self.summary_var.set(f"Summary: {len(aps)} APs")

    # ===== SELECT ROW → SHOW FULL FLAGS =====
    def _on_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return

        item = self.tree.item(selected[0])
        values = item["values"]

        full_flags = values[8]

        self.detail.delete("1.0", tk.END)
        self.detail.insert(tk.END, full_flags)


def launch_gui():
    root = tk.Tk()
    WiFiAnalyzerGUI(root)
    root.mainloop()