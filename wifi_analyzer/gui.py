"""Tkinter GUI for Fake Wi-Fi Risk Analyzer."""
import tkinter as tk
from tkinter import ttk
import threading
import queue
import platform

from .scanner import WiFiScanner
from .analyzer import APAnalyzer
from .config import (
    RISK_HIGH,
    RISK_SUSPICIOUS,
    RISK_SAFE,
    COLOR_HIGH_RISK,
    COLOR_SUSPICIOUS,
    COLOR_SAFE,
    DEFAULT_SCAN_DURATION,
)


class WiFiAnalyzerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Fake Wi-Fi Risk Analyzer (Evil Twin Detector)")
        self.root.geometry("1100x650")
        self.root.minsize(900, 500)

        self._style()
        self._build_ui()

        self.scan_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.result_queue: queue.Queue = queue.Queue()
        self.root.after(100, self._poll_queue)

    def _style(self):
        style = ttk.Style()
        if platform.system() == "Windows":
            style.theme_use("vista")
        elif platform.system() == "Darwin":
            style.theme_use("clam")
        else:
            style.theme_use("clam")

        style.configure("HighRisk.Treeview", background="#ffcccc")
        style.configure("Suspicious.Treeview", background="#ffffcc")
        style.configure("Safe.Treeview", background="#ccffcc")

    def _build_ui(self):
        # ---- Top control frame ----
        ctrl = ttk.Frame(self.root, padding=10)
        ctrl.pack(fill=tk.X)

        ttk.Label(ctrl, text="Interface:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.iface_var = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self.iface_var, width=15).grid(row=0, column=1, sticky=tk.W, padx=(0, 15))

        ttk.Label(ctrl, text="Duration (s):").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.duration_var = tk.StringVar(value=str(DEFAULT_SCAN_DURATION))
        ttk.Entry(ctrl, textvariable=self.duration_var, width=6).grid(row=0, column=3, sticky=tk.W, padx=(0, 15))

        self.demo_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctrl, text="Demo mode (no Wi-Fi needed)", variable=self.demo_var).grid(row=0, column=4, sticky=tk.W, padx=(0, 15))

        self.btn_scan = ttk.Button(ctrl, text="Start Scan", command=self._start_scan)
        self.btn_scan.grid(row=0, column=5, sticky=tk.W, padx=(0, 5))

        self.btn_stop = ttk.Button(ctrl, text="Stop", command=self._stop_scan, state=tk.DISABLED)
        self.btn_stop.grid(row=0, column=6, sticky=tk.W)

        # ---- Progress bar ----
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill=tk.X, padx=10, pady=(0, 5))

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var, font=("Segoe UI", 9, "italic")).pack(anchor=tk.W, padx=10)

        # ---- Treeview ----
        cols = ("ssid", "bssid", "vendor", "channel", "rssi", "encryption", "score", "level", "flags")
        self.tree = ttk.Treeview(
            self.root,
            columns=cols,
            show="headings",
            selectmode="browse",
        )
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        headings = {
            "ssid": "SSID",
            "bssid": "BSSID",
            "vendor": "Vendor",
            "channel": "Ch",
            "rssi": "RSSI",
            "encryption": "Encryption",
            "score": "Score",
            "level": "Risk Level",
            "flags": "Flags",
        }
        widths = {"ssid": 180, "bssid": 140, "vendor": 120, "channel": 40, "rssi": 70, "encryption": 100, "score": 50, "level": 90, "flags": 300}
        for c in cols:
            self.tree.heading(c, text=headings.get(c, c))
            self.tree.column(c, width=widths.get(c, 80), anchor=tk.CENTER if c in ("channel", "rssi", "score", "level") else tk.W)

        vsb = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=vsb.set)

        # ---- Summary bar ----
        self.summary_var = tk.StringVar(value="Summary: 0 APs")
        ttk.Label(self.root, textvariable=self.summary_var, font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, padx=10, pady=(5, 10))

    def _start_scan(self):
        try:
            duration = int(self.duration_var.get())
        except ValueError:
            duration = DEFAULT_SCAN_DURATION

        self.tree.delete(*self.tree.get_children())
        self.stop_event.clear()
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.progress.start()
        self.status_var.set("Scanning...")
        self.summary_var.set("Scanning...")

        iface = self.iface_var.get() or None
        demo = self.demo_var.get()

        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(iface, demo, duration),
            daemon=True,
        )
        self.scan_thread.start()

    def _stop_scan(self):
        self.stop_event.set()
        self.status_var.set("Stopping...")

    def _scan_worker(self, iface, demo, duration):
        try:
            scanner = WiFiScanner(iface=iface, demo=demo, stop_event=self.stop_event)
            aps = scanner.scan(duration=duration)
            
            # If real scan found nothing and not in demo mode, try demo mode as fallback
            if not demo and not aps:
                print("[*] Real scan returned no results. Trying demo mode as fallback...")
                self.status_var.set("No networks found. Using demo data...")
                scanner_demo = WiFiScanner(iface=None, demo=True, stop_event=self.stop_event)
                aps = scanner_demo.scan(duration=min(duration, 5))
            
            analyzer = APAnalyzer(aps)
            report = analyzer.analyze()
            self.result_queue.put(("done", report))
        except Exception as exc:
            self.result_queue.put(("error", str(exc)))

    def _poll_queue(self):
        try:
            msg_type, data = self.result_queue.get_nowait()
            if msg_type == "done":
                self._display_results(data)
                self._finish_scan("Scan complete")
            elif msg_type == "error":
                self._finish_scan(f"Error: {data}")
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _finish_scan(self, status: str):
        self.progress.stop()
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.status_var.set(status)

    def _display_results(self, report):
        aps = report.get("aps", [])
        
        for row in aps:
            score = row["score"]
            level = row["level"]
            tags = ()
            if score >= RISK_HIGH:
                tags = ("high",)
            elif score >= RISK_SUSPICIOUS:
                tags = ("suspicious",)
            else:
                tags = ("safe",)

            self.tree.insert(
                "",
                tk.END,
                values=(
                    row.get("ssid", ""),
                    row.get("bssid", ""),
                    row.get("vendor", ""),
                    row.get("channel", ""),
                    f"{row.get('rssi', '')} dBm",
                    row.get("encryption", ""),
                    score,
                    level,
                    "; ".join(row.get("reasons", [])) if row.get("reasons") else "-",
                ),
                tags=tags,
            )

        # Configure tag colors
        self.tree.tag_configure("high", background="#ff4444", foreground="white")
        self.tree.tag_configure("suspicious", background="#ffcc00", foreground="black")
        self.tree.tag_configure("safe", background="#44dd44", foreground="black")

        # Update summary
        total = report.get("total", len(aps))
        high = sum(1 for r in aps if r["score"] >= RISK_HIGH)
        susp = sum(1 for r in aps if RISK_SUSPICIOUS <= r["score"] < RISK_HIGH)
        safe = sum(1 for r in aps if r["score"] < RISK_SUSPICIOUS)
        self.summary_var.set(f"Summary: {high} High Risk | {susp} Suspicious | {safe} Safe | Total {total}")


def launch_gui():
    root = tk.Tk()
    app = WiFiAnalyzerGUI(root)
    root.mainloop()
