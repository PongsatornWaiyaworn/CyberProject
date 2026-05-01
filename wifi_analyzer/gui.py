import tkinter as tk
from tkinter import ttk
import threading
import queue

from .scanner import WiFiScanner
from .analyzer import APAnalyzer
from .config import DEFAULT_SCAN_DURATION


# ------------------ Tooltip ------------------
class ToolTip:
    def __init__(self, widget):
        self.widget = widget
        self.tip = None

    def show(self, text, x, y):
        self.hide()
        self.tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.geometry(f"+{x}+{y}")

        label = tk.Label(
            tw,
            text=text,
            justify=tk.LEFT,
            bg="#ffffe0",
            relief="solid",
            borderwidth=1,
            font=("Segoe UI", 9)
        )
        label.pack()

    def hide(self):
        if self.tip:
            self.tip.destroy()
            self.tip = None


# ------------------ GUI ------------------
class WiFiAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Risk Analyzer")
        self.root.geometry("1100x750")

        self.tooltip = ToolTip(root)

        self._build_ui()

        self.stop_event = threading.Event()
        self.result_queue = queue.Queue()
        self.root.after(100, self._poll_queue)

    def _build_ui(self):
        # ---------- TOP ----------
        top = ttk.Frame(self.root)
        top.pack(fill=tk.X, padx=10, pady=(5, 2))

        ttk.Label(top, text="Scan Duration (seconds):").pack(side=tk.LEFT)

        self.duration_var = tk.StringVar(value=str(DEFAULT_SCAN_DURATION))
        ttk.Entry(top, textvariable=self.duration_var, width=8).pack(side=tk.LEFT, padx=5)

        self.demo_var = tk.BooleanVar()
        ttk.Checkbutton(top, text="Demo Mode", variable=self.demo_var).pack(side=tk.LEFT, padx=10)

        self.btn_scan = ttk.Button(top, text="Start Scan", command=self._start_scan)
        self.btn_scan.pack(side=tk.LEFT)

        self.btn_stop = ttk.Button(top, text="Stop", command=self._stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill=tk.X, padx=10)

        self.status = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status).pack(anchor=tk.W, padx=10, pady=(0, 2))

        cols = ("ssid","bssid","vendor","channel","rssi","encryption","score","level","flags")

        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 5))

        # ---------- TABLE ----------
        table_frame = ttk.Frame(paned)
        paned.add(table_frame, weight=2)

        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.root.update_idletasks()
        total_width = self.root.winfo_width()

        widths = {
            "ssid": int(total_width * 0.15),
            "bssid": int(total_width * 0.12),
            "vendor": int(total_width * 0.10),
            "channel": int(total_width * 0.08),
            "rssi": int(total_width * 0.07),
            "encryption": int(total_width * 0.10),
            "score": int(total_width * 0.05),
            "level": int(total_width * 0.08),
            "flags": int(total_width * 0.25),
        }

        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=widths[c], stretch=True)

        scrollbar = ttk.Scrollbar(table_frame, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.bind("<Motion>", self._hover)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # ---------- DETAIL ----------
        detail_frame = ttk.LabelFrame(paned, text="Flags Detail")
        paned.add(detail_frame, weight=3)

        self.detail_text = tk.Text(
            detail_frame,
            wrap="word",
            font=("Segoe UI", 10)
        )
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        scroll = ttk.Scrollbar(self.detail_text, command=self.detail_text.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.detail_text.configure(yscrollcommand=scroll.set)

        self.detail_text.config(state=tk.DISABLED)

    # ------------------ Scan ------------------
    def _start_scan(self):
        try:
            duration = int(self.duration_var.get())
            if duration <= 0:
                raise ValueError
        except ValueError:
            duration = DEFAULT_SCAN_DURATION
            self.duration_var.set(str(DEFAULT_SCAN_DURATION))

        self.tree.delete(*self.tree.get_children())

        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.config(state=tk.DISABLED)

        self.stop_event.clear()

        self.btn_scan.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.progress.start()

        self.status.set(f"Scanning {duration}s...")

        threading.Thread(
            target=self._worker,
            args=(self.demo_var.get(), duration),
            daemon=True
        ).start()

    def _stop_scan(self):
        self.stop_event.set()
        self.status.set("Stopping...")

        self.progress.stop()
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)

    def _worker(self, demo, duration):
        scanner = WiFiScanner(demo=demo, stop_event=self.stop_event)
        aps = scanner.scan(duration=duration)

        if self.stop_event.is_set():
            return

        analyzer = APAnalyzer(aps)
        report = analyzer.analyze()

        self.result_queue.put(report)

    def _poll_queue(self):
        try:
            report = self.result_queue.get_nowait()
            self._show(report)
            self._finish()
        except queue.Empty:
            pass

        self.root.after(100, self._poll_queue)

    def _finish(self):
        self.progress.stop()
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.status.set("Done")

    # ------------------ RESULT ------------------
    def _normalize_level(self, level):
        lvl = str(level).lower()
        if "high" in lvl:
            return "high"
        elif "suspicious" in lvl:
            return "suspicious"
        else:
            return "safe"

    def _show(self, report):
        for row in report.get("aps", []):
            lvl = self._normalize_level(row["level"])
            flags = "; ".join(row.get("reasons", []))

            self.tree.insert(
                "",
                tk.END,
                values=(
                    row["ssid"],
                    row["bssid"],
                    row["vendor"],
                    row["channel"],
                    f"{row['rssi']} dBm",
                    row["encryption"],
                    row["score"],
                    row["level"],
                    flags
                ),
                tags=(lvl,)
            )

        self.tree.tag_configure("high", background="#ff6b6b")
        self.tree.tag_configure("suspicious", background="#ffff6a")
        self.tree.tag_configure("safe", background="#6bff6b")

    # ------------------ Tooltip ------------------
    def _hover(self, event):
        item = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)

        if not item:
            self.tooltip.hide()
            return

        col_index = int(col.replace("#", "")) - 1

        if col_index == 8:
            text = self.tree.item(item, "values")[8]
            x = self.root.winfo_pointerx() + 10
            y = self.root.winfo_pointery() + 10
            self.tooltip.show(text, x, y)
        else:
            self.tooltip.hide()

    # ------------------ Detail Panel ------------------
    def _on_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return

        values = self.tree.item(selected[0], "values")

        flags = values[8] if len(values) > 8 else ""

        if flags and flags != "-":
            flag_lines = flags.split("; ")
            flags_text = "\n- " + "\n- ".join(flag_lines)
        else:
            flags_text = "No issues detected"

        text = f"""SSID: {values[0]}
BSSID: {values[1]}
Vendor: {values[2]}
Risk Level: {values[7]}

Reasons:{flags_text}
"""

        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, text)
        self.detail_text.config(state=tk.DISABLED)


def launch_gui():
    root = tk.Tk()
    WiFiAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    launch_gui()