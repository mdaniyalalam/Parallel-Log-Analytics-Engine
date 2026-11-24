import json
import os
import queue
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# Colors and font
BG, CARD, BORDER = "#0f172a", "#1e293b", "#334155"
FG, MUTED, ACCENT = "#f8fafc", "#94a3b8", "#38bdf8"
GREEN, AMBER, ORANGE, RED = "#22c55e", "#f59e0b", "#f97316", "#ef4444"
FONT = "DejaVu Sans"


def card(parent, **kw):
    """A dark rounded-looking box with a thin border."""
    return tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1, **kw)


def label(parent, text, fg=MUTED, size=9, bold=False):
    """A text label that sits on a card."""
    return tk.Label(parent, text=text, bg=CARD, fg=fg, font=(FONT, size, "bold" if bold else "normal"))


class LogAnalyticsApp:
    def __init__(self, root):
        self.root = root
        root.title("Parallel Log Processing & Analytics Engine")
        root.geometry("900x620")
        root.minsize(800, 560)
        root.configure(bg=BG)

        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.engine_path = os.path.join(self.base_dir, "engine")
        self.csv_path = os.path.join(self.base_dir, "report.csv")
        self.msgs = queue.Queue()      # engine thread -> GUI
        self.proc = None               # running engine process
        self.running = False
        self.last_csv = None
        self.threads = self.io = 0     # settings used for the current run

        self._setup_styles()
        self._build_ui()
        self._init_charts()
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        root.after(40, self._poll)

    # ---------- look and layout ----------
    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("TFrame", background=BG)
        s.configure("TLabel", background=BG, foreground=FG, font=(FONT, 10))
        s.configure("TEntry", fieldbackground=CARD, foreground=FG, insertcolor=FG, bordercolor=BORDER)
        s.configure("TSpinbox", fieldbackground=CARD, foreground=FG, arrowcolor=FG, bordercolor=BORDER)
        s.configure("Accent.TButton", background=ACCENT, foreground=BG, font=(FONT, 10, "bold"),
                    borderwidth=0, padding=(14, 6))
        s.map("Accent.TButton", background=[("active", "#7dd3fc"), ("disabled", BORDER)],
              foreground=[("disabled", MUTED)])
        s.configure("Ghost.TButton", background=CARD, foreground=FG, font=(FONT, 10),
                    bordercolor=BORDER, padding=(12, 6))
        s.map("Ghost.TButton", background=[("active", BORDER), ("disabled", BG)],
              foreground=[("disabled", MUTED)])
        s.configure("Horizontal.TProgressbar", troughcolor=CARD, background=ACCENT, bordercolor=BG,
                    lightcolor=ACCENT, darkcolor=ACCENT, thickness=8)
        s.configure("Treeview", background=CARD, foreground=FG, fieldbackground=CARD,
                    rowheight=26, borderwidth=0, font=(FONT, 9))
        s.configure("Treeview.Heading", background=BG, foreground=MUTED, font=(FONT, 9, "bold"), relief="flat")
        s.map("Treeview", background=[("selected", BORDER)])

    def _build_ui(self):
        # Top control bar
        top = card(self.root, padx=16, pady=12)
        top.pack(fill="x", padx=16, pady=(14, 10))
        label(top, "Log File:", bold=True).pack(side="left", padx=(0, 6))
        self.file_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.file_var, width=28).pack(side="left", padx=(0, 6))
        ttk.Button(top, text="Browse", style="Ghost.TButton", command=self._browse).pack(side="left", padx=(0, 14))

        self.threads_var = tk.IntVar(value=4)
        self.io_var = tk.IntVar(value=2)
        for text, var, maximum in (("Threads:", self.threads_var, 32), ("I/O Sem:", self.io_var, 16)):
            label(top, text, bold=True).pack(side="left", padx=(0, 5))
            ttk.Spinbox(top, from_=1, to=maximum, textvariable=var, width=4).pack(side="left", padx=(0, 12))

        self.run_btn = ttk.Button(top, text="Run Analysis", style="Accent.TButton", command=self._start)
        self.run_btn.pack(side="left")
        self.export_btn = ttk.Button(top, text="Save CSV", style="Ghost.TButton",
                                     command=self._save_csv, state="disabled")
        self.export_btn.pack(side="right")

        # Status text + progress bar
        row = ttk.Frame(self.root)
        row.pack(fill="x", padx=16, pady=(0, 10))
        self.status_var = tk.StringVar(value="Select a log file and click Run Analysis.")
        self.pct_var = tk.StringVar(value="0%")
        ttk.Label(row, textvariable=self.status_var, foreground=MUTED).pack(side="left")
        ttk.Label(row, textvariable=self.pct_var, foreground=ACCENT, font=(FONT, 9, "bold")).pack(side="right")
        self.progress = ttk.Progressbar(self.root, mode="determinate", maximum=100)
        self.progress.pack(fill="x", padx=16, pady=(0, 12))

        # Summary cards
        kpi_row = ttk.Frame(self.root)
        kpi_row.pack(fill="x", padx=16, pady=(0, 12))
        self.kpis = {}
        specs = [("lines", "TOTAL LINES", "0", FG), ("single", "SINGLE-THREADED", "—", MUTED),
                 ("multi", "MULTITHREADED", "—", ACCENT), ("speedup", "SPEEDUP", "—", GREEN),
                 ("verified", "INTEGRITY CHECK", "PENDING", MUTED)]
        for i, (key, title, default, color) in enumerate(specs):
            box = card(kpi_row, padx=14, pady=10)
            box.pack(side="left", fill="both", expand=True, padx=(0 if i == 0 else 8, 0))
            label(box, title, size=8, bold=True).pack(anchor="w")
            self.kpis[key] = label(box, default, fg=color, size=16, bold=True)
            self.kpis[key].pack(anchor="w", pady=(4, 0))

        # Charts on the left, security panel on the right
        body = ttk.Frame(self.root)
        body.pack(fill="both", expand=True, padx=16, pady=(0, 14))
        self.chart_frame = card(body)
        self.chart_frame.pack(side="left", fill="both", expand=True, padx=(0, 12))

        right = ttk.Frame(body, width=330)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        pat_card = card(right, padx=14, pady=12)
        pat_card.pack(fill="x", pady=(0, 12))
        label(pat_card, "SECURITY PATTERNS", fg=ACCENT, bold=True).pack(anchor="w", pady=(0, 8))
        self.patterns = {}
        for key, text, color in (("failed_logins", "Failed Logins", ORANGE),
                                 ("invalid_users", "Invalid Users", AMBER),
                                 ("breakin_attempts", "Break-in Attempts", RED),
                                 ("sudo_failures", "Sudo Failures", RED),
                                 ("brute_force_ips", "Brute-Force IPs (>=5)", ACCENT)):
            line = tk.Frame(pat_card, bg=CARD)
            line.pack(fill="x", pady=2)
            label(line, text).pack(side="left")
            self.patterns[key] = label(line, "0", fg=color, size=10, bold=True)
            self.patterns[key].pack(side="right")

        ip_card = card(right, padx=12, pady=12)
        ip_card.pack(fill="both", expand=True)
        label(ip_card, "TOP SUSPICIOUS IPs", fg=ACCENT, bold=True).pack(anchor="w", pady=(0, 8))
        self.tree = ttk.Treeview(ip_card, columns=("ip", "count", "flag"), show="headings", height=10)
        for col, text, width, anchor in (("ip", "IP Address", 120, "w"), ("count", "Events", 70, "e"),
                                         ("flag", "Alert", 95, "center")):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor=anchor)
        self.tree.pack(fill="both", expand=True)

    # ---------- charts ----------
    def _init_charts(self):
        self.fig = Figure(figsize=(8, 4.6), dpi=100, facecolor=CARD)
        self.ax_sev = self.fig.add_subplot(1, 2, 1)
        self.ax_perf = self.fig.add_subplot(1, 2, 2)
        self.fig.subplots_adjust(left=0.12, right=0.96, top=0.86, bottom=0.16, wspace=0.40)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.chart_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=6, pady=6)
        self._draw_severity(0, 0, 0, 0)
        self._draw_perf(0.0, 0.0, 4)

    def _bar_chart(self, ax, title, ylabel, labels, vals, colors, fmt, width):
        """Draw one styled bar chart (used for both charts)."""
        ax.clear()
        ax.set_facecolor(CARD)
        ax.set_title(title, color=FG, fontsize=11, fontweight="bold", pad=12)
        ax.set_ylabel(ylabel, color=MUTED, fontsize=9)
        ax.tick_params(colors=MUTED, labelsize=9)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            ax.spines[side].set_color(BORDER)
        ax.grid(axis="y", color=BORDER, linestyle="--", alpha=0.4)
        ax.set_axisbelow(True)

        bars = ax.bar(labels, vals, color=colors, width=width)
        ax.set_ylim(0, (max(vals) or 10) * 1.2)
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, v, fmt(v), ha="center", va="bottom",
                        color=FG, fontsize=8, fontweight="bold")
        self.canvas.draw_idle()

    def _draw_severity(self, info, warn, err, crit):
        self._bar_chart(self.ax_sev, "Severity Distribution", "Log Entries",
                        ["INFO", "WARN", "ERROR", "CRIT"], [info, warn, err, crit],
                        [ACCENT, AMBER, ORANGE, RED], lambda v: f"{v:,}", 0.55)

    def _draw_perf(self, single_ms, multi_ms, threads):
        self._bar_chart(self.ax_perf, "Execution Time Comparison", "Time (ms)",
                        ["Single\n(1 Thread)", f"Parallel\n({threads} Threads)"], [single_ms, multi_ms],
                        [MUTED, GREEN], lambda v: f"{v:.1f} ms", 0.48)

    # ---------- running the engine ----------
    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select Log File", initialdir=self.base_dir,
            filetypes=[("Log & Text Files", "*.log *.txt"), ("All Files", "*.*")])
        if path:
            self.file_var.set(path)

    def _start(self):
        if self.running:
            return
        log_path = self.file_var.get().strip()
        if not os.path.isfile(log_path):
            messagebox.showwarning("Missing File", "Please select a valid log file first.")
            return
        if not os.path.isfile(self.engine_path):
            messagebox.showerror("Engine Not Found", f"Compiled binary not found at:\n{self.engine_path}\n\n"
                                 "Compile with:\ng++ -O2 -std=c++11 -pthread engine.cpp -o engine")
            return
        try:  
            self.threads = max(1, self.threads_var.get())
            self.io = max(1, self.io_var.get())
        except tk.TclError:
            messagebox.showwarning("Invalid Input", "Threads and I/O Sem must be whole numbers.")
            return

        # Reset the screen for a new run
        self.running = True
        self.run_btn.config(state="disabled")
        self.export_btn.config(state="disabled")
        self.progress["value"] = 0
        self.pct_var.set("0%")
        self.status_var.set("Warming page cache & starting engine...")
        self.kpis["lines"].config(text="0")
        for key, color in (("single", MUTED), ("multi", ACCENT), ("speedup", GREEN)):
            self.kpis[key].config(text="...", fg=color)
        self.kpis["verified"].config(text="RUNNING", fg=AMBER)
        for lbl in self.patterns.values():
            lbl.config(text="0")
        self.tree.delete(*self.tree.get_children())
        self._draw_severity(0, 0, 0, 0)

        cmd = [self.engine_path, log_path, "--threads", str(self.threads),
               "--io-limit", str(self.io), "--csv", self.csv_path]
        threading.Thread(target=self._run_engine, args=(cmd,), daemon=True).start()

    def _run_engine(self, cmd):
        """Runs in a background thread: reads the engine's output and queues it for the GUI."""
        parsers = {"PHASE": ("phase", str), "PROGRESS": ("progress", int),
                   "STATS": ("stats", json.loads), "RESULT": ("result", json.loads)}
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         text=True, bufsize=1)
            for raw in self.proc.stdout:
                tag, _, payload = raw.strip().partition(" ")
                if tag in parsers:
                    kind, parse = parsers[tag]
                    self.msgs.put((kind, parse(payload)))
            err = self.proc.stderr.read().strip()
            rc = self.proc.wait()
            if rc != 0:
                self.msgs.put(("error", err or f"Engine exited with code {rc}"))
            else:
                self.msgs.put(("done", None))
        except Exception as exc:
            self.msgs.put(("error", str(exc)))

    # ---------- updating the screen ----------
    def _poll(self):
        """Runs in the GUI thread every 40 ms and handles queued engine messages."""
        try:
            while True:
                kind, data = self.msgs.get_nowait()
                if kind == "phase":
                    if data == "baseline":
                        self.status_var.set("Phase 1/2: Running single-threaded baseline...")
                    else:
                        self.status_var.set(f"Phase 2/2: Parsing with {self.threads} threads "
                                            f"(I/O limit {self.io})...")
                elif kind == "progress":
                    self.progress["value"] = data
                    self.pct_var.set(f"{data}%")
                elif kind == "stats":
                    self.kpis["lines"].config(text=f"{data['lines']:,}")
                    self._show_patterns(data)
                    self._draw_severity(data["info"], data["warning"], data["error"], data["critical"])
                elif kind == "result":
                    self._apply_result(data)
                elif kind in ("error", "done"):
                    self.running = False
                    self.run_btn.config(state="normal")
                    if kind == "error":
                        self.status_var.set("Analysis failed.")
                        self.kpis["verified"].config(text="ERROR", fg=RED)
                        messagebox.showerror("Engine Error", data)
        except queue.Empty:
            pass
        self.root.after(40, self._poll)

    def _show_patterns(self, counts):
        for key, lbl in self.patterns.items():
            if key in counts:
                lbl.config(text=f"{counts[key]:,}")

    def _apply_result(self, r):
        self.progress["value"] = 100
        self.pct_var.set("100%")
        self.status_var.set(f"Completed: {os.path.basename(r['file'])} ({r['file_size_mb']:.2f} MB)")

        self.kpis["lines"].config(text=f"{r['total_lines']:,}")
        self.kpis["single"].config(text=f"{r['single_ms']:.1f} ms", fg=FG)
        self.kpis["multi"].config(text=f"{r['multi_ms']:.1f} ms", fg=ACCENT)
        self.kpis["speedup"].config(text=f"{r['speedup']:.2f}x", fg=GREEN)
        ok = r["verified"]
        self.kpis["verified"].config(text="VERIFIED" if ok else "MISMATCH", fg=GREEN if ok else RED)

        sev = r["severity"]
        self._draw_severity(sev["info"], sev["warning"], sev["error"], sev["critical"])
        self._draw_perf(r["single_ms"], r["multi_ms"], r["threads"])
        self._show_patterns(r["patterns"])

        for e in r["top_ips"]:
            flag = "BRUTE FORCE" if e["count"] >= 5 else "NORMAL"
            self.tree.insert("", "end", values=(e["ip"], f"{e['count']:,}", flag))

        self.last_csv = r.get("csv_path")
        if self.last_csv and os.path.isfile(self.last_csv):
            self.export_btn.config(state="normal")

    # ---------- other buttons ----------
    def _save_csv(self):
        if not self.last_csv or not os.path.isfile(self.last_csv):
            return
        dest = filedialog.asksaveasfilename(
            title="Export CSV Report", defaultextension=".csv",
            initialfile="log_analytics_report.csv", filetypes=[("CSV Files", "*.csv")])
        if dest:
            shutil.copyfile(self.last_csv, dest)
            self.status_var.set(f"Report exported to {dest}")

    def _on_close(self):
        """Stop the engine if the window is closed during a run."""
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    LogAnalyticsApp(root)
    root.mainloop()