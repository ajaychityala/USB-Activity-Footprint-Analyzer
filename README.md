# USB-Activity-Footprint-Analyzer
A forensic automation tool for monitoring USB device activities, detecting insider threats, and generating digital evidence reports using PowerShell, Python, and Tkinter GUI
"""
USB Activity Footprint Analyzer (with PDF export)
Author: Ajay Chityala (adapted)
Platform: Windows 10/11
"""

import os
import time
import csv
import threading
import zipfile
import tempfile
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog

# Third-party libs
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # backend for PNG creation
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import A4
from reportlab.lib import utils
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table
from reportlab.lib.units import cm

# -------------------- Paths --------------------
DESKTOP = Path(os.path.join(os.path.expanduser("~"), "Desktop"))
CSV_LOG = DESKTOP / "usb_activity_log.csv"
TXT_SUMMARY = DESKTOP / "usb_summary.txt"
PDF_REPORT = DESKTOP / "usb_forensic_report.pdf"
ZIP_REPORT = DESKTOP / "USB_Forensic_Report.zip"
CHART_PNG = DESKTOP / "usb_timeline_chart.png"

# -------------------- Globals --------------------
usb_log = []              # in-memory event list (dicts)
connected_drives = set()
monitoring = False
observer = None

# -------------------- Helpers --------------------
def append_log(event_type, details):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {"Timestamp": ts, "Event": event_type, "Details": details}
    usb_log.append(entry)
    # persist immediately
    save_logs()
    return entry

def save_logs():
    if usb_log:
        df = pd.DataFrame(usb_log)
        df.to_csv(CSV_LOG, index=False)
        with open(TXT_SUMMARY, "w", encoding="utf8") as f:
            for e in usb_log:
                f.write(f"{e['Timestamp']}  |  {e['Event']}  |  {e['Details']}\n")

def zip_report():
    # include CSV, TXT, PDF (if exists), chart (if exists)
    with zipfile.ZipFile(ZIP_REPORT, 'w', zipfile.ZIP_DEFLATED) as z:
        if CSV_LOG.exists(): z.write(CSV_LOG, CSV_LOG.name)
        if TXT_SUMMARY.exists(): z.write(TXT_SUMMARY, TXT_SUMMARY.name)
        if PDF_REPORT.exists(): z.write(PDF_REPORT, PDF_REPORT.name)
        if CHART_PNG.exists(): z.write(CHART_PNG, CHART_PNG.name)
    messagebox.showinfo("ZIP Exported", f"Report ZIP created on Desktop:\n{ZIP_REPORT}")

# -------------------- File event handler --------------------
class USBFileHandler(FileSystemEventHandler):
    def __init__(self, gui_callback):
        super().__init__()
        self.gui_callback = gui_callback

    def on_created(self, event):
        if event.is_directory: return
        e = append_log("File Created", event.src_path)
        self.gui_callback(format_entry(e))

    def on_deleted(self, event):
        if event.is_directory: return
        e = append_log("File Deleted", event.src_path)
        self.gui_callback(format_entry(e))

    def on_modified(self, event):
        if event.is_directory: return
        e = append_log("File Modified", event.src_path)
        self.gui_callback(format_entry(e))

    def on_moved(self, event):
        if event.is_directory: return
        details = f"{event.src_path} → {event.dest_path}"
        e = append_log("File Renamed", details)
        self.gui_callback(format_entry(e))

# -------------------- USB monitoring thread --------------------
class USBMonitor(threading.Thread):
    def __init__(self, gui_callback):
        super().__init__(daemon=True)
        self.gui_callback = gui_callback
        self.stop_flag = False
        self.active_observer = None

    def get_removable(self):
        parts = psutil.disk_partitions(all=False)
        drives = []
        for p in parts:
            # 'removable' may be in opts on some systems; fallback: check device letters under /dev or drive letters
            try:
                if 'removable' in p.opts.lower() or p.fstype != '':
                    # further filter: typical removable drive letters are single letter like 'E:\\'
                    drives.append(p.device)
            except Exception:
                drives.append(p.device)
        return set(drives)

    def run(self):
        global connected_drives
        connected_drives = self.get_removable()
        self.gui_callback("Monitoring started — waiting for USB activity.")
        while not self.stop_flag:
            try:
                current = self.get_removable()
                inserted = current - connected_drives
                removed = connected_drives - current

                for d in inserted:
                    e = append_log("USB Inserted", d)
                    self.gui_callback(format_entry(e))
                    # start file observer for this drive
                    self.start_observer(d)

                for d in removed:
                    e = append_log("USB Removed", d)
                    self.gui_callback(format_entry(e))
                    # stop observer (if any)
                    self.stop_observer()

                connected_drives = current
                time.sleep(1.5)
            except Exception as ex:
                # do not crash thread on unexpected errors
                self.gui_callback(f"[ERROR] Monitor loop: {ex}")
                time.sleep(2)
        # stopped
        self.stop_observer()
        self.gui_callback("Monitoring stopped.")

    def start_observer(self, drive_path):
        global observer
        try:
            if observer and observer.is_alive():
                # already running; stop and restart to watch new path
                self.stop_observer()
            handler = USBFileHandler(self.gui_callback)
            observer = Observer()
            observer.schedule(handler, drive_path, recursive=True)
            observer.start()
            self.gui_callback(f"File monitoring started on {drive_path}")
            append_log("File Monitoring Started", drive_path)
        except Exception as ex:
            self.gui_callback(f"[ERROR] start_observer: {ex}")

    def stop_observer(self):
        global observer
        try:
            if observer:
                observer.stop()
                observer.join(timeout=2)
                observer = None
                self.gui_callback("File monitoring stopped.")
                append_log("File Monitoring Stopped", "Drive disconnected or observer stopped")
        except Exception as ex:
            self.gui_callback(f"[ERROR] stop_observer: {ex}")

    def stop(self):
        self.stop_flag = True

# -------------------- Helpers for display --------------------
def format_entry(e):
    return f"{e['Timestamp']}  |  {e['Event']}  |  {e['Details']}"

# -------------------- PDF export (summary + timeline chart) --------------------
def export_pdf(gui_callback):
    try:
        if not CSV_LOG.exists():
            messagebox.showwarning("No data", "No CSV log found. Run monitoring first.")
            return
        df = pd.read_csv(CSV_LOG, parse_dates=["Timestamp"])
        # summary: counts by Event
        counts = df["Event"].value_counts().to_dict()
        total_events = len(df)

        # timeline chart: events per minute (or per time-bucket)
        df['Minute'] = df['Timestamp'].dt.floor('T')  # minute resolution
        timeline = df.groupby('Minute').size().reset_index(name='Count')

        # draw chart to PNG
        plt.figure(figsize=(10, 3.5))
        plt.plot(timeline['Minute'], timeline['Count'], marker='o', linewidth=1)
        plt.title('USB Events Timeline (events per minute)')
        plt.xlabel('Time')
        plt.ylabel('Event count')
        plt.grid(True, linestyle='--', alpha=0.5)
        plt.tight_layout()
        plt.savefig(CHART_PNG)
        plt.close()

        # create PDF
        doc = SimpleDocTemplate(str(PDF_REPORT), pagesize=A4)
        story = []

        style_h = ParagraphStyle(name="Heading", fontSize=16, leading=20)
        style_n = ParagraphStyle(name="Normal", fontSize=10, leading=12)

        story.append(Paragraph("USB Activity Footprint Analyzer - Forensic Report", style_h))
        story.append(Spacer(1, 12))

        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style_n))
        story.append(Paragraph(f"Total events recorded: {total_events}", style_n))
        story.append(Spacer(1, 8))

        # add counts table
        table_data = [["Event Type", "Count"]]
        for k, v in counts.items():
            table_data.append([k, str(v)])
        t = Table(table_data, colWidths=[8*cm, 4*cm])
        story.append(t)
        story.append(Spacer(1, 12))

        # embed chart image
        if CHART_PNG.exists():
            img = utils.ImageReader(str(CHART_PNG))
            iw, ih = img.getSize()
            aspect = ih / float(iw)
            img_width = 16 * cm
            img_height = img_width * aspect
            story.append(Image(str(CHART_PNG), width=img_width, height=img_height))
            story.append(Spacer(1, 12))

        # add recent events (last 20)
        story.append(Paragraph("Most recent events (latest 20):", style_n))
        recent = df.sort_values('Timestamp', ascending=False).head(20)
        for _, row in recent.iterrows():
            story.append(Paragraph(f"{row['Timestamp'].strftime('%Y-%m-%d %H:%M:%S')} — {row['Event']} — {row['Details']}", style_n))

        doc.build(story)
        gui_callback(f"PDF report created on Desktop: {PDF_REPORT}")
        messagebox.showinfo("PDF Exported", f"PDF report created on Desktop:\n{PDF_REPORT}")
    except Exception as ex:
        messagebox.showerror("PDF Error", f"Failed to create PDF: {ex}")
        gui_callback(f"[ERROR] export_pdf: {ex}")

# -------------------- GUI App --------------------
class USBAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Activity Footprint Analyzer (PDF Export)")
        self.root.geometry("980x640")
        self.monitor_thread = None

        # header
        hdr = tk.Label(root, text="USB Activity Footprint Analyzer", font=("Segoe UI", 16, "bold"), bg="#2c3e50", fg="white", pady=8)
        hdr.pack(fill="x")

        # buttons
        frm = tk.Frame(root)
        frm.pack(pady=8)
        tk.Button(frm, text="Start Monitoring", width=16, command=self.start_monitor).grid(row=0, column=0, padx=6)
        tk.Button(frm, text="Stop Monitoring", width=16, command=self.stop_monitor).grid(row=0, column=1, padx=6)
        tk.Button(frm, text="Export PDF", width=16, command=lambda: threading.Thread(target=export_pdf, args=(self.append_log,), daemon=True).start()).grid(row=0, column=2, padx=6)
        tk.Button(frm, text="Export ZIP (CSV+TXT+PDF+PNG)", width=22, command=zip_report).grid(row=0, column=3, padx=6)
        tk.Button(frm, text="View Saved Logs", width=16, command=self.view_saved_logs).grid(row=0, column=4, padx=6)
        tk.Button(frm, text="Clear Display", width=12, command=self.clear_display).grid(row=0, column=5, padx=6)

        # log area
        self.text = scrolledtext.ScrolledText(root, wrap="word", font=("Consolas", 10), height=28)
        self.text.pack(fill="both", expand=True, padx=8, pady=8)
        self.append_log("Ready. Click 'Start Monitoring' to begin.")

        # status bar
        self.status = tk.Label(root, text="Status: Idle", anchor="w", relief="sunken")
        self.status.pack(fill="x", side="bottom")

    def append_log(self, message):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            # if message already contains timestamp, do not double prepend
            if message.startswith("[") or " - " in message:
                line = message
            else:
                line = f"[{ts}] {message}"
            self.text.insert("end", line + "\n")
            self.text.see("end")
        except Exception:
            pass

    def start_monitor(self):
        global monitoring
        if self.monitor_thread and self.monitor_thread.is_alive():
            messagebox.showinfo("Info", "Monitoring already running.")
            return
        monitoring = True
        self.monitor = USBMonitor(self.append_log)
        self.monitor.start()
        self.append_log("Monitoring started.")
        self.status.config(text="Status: Monitoring active")

    def stop_monitor(self):
        global monitoring
        if hasattr(self, 'monitor') and self.monitor:
            self.monitor.stop()
        monitoring = False
        self.append_log("Monitoring stop requested.")
        self.status.config(text="Status: Stopped")

    def clear_display(self):
        self.text.delete("1.0", "end")

    def view_saved_logs(self):
        if not CSV_LOG.exists():
            messagebox.showwarning("No Logs", "CSV log not found. Run monitoring first.")
            return
        try:
            df = pd.read_csv(CSV_LOG)
            # show in a new window
            win = tk.Toplevel(self.root)
            win.title("Saved USB Activity Log")
            win.geometry("800x500")
            txt = scrolledtext.ScrolledText(win, wrap="word", font=("Consolas", 10))
            txt.pack(fill="both", expand=True)
            for _, r in df.iterrows():
                txt.insert("end", f"{r['Timestamp']}  |  {r['Event']}  |  {r['Details']}\n")
            txt.configure(state="disabled")
        except Exception as ex:
            messagebox.showerror("Error", f"Could not read CSV: {ex}")

# -------------------- Run App --------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = USBAnalyzerGUI(root)
    root.mainloop()
