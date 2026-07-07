import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
from watchdog.observers import Observer
from fim_backend import SecurityMonitorHandler

class FIMApplication(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FIM & Anti-Ransomware Monitor")
        self.geometry("680x480")
        self.observer = None
        self.handler = None
        self.create_widgets()

    def create_widgets(self):
        # Path Selection Module - Using ttk to safely handle padding configuration options
        path_frame = ttk.LabelFrame(self, text=" Configuration Target ", padding=10)
        path_frame.pack(fill="x", padx=15, pady=10)

        self.path_var = tk.StringVar(value="No directory chosen...")
        ttk.Label(path_frame, textvariable=self.path_var, foreground="gray", anchor="w").pack(side="left", fill="x", expand=True, padx=5)
        
        self.browse_btn = ttk.Button(path_frame, text="Select Folder", command=self.browse_folder)
        self.browse_btn.pack(side="right", padx=5)

        # Control Panel Utilities
        control_frame = ttk.Frame(self, padding=5)
        control_frame.pack(fill="x", padx=15)

        # Base tk.Button is retained exclusively here to handle background accent color rendering
        self.start_btn = tk.Button(control_frame, text="Start Real-Time Guard", state="disabled", bg="#2ecc71", fg="white", command=self.start_monitoring)
        self.start_btn.pack(side="left", fill="x", expand=True, padx=5)

        self.stop_btn = tk.Button(control_frame, text="Stop Guard", state="disabled", bg="#e74c3c", fg="white", command=self.stop_monitoring)
        self.stop_btn.pack(side="right", fill="x", expand=True, padx=5)

        # Live Security Audit Logs Frame
        log_frame = ttk.LabelFrame(self, text=" Live Security Audit Log Updates ", padding=10)
        log_frame.pack(fill="both", expand=True, padx=15, pady=15)

        self.log_tree = ttk.Treeview(log_frame, columns=("Timestamp", "Action", "Description"), show="headings")
        self.log_tree.heading("Timestamp", text="Timestamp")
        self.log_tree.heading("Action", text="Security Flag")
        self.log_tree.heading("Description", text="Event Details")
        
        self.log_tree.column("Timestamp", width=130, stretch=False)
        self.log_tree.column("Action", width=100, stretch=False)
        self.log_tree.column("Description", stretch=True)
        
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=scrollbar.set)
        
        self.log_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def browse_folder(self):
        chosen_dir = filedialog.askdirectory()
        if chosen_dir:
            self.path_var.set(chosen_dir)
            self.start_btn.config(state="normal")

    def append_log_ui(self, flag, detail):
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.after(0, lambda: self.log_tree.insert("", 0, values=(timestamp, flag, detail)))

    def trigger_incident_ui_alert(self, anomaly_reason, specific_info):
        """Pops a critical warning modal dialog and completely resets the visual button states."""
        # Step 1: Force the UI components to visually reset immediately
        def reset_ui_elements():
            self.stop_monitoring()  # Destroys the observer thread cleanly
            self.start_btn.config(state="normal")
            self.browse_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            
            # Show the critical modal box to the user
            messagebox.showerror(
                "CRITICAL CYBERSECURITY ALERT", 
                f"POTENTIAL RANSOMWARE ANOMALY INTERCEPTED!\n\n"
                f"Indicator Triggered: {anomaly_reason}\n"
                f"Target Signature Vector: {specific_info}\n\n"
                f"Action Enacted: System isolated. Re-arm the guard manually to continue tracking."
            )
            
        # Run safely inside the main Tkinter UI execution sequence
        self.after(0, reset_ui_elements)

    def start_monitoring(self):
        target = self.path_var.get()
        if not os.path.exists(target): return
            
        self.handler = SecurityMonitorHandler(target, self.trigger_incident_ui_alert, self.append_log_ui)
        self.observer = Observer()
        self.observer.schedule(self.handler, target, recursive=True)
        self.observer.start()
        
        self.start_btn.config(state="disabled")
        self.browse_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.append_log_ui("SYSTEM", f"Cryptographic baseline initialized. Guarding: {target}")

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        self.start_btn.config(state="normal")
        self.browse_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.append_log_ui("SYSTEM", "Security monitoring stopped down cleanly.")

if __name__ == "__main__":
    app = FIMApplication()
    app.protocol("WM_DELETE_WINDOW", lambda: [app.stop_monitoring(), app.destroy()])
    app.mainloop()