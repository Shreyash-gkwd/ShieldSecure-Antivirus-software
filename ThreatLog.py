import os
import json
import customtkinter as ctk
import time
# Set up GUI
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# Paths
USER_DATA_DIR = os.path.join(os.path.expanduser("~"), "ShieldGuardData")
THREAT_LOG_FILE = os.path.join(USER_DATA_DIR, "threatlog.json")

# Ensure directory and log file exist
os.makedirs(USER_DATA_DIR, exist_ok=True)
if not os.path.exists(THREAT_LOG_FILE):
    with open(THREAT_LOG_FILE, "w") as f:
        json.dump([], f)

class ThreatLogApp:
    def __init__(self, root, back_callback=None):
        self.root = root
        self.back_callback = back_callback
        self.root.title("ShieldGuard Antivirus - Threat Logs")
        self.root.geometry("800x500")
        self.root.minsize(600, 400)
        self.build_ui()

        self.header = ctk.CTkLabel(root, text="🧪 Threat Logs", font=("Arial", 20, "bold"))
        self.header.pack(pady=10)

        self.nav_frame = ctk.CTkFrame(root, fg_color="black")
        self.nav_frame.pack(fill="x", padx=10, pady=5)

        self.threat_log_btn = ctk.CTkButton(self.nav_frame, text="Threat Logs", fg_color="#A0A0A0", hover_color="#5E5E5E", text_color="black")
        self.threat_log_btn.pack(side="left", padx=5)

        self.content_frame = ctk.CTkFrame(root, fg_color="black")
        self.content_frame.pack(expand=True, fill="both")

        self.scrollable_frame = None
        self.show_threat_logs()

    def build_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()
        if self.back_callback:
            self.back_button = ctk.CTkButton(self.root, text="⬅️ Back to Home", fg_color="#333", command=self.back_callback)
            self.back_button.pack(pady=10)

    def load_json(self, file):
        if not os.path.exists(file):
            return []
        try:
            with open(file, "r") as f:
                return json.load(f)
        except:
            return []

    def show_threat_logs(self):
        self.clear_frame()
        self.scrollable_frame = ctk.CTkScrollableFrame(self.content_frame, width=750, height=400)
        self.scrollable_frame.pack(expand=True, fill="both", padx=10, pady=5)

        self.display_threats(self.load_json(THREAT_LOG_FILE))

    def display_threats(self, threats):
        title_label = ctk.CTkLabel(self.scrollable_frame, text="Threat Logs", font=("Arial", 18, "bold"))
        title_label.pack(pady=5)

        if not threats:
            empty_label = ctk.CTkLabel(self.scrollable_frame, text="No threats found in logs.", font=("Arial", 14))
            empty_label.pack(pady=10)
            return

        for threat in threats:
            frame = ctk.CTkFrame(self.scrollable_frame, fg_color="#171616", corner_radius=10)
            frame.pack(fill="x", padx=10, pady=5)

            name = threat.get("file_name", "Unknown")
            path = threat.get("original_path", "Unknown")
            quarantined_path = threat.get("quarantined_path", "Unknown")
            found_time = threat.get("found_time", "Unknown")
            threat_report = threat.get("threat_report", "No threat report available.")

            ctk.CTkLabel(frame, text=f"Threat: {name}", font=("Arial", 14, "bold")).pack(anchor="w", padx=10, pady=2)
            ctk.CTkLabel(frame, text=f"Original Path: {path}", font=("Arial", 12)).pack(anchor="w", padx=10)
            ctk.CTkLabel(frame, text=f"Quarantined Path: {quarantined_path}", font=("Arial", 12)).pack(anchor="w", padx=10)
            ctk.CTkLabel(frame, text=f"Found Date & Time: {found_time}", font=("Arial", 12)).pack(anchor="w", padx=10)

            button_frame = ctk.CTkFrame(frame, fg_color="transparent")
            button_frame.pack(pady=5, padx=10, anchor="e")

            report_button = ctk.CTkButton(button_frame, text="View Report", command=lambda t=threat: self.view_report(t))
            report_button.pack(side="left", padx=5)

    def view_report(self, threat):
        """Opens a popup with the threat report info."""
        report = threat.get("threat_report", {})

        # Extract and format the data
        threat_id = report.get("id", "Unknown")
        sha256 = report.get("sha256", "Unknown")
        last_analysis_date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(report.get("last_analysis_date", 0)))
        last_analysis_stats = report.get("last_analysis_stats", {})
        names = "\n  - " + "\n  - ".join(report.get("names", [])) if report.get("names") else "  None"
        known_distributors = "\n  - " + "\n  - ".join(report.get("known_distributors", [])) if report.get("known_distributors") else "  None"
        file_conditions = report.get("filecondis", {})

        # Build a beautified report string
        report_text = f"""
    ====================[ Threat Summary ]====================

    🆔  Threat ID         : {threat_id}
    🔒 SHA256            : {sha256}
    🕒 Last Analysis     : {last_analysis_date}

    ==================[ Analysis Statistics ]==================

    🔴 Malicious        : {last_analysis_stats.get("malicious", 0)}
    🟠 Suspicious       : {last_analysis_stats.get("suspicious", 0)}
    🟢 Undetected       : {last_analysis_stats.get("undetected", 0)}
    ⚪ Harmless         : {last_analysis_stats.get("harmless", 0)}
    ⏱️ Timeout          : {last_analysis_stats.get("timeout", 0)}
    ⏳ Confirmed Timeout: {last_analysis_stats.get("confirmed-timeout", 0)}
    ❌ Failure          : {last_analysis_stats.get("failure", 0)}
    ❓ Unsupported Type : {last_analysis_stats.get("type-unsupported", 0)}

    ==================[ Associated Names ]==================

    {names}

    =================[ Known Distributors ]=================

    {known_distributors}

    ===================[ File Conditions ]==================

    🔗 dhash    : {file_conditions.get("dhash", "Unknown")}
    🧬 raw_md5  : {file_conditions.get("raw_md5", "Unknown")}
    """

        # Create the popup window
        popup = ctk.CTkToplevel(self.root)
        popup.title("Threat Report")
        popup.geometry("700x500")

        popup.lift()
        popup.attributes('-topmost', True)
        popup.after(100, lambda: popup.attributes('-topmost', False))  # Restore normal stacking after 100ms
        
        ctk.CTkLabel(popup, text="🧾 Threat Report", font=("Arial", 18, "bold")).pack(pady=10)

        textbox = ctk.CTkTextbox(popup, wrap="word", font=("Consolas", 12))
        textbox.insert("1.0", report_text)
        textbox.configure(state="disabled")
        textbox.pack(expand=True, fill="both", padx=10, pady=10)


    def clear_frame(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

def start_threatlog_ui(root, back_callback=None):
    ThreatLogApp(root, back_callback)

if __name__ == "__main__":
    root = ctk.CTk()
    app = ThreatLogApp(root)
    root.mainloop()
