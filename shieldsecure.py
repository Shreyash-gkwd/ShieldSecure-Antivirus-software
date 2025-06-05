import customtkinter as ctk
import antvirus  
import quarantine
import ThreatLog
class ShieldSecureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ShieldSecure Antivirus")
        self.root.geometry("900x550")
        self.load_dashboard()  

    def load_dashboard(self):
        """ Loads the main Dashboard UI. """
        for widget in self.root.winfo_children():
            widget.destroy()  

        # Top Navigation Bar
        nav_bar = ctk.CTkFrame(self.root, fg_color="#A0A0A0", height=50)
        nav_bar.pack(fill="x")

        nav_title = ctk.CTkLabel(nav_bar, text="\u26E8 ShieldSecure", font=("Arial", 18, "bold"))
        nav_title.pack(side="left", padx=10, pady=5)

        # Main Content Frame
        main_frame = ctk.CTkFrame(self.root, fg_color="#111")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Left Panel (Protection Status)
        left_panel = ctk.CTkFrame(main_frame, width=600, height=350)
        left_panel.pack(side="left", padx=10, pady=10, fill="y")

        ctk.CTkLabel(left_panel, text="Protection Status", font=("Arial", 16, "bold")).pack(anchor="w", padx=10, pady=5)

        def create_status_box(text, subtext, icon="✔"):
            frame = ctk.CTkFrame(left_panel, fg_color="#A0A0A0")
            frame.pack(fill="x", pady=5, padx=10)

            ctk.CTkLabel(frame, text=text, font=("Arial", 14, "bold"), text_color="black").pack(side="left", padx=10, pady=5)
            ctk.CTkLabel(frame, text=icon, font=("Arial", 14, "bold"), text_color="black").pack(side="right", padx=10)
            ctk.CTkLabel(frame, text=subtext, font=("Arial", 12), text_color="black").pack(anchor="w", padx=10)

        create_status_box("Protection: Active", "Your system is ready to be scanned.")
        create_status_box("Threats Detected: 0", "No threats found.", "")
        create_status_box("System Health: Good", "Your system is running optimally.", "❤️")

        # Right Panel 
        right_panel = ctk.CTkFrame(main_frame, width=250, height=350)
        right_panel.pack(side="right", padx=10, pady=10, fill="y")

        ctk.CTkLabel(right_panel, text="Quick Actions", font=("Arial", 14, "bold")).pack(pady=10)

        actions = [
            ("Scan Now", self.open_antivirus),
            ("Threat Logs", self.open_threatlog),
            ("Quarantine", self.open_quarantine),
        ]

        for action, command in actions:
            ctk.CTkButton(right_panel, text=action, fg_color="#A0A0A0", hover_color="#5E5E5E", text_color="black", command=command).pack(fill="x", padx=20, pady=5)

        # Footer
        ctk.CTkLabel(self.root, text="Last Update: 5 minutes ago\nSystem Health: Good", font=("Arial", 12)).pack(side="bottom", pady=5)

    def open_antivirus(self):
        """ Clears the UI and loads the antivirus scanning UI inside the same window. """
        for widget in self.root.winfo_children():
            widget.destroy()  # Clear the window
        antvirus.start_antivirus_ui(self.root, self.load_dashboard) 
        # Load Antivirus UI and allow back navigation

    def open_quarantine(self):
        """ Clears the UI and loads the Quarantine UI inside the same window. """
        for widget in self.root.winfo_children():
            widget.destroy() 
        quarantine.start_quarantine_ui(self.root, self.load_dashboard)  # Load quarantine UI and allow back navigation

    def open_threatlog(self):
        """ Clears the UI and loads the Threatlog UI inside the same window. """
        for widget in self.root.winfo_children():
            widget.destroy()  
        ThreatLog.start_threatlog_ui(self.root, self.load_dashboard)

if __name__ == "__main__":
    root = ctk.CTk()
    app = ShieldSecureApp(root)
    root.mainloop()
