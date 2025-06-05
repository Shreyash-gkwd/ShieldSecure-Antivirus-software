from dotenv import load_dotenv
import os
import hashlib
import threading
import time
import json
import shutil
import customtkinter as ctk
from tkinter import filedialog
from datetime import datetime

load_dotenv()
import requests

import sys
if sys.stdout is not None:
    sys.stdout.reconfigure(encoding='utf-8')

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class AntivirusApp:
    def __init__(self, root, back_callback=None):
        self.root = root
        self.back_callback = back_callback  
        self.root.title("ShieldGuard Antivirus")
        self.root.geometry("800x500")  
        self.root.minsize(600, 400)

        self.scanning = False
        self.paused = False
        self.files_scanned = 0
        self.threats_found = 0
        self.scan_path = None  
        self.scan_thread = None  

        self.build_ui()

    def build_ui(self):
        """ Builds the UI elements. """
        for widget in self.root.winfo_children():
            widget.destroy()  # Clears the existing UI

        self.label = ctk.CTkLabel(self.root, text="🛡️ ShieldGuard Antivirus", font=("Arial", 22, "bold"))
        self.label.pack(pady=10)

        self.scan_status = ctk.CTkLabel(self.root, text="Status: Idle", font=("Arial", 14))
        self.scan_status.pack()

        self.file_display = ctk.CTkTextbox(self.root, height=200, width=600, fg_color="#1a1a1a", text_color="white")
        self.file_display.pack(pady=10, expand=True, fill='both')

        self.progress_bar = ctk.CTkProgressBar(self.root, height=10)
        self.progress_bar.pack(pady=5, fill='x', padx=20)
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(self.root, text="0%", font=("Arial", 12))
        self.progress_label.pack()

        self.button_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.button_frame.pack(pady=5, fill='x')

        self.select_folder_button = ctk.CTkButton(self.button_frame, text="📂 Select Folder",fg_color="#A0A0A0", hover_color="#5E5E5E", text_color="black", command=self.select_folder)
        self.select_folder_button.pack(side='left', expand=True, padx=5, pady=5)

        self.scan_button = ctk.CTkButton(self.button_frame, text="🚀 Start Scan", fg_color="#4CAF50",hover_color="#2E7D32", text_color="black", command=self.start_scan)
        self.scan_button.pack(side='left', expand=True, padx=5, pady=5)

        self.pause_button = ctk.CTkButton(self.button_frame, text="⏸️ Pause",fg_color="#A0A0A0", hover_color="#5E5E5E", text_color="black", command=self.pause_scan)
        self.pause_button.pack(side='left', expand=True, padx=5, pady=5)

        self.stop_button = ctk.CTkButton(self.button_frame, text="🛑 Stop Scan", fg_color="#D32F2F",hover_color="#B71C1C", text_color="white", command=self.stop_scan)
        self.stop_button.pack(side='left', expand=True, padx=5, pady=5)

        self.result_label = ctk.CTkLabel(self.root, text="Files Scanned: 0 | Threats Found: 0", font=("Arial", 12))
        self.result_label.pack(pady=10)

        if self.back_callback:
            self.back_button = ctk.CTkButton(self.root, text="⬅️ Back to Home", fg_color="#333", command=self.back_callback)
            self.back_button.pack(pady=10)

    def select_folder(self):
        self.scan_path = filedialog.askdirectory() or None
        self.scan_status.configure(text=f"Selected Folder: {self.scan_path}" if self.scan_path else "No folder selected")

    def get_all_files(self, path):
        for root, _, files in os.walk(path):
            for file in files:
                yield os.path.join(root, file)

    def scan_files(self):
        self.scan_status.configure(text="🔄 Scanning...")
        self.files_scanned = 0
        self.threats_found = 0
        total_files = sum(1 for _ in self.get_all_files(self.scan_path))  

        for file_path in self.get_all_files(self.scan_path):
            if not self.scanning:
                break
            if self.paused:
                time.sleep(0.5)
                continue

            self.files_scanned += 1
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.file_display.insert(ctk.END, f"[{timestamp}] Scanning: {file_path}\n")
            self.file_display.see(ctk.END)
            self.scan_status.configure(text=f"Scanning: {os.path.basename(file_path)}")

            if self.is_malicious(file_path):
                if self.quarantine_file(file_path):  
                    self.threats_found += 1

            self.result_label.configure(text=f"Files Scanned: {self.files_scanned} | Threats Found: {self.threats_found}")

            progress = self.files_scanned / max(total_files, 1)
            self.progress_bar.set(progress)
            self.progress_label.configure(text=f"{int(progress * 100)}%")

            time.sleep(0.01)
            self.root.update_idletasks()

        self.scan_status.configure(text="✅ Scan Complete")
        self.progress_label.configure(text="100%")
        self.scanning = False

    def is_malicious(self, file_path):
        known_hashes = {"d41d8cd98f00b204e9800998ecf8427e","44d88612fea8a8f36de82e1278abb02f","e7e5fa40569514ec442bbdf755d89c2f"}  
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            return file_hash in known_hashes
        except:
            return False

    def scan_with_virustotal(self, file_path):
        """ Scans a file using VirusTotal API and returns a simplified report. """
        
        api_key = os.getenv("API_KEY")
        url = "https://www.virustotal.com/api/v3/files/"
        
        # Getting the file hash MD5
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return None

        headers = {
            "x-apikey": api_key
        }
        
        response = requests.get(url + file_hash, headers=headers)

        if response.status_code == 200:
            report = response.json()

            # Extract only the important fields from the report
            if 'data' in report:
                data = report['data']

                simplified_report = {
                    "id": data.get("id"),
                    "type": data.get("type"),
                    "sha256": data.get("attributes", {}).get("sha256"),
                    "last_analysis_date": data.get("attributes", {}).get("last_analysis_date"),
                    "last_analysis_stats": data.get("attributes", {}).get("last_analysis_stats", {}),
                    "names": data.get("attributes", {}).get("names", []),
                    "known_distributors": data.get("attributes", {}).get("known_distributors", {}).get("distributors", []),
                    "filecondis": data.get("attributes", {}).get("filecondis", {}),
                    "size": data.get("attributes", {}).get("size")
                }

                return simplified_report
            else:
                print("Error: No data found in the report.")
                return None
        else:
            print(f"Error: Could not fetch report for {file_path}")
            return None

    def quarantine_file(self, file_path):
        
        file_name = os.path.basename(file_path)

        # safe location for quarantine.json
        user_data_dir = os.path.join(os.path.expanduser("~"), "ShieldGuardData")
        os.makedirs(user_data_dir, exist_ok=True)
        quarantine_json_path = os.path.join(user_data_dir, "quarantine.json")
        threatlog_json_path = os.path.join(user_data_dir, "threatlog.json")
        quarantine_folder= os.path.join(user_data_dir, "quarantine")
        os.makedirs(quarantine_folder, exist_ok=True)
        
        new_path=os.path.join(quarantine_folder,file_name)
        # Getting VirusTotal report
        virus_report = self.scan_with_virustotal(file_path)  # Get VirusTotal scan report

        # Reading existing data if available
        quarantine_data = []
        if os.path.exists(quarantine_json_path):
            try:
                with open(quarantine_json_path, "r") as f:
                    quarantine_data = json.load(f)
            except json.JSONDecodeError:
                print("⚠️ Corrupt quarantine.json detected. Resetting file.")

        # Appending the threat log with VirusTotal report
        threat_data = []
        if os.path.exists(threatlog_json_path):
            try:
                with open(threatlog_json_path, "r") as f:
                    threat_data = json.load(f)
            except json.JSONDecodeError:
                print("⚠️ Corrupt threatlog.json detected. Resetting file.")

        # Adding the VirusTotal report (if available)
        if virus_report:
            threat_data.append({
                "file_name": file_name,
                "original_path": file_path,
                "quarantined_path": new_path,
                "found_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "threat_report": virus_report  
            })
        else:
            # If no report found, append basic info
            threat_data.append({
                "file_name": file_name,
                "original_path": file_path,
                "quarantined_path": new_path,
                "found_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "threat_report": "No VirusTotal report available"
            })

        with open(threatlog_json_path, "w") as f:
            json.dump(threat_data, f, indent=4)
        
        #moving the file
        try:
            shutil.move(file_path, new_path)  
        except Exception as e:
            print(f"❌ Failed to move {file_name} to quarantine: {e}")
            return False  
        
        # Add new record
        quarantine_data.append({
            "file_name": file_name,
            "original_path": file_path,
            "quarantined_path": new_path
        })

        # Write updated data
        with open(quarantine_json_path, "w") as f:
            json.dump(quarantine_data, f, indent=4)

        

        print(f"⚠️ {file_name} moved to quarantine!")
        return True 
     

    def start_scan(self):
        if not self.scan_path:
            self.scan_status.configure(text="⚠️ No folder selected!")
            return

        if not self.scanning:
            self.scanning = True
            self.paused = False
            self.file_display.delete("1.0", ctk.END)
            self.progress_bar.set(0)
            self.progress_label.configure(text="0%")

            self.scan_thread = threading.Thread(target=self.scan_files, daemon=True)
            self.scan_thread.start()

    def pause_scan(self):
        if self.scanning:
            self.paused = not self.paused
            self.scan_status.configure(text="⏸️ Paused" if self.paused else "🔄 Scanning...")

    def stop_scan(self):
        if self.scanning:
            self.scanning = False
            self.scan_status.configure(text="❌ Scan Stopped")
            self.progress_bar.set(0)
            self.progress_label.configure(text="0%")
            self.file_display.insert(ctk.END, "\n❌ Scan Stopped\n")
            self.file_display.see(ctk.END)

def start_antivirus_ui(root, back_callback=None):
    """ Replaces the current UI with the antivirus UI. """
    AntivirusApp(root, back_callback)  

if __name__ == "__main__":
    root = ctk.CTk()
    app = AntivirusApp(root)
    root.mainloop()
