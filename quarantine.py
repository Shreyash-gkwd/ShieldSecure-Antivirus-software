import os
import json
import shutil
import customtkinter as ctk
from send2trash import send2trash

# Set up GUI
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")



#storing quarantine data in user's home directory
USER_DATA_DIR = os.path.join(os.path.expanduser("~"), "ShieldGuardData")
QUARANTINE_FILE = os.path.join(USER_DATA_DIR, "quarantine.json")
QUARANTINE_FOLDER = os.path.join(USER_DATA_DIR, "quarantine")
THREAT_LOG_FILE = os.path.join(USER_DATA_DIR, "threatlog.json")


# Creating folders if they don't exist
os.makedirs(USER_DATA_DIR, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

# Creating an empty JSON file if it doesn't exist
if not os.path.exists(QUARANTINE_FILE):
    with open(QUARANTINE_FILE, "w") as f:
        json.dump([], f)


class ShieldGuardApp:
    def __init__(self, root,back_callback=None):
        self.root = root
        self.back_callback = back_callback 
        self.root.title("ShieldGuard Antivirus")
        self.root.geometry("800x500")
        self.root.minsize(600, 400)
        self.build_ui()
    
   

        # Header
        self.header = ctk.CTkLabel(root, text="🛡️ ShieldGuard", font=("Arial", 20, "bold"))
        self.header.pack(pady=10)

        # Navigation Buttons
        self.nav_frame = ctk.CTkFrame(root, fg_color="black")
        self.nav_frame.pack(fill="x", padx=10, pady=5)

        self.quarantine_btn = ctk.CTkButton(self.nav_frame, text="Quarantine",fg_color="#A0A0A0", hover_color="#5E5E5E", text_color="black", command=self.show_quarantine)
        self.quarantine_btn.pack(side="left", padx=5)

        # Frame for content (Scrollable)
        self.content_frame = ctk.CTkFrame(root, fg_color="black")
        self.content_frame.pack(expand=True, fill="both")

        
        self.scrollable_frame = None 

        self.show_quarantine()  # Show quarantine first
    
    def build_ui(self):
        """ Builds the UI elements. """
        for widget in self.root.winfo_children():
            widget.destroy()  # Clears the existing UI
        if self.back_callback:
            self.back_button = ctk.CTkButton(self.root, text="⬅️ Back to Home", fg_color="#333", command=self.back_callback)
            self.back_button.pack(pady=10)
        

    def load_json(self, file):
        """Loads JSON data, returns empty list if file is missing or corrupted."""
        if not os.path.exists(file):
            return []
        try:
            with open(file, "r") as f:
                return json.load(f)
        except:
            return []

    def update_json(self, file, data, remove=False):
        """Writes data to a JSON file. If remove=True, removes specific data."""
        current_data = self.load_json(file)

        if remove:
            current_data = [t for t in current_data if t != data]
        else:
            current_data.append(data)

        with open(file, "w") as f:
            json.dump(current_data, f, indent=4)

    def show_quarantine(self):
        """Displays quarantined threats in a scrollable frame."""
        self.clear_frame()
        self.scrollable_frame = ctk.CTkScrollableFrame(self.content_frame, width=750, height=400)
        self.scrollable_frame.pack(expand=True, fill="both", padx=10, pady=5)

        self.display_threats(self.load_json(QUARANTINE_FILE), self.restore_threat, "Restore", "Quarantine",
                             self.move_to_recycle_bin, "Move to Recycle Bin")

    def display_threats(self, threats, action_function, button_text, section_title, secondary_action=None,
                        secondary_text=None):
        """Displays a list of threats with action buttons inside the scrollable frame."""
        title_label = ctk.CTkLabel(self.scrollable_frame, text=section_title, font=("Arial", 18, "bold"))
        title_label.pack(pady=5)

        if not threats:
            empty_label = ctk.CTkLabel(self.scrollable_frame, text=f"No threats in {section_title}.", font=("Arial", 14))
            empty_label.pack(pady=10)
            return

        for threat in threats:
            frame = ctk.CTkFrame(self.scrollable_frame, fg_color="#808080", corner_radius=10)
            frame.pack(fill="x", padx=10, pady=5)

            threat_name = ctk.CTkLabel(frame, text=f"Threat: {threat['file_name']}", font=("Arial", 14, "bold"))
            threat_name.pack(anchor="w", padx=10, pady=2)

            path_label = ctk.CTkLabel(frame, text=f"Path: {threat['original_path']}", font=("Arial", 12))
            path_label.pack(anchor="w", padx=10)

            button_frame = ctk.CTkFrame(frame, fg_color="transparent")
            button_frame.pack(pady=5, padx=10, anchor="e")

            action_button = ctk.CTkButton(button_frame, text=button_text, command=lambda t=threat: action_function(t))
            action_button.pack(side="left", padx=5)

            if secondary_action and secondary_text:
                secondary_button = ctk.CTkButton(button_frame, text=secondary_text, fg_color="red",
                                                 command=lambda t=threat: secondary_action(t))
                secondary_button.pack(side="left", padx=5)

    def restore_threat(self, threat):
        """Restores the threat from Quarantine to its original location."""
        original_path = threat["original_path"]
        quarantined_path = threat["quarantined_path"]

        file_path = threat["quarantined_path"]

        threatlog_data = self.load_json(THREAT_LOG_FILE)
        updated_threatlog = [
                {**item, "quarantined_path": "not in quarantine"}
                if item.get("quarantined_path") == file_path
                else item
                for item in threatlog_data
            ]
        with open(THREAT_LOG_FILE, "w") as f:
                json.dump(updated_threatlog, f, indent=4)

        if os.path.exists(quarantined_path):
            try:
                shutil.move(quarantined_path, original_path)  # Restore file
                self.update_json(QUARANTINE_FILE, threat, remove=True)  # Remove from quarantine.json
            except Exception as e:
                print(f"Error restoring file: {e}")

        self.show_quarantine()  # Refresh UI

    def move_to_recycle_bin(self, threat):
        """Moves threat to Recycle Bin and removes from quarantine.json."""
        file_path = threat["quarantined_path"]

        threatlog_data = self.load_json(THREAT_LOG_FILE)
        updated_threatlog = [
                {**item, "quarantined_path": "not in quarantine"}
                if item.get("quarantined_path") == file_path
                else item
                for item in threatlog_data
            ]
        with open(THREAT_LOG_FILE, "w") as f:
                json.dump(updated_threatlog, f, indent=4)

        if os.path.exists(file_path):
            try:
                send2trash(file_path)  # Move to Windows Recycle Bin
                self.update_json(QUARANTINE_FILE, threat, remove=True)  # Remove from quarantine.json
                ctk.CTkLabel(self.content_frame, text="File moved to Recycle Bin. Please empty the Recycle Bin manually to delete it permanently.",
                             font=("Arial", 14), text_color="yellow").pack(pady=10)
            except Exception as e:
                print(f"Error moving to Recycle Bin: {e}")

        self.show_quarantine()

    def clear_frame(self):
        """Clears the content frame."""
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
def start_quarantine_ui(root, back_callback=None):
    """ Replaces the current UI with the antivirus UI. """
    ShieldGuardApp(root, back_callback) 

if __name__ == "__main__":
    root = ctk.CTk()
    app = ShieldGuardApp(root)
    root.mainloop()
