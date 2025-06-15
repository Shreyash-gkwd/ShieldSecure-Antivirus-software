
# 🛡️ ShieldSecure Antivirus Software

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)

![Platform](https://img.shields.io/badge/Platform-Windows-informational?logo=windows)

![Status](https://img.shields.io/badge/Status-Active-brightgreen)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)



🖥️ A Python-based desktop antivirus that performs real-time scanning, threat logging, and quarantine management using a clean GUI built with `customtkinter`.




## 🧩 Features


- ⚡ Quick Scan & Full Scan options  
- 🔒 Real-Time Protection  
- 🧼 Quarantine and Restore functionality  
- 📝 JSON-based Threat Logs  
- 🎨 User-friendly Python GUI with `customtkinter`  
- 🧠 Uses extension and hash-based threat detection


## 📸 Screenshots

<p float="left">
  <img src="https://via.placeholder.com/400x200?text=Dashboard+GUI" alt="Dashboard GUI" width="400"/>
  <img src="https://via.placeholder.com/400x200?text=Scan+Results" alt="Scan Results" width="400"/>
</p>


---
## 🚀 Getting Started

- ### 🧾 Clone the Repository  
    ```bash
    git clone https://github.com/yourusername/shieldguard-antivirus.git
    cd shieldguard-antivirus
    ```

## 📦 Libraries Installation

To install the required libraries for running this project, use the following command:

```bash
pip install python-dotenv customtkinter
```

### 🖥️ Launch the Antivirus Dashboard

To start the ShieldGuard Antivirus application with the GUI, run:

```bash
python shieldsecure.py
```
This will open the main dashboard built with `customtkinter`.


## 📦 Built With

- [Python 3.x](https://www.python.org/) – Core language used
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) – Modern Python UI framework
- Standard Libraries:
  - `os`
  - `hashlib`
  - `json`
  - `datetime`
  - `threading`
  - `tkinter`


## 🧩 API Reference

### 🔍 VirusTotal Public API

This project integrates the [VirusTotal Public API](https://www.virustotal.com/gui/home/search) to enhance malware detection capabilities by scanning file hashes against a large virus signature database.

To use the API:

###### 1. Create a free account at [virustotal.com](https://www.virustotal.com).
###### 2. Go to your profile > API key.
###### 3. Copy the key and store it in a `.env` file as:
   ```env
   API_KEY=your_api_key_here
   ```
###### 4. The app will automatically load this key using `python-dotenv`.
> ⚠️ Note: VirusTotal has rate limits for free users (4 requests per minute).


## 🧪 Future Improvements

- 🧠 AI-based threat detection (ML integration)
- 🌐 Cloud upload of logs
- 📊 Detailed scanning analytics dashboard
- 🗃️ Real-time file system hooks for faster detection

---
## 🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.
## 📜 License

This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html) – see the [LICENSE](LICENSE) file for details.
