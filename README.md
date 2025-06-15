
# 🛡️ ShieldSecure Antivirus Software

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)

![Platform](https://img.shields.io/badge/Platform-Windows-informational?logo=windows)

![Status](https://img.shields.io/badge/Status-Active-brightgreen)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)



🖥️ A Python-based desktop antivirus that performs real-time scanning, threat logging, and quarantine management using a clean GUI built with `customtkinter`.




## 🧩 Features


- ⚡ Quick Scan & Full Scan options   
- 🧼 Quarantine and Restore functionality  
- 📝 JSON-based Threat Logs  
- 🎨 User-friendly Python GUI with `customtkinter`  
- 🧠 Uses extension and hash-based threat detection

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

## 🧪 Detection Capabilities

This antivirus tool is designed for demonstration and educational purposes. It detects:

- 🗂️ **Empty files** (0-byte) as suspicious.
- 💣 **EICAR Standard Test File** — a safe test string used to simulate virus detection.

To test with Empty File:

1. Open **Notepad** (or any text editor).
2. Without typing anything, click **File** → **Save As**.
3. Save the file with any name (e.g., `empty.txt`).
4. Run the antivirus scan — the tool should flag this file as suspicious due to its empty content.

>⚠️ This is a basic test used to simulate scanning behavior. Empty files are treated as suspicious for demonstration purposes.

To test EICAR detection:

1. Open **Notepad**.
2. Paste the following line exactly:

    ```
    X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
    ```

3. Save it as `testvirus.txt`.
4. Run the antivirus scan — the tool should flag this file as suspicious.

> 🛡️ This test file is **not harmful** and is widely used to verify antivirus functionality without risk.


## 📸  ShieldSecure GUI Screenshots

<table>
  <tr>
    <td align="center">
      <img src="https://github.com/user-attachments/assets/7a2b39a0-b5f5-4d80-a2b7-ab8d15bcbb76" width="400"/><br/>
      <strong>GUI Dashboard</strong>
    </td>
    <td align="center">
      <img src="https://github.com/user-attachments/assets/23cb6a08-ca8d-4763-b544-37a9ace9dcd7" width="400"/><br/>
      <strong>Scan Results</strong>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/user-attachments/assets/a343df42-1250-4fc2-b547-f437d6cdc5a4" width="400"/><br/>
      <strong>Quarantine Section</strong>
    </td>
    <td align="center">
      <img src="https://github.com/user-attachments/assets/4f465f42-4d62-421d-9294-1f7e3b66c68e" width="400"/><br/>
      <strong>Threat Logs</strong>
    </td>
  </tr>
  <tr>
    <td align="center" colspan="2">
      <img src="https://github.com/user-attachments/assets/2825db46-f823-4824-8e2f-c21263770a22" width="400"/><br/>
      <strong>Threat Report</strong>
    </td>
  </tr>
</table>


---



## 🧩 API Reference

### 🔍 VirusTotal Public API

This project integrates the [VirusTotal Public API](https://www.virustotal.com/gui/home/search) to enhance malware detection capabilities by scanning file hashes against a large virus signature database.

To use the API:

1. Create a free account at [virustotal.com](https://www.virustotal.com).
2. Go to your profile > API key.
3. Copy the key and store it in a `.env` file as:
   ```env
   API_KEY=your_api_key_here
   ```
4. The app will automatically load this key using `python-dotenv`.
> ⚠️ Note: VirusTotal has rate limits for free users (4 requests per minute).


## 🧪 Future Improvements

- 🧠 AI-based threat detection (ML integration)
- 🌐 Cloud upload of logs
- 📊 Detailed scanning analytics dashboard
- 🗃️ Real-time file system hooks for faster detection


## 🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.
## 📜 License

This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html) – see the [LICENSE](LICENSE) file for details.
