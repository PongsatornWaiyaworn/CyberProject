# Fake Wi-Fi Risk Analyzer (Evil Twin Detector)

### Fake Wi-Fi Risk Analyzer Based on Access Point Anomaly Detection | ระบบวิเคราะห์ความเสี่ยง Wi-Fi ปลอมจากความผิดปกติของ Access Point
Passive Wi-Fi scan, anomaly detection, and risk scoring based on MITRE ATT&CK **T1557.004**.

## Features

- **Passive Scan**: Sniffs 802.11 Beacon frames without connecting to any network.
- **Anomaly Detection**:
  - Multiple BSSIDs sharing the same SSID (Evil Twin indicator)
  - Encryption mismatch within the same SSID
  - Suspiciously strong / weak RSSI
  - Unknown / spoofed vendor OUI
  - Locally administered MAC addresses
  - Non-standard Wi-Fi channels
- **Risk Scoring**: 0–100 scale translated into **Safe**, **Suspicious**, or **High Risk**.
- **Rich CLI**: Color-coded tables and summary statistics.

## Requirements

- Python 3.9+
- `rich`
- **Linux / Kali**: `scapy` + Wi-Fi interface in **monitor mode** (`wlan0mon`)
- **Windows**: No extra drivers needed (uses `netsh`); install [Npcap](https://npcap.com/#download) if you want scapy support
- **macOS**: No extra drivers needed (uses `airport` utility)

## Installation (Kali Linux)

```bash
# 1. Enable monitor mode on your wireless interface
sudo airmon-ng start wlan0

# 2. Clone / copy the project
# cd /path/to/CyberProject

# 3. Install Python dependencies
sudo pip3 install -r requirements.txt

# 4. Run the analyzer
sudo python3 main.py -i wlan0mon -t 30
```

## Usage

```bash
sudo python3 main.py -i <iface> -t <seconds>
```

| Argument      | Description                               | Default |
| ------------- | ----------------------------------------- | ------- |
| `-i, --iface` | Monitor-mode interface                    | auto    |
| `-t, --time`  | Scan duration (seconds)                   | 30      |
| `--no-team`   | Skip team banner                          | false   |
| `--demo`      | Use synthetic mock data (no Wi-Fi needed) | false   |
| `--gui`       | Launch tkinter GUI mode                   | false   |

## How It Works

1. **Scanner** (`scanner.py`) auto-detects the OS and picks the best backend:
   - **Linux / Kali**: `scapy` passive monitor-mode scan (best quality, requires root)
   - **Windows**: `netsh wlan show networks` (no monitor mode needed)
   - **macOS**: `airport -s` utility (no monitor mode needed)
   - **`--demo`**: Synthetic mock data for testing without Wi-Fi hardware
2. **Analyzer** (`analyzer.py`) groups APs by SSID and applies weighted heuristics:
   - SSID Duplicate across multiple BSSIDs → +25
   - Encryption mismatch → +20
   - RSSI anomaly → +15
   - Unknown vendor / locally administered MAC → +15 each
   - Non-standard channel → +10
   - Open network → +10
3. **UI** (`ui.py`) renders the final report with risk levels and detailed flags.

## Demo Mode (Test without Wi-Fi)

Run anywhere without Wi-Fi adapter or monitor mode:

```bash
# Linux / macOS
python3 main.py --demo

# Windows
python main.py --demo
```

This generates synthetic APs including Evil Twin, open networks, suspicious signals, and unknown vendors so you can test the analyzer and UI immediately.

## GUI Mode (Tkinter)

Launch a desktop GUI instead of the terminal UI:

```bash
# Linux / macOS / Windows
python main.py --gui
```

The GUI provides:

- Input fields for **Interface** and **Duration**
- **Demo mode** checkbox
- **Start / Stop** scan buttons
- Results table with color-coded risk levels (red = High Risk, yellow = Suspicious, green = Safe)
- Summary bar showing totals

## Build as Standalone Executable

You can build a single-file binary on **Linux / macOS / Windows**. The binary bundles Python + scapy + rich so it runs without installing dependencies on the target machine.

> **Recommendation**: Wi-Fi monitor mode works best on Linux/Kali. Windows and macOS builds are supported but may have limited scanning capability due to OS driver restrictions.

> **Pre-built Binaries**: This project uses GitHub Actions to automatically build executables for Windows, macOS, and Linux. You can download the latest builds from the **Actions** tab in this repository.

---

### Linux / Kali (Recommended)

```bash
cd /path/to/CyberProject
chmod +x scripts/build.sh
./scripts/build.sh

# Run GUI version
sudo ./dist/wifi-risk-analyzer-gui

# Or run CLI version
sudo ./dist/wifi-risk-analyzer -i wlan0mon -t 30
```

Manual build:

```bash
pip3 install pyinstaller
pyinstaller --onefile --windowed --name wifi-risk-analyzer-gui --hidden-import wifi_analyzer.config --hidden-import wifi_analyzer.vendor_db --hidden-import wifi_analyzer.scanner --hidden-import wifi_analyzer.analyzer --hidden-import wifi_analyzer.ui --hidden-import wifi_analyzer.gui wifi_analyzer/gui.py
```

---

### macOS

```bash
cd /path/to/CyberProject
chmod +x scripts/build_macos.sh
./scripts/build_macos.sh

# Run GUI version (requires root + monitor mode capable adapter)
sudo ./dist/wifi-risk-analyzer-gui

# Or run CLI version
sudo ./dist/wifi-risk-analyzer -i en0 -t 30
```

**Note for macOS**: The `airport` utility works without monitor mode. If scapy fails, you may need `libpcap` (`brew install libpcap`).

---

### Windows

Open PowerShell as **Administrator**:

```powershell
cd D:\Cyber\CyberProject
.\scripts\build.ps1

# Run the GUI application
.\dist\wifi-risk-analyzer-gui.exe

# Or run the CLI application with live scan via netsh
.\dist\wifi-risk-analyzer.exe --no-team

# Or run CLI in demo mode to test without Wi-Fi scan
.\dist\wifi-risk-analyzer.exe --demo --no-team
```

**Note for Windows**: `netsh wlan show networks` works out of the box. Install [Npcap](https://npcap.com/#download) only if you want scapy-level packet capture. For full passive monitor mode, use Kali VM.

---

### Transfer Binary to Another Machine / VM

The produced binary is self-contained (except for `libpcap` / `Npcap` on the target OS). Simply copy and run:

```bash
# Linux / macOS
scp dist/wifi-risk-analyzer-gui dist/wifi-risk-analyzer kali@vm:/home/kali/
ssh kali@vm "sudo /home/kali/wifi-risk-analyzer-gui"
# Or: ssh kali@vm "sudo /home/kali/wifi-risk-analyzer -i wlan0mon -t 30"
```

## Project Structure

```
CyberProject/
├── wifi_analyzer/      # Core Python package
│   ├── __init__.py
│   ├── config.py       # Constants, thresholds, weights
│   ├── vendor_db.py    # Embedded OUI vendor lookup
│   ├── scanner.py      # Cross-platform Wi-Fi scanner
│   ├── analyzer.py     # Anomaly detection & scoring engine
│   ├── ui.py           # Rich CLI output
│   └── gui.py          # Tkinter desktop GUI
├── scripts/            # Build scripts
│   ├── build.sh        # Linux / Kali build (PyInstaller)
│   ├── build_macos.sh  # macOS build (PyInstaller)
│   └── build.ps1       # Windows build (PyInstaller)
├── main.py             # Entry point
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

## Team Members

- 65090500457 นาย สันติจิต คำหนัก
- 66090500405 นาย ณัฏฐชนม์ ชัยมะณี
- 66090500409 นางสาว ต้นหยก บูรณวานิช
- 66090500411 นาย ธนวัฒน์ มะปะเท
- 66090500413 นาย พงศธร ไวยวรณ์
- 66090500435 นาย นฤพนธ์ ฉายสุวรรณคีรี

## References

- MITRE ATT&CK T1557.004 – Adversary-in-the-Middle: Evil Twin  
  https://attack.mitre.org/techniques/T1557/004/

## Disclaimer

This tool is intended for **educational and authorized security assessment purposes only**.  
Always obtain proper permission before scanning wireless networks you do not own or manage.
