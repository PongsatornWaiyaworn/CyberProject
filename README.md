# Fake Wi-Fi Risk Analyzer (Evil Twin Detector)

ระบบวิเคราะห์ความเสี่ยง Wi-Fi ปลอมจากความผิดปกติของ Access Point  
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
- Linux / Kali Linux (root access required)
- Wi-Fi interface in **monitor mode** (`wlan0mon`)
- `scapy` and `rich`

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

| Argument | Description | Default |
|----------|-------------|---------|
| `-i, --iface` | Monitor-mode interface | auto |
| `-t, --time` | Scan duration (seconds) | 30 |
| `--no-team` | Skip team banner | false |

## How It Works

1. **Scanner** (`scanner.py`) uses `scapy` to capture Beacon frames in real time.
2. **Analyzer** (`analyzer.py`) groups APs by SSID and applies weighted heuristics:
   - SSID Duplicate across multiple BSSIDs → +25
   - Encryption mismatch → +20
   - RSSI anomaly → +15
   - Unknown vendor / locally administered MAC → +15 each
   - Non-standard channel → +10
   - Open network → +10
3. **UI** (`ui.py`) renders the final report with risk levels and detailed flags.

## Build as Standalone Executable

You can build a single-file binary on **Linux / macOS / Windows**. The binary bundles Python + scapy + rich so it runs without installing dependencies on the target machine.

> **Recommendation**: Wi-Fi monitor mode works best on Linux/Kali. Windows and macOS builds are supported but may have limited scanning capability due to OS driver restrictions.

---

### Linux / Kali (Recommended)

```bash
cd /path/to/CyberProject
chmod +x scripts/build.sh
./scripts/build.sh

# Run
sudo ./dist/wifi-risk-analyzer -i wlan0mon -t 30
```

Manual build:
```bash
pip3 install pyinstaller
pyinstaller --onefile --name wifi-risk-analyzer --hidden-import wifi_analyzer.config --hidden-import wifi_analyzer.vendor_db --hidden-import wifi_analyzer.scanner --hidden-import wifi_analyzer.analyzer --hidden-import wifi_analyzer.ui main.py
```

---

### macOS

```bash
cd /path/to/CyberProject
chmod +x scripts/build_macos.sh
./scripts/build_macos.sh

# Run (requires root + monitor mode capable adapter)
sudo ./dist/wifi-risk-analyzer -i en0 -t 30
```

**Note for macOS**: macOS Wi-Fi scanning requires root and a Wi-Fi adapter that supports monitor mode. You may need `libpcap` (`brew install libpcap`).

---

### Windows

Open PowerShell as **Administrator**:

```powershell
cd D:\Cyber\CyberProject
.\scripts\build.ps1

# Run (limited scanning on Windows without special drivers)
.\dist\wifi-risk-analyzer.exe --no-team
```

**Note for Windows**: You must install [Npcap](https://npcap.com/#download) first. Windows Wi-Fi monitor mode is very limited; for full functionality run the tool inside a Kali VM.

---

### Transfer Binary to Another Machine / VM

The produced binary is self-contained (except for `libpcap` / `Npcap` on the target OS). Simply copy and run:

```bash
# Linux / macOS
scp dist/wifi-risk-analyzer kali@vm:/home/kali/
ssh kali@vm "sudo /home/kali/wifi-risk-analyzer -i wlan0mon -t 30"
```

## Project Structure

```
CyberProject/
├── wifi_analyzer/      # Core Python package
│   ├── __init__.py
│   ├── config.py       # Constants, thresholds, weights
│   ├── vendor_db.py    # Embedded OUI vendor lookup
│   ├── scanner.py      # scapy passive Wi-Fi scanner
│   ├── analyzer.py     # Anomaly detection & scoring engine
│   └── ui.py           # Rich CLI output
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