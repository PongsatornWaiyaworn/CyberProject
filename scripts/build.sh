#!/bin/bash
# Build script for Kali Linux / Debian-based systems
# Creates a standalone executable using PyInstaller

set -e

echo "[*] Fake Wi-Fi Risk Analyzer - Build Script"
echo "[*] Target OS: $(uname -a)"

# Check if running as root (required for runtime, but build can be user)
if [ "$EUID" -ne 0 ]; then
    echo "[!] Warning: This tool requires root to run. Build can proceed without root."
fi

# Install dependencies
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

# Install PyInstaller if not present
if ! python3 -m pip show pyinstaller &> /dev/null; then
    echo "[*] Installing PyInstaller..."
    pip3 install pyinstaller
fi

# Build single executable
echo "[*] Building GUI executable with PyInstaller..."
python3 -m PyInstaller \
    --onefile \
    --windowed \
    --name wifi-risk-analyzer-gui \
    --hidden-import wifi_analyzer.config \
    --hidden-import wifi_analyzer.vendor_db \
    --hidden-import wifi_analyzer.scanner \
    --hidden-import wifi_analyzer.analyzer \
    --hidden-import wifi_analyzer.ui \
    --hidden-import wifi_analyzer.gui \
    gui_main.py



echo "[*] Build complete!"
echo "[*] Executable location: dist/wifi-risk-analyzer-gui"
echo ""
echo "[*] Usage:"
echo "    sudo ./dist/wifi-risk-analyzer-gui"
echo ""
echo "[*] To run directly without building:"
echo "    sudo python3 main.py -i wlan0mon -t 30"
