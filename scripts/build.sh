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
if ! command -v pyinstaller &> /dev/null; then
    echo "[*] Installing PyInstaller..."
    pip3 install pyinstaller
fi

# Build single executable
echo "[*] Building standalone executable with PyInstaller..."
pyinstaller \
    --onefile \
    --name wifi-risk-analyzer \
    --hidden-import wifi_analyzer.config \
    --hidden-import wifi_analyzer.vendor_db \
    --hidden-import wifi_analyzer.scanner \
    --hidden-import wifi_analyzer.analyzer \
    --hidden-import wifi_analyzer.ui \
    main.py

echo "[*] Build complete!"
echo "[*] Executable location: dist/wifi-risk-analyzer"
echo ""
echo "[*] Usage:"
echo "    sudo ./dist/wifi-risk-analyzer -i wlan0mon -t 30"
echo ""
echo "[*] To run directly without building:"
echo "    sudo python3 main.py -i wlan0mon -t 30"
