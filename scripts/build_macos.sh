#!/bin/bash
# Build script for macOS
# Creates a standalone executable using PyInstaller

set -e

echo "[*] Fake Wi-Fi Risk Analyzer - macOS Build"
echo "[*] OS: $(uname -a)"

# Check if Homebrew is installed (recommended for dependencies)
if command -v brew &> /dev/null; then
    echo "[*] Homebrew detected."
else
    echo "[!] Warning: Homebrew not found. If scapy fails, install libpcap:"
    echo "    brew install libpcap"
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
echo "[*] IMPORTANT NOTES FOR macOS:"
echo "    - macOS Wi-Fi scanning requires root and monitor mode support."
echo "    - Enable monitor mode with: sudo airport en0 sniff"
echo "    - Or use a USB Wi-Fi adapter that supports monitor mode on macOS."
echo "    - For best results, run on Linux/Kali VM."
echo ""
echo "[*] Usage:"
echo "    sudo ./dist/wifi-risk-analyzer-gui"
