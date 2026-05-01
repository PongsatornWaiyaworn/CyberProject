# Fake Wi-Fi Risk Analyzer - Windows Build Script
# Builds a standalone executable using PyInstaller

$ErrorActionPreference = "Stop"

Write-Host "[*] Fake Wi-Fi Risk Analyzer - Windows Build" -ForegroundColor Cyan
Write-Host "[*] OS: $([System.Environment]::OSVersion.VersionString)" -ForegroundColor Cyan

# Check Python
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    Write-Host "[!] Python not found. Please install Python 3.9+ first." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Installing Python dependencies..." -ForegroundColor Green
python -m pip install -r requirements.txt

# Check/Install PyInstaller
Write-Host "[*] Checking PyInstaller..." -ForegroundColor Green
$pi = Get-Command pyinstaller -ErrorAction SilentlyContinue
if (-not $pi) {
    Write-Host "[*] Installing PyInstaller..." -ForegroundColor Yellow
    python -m pip install pyinstaller
}

Write-Host "[*] Building standalone executable..." -ForegroundColor Green
pyinstaller `
    --onefile `
    --name wifi-risk-analyzer `
    --hidden-import wifi_analyzer.config `
    --hidden-import wifi_analyzer.vendor_db `
    --hidden-import wifi_analyzer.scanner `
    --hidden-import wifi_analyzer.analyzer `
    --hidden-import wifi_analyzer.ui `
    main.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "[*] Build complete!" -ForegroundColor Green
    Write-Host "[*] Executable location: dist\wifi-risk-analyzer.exe" -ForegroundColor Green
    Write-Host ""
    Write-Host "[*] IMPORTANT NOTES FOR WINDOWS:" -ForegroundColor Yellow
    Write-Host "    - scapy on Windows requires Npcap (https://npcap.com/#download)" -ForegroundColor Yellow
    Write-Host "    - Monitor mode on Windows is very limited; Wi-Fi scanning may not work correctly." -ForegroundColor Yellow
    Write-Host "    - For full Wi-Fi scanning capability, run the tool on Linux/Kali." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "[*] Usage (limited on Windows):" -ForegroundColor Cyan
    Write-Host "    dist\wifi-risk-analyzer.exe --no-team" -ForegroundColor White
} else {
    Write-Host "[!] Build failed." -ForegroundColor Red
}
