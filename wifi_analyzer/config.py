"""
Configuration and constants for Fake Wi-Fi Risk Analyzer.
"""

# Scanning defaults
DEFAULT_SCAN_DURATION = 30  # seconds
DEFAULT_INTERFACE = None    # auto-detect if None

# Risk scoring thresholds
RISK_SAFE = 30
RISK_SUSPICIOUS = 70
RISK_HIGH = 100

# RSSI anomaly thresholds
RSSI_VERY_STRONG = -20   # dBm; suspiciously strong for public places
RSSI_WEAK = -85          # dBm; very weak, might be far away or fake

# Standard Wi-Fi channels
STANDARD_CHANNELS_2_4 = set(range(1, 15))      # 1-14
STANDARD_CHANNELS_5 = set(range(36, 166, 4)) | {100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165}
STANDARD_CHANNELS_6 = set(range(1, 234))     # 802.11ax 6GHz simplified

# Weight factors for risk score calculation
WEIGHT_SSID_DUPLICATE = 25
WEIGHT_ENCRYPTION_MISMATCH = 20
WEIGHT_RSSI_ANOMALY = 15
WEIGHT_VENDOR_MISMATCH = 15
WEIGHT_CHANNEL_ANOMALY = 10
WEIGHT_LOCALLY_ADMINISTERED = 15

# Encryption strength mapping (lower = weaker)
ENCRYPTION_STRENGTH = {
    "OPN": 0,      # Open
    "WEP": 10,     # WEP
    "WPA": 20,     # WPA
    "WPA2": 40,    # WPA2
    "WPA3": 50,    # WPA3
}

# Rich color mapping
COLOR_SAFE = "green"
COLOR_SUSPICIOUS = "yellow"
COLOR_HIGH = "red"
COLOR_INFO = "cyan"
COLOR_WARN = "orange_red1"

# Team information
TEAM_MEMBERS = [
    "65090500457 นาย สันติจิต คำหนัก",
    "66090500405 นาย ณัฏฐชนม์ ชัยมะณี",
    "66090500409 นางสาว ต้นหยก บูรณวานิช",
    "66090500411 นาย ธนวัฒน์ มะปะเท",
    "66090500413 นาย พงศธร ไวยวรณ์",
    "66090500435 นาย นฤพนธ์ ฉายสุวรรณคีรี",
]
