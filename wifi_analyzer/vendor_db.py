"""OUI vendor lookup (subset)."""

OUI = {
    "00:00:0C": "Cisco", "00:03:93": "Apple", "00:04:0B": "Dell",
    "00:09:5B": "Netgear", "00:0A:27": "Apple", "00:0C:41": "Cisco",
    "00:0E:58": "ASUS", "00:11:32": "Apple", "00:14:6C": "Apple",
    "00:17:88": "Philips", "00:1A:2B": "Apple", "00:1B:77": "Cisco",
    "00:1C:42": "Google", "00:1C:58": "Apple", "00:1E:58": "Apple",
    "00:21:55": "Apple", "00:24:E8": "Apple", "00:25:00": "Apple",
    "00:26:0B": "Apple", "00:26:98": "Apple", "00:33:14": "Cisco",
    "00:36:9D": "Apple", "00:38:68": "Apple", "00:3E:C5": "Apple",
    "00:40:05": "Apple", "00:41:0B": "Apple", "00:42:5A": "Apple",
    "00:50:56": "VMware", "00:50:F2": "Microsoft", "00:54:AF": "Dell",
    "00:58:8C": "Huawei", "00:63:81": "Huawei", "00:6C:FD": "Apple",
    "00:72:BF": "Apple", "00:84:ED": "Apple", "00:88:65": "Apple",
    "00:8C:54": "Apple", "00:93:E9": "Apple", "00:9C:30": "Apple",
    "00:A0:C9": "Intel", "00:A6:CA": "Apple", "00:B0:6A": "Apple",
    "00:B8:C2": "Apple", "00:BB:09": "Apple", "00:C2:C6": "Apple",
    "00:C5:DB": "Apple", "00:CD:FE": "Apple", "00:D4:9E": "Apple",
    "00:D6:32": "Apple", "00:D8:61": "Apple", "00:DB:45": "Apple",
    "00:DD:24": "Apple", "00:E0:14": "Apple", "00:E0:4C": "Realtek",
    "00:E0:B0": "Apple", "00:E8:4C": "Apple", "00:EC:0A": "Apple",
    "00:ED:00": "Apple", "00:F0:4F": "Apple", "00:F2:28": "Apple",
    "00:F3:34": "Apple", "00:F4:31": "Apple", "00:F6:20": "Apple",
    "00:F8:1C": "Apple", "00:FA:21": "Apple", "00:FC:25": "Apple",
    "00:FC:58": "Apple", "00:FE:C8": "Cisco",
}

def get_vendor(mac: str) -> str:
    oui = mac.upper()[:8]
    return OUI.get(oui, "Unknown")
