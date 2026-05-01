"""Cross-platform Wi-Fi scanner with fallback backends."""
import platform
import re
import subprocess
import threading
import time
from typing import Dict, Any, Optional

# scapy availability
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap
    SCAPY_AVAILABLE = True
except ImportError:
    pass

_SYSTEM = platform.system().lower()


class WiFiScanner:
    def __init__(self, iface: Optional[str] = None, demo: bool = False, stop_event: Optional[threading.Event] = None):
        self.iface = iface
        self.demo = demo
        self.results: Dict[str, Dict[str, Any]] = {}
        self._stop = stop_event if stop_event is not None else threading.Event()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def scan(self, duration: int = 30) -> Dict[str, Dict[str, Any]]:
        self.results.clear()
        self._stop.clear()

        if self.demo:
            return self._demo_scan(duration)

        if _SYSTEM == "linux" and SCAPY_AVAILABLE:
            return self._scapy_scan(duration)
        elif _SYSTEM == "darwin":
            return self._macos_scan(duration)
        elif _SYSTEM == "windows":
            return self._windows_scan(duration)
        else:
            print(f"[!] Unsupported platform '{platform.system()}'. Using demo mode.")
            return self._demo_scan(duration)

    # ------------------------------------------------------------------
    # Demo / mock data (testing without Wi-Fi hardware)
    # ------------------------------------------------------------------
    def _demo_scan(self, duration: int) -> Dict[str, Dict[str, Any]]:
        print(f"[*] DEMO MODE: Generating mock Wi-Fi data...")
        # Sleep with periodic stop checks
        end_time = time.time() + min(duration, 2)
        while time.time() < end_time and not self._stop.is_set():
            time.sleep(0.1)
        
        mock = [
            # Evil Twin: same SSID, different BSSID + encryption mismatch
            {"bssid": "00:11:22:33:44:55", "ssid": "Starbucks_WiFi", "rssi": -45, "channel": 6, "encryption": "WPA2/WPA3"},
            {"bssid": "00:11:22:33:44:66", "ssid": "Starbucks_WiFi", "rssi": -85, "channel": 11, "encryption": "OPN"},
            # Normal home network
            {"bssid": "A0:B1:C2:D3:E4:F5", "ssid": "Home_5G", "rssi": -32, "channel": 36, "encryption": "WPA2/WPA3"},
            # Open network
            {"bssid": "AA:BB:CC:DD:EE:01", "ssid": "FreeWiFi", "rssi": -50, "channel": 1, "encryption": "OPN"},
            # Duplicate SSID (hotel) + locally administered MAC
            {"bssid": "02:00:00:00:00:01", "ssid": "Hotel_Guest", "rssi": -60, "channel": 6, "encryption": "WPA2/WPA3"},
            {"bssid": "02:00:00:00:00:02", "ssid": "Hotel_Guest", "rssi": -58, "channel": 6, "encryption": "WPA2/WPA3"},
            # Suspiciously strong + unknown vendor + non-standard channel
            {"bssid": "DE:AD:BE:EF:00:01", "ssid": "EvilTwin_Test", "rssi": -25, "channel": 99, "encryption": "WPA2/WPA3"},
            {"bssid": "DE:AD:BE:EF:00:02", "ssid": "EvilTwin_Test", "rssi": -24, "channel": 99, "encryption": "OPN"},
        ]
        for rec in mock:
            key = rec["bssid"].upper()
            self.results[key] = {**rec, "count": 1}
        print(f"[*] DEMO scan complete. Found {len(self.results)} mock APs.")
        return self.results

    # ------------------------------------------------------------------
    # Linux / Kali — scapy passive monitor-mode scan (best quality)
    # ------------------------------------------------------------------
    @staticmethod
    def _get_encryption(pkt) -> str:
        cap = pkt[Dot11Beacon].cap
        if cap & 0x10:
            return "WEP"
        rsn = False
        wpa = False
        p = pkt.getlayer(Dot11Elt)
        while isinstance(p, Dot11Elt):
            if p.ID == 48:
                rsn = True
            elif p.ID == 221 and p.info and len(p.info) >= 4 and p.info[:4] == b"\x00\x50\xf2\x01":
                wpa = True
            p = p.payload.getlayer(Dot11Elt) if p.payload.haslayer(Dot11Elt) else None
            if p is None:
                break
        if rsn:
            return "WPA2/WPA3"
        if wpa:
            return "WPA"
        return "OPN"

    def _packet_handler(self, pkt):
        if not pkt.haslayer(Dot11Beacon):
            return
        bssid = pkt[Dot11].addr3 or pkt[Dot11].addr2
        if not bssid:
            return
        ssid = ""
        channel = 0
        rssi = -100
        if pkt.haslayer(Dot11Elt):
            try:
                ssid_elt = pkt[Dot11Elt]
                if ssid_elt.ID == 0:
                    ssid = ssid_elt.info.decode("utf-8", "ignore") or ""
            except Exception:
                pass
            try:
                p = pkt.getlayer(Dot11Elt)
                while isinstance(p, Dot11Elt):
                    if p.ID == 3 and p.info and len(p.info) >= 1:
                        channel = p.info[0]
                        if isinstance(channel, bytes):
                            channel = ord(channel)
                        else:
                            channel = int(channel)
                    p = p.payload.getlayer(Dot11Elt) if p.payload.haslayer(Dot11Elt) else None
                    if p is None:
                        break
            except Exception:
                pass
        if pkt.haslayer(RadioTap):
            try:
                rssi = int(pkt[RadioTap].dBm_AntSignal)
            except Exception:
                pass
        enc = self._get_encryption(pkt)
        key = bssid.upper()
        if key not in self.results:
            self.results[key] = {
                "bssid": key,
                "ssid": ssid,
                "rssi": rssi,
                "channel": channel,
                "encryption": enc,
                "count": 1,
            }
        else:
            rec = self.results[key]
            rec["count"] += 1
            if rssi > rec["rssi"]:
                rec["rssi"] = rssi

    def _scapy_scan(self, duration: int) -> Dict[str, Dict[str, Any]]:
        print(f"[*] Starting scapy passive scan on {self.iface or 'default'} for {duration}s...")
        def _run():
            try:
                sniff(
                    iface=self.iface,
                    prn=self._packet_handler,
                    store=0,
                    stop_filter=lambda x: self._stop.is_set(),
                )
            except Exception as e:
                print(f"[!] Sniff error: {e}")
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        time.sleep(duration)
        self._stop.set()
        t.join(timeout=2)
        print(f"[*] Scapy scan complete. Found {len(self.results)} unique APs.")
        return self.results

    # ------------------------------------------------------------------
    # Windows — netsh wlan show networks mode=Bssid (no monitor mode needed)
    # ------------------------------------------------------------------
    def _windows_scan(self, duration: int) -> Dict[str, Dict[str, Any]]:
        print(f"[*] Starting Windows scan via netsh for {duration}s...")
        seen = set()
        end = time.time() + duration
        scan_success = False
        
        while time.time() < end and not self._stop.is_set():
            try:
                out = subprocess.check_output(
                    ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                )
                self._parse_netsh(out, seen)
                scan_success = True
            except subprocess.CalledProcessError as e:
                print(f"[!] netsh error: {e.output.strip()}")
                break
            except Exception as e:
                print(f"[!] Windows scan error: {e}")
                break
            
            # Sleep in small increments to check stop event frequently
            sleep_end = time.time() + 3
            while time.time() < sleep_end and not self._stop.is_set():
                time.sleep(0.1)
        
        print(f"[*] Windows scan complete. Found {len(self.results)} unique APs.")
        return self.results

    def _parse_netsh(self, output: str, seen: set):
        current_ssid = ""
        bssid = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID"):
                m = re.search(r"SSID\s+\d+\s*:\s*(.+)", line)
                current_ssid = m.group(1).strip() if m else ""
            elif line.startswith("BSSID"):
                bm = re.search(r"([0-9a-fA-F:]{17})", line)
                if bm:
                    bssid = bm.group(1).upper()
                    seen.add(bssid)
                    self.results[bssid] = {
                        "bssid": bssid,
                        "ssid": current_ssid,
                        "rssi": -100,
                        "channel": 0,
                        "encryption": "OPN",
                        "count": 1,
                    }
            elif bssid is not None:
                if "Signal" in line:
                    sm = re.search(r"(\d+)\s*%", line)
                    if sm:
                        pct = int(sm.group(1))
                        self.results[bssid]["rssi"] = -100 + int(pct * 0.7)
                elif "Channel" in line:
                    cm = re.search(r"(\d+)", line)
                    if cm:
                        self.results[bssid]["channel"] = int(cm.group(1))
                elif "Authentication" in line:
                    val = line.upper()
                    if "WPA3" in val or "WPA2" in val:
                        self.results[bssid]["encryption"] = "WPA2/WPA3"
                    elif "WPA" in val:
                        self.results[bssid]["encryption"] = "WPA"
                    elif "WEP" in val:
                        self.results[bssid]["encryption"] = "WEP"
                    else:
                        self.results[bssid]["encryption"] = "OPN"

    # ------------------------------------------------------------------
    # macOS — airport utility (no monitor mode needed)
    # ------------------------------------------------------------------
    def _macos_scan(self, duration: int) -> Dict[str, Dict[str, Any]]:
        print(f"[*] Starting macOS scan for {duration}s...")
        end = time.time() + duration
        while time.time() < end and not self._stop.is_set():
            try:
                airport = (
                    "/System/Library/PrivateFrameworks/Apple80211.framework/"
                    "Versions/Current/Resources/airport"
                )
                out = subprocess.check_output(
                    [airport, "-s"],
                    stderr=subprocess.STDOUT,
                    text=True,
                    errors="ignore",
                )
                self._parse_airport(out)
            except Exception as e:
                print(f"[!] macOS scan error: {e}")
                break
            
            # Sleep in small increments to check stop event frequently
            sleep_end = time.time() + 5
            while time.time() < sleep_end and not self._stop.is_set():
                time.sleep(0.1)
        
        print(f"[*] macOS scan complete. Found {len(self.results)} unique APs.")
        return self.results

    def _parse_airport(self, output: str):
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            ssid = parts[0]
            bssid = parts[1].upper()
            rssi = int(parts[2]) if parts[2].lstrip("-").isdigit() else -70
            channel = int(parts[3]) if parts[3].isdigit() else 0
            sec = " ".join(parts[4:]).upper()
            if "WPA3" in sec or "WPA2" in sec:
                enc = "WPA2/WPA3"
            elif "WPA" in sec:
                enc = "WPA"
            elif "WEP" in sec:
                enc = "WEP"
            else:
                enc = "OPN"
            self.results[bssid] = {
                "bssid": bssid,
                "ssid": ssid,
                "rssi": rssi,
                "channel": channel,
                "encryption": enc,
                "count": 1,
            }
