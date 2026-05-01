"""Wi-Fi passive scanner using scapy (requires root + monitor mode on Linux/Kali)."""
import threading
import time
from typing import Dict, Any, Optional

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap
    from scapy.layers.dot11 import Dot11FCS
except ImportError:
    Dot11FCS = None

class WiFiScanner:
    def __init__(self, iface: Optional[str] = None):
        self.iface = iface
        self.results: Dict[str, Dict[str, Any]] = {}
        self._stop = threading.Event()

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
            if enc != rec["encryption"] and enc not in (rec["encryption"], "OPN"):
                rec["encryption"] = enc

    def scan(self, duration: int = 30) -> Dict[str, Dict[str, Any]]:
        self.results.clear()
        self._stop.clear()
        print(f"[*] Starting passive scan on {self.iface or 'default'} for {duration}s...")
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
        print(f"[*] Scan complete. Found {len(self.results)} unique APs.")
        return self.results
