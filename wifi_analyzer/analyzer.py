"""Anomaly detection and risk scoring for Wi-Fi APs."""
from typing import Dict, Any, List
from collections import defaultdict
from .config import (
    WEIGHT_SSID_DUPLICATE,
    WEIGHT_ENCRYPTION_MISMATCH,
    WEIGHT_RSSI_ANOMALY,
    WEIGHT_VENDOR_MISMATCH,
    WEIGHT_CHANNEL_ANOMALY,
    WEIGHT_LOCALLY_ADMINISTERED,
    RSSI_VERY_STRONG,
    RSSI_WEAK,
    STANDARD_CHANNELS_2_4,
    STANDARD_CHANNELS_5,
    RISK_SAFE,
    RISK_SUSPICIOUS,
)
from .vendor_db import get_vendor

class APAnalyzer:
    def __init__(self, aps: Dict[str, Dict[str, Any]]):
        self.aps = aps
        self.ssid_groups = defaultdict(list)
        for bssid, info in aps.items():
            self.ssid_groups[info["ssid"]].append(info)
        self.scores = {}
        self.reasons = defaultdict(list)

    def _is_locally_administered(self, mac: str) -> bool:
        try:
            first_octet = int(mac.split(":")[0], 16)
            return bool(first_octet & 0x02)
        except Exception:
            return False

    def _channel_anomaly(self, ch: int) -> bool:
        if ch == 0:
            return True
        return ch not in STANDARD_CHANNELS_2_4 and ch not in STANDARD_CHANNELS_5

    def analyze(self) -> Dict[str, Any]:
        for bssid, info in self.aps.items():
            score = 0
            ssid = info["ssid"]
            rssi = info["rssi"]
            channel = info["channel"]
            enc = info["encryption"]

            # SSID duplicate
            group = self.ssid_groups.get(ssid, [])
            if len(group) > 1:
                score += WEIGHT_SSID_DUPLICATE
                self.reasons[bssid].append(f"SSID duplicate ({len(group)} APs)")

            # Encryption mismatch within same SSID
            if len(group) > 1:
                encs = {a["encryption"] for a in group}
                if len(encs) > 1:
                    score += WEIGHT_ENCRYPTION_MISMATCH
                    self.reasons[bssid].append("Encryption mismatch within SSID")

            # RSSI anomaly
            if rssi > RSSI_VERY_STRONG:
                score += WEIGHT_RSSI_ANOMALY
                self.reasons[bssid].append(f"Suspiciously strong signal ({rssi} dBm)")
            elif rssi < RSSI_WEAK:
                score += WEIGHT_RSSI_ANOMALY // 2
                self.reasons[bssid].append(f"Very weak signal ({rssi} dBm)")

            # Vendor mismatch
            vendor = get_vendor(bssid)
            if vendor == "Unknown":
                score += WEIGHT_VENDOR_MISMATCH
                self.reasons[bssid].append("Unknown vendor OUI")

            # Locally administered MAC
            if self._is_locally_administered(bssid):
                score += WEIGHT_LOCALLY_ADMINISTERED
                self.reasons[bssid].append("Locally administered MAC (possible spoof)")

            # Channel anomaly
            if self._channel_anomaly(channel):
                score += WEIGHT_CHANNEL_ANOMALY
                self.reasons[bssid].append(f"Non-standard channel {channel}")

            # Open network penalty
            if enc == "OPN":
                score += 10
                self.reasons[bssid].append("Open network (no encryption)")

            self.scores[bssid] = min(score, 100)

        return self._build_report()

    def _build_report(self) -> Dict[str, Any]:
        report = []
        for bssid, info in self.aps.items():
            score = self.scores.get(bssid, 0)
            if score <= RISK_SAFE:
                level = "Safe"
            elif score <= RISK_SUSPICIOUS:
                level = "Suspicious"
            else:
                level = "High Risk"
            report.append({
                "bssid": bssid,
                "ssid": info["ssid"] or "<Hidden>",
                "rssi": info["rssi"],
                "channel": info["channel"],
                "encryption": info["encryption"],
                "score": score,
                "level": level,
                "reasons": self.reasons.get(bssid, []),
                "vendor": get_vendor(bssid),
            })
        report.sort(key=lambda x: (-x["score"], x["ssid"], x["bssid"]))
        return {"aps": report, "total": len(report)}
