#!/usr/bin/env python3
"""Fake Wi-Fi Risk Analyzer - Main Entry Point."""
import argparse
import sys
import os

if hasattr(os, "geteuid") and os.geteuid() != 0:
    print("[!] This tool must run as root (required for monitor mode & raw 802.11 capture).")
    print("    Example: sudo python3 main.py -i wlan0mon -t 30")
    sys.exit(1)

from wifi_analyzer.scanner import WiFiScanner
from wifi_analyzer.analyzer import APAnalyzer
from wifi_analyzer.ui import print_banner, print_team, print_results
from wifi_analyzer.config import DEFAULT_SCAN_DURATION

def main():
    parser = argparse.ArgumentParser(
        description="Fake Wi-Fi Risk Analyzer (Passive Scan / Evil Twin Detection)"
    )
    parser.add_argument("-i", "--iface", default=None, help="Monitor-mode interface (e.g. wlan0mon)")
    parser.add_argument("-t", "--time", type=int, default=DEFAULT_SCAN_DURATION, help="Scan duration in seconds")
    parser.add_argument("--no-team", action="store_true", help="Skip team banner")
    parser.add_argument("--demo", action="store_true", help="Use synthetic mock data instead of live scan")
    parser.add_argument("--gui", action="store_true", help="Launch GUI mode (tkinter)")
    args = parser.parse_args()

    if args.gui:
        from wifi_analyzer.gui import launch_gui
        launch_gui()
        return

    print_banner()
    if not args.no_team:
        print_team()

    if args.demo:
        print("[*] DEMO MODE: Using synthetic Wi-Fi data for testing.")

    scanner = WiFiScanner(iface=args.iface, demo=args.demo)
    aps = scanner.scan(duration=args.time)
    analyzer = APAnalyzer(aps)
    report = analyzer.analyze()
    print_results(report)

if __name__ == "__main__":
    main()
