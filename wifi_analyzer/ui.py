"""CLI UI using rich library."""
from typing import Dict, Any, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from .config import COLOR_SAFE, COLOR_SUSPICIOUS, COLOR_HIGH, COLOR_INFO

console = Console()

def print_banner():
    banner = r"""
[bold cyan]    ____        __           _   __      __  __            
   / __/____ _ / /_ ___ _   / | / /___ _/ /_/ /_ ____  ____
  / /_ / __ `// __// _ `/  /  |/ // _ `// __// __// _ \/ __/
 / __// /_/ // /_ /  __/  / /|  // __// /_ / /_ /  __/ /    
/_/   \__,_/ \__/ \___/  /_/ |_/ \___/ \__/\__/ \___/_/     
[/bold cyan]
[bold red] Fake Wi-Fi Risk Analyzer (Evil Twin Detector)[/bold red]
[white] Passive Scan | Anomaly Detection | MITRE ATT&CK T1557.004[/white]
"""
    console.print(Panel(banner, border_style="cyan", title="CyberProject"))

def print_team():
    members = "\n".join([
        "65090500457 นาย สันติจิต คำหนัก",
        "66090500405 นาย ณัฏฐชนม์ ชัยมะณี",
        "66090500409 นางสาว ต้นหยก บูรณวานิช",
        "66090500411 นาย ธนวัฒน์ มะปะเท",
        "66090500413 นาย พงศธร ไวยวรณ์",
        "66090500435 นาย นฤพนธ์ ฉายสุวรรณคีรี",
    ])
    console.print(Panel(members, title="[bold green]Team Members[/bold green]", border_style="green"))

def print_results(report: Dict[str, Any]):
    aps = report.get("aps", [])
    if not aps:
        console.print("[bold yellow]No APs detected.[/bold yellow]")
        return
    table = Table(title="Wi-Fi Risk Analysis Results", box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("#", style="white", justify="right")
    table.add_column("SSID", style="white")
    table.add_column("BSSID", style="white")
    table.add_column("Vendor", style="white")
    table.add_column("Ch", style="white", justify="right")
    table.add_column("RSSI", style="white", justify="right")
    table.add_column("Enc", style="white")
    table.add_column("Score", justify="right")
    table.add_column("Risk Level", justify="center")
    table.add_column("Flags", style="white")

    for idx, ap in enumerate(aps, 1):
        level = ap["level"]
        color = COLOR_SAFE if level == "Safe" else COLOR_SUSPICIOUS if level == "Suspicious" else COLOR_HIGH
        flags = "; ".join(ap["reasons"]) if ap["reasons"] else "-"
        table.add_row(
            str(idx),
            ap["ssid"],
            ap["bssid"],
            ap["vendor"],
            str(ap["channel"]),
            f"{ap['rssi']} dBm",
            ap["encryption"],
            str(ap["score"]),
            f"[{color}]{level}[/{color}]",
            flags,
        )
    console.print(table)
    high = sum(1 for a in aps if a["level"] == "High Risk")
    sus = sum(1 for a in aps if a["level"] == "Suspicious")
    safe = sum(1 for a in aps if a["level"] == "Safe")
    console.print(f"[bold]Summary:[/bold] [red]{high} High Risk[/red] | [yellow]{sus} Suspicious[/yellow] | [green]{safe} Safe[/green] | Total {len(aps)}")
