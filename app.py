import sys
import socket

from modules.discovery import discover_devices
from modules.device_tracker import detect_new_devices
from modules.logger import log_event
from modules.soc_summary import print_summary, log_daily_summary
from modules.soc_export import export_csv, export_json
from modules.colors import disable_color
from modules.timeline import print_timeline
from modules.timeline_export import export_timeline_json, export_timeline_csv
from modules.soc_metrics import print_metrics
from modules.visualization import print_risk_history, print_incident_summary
from modules.runtime import enable_safe_mode
from modules.audit_checks import run_audit_checks


def get_hostname_ip():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    return hostname, ip


def parse_args():
    return {
        "quiet": "--quiet" in sys.argv,
        "summary": "--summary" in sys.argv,
        "metrics": "--metrics" in sys.argv,
        "visualize": "--visualize" in sys.argv,
        "no_color": "--no-color" in sys.argv,
        "safe_mode": "--safe-mode" in sys.argv,
        "timeline": sys.argv[sys.argv.index("--timeline") + 1] if "--timeline" in sys.argv else None,
        "export": sys.argv[sys.argv.index("--export") + 1] if "--export" in sys.argv else None,
        "timeline_export": (
            sys.argv[sys.argv.index("--timeline-export") + 1],
            sys.argv[sys.argv.index("--timeline-export") + 2],
        ) if "--timeline-export" in sys.argv else None,
    }


def main():
    args = parse_args()

    if args["safe_mode"]:
        enable_safe_mode()
        print("🔵 SAFE MODE ENABLED — READ-ONLY SOC MODE\n")

    if args["no_color"]:
        disable_color()

    hostname, ip = get_hostname_ip()

    if not args["quiet"]:
        print("Home Security Platform initialized")
        print(f"Running on {hostname} ({ip})\n")

    log_event("INFO", "Platform started successfully", host=hostname, ip=ip)

    log_daily_summary()

    if args["metrics"]:
        print_metrics()
        return

    if args["visualize"]:
        print_risk_history()
        print_incident_summary()
        return

    if args["summary"]:
        print_summary()
        return

    if args["timeline"]:
        print_timeline(args["timeline"])
        return

    if args["timeline_export"]:
        fmt, ip_addr = args["timeline_export"]
        if fmt == "json":
            export_timeline_json(ip_addr)
        elif fmt == "csv":
            export_timeline_csv(ip_addr)
        return

    if args["export"]:
        if args["export"] == "json":
            export_json()
        elif args["export"] == "csv":
            export_csv()
        return

    # =========================
    # Normal SOC Run
    # =========================
    current_devices = discover_devices()
    detect_new_devices(current_devices)

    # =========================
    # H5 — Audit Completeness
    # =========================
    run_audit_checks()

    if not args["quiet"]:
        print("No new devices detected.")


if __name__ == "__main__":
    main()
    

    



    
    

    
    

    









