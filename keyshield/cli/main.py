"""
KeyShield CLI v3.0
Main entry point for command-line interface.
"""

import argparse
import sys
import time
import threading
import webbrowser
from typing import Optional

from ..core.engine import ScanEngine, ScanResult
from ..core.config import get_config
from ..utils.reporter import ReportGenerator
from ..utils.logger import SecurityLogger
from ..web.app import create_app


def get_gradient_banner():
    # Blue to Cyan gradient colors (ANSI 256-color mode)
    colors = ["\033[38;5;27m", "\033[38;5;33m", "\033[38;5;39m", "\033[38;5;45m", "\033[38;5;51m", "\033[38;5;87m"]
    reset = "\033[0m"
    
    lines = [
        r"██╗  ██╗███████╗██╗   ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ",
        r"██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗",
        r"█████╔╝ █████╗   ╚████╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║",
        r"██╔═██╗ ██╔══╝    ╚██╔╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║",
        r"██║  ██╗███████╗   ██║   ███████║██║  ██║██║███████╗███████╗██████╔╝",
        r"╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ "
    ]
    
    banner = ""
    for i, line in enumerate(lines):
        color = colors[i % len(colors)]
        banner += f"{color}{line}{reset}\n"
    
    banner += f" {colors[4]}v3.0.0{reset} | {colors[2]}Input Security Monitor{reset}\n"
    return banner

QUICK_START = """
\033[1m🚀 QUICK START:\033[0m
  Full Scan:      \033[32mkeyshield scan\033[0m
  Quick Scan:     \033[32mkeyshield scan --quick\033[0m
  Continuous:     \033[32mkeyshield monitor\033[0m
  Launch Web GUI: \033[32mkeyshield web\033[0m
"""

def main():
    print(get_gradient_banner())
    
    parser = argparse.ArgumentParser(
        description="KeyShield v3.0 — Input Security Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=QUICK_START
    )
    parser.add_argument("--version", action="version", version="KeyShield v3.0.0")
    
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to run")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument("--quick", action="store_true", help="Run a quick scan")
    scan_parser.add_argument("--profile", choices=["quick", "standard", "paranoid"], help="Scan profile to use")
    scan_parser.add_argument("--json", action="store_true", help="Output result as JSON")
    scan_parser.add_argument("--csv", action="store_true", help="Output result as CSV")

    # Web command
    web_parser = subparsers.add_parser("web", help="Start the Web GUI")
    web_parser.add_argument("--port", type=int, default=5000, help="Port to run the web server on")
    web_parser.add_argument("--host", default="127.0.0.1", help="Host to bind the web server to")
    web_parser.add_argument("--no-browser", action="store_true", help="Don't open the browser automatically")

    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Run in continuous monitor mode")
    monitor_parser.add_argument("--interval", type=int, default=60, help="Interval between scans in seconds")
    monitor_parser.add_argument("--profile", choices=["quick", "standard", "paranoid"], help="Scan profile to use")

    # Config command
    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_subparsers = config_parser.add_subparsers(dest="config_command", help="Config subcommand")
    
    whitelist_parser = config_subparsers.add_parser("whitelist", help="Manage process whitelist")
    whitelist_parser.add_argument("action", choices=["add", "remove", "list"], help="Action to perform")
    whitelist_parser.add_argument("process", nargs="?", help="Process name to add or remove")

    args = parser.parse_args()

    if args.command == "scan":
        run_cli_scan(args)
    elif args.command == "web":
        run_web_server(args)
    elif args.command == "monitor":
        run_monitor_mode(args)
    elif args.command == "config":
        handle_config(args)
    else:
        parser.print_help()


def run_cli_scan(args):
    from ..utils.helpers import is_admin
    logger = SecurityLogger(name="KeyShield.CLI")
    engine = ScanEngine()
    
    if not is_admin():
        logger.warning("\033[1mRunning without elevated privileges.\033[0m")
        logger.warning("Some detectors may be restricted and produce incomplete results.")
        logger.warning("Recommendation: Run with 'sudo' (Linux) or as Administrator (Windows).\n")

    logger.info(f"Starting CLI scan (Profile: {args.profile})...")
    result = engine.run_scan(quick=args.quick, profile=args.profile)
    
    if args.json:
        import json
        print(json.dumps(result.to_dict(), indent=2))
    elif args.csv:
        path = ReportGenerator.generate_csv_report(result)
        print(f"CSV report generated: {path}")
    else:
        ReportGenerator.print_summary(result)
        txt_path = ReportGenerator.generate_text_report(result)
        logger.info(f"Full report saved to: {txt_path}")


def run_web_server(args):
    logger = SecurityLogger(name="KeyShield.Web")
    app = create_app()
    
    url = f"http://{args.host}:{args.port}"
    logger.info(f"Starting KeyShield Web GUI at {url}")
    
    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    
    app.run(host=args.host, port=args.port, debug=False)


def run_monitor_mode(args):
    logger = SecurityLogger(name="KeyShield.Monitor")
    engine = ScanEngine()
    
    logger.info(f"Entering monitor mode (Interval: {args.interval}s, Profile: {args.profile})")
    logger.info("Press Ctrl+C to stop.")
    
    try:
        while True:
            result = engine.run_scan(profile=args.profile)
            if result.overall_risk.value >= 2:  # MEDIUM or higher
                logger.warning(f"THREAT DETECTED in monitor mode! Risk: {result.overall_risk.name} | Findings: {result.total_findings}")
                ReportGenerator.generate_text_report(result)
            else:
                logger.info(f"Scan complete: System {result.overall_risk.name}")
            
            time.sleep(args.interval)
    except KeyboardInterrupt:
        logger.info("Monitor mode stopped by user.")


def handle_config(args):
    config = get_config()
    if args.config_command == "whitelist":
        if args.action == "list":
            print("Current Process Whitelist:")
            for p in sorted(config.whitelist):
                print(f"  - {p}")
        elif args.action == "add" and args.process:
            config.add_to_whitelist(args.process)
            print(f"Added '{args.process}' to whitelist.")
        elif args.action == "remove" and args.process:
            config.remove_from_whitelist(args.process)
            print(f"Removed '{args.process}' from whitelist.")
        else:
            print("Invalid whitelist command.")


if __name__ == "__main__":
    main()
