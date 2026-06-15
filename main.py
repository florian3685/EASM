#!/usr/bin/env python3
"""
EASM Scanner — External Attack Surface Management
=====================================================
Main entry point / CLI runner.

Usage:
    python main.py                              # Interactive TUI menu
    python main.py --domain example.com         # CLI mode
    python main.py --domain example.com --exploit --stealth

Environment variables (optional, or via .env file):
    VT_API_KEY          VirusTotal API key
    HIBP_API_KEY        Have I Been Pwned API key
    ABUSEIPDB_API_KEY   AbuseIPDB API key
    GSB_API_KEY         Google Safe Browsing API key
"""

import argparse
import sys
import time
import traceback

from colorama import Fore, Style

from utils import get_logger, print_banner, print_section
from report import ReportGenerator
import config

log = get_logger("easm.main")
# ── Module Registry ──
MODULE_REGISTRY = {
    1: ("Attack Surface",          "modules.attack_surface"),
    2: ("Infrastructure",          "modules.infrastructure"),
    3: ("DNS Configuration",       "modules.dns_config"),
    4: ("Mail Configuration",      "modules.mail_config"),
    5: ("Privacy & Reputation",    "modules.privacy_reputation"),
    6: ("Darknet / OSINT",         "modules.darknet_osint"),
    7: ("Advanced Recon",          "modules.advanced_recon"),
    8: ("Parameter Fuzzing",       "modules.parameter_discovery"),
    9: ("GitHub Recon",            "modules.github_recon"),
   10: ("Cloud Assets",            "modules.cloud_assets"),
   11: ("Active Exploitation",     "modules.active_exploitation"),
   12: ("Subdomain Takeover",      "modules.subdomain_takeover"),
   13: ("JS Secrets Scanner",      "modules.js_secrets"),
   14: ("Web Asset Intelligence",  "modules.web_asset_intelligence"),
}

RESULT_KEYS = {
    1: "attack_surface",
    2: "infrastructure_stability",
    3: "dns_configuration",
    4: "mail_configuration",
    5: "privacy_reputation",
    6: "darknet_osint",
    7: "advanced_recon",
    8: "parameter_discovery",
    9: "github_recon",
   10: "cloud_assets",
   11: "active_exploitation",
   12: "subdomain_takeover",
   13: "js_secrets",
   14: "web_asset_intelligence",
}


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="EASM Scanner — Deep Reconnaissance & Vulnerability Scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                  # Interactive TUI menu
  python main.py --domain example.com
  python main.py --domain example.com --stealth
  python main.py --domain example.com --modules 1,3,7,9,10
  python main.py --domain example.com --exploit
        """,
    )
    parser.add_argument(
        "--domain", "-d", default=None,
        help="Target domain (e.g. example.com). Without this flag the interactive TUI starts.",
    )
    parser.add_argument(
        "--modules", "-m", default="1,2,3,4,5,6,7,8,9,10,12,13,14",
        help="Comma-separated list of modules to run (1-14, default: 1-10,12-14). 11 needs --exploit.",
    )
    parser.add_argument(
        "--outdir", default="results",
        help="Output directory for the JSON report (default: 'results')",
    )
    parser.add_argument(
        "--stealth", action="store_true",
        help="Enable stealth mode (jitter + evasion headers) to bypass anti-bot systems",
    )
    parser.add_argument(
        "--exploit", action="store_true",
        help="WARNING: Enable active weaponized exploitation (SQLi dumps, XSS). Requires authorization!",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose output (debug level)",
    )
    parser.add_argument(
        "--fresh", action="store_true",
        help="Ignore any existing checkpoint and start a fresh scan.",
    )
    return parser.parse_args()


def run_module(module_num: int, domain: str, results_so_far: dict,
               on_progress=None) -> dict:
    """Run a single scan module.

    on_progress: optional callback(partial_module_result, hint) called
                 inside long-running modules so the caller can checkpoint.
    """
    name, module_path = MODULE_REGISTRY[module_num]
    print_section(f"Module {module_num}: {name}")

    try:
        import importlib
        mod = importlib.import_module(module_path)

        # Module 11 (Active Exploitation) needs ALL results as attack surface
        if module_num == 11:
            endpoints = []
            params = {}
            port_results = []
            
            # ── Parameters from Module 8 (Arjun) ──
            if "parameter_discovery" in results_so_far:
                params = results_so_far["parameter_discovery"].get("discovered_parameters", {})
            
            # ── Historical URLs from Module 7 (Wayback Machine) ──
            if "advanced_recon" in results_so_far:
                history = results_so_far["advanced_recon"].get("historical_endpoints", [])
                for url in history:
                    endpoints.append({"url": url})
            
            # ── Port scan results from Module 1 (Attack Surface) ──
            if "attack_surface" in results_so_far:
                port_results = results_so_far["attack_surface"].get("open_ports", [])
                
                # ── Feed all discovered subdomains as web targets ──
                host_disc = results_so_far["attack_surface"].get("host_discovery", {})
                for sub in host_disc.get("subdomains", []):
                    endpoints.append({"url": f"https://{sub}"})
                    endpoints.append({"url": f"http://{sub}"})
                
                # ── Login portals are prime exploit targets ──
                for portal in results_so_far["attack_surface"].get("login_portals", []):
                    endpoints.append({"url": portal.get("url", "")})
            
            log.info(f"Module 11 receives {len(endpoints)} endpoints, {len(params)} param-sets, {len(port_results)} port-results")

            # Wrap on_progress so the exploitation module can checkpoint after
            # each Phase 1 endpoint.
            def _ep_done(partial, idx, total):
                if on_progress:
                    on_progress(partial, f"phase1:{idx}/{total}")

            result = mod.run(domain, endpoints, params, port_results,
                             on_endpoint_done=_ep_done)
        elif module_num == 12:
            # Reuse subdomains discovered in Module 1 if available
            subs = []
            if "attack_surface" in results_so_far:
                hd = results_so_far["attack_surface"].get("host_discovery", {})
                subs = hd.get("subdomains", []) or []
            if subs:
                from modules.subdomain_takeover import check_takeovers
                vulnerable = check_takeovers(subs)
                result = {"checked": len(subs), "vulnerable": vulnerable}
            else:
                result = mod.run(domain)
        elif module_num == 14:
            # Reuse Module 1 subdomains to avoid a second expensive enumeration.
            subs = []
            if "attack_surface" in results_so_far:
                hd = results_so_far["attack_surface"].get("host_discovery", {})
                subs = hd.get("subdomains", []) or []
            result = mod.run(domain, subdomains=subs)
        else:
            result = mod.run(domain)
            
        print(f"\n  {Fore.GREEN}✓ Module {module_num} completed{Style.RESET_ALL}\n")
        return result
    except Exception as exc:
        log.error(f"Module {module_num} ({name}) failed: {exc}")
        traceback.print_exc()
        print(f"\n  {Fore.RED}✗ Module {module_num} failed: {exc}{Style.RESET_ALL}\n")
        return {"error": str(exc)}


def execute_scan(domain: str, selected_modules: list, stealth: bool, exploit: bool,
                 outdir: str = "results", fresh: bool = False):
    """Execute the full scan (used by both CLI and TUI)."""

    # Stealth mode
    if stealth:
        config.STEALTH_MODE = True

    # Banner
    print_banner()

    # Exploit warning
    if exploit and 11 not in selected_modules:
        selected_modules.append(11)
        selected_modules = sorted(set(selected_modules))

    if 11 in selected_modules:
        print(f"\n  {Fore.RED}{Style.BRIGHT}⚠️  EXPLOITATION MODE ACTIVE ⚠️{Style.RESET_ALL}")
        print(f"  {Fore.RED}Vulnerability Exploitation (Module 11) force-enabled.{Style.RESET_ALL}\n")

    # ── Checkpoint: load if exists and not --fresh ──
    from checkpoint import Checkpoint
    cp = Checkpoint(domain, outdir)
    results: dict = {}
    completed: list[int] = []

    if fresh and cp.exists():
        cp.clear()
        print(f"  {Fore.YELLOW}--fresh: vorhandener Checkpoint gelöscht.{Style.RESET_ALL}\n")
    elif cp.exists():
        snapshot = cp.load()
        if snapshot:
            age = cp.age_hours()
            results = snapshot.get("results", {}) or {}
            completed = snapshot.get("_meta", {}).get("completed_modules", []) or []
            print(f"\n  {Fore.GREEN}↻ Checkpoint gefunden{Style.RESET_ALL} "
                  f"(vor {age:.1f}h, {len(completed)} Module abgeschlossen)")
            print(f"  {Style.BRIGHT}Resume:{Style.RESET_ALL} überspringe Module "
                  f"{completed if completed else 'keine'} — "
                  f"setze fort bei {[m for m in selected_modules if m not in completed]}\n")
            print(f"  {Fore.YELLOW}Mit --fresh starten falls du komplett neu willst.{Style.RESET_ALL}\n")

    # Display scan config
    print(f"\n  {Style.BRIGHT}Target Domain:{Style.RESET_ALL}  {Fore.CYAN}{domain}{Style.RESET_ALL}")
    print(f"  {Style.BRIGHT}Modules:{Style.RESET_ALL}        {', '.join(str(m) for m in selected_modules)}")
    print(f"  {Style.BRIGHT}Stealth:{Style.RESET_ALL}        {'✓ ACTIVE' if stealth else '✗ OFF'}")
    print(f"  {Style.BRIGHT}Checkpoint:{Style.RESET_ALL}     {cp.path}")
    print()
    print(f"  {Style.BRIGHT}API Key Status:{Style.RESET_ALL}")
    for name, key in config.API_KEYS.items():
        status = f"{Fore.GREEN}✓ configured{Style.RESET_ALL}" if key else f"{Fore.YELLOW}○ not set{Style.RESET_ALL}"
        print(f"    {name:25s} {status}")
    print()

    # ── Run scan ──
    start_time = time.time()

    for module_num in selected_modules:
        if module_num in completed:
            log.info(f"⤳ Module {module_num} bereits im Checkpoint — überspringe")
            continue

        result_key = RESULT_KEYS[module_num]

        # Per-endpoint checkpoint hook for long-running modules (only Module 11)
        def _on_progress(partial, hint, _key=result_key):
            results[_key] = partial
            cp.save(results, completed, current_module=module_num, phase=hint)

        try:
            results[result_key] = run_module(module_num, domain, results,
                                             on_progress=_on_progress)
            completed.append(module_num)
            cp.save(results, completed, current_module=None)
        except KeyboardInterrupt:
            print(f"\n  {Fore.YELLOW}⚠ Scan abgebrochen (Ctrl+C){Style.RESET_ALL}")
            print(f"  Zwischenstand gespeichert: {cp.path}")
            print(f"  Mit dem gleichen Befehl ohne --fresh fortsetzen.\n")
            raise SystemExit(130)

    elapsed = time.time() - start_time

    # ── Generate report ──
    print_section("REPORT GENERATION")

    generator = ReportGenerator(domain, results)
    generated_files = []

    filepath = generator.generate_json(outdir)
    generated_files.append(filepath)

    try:
        html_path = generator.generate_html(outdir)
        generated_files.append(html_path)
    except Exception as exc:
        log.error(f"HTML report failed: {exc}")

    try:
        pdf_path = generator.generate_pdf(outdir)
        generated_files.append(pdf_path)
    except Exception as exc:
        log.error(f"PDF report failed: {exc}")

    # ── State Tracker & Continuous Diffing ──
    print_section("STATE TRACKING (CONTINUOUS EASM)")
    from state_manager import StateTracker
    tracker = StateTracker()
    tracker.handle_diffing(domain, results)

    # Final report written → checkpoint no longer needed
    cp.clear()

    # ── Summary ──
    print()
    print(f"{'═' * 60}")
    print(f"  {Style.BRIGHT}SCAN COMPLETED{Style.RESET_ALL}")
    print(f"{'═' * 60}")
    print(f"  Domain:    {domain}")
    print(f"  Duration:  {elapsed:.1f} seconds")
    print(f"  Modules:   {len(selected_modules)} executed")
    print()
    print(f"  {Style.BRIGHT}Generated Reports:{Style.RESET_ALL}")
    for f in generated_files:
        print(f"    → {Fore.GREEN}{f}{Style.RESET_ALL}")
    print(f"{'═' * 60}")


def main():
    """Main function of the EASM Scanner."""
    args = parse_args()

    # Logging-Level
    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
        for handler in logging.getLogger().handlers:
            handler.setLevel(logging.DEBUG)

    # ══════════════════════════════════════════════════════════
    # No domain given → launch interactive TUI
    # ══════════════════════════════════════════════════════════
    if args.domain is None:
        try:
            from tui import run_tui
            tui_config = run_tui()
            
            if tui_config is None:
                print(f"\n  {Fore.YELLOW}Cancelled.{Style.RESET_ALL}")
                sys.exit(0)
            
            execute_scan(
                domain=tui_config["domain"],
                selected_modules=tui_config["modules"],
                stealth=tui_config["stealth"],
                exploit=tui_config["exploit"],
                outdir=args.outdir,
                fresh=args.fresh,
            )
        except ImportError as e:
            print(f"{Fore.RED}TUI could not be loaded: {e}{Style.RESET_ALL}")
            print(f"Use instead: python main.py --domain example.com")
            sys.exit(1)
        return

    # ══════════════════════════════════════════════════════════
    # CLI mode
    # ══════════════════════════════════════════════════════════
    domain = args.domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
    if "/" in domain:
        domain = domain.split("/")[0]

    # Parse modules
    try:
        selected_modules = sorted(set(int(m.strip()) for m in args.modules.split(",")))
    except ValueError:
        print(f"{Fore.RED}Invalid module format. Example: --modules 1,2,3{Style.RESET_ALL}")
        sys.exit(1)

    for m in selected_modules:
        if m not in MODULE_REGISTRY:
            print(f"{Fore.RED}Invalid module: {m}. Valid modules: 1-{max(MODULE_REGISTRY)}{Style.RESET_ALL}")
            sys.exit(1)

    # Module 11 (active exploitation) requires --exploit confirmation
    if 11 in selected_modules and not args.exploit:
        print(f"{Fore.RED}Module 11 (Exploitation) requires the --exploit flag for safety.{Style.RESET_ALL}")
        sys.exit(1)
    if args.exploit and 11 not in selected_modules:
        selected_modules = sorted(set(selected_modules + [11]))

    execute_scan(
        domain=domain,
        selected_modules=selected_modules,
        stealth=args.stealth,
        exploit=args.exploit,
        outdir=args.outdir,
        fresh=args.fresh,
    )


if __name__ == "__main__":
    main()
