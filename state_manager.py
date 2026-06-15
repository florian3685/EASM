"""
EASM Scanner — State Diffing & Continuous Monitoring
======================================================
Verwaltet die Historie der Scans in einer SQLite-Datenbank.
Führt Diffs aus, um Benachrichtigungen bei Veränderungen auszulösen.
"""

import sqlite3
import json
import os
from datetime import datetime
from colorama import Fore, Style
from utils import get_logger, send_webhook_alert

log = get_logger("easm.state")

DB_PATH = "easm_state.db"

class StateTracker:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialisiert das Schema der State-Datenbank."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        scan_data TEXT NOT NULL
                    )
                ''')
                conn.commit()
        except Exception as exc:
            log.error(f"Datenbankfehler: {exc}")

    def get_last_scan(self, domain: str) -> dict:
        """Holt den letzten JSON-Report für eine Domain."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT scan_data FROM scan_history WHERE domain = ? ORDER BY timestamp DESC LIMIT 1",
                    (domain,)
                )
                row = cursor.fetchone()
                if row:
                    return json.loads(row[0])
        except Exception as exc:
            log.error(f"Kann alten State nicht laden: {exc}")
        return None

    def save_scan(self, domain: str, scan_data: dict):
        """Speichert den aktuellen Scan in der Historie."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO scan_history (domain, scan_data) VALUES (?, ?)",
                    (domain, json.dumps(scan_data))
                )
                conn.commit()
        except Exception as exc:
            log.error(f"Speichern des States fehlgeschlagen: {exc}")

    def diff_scans(self, domain: str, new_scan: dict) -> list[str]:
        """Gleicht neuen und alten Scan ab und gibt Alerts zurück."""
        old_scan = self.get_last_scan(domain)
        alerts = []
        
        if not old_scan:
            log.info("  Erster Scan für diese Domain, Basis-State gespeichert.")
            self.save_scan(domain, new_scan)
            return alerts

        old_atk = old_scan.get("attack_surface", {})
        new_atk = new_scan.get("attack_surface", {})

        # -- Subdomains Diffing --
        old_subs = set(old_atk.get("host_discovery", {}).get("subdomains", []))
        new_subs = set(new_atk.get("host_discovery", {}).get("subdomains", []))
        
        added_subs = new_subs - old_subs
        for sub in added_subs:
            alerts.append(f"🟢 **NEUE SUBDOMAIN:** {sub}")

        # -- Ports Diffing --
        def extract_ports(hosts: list) -> dict:
            port_map = {}
            for h in hosts:
                ip = h.get("ip", "")
                ports = [p.get("port") for p in h.get("open_ports", [])]
                if ip:
                    port_map[ip] = set(ports)
            return port_map

        old_ports = extract_ports(old_atk.get("open_ports", []))
        new_ports = extract_ports(new_atk.get("open_ports", []))

        for ip, n_ports in new_ports.items():
            o_ports = old_ports.get(ip, set())
            added_ports = n_ports - o_ports
            closed_ports = o_ports - n_ports
            
            for p in added_ports:
                alerts.append(f"🔴 **NEUER PORT GEÖFFNET:** {ip}:{p}")
            for p in closed_ports:
                alerts.append(f"🟢 **PORT GESCHLOSSEN:** {ip}:{p}")

        # -- CVEs Diffing --
        old_cves = set(c.get("cve_id") for c in old_atk.get("software_vulnerabilities", []) if c.get("cve_id"))
        new_cves = set(c.get("cve_id") for c in new_atk.get("software_vulnerabilities", []) if c.get("cve_id"))
        added_cves = new_cves - old_cves
        for cve in added_cves:
            alerts.append(f"🔴 **NEUE LÜCKE (CVE):** {cve} identifiziert!")

        # -- Nuclei Findings --
        old_findings = set(c.get("name") for c in old_atk.get("active_vulnerabilities", []) if c.get("name"))
        new_findings = set(c.get("name") for c in new_atk.get("active_vulnerabilities", []) if c.get("name"))
        added_findings = new_findings - old_findings
        for finding in added_findings:
            alerts.append(f"🔴 **NEUES NUCLEI FINDING:** {finding}")

        # -- Parameter Fuzzing Diffs (Modul 8) --
        old_adv = old_scan.get("advanced_recon", {})
        new_adv = new_scan.get("advanced_recon", {})
        old_params = set(p.get("url") + ": " + p.get("parameter") for p in old_adv.get("hidden_parameters", []))
        new_params = set(p.get("url") + ": " + p.get("parameter") for p in new_adv.get("hidden_parameters", []))
        added_params = new_params - old_params
        for p in added_params:
            alerts.append(f"🔴 **NEUER VERSTECKTER PARAMETER:** {p}")

        # -- Origin-IP (Shodan) Diffs --
        old_infra = old_scan.get("infrastructure_stability", {})
        new_infra = new_scan.get("infrastructure_stability", {})
        old_origins = set(o.get("ip") for o in old_infra.get("origin_ip_leaks", []))
        new_origins = set(o.get("ip") for o in new_infra.get("origin_ip_leaks", []))
        added_origins = new_origins - old_origins
        for ip in added_origins:
            alerts.append(f"🔴 **ORIGIN-IP LEAK (WAF BYPASS) ENTDECKT:** {ip}")

        # Speichern des aktuellen Zustands
        self.save_scan(domain, new_scan)

        return alerts

    def handle_diffing(self, domain: str, results: dict):
        """Wrapper, der Diffs generiert und Benachrichtigungen absendet."""
        alerts = self.diff_scans(domain, results)
        
        if not alerts:
            log.info("  Keine strukturellen Änderungen seit dem letzten Scan.")
            return

        print(f"\n{Fore.RED}{Style.BRIGHT}⚠ STATE-DIFF ALARMS ⚠{Style.RESET_ALL}")
        for alert in alerts:
            # Print to CLI
            clean_alert = alert.replace("**", "")
            print(f"  {clean_alert}")
            
        print()
        
        # Sende konsolidierten Alert an Discord/Slack
        message = "\n".join(alerts)
        is_crit = "🔴" in message
        send_webhook_alert(f"Scan für **{domain}** abgeschlossen. Änderungen festgestellt:\n{message}", is_critical=is_crit)
