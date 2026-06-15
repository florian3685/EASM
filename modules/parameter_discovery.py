"""
EASM Scanner — Modul 8: Parameter Discovery & Fuzzing
=======================================================
Nutzt historische Wege (Wayback) und bekannte Endpunkte von der Attack Surface,
um mit dem Tool 'Arjun' nach versteckten, unausgewerteten HTTP-Parametern zu suchen.
"""

import os
import json
import subprocess
import tempfile
import urllib.parse
from utils import get_logger, print_progress

log = get_logger("easm.parameter_discovery")

def _run_arjun(url: str) -> list[dict]:
    """Startet arjun als Subprozess für eine einzelne URL."""
    found_params = []
    
    try:
        with tempfile.NamedTemporaryFile("r", delete=False) as tf:
            out_file = tf.name
            
        # Arjun args: -u (URL), -oJ (JSON), -t (Threads), -T (Timeout/Delay)
        cmd = ["arjun", "-u", url, "-oJ", out_file, "-t", "5", "--passive", "-"]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        
        if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
            with open(out_file, "r") as f:
                data = json.load(f)
                # Arjun format for JSON is: {"http://target.com": {"param1": {"method": "GET"}, ...}}
                # Oder neuere Versionen: { "url": "http..", "params": ["id", "admin"] }
                for entry_url, params_data in data.items():
                    if isinstance(params_data, dict):
                        for param_name, method_info in params_data.items():
                            found_params.append({
                                "url": url,
                                "parameter": param_name,
                            })
                    elif isinstance(params_data, list):
                         for p in params_data:
                             found_params.append({
                                "url": url,
                                "parameter": p,
                            })
                            
        os.remove(out_file)
    except FileNotFoundError:
        log.warning("Tool 'arjun' fehlt (pip install arjun). Parameter Fuzzing übersprungen.")
    except Exception as exc:
        log.debug(f"Arjun Fehler für {url}: {exc}")
        
    return found_params


def extract_fuzzable_urls(domain: str) -> list[str]:
    """Sucht nach Endpunkten, die Parameter akzeptieren könnten (.php, /api/, etc)."""
    # Da Modul 7 die Wayback URLs bereits liest, rufen wir hier zur Einfachheit
    # direkt einen schnellen Wayback Check auf oder kombinieren es später in main.py.
    # Einfachster Weg Modulübergreifend: Wir fragen Wayback CDX ab nach .php und /api/
    urls = []
    cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=200"
    import requests
    try:
        resp = requests.get(cdx_url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:
                for row in data[1:]:
                    u = row[0]
                    # Nur URLs, die wie APIs / Scripte aussehen
                    if any(x in u.lower() for x in [".php", ".jsp", ".asp", "/api/", "/graphql", "/v1/"]):
                        parsed = urllib.parse.urlparse(u)
                        base_u = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        urls.append(base_u)
    except Exception:
        pass
        
    return list(set(urls))[:10]  # Max 10 URLs fuzzen um Zeit zu sparen


# ═════════════════════════════════════════════════════════════════════════════
#  Hauptfunktion Modul 8
# ═════════════════════════════════════════════════════════════════════════════

def run(domain: str) -> dict:
    """Führt Hidden Parameter Fuzzing aus."""
    print_progress("Parameter Discovery", "Sammle fuzzbare Endpunkte (APIs/PHP/ASP) …")
    target_urls = extract_fuzzable_urls(domain)
    
    # Füge Hauptdomain hinzu als Fallback
    target_urls.append(f"https://{domain}/")
    target_urls = list(set(target_urls))
    
    hidden_parameters = []
    
    log.info(f"  Fuzze {len(target_urls)} Endpunkte nach versteckten Parametern...")
    for target in target_urls:
        params = _run_arjun(target)
        for p in params:
             log.critical(f"  🔴 VERSTECKTER PARAMETER ENTDECKT: {p['url']} -> ?{p['parameter']}=")
             hidden_parameters.append(p)
             
    if not hidden_parameters:
        log.info("  Keine versteckten Parameter gefunden.")
        
    return {
        "hidden_parameters": hidden_parameters
    }
