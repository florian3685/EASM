"""
EASM Scanner — Modul 9: GitHub Reconnaissance
================================================
Sucht über die GitHub Search API nach Repositories der Zieldomain,
um Source-Code Leaks, Konfigurationen und Secrets zu entdecken.
"""

import time
import requests
import json
from urllib.parse import quote

import config
from utils import get_logger, print_progress, http_get

log = get_logger("easm.github_recon")


def search_github_repos(domain: str) -> list[dict]:
    """Nutzt die GitHub API, um nach Code-Leaks und Repos zu suchen."""
    print_progress("GitHub Recon", "Sucht GitHub Repositories und Source-Leaks …")
    found_repos = []
    
    github_token = config.API_KEYS.get("github")
    headers = {"Accept": "application/vnd.github.v3+json"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    else:
        log.warning("Kein GITHUB_TOKEN konfiguriert. Erwarte strenges Rate-Limiting!")

    # Wir suchen nach der Domain im Code oder als Organisation
    org_name = domain.split(".")[0]
    query = quote(f"org:{org_name} OR {domain}")
    url = f"https://api.github.com/search/code?q={query}&per_page=10"
    
    try:
        # Code Suche (benötigt auth typischerweise für Code-Search, oder geht manchmal so)
        # Besser wir suchen erstmal Repositories um Rate-Limits zu schonen
        repo_query = quote(f"{org_name} OR {domain}")
        repo_url = f"https://api.github.com/search/repositories?q={repo_query}&per_page=15"
        
        # httpx wrapper (ohne Jitter, da API direkt)
        resp = requests.get(repo_url, headers=headers, timeout=config.HTTP_TIMEOUT)
        
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("items", []):
                # Wir checken, ob es wirklich Bezug zur Domain hat
                desc = str(item.get("description", "")).lower()
                name = str(item.get("name", "")).lower()
                owner = str(item.get("owner", {}).get("login", "")).lower()
                
                if org_name in name or org_name in desc or org_name in owner:
                    found_repos.append({
                        "name": item.get("full_name"),
                        "url": item.get("html_url"),
                        "description": item.get("description"),
                        "is_fork": item.get("fork"),
                        "language": item.get("language"),
                        "stars": item.get("stargazers_count")
                    })
        elif resp.status_code == 403:
            log.warning("GitHub API Rate-Limit erreicht oder Token ungültig.")
        else:
            log.debug(f"GitHub Search Fail: {resp.status_code}")
            
    except Exception as exc:
        log.debug(f"GitHub Recon Fehler: {exc}")

    if found_repos:
        log.info(f"  {len(found_repos)} potenzielle GitHub Repositories gefunden.")
    else:
        log.info("  Keine direkten GitHub Repositories gefunden.")
        
    return found_repos


def search_github_secrets(domain: str) -> list[dict]:
    """Suche über die Code API nach typischen Secrets (keys, passwords, env)."""
    # Dies ist sehr rate-limited. Nur machen, wenn Token da ist.
    github_token = config.API_KEYS.get("github")
    if not github_token:
        return []
        
    print_progress("GitHub Recon", "Deep-Scraping nach hardcodierten Secrets …")
    found_secrets = []
    headers = {"Accept": "application/vnd.github.v3+json", "Authorization": f"token {github_token}"}
    
    org_name = domain.split(".")[0]
    
    # Kritische Keywords
    keywords = ["password", "secret", "api_key", "token", "credentials", "aws_access_key"]
    
    try:
        # Nur eine Query ausführen, um Limit-Ban zu vermeiden
        query = quote(f"{org_name} password OR token OR secret")
        search_url = f"https://api.github.com/search/code?q={query}&per_page=5"
        
        resp = requests.get(search_url, headers=headers, timeout=config.HTTP_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("items", []):
                file_name = str(item.get("name", "")).lower()
                # Nur interessante Dateien
                if any(ext in file_name for ext in [".py", ".php", ".env", ".json", ".yml", ".ts", ".js"]):
                    url = item.get("html_url")
                    found_secrets.append({
                        "file": item.get("name"),
                        "repository": item.get("repository", {}).get("full_name"),
                        "url": url,
                        "assessment": "CRITICAL: Hardcodierte Secrets in Source-Code vermutet."
                    })
                    log.critical(f"  🔴 SOURCE LEAK VERMUTET: {url}")
            
        time.sleep(2) # Respektiere API Abuse Rate Limits
    except Exception as exc:
        log.debug(f"GitHub Secret Fuzz Fehler: {exc}")

    return found_secrets


# ═════════════════════════════════════════════════════════════════════════════
#  Hauptfunktion Modul 9
# ═════════════════════════════════════════════════════════════════════════════

def run(domain: str) -> dict:
    """Führt Modul 9 (GitHub Reconnaissance) aus."""
    repos = search_github_repos(domain)
    secrets = search_github_secrets(domain)
    
    return {
        "repositories_discovered": repos,
        "potential_secrets_leaked": secrets,
    }
