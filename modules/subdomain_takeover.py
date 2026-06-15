"""
EASM Scanner — Module 12: Subdomain Takeover Detection
========================================================
Detects dangling DNS records (CNAME/A) pointing to unclaimed
cloud services that an attacker could re-claim and take over.

Methodology:
  1. For each subdomain, resolve CNAME chain.
  2. If CNAME points to a known SaaS provider (S3, GitHub Pages,
     Heroku, Azure, Shopify, …) and the response page contains a
     known "not claimed" fingerprint → vulnerable.
  3. Also detect dangling A-records (NXDOMAIN on CNAME target).
"""

from __future__ import annotations

import concurrent.futures as cf
from typing import Iterable

import dns.resolver
import dns.exception

from utils import get_logger, http_get, print_progress

log = get_logger("easm.subdomain_takeover")


# Each entry: keywords in CNAME → (service name, fingerprint to look for in HTTP body)
# Fingerprints derived from public can-i-take-over-xyz dataset.
TAKEOVER_SIGNATURES = [
    # AWS S3
    ("s3.amazonaws.com",        "AWS S3",        "NoSuchBucket"),
    ("s3-website",              "AWS S3",        "NoSuchBucket"),
    # GitHub Pages
    ("github.io",               "GitHub Pages",  "There isn't a GitHub Pages site here"),
    # Heroku
    ("herokuapp.com",           "Heroku",        "No such app"),
    ("herokudns.com",           "Heroku",        "No such app"),
    # Azure
    ("azurewebsites.net",       "Azure",         "404 Web Site not found"),
    ("cloudapp.net",            "Azure",         "404 Web Site not found"),
    ("trafficmanager.net",      "Azure",         "404 Web Site not found"),
    ("blob.core.windows.net",   "Azure Blob",    "BlobNotFound"),
    # Shopify
    ("myshopify.com",           "Shopify",       "Sorry, this shop is currently unavailable"),
    # Fastly
    ("fastly.net",              "Fastly",        "Fastly error: unknown domain"),
    # Pantheon
    ("pantheonsite.io",         "Pantheon",      "The gods are wise, but do not know of the site which you seek."),
    # Tumblr
    ("domains.tumblr.com",      "Tumblr",        "Whatever you were looking for doesn't currently exist"),
    # Wordpress
    ("wordpress.com",           "WordPress",     "Do you want to register"),
    # Surge
    ("surge.sh",                "Surge",         "project not found"),
    # Bitbucket
    ("bitbucket.io",            "Bitbucket",     "Repository not found"),
    # Ghost
    ("ghost.io",                "Ghost",         "The thing you were looking for is no longer here"),
    # Helpjuice
    ("helpjuice.com",           "Helpjuice",     "We could not find what you're looking for"),
    # Helpscout
    ("helpscoutdocs.com",       "HelpScout",     "No settings were found for this company"),
    # Cargo
    ("cargocollective.com",     "Cargo",         "404 Not Found"),
    # Statuspage
    ("statuspage.io",           "Statuspage",    "You are being <a href"),
    # Tilda
    ("tilda.ws",                "Tilda",         "Please renew your subscription"),
    # Unbounce
    ("unbouncepages.com",       "Unbounce",      "The requested URL was not found on this server"),
    # Webflow
    ("proxy.webflow.com",       "Webflow",       "The page you are looking for doesn't exist or has been moved"),
    # Smartling
    ("smartling.com",           "Smartling",     "Domain is not configured"),
    # Readme
    ("readme.io",               "Readme.io",     "Project doesnt exist... yet!"),
    # Zendesk
    ("zendesk.com",             "Zendesk",       "Help Center Closed"),
    # Vercel
    ("vercel.app",              "Vercel",        "DEPLOYMENT_NOT_FOUND"),
    ("now.sh",                  "Vercel/Now",    "DEPLOYMENT_NOT_FOUND"),
    # Netlify
    ("netlify.app",             "Netlify",       "Not Found - Request ID"),
    ("netlify.com",             "Netlify",       "Not Found - Request ID"),
]


def _get_cname(host: str) -> str | None:
    try:
        ans = dns.resolver.resolve(host, "CNAME", lifetime=4)
        for r in ans:
            return str(r.target).rstrip(".").lower()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.exception.DNSException):
        return None
    return None


def _resolves(host: str) -> bool:
    try:
        dns.resolver.resolve(host, "A", lifetime=3)
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.exception.DNSException):
        return False


def _check_one(subdomain: str) -> dict | None:
    cname = _get_cname(subdomain)
    if not cname:
        return None

    # Match against signature list
    matched = None
    for keyword, service, fingerprint in TAKEOVER_SIGNATURES:
        if keyword in cname:
            matched = (service, fingerprint, keyword)
            break
    if not matched:
        return None

    service, fingerprint, keyword = matched

    # Strong signal: the CNAME target itself doesn't resolve → almost certainly takeover
    if not _resolves(cname):
        return {
            "subdomain": subdomain,
            "cname": cname,
            "service": service,
            "reason": f"CNAME target {cname} does not resolve (NXDOMAIN).",
            "evidence": "dangling_cname",
            "severity": "CRITICAL",
        }

    # Weak signal: target resolves, check HTTP body for the unclaimed-fingerprint
    for scheme in ("https", "http"):
        try:
            resp = http_get(f"{scheme}://{subdomain}", timeout=10, verify_ssl=False)
            if resp and fingerprint.lower() in (resp.text or "").lower():
                return {
                    "subdomain": subdomain,
                    "cname": cname,
                    "service": service,
                    "reason": f"Page returned the '{service}' unclaimed-fingerprint.",
                    "evidence": fingerprint,
                    "severity": "CRITICAL",
                }
        except Exception:
            continue

    # Found a CNAME to a known service but no clear takeover signal → suspicious
    return {
        "subdomain": subdomain,
        "cname": cname,
        "service": service,
        "reason": "CNAME points to a known SaaS provider — verify ownership.",
        "evidence": "suspicious_cname",
        "severity": "MEDIUM",
    }


def check_takeovers(subdomains: Iterable[str], max_workers: int = 20) -> list[dict]:
    subs = list(subdomains)
    findings: list[dict] = []
    if not subs:
        return findings
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for res in ex.map(_check_one, subs):
            if res:
                findings.append(res)
    return findings


def run(domain: str) -> dict:
    """Module entry point — needs subdomains from attack_surface."""
    print_progress("Subdomain Takeover", "Resolving CNAMEs and checking for unclaimed services …")

    # Re-enumerate quickly (cheap CT-only fetch) to keep this module self-contained.
    from modules.subdomain_enum import enumerate_all
    subs = enumerate_all(domain, bruteforce=False, permute=False, validate=True,
                        max_workers=20)["subdomains"]

    vulnerable = check_takeovers(subs)
    log.info(f"Subdomain Takeover Scan: {len(vulnerable)} suspicious / vulnerable entries")

    return {
        "checked": len(subs),
        "vulnerable": vulnerable,
    }
