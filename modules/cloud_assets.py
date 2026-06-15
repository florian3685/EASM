"""
EASM Scanner — Modul 10: Cloud Asset Escalation
=================================================
Identifiziert und prüft ungeschützte Cloud-Speicher (AWS S3, Azure Blob, GCP)
auf Basis von Domain-Permutationen, um "Missing Access Control" aufzuzeigen.
"""

import httpx
from utils import get_logger, print_progress
import config

log = get_logger("easm.cloud_assets")

# Typische Suffixe/Präfixe für Firmen-Buckets
PERMUTATIONS = [
    "", "-dev", "-prod", "-staging", "-backup", "-assets", "-static",
    "-media", "-public", "-private", "-test", "dev-", "prod-"
]

def generate_bucket_names(domain: str) -> list[str]:
    """Generiert typische Bucket-Namen basierend auf der Domain."""
    base = domain.split(".")[0]
    names = []
    for p in PERMUTATIONS:
        names.append(f"{base}{p}")
        # Manchmal auch die ganze Domain als Name
        names.append(f"{domain.replace('.', '-')}{p}")
    return list(set(names))


def check_aws_s3(bucket_name: str) -> dict:
    """Prüft, ob der S3 Bucket existiert und ob er 'ListBucketResult' zulässt."""
    url = f"https://{bucket_name}.s3.amazonaws.com/"
    
    # httpx Head-Check für schnelle Filterung
    try:
        with httpx.Client(verify=False, follow_redirects=True) as client:
            resp = client.get(url, timeout=4)
            # Wenn 404 (NoSuchBucket), existiert er nicht
            if resp.status_code == 404:
                return None
                
            # Wenn 200, ist das Listing aktiviert! (EXTREM KRITISCH)
            if resp.status_code == 200 and "ListBucketResult" in resp.text:
                return {
                    "bucket_name": bucket_name,
                    "provider": "AWS S3",
                    "url": url,
                    "status": "OPEN",
                    "assessment": "CRITICAL: Bucket Listing Enabled. Data Exfiltration möglich!"
                }
            # Wenn 403 (AccessDenied), gehört er meistens jemandem (Existenz bewiesen)
            elif resp.status_code == 403:
                return {
                    "bucket_name": bucket_name,
                    "provider": "AWS S3",
                    "url": url,
                    "status": "PROTECTED",
                    "assessment": "WARNING: Bucket existiert, Listing blockiert, aber Objekte potentiell aufrufbar."
                }
    except Exception:
        pass
    return None


def check_azure_blob(bucket_name: str) -> dict:
    """Prüft, ob der Azure Blob Container existiert."""
    url = f"https://{bucket_name}.blob.core.windows.net/?comp=list"
    try:
        with httpx.Client(verify=False) as client:
            resp = client.get(url, timeout=4)
            if resp.status_code == 404 or "Server failed to authenticate" in resp.text:
                return None
            
            if resp.status_code == 200 and "EnumerationResults" in resp.text:
                return {
                    "bucket_name": bucket_name,
                    "provider": "Azure Blob",
                    "url": url,
                    "status": "OPEN",
                    "assessment": "CRITICAL: Blob Listing Enabled. Data Exfiltration möglich!"
                }
            elif resp.status_code in [403, 400]:
                return {
                     "bucket_name": bucket_name,
                     "provider": "Azure Blob",
                     "url": url.split("?")[0],
                     "status": "PROTECTED",
                     "assessment": "WARNING: Container existiert, Listing blockiert."
                }
    except Exception:
        pass
    return None


def check_gcp_bucket(bucket_name: str) -> dict:
    """Prüft, ob ein Google Cloud Storage Bucket existiert."""
    url = f"https://storage.googleapis.com/{bucket_name}/"
    try:
        with httpx.Client(verify=False) as client:
            resp = client.get(url, timeout=4)
            if resp.status_code == 404:
                return None
                
            if resp.status_code == 200 and "ListBucketResult" in resp.text:
                return {
                    "bucket_name": bucket_name,
                    "provider": "GCP Storage",
                    "url": url,
                    "status": "OPEN",
                    "assessment": "CRITICAL: GCP Bucket Listing Enabled!"
                }
            elif resp.status_code in [401, 403]:
                return {
                     "bucket_name": bucket_name,
                     "provider": "GCP Storage",
                     "url": url,
                     "status": "PROTECTED",
                     "assessment": "WARNING: GCP Bucket existiert, Listing blockiert."
                }
    except Exception:
        pass
    return None


# ═════════════════════════════════════════════════════════════════════════════
#  Hauptfunktion Modul 10
# ═════════════════════════════════════════════════════════════════════════════

def run(domain: str) -> dict:
    """Führt Modul 10 (Cloud Asset Escalation) aus."""
    print_progress("Cloud Assets", "Generiere Bucket-Permutationen und fuzze Cloud Provider …")
    found_buckets = []
    
    names = generate_bucket_names(domain)
    log.info(f"  Fuzze {len(names)} Permutationen gegen AWS, Azure und GCP...")
    
    import concurrent.futures

    # Asynchrones Fuzzing für Geschwindigkeit
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Submit AWS S3
        future_to_bucket = {executor.submit(check_aws_s3, name): name for name in names}
        for future in concurrent.futures.as_completed(future_to_bucket):
            res = future.result()
            if res:
                found_buckets.append(res)
                if res["status"] == "OPEN":
                    log.critical(f"  🔴 OPEN BUCKET GEFUNDEN: {res['url']}")
                else:
                    log.warning(f"  🟡 Protected Bucket gefunden: {res['url']}")

        # Submit Azure
        future_to_bucket = {executor.submit(check_azure_blob, name): name for name in names}
        for future in concurrent.futures.as_completed(future_to_bucket):
            res = future.result()
            if res:
                   found_buckets.append(res)
                   if res["status"] == "OPEN":
                       log.critical(f"  🔴 OPEN AZURE BLOB: {res['url']}")
                   else:
                       log.warning(f"  🟡 Protected Azure Blob: {res['url']}")
                       
        # Submit GCP
        future_to_bucket = {executor.submit(check_gcp_bucket, name): name for name in names}
        for future in concurrent.futures.as_completed(future_to_bucket):
            res = future.result()
            if res:
                   found_buckets.append(res)
                   if res["status"] == "OPEN":
                       log.critical(f"  🔴 OPEN GCP BUCKET: {res['url']}")
                   else:
                       log.warning(f"  🟡 Protected GCP Bucket: {res['url']}")

    if not found_buckets:
        log.info("  Keine assoziierten Cloud-Buckets gefunden.")

    open_buckets = [b for b in found_buckets if b.get("status") == "OPEN"]
    protected_buckets = [b for b in found_buckets if b.get("status") == "PROTECTED"]

    return {
        "open_buckets": open_buckets,
        "protected_buckets": protected_buckets,
    }
