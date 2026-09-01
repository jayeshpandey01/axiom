import os
import sys

import httpx
from dotenv import load_dotenv

load_dotenv(".env.local")
load_dotenv(".env")

API_BASE = os.getenv("CONTROLLER_API_ENDPOINT", "https://axiom-xjkc.onrender.com").rstrip("/")
ADMIN_KEY = os.getenv("ADMIN_API_KEY", "nBK_0V8AQVDZmC6gTpgkTn04t7Gx2IYSYiPvdT5zymU")
OPERATOR_KEY = os.getenv("API_KEY", "Jf2T0sTy0IauJ6ELjLWAibC9-EpFo5LXwneztTBeyAU")
TARGET_HOST = "scanme.nmap.org"
PROFILE = "recon"

print("=" * 65)
print("TESTING 24/7 CLOUD-NATIVE SCANNER (NO LOCAL CONTROLLER)")
print(f"API Endpoint: {API_BASE}")
print("=" * 65)

client = httpx.Client(timeout=30)

# 1. Health check
print("\n[1/4] Checking Render API Health...")
try:
    res = client.get(f"{API_BASE}/health")
    print(f"[+] API Status: {res.status_code} {res.json()}")
except Exception as e:
    print(f"[-] Failed to connect: {e}")
    sys.exit(1)

# 2. Register Target
print(f"\n[2/4] Registering Target '{TARGET_HOST}'...")
t_res = client.post(
    f"{API_BASE}/v1/targets",
    headers={"X-API-Key": ADMIN_KEY},
    json={"value": TARGET_HOST, "owner_reference": "Nmap Org", "authorization_reference": "AUTH-CLOUD-TEST-001"}
)
if t_res.status_code not in (200, 201):
    print(f"[-] Error registering target: {t_res.status_code} {t_res.text}")
    sys.exit(1)

target_id = t_res.json()["id"]
print(f"[+] Target Registered. Target ID: {target_id}")

# 3. Queue Scan Job
print(f"\n[3/4] Queuing Scan Job for profile '{PROFILE}'...")
s_res = client.post(
    f"{API_BASE}/v1/scans",
    headers={"X-API-Key": OPERATOR_KEY},
    json={"target_id": target_id, "profile": PROFILE}
)
if s_res.status_code != 202:
    print(f"[-] Error queuing scan: {s_res.status_code} {s_res.text}")
    sys.exit(1)

scan_data = s_res.json()
scan_id = scan_data["id"]
print("[+] Scan Job Successfully Queued!")
print(f"    Scan ID: {scan_id}")
print(f"    Status:  {scan_data['status'].upper()}")

print("\n" + "=" * 65)
print("JOB IS NOW WAITING IN THE CLOUD DATABASE.")
print("Now GitHub Cloud Actions will automatically pick it up!")
print("=" * 65)
