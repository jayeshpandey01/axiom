import os
import sys

import httpx
from dotenv import load_dotenv

load_dotenv(".env.local")
load_dotenv(".env")

API_BASE = os.getenv("CONTROLLER_API_ENDPOINT", "https://axiom-xjkc.onrender.com").rstrip("/")
ADMIN_KEY = os.getenv("ADMIN_API_KEY", "nBK_0V8AQVDZmC6gTpgkTn04t7Gx2IYSYiPvdT5zymU")
OPERATOR_KEY = os.getenv("API_KEY", "Jf2T0sTy0IauJ6ELjLWAibC9-EpFo5LXwneztTBeyAU")
TARGET = "testphp.vulnweb.com"
PROFILE = "recon"

client = httpx.Client(timeout=30)

print(f"Registering and scanning authorized test target: {TARGET}...")

# 1. Register target
t_res = client.post(
    f"{API_BASE}/v1/targets",
    headers={"X-API-Key": ADMIN_KEY},
    json={"value": TARGET, "owner_reference": "Acunetix Test Site", "authorization_reference": "AUTH-ACUNETIX-PUBLIC-TEST"},
)
if t_res.status_code not in (200, 201):
    print(f"Target registration response: {t_res.status_code} {t_res.text}")
    sys.exit(1)

target_id = t_res.json()["id"]
print(f"[+] Target Registered: {target_id}")

# 2. Queue scan
s_res = client.post(f"{API_BASE}/v1/scans", headers={"X-API-Key": OPERATOR_KEY}, json={"target_id": target_id, "profile": PROFILE})
if s_res.status_code != 202:
    print(f"Scan queue failed: {s_res.status_code} {s_res.text}")
    sys.exit(1)

scan_id = s_res.json()["id"]
print(f"[+] Scan Queued: {scan_id}")
print("[+] Ready for cloud execution verification!")
