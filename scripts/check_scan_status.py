import json
import os
import sys

import httpx
from dotenv import load_dotenv

load_dotenv(".env.local")
load_dotenv(".env")

API_BASE = os.getenv("CONTROLLER_API_ENDPOINT", "https://axiom-xjkc.onrender.com").rstrip("/")
OPERATOR_KEY = os.getenv("API_KEY", "Jf2T0sTy0IauJ6ELjLWAibC9-EpFo5LXwneztTBeyAU")
SCAN_ID = "31cf7010-a1ce-40c3-a2d6-4b08656c2d8c"

print("=" * 65)
print("CHECKING CLOUD SCAN STATUS & RESULTS")
print(f"API Endpoint: {API_BASE}")
print(f"Scan Job ID:  {SCAN_ID}")
print("=" * 65)

client = httpx.Client(timeout=30)

# 1. Fetch scan status
try:
    res = client.get(
        f"{API_BASE}/v1/scans/{SCAN_ID}",
        headers={"X-API-Key": OPERATOR_KEY}
    )
    if res.status_code != 200:
        print(f"[-] Failed to fetch scan status: {res.status_code} {res.text}")
        sys.exit(1)

    scan_data = res.json()
    status = scan_data.get("status")
    print(f"\n[+] Current Scan Status: {status.upper()}")
    print(f"    Target:  {scan_data.get('target', {}).get('value', 'unknown')}")
    print(f"    Profile: {scan_data.get('profile')}")
    print(f"    Created: {scan_data.get('created_at')}")

    if status == "completed":
        print("\n[+] SUCCESS! Cloud runner picked up and completed the job.")
        # 2. Fetch results
        r_res = client.get(
            f"{API_BASE}/v1/scans/{SCAN_ID}/result",
            headers={"X-API-Key": OPERATOR_KEY}
        )
        if r_res.status_code == 200:
            result = r_res.json()
            summary = result.get("summary", {})
            print("\n" + "=" * 65)
            print("                 NORMALIZED SCAN FINDINGS")
            print("=" * 65)
            print(f"Live Hosts Found:     {summary.get('live_hosts_count', 0)}")
            print(f"HTTP Status Codes:    {json.dumps(summary.get('status_codes', {}))}")
            print(f"Web Servers Detected: {', '.join(summary.get('web_servers', [])) or 'None'}")
            print(f"Page Titles:          {', '.join(summary.get('titles', [])) or 'None'}")
            print(f"Technologies:         {', '.join(summary.get('technologies', [])) or 'None'}")
            print("=" * 65)
        else:
            print(f"[-] Could not retrieve result payload: {r_res.status_code} {r_res.text}")
    elif status == "running":
        print("\n[i] Scan is currently RUNNING in GitHub Cloud Actions! Please check back in a moment.")
    elif status == "failed":
        print(f"\n[-] Scan failed in cloud. Failure Reason: {scan_data.get('failure_reason')}")
    else:
        print(f"\n[i] Scan is still in '{status.upper()}' state. GitHub Actions may take 10-30s to spin up the VM.")

except Exception as exc:
    print(f"[-] Error querying API: {exc}")
    sys.exit(1)
