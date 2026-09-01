import json
import time
import urllib.request

# --- Configuration ---
API_BASE = "https://axiom-xjkc.onrender.com"

# Render Keys
API_KEY = "Jf2T0sTy0IauJ6ELjLWAibC9-EpFo5LXwneztTBeyAU"
ADMIN_API_KEY = "nBK_0V8AQVDZmC6gTpgkTn04t7Gx2IYSYiPvdT5zymU"

# Use a safe placeholder target
TARGET_IP = "alphamothers.com"

HEADERS = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY
}

ADMIN_HEADERS = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
    'X-API-Key': ADMIN_API_KEY
}

PROFILES = [
    "recon",
    "web-discovery",
    "network-portscan",
    "fast-portscan",
    "content-discovery",
    "vuln-assessment"
]

def make_request(method, endpoint, data=None, headers=HEADERS):
    req = urllib.request.Request(
        f"{API_BASE}{endpoint}",
        data=json.dumps(data).encode() if data else None,
        headers=headers,
        method=method
    )
    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read())
    except urllib.error.HTTPError as e:
        print(f"HTTP Error {e.code}: {e.read().decode()}")
        return None
    except Exception as e:
        print(f"Error connecting: {e}")
        return None

# 1. Check Health
print("Checking API Health...")
health = make_request("GET", "/health")
print(f"Health: {health}\n")

if not health:
    print("Could not reach the Render API. Exiting.")
    exit(1)

# 2. Register Target (Requires ADMIN Headers)
print(f"Registering target: {TARGET_IP}")
target = make_request("POST", "/v1/targets", {
    "value": TARGET_IP,
    "owner_reference": "Render-Test",
    "authorization_reference": "AUTH-TEST"
}, headers=ADMIN_HEADERS)

if not target:
    print("Failed to register target.")
    exit(1)

target_id = target["id"]
print(f"Target ID: {target_id}\n")

# 3. Queue Scans
scan_ids = {}
for profile in PROFILES:
    print(f"Queueing {profile} scan...")
    scan = make_request("POST", "/v1/scans", {
        "target_id": target_id,
        "profile": profile
    })
    if scan:
        scan_ids[profile] = scan["id"]
        print(f"  -> Success! Scan ID: {scan['id']}")

# 4. Check Statuses
print("\nWaiting 15 seconds for controller to pick up jobs...\n")
time.sleep(15)

for profile, scan_id in scan_ids.items():
    status = make_request("GET", f"/v1/scans/{scan_id}")
    if status:
        print(f"[{profile}] Status: {status['status']}")

        # If complete, fetch results
        if status['status'] == 'completed':
            result = make_request("GET", f"/v1/scans/{scan_id}/result")
            if result:
                total_findings = result.get('summary', {}).get('risk_summary', {}).get('total', 0)
                print(f"  -> Result retrieved successfully! (Total Findings: {total_findings})")

# all session scan results
print("\nAll session scan results:")
for profile, scan_id in scan_ids.items():
    result = make_request("GET", f"/v1/scans/{scan_id}/result")
    if result:
        total_findings = result.get('summary', {}).get('risk_summary', {}).get('total', 0)
        print(f"[{profile}] (Total Findings: {total_findings})")


