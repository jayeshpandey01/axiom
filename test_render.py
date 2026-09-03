import json
import os
import time
import urllib.request

# --- Configuration ---
API_BASE = os.getenv("API_BASE_URL", "https://axiom-xjkc.onrender.com")

# Render Keys
API_KEY = os.getenv("API_KEY", "Jf2T0sTy0IauJ6ELjLWAibC9-EpFo5LXwneztTBeyAU")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "nBK_0V8AQVDZmC6gTpgkTn04t7Gx2IYSYiPvdT5zymU")

# Use a safe placeholder target
TARGET_IP = os.getenv("TARGET_HOST", "portfoliojayesh.netlify.app")


HEADERS = {"accept": "application/json", "Content-Type": "application/json", "X-API-Key": API_KEY}

ADMIN_HEADERS = {"accept": "application/json", "Content-Type": "application/json", "X-API-Key": ADMIN_API_KEY}

PROFILES = ["recon", "web-discovery", "network-portscan", "fast-portscan", "content-discovery", "vuln-assessment"]


def make_request(method, endpoint, data=None, headers=HEADERS):
    req = urllib.request.Request(f"{API_BASE}{endpoint}", data=json.dumps(data).encode() if data else None, headers=headers, method=method)
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
target = make_request(
    "POST",
    "/v1/targets",
    {"value": TARGET_IP, "owner_reference": "Render-Test", "authorization_reference": "AUTH-TEST"},
    headers=ADMIN_HEADERS,
)

if not target:
    print("Failed to register target.")
    exit(1)

target_id = target["id"]
print(f"Target ID: {target_id}\n")

# 3. Queue Scans
scan_ids = {}
for profile in PROFILES:
    print(f"Queueing {profile} scan...")
    scan = make_request("POST", "/v1/scans", {"target_id": target_id, "profile": profile})
    if scan:
        scan_ids[profile] = scan["id"]
        print(f"  -> Success! Scan ID: {scan['id']}")

# 4. Poll Statuses until Complete
print("\nWaiting for cloud runner to process scans (polling every 5 seconds)...")
pending = set(scan_ids.keys())
timeout = 180  # 3 minutes max
start_time = time.time()

while pending and (time.time() - start_time) < timeout:
    time.sleep(5)
    for profile in list(pending):
        scan_id = scan_ids[profile]
        status = make_request("GET", f"/v1/scans/{scan_id}")
        if status:
            curr_status = status.get("status")
            print(f"[{profile}] Status: {curr_status}")
            if curr_status in ("completed", "failed"):
                pending.remove(profile)

# 5. Fetch Final Results
print("\n--- Final Scan Results ---")
for profile, scan_id in scan_ids.items():
    result = make_request("GET", f"/v1/scans/{scan_id}/result")
    if result:
        summary = result.get("summary", {})
        risk = summary.get("risk_summary", {})
        total_findings = risk.get("total", len(summary.get("findings", [])))
        print(
            f"[{profile}] Completed successfully! -> Total Findings: {total_findings} (Critical: {risk.get('critical', 0)}, High: {risk.get('high', 0)}, Medium: {risk.get('medium', 0)}, Low: {risk.get('low', 0)}, Info: {risk.get('info', 0)})"
        )
