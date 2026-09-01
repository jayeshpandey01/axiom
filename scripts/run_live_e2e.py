"""Live End-to-End Test Runner against the Deployed Scan Tool API & Controller.

Executes a complete scan lifecycle on an authorized test host and displays
the normalized security findings and technology footprint.
"""
import json
import os
import sys
import time

import httpx
from dotenv import load_dotenv

# Load local environment
load_dotenv(".env.local")
load_dotenv(".env")

API_BASE = os.getenv("CONTROLLER_API_ENDPOINT", "https://axiom-xjkc.onrender.com").rstrip("/")
ADMIN_KEY = os.getenv("ADMIN_API_KEY", "nBK_0V8AQVDZmC6gTpgkTn04t7Gx2IYSYiPvdT5zymU")
OPERATOR_KEY = os.getenv("API_KEY", "Jf2T0sTy0IauJ6ELjLWAibC9-EpFo5LXwneztTBeyAU")
TARGET_HOST = "scanme.nmap.org"
PROFILE = "recon"


def main():
    print("=" * 65)
    print("LIVE END-TO-END SECURITY SCAN ORCHESTRATION TEST")
    print(f"API Endpoint:     {API_BASE}")
    print(f"Target Host:      {TARGET_HOST} (Authorized)")
    print(f"Scan Profile:     {PROFILE}")
    print("=" * 65)

    client = httpx.Client(timeout=30)

    # 1. Health check
    print("\n[1/5] Checking API Health...")
    try:
        health_res = client.get(f"{API_BASE}/health")
        if health_res.status_code != 200:
            print(f"[-] API Health Check failed with status {health_res.status_code}: {health_res.text}")
            sys.exit(1)
        print("[+] API is online and healthy.")
    except Exception as exc:
        print(f"[-] Could not connect to API at {API_BASE}: {exc}")
        sys.exit(1)

    # 2. Register Authorized Target
    print(f"\n[2/5] Registering Authorized Target '{TARGET_HOST}' (Admin)...")
    target_payload = {
        "value": TARGET_HOST,
        "owner_reference": "Nmap Project",
        "authorization_reference": "AUTH-LIVE-E2E-TEST-2026",
    }
    target_res = client.post(
        f"{API_BASE}/v1/targets",
        headers={"X-API-Key": ADMIN_KEY, "Content-Type": "application/json"},
        json=target_payload,
    )
    if target_res.status_code not in (200, 201):
        print(f"[-] Target registration failed ({target_res.status_code}): {target_res.text}")
        sys.exit(1)

    target_data = target_res.json()
    target_id = target_data["id"]
    print(f"[+] Target registered successfully! Target ID: {target_id}")

    # 3. Queue Scan Job
    print(f"\n[3/5] Queuing '{PROFILE}' Scan Job (Operator)...")
    scan_payload = {
        "target_id": target_id,
        "profile": PROFILE,
    }
    scan_res = client.post(
        f"{API_BASE}/v1/scans",
        headers={"X-API-Key": OPERATOR_KEY, "Content-Type": "application/json"},
        json=scan_payload,
    )
    if scan_res.status_code != 202:
        print(f"[-] Failed to queue scan ({scan_res.status_code}): {scan_res.text}")
        sys.exit(1)

    scan_data = scan_res.json()
    scan_id = scan_data["id"]
    print(f"[+] Scan queued successfully! Scan Job ID: {scan_id}")
    print(f"[+] Current Status: {scan_data['status'].upper()}")

    # 4. Poll for Completion
    print("\n[4/5] Waiting for Cloud Shell Controller Agent to process the job...")
    max_wait = 180  # 3 minutes max
    start_time = time.time()
    completed = False

    while time.time() - start_time < max_wait:
        poll_res = client.get(
            f"{API_BASE}/v1/scans/{scan_id}",
            headers={"X-API-Key": OPERATOR_KEY},
        )
        if poll_res.status_code == 200:
            status_data = poll_res.json()
            current_status = status_data.get("status")
            print(f"    -> Job Status: {current_status.upper()} (Elapsed: {int(time.time() - start_time)}s)")
            if current_status == "completed":
                completed = True
                break
            elif current_status in ("failed", "cancelled"):
                print(f"[-] Scan finished with terminal status: {current_status}")
                if status_data.get("failure_reason"):
                    print(f"    Failure Reason: {status_data.get('failure_reason')}")
                sys.exit(1)
        time.sleep(4)

    if not completed:
        print("[-] Timed out waiting for controller agent to complete the scan.")
        print("    Ensure your Cloud Shell terminal is running: python3 -m controller.agent")
        sys.exit(1)

    # 5. Retrieve Normalized Findings
    print("\n[5/5] Fetching Security Findings & Results...")
    result_res = client.get(
        f"{API_BASE}/v1/scans/{scan_id}/result",
        headers={"X-API-Key": OPERATOR_KEY},
    )
    if result_res.status_code != 200:
        print(f"[-] Could not fetch scan results: {result_res.text}")
        sys.exit(1)

    result = result_res.json()
    summary = result.get("summary", {})

    print("\n" + "=" * 65)
    print("                  SECURITY FINDINGS REPORT")
    print("=" * 65)
    print(f"Target:               {TARGET_HOST}")
    print(f"Scan Job ID:          {scan_id}")
    print(f"Live Hosts Found:     {summary.get('live_hosts_count', 0)}")
    print(f"HTTP Status Codes:    {json.dumps(summary.get('status_codes', {}))}")
    print(f"Web Servers Detected: {', '.join(summary.get('web_servers', [])) or 'None detected'}")
    print(f"Page Titles:          {', '.join(summary.get('titles', [])) or 'None'}")
    print(f"Technologies:         {', '.join(summary.get('technologies', [])) or 'None detected'}")
    print("-" * 65)
    print("SECURITY OBSERVATIONS / EXPOSURES:")
    if summary.get("web_servers"):
        for server in summary.get("web_servers"):
            print(f" [!] Information Disclosure: Server version header leaked ('{server}')")
    if summary.get("technologies"):
        print(f" [i] Attack Surface Footprint: Detected stack: {summary.get('technologies')}")
    print("=" * 65)
    print("[SUCCESS] Full end-to-end security test completed successfully!")


if __name__ == "__main__":
    main()
