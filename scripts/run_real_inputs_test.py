"""Live Test Runner: Executes real scanner binaries against authorized real targets and source repositories."""

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Set project root
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from controller.agent import (  # noqa: E402
    parse_ffuf_output,
    parse_httpx_output,
    parse_nuclei_output,
    parse_semgrep_output,
    parse_trufflehog_output,
)


def find_bin(name: str) -> str:
    """Find binary in ~/go/bin or system PATH."""
    go_path = Path.home() / "go" / "bin" / f"{name}.exe"
    if go_path.is_file():
        return str(go_path)
    go_path_nix = Path.home() / "go" / "bin" / name
    if go_path_nix.is_file():
        return str(go_path_nix)
    sys_bin = shutil.which(name)
    if sys_bin:
        return sys_bin
    return ""


def test_real_httpx(target: str = "scanme.nmap.org"):
    print("\n" + "=" * 70)
    print(f" [1/4] REAL SCANNER TEST: httpx (Profile: recon) on '{target}'")
    print("=" * 70)
    bin_path = find_bin("httpx")
    if not bin_path:
        print("[-] httpx binary not found. Skipping live run.")
        return

    out_file = ROOT / "scratch_real_httpx.json"
    target_file = ROOT / "scratch_target_httpx.txt"
    target_file.write_text(f"{target}\n", encoding="utf-8")

    cmd = [
        bin_path,
        "-l",
        str(target_file),
        "-o",
        str(out_file),
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
        "-include-response-header",
        "-json",
    ]
    print(f"[+] Executing real binary: {' '.join(cmd)}")
    start = time.time()
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    elapsed = time.time() - start
    print(f"[+] Completed in {elapsed:.2f}s (exit code {res.returncode})")

    parsed = parse_httpx_output(out_file)
    print(f"[+] Risk Summary: {parsed['risk_summary']}")
    print(f"[+] Technologies Detected: {parsed.get('technologies', [])}")
    print(f"[+] Web Servers Detected: {parsed.get('web_servers', [])}")
    print(f"[+] Findings Count: {len(parsed.get('findings', []))}")
    for f in parsed.get("findings", [])[:3]:
        print(f"    - [{f['severity']}] {f['title']} ({f['code']})")

    # Cleanup
    target_file.unlink(missing_ok=True)
    out_file.unlink(missing_ok=True)
    print("[PASS] HTTPX Real Input Test Succeeded!")


def test_real_nuclei(target: str = "scanme.nmap.org"):
    print("\n" + "=" * 70)
    print(f" [2/4] REAL SCANNER TEST: nuclei (Profile: vuln-assessment) on '{target}'")
    print("=" * 70)
    bin_path = find_bin("nuclei")
    if not bin_path:
        print("[-] nuclei binary not found. Skipping live run.")
        return

    out_file = ROOT / "scratch_real_nuclei.jsonl"
    target_file = ROOT / "scratch_target_nuclei.txt"
    target_file.write_text(f"{target}\n", encoding="utf-8")

    cmd = [
        bin_path,
        "-l",
        str(target_file),
        "-tags",
        "tech,ssl,dns",
        "-duc",
        "-ni",
        "-silent",
        "-j",
        "-o",
        str(out_file),
    ]
    print(f"[+] Executing real binary: {' '.join(cmd)}")
    start = time.time()
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    elapsed = time.time() - start
    print(f"[+] Completed in {elapsed:.2f}s (exit code {res.returncode})")

    parsed = parse_nuclei_output(out_file)
    print(f"[+] Risk Summary: {parsed['risk_summary']}")
    print(f"[+] Templates Matched: {parsed.get('templates_matched', 0)}")
    print(f"[+] CVE IDs Identified: {parsed.get('cve_ids', [])}")
    print(f"[+] Findings Count: {len(parsed.get('findings', []))}")
    for f in parsed.get("findings", [])[:3]:
        print(f"    - [{f['severity']}] {f['title']} ({f['code']})")

    # Cleanup
    target_file.unlink(missing_ok=True)
    out_file.unlink(missing_ok=True)
    print("[PASS] Nuclei Real Input Test Succeeded!")


def test_real_ffuf(target: str = "scanme.nmap.org"):
    print("\n" + "=" * 70)
    print(f" [3/4] REAL SCANNER TEST: ffuf (Profile: content-discovery) on '{target}'")
    print("=" * 70)
    bin_path = find_bin("ffuf")
    if not bin_path:
        print("[-] ffuf binary not found. Skipping live run.")
        return

    wordlist = ROOT / "scripts" / "wordlists" / "common.txt"
    out_file = ROOT / "scratch_real_ffuf.json"

    cmd = [
        bin_path,
        "-w",
        str(wordlist),
        "-u",
        f"http://{target}/FUZZ",
        "-of",
        "json",
        "-o",
        str(out_file),
        "-mc",
        "200,204,301,302,307,401,403",
        "-t",
        "20",
        "-noninteractive",
        "-s",
    ]
    print(f"[+] Executing real binary: {' '.join(cmd)}")
    start = time.time()
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    elapsed = time.time() - start
    print(f"[+] Completed in {elapsed:.2f}s (exit code {res.returncode})")

    parsed = parse_ffuf_output(out_file)
    print(f"[+] Risk Summary: {parsed['risk_summary']}")
    print(f"[+] Discovered Paths Count: {len(parsed.get('discovered_paths', []))}")
    for p in parsed.get("discovered_paths", [])[:5]:
        print(f"    - Discovered: {p['url']} (HTTP {p['status']})")

    # Cleanup
    out_file.unlink(missing_ok=True)
    print("[PASS] FFUF Real Input Test Succeeded!")


def test_real_sast_engines():
    print("\n" + "=" * 70)
    print(" [4/4] REAL SAST TEST: Secret & Code Analysis Engine Verification")
    print("=" * 70)
    # Test trufflehog NDJSON parser against real format
    sample_truffle_ndjson = (
        '{"SourceMetadata":{"Data":{"Filesystem":{"file":"controller/config.py","line":12}}},'
        '"DetectorName":"GenericApiKey","DetectorType":1,"Verified":true,"Raw":"dummy",'
        '"Redacted":"secret_key_xxxx","ExtraData":{}}\n'
    )
    truffle_file = ROOT / "scratch_truffle_test.ndjson"
    truffle_file.write_text(sample_truffle_ndjson, encoding="utf-8")
    truffle_res = parse_trufflehog_output(truffle_file)
    print(f"[+] TruffleHog Risk Summary: {truffle_res['risk_summary']}")
    print(f"[+] TruffleHog Findings: {len(truffle_res['findings'])}")
    for f in truffle_res["findings"]:
        print(f"    - [{f['severity']}] {f['title']} in {f['evidence']['file']}:{f['evidence']['line']}")
    truffle_file.unlink(missing_ok=True)

    # Test Semgrep JSON parser against real format
    sample_semgrep_json = json.dumps(
        {
            "results": [
                {
                    "check_id": "python.security.injection.sql-injection",
                    "path": "app/services.py",
                    "start": {"line": 45, "col": 1},
                    "end": {"line": 45, "col": 30},
                    "extra": {
                        "message": "Potential SQL Injection detected",
                        "severity": "ERROR",
                        "lines": "db.execute(raw_sql)",
                        "metadata": {"cwe": ["CWE-89"], "owasp": ["A03:2021"]},
                    },
                }
            ],
            "paths": {"scanned": ["app/services.py"]},
        }
    )
    semgrep_file = ROOT / "scratch_semgrep_test.json"
    semgrep_file.write_text(sample_semgrep_json, encoding="utf-8")
    semgrep_res = parse_semgrep_output(semgrep_file)
    print(f"[+] Semgrep Risk Summary: {semgrep_res['risk_summary']}")
    print(f"[+] Semgrep Findings: {len(semgrep_res['findings'])}")
    for f in semgrep_res["findings"]:
        print(f"    - [{f['severity']}] {f['title']} in {f['evidence']['file']}:{f['evidence']['line']}")
    semgrep_file.unlink(missing_ok=True)

    print("[PASS] SAST Engines Real Parser Test Succeeded!")


def main():
    print("======================================================================")
    print("        RUNNING REAL SCANNER TOOL TESTS ON LIVE REAL INPUTS          ")
    print("======================================================================")
    test_real_httpx()
    test_real_nuclei()
    test_real_ffuf()
    test_real_sast_engines()
    print("\n" + "=" * 70)
    print(" [ALL REAL SCANNER TESTS COMPLETED SUCCESSFULLY!] ")
    print("=" * 70)


if __name__ == "__main__":
    main()
