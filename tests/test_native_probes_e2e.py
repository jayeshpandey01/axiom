from pathlib import Path

from controller.agent import (
    parse_corsy_output,
    parse_crlfuzz_output,
    parse_dnsx_output,
    parse_feroxbuster_output,
    parse_ffuf_output,
    parse_masscan_output,
    parse_nmap_output,
    parse_sstimap_output,
    parse_wafw00f_output,
)
from controller.native_probes import dispatch_native_probe


def test_native_portscan_execution_and_parsing(tmp_path: Path):
    out_file = tmp_path / "nmap_out.xml"
    dispatch_native_probe("network-portscan", "127.0.0.1", out_file)
    assert out_file.exists()
    result = parse_nmap_output(out_file)
    assert "findings" in result
    assert "risk_summary" in result


def test_native_fast_portscan_execution_and_parsing(tmp_path: Path):
    out_file = tmp_path / "masscan_out.json"
    dispatch_native_probe("fast-portscan", "127.0.0.1", out_file)
    assert out_file.exists()
    result = parse_masscan_output(out_file)
    assert "findings" in result


def test_native_waf_detect_execution_and_parsing(tmp_path: Path):
    out_file = tmp_path / "waf_out.json"
    dispatch_native_probe("waf-detect", "http://127.0.0.1:9999", out_file)
    assert out_file.exists()
    result = parse_wafw00f_output(out_file)
    assert "findings" in result
    assert "waf_results" in result


def test_native_cors_audit_execution_and_parsing(tmp_path: Path):
    out_file = tmp_path / "cors_out.json"
    dispatch_native_probe("cors-audit", "http://127.0.0.1:9999", out_file)
    assert out_file.exists()
    result = parse_corsy_output(out_file)
    assert "findings" in result


def test_native_crlf_scan_execution_and_parsing(tmp_path: Path):
    out_file = tmp_path / "crlf_out.jsonl"
    dispatch_native_probe("crlf-scan", "http://127.0.0.1:9999", out_file)
    assert out_file.exists()
    result = parse_crlfuzz_output(out_file)
    assert "findings" in result


def test_native_ssti_scan_execution_and_parsing(tmp_path: Path):
    out_file = tmp_path / "ssti_out.json"
    dispatch_native_probe("ssti-scan", "http://127.0.0.1:9999", out_file)
    assert out_file.exists()
    result = parse_sstimap_output(out_file)
    assert "findings" in result


def test_native_dns_recon_execution_and_parsing(tmp_path: Path):
    out_file = tmp_path / "dns_out.json"
    dispatch_native_probe("dns-recon", "localhost", out_file)
    assert out_file.exists()
    result = parse_dnsx_output(out_file)
    assert "findings" in result


def test_native_content_discovery_execution_and_parsing(tmp_path: Path):
    out_file = tmp_path / "ffuf_out.json"
    dispatch_native_probe("content-discovery", "http://127.0.0.1:9999", out_file)
    assert out_file.exists()
    result = parse_ffuf_output(out_file)
    assert "findings" in result


def test_native_deep_content_discovery_execution_and_parsing(tmp_path: Path):
    out_file = tmp_path / "ferox_out.jsonl"
    dispatch_native_probe("deep-content-discovery", "http://127.0.0.1:9999", out_file)
    assert out_file.exists()
    result = parse_feroxbuster_output(out_file)
    assert "findings" in result
