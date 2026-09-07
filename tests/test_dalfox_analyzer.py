"""Unit tests for DalFox XSS Scanner Output Analyzer."""

import json
from pathlib import Path

from controller.agent import parse_dalfox_output
from controller.analyzer import DalfoxAnalyzer


def test_dalfox_analyzer_empty_records():
    analyzer = DalfoxAnalyzer()
    result = analyzer.analyze([])
    assert result["risk_summary"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    assert result["findings"] == []
    assert result["vulnerable_parameters"] == []
    assert result["verified_xss_count"] == 0
    assert result["tested_urls"] == []


def test_dalfox_analyzer_varied_findings():
    analyzer = DalfoxAnalyzer()
    sample_records = [
        {
            "type": "V",
            "type_description": "Vulnerable - dalfox asserts this input is exploitable; act on it",
            "param": "search",
            "payload": "\"><script>alert(1)</script>",
            "evidence": "<input value=\"\"><script>alert(1)</script>\">",
            "cwe": "CWE-79",
            "severity": "high",
            "method": "GET",
            "url": "https://example.com/search?search=%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
            "message": "Verified XSS found in parameter 'search'",
            "detection_method": "dom-verification",
            "confidence": "high",
        },
        {
            "type": "A",
            "type_description": "AST-detected DOM XSS",
            "param": "redirect",
            "payload": "javascript:alert(1)",
            "evidence": "location.href = new URLSearchParams(location.search).get('redirect')",
            "cwe": "CWE-79",
            "severity": "high",
            "method": "GET",
            "url": "https://example.com/login?redirect=javascript:alert(1)",
            "message": "AST-Detected DOM Cross-Site Scripting in 'redirect'",
            "detection_method": "ast",
            "confidence": "high",
        },
        {
            "type": "R",
            "type_description": "Reflected - payload appears in response",
            "param": "ref",
            "payload": "dalfox123",
            "evidence": "<span>dalfox123</span>",
            "cwe": "CWE-79",
            "severity": "medium",
            "method": "GET",
            "url": "https://example.com/index?ref=dalfox123",
            "message": "Reflected parameter 'ref' detected",
            "detection_method": "reflection",
            "confidence": "low",
        },
        {
            "type": "G",
            "type_description": "Grep check found sensitive pattern",
            "param": "token",
            "payload": "test",
            "evidence": "API_TOKEN_EXPOSED",
            "cwe": "CWE-200",
            "severity": "low",
            "method": "POST",
            "url": "https://example.com/api/token",
            "message": "Heuristic reflection detected on token",
            "detection_method": "reflection",
            "confidence": "low",
        },
        {
            "type": "I",
            "type_description": "Informational",
            "param": "",
            "payload": "",
            "evidence": "jQuery 1.12.4",
            "cwe": "CWE-1104",
            "severity": "info",
            "method": "GET",
            "url": "https://example.com/",
            "message": "Outdated jQuery library detected",
            "detection_method": "library",
            "confidence": "low",
        },
    ]

    result = analyzer.analyze(sample_records)
    summary = result["risk_summary"]

    assert summary["high"] == 2
    assert summary["medium"] == 1
    assert summary["low"] == 1
    assert summary["info"] == 1
    assert summary["total"] == 5

    assert result["verified_xss_count"] == 1
    assert "search" in result["vulnerable_parameters"]
    assert "redirect" in result["vulnerable_parameters"]
    assert "ref" in result["vulnerable_parameters"]
    assert len(result["tested_urls"]) == 5

    # Verify findings structure
    v_finding = next(f for f in result["findings"] if f["code"] == "DALFOX_VERIFIED_XSS")
    assert v_finding["severity"] == "HIGH"
    assert "Verified Cross-Site Scripting" in v_finding["title"]
    assert v_finding["evidence"]["parameter"] == "search"
    assert "Output encoding" in v_finding["remediation"] or "output encoding" in v_finding["remediation"].lower()


def test_parse_dalfox_output_json_array(tmp_path: Path):
    out_file = tmp_path / "dalfox_output.json"
    records = [
        {
            "type": "V",
            "param": "query",
            "payload": "<img src=x onerror=alert(1)>",
            "severity": "high",
            "url": "https://target.test/search?query=x",
        }
    ]
    out_file.write_text(json.dumps(records), encoding="utf-8")

    parsed = parse_dalfox_output(out_file)
    assert parsed["risk_summary"]["high"] == 1
    assert parsed["verified_xss_count"] == 1
    assert parsed["vulnerable_parameters"] == ["query"]


def test_parse_dalfox_output_jsonl(tmp_path: Path):
    out_file = tmp_path / "dalfox_output.jsonl"
    line1 = json.dumps({"type": "R", "param": "id", "severity": "medium", "url": "https://target.test/view?id=1"})
    line2 = json.dumps({"type": "V", "param": "name", "severity": "high", "url": "https://target.test/hello?name=x"})
    out_file.write_text(f"{line1}\n{line2}\n", encoding="utf-8")

    parsed = parse_dalfox_output(out_file)
    assert parsed["risk_summary"]["total"] == 2
    assert parsed["risk_summary"]["high"] == 1
    assert parsed["risk_summary"]["medium"] == 1
    assert parsed["verified_xss_count"] == 1
    assert set(parsed["vulnerable_parameters"]) == {"id", "name"}


def test_parse_dalfox_output_missing_file(tmp_path: Path):
    missing_file = tmp_path / "nonexistent.json"
    parsed = parse_dalfox_output(missing_file)
    assert parsed["risk_summary"]["total"] == 0
    assert parsed["findings"] == []
