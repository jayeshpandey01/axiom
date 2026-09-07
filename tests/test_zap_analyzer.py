"""Unit tests for OWASP ZAP (Zed Attack Proxy) DAST Analysis Engine."""

import json
from pathlib import Path

from controller.agent import parse_zap_output
from controller.analyzer import ZAPAnalyzer


def test_zap_analyzer_empty_records():
    """Empty report or missing alerts should yield 0 findings without exceptions."""
    analyzer = ZAPAnalyzer()
    res = analyzer.analyze({})
    assert res["risk_summary"]["total"] == 0
    assert res["risk_summary"]["critical"] == 0
    assert res["risk_summary"]["high"] == 0
    assert res["risk_summary"]["medium"] == 0
    assert res["risk_summary"]["low"] == 0
    assert res["risk_summary"]["info"] == 0
    assert res["findings"] == []
    assert res["tested_urls"] == []
    assert res["vulnerable_parameters"] == []


def test_zap_analyzer_varied_risk_levels():
    """Test full parsing of ZAP alerts across all risk codes, CWE extraction, and parameter isolation."""
    zap_report = {
        "@version": "2.14.0",
        "site": [
            {
                "@name": "https://example.com",
                "@host": "example.com",
                "alerts": [
                    {
                        "pluginid": "90020",
                        "alert": "Remote Code Execution in Admin Endpoint",
                        "riskcode": "3",
                        "confidence": "3",
                        "desc": "<p>Arbitrary code execution flaw detected via dynamic parameter evaluation.</p>",
                        "instances": [
                            {
                                "uri": "https://example.com/api/eval?code=phpinfo()",
                                "method": "POST",
                                "param": "code",
                                "attack": "phpinfo()",
                                "evidence": "PHP Version 8.2",
                            }
                        ],
                        "solution": "<p>Eliminate eval sinks and validate execution context.</p>",
                        "cweid": "94",
                        "wascid": "20",
                    },
                    {
                        "pluginid": "40012",
                        "alert": "Cross Site Scripting (Reflected)",
                        "riskcode": "3",
                        "confidence": "2",
                        "desc": "User input reflected without context-aware encoding.",
                        "instances": [
                            {
                                "uri": "https://example.com/search?q=test",
                                "method": "GET",
                                "param": "q",
                                "attack": "<script>alert(1)</script>",
                            }
                        ],
                        "solution": "Contextually encode all user-controlled data.",
                        "cweid": "79",
                        "wascid": "8",
                    },
                    {
                        "pluginid": "10038",
                        "alert": "Content Security Policy (CSP) Header Not Set",
                        "riskcode": "2",
                        "confidence": "3",
                        "desc": "CSP header missing from HTTP response headers.",
                        "instances": [{"uri": "https://example.com/"}],
                        "solution": "Enforce strong Content-Security-Policy headers.",
                        "cweid": "693",
                    },
                    {
                        "pluginid": "10020",
                        "alert": "Missing Anti-clickjacking Header",
                        "riskcode": "1",
                        "confidence": "2",
                        "desc": "X-Frame-Options or CSP frame-ancestors missing.",
                        "instances": [{"uri": "https://example.com/login"}],
                        "cweid": "1021",
                    },
                    {
                        "pluginid": "10027",
                        "alert": "Information Disclosure - Suspicious Comments",
                        "riskcode": "0",
                        "confidence": "1",
                        "desc": "Source code comments contain developer references.",
                        "instances": [{"uri": "https://example.com/app.js"}],
                        "cweid": "200",
                    },
                ],
            }
        ],
    }

    analyzer = ZAPAnalyzer()
    res = analyzer.analyze(zap_report)

    summary = res["risk_summary"]
    assert summary["total"] == 5
    assert summary["critical"] == 1  # Promoted to CRITICAL because RCE + confidence 3
    assert summary["high"] == 1      # XSS
    assert summary["medium"] == 1    # CSP
    assert summary["low"] == 1       # Anti-clickjacking
    assert summary["info"] == 1      # Information disclosure

    # Parameter & URL extraction
    assert "code" in res["vulnerable_parameters"]
    assert "q" in res["vulnerable_parameters"]
    assert "https://example.com/api/eval?code=phpinfo()" in res["tested_urls"]
    assert "https://example.com/search?q=test" in res["tested_urls"]

    # Finding 1: RCE
    f1 = res["findings"][0]
    assert f1["severity"] == "CRITICAL"
    assert f1["code"] == "zap/90020"
    assert f1["evidence"]["cwe"] == "CWE-94"
    assert f1["evidence"]["wasc"] == "WASC-20"
    assert "Eliminate eval sinks" in f1["remediation"]

    # Finding 2: XSS
    f2 = res["findings"][1]
    assert f2["severity"] == "HIGH"
    assert f2["evidence"]["cwe"] == "CWE-79"


def test_zap_analyzer_site_as_single_dict():
    """Verify analyzer handles 'site' as a dictionary instead of a list."""
    zap_report = {
        "site": {
            "@name": "http://testphp.vulnweb.com",
            "alerts": [
                {
                    "pluginid": "40018",
                    "alert": "SQL Injection",
                    "riskcode": "3",
                    "confidence": "3",
                    "desc": "SQL injection vulnerability detected in id parameter.",
                    "instances": [{"uri": "http://testphp.vulnweb.com/artists.php?artist=1", "param": "artist"}],
                    "cweid": "89",
                }
            ],
        }
    }
    analyzer = ZAPAnalyzer()
    res = analyzer.analyze(zap_report)
    assert res["risk_summary"]["total"] == 1
    assert res["risk_summary"]["critical"] == 1  # SQL injection + confidence 3 -> CRITICAL
    assert "artist" in res["vulnerable_parameters"]


def test_zap_analyzer_raw_string_and_invalid_data():
    """Verify analyzer gracefully handles stringified JSON and corrupted text."""
    analyzer = ZAPAnalyzer()

    # Valid stringified JSON
    json_str = json.dumps({"alerts": [{"pluginid": "1001", "alert": "Test Alert", "riskcode": "2"}]})
    res = analyzer.analyze(json_str)
    assert res["risk_summary"]["total"] == 1
    assert res["risk_summary"]["medium"] == 1

    # Malformed text
    res_bad = analyzer.analyze("INVALID_JSON_CORRUPT")
    assert res_bad["risk_summary"]["total"] == 0
    assert res_bad["findings"] == []


def test_parse_zap_output_file(tmp_path: Path):
    """Verify parse_zap_output disk reader handling non-existent, empty, and valid files."""
    zap_path = tmp_path / "zap_report.json"

    # Missing file
    res_missing = parse_zap_output(tmp_path / "non_existent.json")
    assert res_missing["risk_summary"]["total"] == 0

    # Empty file
    zap_path.write_text("", encoding="utf-8")
    res_empty = parse_zap_output(zap_path)
    assert res_empty["risk_summary"]["total"] == 0

    # Valid file
    valid_data = {
        "alerts": [
            {
                "pluginid": "10001",
                "alert": "Weak TLS Cipher Suite",
                "riskcode": "1",
                "instances": [{"uri": "https://example.com"}],
            }
        ]
    }
    zap_path.write_text(json.dumps(valid_data), encoding="utf-8")
    res_valid = parse_zap_output(zap_path)
    assert res_valid["risk_summary"]["total"] == 1
    assert res_valid["risk_summary"]["low"] == 1
