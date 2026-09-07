"""Tests for InteractshAnalyzer and ProjectDiscovery Interactsh OOB callback parsing."""

import json
from pathlib import Path

from controller.agent import parse_interactsh_output
from controller.analyzer import InteractshAnalyzer, NucleiAnalyzer


def test_interactsh_analyzer_empty_records():
    analyzer = InteractshAnalyzer()
    res = analyzer.analyze([])
    assert res["risk_summary"]["total"] == 0
    assert res["findings"] == []
    assert res["interaction_types"] == []
    assert res["callback_hosts"] == []


def test_interactsh_analyzer_varied_protocols():
    records = [
        {
            "protocol": "ldap",
            "unique-id": "cid-ldap-001",
            "full-id": "cid-ldap-001.oast.fun",
            "remote-address": "198.51.100.1:38901",
            "timestamp": "2026-09-08T00:20:00Z",
            "raw-request": "LDAP search request: dc=example,dc=com",
        },
        {
            "protocol": "http",
            "unique-id": "cid-http-002",
            "full-id": "cid-http-002.oast.fun",
            "remote-address": "203.0.113.55:54321",
            "timestamp": "2026-09-08T00:20:05Z",
            "raw-request": "GET /callback?status=ok HTTP/1.1\r\nHost: cid-http-002.oast.fun\r\n\r\n",
        },
        {
            "protocol": "smtp",
            "unique-id": "cid-smtp-003",
            "full-id": "cid-smtp-003.oast.fun",
            "remote-address": "192.0.2.77:25000",
            "timestamp": "2026-09-08T00:20:10Z",
            "raw-request": "HELO mail.victim.com\r\nMAIL FROM:<user@victim.com>\r\n",
        },
        {
            "protocol": "dns",
            "unique-id": "cid-dns-004",
            "full-id": "cid-dns-004.oast.fun",
            "q-type": "A",
            "remote-address": "8.8.8.8:53",
            "timestamp": "2026-09-08T00:20:15Z",
            "raw-request": "Query: cid-dns-004.oast.fun IN A",
        },
    ]

    analyzer = InteractshAnalyzer()
    res = analyzer.analyze(records)

    assert res["risk_summary"]["critical"] == 1  # LDAP
    assert res["risk_summary"]["high"] == 2  # HTTP, SMTP
    assert res["risk_summary"]["medium"] == 1  # DNS
    assert res["risk_summary"]["total"] == 4

    assert "LDAP" in res["interaction_types"]
    assert "HTTP" in res["interaction_types"]
    assert "SMTP" in res["interaction_types"]
    assert "DNS" in res["interaction_types"]

    # Verify LDAP is classified as Critical RCE
    ldap_finding = next(f for f in res["findings"] if f["code"] == "INTERACTSH_OOB_LDAP_JNDI")
    assert ldap_finding["severity"] == "CRITICAL"
    assert ldap_finding["score"] == 9.8
    assert "JNDI" in ldap_finding["title"]
    assert ldap_finding["evidence"]["protocol"] == "LDAP"

    # Verify HTTP is classified as High SSRF
    http_finding = next(f for f in res["findings"] if f["code"] == "INTERACTSH_OOB_HTTP_SSRF")
    assert http_finding["severity"] == "HIGH"
    assert http_finding["score"] == 8.6
    assert "SSRF" in http_finding["title"]

    # Verify SMTP is classified as High Email/SSRF
    smtp_finding = next(f for f in res["findings"] if f["code"] == "INTERACTSH_OOB_SMTP_INJECTION")
    assert smtp_finding["severity"] == "HIGH"
    assert smtp_finding["score"] == 8.0

    # Verify DNS is classified as Medium
    dns_finding = next(f for f in res["findings"] if f["code"] == "INTERACTSH_OOB_DNS_LOOKUP")
    assert dns_finding["severity"] == "MEDIUM"
    assert dns_finding["score"] == 6.5
    assert dns_finding["evidence"]["query_type"] == "A"


def test_interactsh_analyzer_secret_redaction():
    records = [
        {
            "protocol": "http",
            "unique-id": "cid-sec-001",
            "full-id": "cid-sec-001.oast.fun",
            "remote-address": "1.2.3.4:5000",
            "raw-request": (
                "POST /api HTTP/1.1\r\n"
                "Host: cid-sec-001.oast.fun\r\n"
                "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.supersecret\r\n"
                "Cookie: session=xyz987654321; token=abc12345\r\n"
                "\r\n"
                "api_key=secret-production-key-999&user=admin"
            ),
        }
    ]

    analyzer = InteractshAnalyzer()
    res = analyzer.analyze(records)
    finding = res["findings"][0]

    # Verify secrets are scrubbed in logs and snippet
    assert "supersecret" not in finding["logs"]
    assert "xyz987654321" not in finding["logs"]
    assert "secret-production-key-999" not in finding["logs"]
    assert "<REDACTED>" in finding["logs"]

    snippet = finding["evidence"]["raw_request_snippet"]
    assert "supersecret" not in snippet
    assert "<REDACTED>" in snippet


def test_parse_interactsh_output_file(tmp_path: Path):
    # Test JSON Lines parsing
    ndjson_file = tmp_path / "interactions.ndjson"
    ndjson_content = (
        '{"protocol": "dns", "unique-id": "c01", "remote-address": "8.8.8.8"}\n'
        '{"protocol": "http", "unique-id": "c02", "remote-address": "10.0.0.1"}\n'
    )
    ndjson_file.write_text(ndjson_content, encoding="utf-8")

    res = parse_interactsh_output(ndjson_file)
    assert res["risk_summary"]["total"] == 2
    assert len(res["findings"]) == 2

    # Test JSON Array parsing
    json_file = tmp_path / "interactions.json"
    json_content = json.dumps([{"protocol": "ldap", "unique-id": "c03", "remote-address": "1.1.1.1"}])
    json_file.write_text(json_content, encoding="utf-8")

    res2 = parse_interactsh_output(json_file)
    assert res2["risk_summary"]["total"] == 1
    assert res2["findings"][0]["severity"] == "CRITICAL"

    # Test Missing File
    res_empty = parse_interactsh_output(tmp_path / "non_existent.json")
    assert res_empty["risk_summary"]["total"] == 0


def test_nuclei_analyzer_with_oob_interaction():
    records = [
        {
            "template-id": "blind-ssrf",
            "info": {
                "name": "Blind SSRF Detection",
                "severity": "high",
                "description": "An Out-of-Band (OOB) HTTP callback was detected via Interactsh.",
            },
            "host": "https://example.com",
            "matched-at": "https://example.com/redirect?url=http://c123.oast.fun",
            "interaction": {
                "protocol": "http",
                "remote-address": "198.51.100.42",
                "unique-id": "c123",
                "q-type": None,
            },
        }
    ]

    analyzer = NucleiAnalyzer()
    res = analyzer.analyze(records)
    assert res["risk_summary"]["high"] == 1
    finding = res["findings"][0]
    assert "oob_interaction" in finding["evidence"]
    assert finding["evidence"]["oob_interaction"]["protocol"] == "HTTP"
    assert finding["evidence"]["oob_interaction"]["remote_address"] == "198.51.100.42"
    assert finding["evidence"]["oob_interaction"]["unique_id"] == "c123"

