"""Unit tests for the 10 new Phase 2 & 3 analyzer classes."""



# ──────────────────────────────────────────────────────────────────
# KatanaAnalyzer
# ──────────────────────────────────────────────────────────────────
class TestKatanaAnalyzer:
    def test_empty_records(self):
        from controller.analyzer import KatanaAnalyzer
        result = KatanaAnalyzer().analyze([])
        assert result["endpoints_discovered"] == 0
        assert result["findings"] == []

    def test_normal_endpoint_no_finding(self):
        from controller.analyzer import KatanaAnalyzer
        result = KatanaAnalyzer().analyze([{"endpoint": "https://example.com/about"}])
        assert result["endpoints_discovered"] == 1
        assert result["findings"] == []

    def test_sensitive_admin_endpoint_flagged(self):
        from controller.analyzer import KatanaAnalyzer
        result = KatanaAnalyzer().analyze([{"endpoint": "https://example.com/admin/dashboard"}])
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "MEDIUM"
        assert "KATANA_SENSITIVE_ENDPOINT" in result["findings"][0]["code"]

    def test_env_file_endpoint_flagged(self):
        from controller.analyzer import KatanaAnalyzer
        result = KatanaAnalyzer().analyze([{"endpoint": "https://example.com/.env"}])
        assert result["risk_summary"]["medium"] == 1

    def test_multiple_endpoints(self):
        from controller.analyzer import KatanaAnalyzer
        records = [
            {"endpoint": "https://example.com/index.html"},
            {"endpoint": "https://example.com/wp-admin/"},
            {"endpoint": "https://example.com/swagger/"},
        ]
        result = KatanaAnalyzer().analyze(records)
        assert result["endpoints_discovered"] == 3
        assert len(result["findings"]) == 2


# ──────────────────────────────────────────────────────────────────
# FeroxbusterAnalyzer
# ──────────────────────────────────────────────────────────────────
class TestFeroxbusterAnalyzer:
    def test_empty_records(self):
        from controller.analyzer import FeroxbusterAnalyzer
        result = FeroxbusterAnalyzer().analyze([])
        assert result["paths_discovered"] == 0
        assert result["findings"] == []

    def test_non_response_type_skipped(self):
        from controller.analyzer import FeroxbusterAnalyzer
        result = FeroxbusterAnalyzer().analyze([{"type": "statistics", "url": "https://example.com/admin"}])
        assert result["findings"] == []

    def test_critical_env_path(self):
        from controller.analyzer import FeroxbusterAnalyzer
        result = FeroxbusterAnalyzer().analyze([{"type": "response", "url": "https://example.com/.env", "status": 200}])
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "CRITICAL"

    def test_high_admin_path(self):
        from controller.analyzer import FeroxbusterAnalyzer
        result = FeroxbusterAnalyzer().analyze([{"type": "response", "url": "https://example.com/admin/", "status": 200}])
        assert result["findings"][0]["severity"] == "HIGH"

    def test_404_skipped(self):
        from controller.analyzer import FeroxbusterAnalyzer
        result = FeroxbusterAnalyzer().analyze([{"type": "response", "url": "https://example.com/.env", "status": 404}])
        assert result["findings"] == []


# ──────────────────────────────────────────────────────────────────
# DNSXAnalyzer
# ──────────────────────────────────────────────────────────────────
class TestDNSXAnalyzer:
    def test_empty(self):
        from controller.analyzer import DNSXAnalyzer
        result = DNSXAnalyzer().analyze([])
        assert result["hosts_resolved"] == 0

    def test_clean_host_no_finding(self):
        from controller.analyzer import DNSXAnalyzer
        result = DNSXAnalyzer().analyze([{"host": "example.com", "a": ["1.2.3.4"]}])
        assert result["findings"] == []

    def test_dangling_s3_cname(self):
        from controller.analyzer import DNSXAnalyzer
        result = DNSXAnalyzer().analyze([
            {"host": "assets.example.com", "cname": ["assets.s3.amazonaws.com"]}
        ])
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["code"] == "DNSX_DANGLING_CNAME"
        assert result["findings"][0]["severity"] == "HIGH"

    def test_missing_spf_with_mx(self):
        from controller.analyzer import DNSXAnalyzer
        result = DNSXAnalyzer().analyze([
            {"host": "example.com", "mx": ["mail.example.com"], "txt": ["some-other-record"]}
        ])
        codes = [f["code"] for f in result["findings"]]
        assert "DNSX_MISSING_SPF" in codes

    def test_no_spf_finding_when_spf_present(self):
        from controller.analyzer import DNSXAnalyzer
        result = DNSXAnalyzer().analyze([
            {"host": "example.com", "mx": ["mail.example.com"], "txt": ["v=spf1 include:sendgrid.net ~all"]}
        ])
        codes = [f["code"] for f in result["findings"]]
        assert "DNSX_MISSING_SPF" not in codes


# ──────────────────────────────────────────────────────────────────
# SubdomainTakeoverAnalyzer
# ──────────────────────────────────────────────────────────────────
class TestSubdomainTakeoverAnalyzer:
    def test_empty(self):
        from controller.analyzer import SubdomainTakeoverAnalyzer
        result = SubdomainTakeoverAnalyzer().analyze([])
        assert result["subdomains_checked"] == 0
        assert result["findings"] == []

    def test_safe_subdomain_no_finding(self):
        from controller.analyzer import SubdomainTakeoverAnalyzer
        result = SubdomainTakeoverAnalyzer().analyze([{"subdomain": "www.example.com", "result": "NOT VULNERABLE"}])
        assert result["findings"] == []

    def test_vulnerable_subdomain_critical(self):
        from controller.analyzer import SubdomainTakeoverAnalyzer
        result = SubdomainTakeoverAnalyzer().analyze([
            {"subdomain": "old.example.com", "result": "VULNERABLE", "service": "AWS S3"}
        ])
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "CRITICAL"
        assert result["risk_summary"]["critical"] == 1

    def test_multiple_vulnerabilities(self):
        from controller.analyzer import SubdomainTakeoverAnalyzer
        records = [
            {"subdomain": "a.example.com", "result": "VULNERABLE", "service": "GitHub Pages"},
            {"subdomain": "b.example.com", "result": "VULNERABLE", "service": "Heroku"},
            {"subdomain": "c.example.com", "result": "NOT VULNERABLE", "service": "Custom"},
        ]
        result = SubdomainTakeoverAnalyzer().analyze(records)
        assert len(result["findings"]) == 2
        assert result["subdomains_checked"] == 3


# ──────────────────────────────────────────────────────────────────
# NaabuAnalyzer
# ──────────────────────────────────────────────────────────────────
class TestNaabuAnalyzer:
    def test_empty(self):
        from controller.analyzer import NaabuAnalyzer
        result = NaabuAnalyzer().analyze([])
        assert result["open_ports_count"] == 0

    def test_safe_port_443(self):
        from controller.analyzer import NaabuAnalyzer
        result = NaabuAnalyzer().analyze([{"host": "example.com", "port": 443}])
        assert result["findings"] == []

    def test_risky_telnet_port(self):
        from controller.analyzer import NaabuAnalyzer
        result = NaabuAnalyzer().analyze([{"host": "192.168.1.1", "port": 23}])
        assert result["findings"][0]["severity"] == "CRITICAL"

    def test_mongodb_critical(self):
        from controller.analyzer import NaabuAnalyzer
        result = NaabuAnalyzer().analyze([{"host": "db.example.com", "port": 27017}])
        assert result["findings"][0]["severity"] == "CRITICAL"
        assert result["risk_summary"]["critical"] == 1


# ──────────────────────────────────────────────────────────────────
# WAFDetectionAnalyzer
# ──────────────────────────────────────────────────────────────────
class TestWAFDetectionAnalyzer:
    def test_empty(self):
        from controller.analyzer import WAFDetectionAnalyzer
        result = WAFDetectionAnalyzer().analyze([])
        assert result["findings"] == []

    def test_waf_detected(self):
        from controller.analyzer import WAFDetectionAnalyzer
        result = WAFDetectionAnalyzer().analyze([{
            "url": "https://example.com",
            "detected": [{"firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}]
        }])
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "INFO"
        assert "Cloudflare" in result["findings"][0]["title"]

    def test_no_waf_detected(self):
        from controller.analyzer import WAFDetectionAnalyzer
        result = WAFDetectionAnalyzer().analyze([{"url": "https://example.com", "detected": []}])
        assert result["findings"] == []


# ──────────────────────────────────────────────────────────────────
# CORSAnalyzer
# ──────────────────────────────────────────────────────────────────
class TestCORSAnalyzer:
    def test_empty(self):
        from controller.analyzer import CORSAnalyzer
        result = CORSAnalyzer().analyze([])
        assert result["findings"] == []

    def test_null_origin_high(self):
        from controller.analyzer import CORSAnalyzer
        result = CORSAnalyzer().analyze([{"url": "https://api.example.com/data", "class": "Null Origin Allowed", "credentials": False}])
        assert result["findings"][0]["severity"] == "HIGH"

    def test_null_origin_with_credentials_critical(self):
        from controller.analyzer import CORSAnalyzer
        result = CORSAnalyzer().analyze([{"url": "https://api.example.com/data", "class": "Null Origin Allowed", "credentials": True}])
        assert result["findings"][0]["severity"] == "CRITICAL"
        assert result["risk_summary"]["critical"] == 1

    def test_origin_reflected(self):
        from controller.analyzer import CORSAnalyzer
        result = CORSAnalyzer().analyze([{"url": "https://api.example.com/data", "class": "Origin Reflected", "credentials": False}])
        assert result["findings"][0]["severity"] == "MEDIUM"


# ──────────────────────────────────────────────────────────────────
# CRLFAnalyzer
# ──────────────────────────────────────────────────────────────────
class TestCRLFAnalyzer:
    def test_empty(self):
        from controller.analyzer import CRLFAnalyzer
        result = CRLFAnalyzer().analyze([])
        assert result["findings"] == []

    def test_single_finding(self):
        from controller.analyzer import CRLFAnalyzer
        result = CRLFAnalyzer().analyze([{"url": "https://example.com/?r=foo%0d%0a", "payload": "%0d%0a"}])
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "MEDIUM"
        assert result["findings"][0]["code"] == "CRLF_INJECTION"

    def test_multiple_findings(self):
        from controller.analyzer import CRLFAnalyzer
        result = CRLFAnalyzer().analyze([
            {"url": "https://example.com/?r=foo%0d%0a"},
            {"url": "https://example.com/search?q=bar%0d%0a"},
        ])
        assert result["risk_summary"]["medium"] == 2
        assert result["risk_summary"]["total"] == 2


# ──────────────────────────────────────────────────────────────────
# SSTIAnalyzer
# ──────────────────────────────────────────────────────────────────
class TestSSTIAnalyzer:
    def test_empty(self):
        from controller.analyzer import SSTIAnalyzer
        result = SSTIAnalyzer().analyze([])
        assert result["findings"] == []

    def test_jinja2_critical(self):
        from controller.analyzer import SSTIAnalyzer
        result = SSTIAnalyzer().analyze([{"url": "https://example.com/render", "engine": "jinja2", "parameter": "name", "rce": False}])
        assert result["findings"][0]["severity"] == "CRITICAL"

    def test_rce_confirmed_max_severity(self):
        from controller.analyzer import SSTIAnalyzer
        result = SSTIAnalyzer().analyze([{"url": "https://example.com/render", "engine": "twig", "parameter": "template", "rce": True}])
        assert result["findings"][0]["score"] == 10.0
        assert result["risk_summary"]["critical"] == 1

    def test_unknown_engine_high(self):
        from controller.analyzer import SSTIAnalyzer
        result = SSTIAnalyzer().analyze([{"url": "https://example.com/render", "engine": "", "parameter": "q", "rce": False}])
        assert result["findings"][0]["severity"] == "HIGH"


# ──────────────────────────────────────────────────────────────────
# GitleaksAnalyzer
# ──────────────────────────────────────────────────────────────────
class TestGitleaksAnalyzer:
    def test_empty(self):
        from controller.analyzer import GitleaksAnalyzer
        result = GitleaksAnalyzer().analyze([])
        assert result["secrets_found"] == 0

    def test_aws_key_critical(self):
        from controller.analyzer import GitleaksAnalyzer
        result = GitleaksAnalyzer().analyze([{
            "RuleID": "aws-access-token",
            "File": "config/settings.py",
            "StartLine": 42,
            "Match": "aws_key=AKIAIOSFODNN7EXAMPLE",
            "Commit": "abc123",
        }])
        assert result["findings"][0]["severity"] == "CRITICAL"
        assert result["secrets_found"] == 1

    def test_secret_is_redacted_in_evidence(self):
        from controller.analyzer import GitleaksAnalyzer
        result = GitleaksAnalyzer().analyze([{
            "RuleID": "generic-api-key",
            "File": ".env",
            "StartLine": 1,
            "Match": "api_key=supersecretvalue123456",
            "Commit": "def456",
        }])
        evidence = result["findings"][0]["evidence"]["match_redacted"]
        assert "supersecretvalue" not in evidence
        assert "<REDACTED>" in evidence

    def test_multiple_secrets(self):
        from controller.analyzer import GitleaksAnalyzer
        records = [
            {"RuleID": "github-token", "File": "ci.yml", "StartLine": 10, "Match": "token=ghp_abc", "Commit": "x"},
            {"RuleID": "slack-token", "File": "notify.py", "StartLine": 5, "Match": "token=xoxb-123", "Commit": "y"},
        ]
        result = GitleaksAnalyzer().analyze(records)
        assert result["secrets_found"] == 2
        assert result["risk_summary"]["critical"] == 2
