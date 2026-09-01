from pathlib import Path
from unittest.mock import patch

import pytest

from controller.config import settings
from controller.fleet_manager import FleetManager
from controller.profiles import get_profile
from controller.watchdog import OrphanWatchdog


def test_supported_profiles() -> None:
    recon = get_profile("recon")
    assert recon.name == "recon"
    assert recon.axiom_module == "httpx"
    assert "-json" in recon.extra_flags

    web = get_profile("web-discovery")
    assert web.name == "web-discovery"

    with pytest.raises(ValueError, match="Unsupported scan profile"):
        get_profile("arbitrary-nmap-profile")


def test_new_profiles_exist() -> None:
    """All four new scanner profiles must be registered and have correct configuration."""
    nmap_profile = get_profile("network-portscan")
    assert nmap_profile.name == "network-portscan"
    assert nmap_profile.axiom_module == "nmap"
    assert nmap_profile.standalone_binary == "nmap"
    assert nmap_profile.default_timeout_sec == 900

    masscan_profile = get_profile("fast-portscan")
    assert masscan_profile.name == "fast-portscan"
    assert masscan_profile.axiom_module == "masscan"
    assert masscan_profile.standalone_binary == "masscan"

    ffuf_profile = get_profile("content-discovery")
    assert ffuf_profile.name == "content-discovery"
    assert ffuf_profile.axiom_module == "ffuf"
    assert ffuf_profile.standalone_binary == "ffuf"

    nuclei_profile = get_profile("vuln-assessment")
    assert nuclei_profile.name == "vuln-assessment"
    assert nuclei_profile.axiom_module == "nuclei"
    assert nuclei_profile.standalone_binary == "nuclei"
    assert "-severity" in nuclei_profile.extra_flags


def test_fleet_manager_enforces_max_fleet_size() -> None:
    manager = FleetManager(dry_run=True)
    with pytest.raises(ValueError, match="exceeds maximum allowed fleet size"):
        manager.create_fleet("overflow-fleet", count=settings.max_fleet_size + 1)


def test_dry_run_scan_execution(tmp_path: Path) -> None:
    manager = FleetManager(dry_run=True)
    manager.work_dir = tmp_path
    output_file = tmp_path / "test_out.json"

    with manager.managed_fleet("test-fleet-1", count=1) as fleet:
        assert fleet == "test-fleet-1"
        res = manager.execute_scan(fleet, "recon", "scanme.nmap.org", output_file)
        assert res == output_file


def test_guaranteed_teardown_on_exception() -> None:
    manager = FleetManager(dry_run=True)
    with patch.object(manager, "destroy_fleet", wraps=manager.destroy_fleet) as mock_destroy:
        with pytest.raises(RuntimeError, match="Simulated mid-scan failure"):
            with manager.managed_fleet("failing-fleet", count=1):
                raise RuntimeError("Simulated mid-scan failure")

        # Verify teardown was called despite the exception
        mock_destroy.assert_called_once_with("failing-fleet")


def test_watchdog_dry_run_cleanup() -> None:
    manager = FleetManager(dry_run=True)
    watchdog = OrphanWatchdog(manager=manager)
    purged = watchdog.cleanup_all_fleets(force=True)
    assert isinstance(purged, int)


def test_dry_run_nmap_scan(tmp_path: Path) -> None:
    """Dry-run network-portscan must produce parseable nmap XML output."""
    manager = FleetManager(dry_run=True)
    manager.work_dir = tmp_path
    output_file = tmp_path / "nmap_out.xml"

    with manager.managed_fleet("test-nmap-fleet", count=1) as fleet:
        res = manager.execute_scan(fleet, "network-portscan", "scanme.nmap.org", output_file)
        assert res == output_file
        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        assert "nmaprun" in content  # XML root element
        assert "open" in content      # at least one open port in mock


def test_dry_run_masscan_scan(tmp_path: Path) -> None:
    """Dry-run fast-portscan must produce parseable masscan JSON output."""
    import json
    manager = FleetManager(dry_run=True)
    manager.work_dir = tmp_path
    output_file = tmp_path / "masscan_out.json"

    with manager.managed_fleet("test-masscan-fleet", count=1) as fleet:
        manager.execute_scan(fleet, "fast-portscan", "scanme.nmap.org", output_file)
        assert output_file.exists()
        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        assert any("ports" in entry for entry in data)


def test_dry_run_ffuf_scan(tmp_path: Path) -> None:
    """Dry-run content-discovery must produce parseable FFUF JSON output."""
    import json
    manager = FleetManager(dry_run=True)
    manager.work_dir = tmp_path
    output_file = tmp_path / "ffuf_out.json"

    with manager.managed_fleet("test-ffuf-fleet", count=1) as fleet:
        manager.execute_scan(fleet, "content-discovery", "example.com", output_file)
        assert output_file.exists()
        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert "results" in data
        assert len(data["results"]) > 0


def test_dry_run_nuclei_scan(tmp_path: Path) -> None:
    """Dry-run vuln-assessment must produce parseable Nuclei JSONL output."""
    import json
    manager = FleetManager(dry_run=True)
    manager.work_dir = tmp_path
    output_file = tmp_path / "nuclei_out.jsonl"

    with manager.managed_fleet("test-nuclei-fleet", count=1) as fleet:
        manager.execute_scan(fleet, "vuln-assessment", "example.com", output_file)
        assert output_file.exists()
        lines = [line.strip() for line in output_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert len(lines) >= 1
        record = json.loads(lines[0])
        assert "template-id" in record
        assert "info" in record


def test_vulnerability_analyzer_classifies_findings() -> None:
    from controller.analyzer import VulnerabilityAnalyzer

    sample_records = [
        {
            "url": "https://example.com",
            "status_code": 200,
            "webserver": "Apache/2.4.41 (Ubuntu)",
            "title": "Example Domain Admin Dashboard",
            "tech": ["Apache", "PHP", "Ubuntu"],
            "header": {
                "Server": "Apache/2.4.41 (Ubuntu)",
                "X-Powered-By": "PHP/7.4.3",
            },
        }
    ]

    analyzer = VulnerabilityAnalyzer()
    summary = analyzer.analyze(sample_records)

    assert summary["live_hosts_count"] == 1
    assert "risk_summary" in summary
    assert summary["risk_summary"]["low"] >= 1
    assert summary["risk_summary"]["total"] >= 1

    findings = summary["findings"]
    finding_codes = [f["code"] for f in findings]

    assert "INFO_SERVER_BANNER_LEAK" in finding_codes
    assert "INFO_POWERED_BY_LEAK" in finding_codes
    assert "SEC_HEADER_MISSING_HSTS" in finding_codes
    assert "RECON_TECH_DETECTED" in finding_codes


def test_port_scan_analyzer_classifies_risky_ports() -> None:
    from controller.analyzer import PortScanAnalyzer

    records = [
        {"ip": "1.2.3.4", "host_state": "up", "port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "8.9"},
        {"ip": "1.2.3.4", "host_state": "up", "port": 3306, "protocol": "tcp", "service": "mysql", "product": "MySQL", "version": "8.0"},
        {"ip": "1.2.3.4", "host_state": "up", "port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.18"},
    ]

    analyzer = PortScanAnalyzer()
    summary = analyzer.analyze(records)

    assert summary["risk_summary"]["total"] >= 1
    assert len(summary["open_ports"]) == 3
    finding_codes = [f["code"] for f in summary["findings"]]
    assert "OPEN_PORT_RISK_HIGH" in finding_codes   # port 22 and 3306
    assert "SERVICE_VERSION_DISCLOSURE" in finding_codes
    assert "UNENCRYPTED_NETWORK_SERVICE" in finding_codes  # port 80
    assert "OPEN_PORT_SUMMARY" in finding_codes
    assert summary["risk_summary"]["high"] >= 2   # port 22 + 3306


def test_content_discovery_analyzer_flags_sensitive_paths() -> None:
    from controller.analyzer import ContentDiscoveryAnalyzer

    records = [
        {"url": "https://example.com/admin", "status": 200, "length": 1024, "words": 50, "lines": 30, "duration": 10},
        {"url": "https://example.com/.env", "status": 200, "length": 256, "words": 10, "lines": 5, "duration": 8},
        {"url": "https://example.com/api", "status": 200, "length": 512, "words": 8, "lines": 1, "duration": 12},
        {"url": "https://example.com/secret", "status": 403, "length": 0, "words": 0, "lines": 0, "duration": 5},
    ]

    analyzer = ContentDiscoveryAnalyzer()
    summary = analyzer.analyze(records)

    finding_codes = [f["code"] for f in summary["findings"]]
    assert "SENSITIVE_PATH_EXPOSED" in finding_codes
    assert "AUTH_BYPASS_CANDIDATE" in finding_codes
    assert "DISCOVERY_SUMMARY" in finding_codes
    assert summary["risk_summary"]["high"] >= 1  # /admin and /.env are HIGH
    assert len(summary["discovered_paths"]) == 4


def test_nuclei_analyzer_normalizes_severity() -> None:
    from controller.analyzer import NucleiAnalyzer

    records = [
        {
            "template-id": "http-missing-security-headers",
            "info": {"name": "Missing Security Headers", "severity": "info", "description": "Headers missing."},
            "host": "https://example.com",
            "matched-at": "https://example.com",
            "extracted-results": [],
        },
        {
            "template-id": "CVE-2021-44228",
            "info": {"name": "Log4Shell RCE", "severity": "critical", "description": "Log4j RCE."},
            "host": "https://example.com",
            "matched-at": "https://example.com/api",
            "extracted-results": ["jndi:ldap://attacker.com"],
        },
    ]

    analyzer = NucleiAnalyzer()
    summary = analyzer.analyze(records)

    assert summary["templates_matched"] == 2
    assert summary["risk_summary"]["critical"] == 1
    assert summary["risk_summary"]["info"] == 1
    assert "CVE-2021-44228" in summary["cve_ids"]
    findings = summary["findings"]
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    assert critical[0]["title"] == "Log4Shell RCE"
