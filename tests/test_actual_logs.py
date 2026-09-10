from controller.analyzer import (
    ContentDiscoveryAnalyzer,
    DalfoxAnalyzer,
    InteractshAnalyzer,
    NucleiAnalyzer,
    PortScanAnalyzer,
    VulnerabilityAnalyzer,
    ZAPAnalyzer,
)
from controller.sast_analyzer import (
    CodeQLAnalyzer,
    SemgrepAnalyzer,
    TruffleHogAnalyzer,
)


def test_vulnerability_analyzer_has_actual_logs():
    analyzer = VulnerabilityAnalyzer()
    res = analyzer.analyze([{"url": "https://example.com", "header": {"Server": "Apache/2.4"}}])
    assert len(res["findings"]) > 0
    for f in res["findings"]:
        assert "actual_logs" in f
        assert "Actual_logs" in f
        assert f["actual_logs"] == f["Actual_logs"]
        assert len(str(f["actual_logs"])) > 0


def test_port_scan_analyzer_has_actual_logs():
    analyzer = PortScanAnalyzer()
    res = analyzer.analyze([{"ip": "1.2.3.4", "port": 21, "protocol": "tcp", "service": "ftp"}])
    assert len(res["findings"]) > 0
    for f in res["findings"]:
        assert "actual_logs" in f
        assert "Actual_logs" in f
        assert len(str(f["actual_logs"])) > 0


def test_content_discovery_analyzer_has_actual_logs():
    analyzer = ContentDiscoveryAnalyzer()
    res = analyzer.analyze([{"url": "http://example.com/admin", "status": 200, "length": 500}])
    assert len(res["findings"]) > 0
    for f in res["findings"]:
        assert "actual_logs" in f
        assert "Actual_logs" in f
        assert len(str(f["actual_logs"])) > 0


def test_nuclei_analyzer_has_actual_logs():
    analyzer = NucleiAnalyzer()
    res = analyzer.analyze([{"template-id": "test-cve", "info": {"name": "Test CVE", "severity": "high"}, "matched-at": "http://example.com"}])
    assert len(res["findings"]) > 0
    for f in res["findings"]:
        assert "actual_logs" in f
        assert "Actual_logs" in f
        assert len(str(f["actual_logs"])) > 0


def test_dalfox_analyzer_has_actual_logs():
    analyzer = DalfoxAnalyzer()
    res = analyzer.analyze([{"type": "V", "param": "q", "payload": "<script>alert(1)</script>", "url": "http://example.com?q=1"}])
    assert len(res["findings"]) > 0
    for f in res["findings"]:
        assert "actual_logs" in f
        assert "Actual_logs" in f
        assert len(str(f["actual_logs"])) > 0


def test_zap_analyzer_has_actual_logs():
    analyzer = ZAPAnalyzer()
    res = analyzer.analyze({"alerts": [{"pluginId": "10001", "alert": "Test Alert", "riskcode": "3", "confidence": "2", "desc": "Desc", "solution": "Fix"}]})
    assert len(res["findings"]) > 0
    for f in res["findings"]:
        assert "actual_logs" in f
        assert "Actual_logs" in f
        assert len(str(f["actual_logs"])) > 0


def test_interactsh_analyzer_has_actual_logs():
    analyzer = InteractshAnalyzer()
    res = analyzer.analyze([{"protocol": "dns", "unique-id": "abc", "full-id": "abc.oast.me", "q-type": "A", "remote-address": "1.2.3.4"}])
    assert len(res["findings"]) > 0
    for f in res["findings"]:
        assert "actual_logs" in f
        assert "Actual_logs" in f
        assert len(str(f["actual_logs"])) > 0


def test_sast_analyzers_have_actual_logs():
    # Semgrep
    sem_res = SemgrepAnalyzer().analyze({"results": [{"check_id": "test.rule", "path": "app.py", "extra": {"message": "Msg", "severity": "ERROR"}}]})
    assert len(sem_res["findings"]) > 0
    assert "actual_logs" in sem_res["findings"][0]
    assert "Actual_logs" in sem_res["findings"][0]

    # TruffleHog
    truffle_res = TruffleHogAnalyzer().analyze([{"DetectorName": "AWS", "Verified": True, "Redacted": "AKIA***"}])
    assert len(truffle_res["findings"]) > 0
    assert "actual_logs" in truffle_res["findings"][0]
    assert "Actual_logs" in truffle_res["findings"][0]

    # CodeQL
    codeql_res = CodeQLAnalyzer().analyze({"runs": [{"tool": {"driver": {"rules": [{"id": "py/test"}]}}, "results": [{"ruleId": "py/test", "message": {"text": "CodeQL finding"}}]}]})
    assert len(codeql_res["findings"]) > 0
    assert "actual_logs" in codeql_res["findings"][0]
    assert "Actual_logs" in codeql_res["findings"][0]
