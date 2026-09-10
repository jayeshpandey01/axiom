from controller.sast_analyzer import BanditAnalyzer


def test_bandit_analyzer_empty():
    analyzer = BanditAnalyzer()
    res = analyzer.analyze({})
    assert res["risk_summary"]["total"] == 0
    assert len(res["findings"]) == 0

def test_bandit_analyzer_findings():
    analyzer = BanditAnalyzer()

    mock_data = {
      "errors": [],
      "generated_at": "2026-09-11T00:30:00Z",
      "metrics": {
        "_totals": {
          "CONFIDENCE.HIGH": 1,
          "SEVERITY.HIGH": 1,
          "loc": 10
        }
      },
      "results": [
        {
          "code": "5     def func():\n6         pass\n",
          "filename": "example.py",
          "issue_confidence": "HIGH",
          "issue_cwe": {
            "id": 295,
            "link": "https://cwe.mitre.org/data/definitions/295.html"
          },
          "issue_severity": "HIGH",
          "issue_text": "Call to httpx with verify=False",
          "line_number": 6,
          "line_range": [6],
          "more_info": "https://bandit.readthedocs.io/en/latest/",
          "test_id": "B501",
          "test_name": "request_with_no_cert_validation"
        }
      ]
    }

    res = analyzer.analyze(mock_data)

    assert res["risk_summary"]["critical"] == 1
    assert res["risk_summary"]["total"] == 1

    finding = res["findings"][0]
    assert finding["code"] == "bandit/B501"
    assert finding["severity"] == "CRITICAL" # HIGH severity + HIGH confidence = CRITICAL
    assert "Call to httpx with verify=False" in finding["description"]
    assert "CWE-295" in finding["evidence"]["cwes"]
    assert finding["evidence"]["file"] == "example.py"
    assert finding["evidence"]["line"] == 6
    assert finding["actual_logs"]

def test_bandit_analyzer_medium_severity():
    analyzer = BanditAnalyzer()

    mock_data = {
      "results": [
        {
          "filename": "test.py",
          "issue_confidence": "HIGH",
          "issue_severity": "MEDIUM",
          "issue_text": "MD5 used",
          "test_id": "B324",
          "test_name": "hashlib_md5"
        }
      ]
    }

    res = analyzer.analyze(mock_data)
    assert res["risk_summary"]["medium"] == 1
    assert res["findings"][0]["severity"] == "MEDIUM"

