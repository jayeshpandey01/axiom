"""Unit tests for GitHub CodeQL SARIF v2.1.0 Static Analysis Engine."""

import json
from pathlib import Path

from controller.agent import parse_codeql_output
from controller.sast_analyzer import CodeQLAnalyzer


def test_codeql_analyzer_empty_sarif():
    """Empty SARIF object or empty runs should yield zero findings without errors."""
    analyzer = CodeQLAnalyzer()
    res = analyzer.analyze({"version": "2.1.0", "runs": []})
    assert res["risk_summary"]["total"] == 0
    assert res["risk_summary"]["critical"] == 0
    assert res["risk_summary"]["high"] == 0
    assert res["risk_summary"]["medium"] == 0
    assert res["risk_summary"]["low"] == 0
    assert res["risk_summary"]["info"] == 0
    assert res["findings"] == []
    assert res["scanned_files_count"] == 0
    assert res["total_rules_evaluated"] == 0


def test_codeql_analyzer_valid_sarif_with_taint_flows():
    """Comprehensive test validating SARIF parsing with multiple severities, CWEs, and taint traces."""
    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "version": "2.16.0",
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "name": "py/sql-injection",
                                "shortDescription": {"text": "SQL query built from user-controlled sources"},
                                "fullDescription": {"text": "Concatenating untrusted user input into SQL queries enables injection."},
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-089"],
                                    "problem.severity": "error",
                                    "security-severity": "8.8",
                                },
                                "help": {"text": "Use parameterized queries or ORM abstractions instead."},
                            },
                            {
                                "id": "py/command-line-injection",
                                "name": "py/command-line-injection",
                                "shortDescription": {"text": "Uncontrolled command line execution"},
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-078"],
                                    "problem.severity": "error",
                                    "security-severity": "9.5",
                                },
                            },
                            {
                                "id": "py/weak-cryptographic-algorithm",
                                "name": "py/weak-cryptographic-algorithm",
                                "shortDescription": {"text": "Use of weak cryptographic hashing algorithm"},
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-327"],
                                    "problem.severity": "warning",
                                    "security-severity": "4.5",
                                },
                            },
                            {
                                "id": "py/cleartext-logging",
                                "name": "py/cleartext-logging",
                                "shortDescription": {"text": "Cleartext logging of sensitive information"},
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-312"],
                                    "problem.severity": "recommendation",
                                },
                                "defaultConfiguration": {"level": "note"},
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "error",
                        "message": {"text": "User-provided value flows into SQL execute sink."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/db/queries.py"},
                                    "region": {
                                        "startLine": 42,
                                        "startColumn": 5,
                                        "snippet": {"text": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"},
                                    },
                                }
                            }
                        ],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": "app/api/routes.py"},
                                                        "region": {"startLine": 18},
                                                    },
                                                    "message": {"text": "user_id enters from HTTP query parameter"},
                                                }
                                            },
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {"uri": "app/db/queries.py"},
                                                        "region": {"startLine": 42},
                                                    },
                                                    "message": {"text": "user_id formatted into raw SQL without sanitization"},
                                                }
                                            },
                                        ]
                                    }
                                ]
                            }
                        ],
                    },
                    {
                        "ruleId": "py/command-line-injection",
                        "level": "error",
                        "message": {"text": "Command line formatted with untrusted input."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/utils/exec.py"},
                                    "region": {"startLine": 105},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "py/weak-cryptographic-algorithm",
                        "level": "warning",
                        "message": {"text": "MD5 hash used for token generation."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/auth/tokens.py"},
                                    "region": {"startLine": 23},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "py/cleartext-logging",
                        "level": "note",
                        "message": {"text": "Sensitive variable printed to console logs."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/logger.py"},
                                    "region": {"startLine": 55},
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }

    analyzer = CodeQLAnalyzer()
    res = analyzer.analyze(sarif_data)

    # Risk summary verification
    summary = res["risk_summary"]
    assert summary["total"] == 4
    assert summary["critical"] == 1  # 9.5 CVSS -> CRITICAL
    assert summary["high"] == 1      # 8.8 CVSS -> HIGH
    assert summary["medium"] == 1    # 4.5 CVSS -> MEDIUM
    assert summary["low"] == 1       # note level -> LOW
    assert summary["info"] == 0

    assert res["scanned_files_count"] == 4
    assert res["total_rules_evaluated"] >= 4

    # Finding 1: SQL Injection
    f1 = res["findings"][0]
    assert f1["severity"] == "HIGH"
    assert f1["code"] == "codeql/py.sql-injection"
    assert f1["title"] == "SQL query built from user-controlled sources"
    assert "CWE-89" in f1["evidence"]["cwes"]
    assert f1["evidence"]["file"] == "app/db/queries.py"
    assert f1["evidence"]["line"] == 42
    assert "taint_trace" in f1["evidence"]
    assert len(f1["evidence"]["taint_trace"]) == 2
    assert f1["evidence"]["taint_trace"][0]["file"] == "app/api/routes.py"
    assert f1["remediation"] == "Use parameterized queries or ORM abstractions instead."

    # Finding 2: Command Injection
    f2 = res["findings"][1]
    assert f2["severity"] == "CRITICAL"
    assert "CWE-78" in f2["evidence"]["cwes"]

    # Finding 3: Weak Crypto
    f3 = res["findings"][2]
    assert f3["severity"] == "MEDIUM"
    assert "CWE-327" in f3["evidence"]["cwes"]

    # Finding 4: Cleartext logging
    f4 = res["findings"][3]
    assert f4["severity"] == "LOW"


def test_codeql_analyzer_rule_index_fallback():
    """Verify analyzer correctly resolves rule metadata when result references ruleIndex."""
    sarif_data = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/path-injection",
                                "name": "py/path-injection",
                                "shortDescription": {"text": "Arbitrary file write via path traversal"},
                                "properties": {"security-severity": "7.5", "tags": ["external/cwe/cwe-022"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleIndex": 0,
                        "message": {"text": "User controlled path leads to path traversal."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/storage.py"},
                                    "region": {"startLine": 88},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }

    analyzer = CodeQLAnalyzer()
    res = analyzer.analyze(sarif_data)
    assert res["risk_summary"]["total"] == 1
    assert res["risk_summary"]["high"] == 1
    f = res["findings"][0]
    assert f["code"] == "codeql/py.path-injection"
    assert "CWE-22" in f["evidence"]["cwes"]
    assert f["evidence"]["line"] == 88


def test_codeql_analyzer_json_string_and_invalid_data():
    """Ensure raw string JSON is parsed and malformed input handled gracefully."""
    analyzer = CodeQLAnalyzer()

    # Valid string
    valid_str = json.dumps({"version": "2.1.0", "runs": []})
    res = analyzer.analyze(valid_str)
    assert res["risk_summary"]["total"] == 0

    # Malformed string
    res_bad = analyzer.analyze("NOT_JSON_DATA_!!!")
    assert res_bad["risk_summary"]["total"] == 0
    assert res_bad["findings"] == []


def test_parse_codeql_output_file(tmp_path: Path):
    """Verify parse_codeql_output helper reading from disk."""
    sarif_path = tmp_path / "results.sarif"

    # Missing file
    res_missing = parse_codeql_output(tmp_path / "non_existent.sarif")
    assert res_missing["risk_summary"]["total"] == 0

    # Empty file
    sarif_path.write_text("", encoding="utf-8")
    res_empty = parse_codeql_output(sarif_path)
    assert res_empty["risk_summary"]["total"] == 0

    # Valid SARIF file
    sample = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "CodeQL", "rules": []}},
                "results": [
                    {
                        "ruleId": "py/hardcoded-credentials",
                        "level": "error",
                        "message": {"text": "Hardcoded secret found in configuration."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "config.py"},
                                    "region": {"startLine": 12},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    sarif_path.write_text(json.dumps(sample), encoding="utf-8")
    res_valid = parse_codeql_output(sarif_path)
    assert res_valid["risk_summary"]["total"] == 1
    assert res_valid["risk_summary"]["high"] == 1
    assert res_valid["findings"][0]["evidence"]["file"] == "config.py"
