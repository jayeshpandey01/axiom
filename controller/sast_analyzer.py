"""Dedicated SAST & Code Property Graph (CPG) Analysis Engine for Joern.

Analyzes raw Joern static analysis output (both structured JSON and `joern-scan`
plaintext output), maps dataflow taint traces and AST/CFG pattern findings,
and produces normalized security findings with line-level code evidence and
remediation advice.
"""

import json
import re
from typing import Any


def score_to_severity(score: float | int) -> str:
    """Map numeric CVSS/Joern score (0.0 - 10.0) to standard severity label."""
    try:
        val = float(score)
    except (ValueError, TypeError):
        return "MEDIUM"

    if val >= 9.0:
        return "CRITICAL"
    if val >= 7.0:
        return "HIGH"
    if val >= 4.0:
        return "MEDIUM"
    if val >= 1.0:
        return "LOW"
    return "INFO"


# Standard remediation database for common SAST vulnerability classes
_REMEDIATION_MAP: dict[str, str] = {
    "sql-injection": "Use parameterized queries or ORM abstractions instead of concatenating raw user input into SQL queries.",
    "sqli": "Use parameterized queries or prepared statements.",
    "command-injection": "Avoid executing dynamic shell commands. Use subprocess with argument lists and shell=False.",
    "rce": "Sanitize and validate all external inputs before passing them to execution contexts.",
    "path-traversal": "Validate and canonicalize file paths using os.path.realpath and verify they reside within the allowed directory root.",
    "deserialization": "Avoid deserializing untrusted data with pickle/yaml.load; use safe serialization formats like JSON.",
    "ssrf": "Validate and whitelist destination hostnames and IP addresses, blocking RFC1918 and cloud metadata endpoints (169.254.169.254).",
    "xss": "Contextually encode user-controlled output in HTML/template rendering and enforce a strict Content-Security-Policy.",
    "hardcoded-secret": "Store secrets, API keys, and credentials in environment variables or a dedicated secrets manager (e.g., Vault, AWS Secrets Manager).",
    "buffer-overflow": "Use bounds-checked string and memory manipulation functions (e.g. strncpy_s, snprintf) or memory-safe languages.",
    "use-after-free": "Ensure pointers are set to NULL immediately after freeing, or utilize RAII/smart pointers.",
    "weak-crypto": "Replace weak cryptographic algorithms (MD5, SHA1, DES) with modern standards (SHA-256, AES-GCM, Argon2/bcrypt for passwords).",
}


def _get_remediation_for_title(title: str) -> str:
    """Derive appropriate remediation guidance based on rule title keywords."""
    title_lower = title.lower()
    for key, remediation in _REMEDIATION_MAP.items():
        if key in title_lower or key.replace("-", " ") in title_lower:
            return remediation
    return "Review the identified code location and sanitize input data before passing it to sensitive operations."


class JoernAnalyzer:
    """Evaluates Joern static analysis output for code vulnerabilities and dataflow flaws."""

    # Regex for standard joern-scan plaintext output:
    # Result: 9.0 : SQL Injection in handler : src/app.py:42:handle_request
    _SCAN_OUTPUT_REGEX = re.compile(
        r"^(?:Result:\s*)?(?P<score>\d+(?:\.\d+)?)\s*:\s*(?P<title>[^:]+)\s*:\s*(?P<location>[^:]+)(?::(?P<line>\d+))?(?::(?P<func>.+))?$",
        re.IGNORECASE,
    )

    def analyze(self, raw_data: list[dict[str, Any]] | list[str] | str) -> dict[str, Any]:
        """Analyze Joern scan results and return normalized findings and risk summary.

        Args:
            raw_data: Can be a list of JSON record dicts, a list of plaintext lines,
                      or a single raw string containing JSON or joern-scan lines.

        Returns:
            Standardized dict containing risk_summary, findings, scanned_files_count,
            and total_rules_evaluated.
        """
        findings: list[dict[str, Any]] = []
        finding_id_counter = 1
        scanned_files: set[str] = set()

        def add_finding(
            code: str,
            severity: str,
            title: str,
            description: str,
            evidence: Any,
            remediation: str | None = None,
            logs: str | None = None,
            actual_logs: Any = None,
        ) -> None:
            nonlocal finding_id_counter
            log_entry = logs if logs is not None else f"[{code}] {title} | Evidence: {evidence}"
            actual_log_entry = actual_logs if actual_logs is not None else log_entry
            findings.append(
                {
                    "id": f"SEC-{finding_id_counter:03d}",
                    "code": code,
                    "logs": log_entry,
                    "severity": severity.upper(),
                    "title": title,
                    "description": description,
                    "evidence": evidence,
                    "remediation": remediation or _get_remediation_for_title(title),
                    "actual_logs": actual_log_entry,
                    "Actual_logs": actual_log_entry,
                }
            )
            finding_id_counter += 1

        # Normalize raw_data into lines or dict records
        records_to_process: list[Any] = []
        if isinstance(raw_data, str):
            cleaned = raw_data.strip()
            if cleaned.startswith("[") and cleaned.endswith("]"):
                try:
                    records_to_process = json.loads(cleaned)
                except json.JSONDecodeError:
                    records_to_process = cleaned.splitlines()
            elif cleaned.startswith("{") and cleaned.endswith("}"):
                try:
                    records_to_process = [json.loads(cleaned)]
                except json.JSONDecodeError:
                    records_to_process = cleaned.splitlines()
            else:
                records_to_process = cleaned.splitlines()
        elif isinstance(raw_data, list):
            records_to_process = raw_data

        for item in records_to_process:
            # Case 1: Structured JSON dictionary
            if isinstance(item, dict):
                rule_id = item.get("rule_id") or item.get("query_name") or item.get("id") or "VULN"
                title = item.get("title") or item.get("name") or str(rule_id)
                description = item.get("description") or "Static code analysis pattern match detected by Joern CPG."
                score = item.get("score", 7.0)
                raw_severity = item.get("severity")
                severity = raw_severity.upper() if raw_severity else score_to_severity(score)

                filepath = item.get("file") or item.get("filename") or item.get("path") or "unknown_file"
                line = item.get("line") or item.get("lineNumber") or item.get("line_number")
                func = item.get("function") or item.get("method") or item.get("methodName")
                snippet = item.get("evidence") or item.get("snippet") or item.get("code") or ""

                if filepath != "unknown_file":
                    scanned_files.add(str(filepath))

                location_str = str(filepath)
                if line:
                    location_str += f":{line}"
                if func:
                    location_str += f" ({func})"

                evidence = {
                    "location": location_str,
                    "file": str(filepath),
                    "line": int(line) if line and str(line).isdigit() else None,
                    "function": str(func) if func else None,
                    "snippet": str(snippet) if snippet else None,
                }
                if item.get("flow"):
                    evidence["flow"] = item.get("flow")

                code = f"JOERN_{str(rule_id).upper().replace('-', '_').replace(' ', '_')}"
                remediation = item.get("remediation")

                add_finding(
                    code=code,
                    severity=severity,
                    title=title,
                    description=description,
                    evidence=evidence,
                    remediation=remediation,
                    logs=json.dumps(item, indent=2),
                )

            # Case 2: Plaintext line from joern-scan
            elif isinstance(item, str):
                line_str = item.strip()
                if not line_str or line_str.startswith("#"):
                    continue

                # Try parsing as single JSON line
                if line_str.startswith("{") and line_str.endswith("}"):
                    try:
                        record_dict = json.loads(line_str)
                        if isinstance(record_dict, dict):
                            records_to_process.append(record_dict)
                            continue
                    except json.JSONDecodeError:
                        pass

                match = self._SCAN_OUTPUT_REGEX.match(line_str)
                if match:
                    score_val = float(match.group("score"))
                    title_val = match.group("title").strip()
                    loc_val = match.group("location").strip()
                    line_num = match.group("line")
                    func_name = match.group("func")

                    scanned_files.add(loc_val)
                    sev = score_to_severity(score_val)
                    clean_code = "JOERN_" + re.sub(r"[^A-Za-z0-9]+", "_", title_val).upper().strip("_")

                    evidence_dict = {
                        "location": f"{loc_val}:{line_num}" if line_num else loc_val,
                        "file": loc_val,
                        "line": int(line_num) if line_num else None,
                        "function": func_name.strip() if func_name else None,
                    }

                    add_finding(
                        code=clean_code,
                        severity=sev,
                        title=title_val,
                        description=f"Potential {title_val} detected by Joern CPG dataflow/AST query (score: {score_val}).",
                        evidence=evidence_dict,
                        logs=line_str,
                    )
                else:
                    # Generic non-empty line
                    if "result:" in line_str.lower() or "error" in line_str.lower() or "vulnerability" in line_str.lower():
                        add_finding(
                            code="JOERN_GENERIC_FINDING",
                            severity="MEDIUM",
                            title="Code Analysis Finding",
                            description="Joern reported an issue during static analysis.",
                            evidence={"raw": line_str},
                            logs=line_str,
                        )

        risk_summary = {
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
            "info": sum(1 for f in findings if f["severity"] == "INFO"),
            "total": len(findings),
        }

        return {
            "risk_summary": risk_summary,
            "findings": findings,
            "scanned_files_count": len(scanned_files),
            "total_rules_evaluated": len(findings),
        }


class SemgrepAnalyzer:
    """Evaluates Semgrep AST pattern and security audit output."""

    @staticmethod
    def _normalize_severity(raw_severity: str, check_id: str = "") -> str:
        s = str(raw_severity).upper().strip()
        check_lower = str(check_id).lower()
        if (
            "sqli" in check_lower
            or "sql-injection" in check_lower
            or "rce" in check_lower
            or "command-injection" in check_lower
            or "system-call" in check_lower
            or "dangerous-system" in check_lower
            or "code-execution" in check_lower
        ):
            return "CRITICAL"
        if s in ("ERROR", "CRITICAL"):
            return "HIGH"
        if s in ("WARNING", "WARN", "MEDIUM"):
            return "MEDIUM"
        if s in ("INFO", "LOW"):
            return "LOW"
        return "INFO"

    def analyze(self, raw_data: dict[str, Any] | list[dict[str, Any]] | str) -> dict[str, Any]:
        """Analyze Semgrep JSON results and return normalized findings and risk summary.

        Args:
            raw_data: Semgrep JSON output dictionary or raw string containing 'results' list.

        Returns:
            Normalized dictionary containing risk_summary and list of findings.
        """
        if isinstance(raw_data, str):
            try:
                data = json.loads(raw_data)
            except Exception:
                data = {"results": []}
        elif isinstance(raw_data, list):
            data = {"results": raw_data}
        elif isinstance(raw_data, dict):
            data = raw_data
        else:
            data = {"results": []}

        results = data.get("results", [])
        if not isinstance(results, list):
            results = []

        scanned_files = set()
        paths_data = data.get("paths", {})
        if isinstance(paths_data, dict) and "scanned" in paths_data:
            scanned_files.update(paths_data["scanned"])

        findings: list[dict[str, Any]] = []
        finding_id_counter = 1

        for r in results:
            if not isinstance(r, dict):
                continue
            check_id = str(r.get("check_id", "unknown-rule"))
            file_path = str(r.get("path", "unknown_file"))
            scanned_files.add(file_path)

            start = r.get("start", {})
            start_line = start.get("line") if isinstance(start, dict) else None
            start_col = start.get("col") if isinstance(start, dict) else None

            extra = r.get("extra", {})
            if not isinstance(extra, dict):
                extra = {}

            message = extra.get("message", "Semgrep security finding detected.")
            raw_severity = extra.get("severity", "WARNING")
            lines_snippet = extra.get("lines", "")
            metadata = extra.get("metadata", {})
            if not isinstance(metadata, dict):
                metadata = {}

            severity = self._normalize_severity(raw_severity, check_id)

            # Derive title and remediation
            title = message.split("\n")[0][:120].strip() if message else f"Security Finding ({check_id})"
            remediation = _get_remediation_for_title(f"{check_id} {message}")

            code_slug = "SEMGREP_" + re.sub(r"[^A-Za-z0-9]+", "_", check_id).strip("_").upper()[:45]

            loc_str = f"{file_path}"
            if start_line is not None:
                loc_str += f":{start_line}"
                if start_col is not None:
                    loc_str += f":{start_col}"

            evidence = {
                "location": loc_str,
                "file": file_path,
                "line": start_line,
                "column": start_col,
                "snippet": lines_snippet.strip() if lines_snippet else None,
                "check_id": check_id,
            }
            if "cwe" in metadata:
                evidence["cwe"] = metadata["cwe"]
            if "owasp" in metadata:
                evidence["owasp"] = metadata["owasp"]

            findings.append(
                {
                    "id": f"SEC-{finding_id_counter:03d}",
                    "code": code_slug,
                    "logs": json.dumps(r, indent=2),
                    "severity": severity,
                    "title": title,
                    "description": message,
                    "evidence": evidence,
                    "remediation": remediation,
                    "actual_logs": json.dumps(r, indent=2),
                    "Actual_logs": json.dumps(r, indent=2),
                }
            )
            finding_id_counter += 1

        risk_summary = {
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
            "info": sum(1 for f in findings if f["severity"] == "INFO"),
            "total": len(findings),
        }

        return {
            "risk_summary": risk_summary,
            "findings": findings,
            "scanned_files_count": len(scanned_files),
            "total_rules_evaluated": len(findings),
        }


class TruffleHogAnalyzer:
    """Evaluates TruffleHog secret and leaked credential detection output."""

    @staticmethod
    def _get_secret_remediation(detector_name: str) -> str:
        d = detector_name.lower()
        if "aws" in d:
            return "Immediately revoke the compromised credential in AWS IAM console, audit CloudTrail logs for unauthorized usage, and rotate secrets using AWS Secrets Manager."
        if "github" in d:
            return "Revoke the exposed GitHub token or SSH key immediately in GitHub Developer Settings and inspect repository audit logs for unauthorized access."
        if "slack" in d or "discord" in d:
            return "Revoke the exposed webhook URL or bot token immediately in the application integration settings and re-generate a new token."
        if "openai" in d or "anthropic" in d:
            return "Revoke the AI API token in the provider's developer console, audit billing usage, and inject keys via environment variables."
        if "jwt" in d or "private" in d or "ssh" in d:
            return "Generate a new cryptographic key pair, invalidate all active sessions/tokens signed with the old key, and deploy the new key securely."
        return "Immediately revoke and rotate the exposed credential. Audit service logs for unauthorized access and store secrets in a managed vault."

    def analyze(self, raw_data: list[dict[str, Any]] | dict[str, Any] | str) -> dict[str, Any]:
        """Analyze TruffleHog NDJSON or list of finding dictionaries.

        Args:
            raw_data: String with newline-delimited JSON, parsed list of dicts, or single dict.

        Returns:
            Normalized dictionary containing risk_summary and list of findings.
        """
        records: list[dict[str, Any]] = []

        if isinstance(raw_data, str):
            for line in raw_data.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        elif isinstance(raw_data, list):
            records = [r for r in raw_data if isinstance(r, dict)]
        elif isinstance(raw_data, dict):
            if "results" in raw_data and isinstance(raw_data["results"], list):
                records = raw_data["results"]
            else:
                records = [raw_data]

        scanned_files = set()
        findings: list[dict[str, Any]] = []
        finding_id_counter = 1

        for r in records:
            detector = str(r.get("DetectorName") or r.get("detector_name") or "GenericSecret")
            verified = bool(r.get("Verified", False))
            redacted = str(r.get("Redacted") or r.get("redacted") or "<REDACTED>")

            # Extract filesystem location
            file_path = "unknown_file"
            line_num: int | None = None
            source_meta = r.get("SourceMetadata") or {}
            if isinstance(source_meta, dict):
                data = source_meta.get("Data") or {}
                if isinstance(data, dict):
                    fs = data.get("Filesystem") or {}
                    if isinstance(fs, dict):
                        file_path = str(fs.get("file") or file_path)
                        line_num = fs.get("line")

            # Fallback direct keys if flattened
            if file_path == "unknown_file" and "file" in r:
                file_path = str(r["file"])
            if line_num is None and "line" in r:
                line_num = r.get("line")

            scanned_files.add(file_path)

            # Severity: Verified live keys are CRITICAL; unverified matches are HIGH
            severity = "CRITICAL" if verified else "HIGH"

            status_label = "Verified Active" if verified else "Potential Leaked"
            title = f"{status_label} {detector} Secret Detected"
            description = f"{status_label} {detector} credential discovered in source file '{file_path}'. Redacted secret: {redacted}"

            code_slug = "TRUFFLEHOG_" + re.sub(r"[^A-Za-z0-9]+", "_", detector).strip("_").upper()[:40]

            loc_str = file_path
            if line_num is not None:
                loc_str += f":{line_num}"

            evidence: dict[str, Any] = {
                "location": loc_str,
                "file": file_path,
                "line": line_num,
                "detector": detector,
                "verified": verified,
                "redacted_secret": redacted,
            }
            if "ExtraData" in r and isinstance(r["ExtraData"], dict):
                evidence["extra_data"] = r["ExtraData"]

            remediation = self._get_secret_remediation(detector)

            # Sanitize record for logs to strictly avoid secret leakage
            safe_record = dict(r)
            for secret_field in ("Raw", "raw", "Secret", "secret", "Value", "value"):
                if secret_field in safe_record:
                    safe_record[secret_field] = "<REDACTED>"

            findings.append(
                {
                    "id": f"SEC-{finding_id_counter:03d}",
                    "code": code_slug,
                    "logs": json.dumps(safe_record, indent=2),
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "evidence": evidence,
                    "remediation": remediation,
                    "actual_logs": json.dumps(safe_record, indent=2),
                    "Actual_logs": json.dumps(safe_record, indent=2),
                }
            )
            finding_id_counter += 1

        risk_summary = {
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
            "info": sum(1 for f in findings if f["severity"] == "INFO"),
            "total": len(findings),
        }

        return {
            "risk_summary": risk_summary,
            "findings": findings,
            "scanned_files_count": len(scanned_files),
            "total_rules_evaluated": len(findings),
        }


class CodeQLAnalyzer:
    """Evaluates GitHub CodeQL static analysis results in SARIF v2.1.0 format.

    Parses semantic AST and inter-procedural taint-tracking findings, normalizes
    CVSS security-severity scores and SARIF problem severities, extracts CWE metadata,
    and maps multi-step dataflow code traces into standardized Axiom findings.
    """

    def analyze(self, raw_data: dict[str, Any] | str | list[Any]) -> dict[str, Any]:
        """Analyze CodeQL SARIF output and return normalized findings and risk summary.

        Args:
            raw_data: Can be a parsed SARIF dict, a raw JSON string, or a list of records.

        Returns:
            Standardized dict containing risk_summary, findings, scanned_files_count,
            and total_rules_evaluated.
        """
        sarif_obj: dict[str, Any] = {}
        if isinstance(raw_data, str):
            try:
                sarif_obj = json.loads(raw_data)
            except Exception:
                sarif_obj = {}
        elif isinstance(raw_data, dict):
            sarif_obj = raw_data
        elif isinstance(raw_data, list) and raw_data and isinstance(raw_data[0], dict):
            sarif_obj = raw_data[0]

        findings: list[dict[str, Any]] = []
        finding_id_counter = 1
        scanned_files: set[str] = set()
        total_rules_count = 0

        runs = sarif_obj.get("runs", [])
        if not isinstance(runs, list):
            runs = []

        for run in runs:
            if not isinstance(run, dict):
                continue

            driver = run.get("tool", {}).get("driver", {})
            rules_list = driver.get("rules", [])
            if not isinstance(rules_list, list):
                rules_list = []
            total_rules_count += len(rules_list)

            # Map rules by id and index
            rules_by_id: dict[str, dict[str, Any]] = {}
            for idx, r in enumerate(rules_list):
                if isinstance(r, dict):
                    rid = r.get("id")
                    if rid:
                        rules_by_id[str(rid)] = r

            results = run.get("results", [])
            if not isinstance(results, list):
                results = []

            for res in results:
                if not isinstance(res, dict):
                    continue

                # 1. Resolve rule metadata
                rule_id = res.get("ruleId")
                rule_meta: dict[str, Any] = {}
                if rule_id and str(rule_id) in rules_by_id:
                    rule_meta = rules_by_id[str(rule_id)]
                elif "ruleIndex" in res:
                    try:
                        rule_idx = int(res["ruleIndex"])
                        if 0 <= rule_idx < len(rules_list):
                            rule_meta = rules_list[rule_idx]
                            if not rule_id:
                                rule_id = rule_meta.get("id")
                    except (ValueError, TypeError):
                        pass

                rule_id_str = str(rule_id or "codeql-unknown-rule")

                # 2. Extract title, descriptions, and CWEs
                rule_props = rule_meta.get("properties", {}) if isinstance(rule_meta.get("properties"), dict) else {}
                title = (
                    rule_meta.get("shortDescription", {}).get("text")
                    or rule_meta.get("name")
                    or rule_id_str.replace("-", " ").replace("/", ": ").title()
                )

                description = res.get("message", {}).get("text") or rule_meta.get("fullDescription", {}).get("text") or title

                # Extract CWE tags
                cwes: list[str] = []
                tags = rule_props.get("tags", [])
                if isinstance(tags, list):
                    for tag in tags:
                        if isinstance(tag, str):
                            m = re.search(r"external/cwe/cwe-(\d+)", tag, re.IGNORECASE)
                            if m:
                                cwes.append(f"CWE-{int(m.group(1))}")
                            elif tag.upper().startswith("CWE-"):
                                cwes.append(tag.upper())

                # 3. Determine severity
                # Check security-severity CVSS score (e.g. "8.8", 9.2)
                sec_score = rule_props.get("security-severity") or res.get("properties", {}).get("security-severity")
                severity: str | None = None
                if sec_score is not None:
                    try:
                        severity = score_to_severity(float(sec_score))
                    except (ValueError, TypeError):
                        pass

                if not severity:
                    level = res.get("level") or rule_meta.get("defaultConfiguration", {}).get("level") or rule_props.get("problem.severity")
                    level_str = str(level).lower() if level else "warning"
                    if level_str in ("error", "critical"):
                        severity = "HIGH"
                    elif level_str in ("warning", "medium"):
                        severity = "MEDIUM"
                    elif level_str in ("note", "low"):
                        severity = "LOW"
                    else:
                        severity = "INFO"

                # 4. Resolve source file location
                locations = res.get("locations", [])
                file_path = "unknown"
                line_num: int | None = None
                col_num: int | None = None
                snippet: str | None = None

                if isinstance(locations, list) and locations:
                    first_loc = locations[0]
                    if isinstance(first_loc, dict):
                        phys = first_loc.get("physicalLocation", {})
                        if isinstance(phys, dict):
                            art = phys.get("artifactLocation", {})
                            if isinstance(art, dict) and "uri" in art:
                                file_path = str(art["uri"])
                                scanned_files.add(file_path)

                            region = phys.get("region", {})
                            if isinstance(region, dict):
                                line_num = region.get("startLine")
                                col_num = region.get("startColumn")
                                snip_obj = region.get("snippet", {})
                                if isinstance(snip_obj, dict):
                                    snippet = snip_obj.get("text")

                loc_str = file_path
                if line_num is not None:
                    loc_str += f":{line_num}"

                # 5. Extract Code Flow / Taint Dataflow Traces
                code_flows = res.get("codeFlows", [])
                flow_steps: list[dict[str, Any]] = []
                if isinstance(code_flows, list):
                    for cf in code_flows:
                        if not isinstance(cf, dict):
                            continue
                        thread_flows = cf.get("threadFlows", [])
                        if isinstance(thread_flows, list):
                            for tf in thread_flows:
                                if not isinstance(tf, dict):
                                    continue
                                tf_locs = tf.get("locations", [])
                                if isinstance(tf_locs, list):
                                    for tfl in tf_locs:
                                        if not isinstance(tfl, dict):
                                            continue
                                        loc_item = tfl.get("location", {})
                                        phys_item = loc_item.get("physicalLocation", {})
                                        art_uri = phys_item.get("artifactLocation", {}).get("uri", "")
                                        start_l = phys_item.get("region", {}).get("startLine")
                                        msg = loc_item.get("message", {}).get("text", "")
                                        if art_uri:
                                            flow_steps.append({"file": str(art_uri), "line": start_l, "message": str(msg)})

                # 6. Remediation advice
                remediation = _get_remediation_for_title(title)
                help_obj = rule_meta.get("help", {})
                if isinstance(help_obj, dict) and help_obj.get("text"):
                    remediation = help_obj["text"].strip()
                elif isinstance(rule_meta.get("help"), str) and rule_meta["help"].strip():
                    remediation = rule_meta["help"].strip()

                evidence: dict[str, Any] = {
                    "location": loc_str,
                    "file": file_path,
                    "line": line_num,
                    "column": col_num,
                    "rule_id": rule_id_str,
                    "cwes": cwes,
                    "snippet": snippet,
                }
                if flow_steps:
                    evidence["taint_trace"] = flow_steps

                code_slug = f"codeql/{rule_id_str.replace('/', '.')}"

                findings.append(
                    {
                        "id": f"SEC-{finding_id_counter:03d}",
                        "code": code_slug,
                        "logs": f"[{rule_id_str}] {title} at {loc_str} | {description}",
                        "severity": severity,
                        "title": title,
                        "description": description,
                        "evidence": evidence,
                        "remediation": remediation,
                        "actual_logs": json.dumps(res, indent=2) if isinstance(res, dict) else str(res),
                        "Actual_logs": json.dumps(res, indent=2) if isinstance(res, dict) else str(res),
                    }
                )
                finding_id_counter += 1

        risk_summary = {
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
            "info": sum(1 for f in findings if f["severity"] == "INFO"),
            "total": len(findings),
        }

        return {
            "risk_summary": risk_summary,
            "findings": findings,
            "scanned_files_count": len(scanned_files),
            "total_rules_evaluated": max(total_rules_count, len(findings)),
        }

