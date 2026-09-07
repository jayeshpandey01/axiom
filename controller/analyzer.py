"""Security Vulnerability & Exposure Analysis Engine.

Analyzes raw scanner probe records (HTTP response headers, status codes,
technologies, server banners) against security rules and outputs categorized,
severity-ranked findings and risk scores.
"""

import json
import re
from typing import Any


class VulnerabilityAnalyzer:
    """Evaluates probe output for security weaknesses, misconfigurations, and disclosures."""

    def analyze(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        findings = []
        finding_id_counter = 1

        def add_finding(
            code: str,
            severity: str,
            title: str,
            description: str,
            evidence: Any,
            remediation: str | None = None,
            logs: str | None = None,
        ):
            nonlocal finding_id_counter
            log_entry = logs if logs is not None else f"[{code}] {title} | Evidence: {evidence}"
            findings.append(
                {
                    "id": f"SEC-{finding_id_counter:03d}",
                    "code": code,
                    "logs": log_entry,
                    "severity": severity.upper(),
                    "title": title,
                    "description": description,
                    "evidence": evidence,
                    "remediation": remediation,
                }
            )
            finding_id_counter += 1

        all_technologies = set()
        all_web_servers = set()
        all_titles = []
        status_codes = {}

        for record in records:
            if not isinstance(record, dict):
                continue

            # Extract basic recon info
            code = record.get("status_code") or record.get("status-code")
            if code:
                status_codes[str(code)] = status_codes.get(str(code), 0) + 1

            server = record.get("webserver") or record.get("web_server")
            if server:
                all_web_servers.add(str(server))

            title = record.get("title")
            if title:
                all_titles.append(str(title)[:100])

            tech = record.get("tech") or record.get("technologies") or []
            if isinstance(tech, list):
                for t in tech:
                    all_technologies.add(str(t))

            headers_raw = record.get("header") or record.get("headers") or {}
            headers = {}
            if isinstance(headers_raw, dict):
                headers = {k.lower(): v for k, v in headers_raw.items()}
            elif isinstance(headers_raw, str):
                for line in headers_raw.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().lower()] = v.strip()

            url = record.get("url") or record.get("input") or ""
            scheme = record.get("scheme") or ("https" if url.startswith("https") else "http" if url.startswith("http") else "")

            # RULE 1: Server Banner Version Disclosure
            if server:
                server_str = str(server)
                has_version = any(char.isdigit() for char in server_str)
                if has_version:
                    add_finding(
                        code="INFO_SERVER_BANNER_LEAK",
                        severity="LOW",
                        title="Web Server Version Disclosed in HTTP Header",
                        description="The HTTP 'Server' header exposes exact software and version numbers, allowing attackers to target version-specific CVEs.",
                        evidence=f"Server: {server_str}",
                        remediation="Configure your web server to suppress version tokens (e.g. 'server_tokens off;' in Nginx or 'ServerTokens Prod' in Apache).",
                    )

            # RULE 2: X-Powered-By / Framework Disclosure
            powered_by = headers.get("x-powered-by")
            if powered_by:
                add_finding(
                    code="INFO_POWERED_BY_LEAK",
                    severity="LOW",
                    title="Technology Framework Header Disclosed (X-Powered-By)",
                    description="The 'X-Powered-By' header exposes backend runtime/framework information.",
                    evidence=f"X-Powered-By: {powered_by}",
                    remediation="Disable the X-Powered-By header in your application configuration or reverse proxy.",
                )

            # RULE 3: Missing HSTS Header (on HTTPS services)
            if scheme == "https" or "https://" in url:
                hsts = headers.get("strict-transport-security")
                if not hsts and headers:
                    add_finding(
                        code="SEC_HEADER_MISSING_HSTS",
                        severity="LOW",
                        title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                        description="The website does not enforce HTTPS connections via HSTS, increasing exposure to SSL-stripping man-in-the-middle attacks.",
                        evidence="Strict-Transport-Security header is absent.",
                        remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to your HTTPS response headers.",
                    )

            # RULE 4: Missing Content-Security-Policy (CSP)
            if headers and not headers.get("content-security-policy"):
                add_finding(
                    code="SEC_HEADER_MISSING_CSP",
                    severity="LOW",
                    title="Missing Content-Security-Policy (CSP) Header",
                    description="No Content-Security-Policy header was detected, reducing client-side mitigation against Cross-Site Scripting (XSS) and data injection.",
                    evidence="Content-Security-Policy header is absent.",
                    remediation="Define a strong Content-Security-Policy header restricting trusted script, style, and frame sources.",
                )

            # RULE 5: Missing X-Frame-Options (Clickjacking Protection)
            if headers and not headers.get("x-frame-options") and not headers.get("content-security-policy"):
                add_finding(
                    code="SEC_HEADER_MISSING_XFO",
                    severity="LOW",
                    title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                    description="The web application lacks X-Frame-Options or frame-ancestors CSP directive, allowing the page to be rendered inside an attacker's iframe.",
                    evidence="X-Frame-Options header is absent.",
                    remediation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to all HTTP responses.",
                )

            # RULE 6: Missing X-Content-Type-Options
            if headers and headers.get("x-content-type-options", "").lower() != "nosniff":
                if headers:
                    add_finding(
                        code="SEC_HEADER_MISSING_XCTO",
                        severity="LOW",
                        title="Missing X-Content-Type-Options Header",
                        description="The 'X-Content-Type-Options: nosniff' header is missing, allowing browsers to MIME-sniff response content types.",
                        evidence="X-Content-Type-Options: nosniff header is absent.",
                        remediation="Add 'X-Content-Type-Options: nosniff' to HTTP responses.",
                    )

            # RULE 7: Insecure Plaintext HTTP Endpoint
            if scheme == "http" and code in (200, 201, 202, 204):
                add_finding(
                    code="INSECURE_PLAINTEXT_HTTP",
                    severity="MEDIUM",
                    title="Plaintext HTTP Service Accessible",
                    description="The endpoint accepts unencrypted HTTP connections without automatically redirecting to HTTPS.",
                    evidence=f"HTTP endpoint '{url}' returned status {code} without redirection.",
                    remediation="Enforce an automatic 301 Permanent Redirect from HTTP (port 80) to HTTPS (port 443).",
                )

            # RULE 8: Exposed Sensitive or Administrative Page Title
            if title:
                t_lower = str(title).lower()
                sensitive_terms = ["admin", "dashboard", "phpmyadmin", "cpanel", "login", "swagger ui", "grafana", "kibana", "actuator"]
                for term in sensitive_terms:
                    if term in t_lower:
                        add_finding(
                            code="EXPOSURE_SENSITIVE_ENDPOINT",
                            severity="MEDIUM" if term in ["admin", "phpmyadmin", "cpanel"] else "LOW",
                            title=f"Potential Administrative/Management Interface Disclosed ('{term}')",
                            description=f"Page title '{title}' suggests an administrative or internal interface accessible on the target.",
                            evidence=f"Page Title: '{title}' on URL: {url}",
                            remediation="Ensure administrative interfaces are protected with multi-factor authentication and restricted via IP allowlisting.",
                        )
                        break

        # RULE 9: Informational Technology Stack Summary
        if all_technologies:
            add_finding(
                code="RECON_TECH_DETECTED",
                severity="INFO",
                title="Identified Technology Stack Components",
                description="Detected libraries, frameworks, and web server technologies on the target.",
                evidence=sorted(list(all_technologies)),
                remediation=None,
            )

        # Calculate risk summary counts
        risk_summary = {
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
            "info": sum(1 for f in findings if f["severity"] == "INFO"),
            "total": len(findings),
        }

        return {
            "live_hosts_count": len(records),
            "risk_summary": risk_summary,
            "findings": findings,
            "status_codes": status_codes,
            "web_servers": sorted(list(all_web_servers))[:10],
            "titles": all_titles[:10],
            "technologies": sorted(list(all_technologies))[:20],
        }


# ---------------------------------------------------------------------------
# Port Scan Analyzer — for nmap (network-portscan) and masscan (fast-portscan)
# ---------------------------------------------------------------------------

# Ports that commonly indicate high-risk exposures
_HIGH_RISK_PORTS: dict[int, str] = {
    21: "FTP (unencrypted file transfer)",
    22: "SSH (brute-force target)",
    23: "Telnet (cleartext remote shell)",
    25: "SMTP (mail relay abuse)",
    445: "SMB (ransomware / lateral movement)",
    1433: "MSSQL database",
    1521: "Oracle DB",
    2375: "Docker daemon (unauthenticated remote access)",
    3306: "MySQL database",
    3389: "RDP (brute-force / BlueKeep target)",
    5432: "PostgreSQL database",
    5900: "VNC (remote desktop, often unauthenticated)",
    6379: "Redis (commonly exposed without auth)",
    8080: "HTTP alternate (admin panels, dev servers)",
    8443: "HTTPS alternate",
    8888: "Jupyter / development server",
    9200: "Elasticsearch HTTP API",
    9300: "Elasticsearch cluster port",
    27017: "MongoDB (often exposed without auth)",
    27018: "MongoDB shard server",
}

_UNENCRYPTED_SERVICE_PORTS: set[int] = {21, 23, 80, 8080}


class PortScanAnalyzer:
    """Analyzes nmap / masscan open-port records for risk classification.

    Input record schema:
        {"ip": str, "host_state": str, "port": int, "protocol": str,
         "service": str, "product": str, "version": str}

    Findings generated:
    - OPEN_PORT_RISK_HIGH     — well-known high-risk port detected open
    - SERVICE_VERSION_DISCLOSURE — product/version banner exposed
    - UNENCRYPTED_NETWORK_SERVICE — cleartext service on open port
    - OPEN_PORT_SUMMARY       — informational count of all open ports
    """

    def analyze(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        finding_id_counter = 1

        def add_finding(
            code: str, severity: str, title: str, description: str, evidence: Any, remediation: str | None = None, logs: str | None = None
        ) -> None:
            nonlocal finding_id_counter
            log_entry = logs if logs is not None else f"[{code}] {title} | Evidence: {evidence}"
            findings.append(
                {
                    "id": f"SEC-{finding_id_counter:03d}",
                    "code": code,
                    "logs": log_entry,
                    "severity": severity.upper(),
                    "title": title,
                    "description": description,
                    "evidence": evidence,
                    "remediation": remediation,
                }
            )
            finding_id_counter += 1

        open_ports: list[dict[str, Any]] = []

        for record in records:
            if not isinstance(record, dict):
                continue
            port = int(record.get("port", 0))
            protocol = record.get("protocol", "tcp")
            service = record.get("service", "")
            product = record.get("product", "")
            version = record.get("version", "")
            ip = record.get("ip", "")

            open_ports.append({"ip": ip, "port": port, "protocol": protocol, "service": service})

            # RULE 1: High-risk port open
            if port in _HIGH_RISK_PORTS:
                add_finding(
                    code="OPEN_PORT_RISK_HIGH",
                    severity="HIGH",
                    title=f"High-Risk Port {port}/{protocol} Detected Open",
                    description=f"Port {port} ({_HIGH_RISK_PORTS[port]}) is accessible. This service is a common attack target.",
                    evidence=f"{ip}:{port}/{protocol} ({service})",
                    remediation=f"Restrict access to port {port} via firewall rules. Enable authentication and encryption if the service must remain accessible.",
                )

            # RULE 2: Service version banner exposure
            if product or version:
                banner = f"{product} {version}".strip()
                add_finding(
                    code="SERVICE_VERSION_DISCLOSURE",
                    severity="LOW",
                    title=f"Network Service Version Disclosed on Port {port}",
                    description="The network service exposes exact product name and version, enabling targeted CVE exploitation.",
                    evidence=f"{ip}:{port} — {banner}",
                    remediation="Configure the service to suppress version information in banners.",
                )

            # RULE 3: Unencrypted cleartext service
            if port in _UNENCRYPTED_SERVICE_PORTS:
                add_finding(
                    code="UNENCRYPTED_NETWORK_SERVICE",
                    severity="MEDIUM",
                    title=f"Unencrypted Network Service on Port {port}",
                    description=f"Port {port} runs an unencrypted service, allowing network eavesdropping of credentials and data.",
                    evidence=f"{ip}:{port}/{protocol} — {service or 'unknown service'}",
                    remediation="Replace this service with its TLS-encrypted equivalent or restrict access to trusted networks only.",
                )

        # RULE 4: Informational open port summary
        if open_ports:
            add_finding(
                code="OPEN_PORT_SUMMARY",
                severity="INFO",
                title=f"{len(open_ports)} Open Port(s) Detected",
                description="Summary of all TCP/UDP ports found in open state during the scan.",
                evidence=[f"{p['ip']}:{p['port']}/{p['protocol']} ({p['service']})" for p in open_ports[:50]],
                remediation=None,
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
            "open_ports": open_ports[:200],
        }


# ---------------------------------------------------------------------------
# Content Discovery Analyzer — for FFUF (content-discovery)
# ---------------------------------------------------------------------------

_SENSITIVE_PATH_PATTERNS: list[tuple[str, str]] = [
    ("admin", "HIGH"),
    ("administrator", "HIGH"),
    ("phpmyadmin", "HIGH"),
    ("cpanel", "HIGH"),
    ("wp-admin", "HIGH"),
    ("wp-login", "HIGH"),
    ("webadmin", "HIGH"),
    (".git", "HIGH"),
    (".env", "HIGH"),
    (".htaccess", "MEDIUM"),
    ("backup", "MEDIUM"),
    ("config", "MEDIUM"),
    ("database", "MEDIUM"),
    ("dump", "MEDIUM"),
    ("swagger", "MEDIUM"),
    ("actuator", "MEDIUM"),
    ("console", "MEDIUM"),
    ("dashboard", "MEDIUM"),
    ("grafana", "MEDIUM"),
    ("kibana", "MEDIUM"),
    ("phpinfo", "MEDIUM"),
    ("debug", "LOW"),
    ("test", "LOW"),
    ("dev", "LOW"),
    ("staging", "LOW"),
    ("login", "LOW"),
    ("api", "INFO"),
]


class ContentDiscoveryAnalyzer:
    """Analyzes FFUF directory/endpoint fuzzing results for security exposure.

    Input record schema (from FFUF results array):
        {"url": str, "status": int, "length": int, "words": int, "lines": int, "duration": int}

    Findings generated:
    - SENSITIVE_PATH_EXPOSED   — path matches a known sensitive pattern and returned 2xx/3xx
    - AUTH_BYPASS_CANDIDATE    — 403 paths that may be accessible via bypass techniques
    - DISCOVERY_SUMMARY        — informational count of discovered paths
    """

    def analyze(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        finding_id_counter = 1

        def add_finding(
            code: str, severity: str, title: str, description: str, evidence: Any, remediation: str | None = None, logs: str | None = None
        ) -> None:
            nonlocal finding_id_counter
            log_entry = logs if logs is not None else f"[{code}] {title} | Evidence: {evidence}"
            findings.append(
                {
                    "id": f"SEC-{finding_id_counter:03d}",
                    "code": code,
                    "logs": log_entry,
                    "severity": severity.upper(),
                    "title": title,
                    "description": description,
                    "evidence": evidence,
                    "remediation": remediation,
                }
            )
            finding_id_counter += 1

        discovered_paths: list[dict[str, Any]] = []
        auth_bypass_candidates: list[str] = []

        for record in records:
            if not isinstance(record, dict):
                continue
            url = record.get("url", "")
            status = int(record.get("status", 0))
            length = record.get("length", 0)

            if status in (200, 201, 204, 301, 302, 307, 401, 403):
                path_lower = url.lower()
                discovered_paths.append({"url": url, "status": status, "length": length})

                if status == 403:
                    auth_bypass_candidates.append(url)

                # Check path against sensitive patterns
                for pattern, severity in _SENSITIVE_PATH_PATTERNS:
                    if pattern in path_lower and status not in (404, 410):
                        add_finding(
                            code="SENSITIVE_PATH_EXPOSED",
                            severity=severity,
                            title=f"Sensitive Path Accessible: /{pattern}",
                            description=f"A path matching the sensitive pattern '{pattern}' returned HTTP {status}. This may expose administrative interfaces, configuration files, or internal tooling.",
                            evidence=f"{url} → HTTP {status} ({length} bytes)",
                            remediation="Restrict access to this path via authentication, IP allowlisting, or remove the resource if no longer needed.",
                        )
                        break  # One finding per URL

        # Auth bypass candidates
        if auth_bypass_candidates:
            add_finding(
                code="AUTH_BYPASS_CANDIDATE",
                severity="LOW",
                title=f"{len(auth_bypass_candidates)} HTTP 403 Path(s) May Be Bypassable",
                description="Paths returning HTTP 403 Forbidden may be accessible via URL manipulation, header injection, or verb tampering.",
                evidence=auth_bypass_candidates[:20],
                remediation="Verify these paths are properly protected at the application layer, not just by URL pattern matching.",
            )

        # Discovery summary
        if discovered_paths:
            add_finding(
                code="DISCOVERY_SUMMARY",
                severity="INFO",
                title=f"{len(discovered_paths)} Web Path(s) Discovered",
                description="Summary of all paths discovered during web content fuzzing.",
                evidence=[f"{p['url']} → HTTP {p['status']}" for p in discovered_paths[:50]],
                remediation=None,
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
            "discovered_paths": discovered_paths[:200],
        }


# ---------------------------------------------------------------------------
# Nuclei Analyzer — for nuclei (vuln-assessment)
# ---------------------------------------------------------------------------

_NUCLEI_SEVERITY_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "unknown": "INFO",
}


class NucleiAnalyzer:
    """Normalizes Nuclei JSONL template output into the standard findings schema.

    Input record schema (one Nuclei JSONL line):
        {
          "template-id": str,
          "info": {"name": str, "severity": str, "description": str, "tags": [str], ...},
          "host": str,
          "matched-at": str,
          "extracted-results": [str],
          "curl-command": str,  # optional
        }

    Findings generated: one per Nuclei template match, severity mapped from Nuclei's own severity.
    CVE IDs are extracted from template-id and info.classification fields.
    """

    def analyze(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        finding_id_counter = 1
        cve_ids: list[str] = []

        for record in records:
            if not isinstance(record, dict):
                continue
            info = record.get("info", {}) if isinstance(record.get("info"), dict) else {}
            template_id = record.get("template-id", "unknown")
            name = info.get("name", template_id)
            raw_severity = str(info.get("severity", "info")).lower()
            severity = _NUCLEI_SEVERITY_MAP.get(raw_severity, "INFO")
            description = info.get("description", "No description provided.")
            host = record.get("host", "")
            matched_at = record.get("matched-at", host)
            extracted = record.get("extracted-results", [])
            remediation = info.get("remediation", None)

            # Extract CVE identifiers safely
            classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
            cve_val = classification.get("cve-id") if isinstance(classification, dict) else None
            if isinstance(cve_val, str) and cve_val.upper().startswith("CVE-"):
                if cve_val.upper() not in cve_ids:
                    cve_ids.append(cve_val.upper())
            elif isinstance(cve_val, list):
                for cve in cve_val:
                    if isinstance(cve, str) and cve.upper().startswith("CVE-"):
                        if cve.upper() not in cve_ids:
                            cve_ids.append(cve.upper())

            # Also check template-id itself
            if template_id.upper().startswith("CVE-") and template_id.upper() not in cve_ids:
                cve_ids.append(template_id.upper())

            evidence: Any = f"Matched at: {matched_at}"
            interaction = record.get("interaction") if isinstance(record.get("interaction"), dict) else None
            if interaction:
                proto = str(interaction.get("protocol", "oob")).upper()
                remote_ip = interaction.get("remote-address", "")
                evidence = {
                    "matched_at": matched_at,
                    "oob_interaction": {
                        "protocol": proto,
                        "remote_address": remote_ip,
                        "query_type": interaction.get("q-type"),
                        "unique_id": interaction.get("unique-id"),
                    },
                }
            elif extracted:
                if isinstance(extracted, list):
                    evidence = {"matched_at": matched_at, "extracted": extracted[:10]}
                else:
                    evidence = {"matched_at": matched_at, "extracted": str(extracted)}

            findings.append(
                {
                    "id": f"SEC-{finding_id_counter:03d}",
                    "code": f"NUCLEI_{template_id.upper().replace('-', '_')}",
                    "logs": json.dumps(record, indent=2) if isinstance(record, dict) else str(record),
                    "severity": severity,
                    "title": name,
                    "description": description,
                    "evidence": evidence,
                    "remediation": remediation,
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
            "cve_ids": cve_ids,
            "templates_matched": len(findings),
        }


_DALFOX_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
}


class DalfoxAnalyzer:
    """Normalizes DalFox XSS and parameter analysis JSON findings into the standard schema.

    Handles DalFox findings (Verified 'V', AST-detected 'A', Reflected 'R', Grep 'G', Informational 'I').
    Input record schema:
        {
          "type": "V" | "A" | "R" | "G" | "I",
          "type_description": str,
          "param": str,
          "payload": str,
          "evidence": str,
          "cwe": str,
          "severity": str,
          "method": str,
          "url": str (or "data": str),
          "message": str (or "message_str": str),
          "detection_method": str,
          "confidence": str
        }
    """

    def analyze(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        finding_id_counter = 1
        vulnerable_params: set[str] = set()
        tested_urls: set[str] = set()
        verified_count = 0

        for record in records:
            if not isinstance(record, dict):
                continue

            finding_type = str(record.get("type", "R")).strip().upper()
            raw_severity = str(record.get("severity", "")).strip().lower()

            # Map severity based on explicit field or finding type confidence
            if raw_severity in _DALFOX_SEVERITY_MAP:
                severity = _DALFOX_SEVERITY_MAP[raw_severity]
            elif finding_type == "V":
                severity = "HIGH"
            elif finding_type == "A":
                severity = "HIGH"
            elif finding_type == "R":
                severity = "MEDIUM"
            elif finding_type == "G":
                severity = "LOW"
            elif finding_type == "I":
                severity = "INFO"
            else:
                severity = "MEDIUM"

            if finding_type == "V":
                verified_count += 1

            param = record.get("param", "") or record.get("parameter", "")
            if param:
                vulnerable_params.add(str(param))

            payload = record.get("payload", "")
            url = record.get("url") or record.get("data") or ""
            if url:
                tested_urls.add(str(url))

            http_method = record.get("method", "GET")
            cwe = record.get("cwe", "CWE-79")
            msg = record.get("message") or record.get("message_str") or record.get("type_description") or ""

            # Compose descriptive title
            if finding_type == "V":
                title = f"Verified Cross-Site Scripting (XSS) in Parameter '{param}'" if param else "Verified Cross-Site Scripting (XSS)"
                code = "DALFOX_VERIFIED_XSS"
            elif finding_type == "A":
                title = f"AST-Detected DOM XSS in Parameter '{param}'" if param else "AST-Detected DOM Cross-Site Scripting"
                code = "DALFOX_DOM_XSS"
            elif finding_type == "R":
                title = f"Reflected Input Parameter (Potential XSS) in '{param}'" if param else "Reflected Input Parameter"
                code = "DALFOX_REFLECTED_PARAM"
            elif finding_type == "G":
                title = f"Heuristic Reflection Detected on '{param}'" if param else "Heuristic Reflection Detected"
                code = "DALFOX_GREP_REFLECTION"
            elif finding_type == "I":
                title = msg or "DalFox Informational Observation"
                code = "DALFOX_INFORMATIONAL"
            else:
                title = f"DalFox Finding ({finding_type}) in '{param}'" if param else f"DalFox Finding ({finding_type})"
                code = f"DALFOX_{finding_type}"

            description = (
                msg
                or f"DalFox detected a {finding_type} finding on parameter '{param}' using method {http_method} with {cwe}."
            )

            evidence_data = {
                "url": url,
                "parameter": param,
                "payload": payload,
                "method": http_method,
                "cwe": cwe,
                "detection_method": record.get("detection_method", "reflection"),
                "confidence": record.get("confidence", "high" if finding_type == "V" else "low"),
            }
            if record.get("evidence"):
                evidence_data["snippet"] = str(record["evidence"])

            if finding_type in ("V", "A", "R", "G"):
                remediation = (
                    "Implement context-aware output encoding (HTML, JavaScript, Attribute, or URL encoding) "
                    "for all user-controllable input before rendering it in the DOM. Deploy a strong Content-Security-Policy (CSP) "
                    "without 'unsafe-inline' and sanitize untrusted HTML using DOMPurify or equivalent framework mechanisms."
                )
            else:
                remediation = "Review the informational finding and update dependencies or configuration as required."

            findings.append(
                {
                    "id": f"SEC-{finding_id_counter:03d}",
                    "code": code,
                    "logs": json.dumps(record, indent=2),
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "evidence": evidence_data,
                    "remediation": remediation,
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
            "vulnerable_parameters": sorted(list(vulnerable_params)),
            "verified_xss_count": verified_count,
            "tested_urls": sorted(list(tested_urls)),
        }


class ZAPAnalyzer:
    """Evaluates OWASP ZAP (Zed Attack Proxy) active & passive security scan reports.

    Parses ZAP JSON alert structures, maps ZAP risk codes to standardized
    severity levels (Critical, High, Medium, Low, Info), extracts CWE/WASC taxonomies,
    isolates vulnerable parameters and endpoints, and generates actionable remediation guidance.
    """

    @staticmethod
    def _strip_html(text: str | None) -> str:
        if not text:
            return ""
        return re.sub(r"<[^>]+>", " ", str(text)).strip()

    def analyze(self, raw_data: dict[str, Any] | list[Any] | str) -> dict[str, Any]:
        """Analyze OWASP ZAP report JSON and produce normalized findings and risk summary."""
        zap_obj: dict[str, Any] = {}
        if isinstance(raw_data, str):
            try:
                zap_obj = json.loads(raw_data)
            except Exception:
                zap_obj = {}
        elif isinstance(raw_data, dict):
            zap_obj = raw_data
        elif isinstance(raw_data, list):
            zap_obj = {"alerts": raw_data}

        # Extract alerts list across various ZAP report formats
        alerts: list[dict[str, Any]] = []
        if "site" in zap_obj:
            sites = zap_obj["site"]
            if isinstance(sites, dict):
                sites = [sites]
            if isinstance(sites, list):
                for s in sites:
                    if isinstance(s, dict) and "alerts" in s and isinstance(s["alerts"], list):
                        alerts.extend(s["alerts"])
        elif "alerts" in zap_obj and isinstance(zap_obj["alerts"], list):
            alerts = zap_obj["alerts"]

        findings: list[dict[str, Any]] = []
        finding_id_counter = 1
        tested_urls: set[str] = set()
        vulnerable_params: set[str] = set()

        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            raw_title = alert.get("alert") or alert.get("name") or "OWASP ZAP Finding"
            title = self._strip_html(raw_title)
            plugin_id = str(alert.get("pluginid") or alert.get("alertRef") or "zap")
            risk_code = str(alert.get("riskcode", "1"))
            confidence = str(alert.get("confidence", "2"))

            # Determine severity
            if risk_code == "3":
                # High severity; promote to Critical if high confidence and critical attack pattern
                crit_keywords = ["remote code execution", "sql injection", "command injection", "rce"]
                if confidence == "3" and any(k in title.lower() for k in crit_keywords):
                    severity = "CRITICAL"
                else:
                    severity = "HIGH"
            elif risk_code == "2":
                severity = "MEDIUM"
            elif risk_code == "1":
                severity = "LOW"
            else:
                severity = "INFO"

            # CWE and WASC mappings
            cwe_id = alert.get("cweid")
            cwe_str = f"CWE-{cwe_id}" if cwe_id and str(cwe_id) != "0" else None
            wasc_id = alert.get("wascid")
            wasc_str = f"WASC-{wasc_id}" if wasc_id and str(wasc_id) != "0" else None

            desc = self._strip_html(alert.get("desc") or alert.get("description") or title)
            solution = self._strip_html(alert.get("solution")) or "Review and apply security patches to remediate the identified flaw."
            reference = self._strip_html(alert.get("reference"))

            instances = alert.get("instances", [])
            instance_data = []
            if isinstance(instances, list):
                for inst in instances:
                    if isinstance(inst, dict):
                        uri = inst.get("uri")
                        if uri:
                            tested_urls.add(str(uri))
                        param = inst.get("param")
                        if param:
                            vulnerable_params.add(str(param))
                        instance_data.append(
                            {
                                "uri": uri,
                                "method": inst.get("method"),
                                "param": param,
                                "attack": inst.get("attack"),
                                "evidence": inst.get("evidence"),
                            }
                        )

            evidence = {
                "plugin_id": plugin_id,
                "cwe": cwe_str,
                "wasc": wasc_str,
                "risk_desc": alert.get("riskdesc", ""),
                "confidence": confidence,
                "instances_count": len(instance_data) or int(alert.get("count", 1)),
                "instances": instance_data[:10],
                "reference": reference,
            }

            code = f"zap/{plugin_id}"
            findings.append(
                {
                    "id": f"SEC-{finding_id_counter:03d}",
                    "code": code,
                    "logs": f"[{code}] {title} (Risk: {risk_code}, Confidence: {confidence}) | {desc[:200]}",
                    "severity": severity,
                    "title": title,
                    "description": desc,
                    "evidence": evidence,
                    "remediation": solution,
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
            "tested_urls": sorted(list(tested_urls)),
            "vulnerable_parameters": sorted(list(vulnerable_params)),
            "total_alerts_count": len(findings),
        }


class InteractshAnalyzer:
    """Normalizes ProjectDiscovery Interactsh Out-of-Band (OOB) interaction logs into standard findings.

    Input record schema (one JSON or JSONL object from interactsh-client):
        {
            "protocol": "dns" | "http" | "https" | "smtp" | "ldap",
            "unique-id": "c123456",
            "full-id": "c123456.oast.fun",
            "q-type": "A",
            "raw-request": "...",
            "raw-response": "...",
            "remote-address": "203.0.113.42:53",
            "timestamp": "2026-09-08T00:15:30Z"
        }
    """

    def _sanitize_log_data(self, raw_str: str) -> str:
        """Sanitize sensitive authorization tokens or secrets from raw request/response logs."""
        cleaned = re.sub(r"(?i)(authorization:\s*(?:bearer|basic)\s+)[^\r\n]+", r"\1<REDACTED>", raw_str)
        cleaned = re.sub(r"(?i)(cookie:\s*)[^\r\n]+", r"\1<REDACTED>", cleaned)
        cleaned = re.sub(r"(?i)(api[_-]?key|token|password|secret)=([^&\s]+)", r"\1=<REDACTED>", cleaned)
        return cleaned

    def analyze(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        finding_id_counter = 1
        interaction_types: set[str] = set()
        callback_hosts: set[str] = set()

        for record in records:
            if not isinstance(record, dict):
                continue

            proto = str(record.get("protocol", "oob")).lower().strip()
            unique_id = str(record.get("unique-id", "unknown"))
            full_id = str(record.get("full-id", unique_id))
            remote_addr = str(record.get("remote-address", "unknown"))
            q_type = record.get("q-type")
            timestamp = str(record.get("timestamp", ""))
            raw_req = record.get("raw-request", "")
            safe_raw = self._sanitize_log_data(str(raw_req))

            interaction_types.add(proto.upper())
            callback_hosts.add(remote_addr.split(":")[0])

            if proto == "ldap":
                severity = "CRITICAL"
                score = 9.8
                code = "INTERACTSH_OOB_LDAP_JNDI"
                title = "Out-of-Band LDAP / JNDI Callback Detected (Potential Blind RCE)"
                description = (
                    f"An Out-of-Band (OOB) LDAP connection was initiated by remote host {remote_addr} "
                    f"to the correlation identifier '{full_id}'. This indicates a high-probability Remote Code "
                    "Execution (RCE) or JNDI injection vulnerability (such as Log4Shell or Spring4Shell)."
                )
                remediation = (
                    "Audit input parameters and backend frameworks for JNDI/LDAP lookups. Upgrade vulnerable libraries "
                    "(e.g., Log4j, Spring Framework, Fastjson) and restrict egress LDAP network traffic from servers."
                )
            elif proto in ("http", "https"):
                severity = "HIGH"
                score = 8.6
                code = "INTERACTSH_OOB_HTTP_SSRF"
                title = f"Out-of-Band {proto.upper()} Interaction Detected (Blind SSRF)"
                description = (
                    f"An Out-of-Band (OOB) {proto.upper()} request was initiated by remote host {remote_addr} "
                    f"to the correlation target '{full_id}'. This confirms a Server-Side Request Forgery (SSRF) "
                    "or blind external URL fetch vulnerability."
                )
                remediation = (
                    "Enforce strict destination hostname allowlists for outbound HTTP requests, disable unused URL schemes "
                    "(file://, gopher://, dict://), and implement network egress filtering to prevent internal servers from "
                    "calling arbitrary external internet endpoints."
                )
            elif proto == "smtp":
                severity = "HIGH"
                score = 8.0
                code = "INTERACTSH_OOB_SMTP_INJECTION"
                title = "Out-of-Band SMTP Interaction Detected (Email Header Injection / SSRF)"
                description = (
                    f"An Out-of-Band (OOB) SMTP connection was initiated by remote host {remote_addr} "
                    f"to the correlation listener '{full_id}'. This demonstrates an email header injection, "
                    "CRLF injection, or an SSRF reaching external mail services."
                )
                remediation = (
                    "Sanitize and validate all user input included in email headers, subject lines, or recipient lists. "
                    "Restrict outbound SMTP ports (25, 465, 587) from application servers."
                )
            elif proto == "dns":
                severity = "MEDIUM"
                score = 6.5
                code = "INTERACTSH_OOB_DNS_LOOKUP"
                query_info = f" (Query: {q_type})" if q_type else ""
                title = f"Out-of-Band DNS Interaction Detected (Blind Injection / DNS Exfiltration){query_info}"
                description = (
                    f"An Out-of-Band (OOB) DNS lookup was triggered by remote host {remote_addr} "
                    f"for correlation domain '{full_id}'. This confirms that user input reached a network "
                    "or name-resolution sink (such as blind SQL injection, OS command injection, or blind XXE)."
                )
                remediation = (
                    "Identify the parameter or header that triggered the external DNS query. Apply strict input validation "
                    "and type checking, and restrict internal DNS resolvers from resolving arbitrary external domains."
                )
            else:
                severity = "INFO"
                score = 3.5
                code = f"INTERACTSH_OOB_{proto.upper()}"
                title = f"Out-of-Band {proto.upper()} Callback Detected"
                description = f"An Out-of-Band interaction was detected via protocol {proto.upper()} from {remote_addr}."
                remediation = "Review application egress logs and input validation routines."

            evidence = {
                "protocol": proto.upper(),
                "remote_address": remote_addr,
                "correlation_id": unique_id,
                "full_correlation_domain": full_id,
                "query_type": q_type,
                "timestamp": timestamp,
                "raw_request_snippet": safe_raw[:300] if safe_raw else None,
            }

            safe_record = dict(record)
            if "raw-request" in safe_record:
                safe_record["raw-request"] = safe_raw
            if "raw-response" in safe_record:
                safe_record["raw-response"] = self._sanitize_log_data(str(safe_record["raw-response"]))

            findings.append(
                {
                    "id": f"SEC-{finding_id_counter:03d}",
                    "code": code,
                    "logs": json.dumps(safe_record, indent=2),
                    "severity": severity,
                    "score": score,
                    "title": title,
                    "description": description,
                    "evidence": evidence,
                    "remediation": remediation,
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
            "interaction_types": sorted(list(interaction_types)),
            "callback_hosts": sorted(list(callback_hosts)),
            "total_interactions_count": len(findings),
        }




# ===========================================================================
# NEW TOOL ANALYZERS (Phase 2 & 3 Additions)
# ===========================================================================


class KatanaAnalyzer:
    """Analyzer for ProjectDiscovery Katana web crawler output."""

    SENSITIVE_PATH_PATTERNS = [
        "/admin", "/administrator", "/.env", "/backup", "/api/", "/debug",
        "/upload", "/config", "/secret", "/internal", "/private", "/swagger",
        "/graphql", "/actuator", "/.git", "/phpinfo", "/wp-admin",
    ]

    def analyze(self, records: list[dict]) -> dict:
        findings = []
        endpoints: list[str] = []
        counter = 1

        for rec in records:
            endpoint = rec.get("endpoint", rec.get("url", ""))
            if not endpoint:
                continue
            endpoints.append(endpoint)

            lower = endpoint.lower()
            for pat in self.SENSITIVE_PATH_PATTERNS:
                if pat in lower:
                    findings.append({
                        "id": f"SEC-{counter:03d}",
                        "code": "KATANA_SENSITIVE_ENDPOINT",
                        "severity": "MEDIUM",
                        "score": 5.3,
                        "title": f"Sensitive Endpoint Discovered: {pat}",
                        "description": f"Web crawler discovered a potentially sensitive endpoint at: {endpoint}",
                        "remediation": "Verify the endpoint is intended to be publicly accessible and apply appropriate authentication.",
                        "evidence": {"endpoint": endpoint, "pattern_matched": pat},
                        "cve_ids": [],
                    })
                    counter += 1
                    break

        risk = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for f in findings:
            sev = f["severity"].lower()
            if sev in risk:
                risk[sev] += 1
        risk["total"] = len(findings)

        return {
            "endpoints_discovered": len(endpoints),
            "endpoints": endpoints[:200],
            "risk_summary": risk,
            "findings": findings,
        }


class FeroxbusterAnalyzer:
    """Analyzer for Feroxbuster recursive content discovery output."""

    CRITICAL_PATHS = ["/.env", "/.git/", "/backup", "/db_backup", "/credentials"]
    HIGH_PATHS = ["/admin", "/administrator", "/wp-admin", "/phpinfo", "/actuator", "/debug"]
    MEDIUM_PATHS = ["/api/", "/swagger", "/graphql", "/upload", "/internal", "/private"]

    def analyze(self, records: list[dict]) -> dict:
        findings = []
        discovered: list[str] = []
        counter = 1

        for rec in records:
            if rec.get("type") != "response":
                continue
            url = rec.get("url", "")
            status_code = rec.get("status", 0)
            if not url or status_code in (404, 400, 500):
                continue
            discovered.append(url)
            lower = url.lower()

            severity, score, label = None, 0.0, ""
            for pat in self.CRITICAL_PATHS:
                if pat in lower:
                    severity, score, label = "CRITICAL", 9.1, pat
                    break
            if not severity:
                for pat in self.HIGH_PATHS:
                    if pat in lower:
                        severity, score, label = "HIGH", 7.5, pat
                        break
            if not severity:
                for pat in self.MEDIUM_PATHS:
                    if pat in lower:
                        severity, score, label = "MEDIUM", 5.3, pat
                        break

            if severity:
                findings.append({
                    "id": f"SEC-{counter:03d}",
                    "code": f"FEROX_SENSITIVE_{severity}",
                    "severity": severity,
                    "score": score,
                    "title": f"Sensitive Path Discovered [{status_code}]: {label}",
                    "description": f"Recursive content scan found accessible sensitive path at: {url}",
                    "remediation": "Restrict access to sensitive paths via WAF rules, authentication, or removal.",
                    "evidence": {"url": url, "status_code": status_code},
                    "cve_ids": [],
                })
                counter += 1

        risk = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for f in findings:
            sev = f["severity"].lower()
            if sev in risk:
                risk[sev] += 1
        risk["total"] = len(findings)

        return {"paths_discovered": len(discovered), "risk_summary": risk, "findings": findings}


class DNSXAnalyzer:
    """Analyzer for ProjectDiscovery DNSX DNS resolution output."""

    def analyze(self, records: list[dict]) -> dict:
        findings = []
        resolved: list[str] = []
        counter = 1

        for rec in records:
            host = rec.get("host", "")
            if not host:
                continue
            resolved.append(host)

            # Dangling CNAME check
            cname = rec.get("cname", [])
            if isinstance(cname, list):
                for c in cname:
                    if any(svc in c for svc in ["s3.amazonaws.com", "azurewebsites.net", "herokudns.com",
                                                 "github.io", "myshopify.com", "cloudfront.net"]):
                        findings.append({
                            "id": f"SEC-{counter:03d}",
                            "code": "DNSX_DANGLING_CNAME",
                            "severity": "HIGH",
                            "score": 7.5,
                            "title": f"Potentially Dangling CNAME: {c}",
                            "description": f"Host '{host}' has a CNAME pointing to '{c}' which may be claimable.",
                            "remediation": "Verify the CNAME target is still provisioned and owned. Remove or update dangling records.",
                            "evidence": {"host": host, "cname": c},
                            "cve_ids": [],
                        })
                        counter += 1

            # Missing SPF/DMARC for MX-bearing domains
            mx = rec.get("mx", [])
            txt = rec.get("txt", [])
            if mx and isinstance(txt, list):
                has_spf = any("v=spf1" in t for t in txt)
                if not has_spf:
                    findings.append({
                        "id": f"SEC-{counter:03d}",
                        "code": "DNSX_MISSING_SPF",
                        "severity": "MEDIUM",
                        "score": 5.3,
                        "title": f"Missing SPF Record for Mail Domain: {host}",
                        "description": "Domain has MX records but no SPF TXT record, enabling email spoofing.",
                        "remediation": "Add an SPF TXT record: 'v=spf1 include:yourprovider.com ~all'.",
                        "evidence": {"host": host, "mx": mx},
                        "cve_ids": [],
                    })
                    counter += 1

        risk = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for f in findings:
            sev = f["severity"].lower()
            if sev in risk:
                risk[sev] += 1
        risk["total"] = len(findings)

        return {
            "hosts_resolved": len(resolved),
            "risk_summary": risk,
            "findings": findings,
        }


class SubdomainTakeoverAnalyzer:
    """Analyzer for Subzy subdomain takeover detection output."""

    CONFIRMED_SEVERITY = "CRITICAL"
    VULNERABLE_SEVERITY = "HIGH"

    def analyze(self, records: list[dict]) -> dict:
        findings = []
        counter = 1

        for rec in records:
            subdomain = rec.get("subdomain", rec.get("host", ""))
            result = str(rec.get("result", "")).upper()
            service = rec.get("service", "unknown")

            if result in ("VULNERABLE", "VULNERABLE!", "TAKEABLE"):
                findings.append({
                    "id": f"SEC-{counter:03d}",
                    "code": "SUBDOMAIN_TAKEOVER_VULNERABLE",
                    "severity": self.CONFIRMED_SEVERITY,
                    "score": 9.3,
                    "title": f"Subdomain Takeover Vulnerability: {subdomain}",
                    "description": f"'{subdomain}' has a dangling DNS record pointing to an unclaimed '{service}' resource. An attacker can claim it.",
                    "remediation": "Remove the dangling DNS CNAME record or re-provision the missing service resource immediately.",
                    "evidence": {"subdomain": subdomain, "service": service, "result": result},
                    "cve_ids": [],
                })
                counter += 1

        risk = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for f in findings:
            sev = f["severity"].lower()
            if sev in risk:
                risk[sev] += 1
        risk["total"] = len(findings)

        return {"subdomains_checked": len(records), "risk_summary": risk, "findings": findings}


class NaabuAnalyzer:
    """Analyzer for ProjectDiscovery Naabu fast port scanner output."""

    # Reuse the risky ports classification from PortScanAnalyzer
    RISKY_PORTS: dict[int, tuple[str, str, float]] = {
        21: ("FTP", "HIGH", 7.5), 22: ("SSH", "INFO", 0.0), 23: ("Telnet", "CRITICAL", 9.8),
        25: ("SMTP", "MEDIUM", 5.3), 110: ("POP3", "MEDIUM", 5.3), 143: ("IMAP", "MEDIUM", 5.3),
        445: ("SMB", "HIGH", 8.8), 3389: ("RDP", "HIGH", 8.1), 1433: ("MSSQL", "HIGH", 7.5),
        3306: ("MySQL", "HIGH", 7.5), 5432: ("PostgreSQL", "HIGH", 7.5),
        27017: ("MongoDB", "CRITICAL", 9.8), 6379: ("Redis", "HIGH", 8.1),
        9200: ("Elasticsearch", "CRITICAL", 9.8), 11211: ("Memcached", "HIGH", 7.5),
        2375: ("Docker API", "CRITICAL", 9.8), 8500: ("Consul", "HIGH", 8.1),
    }

    def analyze(self, records: list[dict]) -> dict:
        findings = []
        open_ports: list[dict] = []
        counter = 1

        for rec in records:
            host = rec.get("host", rec.get("ip", ""))
            port = rec.get("port", 0)
            if not host or not port:
                continue

            open_ports.append({"host": host, "port": port})

            if port in self.RISKY_PORTS:
                svc, sev, score = self.RISKY_PORTS[port]
                if sev == "INFO":
                    continue
                findings.append({
                    "id": f"SEC-{counter:03d}",
                    "code": f"NAABU_RISKY_PORT_{port}",
                    "severity": sev,
                    "score": score,
                    "title": f"Risky Open Port {port} ({svc}) on {host}",
                    "description": f"Port {port} ({svc}) is open and accessible on {host}.",
                    "remediation": "Restrict access to this port via firewall rules. Only allow from trusted IP ranges.",
                    "evidence": {"host": host, "port": port, "service": svc},
                    "cve_ids": [],
                })
                counter += 1

        risk = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for f in findings:
            sev = f["severity"].lower()
            if sev in risk:
                risk[sev] += 1
        risk["total"] = len(findings)

        return {"open_ports_count": len(open_ports), "open_ports": open_ports[:100], "risk_summary": risk, "findings": findings}


class WAFDetectionAnalyzer:
    """Analyzer for WafW00f WAF fingerprinting output."""

    def analyze(self, records: list[dict]) -> dict:
        findings = []
        waf_results: list[dict] = []
        counter = 1

        for rec in records:
            url = rec.get("url", "")
            waf = rec.get("detected", [])
            if isinstance(waf, list):
                for detected in waf:
                    name = detected.get("firewall", "Unknown WAF")
                    manufacturer = detected.get("manufacturer", "")
                    waf_results.append({"url": url, "waf": name, "manufacturer": manufacturer})
                    findings.append({
                        "id": f"SEC-{counter:03d}",
                        "code": "WAF_DETECTED",
                        "severity": "INFO",
                        "score": 0.0,
                        "title": f"WAF Detected: {name} ({manufacturer})",
                        "description": f"Web Application Firewall '{name}' by '{manufacturer}' detected on {url}.",
                        "remediation": "Ensure WAF rules are current and tuned. Test bypass techniques regularly.",
                        "evidence": {"url": url, "waf": name, "manufacturer": manufacturer},
                        "cve_ids": [],
                    })
                    counter += 1

        risk = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": len(findings), "total": len(findings)}
        return {"waf_results": waf_results, "risk_summary": risk, "findings": findings}


class CORSAnalyzer:
    """Analyzer for Corsy CORS misconfiguration scanner output."""

    SEVERITY_MAP = {
        "Wildcard Origin Allowed": ("HIGH", 7.5),
        "Null Origin Allowed": ("HIGH", 8.1),
        "Origin Reflected": ("MEDIUM", 5.3),
        "Wildcard HTTPS Origin Allowed": ("MEDIUM", 5.3),
        "Third Party Allowed": ("MEDIUM", 5.3),
    }

    def analyze(self, records: list[dict]) -> dict:
        findings = []
        counter = 1

        for rec in records:
            url = rec.get("url", "")
            cors_type = rec.get("class", rec.get("type", "CORS Misconfiguration"))
            credentials = rec.get("credentials", False)

            sev, score = self.SEVERITY_MAP.get(cors_type, ("MEDIUM", 5.3))
            # Escalate to CRITICAL if credentials are included
            if credentials and sev in ("HIGH", "MEDIUM"):
                sev, score = "CRITICAL", 9.3

            findings.append({
                "id": f"SEC-{counter:03d}",
                "code": f"CORS_{cors_type.upper().replace(' ', '_')}",
                "severity": sev,
                "score": score,
                "title": f"CORS Misconfiguration: {cors_type}",
                "description": f"CORS misconfiguration ({cors_type}) detected at {url}. Credentials included: {credentials}.",
                "remediation": "Restrict CORS policy to specific trusted origins. Never use wildcard (*) with Allow-Credentials: true.",
                "evidence": {"url": url, "type": cors_type, "credentials": credentials},
                "cve_ids": [],
            })
            counter += 1

        risk = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for f in findings:
            sev = f["severity"].lower()
            if sev in risk:
                risk[sev] += 1
        risk["total"] = len(findings)

        return {"risk_summary": risk, "findings": findings}


class CRLFAnalyzer:
    """Analyzer for CRLFuzz CRLF injection scanner output."""

    def analyze(self, records: list[dict]) -> dict:
        findings = []
        counter = 1

        for rec in records:
            url = rec.get("url", str(rec) if isinstance(rec, str) else "")
            payload = rec.get("payload", "") if isinstance(rec, dict) else ""
            findings.append({
                "id": f"SEC-{counter:03d}",
                "code": "CRLF_INJECTION",
                "severity": "MEDIUM",
                "score": 6.1,
                "title": f"CRLF Injection Vulnerability: {url}",
                "description": "CRLF sequence injection confirmed. Attacker can inject arbitrary HTTP response headers, leading to cache poisoning, XSS, or session fixation.",
                "remediation": r"Sanitize all user-controlled inputs before reflecting them in HTTP response headers. Encode newline characters (\r\n).",
                "evidence": {"url": url, "payload": payload},
                "cve_ids": [],
            })
            counter += 1

        risk = {"critical": 0, "high": 0, "medium": len(findings), "low": 0, "info": 0, "total": len(findings)}
        return {"risk_summary": risk, "findings": findings}


class SSTIAnalyzer:
    """Analyzer for SSTImap Server-Side Template Injection scanner output."""

    ENGINE_SEVERITY: dict[str, tuple[str, float]] = {
        "jinja2": ("CRITICAL", 9.8),
        "twig": ("CRITICAL", 9.8),
        "freemarker": ("CRITICAL", 9.8),
        "smarty": ("HIGH", 8.8),
        "pebble": ("HIGH", 8.1),
        "velocity": ("HIGH", 8.1),
        "mako": ("CRITICAL", 9.5),
    }
    DEFAULT = ("HIGH", 8.0)

    def analyze(self, records: list[dict]) -> dict:
        findings = []
        counter = 1

        for rec in records:
            url = rec.get("url", "")
            engine = str(rec.get("engine", "")).lower()
            parameter = rec.get("parameter", "unknown")
            rce_confirmed = rec.get("rce", False)

            sev, score = self.ENGINE_SEVERITY.get(engine, self.DEFAULT)
            if rce_confirmed:
                sev, score = "CRITICAL", 10.0

            findings.append({
                "id": f"SEC-{counter:03d}",
                "code": f"SSTI_{engine.upper() or 'UNKNOWN'}_INJECTION",
                "severity": sev,
                "score": score,
                "title": f"SSTI Detected ({engine or 'Unknown Engine'}): {url}",
                "description": f"Server-Side Template Injection in '{parameter}' parameter at {url}. Engine: {engine}. RCE confirmed: {rce_confirmed}.",
                "remediation": "Never pass user input directly into template rendering. Use sandboxed templates or strict output encoding.",
                "evidence": {"url": url, "engine": engine, "parameter": parameter, "rce": rce_confirmed},
                "cve_ids": [],
            })
            counter += 1

        risk = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for f in findings:
            sev = f["severity"].lower()
            if sev in risk:
                risk[sev] += 1
        risk["total"] = len(findings)

        return {"risk_summary": risk, "findings": findings}


class GitleaksAnalyzer:
    """Analyzer for Gitleaks secret scanner output."""

    HIGH_RULES = {"aws", "gcp", "azure", "private-key", "rsa", "github-token", "slack", "stripe", "twilio", "sendgrid"}
    REDACT_PATTERN = __import__('re').compile(r"(?i)(key|token|secret|password|credential|api[_-]?key)=[\w+/=]{8,}")

    def analyze(self, records: list[dict]) -> dict:
        import re
        findings = []
        counter = 1

        for rec in records:
            rule_id = str(rec.get("RuleID", rec.get("rule_id", "secret"))).lower()
            file_path = rec.get("File", rec.get("file", ""))
            line_no = rec.get("StartLine", rec.get("line", 0))
            match_text = rec.get("Match", rec.get("match", ""))
            commit = rec.get("Commit", rec.get("commit", ""))

            # Redact actual secret from evidence
            redacted = re.sub(self.REDACT_PATTERN, lambda m: m.group().split("=")[0] + "=<REDACTED>", match_text)

            severity = "CRITICAL" if any(h in rule_id for h in self.HIGH_RULES) else "HIGH"
            score = 9.8 if severity == "CRITICAL" else 8.5

            findings.append({
                "id": f"SEC-{counter:03d}",
                "code": f"GITLEAKS_{rule_id.upper().replace('-', '_')}",
                "severity": severity,
                "score": score,
                "title": f"Secret Leaked: {rule_id}",
                "description": f"Hardcoded secret of type '{rule_id}' detected at {file_path}:{line_no}.",
                "remediation": "Immediately rotate the leaked credential. Remove from git history using 'git filter-repo' or BFG Repo Cleaner. Add to .gitignore.",
                "evidence": {"rule": rule_id, "file": file_path, "line": line_no, "match_redacted": redacted, "commit": commit},
                "cve_ids": [],
            })
            counter += 1

        risk = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for f in findings:
            sev = f["severity"].lower()
            if sev in risk:
                risk[sev] += 1
        risk["total"] = len(findings)

        return {"secrets_found": len(findings), "risk_summary": risk, "findings": findings}
