"""Security Vulnerability & Exposure Analysis Engine.

Analyzes raw scanner probe records (HTTP response headers, status codes,
technologies, server banners) against security rules and outputs categorized,
severity-ranked findings and risk scores.
"""

import json
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
            if extracted:
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
