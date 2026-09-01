"""Security Vulnerability & Exposure Analysis Engine.

Analyzes raw scanner probe records (HTTP response headers, status codes,
technologies, server banners) against security rules and outputs categorized,
severity-ranked findings and risk scores.
"""
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
        ):
            nonlocal finding_id_counter
            findings.append({
                "id": f"SEC-{finding_id_counter:03d}",
                "code": code,
                "severity": severity.upper(),
                "title": title,
                "description": description,
                "evidence": evidence,
                "remediation": remediation,
            })
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
