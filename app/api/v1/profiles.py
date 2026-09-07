"""Profile listing endpoints for DAST and SAST profiles."""

from typing import Any

from fastapi import APIRouter

router = APIRouter()


@router.get("", summary="List Available DAST Profiles", tags=["DAST Scans"])
def get_dast_profiles() -> dict[str, Any]:
    """Retrieve all supported DAST scan profiles and scanner tools."""
    return {
        "dast_profiles": [
            {"profile": "recon", "scanner": "httpx", "purpose": "Fast HTTP service, security headers, and title discovery"},
            {"profile": "web-discovery", "scanner": "httpx", "purpose": "Comprehensive HTTP/HTTPS port, technology, and vulnerability discovery"},
            {"profile": "network-portscan", "scanner": "nmap", "purpose": "Detailed TCP service and version detection (nmap -sV -T4)"},
            {"profile": "fast-portscan", "scanner": "masscan", "purpose": "High-speed full port availability scan (masscan)"},
            {"profile": "smart-portscan", "scanner": "naabu", "purpose": "Fast reliable port discovery via ProjectDiscovery Naabu"},
            {"profile": "content-discovery", "scanner": "ffuf", "purpose": "Web directory, route, and endpoint enumeration via fuzzing"},
            {"profile": "deep-content-discovery", "scanner": "feroxbuster", "purpose": "Recursive web content discovery via Feroxbuster (Rust)"},
            {"profile": "web-crawl", "scanner": "katana", "purpose": "Dynamic JS-aware web crawling and endpoint extraction via Katana"},
            {"profile": "vuln-assessment", "scanner": "nuclei", "purpose": "Template-based vulnerability detection (info through critical severity)"},
            {"profile": "xss-scan", "scanner": "dalfox", "purpose": "Automated parameter analysis and XSS scanning via DalFox"},
            {"profile": "dast-zap", "scanner": "zap", "purpose": "Automated web application vulnerability scan via OWASP ZAP"},
            {"profile": "oob-interaction", "scanner": "interactsh", "purpose": "Out-of-band interaction and Blind SSRF detection via Interactsh"},
            {"profile": "dns-recon", "scanner": "dnsx", "purpose": "Mass DNS resolution, CNAME/A/MX/TXT record extraction via DNSX"},
            {"profile": "subdomain-takeover", "scanner": "subzy", "purpose": "Subdomain takeover detection via dangling DNS CNAME fingerprinting"},
            {"profile": "waf-detect", "scanner": "wafw00f", "purpose": "WAF and CDN product fingerprinting before active scanning"},
            {"profile": "cors-audit", "scanner": "corsy", "purpose": "CORS misconfiguration detection (null origin, wildcard+credentials)"},
            {"profile": "crlf-scan", "scanner": "crlfuzz", "purpose": "CRLF injection and HTTP Response Splitting detection"},
            {"profile": "ssti-scan", "scanner": "sstimap", "purpose": "Server-Side Template Injection detection across Jinja2, Twig, Smarty, Freemarker"},
        ]
    }


@router.get("/sast", summary="List Available SAST Profiles", tags=["SAST Scans"])
def get_sast_profiles() -> dict[str, Any]:
    """Retrieve supported SAST profiles, query bundles, and language engines."""
    return {
        "sast_profiles": [
            {
                "profile": "sast-joern",
                "engine": "Joern CPG",
                "languages": ["C", "C++", "Java", "Kotlin", "JavaScript", "TypeScript", "Python", "Go", "PHP"],
                "purpose": "Static application security testing via Code Property Graphs",
            },
            {
                "profile": "sast-semgrep",
                "engine": "Semgrep",
                "languages": ["Python", "JavaScript", "TypeScript", "Java", "Go", "C", "C++", "Ruby", "PHP", "Rust", "Dockerfile", "Terraform"],
                "purpose": "High-speed semantic AST pattern matching and vulnerability rule scanning",
            },
            {
                "profile": "sast-trufflehog",
                "engine": "TruffleHog",
                "languages": ["All Languages", "Git History", "Environment Files"],
                "purpose": "Automated secret scanning and live API key/credential leak verification",
            },
            {
                "profile": "sast-codeql",
                "engine": "GitHub CodeQL",
                "languages": ["Python", "JavaScript", "TypeScript", "Java", "Go", "C", "C++", "C#", "Ruby", "Swift"],
                "purpose": "Deep semantic code analysis and inter-procedural taint-tracking via GitHub CodeQL",
            },
            {
                "profile": "sast-gitleaks",
                "engine": "Gitleaks",
                "languages": ["All Languages", "Git History", "Directories"],
                "purpose": "Fast Git repository and filesystem secret scanning with Shannon entropy analysis",
            },
        ]
    }
