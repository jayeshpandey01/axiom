"""Fixed scanner profiles mapping server-side profile enums to safe Axiom module invocations."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ScannerProfile:
    name: str
    axiom_module: str
    description: str
    default_timeout_sec: int
    extra_flags: list[str]
    # Binary name used in standalone (non-Axiom) mode. Defaults to axiom_module.
    standalone_binary: str = ""

    def __post_init__(self) -> None:
        # Use axiom_module as standalone_binary if not explicitly set
        if not self.standalone_binary:
            object.__setattr__(self, "standalone_binary", self.axiom_module)


# DAST / Network scanning profiles
DAST_PROFILES: dict[str, ScannerProfile] = {
    "recon": ScannerProfile(
        name="recon",
        axiom_module="httpx",
        description="Fast HTTP service, security headers, and title discovery on authorized hostnames",
        default_timeout_sec=600,
        extra_flags=["-silent", "-status-code", "-title", "-tech-detect", "-web-server", "-include-response-header", "-json"],
        standalone_binary="httpx",
    ),
    "web-discovery": ScannerProfile(
        name="web-discovery",
        axiom_module="httpx",
        description="Comprehensive HTTP/HTTPS port, technology, and vulnerability discovery",
        default_timeout_sec=900,
        extra_flags=[
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-web-server",
            "-content-type",
            "-include-response-header",
            "-json",
        ],
        standalone_binary="httpx",
    ),
    "network-portscan": ScannerProfile(
        name="network-portscan",
        axiom_module="nmap",
        description="Detailed TCP service and version detection on authorized hosts (nmap -sV)",
        default_timeout_sec=900,
        extra_flags=[],
        standalone_binary="nmap",
    ),
    "fast-portscan": ScannerProfile(
        name="fast-portscan",
        axiom_module="masscan",
        description="High-speed full TCP port availability scan on authorized hosts (masscan)",
        default_timeout_sec=600,
        extra_flags=[],
        standalone_binary="masscan",
    ),
    "content-discovery": ScannerProfile(
        name="content-discovery",
        axiom_module="ffuf",
        description="Web directory, route and endpoint enumeration via FFUF fuzzing",
        default_timeout_sec=1200,
        extra_flags=["-mc", "200,204,301,302,307,401,403", "-t", "40", "-noninteractive"],
        standalone_binary="ffuf",
    ),
    "vuln-assessment": ScannerProfile(
        name="vuln-assessment",
        axiom_module="nuclei",
        description="Template-based vulnerability detection using Nuclei (info through critical severity)",
        default_timeout_sec=1800,
        extra_flags=["-silent", "-duc", "-ni", "-severity", "info,low,medium,high,critical"],
        standalone_binary="nuclei",
    ),
    "xss-scan": ScannerProfile(
        name="xss-scan",
        axiom_module="dalfox",
        description="Automated parameter analysis and XSS (Reflected, Stored, DOM) vulnerability scanning via DalFox",
        default_timeout_sec=1200,
        extra_flags=["--silence", "--format", "json", "--mining-dict", "--mining-dom"],
        standalone_binary="dalfox",
    ),
    "dast-zap": ScannerProfile(
        name="dast-zap",
        axiom_module="zap",
        description="Automated web application security scan via OWASP ZAP (passive & active vulnerability assessment)",
        default_timeout_sec=1800,
        extra_flags=["-I"],
        standalone_binary="zap-baseline.py",
    ),
    "oob-interaction": ScannerProfile(
        name="oob-interaction",
        axiom_module="interactsh",
        description="Out-of-band (OOB) interaction, Blind SSRF, and callback detection via ProjectDiscovery Interactsh",
        default_timeout_sec=600,
        extra_flags=["-json"],
        standalone_binary="interactsh-client",
    ),
    "web-crawl": ScannerProfile(
        name="web-crawl",
        axiom_module="katana",
        description="Dynamic JS-aware web crawling and endpoint extraction via ProjectDiscovery Katana",
        default_timeout_sec=900,
        extra_flags=["-silent", "-json"],
        standalone_binary="katana",
    ),
    "deep-content-discovery": ScannerProfile(
        name="deep-content-discovery",
        axiom_module="feroxbuster",
        description="Recursive web directory and endpoint content discovery via Feroxbuster (Rust)",
        default_timeout_sec=1200,
        extra_flags=["--json", "--silent", "--auto-tune"],
        standalone_binary="feroxbuster",
    ),
    "dns-recon": ScannerProfile(
        name="dns-recon",
        axiom_module="dnsx",
        description="Mass DNS resolution and record extraction (A, AAAA, CNAME, MX, TXT) via DNSX",
        default_timeout_sec=600,
        extra_flags=["-silent", "-json", "-a", "-aaaa", "-cname", "-mx", "-txt"],
        standalone_binary="dnsx",
    ),
    "subdomain-takeover": ScannerProfile(
        name="subdomain-takeover",
        axiom_module="subzy",
        description="Subdomain takeover vulnerability detection via CNAME fingerprinting",
        default_timeout_sec=600,
        extra_flags=["--json"],
        standalone_binary="subzy",
    ),
    "smart-portscan": ScannerProfile(
        name="smart-portscan",
        axiom_module="naabu",
        description="Fast and reliable port discovery via ProjectDiscovery Naabu",
        default_timeout_sec=600,
        extra_flags=["-silent", "-json", "-top-ports", "1000"],
        standalone_binary="naabu",
    ),
    "waf-detect": ScannerProfile(
        name="waf-detect",
        axiom_module="wafw00f",
        description="WAF and CDN product fingerprinting via WafW00f before active scanning",
        default_timeout_sec=300,
        extra_flags=["-a", "-f", "json"],
        standalone_binary="wafw00f",
    ),
    "cors-audit": ScannerProfile(
        name="cors-audit",
        axiom_module="corsy",
        description="CORS misconfiguration detection (null origin, wildcard+credentials) via Corsy",
        default_timeout_sec=600,
        extra_flags=[],
        standalone_binary="corsy",
    ),
    "crlf-scan": ScannerProfile(
        name="crlf-scan",
        axiom_module="crlfuzz",
        description="CRLF injection and HTTP Response Splitting detection via CRLFuzz",
        default_timeout_sec=600,
        extra_flags=["-s"],
        standalone_binary="crlfuzz",
    ),
    "ssti-scan": ScannerProfile(
        name="ssti-scan",
        axiom_module="sstimap",
        description="Server-Side Template Injection detection across Jinja2, Twig, Smarty, Freemarker via SSTImap",
        default_timeout_sec=900,
        extra_flags=["--json"],
        standalone_binary="sstimap",
    ),
}

# SAST / Source code analysis profiles
SAST_PROFILES: dict[str, ScannerProfile] = {
    "sast-joern": ScannerProfile(
        name="sast-joern",
        axiom_module="joern",
        description="Static application security testing and dataflow analysis via Joern CPG",
        default_timeout_sec=1800,
        extra_flags=[],
        standalone_binary="joern-scan",
    ),
    "sast-semgrep": ScannerProfile(
        name="sast-semgrep",
        axiom_module="semgrep",
        description="Fast semantic pattern matching and SAST security audit via Semgrep rules",
        default_timeout_sec=900,
        extra_flags=["--config=auto", "--quiet"],
        standalone_binary="semgrep",
    ),
    "sast-trufflehog": ScannerProfile(
        name="sast-trufflehog",
        axiom_module="trufflehog",
        description="Automated secret scanning and live credential leak verification via TruffleHog",
        default_timeout_sec=600,
        extra_flags=["--no-verification"],
        standalone_binary="trufflehog",
    ),
    "sast-codeql": ScannerProfile(
        name="sast-codeql",
        axiom_module="codeql",
        description="Deep semantic AST and inter-procedural dataflow security analysis via GitHub CodeQL (SARIF output)",
        default_timeout_sec=1800,
        extra_flags=[],
        standalone_binary="codeql",
    ),
    "sast-gitleaks": ScannerProfile(
        name="sast-gitleaks",
        axiom_module="gitleaks",
        description="Fast Git repository and filesystem secret scanning with Shannon entropy via Gitleaks",
        default_timeout_sec=600,
        extra_flags=["--report-format", "json"],
        standalone_binary="gitleaks",
    ),
}

SUPPORTED_PROFILES: dict[str, ScannerProfile] = {**DAST_PROFILES, **SAST_PROFILES}


def get_profile(profile_name: str) -> ScannerProfile:
    """Retrieve and validate scanner profile.

    Raises:
        ValueError: If an unrecognized profile is requested.
    """
    if profile_name not in SUPPORTED_PROFILES:
        raise ValueError(f"Unsupported scan profile '{profile_name}'. Allowed profiles: {list(SUPPORTED_PROFILES.keys())}")
    return SUPPORTED_PROFILES[profile_name]
