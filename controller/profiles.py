"""Fixed scanner profiles mapping server-side profile enums to safe Axiom module invocations."""
from dataclasses import dataclass, field


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


SUPPORTED_PROFILES: dict[str, ScannerProfile] = {
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
        extra_flags=["-silent", "-status-code", "-title", "-tech-detect", "-web-server", "-content-type", "-include-response-header", "-json"],
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
        extra_flags=["-mc", "200,204,301,302,307,401,403", "-t", "40"],
        standalone_binary="ffuf",
    ),
    "vuln-assessment": ScannerProfile(
        name="vuln-assessment",
        axiom_module="nuclei",
        description="Template-based vulnerability detection using Nuclei (info through critical severity)",
        default_timeout_sec=1800,
        extra_flags=["-silent", "-severity", "info,low,medium,high,critical"],
        standalone_binary="nuclei",
    ),
}


def get_profile(profile_name: str) -> ScannerProfile:
    """Retrieve and validate scanner profile.

    Raises:
        ValueError: If an unrecognized profile is requested.
    """
    if profile_name not in SUPPORTED_PROFILES:
        raise ValueError(
            f"Unsupported scan profile '{profile_name}'. Allowed profiles: {list(SUPPORTED_PROFILES.keys())}"
        )
    return SUPPORTED_PROFILES[profile_name]
