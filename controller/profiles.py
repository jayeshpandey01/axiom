"""Fixed scanner profiles mapping server-side profile enums to safe Axiom module invocations."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ScannerProfile:
    name: str
    axiom_module: str
    description: str
    default_timeout_sec: int
    extra_flags: list[str]


SUPPORTED_PROFILES: dict[str, ScannerProfile] = {
    "recon": ScannerProfile(
        name="recon",
        axiom_module="httpx",
        description="Fast HTTP service, security headers, and title discovery on authorized hostnames",
        default_timeout_sec=600,
        extra_flags=["-silent", "-status-code", "-title", "-tech-detect", "-web-server", "-include-response-header", "-json"],
    ),
    "web-discovery": ScannerProfile(
        name="web-discovery",
        axiom_module="httpx",
        description="Comprehensive HTTP/HTTPS port, technology, and vulnerability discovery",
        default_timeout_sec=900,
        extra_flags=["-silent", "-status-code", "-title", "-tech-detect", "-web-server", "-content-type", "-include-response-header", "-json"],
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
