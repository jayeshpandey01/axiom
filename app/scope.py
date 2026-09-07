"""Target scope and network safety validation engine.

Prevents targeting private networks, loopback addresses, cloud metadata endpoints,
or reserved IP ranges.
"""

import ipaddress
import re

# Disallowed hostname patterns (cloud metadata, internal DNS, local domains)
FORBIDDEN_HOSTNAME_PATTERNS = [
    re.compile(r"^localhost$", re.IGNORECASE),
    re.compile(r"^localhost\.localdomain$", re.IGNORECASE),
    re.compile(r".*\.local$", re.IGNORECASE),
    re.compile(r".*\.internal$", re.IGNORECASE),
    re.compile(r"^metadata\.google\.internal$", re.IGNORECASE),
    re.compile(r"^instance-data$", re.IGNORECASE),
]

HOSTNAME_REGEX = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*$")


def validate_target_scope(target: str) -> str:
    """Validate that a target value is safe and within authorized scanning scope.

    Args:
        target: Hostname or IP address string.

    Returns:
        The normalized target string.

    Raises:
        ValueError: If the target falls into private, loopback, multicast, or reserved ranges.
    """
    normalized = target.strip().lower().rstrip(".")

    if not normalized:
        raise ValueError("Target value cannot be empty.")

    if "://" in normalized or "/" in normalized or " " in normalized:
        raise ValueError("Target must be a plain hostname or IP address without URL scheme or path.")

    # Check if target is an IP address
    try:
        ip = ipaddress.ip_address(normalized)

        if ip.is_loopback:
            raise ValueError(f"Target IP '{normalized}' is a loopback address and cannot be scanned.")
        if ip.is_link_local:
            raise ValueError(f"Target IP '{normalized}' is a link-local / cloud metadata address and cannot be scanned.")
        if ip.is_private:
            raise ValueError(f"Target IP '{normalized}' is a private RFC1918/RFC4193 address and cannot be scanned.")
        if ip.is_multicast:
            raise ValueError(f"Target IP '{normalized}' is a multicast address and cannot be scanned.")
        if ip.is_reserved or ip.is_unspecified:
            raise ValueError(f"Target IP '{normalized}' is a reserved/unspecified address and cannot be scanned.")

        return str(ip)
    except ValueError as err:
        # Not an IP address, proceed to hostname validation unless it was an invalid IP error raised above
        if "cannot be scanned" in str(err):
            raise

    # Hostname validation
    for pattern in FORBIDDEN_HOSTNAME_PATTERNS:
        if pattern.match(normalized):
            raise ValueError(f"Target hostname '{normalized}' is forbidden (internal/metadata domain).")

    if not HOSTNAME_REGEX.match(normalized):
        raise ValueError(f"Target hostname '{normalized}' is not a valid RFC 1123 hostname.")

    if len(normalized) > 253:
        raise ValueError("Target hostname exceeds 253 characters maximum length.")

    return normalized


FORBIDDEN_SYSTEM_PATHS = [
    "/etc",
    "/sys",
    "/proc",
    "/dev",
    "/boot",
    "/root",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "c:\\windows",
    "c:\\windows\\system32",
]


def validate_sast_target_scope(target: str) -> str:
    """Validate that a source code target is safe and within authorized repository or local directory scope.

    Args:
        target: Filesystem path string or repository URL.

    Returns:
        Normalized target string.

    Raises:
        ValueError: If target is empty, targets restricted system directories, or contains invalid syntax.
    """
    normalized = target.strip()
    if not normalized:
        raise ValueError("Source target value cannot be empty.")

    if len(normalized) > 253:
        raise ValueError("Target value exceeds 253 characters maximum length.")

    # Check if target is a git repository URL
    if normalized.startswith(("https://", "git@", "ssh://")):
        if not re.match(r"^(https://|git@|ssh://)[A-Za-z0-9_.-]+(/|:)[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?$", normalized):
            raise ValueError("Target repository URL is not a valid git URL format.")
        return normalized

    # Local directory/file path validation
    clean_path = normalized.replace("\\", "/").rstrip("/")
    lower_path = clean_path.lower()

    for forbidden in FORBIDDEN_SYSTEM_PATHS:
        if lower_path == forbidden or lower_path.startswith(forbidden + "/"):
            raise ValueError(f"Target path '{normalized}' points to a restricted system directory.")

    return normalized
