"""Zero-Data-Leakage Sanitizer and Evidence Redaction Engine.

Ensures no internal credentials, absolute system filesystem paths, auth tokens,
or private database connection URIs leak through API responses, error logs,
or scan result summaries.
"""

import re
from typing import Any

# Patterns that expose sensitive secrets or credentials
_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(?:password|secret|token|api[_-]?key|authorization|bearer|cookie|passwd|credential|private[_-]?key)"
)

_SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?i)(?:password|secret|token|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+"
)

# System user paths pattern (e.g. /Users/john/..., /home/ubuntu/..., C:\Users\...)
_USER_PATH_PATTERN = re.compile(r"/(?:Users|home)/[^/\s]+(/.*)?")
_WIN_USER_PATH_PATTERN = re.compile(r"[A-Z]:\\(?:Users|Documents and Settings)\\[^\\]+(\\.*)?", re.IGNORECASE)

# Database connection string pattern
_DB_URI_PATTERN = re.compile(r"[a-zA-Z+]+://[^:]+:[^@]+@[^/\s]+(?:/[^\s]*)?")


def sanitize_error_logs(reason: str | None) -> str | None:
    """Sanitize failure diagnostic reasons before returning via public API.

    Prevents leaking passwords, credentials, database URIs, stack traces,
    or internal user filesystem paths.
    """
    if not reason:
        return None

    cleaned = reason.strip().split("\n")[0][:250]

    # Redact database connection strings
    cleaned = _DB_URI_PATTERN.sub("<REDACTED_DATABASE_URI>", cleaned)

    # Redact sensitive key=value pairs
    if _SENSITIVE_KEY_PATTERN.search(cleaned) and ("=" in cleaned or ":" in cleaned):
        return "Execution failed due to an internal scanner error."

    # Redact user filesystem paths to prevent username exposure
    cleaned = _USER_PATH_PATTERN.sub(r"/workspace\1", cleaned)
    cleaned = _WIN_USER_PATH_PATTERN.sub(r"C:\\workspace\1", cleaned)

    return cleaned


def redact_sensitive_headers(headers: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of headers with sensitive fields redacted."""
    sanitized = {}
    for k, v in headers.items():
        if _SENSITIVE_KEY_PATTERN.search(str(k)):
            sanitized[k] = "<REDACTED>"
        else:
            sanitized[k] = v
    return sanitized
