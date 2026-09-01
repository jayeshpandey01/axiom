import pytest

from app.scope import validate_target_scope


def test_valid_hostnames_pass() -> None:
    assert validate_target_scope("example.com") == "example.com"
    assert validate_target_scope("scanme.nmap.org") == "scanme.nmap.org"
    assert validate_target_scope("api.sub-domain.co.uk") == "api.sub-domain.co.uk"
    assert validate_target_scope("  EXAMPLE.COM.  ") == "example.com"


def test_valid_public_ips_pass() -> None:
    assert validate_target_scope("93.184.216.34") == "93.184.216.34"
    assert validate_target_scope("8.8.8.8") == "8.8.8.8"
    assert validate_target_scope("1.1.1.1") == "1.1.1.1"


def test_private_ips_rejected() -> None:
    with pytest.raises(ValueError, match="private RFC1918"):
        validate_target_scope("10.0.0.1")

    with pytest.raises(ValueError, match="private RFC1918"):
        validate_target_scope("192.168.1.1")

    with pytest.raises(ValueError, match="private RFC1918"):
        validate_target_scope("172.16.0.5")


def test_loopback_and_metadata_rejected() -> None:
    with pytest.raises(ValueError, match="loopback address"):
        validate_target_scope("127.0.0.1")

    with pytest.raises(ValueError, match="link-local / cloud metadata"):
        validate_target_scope("169.254.169.254")


def test_forbidden_hostnames_rejected() -> None:
    with pytest.raises(ValueError, match="forbidden"):
        validate_target_scope("localhost")

    with pytest.raises(ValueError, match="forbidden"):
        validate_target_scope("metadata.google.internal")

    with pytest.raises(ValueError, match="forbidden"):
        validate_target_scope("server.local")


def test_urls_and_paths_rejected() -> None:
    with pytest.raises(ValueError, match="without URL scheme or path"):
        validate_target_scope("https://example.com")

    with pytest.raises(ValueError, match="without URL scheme or path"):
        validate_target_scope("example.com/login")
