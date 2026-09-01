from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from controller.config import settings
from controller.fleet_manager import FleetError, FleetManager
from controller.profiles import SUPPORTED_PROFILES, get_profile
from controller.watchdog import OrphanWatchdog


def test_supported_profiles() -> None:
    recon = get_profile("recon")
    assert recon.name == "recon"
    assert recon.axiom_module == "httpx"
    assert "-json" in recon.extra_flags

    web = get_profile("web-discovery")
    assert web.name == "web-discovery"

    with pytest.raises(ValueError, match="Unsupported scan profile"):
        get_profile("arbitrary-nmap-profile")


def test_fleet_manager_enforces_max_fleet_size() -> None:
    manager = FleetManager(dry_run=True)
    with pytest.raises(ValueError, match="exceeds maximum allowed fleet size"):
        manager.create_fleet("overflow-fleet", count=settings.max_fleet_size + 1)


def test_dry_run_scan_execution(tmp_path: Path) -> None:
    manager = FleetManager(dry_run=True)
    manager.work_dir = tmp_path
    output_file = tmp_path / "test_out.json"

    with manager.managed_fleet("test-fleet-1", count=1) as fleet:
        assert fleet == "test-fleet-1"
        res = manager.execute_scan(fleet, "recon", "scanme.nmap.org", output_file)
        assert res == output_file


def test_guaranteed_teardown_on_exception() -> None:
    manager = FleetManager(dry_run=True)
    with patch.object(manager, "destroy_fleet", wraps=manager.destroy_fleet) as mock_destroy:
        with pytest.raises(RuntimeError, match="Simulated mid-scan failure"):
            with manager.managed_fleet("failing-fleet", count=1):
                raise RuntimeError("Simulated mid-scan failure")

        # Verify teardown was called despite the exception
        mock_destroy.assert_called_once_with("failing-fleet")


def test_watchdog_dry_run_cleanup() -> None:
    manager = FleetManager(dry_run=True)
    watchdog = OrphanWatchdog(manager=manager)
    purged = watchdog.cleanup_all_fleets(force=True)
    assert isinstance(purged, int)
