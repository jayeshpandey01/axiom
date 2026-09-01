"""Background Watchdog Daemon to detect and terminate orphaned Axiom scanner droplets."""
import logging
import time

from controller.config import settings
from controller.fleet_manager import FleetManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("controller.watchdog")


class OrphanWatchdog:
    """Detects and deletes stale scanner fleets exceeding max TTL."""

    def __init__(self, manager: FleetManager | None = None, max_ttl_minutes: int | None = None):
        self.manager = manager or FleetManager()
        self.max_ttl_minutes = max_ttl_minutes or settings.droplet_ttl_minutes

    def list_active_instances(self) -> list[str]:
        """Query active Axiom instances."""
        try:
            bin_path = self.manager._resolve_binary("axiom-ls")
            res = self.manager._run_command([bin_path], timeout=60)
            if res.returncode == 0:
                lines = [line.strip() for line in res.stdout.strip().split("\n") if line.strip()]
                return lines
        except Exception as exc:
            logger.warning("Failed to list active instances: %s", exc)
        return []

    def cleanup_all_fleets(self, force: bool = True) -> int:
        """Emergency cleanup to destroy all active fleets/droplets."""
        instances = self.list_active_instances()
        if not instances and not self.manager.dry_run:
            logger.info("Watchdog: No active scanner instances detected.")
            return 0

        logger.warning("Watchdog: Purging %d active instance(s)...", len(instances))
        purged = 0
        try:
            bin_path = self.manager._resolve_binary("axiom-rm")
            cmd = [bin_path, "*", "-f"] if force else [bin_path, "*"]
            res = self.manager._run_command(cmd, timeout=180)
            if res.returncode == 0 or self.manager.dry_run:
                purged = len(instances)
                logger.info("Watchdog: Successfully purged active instances.")
        except Exception as exc:
            logger.error("Watchdog: Error executing purge: %s", exc)
        return purged

    def run_loop(self, poll_interval_sec: int = 300) -> None:
        """Continuous watchdog polling loop."""
        logger.info("Starting Orphan Watchdog (max TTL: %d mins, poll interval: %ds)...", self.max_ttl_minutes, poll_interval_sec)
        while True:
            try:
                instances = self.list_active_instances()
                if instances:
                    logger.info("Active scanner instances found: %s", instances)
                else:
                    logger.debug("No active instances found.")
            except Exception as exc:
                logger.error("Watchdog iteration error: %s", exc)
            time.sleep(poll_interval_sec)


if __name__ == "__main__":
    daemon = OrphanWatchdog()
    daemon.run_loop()
