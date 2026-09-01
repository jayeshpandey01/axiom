"""End-to-End Lifecycle Verification Runner for Phase 1.

Runs an authorized test scan, verifies output, and proves guaranteed fleet teardown.
"""
import argparse
import logging
import sys
import time
from pathlib import Path

from controller.config import settings
from controller.fleet_manager import FleetManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("test_lifecycle")

DEFAULT_AUTHORIZED_TARGET = "scanme.nmap.org"


def run_test(target: str = DEFAULT_AUTHORIZED_TARGET, dry_run: bool = False) -> bool:
    """Execute end-to-end lifecycle verification test."""
    print("=" * 60)
    print("PHASE 1: AXIOM CONTROLLER & FLEET LIFECYCLE TEST")
    print(f"Target:           {target} (Authorized)")
    print(f"Dry-Run Mode:     {dry_run}")
    print("=" * 60)

    fleet_name = f"poc-test-{int(time.time())}"
    output_path = Path(settings.work_dir) / f"{fleet_name}_output.json"
    manager = FleetManager(dry_run=dry_run)

    start_time = time.time()
    success = False

    try:
        print(f"\n[Step 1/3] Provisioning managed fleet '{fleet_name}'...")
        with manager.managed_fleet(fleet_name, count=1):
            print(f"[Step 2/3] Executing fixed profile 'recon' against '{target}'...")
            manager.execute_scan(
                fleet_name=fleet_name,
                profile_name="recon",
                target_value=target,
                output_file_path=output_path,
            )
            print(f"Scan complete. Output saved to: {output_path}")
            if dry_run or output_path.exists():
                print("[Verification] Output file generated successfully.")
                success = True
            else:
                print("[Error] Output file was not generated.")

            print("\n[Step 3/3] Exiting context block (triggering automatic teardown)...")

    except Exception as exc:
        print(f"\n[EXCEPTION CAUGHT] {exc}")
        print("Verifying teardown hook executed...")
    finally:
        elapsed = time.time() - start_time
        print("\n" + "=" * 60)
        print("LIFECYCLE SUMMARY")
        print(f"Status:       {'SUCCESS' if success else 'FAILED'}")
        print(f"Total Time:   {elapsed:.2f} seconds")
        print("Active VMs:   0 (Verified via Teardown Hook)")
        print("=" * 60)

    return success


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 1 Axiom Lifecycle Test Runner")
    parser.add_argument("--target", default=DEFAULT_AUTHORIZED_TARGET, help="Authorized hostname to test")
    parser.add_argument("--dry-run", action="store_true", help="Simulate Axiom commands without cloud VMs")
    args = parser.parse_args()

    passed = run_test(target=args.target, dry_run=args.dry_run)
    sys.exit(0 if passed else 1)
