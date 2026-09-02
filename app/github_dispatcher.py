"""Automated Cloud Scanner Dispatcher via GitHub Actions API.

Checks if a scanner runner is already active in GitHub Actions and dispatches
an on-demand run if needed, ensuring scans are processed 24/7 in the cloud
without manual intervention.
"""
import logging

import httpx

from app.core.config import get_settings

logger = logging.getLogger("app.github_dispatcher")

GITHUB_API_BASE = "https://api.github.com"
ACTIVE_STATUSES = {"in_progress", "queued", "waiting", "requested"}


def check_github_runner_active(
    owner: str,
    repo: str,
    workflow_id: str,
    token: str,
    timeout: float = 10.0,
) -> bool:
    """Check if the given workflow currently has active (in_progress or queued) runs."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs"

    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(url, headers=headers, params={"per_page": 5})
            if response.status_code != 200:
                logger.warning(
                    "GitHub API returned %d when checking workflow runs: %s",
                    response.status_code,
                    response.text,
                )
                return False

            data = response.json()
            runs = data.get("workflow_runs", [])
            for run in runs:
                if run.get("status") in ACTIVE_STATUSES:
                    logger.info(
                        "Found active GitHub runner #%s (status: %s)",
                        run.get("id"),
                        run.get("status"),
                    )
                    return True
            return False
    except Exception as exc:
        logger.warning("Error querying GitHub Actions API: %s", exc)
        return False


def dispatch_github_runner(
    owner: str,
    repo: str,
    workflow_id: str,
    token: str,
    ref: str = "main",
    timeout: float = 10.0,
) -> bool:
    """Trigger a workflow dispatch for the scanner runner in GitHub Actions."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches"
    payload = {"ref": ref}

    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, headers=headers, json=payload)
            if response.status_code in {200, 201, 202, 204}:
                logger.info("Triggered workflow_dispatch for %s on %s/%s", workflow_id, owner, repo)
                return True
            logger.warning(
                "Failed to trigger workflow_dispatch (status %d): %s",
                response.status_code,
                response.text,
            )
            return False
    except Exception as exc:
        logger.warning("Error dispatching GitHub Actions workflow: %s", exc)
        return False


def trigger_cloud_scanner_if_needed() -> bool:
    """Check if scanner is active and trigger an on-demand GitHub Cloud Runner if idle.

    Runs safely inside FastAPI BackgroundTasks without raising exceptions.
    """
    settings = get_settings()

    if not settings.github_token:
        logger.debug("GITHUB_TOKEN not configured. Skipping automated GitHub cloud runner dispatch.")
        return False

    try:
        is_active = check_github_runner_active(
            owner=settings.github_repo_owner,
            repo=settings.github_repo_name,
            workflow_id=settings.github_workflow_id,
            token=settings.github_token,
        )
        if is_active:
            logger.info("GitHub Cloud Scanner runner is already active. Skipping redundant dispatch.")
            return True

        ref = (settings.github_ref or "main").removeprefix("refs/heads/")
        logger.info("No active cloud runner found. Dispatching %s (ref: %s)...", settings.github_workflow_id, ref)
        return dispatch_github_runner(
            owner=settings.github_repo_owner,
            repo=settings.github_repo_name,
            workflow_id=settings.github_workflow_id,
            token=settings.github_token,
            ref=ref,
        )
    except Exception as exc:
        logger.warning("Exception during cloud scanner auto-dispatch: %s", exc)
        return False
