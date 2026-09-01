"""Tests for the GitHub Actions Cloud Scanner Dispatcher."""
from unittest.mock import MagicMock, patch

from app.core.config import Settings
from app.github_dispatcher import (
    check_github_runner_active,
    dispatch_github_runner,
    trigger_cloud_scanner_if_needed,
)


def test_check_github_runner_active_when_running():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "workflow_runs": [
            {"id": 101, "status": "in_progress"},
            {"id": 100, "status": "completed"},
        ]
    }

    with patch("httpx.Client.get", return_value=mock_response):
        is_active = check_github_runner_active(
            owner="jayeshpandey01",
            repo="axiom",
            workflow_id="scanner_runner.yml",
            token="ghp_mocktoken",
        )
        assert is_active is True


def test_check_github_runner_active_when_queued():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "workflow_runs": [
            {"id": 102, "status": "queued"},
        ]
    }

    with patch("httpx.Client.get", return_value=mock_response):
        is_active = check_github_runner_active(
            owner="jayeshpandey01",
            repo="axiom",
            workflow_id="scanner_runner.yml",
            token="ghp_mocktoken",
        )
        assert is_active is True


def test_check_github_runner_active_when_idle():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "workflow_runs": [
            {"id": 100, "status": "completed"},
            {"id": 99, "status": "completed"},
        ]
    }

    with patch("httpx.Client.get", return_value=mock_response):
        is_active = check_github_runner_active(
            owner="jayeshpandey01",
            repo="axiom",
            workflow_id="scanner_runner.yml",
            token="ghp_mocktoken",
        )
        assert is_active is False


def test_check_github_runner_active_on_http_error():
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.text = "Not Found"

    with patch("httpx.Client.get", return_value=mock_response):
        is_active = check_github_runner_active(
            owner="jayeshpandey01",
            repo="axiom",
            workflow_id="scanner_runner.yml",
            token="ghp_mocktoken",
        )
        assert is_active is False


def test_dispatch_github_runner_success():
    mock_response = MagicMock()
    mock_response.status_code = 204

    with patch("httpx.Client.post", return_value=mock_response):
        success = dispatch_github_runner(
            owner="jayeshpandey01",
            repo="axiom",
            workflow_id="scanner_runner.yml",
            token="ghp_mocktoken",
        )
        assert success is True


def test_dispatch_github_runner_failure():
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.text = "Bad credentials"

    with patch("httpx.Client.post", return_value=mock_response):
        success = dispatch_github_runner(
            owner="jayeshpandey01",
            repo="axiom",
            workflow_id="scanner_runner.yml",
            token="ghp_mocktoken",
        )
        assert success is False


def test_trigger_cloud_scanner_skips_when_no_token():
    dummy_settings = Settings(github_token=None)
    with patch("app.github_dispatcher.get_settings", return_value=dummy_settings):
        result = trigger_cloud_scanner_if_needed()
        assert result is False


def test_trigger_cloud_scanner_skips_when_already_active():
    dummy_settings = Settings(github_token="ghp_test")
    with (
        patch("app.github_dispatcher.get_settings", return_value=dummy_settings),
        patch("app.github_dispatcher.check_github_runner_active", return_value=True),
        patch("app.github_dispatcher.dispatch_github_runner") as mock_dispatch,
    ):
        result = trigger_cloud_scanner_if_needed()
        assert result is True
        mock_dispatch.assert_not_called()


def test_trigger_cloud_scanner_dispatches_when_idle():
    dummy_settings = Settings(
        github_token="ghp_test",
        github_repo_owner="jayeshpandey01",
        github_repo_name="axiom",
        github_workflow_id="scanner_runner.yml",
    )
    with (
        patch("app.github_dispatcher.get_settings", return_value=dummy_settings),
        patch("app.github_dispatcher.check_github_runner_active", return_value=False),
        patch("app.github_dispatcher.dispatch_github_runner", return_value=True) as mock_dispatch,
    ):
        result = trigger_cloud_scanner_if_needed()
        assert result is True
        mock_dispatch.assert_called_once_with(
            owner="jayeshpandey01",
            repo="axiom",
            workflow_id="scanner_runner.yml",
            token="ghp_test",
            ref="main",
        )
