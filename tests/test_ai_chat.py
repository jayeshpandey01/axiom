"""Test AI Chat & Grounded Streaming Endpoint (/v1/ai/chat)."""

import os
from unittest.mock import patch

from starlette.testclient import TestClient

from app.api.v1.ai import get_llm_client
from app.main import app

client = TestClient(app)


def test_ai_chat_streaming():
    response = client.post(
        "/v1/ai/chat",
        json={
            "query": "explain F-10291 in auth.ts",
            "stream": True,
            "citations": [
                {
                    "citationIndex": 1,
                    "section": "SQL Injection in auth.ts",
                    "filePath": "src/api/auth.ts",
                    "line": 42,
                    "findingId": "F-10291",
                }
            ],
            "referenced_finding_ids": ["F-10291"],
            "graph_view_mode": "control_flow",
        },
    )
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]

    content = response.text
    assert "data: " in content
    assert "[DONE]" in content
    assert "F-10291" in content


def test_ai_chat_non_streaming():
    response = client.post(
        "/v1/ai/chat",
        json={
            "query": "explain F-10291 in auth.ts",
            "stream": False,
            "citations": [
                {
                    "citationIndex": 1,
                    "section": "SQL Injection in auth.ts",
                    "filePath": "src/api/auth.ts",
                    "line": 42,
                    "findingId": "F-10291",
                }
            ],
            "referenced_finding_ids": ["F-10291"],
            "graph_view_mode": "control_flow",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "reply" in data
    assert data["referenced_finding_ids"] == ["F-10291"]
    assert data["graph_view_mode"] == "control_flow"


def test_ai_chat_ignores_legacy_api_key():
    """Verify that clients passing a legacy api_key field are gracefully accepted via extra='ignore'."""
    response = client.post(
        "/v1/ai/chat",
        json={
            "query": "explain vulnerability",
            "stream": False,
            "api_key": "legacy-key-that-should-be-ignored",
        },
    )
    assert response.status_code == 200
    assert "reply" in response.json()


def test_get_llm_client_picks_up_cmd_d_api_key():
    """Verify get_llm_client checks CMD_D_API_KEY from environment."""
    with patch.dict(os.environ, {"CMD_D_API_KEY": "test-render-key"}, clear=False):
        with patch("app.api.v1.ai.TRAINIQ_AVAILABLE", True), patch("app.api.v1.ai.cmddllm", create=True) as mock_cmddllm:
            client_inst = get_llm_client()
            mock_cmddllm.assert_called_once_with(api_key="test-render-key")
            assert client_inst is mock_cmddllm.return_value

