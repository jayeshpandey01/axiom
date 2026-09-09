"""Test AI Chat & Grounded Streaming Endpoint (/v1/ai/chat)."""

import os
from unittest.mock import patch
from unittest.mock import AsyncMock, patch

from starlette.testclient import TestClient

from app.api.v1.ai import get_llm_client
from app.api.v1.ai import get_effective_api_key, get_llm_client
from app.main import app

client = TestClient(app)


def test_ai_chat_streaming():
MOCK_UPSTREAM_RESPONSE = {
    "response": "Here is the explanation for finding F-10291 in auth.ts.",
    "latency_ms": 120.5,
    "tokens_used": 45,
    "search_performed": False,
    "sources": [],
    "provider": "cmd-d_engine",
    "model": "cmd-d_llm",
}


@patch("app.api.v1.ai.query_cmdd_gateway", new_callable=AsyncMock)
def test_ai_chat_streaming(mock_query):
    mock_query.return_value = MOCK_UPSTREAM_RESPONSE

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
    assert "cmd-d_engine" in content
    mock_query.assert_awaited_once()


def test_ai_chat_non_streaming():
@patch("app.api.v1.ai.query_cmdd_gateway", new_callable=AsyncMock)
def test_ai_chat_non_streaming(mock_query):
    mock_query.return_value = MOCK_UPSTREAM_RESPONSE

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
    assert "F-10291" in data["reply"]
    assert data["referenced_finding_ids"] == ["F-10291"]
    assert data["graph_view_mode"] == "control_flow"
    assert data["provider"] == "cmd-d_engine"
    assert data["model"] == "cmd-d_llm"
    mock_query.assert_awaited_once()


@patch("app.api.v1.ai.query_cmdd_gateway", new_callable=AsyncMock)
def test_ai_chat_web_search_flag(mock_query):
    mock_query.return_value = {
        **MOCK_UPSTREAM_RESPONSE,
        "search_performed": True,
        "sources": [{"index": 1, "title": "CVE-2026-0001", "url": "https://cve.mitre.org"}],
    }

    response = client.post(
        "/v1/ai/chat",
        json={
            "query": "latest vulnerabilities",
            "stream": False,
            "web_search": True,
            "max_search_results": 2,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["search_performed"] is True
    assert len(data["sources"]) == 1
    mock_query.assert_awaited_once_with(
        query="latest vulnerabilities",
        max_tokens=512,
        temperature=0.7,
        web_search=True,
        max_search_results=2,
        language="auto",
        api_key=None,
    )


def test_ai_chat_ignores_legacy_api_key():
    """Verify that clients passing a legacy api_key field are gracefully accepted via extra='ignore'."""
    """Verify that clients passing a legacy api_key field are gracefully accepted."""
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
    """Verify get_effective_api_key and get_llm_client checks CMD_D_API_KEY from environment."""
    with patch.dict(os.environ, {"CMD_D_API_KEY": "test-render-key"}, clear=False):
        with patch("app.api.v1.ai.TRAINIQ_AVAILABLE", True), patch("app.api.v1.ai.cmddllm", create=True) as mock_cmddllm:
            client_inst = get_llm_client()
            mock_cmddllm.assert_called_once_with(api_key="test-render-key")
            assert client_inst is mock_cmddllm.return_value

        assert get_effective_api_key() == "test-render-key"
        client_inst = get_llm_client()
        assert client_inst is not None
        assert client_inst["api_key"] == "test-render-key"
