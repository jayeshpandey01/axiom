"""Test AI Chat & Grounded Streaming Endpoint (/v1/ai/chat)."""

import json
import pytest
from starlette.testclient import TestClient
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
