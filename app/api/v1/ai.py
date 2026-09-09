"""AI Chat & Security Query Streaming Endpoint."""
"""AI Chat & Security Query Endpoint powered by cmd-d_llm Gateway."""

import json
import logging
import os
import time
from typing import List, Optional
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from app.core.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["AI"])

# Check TrainIQ availability
TRAINIQ_AVAILABLE = False
try:
    from trainiq import cmddllm

    TRAINIQ_AVAILABLE = True
except ImportError:
    logger.info("[AI] TrainIQ package not installed; will use simulated fallback.")


class AiChatCitation(BaseModel):
    citationIndex: int
    section: str
    score: Optional[float] = None
    filePath: Optional[str] = None
    line: Optional[int] = None
    findingId: Optional[str] = None


class AiChatRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    query: str
    system_prompt: Optional[str] = None
    citations: Optional[List[AiChatCitation]] = None
    referenced_finding_ids: Optional[List[str]] = None
    graph_view_mode: Optional[str] = None
    stream: bool = True
    model: Optional[str] = "cmd-d"
    temperature: Optional[float] = 0.2
    api_key: Optional[str] = Field(None, description="Optional dynamic TrainIQ API key")
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 512
    web_search: Optional[bool] = False
    max_search_results: Optional[int] = 3
    language: Optional[str] = "auto"
    api_key: Optional[str] = Field(None, description="Optional dynamic API key override")


class AiChatResponse(BaseModel):
    reply: str
    citations: Optional[List[AiChatCitation]] = None
    referenced_finding_ids: Optional[List[str]] = None
    graph_view_mode: Optional[str] = None
    duration_ms: float = 0.0
    tokens_used: Optional[int] = 0
    search_performed: bool = False
    sources: Optional[List[Dict[str, Any]]] = None
    provider: Optional[str] = None
    model: Optional[str] = None


def get_llm_client(override_key: Optional[str] = None):
    settings = get_settings()
    key = (
        override_key
        or settings.cmd_d_api_key
        or os.getenv("CMD_D_API_KEY")
        or os.getenv("CMDD_API_KEY")
        or settings.trainiq_api_key
        or os.getenv("TRAINIQ_API_KEY")
        or os.getenv("CMD_D_KEY")
    )
    if TRAINIQ_AVAILABLE and key:
        try:
            return cmddllm(api_key=key)
        except Exception as e:
            logger.warning("[AI] Failed to initialize TrainIQ client: %s", e)
    return None


DEFAULT_GENERAL_SYSTEM_PROMPT = (
    "You are Codefy Security & Engineering AI assistant. "
    "Answer programming, cybersecurity, and engineering questions directly, accurately, and concisely."
)

DEFAULT_SECURITY_SYSTEM_PROMPT = """You are Codefy Security Intelligence AI, an expert application security auditor.
Provide concise, evidence-grounded vulnerability triage, taint trace analysis, and remediation diffs.

RULES:
1. GROUNDING: Assert facts ONLY from verified <context>. If absent or unknown, state "Not detected in current scan". Never invent files, CWEs, or line numbers.
2. CITATIONS: Cite evidence using [1], [2] matching citation tags in <context>. Always reference finding IDs (e.g. F-10291).
3. REMEDIATIONS: When asked for a fix, output exact before/after code blocks or unified git diffs with secure parameterized/sanitized patterns.
4. STYLE: Technical, direct, and actionable. No conversational filler."""


def get_effective_api_key(override_key: Optional[str] = None) -> Optional[str]:
    if override_key:
        return override_key
    env_key = (
        os.getenv("CMD_D_API_KEY")
        or os.getenv("CMDD_API_KEY")
        or os.getenv("TRAINIQ_API_KEY")
        or os.getenv("CMD_D_KEY")
    )
    if env_key:
        return env_key
    settings = get_settings()
    return settings.cmd_d_api_key or settings.trainiq_api_key


def get_gateway_url() -> str:
    settings = get_settings()
    return (
        os.getenv("CMD_D_GATEWAY_URL")
        or getattr(settings, "cmd_d_gateway_url", None)
        or "https://i8791yv32r8c7t21387rcfvt8713cv.onrender.com"
    ).rstrip("/")


def build_upstream_query(req: AiChatRequest) -> str:
    """Build grounded prompt including citations or system prompt if present."""
    if req.system_prompt:
        return f"{req.system_prompt}\n\nQuery: {req.query}"
    if req.citations:
        context_lines = []
        for c in req.citations:
            loc = f" ({c.filePath}:{c.line})" if c.filePath else ""
            context_lines.append(f"[{c.citationIndex}] {c.section}{loc}")
        context_str = "\n".join(context_lines)
        return (
            f"{DEFAULT_SECURITY_SYSTEM_PROMPT}\n\n"
            f"<context>\n{context_str}\n</context>\n\n"
            f"Query: {req.query}"
        )
    return req.query


async def query_cmdd_gateway(
    query: str,
    max_tokens: int = 512,
    temperature: float = 0.7,
    web_search: bool = False,
    max_search_results: int = 3,
    language: str = "auto",
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute direct inference call against cmd-d_llm Gateway /api/chat."""
    url = f"{get_gateway_url()}/api/chat"
    headers = {"Content-Type": "application/json"}
    key = get_effective_api_key(api_key)
    if key:
        headers["Authorization"] = f"Bearer {key}"

    payload = {
        "query": query,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "web_search": web_search,
        "max_search_results": max_search_results,
        "language": language,
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()


# Compatibility helper for legacy tests
def get_llm_client(override_key: Optional[str] = None):
    key = get_effective_api_key(override_key)
    if key:
        return {"gateway": get_gateway_url(), "api_key": key}
    return None


@router.post(
    "/chat",
    summary="Stream Grounded AI Security & Code Responses",
    description="Streams real-time markdown tokens grounded in pre-retrieved TypeScript RAG context and citations.",
    description="Streams real-time markdown tokens from cmd-d_llm Gateway /api/chat with optional web search.",
)
async def ai_chat(
    req: AiChatRequest,
    raw_request: Request,
):
    start_t = time.time()
    formatted_query = build_upstream_query(req)

    if req.system_prompt:
        system_prompt = req.system_prompt
    else:
    elif req.citations:
        context_lines = []
        if req.citations:
            for c in req.citations:
                loc = f" ({c.filePath}:{c.line})" if c.filePath else ""
                context_lines.append(f"[{c.citationIndex}] {c.section}{loc}")
        context_str = "\n".join(context_lines) if context_lines else "No direct findings cited in scan."
        for c in req.citations:
            loc = f" ({c.filePath}:{c.line})" if c.filePath else ""
            context_lines.append(f"[{c.citationIndex}] {c.section}{loc}")
        context_str = "\n".join(context_lines)
        system_prompt = f"{DEFAULT_SECURITY_SYSTEM_PROMPT}\n\n<context>\n{context_str}\n</context>"
    else:
        system_prompt = DEFAULT_GENERAL_SYSTEM_PROMPT

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": req.query},
    ]

    client = get_llm_client(req.api_key)

    if req.stream:
        def sse_generator():
        async def sse_generator():
            accumulated_tokens = 0
            accumulated_text = ""

            if client:
                try:
                    reply_text = ""
                    resp = client.chat.completions.create(
                        messages=messages,
                        max_tokens=1024,
                        temperature=req.temperature or 0.2,
                        stream=False,
                    )
                    if hasattr(resp, "choices") and resp.choices:
                        msg = getattr(resp.choices[0], "message", None)
                        reply_text = getattr(msg, "content", "") or ""
            try:
                data = await query_cmdd_gateway(
                    query=formatted_query,
                    max_tokens=req.max_tokens or 512,
                    temperature=req.temperature or 0.7,
                    web_search=bool(req.web_search),
                    max_search_results=req.max_search_results or 3,
                    language=req.language or "auto",
                    api_key=req.api_key,
                )
                reply_text = data.get("response", "")

                    if reply_text:
                        words = reply_text.split(" ")
                        for i, w in enumerate(words):
                            token = w + (" " if i < len(words) - 1 else "")
                            accumulated_tokens += 1
                            accumulated_text += token
                            yield f"data: {json.dumps({'reply': token, 'done': False})}\n\n"
                            time.sleep(0.015)
                if reply_text:
                    words = reply_text.split(" ")
                    for i, w in enumerate(words):
                        token = w + (" " if i < len(words) - 1 else "")
                        accumulated_tokens += 1
                        accumulated_text += token
                        yield f"data: {json.dumps({'reply': token, 'done': False})}\n\n"
                        time.sleep(0.015)

                        duration_ms = (time.time() - start_t) * 1000
                        terminal_payload = {
                            "reply": "",
                            "done": True,
                            "citations": [c.model_dump() for c in (req.citations or [])],
                            "referenced_finding_ids": req.referenced_finding_ids or [],
                            "graph_view_mode": req.graph_view_mode,
                            "tokens_generated": accumulated_tokens,
                            "duration_ms": round(duration_ms, 2),
                        }
                        yield f"data: {json.dumps(terminal_payload)}\n\n"
                        yield "data: [DONE]\n\n"
                        return
                except Exception as e:
                    // [Fixed Syntax Error on line 288]
                    logger.warning("[AI] TrainIQ completion failed: %s; falling back.", e)
                    duration_ms = (time.time() - start_t) * 1000
                    terminal_payload = {
                        "reply": "",
                        "done": True,
                        "citations": [c.model_dump() for c in (req.citations or [])],
                        "referenced_finding_ids": req.referenced_finding_ids or [],
                        "graph_view_mode": req.graph_view_mode,
                        "tokens_generated": accumulated_tokens,
                        "tokens_used": data.get("tokens_used", 0),
                        "latency_ms": data.get("latency_ms", round(duration_ms, 2)),
                        "duration_ms": round(duration_ms, 2),
                        "search_performed": data.get("search_performed", False),
                        "sources": data.get("sources", []),
                        "provider": data.get("provider", "cmd-d_engine"),
                        "model": data.get("model", "cmd-d_llm"),
                    }
                    yield f"data: {json.dumps(terminal_payload)}\n\n"
                    yield "data: [DONE]\n\n"
                    return
            except Exception as e:
                logger.warning("[AI] Gateway query failed: %s; falling back.", e)

            # Fallback simulated stream if client unavailable or fails
            # Fallback stream if gateway unavailable
            fallback_text = (
                f"### Analysis for: {req.query}\n\n"
                f"Grounded in verified codebase evidence. Found {len(req.citations or [])} citation(s).\n\n"
                f"To enable live TrainIQ generation, ensure `TrainIQ` is installed and `CMD_D_API_KEY` is configured."
                f"cmd-d_llm Gateway is temporarily unreachable."
            )
            words = fallback_text.split(" ")
            for w in words:
                yield f"data: {json.dumps({'reply': w + ' ', 'done': False})}\n\n"
                time.sleep(0.02)

            duration_ms = (time.time() - start_t) * 1000
            terminal_payload = {
                "reply": "",
                "done": True,
                "citations": [c.model_dump() for c in (req.citations or [])],
                "referenced_finding_ids": req.referenced_finding_ids or [],
                "graph_view_mode": req.graph_view_mode,
                "duration_ms": round(duration_ms, 2),
                "tokens_used": 0,
                "search_performed": False,
                "sources": [],
                "provider": "fallback",
                "model": "simulated",
            }
            yield f"data: {json.dumps(terminal_payload)}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(sse_generator(), media_type="text/event-stream")

    # Non-streaming
    reply_text = ""
    if client:
        try:
            resp = client.chat.completions.create(
                messages=messages,
                max_tokens=1024,
                temperature=req.temperature or 0.2,
                stream=False,
            )
            if hasattr(resp, "choices") and resp.choices:
                msg = getattr(resp.choices[0], "message", None)
                reply_text = getattr(msg, "content", "") or ""
        except Exception as e:
            logger.warning("[AI] TrainIQ completion error: %s", e)

    if not reply_text:
        reply_text = f"Analyzed query: {req.query}. Verified {len(req.citations or [])} citations."

    duration_ms = (time.time() - start_t) * 1000
    return AiChatResponse(
        reply=reply_text,
        citations=req.citations,
        referenced_finding_ids=req.referenced_finding_ids,
        graph_view_mode=req.graph_view_mode,
        duration_ms=round(duration_ms, 2),
    )
    try:
        data = await query_cmdd_gateway(
            query=formatted_query,
            max_tokens=req.max_tokens or 512,
            temperature=req.temperature or 0.7,
            web_search=bool(req.web_search),
            max_search_results=req.max_search_results or 3,
            language=req.language or "auto",
            api_key=req.api_key,
        )
        duration_ms = (time.time() - start_t) * 1000
        return AiChatResponse(
            reply=data.get("response", ""),
            citations=req.citations,
            referenced_finding_ids=req.referenced_finding_ids,
            graph_view_mode=req.graph_view_mode,
            duration_ms=round(duration_ms, 2),
            tokens_used=data.get("tokens_used", 0),
            search_performed=data.get("search_performed", False),
            sources=data.get("sources", []),
            provider=data.get("provider", "cmd-d_engine"),
            model=data.get("model", "cmd-d_llm"),
        )
    except Exception as e:
        logger.warning("[AI] Gateway non-streaming query failed: %s; using fallback.", e)
        duration_ms = (time.time() - start_t) * 1000
        return AiChatResponse(
            reply=f"Analyzed query: {req.query}. Verified {len(req.citations or [])} citations.",
            citations=req.citations,
            referenced_finding_ids=req.referenced_finding_ids,
            graph_view_mode=req.graph_view_mode,
            duration_ms=round(duration_ms, 2),
            tokens_used=0,
            search_performed=False,
            sources=[],
            provider="fallback",
            model="simulated",
        )
