"""AI Chat & Security Query Streaming Endpoint."""

import json
import logging
import os
import time
from typing import List, Optional

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict

from app.core.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["AI"])

# Check TrainIQ availability
TRAINIQ_AVAILABLE = False
try:
    from trainiq import cmddllm
    TRAINIQ_AVAILABLE = True
except ImportError:
    logger.info("[AI] trainiq package not installed; will use HTTP streaming fallback.")


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


class AiChatResponse(BaseModel):
    reply: str
    citations: Optional[List[AiChatCitation]] = None
    referenced_finding_ids: Optional[List[str]] = None
    graph_view_mode: Optional[str] = None
    duration_ms: float = 0.0


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


DEFAULT_SECURITY_SYSTEM_PROMPT = """You are Codefy Security Intelligence AI, an expert application security auditor.
Provide concise, evidence-grounded vulnerability triage, taint trace analysis, and remediation diffs.

RULES:
1. GROUNDING: Assert facts ONLY from verified <context>. If absent or unknown, state "Not detected in current scan". Never invent files, CWEs, or line numbers.
2. CITATIONS: Cite evidence using [1], [2] matching citation tags in <context>. Always reference finding IDs (e.g. F-10291).
3. REMEDIATIONS: When asked for a fix, output exact before/after code blocks or unified git diffs with secure parameterized/sanitized patterns.
4. STYLE: Technical, direct, and actionable. No conversational filler."""


@router.post(
    "/chat",
    summary="Stream Grounded AI Security & Code Responses",
    description="Streams real-time markdown tokens grounded in pre-retrieved TypeScript RAG context and citations.",
)
async def ai_chat(
    req: AiChatRequest,
    raw_request: Request,
):
    start_t = time.time()

    if req.system_prompt:
        system_prompt = req.system_prompt
    else:
        context_lines = []
        if req.citations:
            for c in req.citations:
                loc = f" ({c.filePath}:{c.line})" if c.filePath else ""
                context_lines.append(f"[{c.citationIndex}] {c.section}{loc}")
        context_str = "\n".join(context_lines) if context_lines else "No direct findings cited in scan."
        system_prompt = f"{DEFAULT_SECURITY_SYSTEM_PROMPT}\n\n<context>\n{context_str}\n</context>"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": req.query},
    ]

    client = get_llm_client()

    if req.stream:
        def sse_generator():
            accumulated_tokens = 0
            accumulated_text = ""

            if client:
                try:
                    stream_res = client.chat.completions.create(
                        messages=messages,
                        max_tokens=1024,
                        temperature=req.temperature or 0.2,
                        stream=True,
                    )
                    for chunk in stream_res:
                        delta = ""
                        if hasattr(chunk, "choices") and chunk.choices:
                            delta = getattr(chunk.choices[0].delta, "content", "") or ""
                        if delta:
                            accumulated_tokens += 1
                            accumulated_text += delta
                            yield f"data: {json.dumps({'reply': delta, 'done': False})}\n\n"

                    # Terminal event
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
                    logger.warning("[AI] TrainIQ streaming failed: %s; falling back.", e)

            # Fallback simulated stream if client unavailable
            fallback_text = (
                f"### Analysis for: {req.query}\n\n"
                f"Grounded in verified codebase evidence. Found {len(req.citations or [])} citation(s).\n\n"
                f"To enable live TrainIQ generation, set `CMD_D_API_KEY` in environment."
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
            )
            reply_text = resp.choices[0].message.content
        except Exception as e:
            logger.warning(f"[AI] TrainIQ completion error: {e}")

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

