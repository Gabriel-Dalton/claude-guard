"""
claude-guard V2.2: LLM-fallback for the ask band.

When the scoring pipeline returns a score in the ask band (25 to 59),
this module consults Claude Haiku for a second opinion. The model gets
the command, the score, the signal breakdown, and an optional project
context blurb; it returns a structured verdict (allow / deny / escalate)
with a short reasoning string and a confidence value.

Design rules:
  - Python 3.9+ standard library only. No external SDKs.
  - Hard 3 second wall clock timeout on the HTTP call.
  - Any failure (missing key, network error, malformed response, invalid
    verdict, JSON not parseable) returns None so the caller can fall back
    to the deterministic decision.
  - Never raises. Failure modes are silent (None) on purpose; the hook
    must not break because the LLM provider is having a bad day.

Public API:
  check(ctx, score, signals) -> dict | None
"""

from __future__ import annotations

import json
import os
import re
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional


# ============================================================================
# Constants
# ============================================================================

API_ENDPOINT = "https://api.anthropic.com/v1/messages"
API_MODEL = "claude-haiku-4-5-20251001"
API_VERSION = "2023-06-01"
API_TIMEOUT_SECONDS = 3.0
MAX_TOKENS = 200

ASK_BAND_LOW = 25
ASK_BAND_HIGH = 59

ALLOWED_VERDICTS = {"allow", "deny", "escalate"}
REASONING_MAX_CHARS = 300

# Tuple of exception types that can come out of urllib / sockets across
# Python 3.9 through 3.12. socket.timeout became an alias for TimeoutError
# in 3.10 but is still its own name in 3.9; keep both for safety.
_NETWORK_EXC = (
    urllib.error.URLError,
    urllib.error.HTTPError,
    TimeoutError,
    socket.timeout,
    OSError,
    ValueError,
)


# ============================================================================
# Project context (loaded once at import time)
# ============================================================================

def _load_project_context() -> str:
    """Read project_context.md sitting next to this file. Empty on any error."""
    try:
        path = Path(__file__).resolve().parent / "project_context.md"
        if not path.is_file():
            return ""
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        # Collapse to a single paragraph so it slots cleanly into the prompt.
        collapsed = re.sub(r"\s+", " ", text)
        return collapsed
    except Exception:
        return ""


_PROJECT_CONTEXT = _load_project_context()


# ============================================================================
# Prompt construction
# ============================================================================

def _format_signals(signals: list) -> str:
    """Render the signal list in the same [+N] name: reason format the hook uses."""
    if not signals:
        return "  (no signals matched)"
    lines = []
    for s in signals:
        try:
            points = int(getattr(s, "points", 0))
            name = str(getattr(s, "name", "?"))
            reason = str(getattr(s, "reason", ""))
        except Exception:
            continue
        sign = "+" if points >= 0 else ""
        lines.append(f"  [{sign}{points}] {name}: {reason}")
    return "\n".join(lines) if lines else "  (no signals matched)"


def _build_prompt(ctx, score: int, signals: list) -> str:
    """Assemble the user prompt sent to Claude Haiku."""
    command = str(getattr(ctx, "command", "")).strip()
    project_dir = str(getattr(ctx, "project_dir", ""))

    context_block = (
        _PROJECT_CONTEXT
        if _PROJECT_CONTEXT
        else "(no project context provided)"
    )

    signal_block = _format_signals(signals)

    prompt = (
        "You are a security reviewer for a shell command about to run "
        "inside a developer's project. The deterministic scoring layer "
        "has already produced a numeric risk score in the ambiguous "
        f"'ask' band (range {ASK_BAND_LOW} to {ASK_BAND_HIGH} out of 100). "
        "Your job is to give a second opinion.\n\n"
        "Project context:\n"
        f"{context_block}\n\n"
        f"Project directory: {project_dir}\n\n"
        "Command under review:\n"
        f"{command}\n\n"
        f"Score from rule pipeline: {score} (ask band is {ASK_BAND_LOW} to {ASK_BAND_HIGH})\n\n"
        "Signal breakdown from the rule pipeline:\n"
        f"{signal_block}\n\n"
        "Decide one verdict:\n"
        "  allow    = clearly safe in this project context.\n"
        "  deny     = strong evidence of malicious or destructive intent.\n"
        "  escalate = ambiguous. Default to escalate when unsure.\n\n"
        "Respond with a single JSON object and nothing else. Schema:\n"
        '{"verdict": "allow" | "deny" | "escalate", '
        '"reasoning": "<=300 chars, no line breaks", '
        '"confidence": <float between 0.0 and 1.0>}\n'
        "Do not wrap the JSON in markdown fences. Do not add commentary "
        "before or after the JSON. If you are not sure, choose escalate."
    )
    return prompt


# ============================================================================
# HTTP call
# ============================================================================

def _call_api(api_key: str, prompt: str) -> Optional[dict]:
    """POST to the Anthropic messages endpoint. Returns parsed JSON or None."""
    body = {
        "model": API_MODEL,
        "max_tokens": MAX_TOKENS,
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        data = json.dumps(body).encode("utf-8")
    except (TypeError, ValueError):
        return None

    req = urllib.request.Request(
        API_ENDPOINT,
        data=data,
        method="POST",
        headers={
            "x-api-key": api_key,
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT_SECONDS) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            if status != 200:
                return None
            raw = resp.read()
        return json.loads(raw.decode("utf-8", errors="replace"))
    except _NETWORK_EXC:
        return None
    except Exception:
        # Belt and suspenders: nothing escapes this function.
        return None


# ============================================================================
# Response parsing
# ============================================================================

def _extract_first_text_block(api_response: dict) -> Optional[str]:
    """Pull the first text block out of the Anthropic content array."""
    content = api_response.get("content")
    if not isinstance(content, list) or not content:
        return None
    for block in content:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text":
            text = block.get("text")
            if isinstance(text, str) and text.strip():
                return text
    return None


def _extract_first_json_object(text: str) -> Optional[dict]:
    """Find the first {...} substring and parse it as JSON.

    Uses a non-greedy regex with DOTALL so the model can produce a JSON
    object on multiple lines and we still grab it. If the first candidate
    fails to parse, walks forward and tries the next match.
    """
    # Greedy match from first '{' to last '}'. JSON parser will tell us
    # whether that span is valid. If not, fall back to per-candidate
    # bracket matching.
    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last != -1 and last > first:
        candidate = text[first : last + 1]
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except (ValueError, TypeError):
            pass

    # Fallback: scan all balanced-ish candidates.
    for match in re.finditer(r"\{[^{}]*\}", text, flags=re.DOTALL):
        try:
            obj = json.loads(match.group(0))
            if isinstance(obj, dict):
                return obj
        except (ValueError, TypeError):
            continue
    return None


def _coerce_confidence(value) -> float:
    """Best-effort cast to a float clamped to [0.0, 1.0]. Missing or junk: 0.0."""
    if value is None:
        return 0.0
    try:
        f = float(value)
    except (TypeError, ValueError):
        return 0.0
    if f != f:  # NaN check (NaN is the only value not equal to itself)
        return 0.0
    if f < 0.0:
        return 0.0
    if f > 1.0:
        return 1.0
    return f


def _coerce_reasoning(value) -> str:
    """Stringify, strip, collapse line breaks, truncate to 300 chars."""
    if value is None:
        return ""
    try:
        s = str(value)
    except Exception:
        return ""
    s = s.replace("\r", " ").replace("\n", " ").strip()
    if len(s) > REASONING_MAX_CHARS:
        s = s[:REASONING_MAX_CHARS]
    return s


def _parse_verdict(obj: dict) -> Optional[dict]:
    """Validate the JSON object the model produced. None if unusable."""
    if not isinstance(obj, dict):
        return None

    verdict = obj.get("verdict")
    if not isinstance(verdict, str):
        return None
    verdict = verdict.strip().lower()
    if verdict not in ALLOWED_VERDICTS:
        return None

    reasoning = _coerce_reasoning(obj.get("reasoning"))
    confidence = _coerce_confidence(obj.get("confidence"))

    return {
        "verdict": verdict,
        "reasoning": reasoning,
        "confidence": confidence,
    }


# ============================================================================
# Public entry point
# ============================================================================

def check(ctx, score: int, signals: list) -> Optional[dict]:
    """Consult Claude Haiku about an ask-band command.

    Returns one of:
      - {"verdict": "allow"|"deny"|"escalate",
         "reasoning": str (<=300 chars),
         "confidence": float in [0.0, 1.0]}
      - None on any failure path (missing key, network error, timeout,
        non-200, malformed body, invalid verdict).

    Never raises. Hard 3 second timeout.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        # Cheap exit: no key, no work.
        return None

    try:
        prompt = _build_prompt(ctx, score, signals)
    except Exception:
        return None

    api_response = _call_api(api_key, prompt)
    if api_response is None:
        return None

    text = _extract_first_text_block(api_response)
    if not text:
        return None

    obj = _extract_first_json_object(text)
    if obj is None:
        return None

    return _parse_verdict(obj)
