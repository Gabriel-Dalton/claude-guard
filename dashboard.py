#!/usr/bin/env python3
"""
claude-guard dashboard — a single-file local operations console for the
PreToolUse hook's decision log.

Usage:
    python dashboard.py
    python dashboard.py --port 9000
    python dashboard.py --log /path/to/audit.jsonl
    python dashboard.py --no-browser

The dashboard binds to 127.0.0.1, reads audit.jsonl fresh on every API
request (no caching beyond the OS file cache), and the browser polls every
two seconds. Python 3.9+ standard library only. No frameworks, no chart
libraries, no build step. See DASHBOARD.md for the design brief.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from collections import Counter
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

DEFAULT_PORT = 7475
HISTOGRAM_BUCKETS = 10
TOP_N = 10
DECISION_LIMIT = 200
PENDING_MAX_AGE_S = 300  # ignore stale pending files older than 5 minutes
PENDING_UUID_RE = re.compile(r"^[a-f0-9]{8,64}$")
# Long-poll: hold /api/decisions-wait open until audit.jsonl mtime changes
# or this many seconds elapse, then respond. Browser immediately reconnects.
LONG_POLL_TIMEOUT_S = 25
LONG_POLL_TICK_S = 0.1

# Window selector values map to a duration in seconds. "all" means no cutoff.
WINDOWS = {
    "1h":  3600,
    "24h": 86400,
    "7d":  604800,
    "all": None,
}


# ============================================================================
# Data layer — reads audit.jsonl on every call
# ============================================================================

def read_audit_log(path: Path) -> list[dict]:
    """Return all decisions from the log, oldest-first.

    Returns an empty list when the file is missing or unreadable. Malformed
    lines are silently skipped — the log is append-only and may contain a
    partial trailing line at any moment.
    """
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return []
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _parse_ts(ts: object) -> float | None:
    """Parse an ISO-8601 timestamp to a POSIX float. None on failure."""
    if not isinstance(ts, str):
        return None
    s = ts
    # datetime.fromisoformat accepts "+00:00" but not the bare "Z" suffix
    # before Python 3.11. Normalize.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s).timestamp()
    except (ValueError, TypeError):
        return None


def filter_by_window(entries: list[dict], window: str) -> list[dict]:
    seconds = WINDOWS.get(window)
    if seconds is None:
        return entries
    cutoff = time.time() - seconds
    out = []
    for e in entries:
        t = _parse_ts(e.get("ts"))
        if t is None or t >= cutoff:
            # Keep entries with unparseable timestamps too — better to over-
            # show than to silently drop them.
            out.append(e)
    return out


def filter_decisions(
    entries: list[dict],
    decision_filter: str,
    query: str,
) -> list[dict]:
    """Apply the decision-type chip and free-text search filters."""
    out = entries
    if decision_filter and decision_filter != "all":
        out = [e for e in out if (e.get("decision") or "").lower() == decision_filter]
    q = (query or "").strip().lower()
    if q:
        def hay(e):
            sigs = " ".join((s.get("name") or "") for s in (e.get("signals") or []))
            return (
                f"{e.get('command','')} {e.get('tool','')} "
                f"{e.get('project_dir','')} {sigs}"
            ).lower()
        out = [e for e in out if q in hay(e)]
    return out


# ----------------------------------------------------------------------------
# Aggregations
# ----------------------------------------------------------------------------

_URL_DOMAIN_RE = re.compile(r"https?://([^/\s)]+)", re.I)
_SYNTHETIC_PREFIXES = (
    "Edit:", "Write:", "MultiEdit:", "WebFetch:", "WebSearch:",
)


def cluster_key(command: str) -> str:
    """Reduce a command to a short cluster key for grouping ask-band entries.

    Rules:
      - Bash: first two whitespace-separated tokens (e.g. ``"npm install"``).
      - Synthetic non-Bash commands written by the V3 dispatcher look like
        ``"Tool:payload"``. Key by tool plus either the URL host or the
        parent directory of the path.
      - MCP synthetic strings start with ``"mcp__server__action"`` — key by
        that prefix (drop the JSON args).
    """
    cmd = (command or "").strip()
    if not cmd:
        return ""

    # MCP synthetic commands
    if cmd.startswith("mcp__"):
        head = cmd.split(":", 1)[0]
        return head

    # Edit/Write/Web synthetic commands
    for prefix in _SYNTHETIC_PREFIXES:
        if cmd.startswith(prefix):
            rest = cmd[len(prefix):].strip()
            label = prefix[:-1]  # drop trailing ':'
            m = _URL_DOMAIN_RE.match(rest)
            if m:
                return f"{label}: {m.group(1).lower()}"
            normalized = rest.replace("\\", "/")
            if "/" in normalized:
                parent = normalized.rsplit("/", 1)[0]
                if len(parent) > 60:
                    parent = "…" + parent[-58:]
                return f"{label}: {parent}/"
            return f"{label}: {rest[:50]}"

    # Bash and everything else: first two tokens
    tokens = cmd.split()
    if not tokens:
        return ""
    if len(tokens) == 1:
        return tokens[0][:40]
    return f"{tokens[0]} {tokens[1]}"[:60]


def _bucket_config(window: str, entries: list[dict]) -> tuple[int, float, float]:
    """Decide (n_buckets, bucket_seconds, start_ts) for the time-series chart.

    Aims for ~24-30 buckets across the chosen window so the sparkline has
    visible resolution without aliasing.
    """
    now = time.time()
    if window == "1h":
        n, secs = 12, 300.0       # 12 buckets of 5 minutes
        return n, secs, now - n * secs
    if window == "24h":
        n, secs = 24, 3600.0      # 24 hourly buckets
        return n, secs, now - n * secs
    if window == "7d":
        n, secs = 28, 21600.0     # 28 buckets of 6 hours
        return n, secs, now - n * secs

    # "all" — span from the oldest entry to now, capped to 30 buckets
    oldest = None
    for e in entries:
        t = _parse_ts(e.get("ts"))
        if t is not None and (oldest is None or t < oldest):
            oldest = t
    if oldest is None or oldest >= now:
        # No data or all in the future: show last hour by default
        return 12, 300.0, now - 3600
    span = max(now - oldest, 1.0)
    n = 30
    secs = span / n
    return n, secs, oldest


def compute_stats(all_entries: list[dict], window: str) -> dict:
    """Compute every aggregate the frontend needs in one pass.

    ``all_entries`` is the full log (oldest-first). We window inside this
    function so the time-series can use either the windowed or full set
    depending on the metric.
    """
    windowed = filter_by_window(all_entries, window)

    total = len(windowed)
    by_decision = Counter((e.get("decision") or "").lower() for e in windowed)
    scores = [
        e.get("score") for e in windowed
        if isinstance(e.get("score"), (int, float))
    ]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0

    # 10-bucket score histogram: [0-9], [10-19], ... [90-100].
    histogram = [0] * HISTOGRAM_BUCKETS
    for s in scores:
        idx = int(s) // 10
        if idx < 0:
            idx = 0
        elif idx >= HISTOGRAM_BUCKETS:
            idx = HISTOGRAM_BUCKETS - 1
        histogram[idx] += 1

    # Top firing rules.
    rule_counts: Counter[str] = Counter()
    for e in windowed:
        for sig in (e.get("signals") or []):
            name = sig.get("name")
            if name:
                rule_counts[name] += 1
    top_rules = [
        {"name": n, "count": c} for n, c in rule_counts.most_common(TOP_N)
    ]

    # Tuning candidates: ask-band command clusters that repeat.
    ask_clusters: Counter[str] = Counter()
    ask_examples: dict[str, str] = {}
    for e in windowed:
        if (e.get("decision") or "").lower() != "ask":
            continue
        key = cluster_key(e.get("command", ""))
        if not key:
            continue
        ask_clusters[key] += 1
        if key not in ask_examples:
            ask_examples[key] = e.get("command", "")
    tuning_candidates = [
        {"cluster": k, "count": c, "example": ask_examples.get(k, "")}
        for k, c in ask_clusters.most_common(TOP_N)
        if c >= 2
    ]

    # Project breakdown.
    project_counts: Counter[str] = Counter(
        e.get("project_dir") for e in windowed if e.get("project_dir")
    )
    projects = [
        {"path": p, "count": c} for p, c in project_counts.most_common(TOP_N)
    ]

    # Time-series (decisions per bucket) over the chosen window.
    n_buckets, bucket_secs, start_ts = _bucket_config(window, all_entries)
    series_allow = [0] * n_buckets
    series_ask = [0] * n_buckets
    series_deny = [0] * n_buckets
    for e in windowed:
        t = _parse_ts(e.get("ts"))
        if t is None:
            continue
        idx = int((t - start_ts) / bucket_secs)
        if idx < 0 or idx >= n_buckets:
            continue
        dec = (e.get("decision") or "").lower()
        if dec == "allow":
            series_allow[idx] += 1
        elif dec == "ask":
            series_ask[idx] += 1
        elif dec == "deny":
            series_deny[idx] += 1

    return {
        "window": window,
        "total": total,
        "by_decision": {
            "allow": by_decision.get("allow", 0),
            "ask":   by_decision.get("ask",   0),
            "deny":  by_decision.get("deny",  0),
        },
        "avg_score": avg_score,
        "histogram": histogram,
        "top_rules": top_rules,
        "tuning_candidates": tuning_candidates,
        "projects": projects,
        "timeseries": {
            "buckets": n_buckets,
            "bucket_seconds": bucket_secs,
            "start": start_ts,
            "allow": series_allow,
            "ask":   series_ask,
            "deny":  series_deny,
        },
        "log_present": True,
    }


# ============================================================================
# Pending decisions (V4 dashboard bridge)
# ============================================================================
# The hook writes pending/<uuid>.json when an ask-band decision needs human
# approval. The dashboard reads those files, surfaces them in the UI, and
# writes pending/<uuid>.response when the user clicks Approve / Deny.

def _pending_dir_for(log_path: Path) -> Path:
    return log_path.parent / "pending"


def list_pending(log_path: Path) -> list[dict]:
    """Return all pending request records. Cleans up stale request files
    (older than PENDING_MAX_AGE_S) so a dead hook doesn't leave them forever."""
    pdir = _pending_dir_for(log_path)
    if not pdir.exists():
        return []
    now = time.time()
    out = []
    try:
        files = sorted(pdir.glob("*.json"))
    except OSError:
        return []
    for f in files:
        try:
            age = now - f.stat().st_mtime
        except OSError:
            continue
        if age > PENDING_MAX_AGE_S:
            try:
                f.unlink()
                (f.with_suffix(".response")).unlink()
            except OSError:
                pass
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and data.get("uuid"):
            data["_age_s"] = round(age, 1)
            out.append(data)
    return out


def write_pending_response(log_path: Path, uuid: str, verdict: str) -> bool:
    """Atomically write pending/<uuid>.response. Returns True on success."""
    if verdict not in ("allow", "deny"):
        return False
    if not PENDING_UUID_RE.match(uuid):
        return False
    pdir = _pending_dir_for(log_path)
    req = pdir / f"{uuid}.json"
    if not req.exists():
        return False
    resp = pdir / f"{uuid}.response"
    tmp = pdir / f"{uuid}.response.tmp"
    try:
        with tmp.open("w", encoding="utf-8") as f:
            json.dump({"verdict": verdict}, f)
        os.replace(tmp, resp)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return False
    return True


# ============================================================================
# HTTP handler
# ============================================================================

class DashboardHandler(BaseHTTPRequestHandler):
    log_path: Path = None  # set on class before serve_forever

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return  # quiet by design

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path in ("/", "/index.html"):
            self._serve_html()
        elif parsed.path == "/api/stats":
            self._serve_stats(parse_qs(parsed.query))
        elif parsed.path == "/api/decisions":
            self._serve_decisions(parse_qs(parsed.query))
        elif parsed.path == "/api/decisions-wait":
            self._serve_decisions_wait(parse_qs(parsed.query))
        elif parsed.path == "/api/pending":
            self._serve_pending()
        elif parsed.path == "/api/health":
            self._serve_json({"ok": True, "log_path": str(self.log_path)})
        elif parsed.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        # /api/pending/<uuid>/respond
        m = re.match(r"^/api/pending/([a-f0-9]{8,64})/respond$", parsed.path)
        if not m:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        uuid = m.group(1)
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 4096:
            self.send_error(HTTPStatus.BAD_REQUEST, "missing or oversized body")
            return
        try:
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            self.send_error(HTTPStatus.BAD_REQUEST, "invalid JSON")
            return
        verdict = (data or {}).get("verdict")
        if verdict not in ("allow", "deny"):
            self.send_error(HTTPStatus.BAD_REQUEST, "verdict must be allow or deny")
            return
        ok = write_pending_response(self.log_path, uuid, verdict)
        if not ok:
            self.send_error(HTTPStatus.NOT_FOUND, "no such pending decision")
            return
        self._serve_json({"ok": True, "uuid": uuid, "verdict": verdict})

    def _serve_html(self) -> None:
        body = INDEX_HTML.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _serve_stats(self, params: dict) -> None:
        window = _qparam(params, "window", "24h")
        if window not in WINDOWS:
            window = "24h"
        entries = read_audit_log(self.log_path)
        if not entries:
            self._serve_json({
                "window": window,
                "total": 0,
                "by_decision": {"allow": 0, "ask": 0, "deny": 0},
                "avg_score": 0.0,
                "histogram": [0] * HISTOGRAM_BUCKETS,
                "top_rules": [],
                "tuning_candidates": [],
                "projects": [],
                "timeseries": {"buckets": 0, "bucket_seconds": 0,
                               "start": 0, "allow": [], "ask": [], "deny": []},
                "log_present": self.log_path.exists(),
                "log_path": str(self.log_path),
            })
            return
        stats = compute_stats(entries, window)
        stats["log_path"] = str(self.log_path)
        self._serve_json(stats)

    def _serve_decisions(self, params: dict) -> None:
        window = _qparam(params, "window", "24h")
        if window not in WINDOWS:
            window = "24h"
        decision_filter = _qparam(params, "filter", "all").lower()
        query = _qparam(params, "q", "")
        try:
            limit = max(1, min(int(_qparam(params, "limit", str(DECISION_LIMIT))), 2000))
        except (TypeError, ValueError):
            limit = DECISION_LIMIT

        entries = read_audit_log(self.log_path)
        entries = filter_by_window(entries, window)
        entries = filter_decisions(entries, decision_filter, query)
        # Newest first, capped to limit.
        entries.reverse()
        self._serve_json({
            "entries": entries[:limit],
            "total_matched": len(entries),
            "window": window,
            "filter": decision_filter,
            "q": query,
        })

    def _serve_decisions_wait(self, params: dict) -> None:
        """Long-poll the decisions feed. Hangs until audit.jsonl's mtime is
        newer than the client's `since` value, or until LONG_POLL_TIMEOUT_S
        elapses. Browser is expected to immediately re-request.

        The 25s ceiling stays well under any proxy / reverse-proxy idle
        timeout the user might sit behind. With ThreadingHTTPServer each
        long-poll holds one server thread; this is single-user so that's
        fine. The browser aborts the request when filter/window/search
        change, which closes the socket and lets the thread exit on its
        next tick."""
        window = _qparam(params, "window", "24h")
        if window not in WINDOWS:
            window = "24h"
        decision_filter = _qparam(params, "filter", "all").lower()
        query = _qparam(params, "q", "")
        try:
            limit = max(1, min(int(_qparam(params, "limit", str(DECISION_LIMIT))), 2000))
        except (TypeError, ValueError):
            limit = DECISION_LIMIT
        try:
            since = float(_qparam(params, "since", "0"))
        except ValueError:
            since = 0.0

        deadline = time.time() + LONG_POLL_TIMEOUT_S
        while True:
            try:
                current_mtime = self.log_path.stat().st_mtime
            except OSError:
                current_mtime = 0.0

            if current_mtime > since:
                # New data — return immediately.
                entries = read_audit_log(self.log_path)
                entries = filter_by_window(entries, window)
                entries = filter_decisions(entries, decision_filter, query)
                entries.reverse()
                self._serve_json({
                    "entries": entries[:limit],
                    "total_matched": len(entries),
                    "window": window,
                    "filter": decision_filter,
                    "q": query,
                    "mtime": current_mtime,
                    "timeout": False,
                })
                return

            if time.time() >= deadline:
                # No change — respond so the browser can reconnect with a
                # fresh request. Keeps connections from sitting open longer
                # than any reasonable proxy will tolerate.
                self._serve_json({
                    "entries": None,
                    "mtime": current_mtime,
                    "timeout": True,
                })
                return

            time.sleep(LONG_POLL_TICK_S)

    def _serve_pending(self) -> None:
        items = list_pending(self.log_path)
        self._serve_json({"pending": items, "count": len(items)})

    def _serve_json(self, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def _qparam(params: dict, key: str, default: str) -> str:
    values = params.get(key)
    if not values:
        return default
    v = values[0]
    if isinstance(v, bytes):
        try:
            v = v.decode("utf-8", errors="replace")
        except Exception:
            return default
    return v


# ============================================================================
# Embedded frontend (HTML + CSS + JS)
# ============================================================================

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>claude-guard dashboard</title>
<meta name="color-scheme" content="dark">
<style>
:root {
  --bg:           #0b0c0e;
  --bg-elev:      #14161a;
  --bg-elev-2:    #1a1d22;
  --bg-elev-3:    #22262d;
  --fg:           #ece6d7;   /* >= 14:1 on bg */
  --fg-dim:       #c0bcb0;   /* >= 8.5:1 on bg */
  --fg-soft:      #968f80;   /* >= 5.4:1 on bg, passes AA for normal text */
  --fg-faint:     #5d574e;   /* decorative only */
  --accent:       #e2b06b;   /* >= 9:1 on bg */
  --accent-soft:  #b88c4f;
  --accent-tint:  rgba(226, 176, 107, 0.10);
  --good:         #9bbd80;   /* >= 8:1 on bg */
  --warn:         #e2b06b;
  --bad:          #d27466;   /* >= 6.5:1 on bg */
  --bad-tint:     rgba(210, 116, 102, 0.12);
  --good-tint:    rgba(155, 189, 128, 0.12);
  --warn-tint:    rgba(226, 176, 107, 0.10);
  --border:       #2a2e36;
  --border-soft:  #1e2127;
  --border-strong:#42485200;

  --font-sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: ui-monospace, "SF Mono", "Cascadia Code", "Roboto Mono", Menlo, Consolas, monospace;
}

*, *::before, *::after { box-sizing: border-box; }
html, body { margin: 0; background: var(--bg); color: var(--fg); }
body {
  font-family: var(--font-sans);
  font-size: 13px;
  line-height: 1.5;
  min-height: 100vh;
  background:
    radial-gradient(900px 500px at 15% -240px, rgba(226, 176, 107, 0.05), transparent 60%),
    radial-gradient(700px 350px at 90% 0%, rgba(155, 189, 128, 0.03), transparent 60%),
    var(--bg);
  background-attachment: fixed;
}

button { font: inherit; color: inherit; background: none; border: 0; padding: 0; cursor: pointer; }
button:focus-visible, input:focus-visible, [tabindex]:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
  border-radius: 4px;
}

/* ─── status bar ───────────────────────────────────────────── */
.statusbar {
  position: sticky; top: 0; z-index: 50;
  display: flex; align-items: center; gap: 0.85rem;
  padding: 0.5rem 1rem;
  background: rgba(11, 12, 14, 0.85);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--border-soft);
  font-family: var(--font-mono); font-size: 0.75rem; color: var(--fg-soft);
}
.statusbar .dots { display: inline-flex; gap: 0.35rem; }
.statusbar .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--fg-faint); }
.statusbar .dot.red { background: var(--bad); }
.statusbar .dot.amber { background: var(--accent); }
.statusbar .dot.green { background: var(--good); }
.statusbar .path { color: var(--fg-dim); }
.statusbar .spacer { flex: 1; }
.statusbar .ver { color: var(--accent); font-weight: 500; }
.live {
  display: inline-flex; align-items: center; gap: 0.35rem;
  color: var(--fg-soft);
}
.live-pip {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--good);
  box-shadow: 0 0 0 4px rgba(155, 189, 128, 0.12);
  animation: pulse 1.8s ease-in-out infinite;
}
.live.stale .live-pip {
  background: var(--bad);
  box-shadow: 0 0 0 4px var(--bad-tint);
  animation: none;
}
.live.idle .live-pip { animation: none; opacity: 0.6; }
@keyframes pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50%      { opacity: 0.55; transform: scale(0.85); }
}

/* ─── pending-decision bridge banner ───────────────────────── */
.pending-banner {
  position: sticky;
  top: 32px;
  z-index: 49;
  padding: 0.8rem 1rem;
  background: linear-gradient(180deg, rgba(226, 176, 107, 0.18), rgba(226, 176, 107, 0.06));
  border-bottom: 1px solid var(--accent-soft);
  display: none;
}
.pending-banner.has-items { display: block; }
.pending-card {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 0.8rem;
  align-items: center;
  padding: 0.55rem 0.75rem;
  margin-bottom: 0.5rem;
  border: 1px solid var(--accent-soft);
  background: var(--bg-elev);
  border-radius: 6px;
}
.pending-card:last-child { margin-bottom: 0; }
.pending-card__body {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 0.18rem;
}
.pending-card__head {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-family: var(--font-mono);
  font-size: 0.66rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--accent);
}
.pending-card__age { color: var(--fg-soft); }
.pending-card__cmd {
  font-family: var(--font-mono);
  font-size: 0.82rem;
  color: var(--fg);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.pending-card__sigs {
  font-family: var(--font-mono);
  font-size: 0.7rem;
  color: var(--fg-soft);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.pending-card__actions { display: flex; gap: 0.4rem; }
.pending-btn {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  padding: 0.45rem 0.9rem;
  border-radius: 4px;
  border: 1px solid var(--border);
  background: var(--bg-elev-2);
  color: var(--fg);
  transition: all 0.12s ease;
}
.pending-btn:hover:not(:disabled) { transform: translateY(-1px); }
.pending-btn:disabled { opacity: 0.5; cursor: wait; }
.pending-btn.allow { color: var(--good); border-color: var(--good); }
.pending-btn.allow:hover:not(:disabled) { background: var(--good-tint); }
.pending-btn.deny  { color: var(--bad);  border-color: var(--bad); }
.pending-btn.deny:hover:not(:disabled)  { background: var(--bad-tint); }

/* ─── layout ───────────────────────────────────────────────── */
.app {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 320px;
  gap: 1rem;
  padding: 0.9rem 1.1rem 1rem;
  margin: 0 auto;
}
@media (min-width: 1700px) {
  .app { grid-template-columns: minmax(0, 1fr) 360px; }
}
@media (max-width: 960px) {
  .app { grid-template-columns: 1fr; }
}

/* charts that should sit side-by-side on wide screens */
.chart-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 1rem;
  margin-bottom: 1rem;
}
.chart-row > .card { margin-bottom: 0; }
@media (max-width: 1100px) {
  .chart-row { grid-template-columns: 1fr; }
}

h1 {
  font-family: var(--font-sans);
  font-weight: 600;
  font-size: 1.45rem;
  margin: 0;
  letter-spacing: -0.01em;
}
.subhead { color: var(--fg-dim); font-size: 0.85rem; margin: 0.2rem 0 1.2rem; }

/* ─── window pill bar ──────────────────────────────────────── */
.window-bar {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 0.2rem;
  margin-bottom: 1rem;
}
.window-bar button {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  padding: 0.38rem 0.85rem;
  border-radius: 999px;
  color: var(--fg-soft);
  transition: color 0.12s ease, background 0.12s ease;
}
.window-bar button:hover { color: var(--fg); }
.window-bar button[aria-pressed="true"] {
  background: var(--accent-tint);
  color: var(--accent);
}

/* ─── metric tiles ─────────────────────────────────────────── */
.metrics {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 0.75rem;
  margin-bottom: 1rem;
}
@media (max-width: 720px) { .metrics { grid-template-columns: repeat(2, 1fr); } }

.metric {
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.7rem 0.85rem;
  position: relative;
}
.metric .label {
  font-family: var(--font-mono);
  font-size: 0.66rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--fg-soft);
  margin-bottom: 0.4rem;
}
.metric .value {
  font-family: var(--font-sans);
  font-weight: 500;
  font-size: 1.55rem;
  line-height: 1;
  color: var(--fg);
  font-variant-numeric: tabular-nums;
}
.metric.allow .value { color: var(--good); }
.metric.ask .value   { color: var(--warn); }
.metric.deny .value  { color: var(--bad); }
.metric .delta {
  font-family: var(--font-mono);
  font-size: 0.68rem;
  color: var(--fg-faint);
  margin-top: 0.25rem;
}

/* ─── cards / panels ──────────────────────────────────────── */
.card {
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-radius: 10px;
  margin-bottom: 1rem;
  overflow: hidden;
}
.card-head {
  padding: 0.55rem 0.9rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  border-bottom: 1px solid var(--border-soft);
  font-family: var(--font-mono);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--fg-soft);
}
.card-head .spacer { flex: 1; }
.card-body { padding: 0.9rem; }

/* ─── score histogram ─────────────────────────────────────── */
.histogram {
  display: grid;
  grid-template-columns: repeat(10, 1fr);
  gap: 0.3rem;
  align-items: end;
  height: 70px;
  padding: 0 0.2rem;
}
.bar {
  position: relative;
  background: var(--bg-elev-3);
  border-radius: 3px 3px 0 0;
  min-height: 2px;
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding-top: 0.25rem;
  cursor: default;
}
.bar.lo { background: var(--good); opacity: 0.85; }
.bar.mid { background: var(--warn); opacity: 0.85; }
.bar.hi { background: var(--bad); opacity: 0.9; }
.bar .bar-count {
  position: absolute;
  top: -1.1rem;
  font-family: var(--font-mono);
  font-size: 0.65rem;
  color: var(--fg-dim);
  font-variant-numeric: tabular-nums;
}
.bar .bar-label {
  position: absolute;
  bottom: -1.2rem;
  font-family: var(--font-mono);
  font-size: 0.6rem;
  color: var(--fg-faint);
  letter-spacing: 0.04em;
}
.histogram-wrap { padding: 0.5rem 0.9rem 1.5rem; }

/* ─── timeseries sparkline (svg) ──────────────────────────── */
.spark-wrap {
  position: relative;
  height: 95px;
}
.spark {
  width: 100%;
  height: 100%;
  display: block;
}
.spark-grid { stroke: var(--border-soft); stroke-width: 1; }
.spark-stack-allow { fill: var(--good); opacity: 0.5; }
.spark-stack-ask   { fill: var(--warn); opacity: 0.65; }
.spark-stack-deny  { fill: var(--bad);  opacity: 0.85; }
.spark-overlay {
  position: absolute;
  inset: 0;
  pointer-events: none;
  font-family: var(--font-mono);
  font-size: 0.62rem;
  color: var(--fg-soft);
  letter-spacing: 0.02em;
}
.spark-overlay > span { position: absolute; line-height: 1; }
.spark-overlay .top-left     { top: 4px;    left: 8px; }
.spark-overlay .bottom-left  { bottom: 4px; left: 8px; }
.spark-overlay .bottom-right { bottom: 4px; right: 8px; }

/* ─── filter row ──────────────────────────────────────────── */
.filters {
  display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center;
  margin-bottom: 0.75rem;
}
.chip {
  font-family: var(--font-mono);
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  padding: 0.32rem 0.75rem;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--bg-elev);
  color: var(--fg-soft);
  transition: color 0.12s ease, background 0.12s ease, border-color 0.12s ease;
}
.chip:hover { color: var(--fg); border-color: var(--border-strong); }
.chip[aria-pressed="true"] {
  background: var(--accent-tint);
  border-color: var(--accent-soft);
  color: var(--accent);
}
.chip.allow[aria-pressed="true"] { background: var(--good-tint); border-color: var(--good); color: var(--good); }
.chip.ask[aria-pressed="true"]   { background: var(--warn-tint); border-color: var(--warn); color: var(--warn); }
.chip.deny[aria-pressed="true"]  { background: var(--bad-tint);  border-color: var(--bad);  color: var(--bad); }

.search {
  flex: 1;
  min-width: 200px;
  padding: 0.42rem 0.7rem;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-elev);
  color: var(--fg);
  font-family: var(--font-mono);
  font-size: 0.78rem;
}
.search::placeholder { color: var(--fg-faint); }

/* ─── decision feed ───────────────────────────────────────── */
.feed { max-height: calc(100vh - 460px); min-height: 220px; overflow-y: auto; }
.feed::-webkit-scrollbar { width: 8px; }
.feed::-webkit-scrollbar-thumb { background: var(--bg-elev-3); border-radius: 4px; }
.feed::-webkit-scrollbar-track { background: transparent; }

.row {
  display: grid;
  grid-template-columns: 70px 60px 90px 1fr 50px;
  gap: 0.7rem;
  align-items: center;
  padding: 0.45rem 0.9rem;
  border-bottom: 1px solid var(--border-soft);
  font-family: var(--font-mono);
  font-size: 0.78rem;
  cursor: pointer;
  transition: background 0.1s ease;
}
.row:hover, .row:focus-visible { background: var(--bg-elev-2); }
.row .ts { color: var(--fg-soft); font-size: 0.7rem; font-variant-numeric: tabular-nums; }
.row .decision {
  font-weight: 600;
  font-size: 0.68rem;
  letter-spacing: 0.08em;
  display: inline-block;
  padding: 0.1rem 0.35rem;
  border-radius: 3px;
  text-align: center;
  border: 1px solid transparent;
}
.row.allow .decision { color: var(--good); border-color: rgba(155, 189, 128, 0.35); background: var(--good-tint); }
.row.ask .decision   { color: var(--warn); border-color: rgba(226, 176, 107, 0.35); background: var(--warn-tint); }
.row.deny .decision  { color: var(--bad);  border-color: rgba(210, 116, 102, 0.35); background: var(--bad-tint); }
.row .tool {
  color: var(--fg-dim);
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.row .summary {
  color: var(--fg);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.row .score {
  text-align: right; color: var(--fg-soft);
  font-variant-numeric: tabular-nums;
}
.row.allow .score { color: var(--good); }
.row.ask .score   { color: var(--warn); }
.row.deny .score  { color: var(--bad); }
.row[aria-expanded="true"] { background: var(--bg-elev-2); }
.row.flash-in {
  animation: flash-in 1.6s ease-out;
}
@keyframes flash-in {
  0%   { background: var(--accent-tint); }
  100% { background: transparent; }
}
.row.ask.flash-in   { animation-name: flash-in-ask; }
.row.deny.flash-in  { animation-name: flash-in-deny; }
@keyframes flash-in-ask {
  0%   { background: var(--warn-tint); }
  100% { background: transparent; }
}
@keyframes flash-in-deny {
  0%   { background: var(--bad-tint); }
  100% { background: transparent; }
}

/* ─── status bar toggle ─────────────────────────────────────── */
.notify-toggle {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  font-family: var(--font-mono);
  font-size: 0.7rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  padding: 0.2rem 0.55rem;
  margin-right: 0.5rem;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--bg-elev);
  color: var(--fg-soft);
  transition: color 0.12s ease, border-color 0.12s ease;
}
.notify-toggle:hover { color: var(--fg); border-color: var(--accent-soft); }
.notify-toggle[aria-pressed="true"] {
  color: var(--accent);
  border-color: var(--accent-soft);
  background: var(--accent-tint);
}
.notify-toggle::before {
  content: "";
  width: 6px; height: 6px;
  border-radius: 50%;
  background: var(--fg-faint);
}
.notify-toggle[aria-pressed="true"]::before { background: var(--accent); }

.row-detail {
  display: none;
  padding: 0.9rem 0.9rem 1.1rem 0.9rem;
  background: var(--bg-elev-2);
  border-bottom: 1px solid var(--border-soft);
  font-family: var(--font-mono);
  font-size: 0.75rem;
  color: var(--fg-dim);
}
.row[aria-expanded="true"] + .row-detail { display: block; }
.row-detail .field { margin-bottom: 0.5rem; }
.row-detail .field-label {
  color: var(--fg-soft);
  text-transform: uppercase;
  font-size: 0.62rem;
  letter-spacing: 0.1em;
  margin-bottom: 0.2rem;
}
.row-detail pre {
  margin: 0;
  padding: 0.45rem 0.65rem;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--fg);
}
.row-detail .signal {
  display: flex;
  gap: 0.6rem;
  padding: 0.22rem 0;
  border-top: 1px solid var(--border-soft);
}
.row-detail .signal:first-of-type { border-top: 0; }
.row-detail .signal-pts {
  font-variant-numeric: tabular-nums;
  min-width: 3rem;
  text-align: right;
}
.row-detail .signal-pts.pos { color: var(--bad); }
.row-detail .signal-pts.neg { color: var(--good); }
.row-detail .signal-pts.zero { color: var(--fg-soft); }
.row-detail .signal-name { color: var(--accent); min-width: 12rem; }
.row-detail .signal-reason { color: var(--fg-dim); flex: 1; }

.empty {
  padding: 2rem 1rem;
  text-align: center;
  color: var(--fg-soft);
  font-family: var(--font-mono);
  font-size: 0.8rem;
}
.empty .hint {
  margin-top: 0.5rem;
  color: var(--fg-faint);
  font-size: 0.72rem;
}

/* ─── sidebar ─────────────────────────────────────────────── */
.sidebar { display: flex; flex-direction: column; gap: 1rem; }
.sidebar .card-body { padding: 0.5rem 0.9rem 0.7rem; }

.list-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.3rem 0;
  font-family: var(--font-mono);
  font-size: 0.74rem;
  color: var(--fg-dim);
  border-bottom: 1px solid var(--border-soft);
  gap: 0.5rem;
}
.list-row:last-child { border-bottom: 0; }
.list-row .name {
  color: var(--fg);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  flex: 1; min-width: 0;
}
.list-row .count {
  font-variant-numeric: tabular-nums;
  color: var(--accent);
  min-width: 1.5rem;
  text-align: right;
}

.tuning-row {
  padding: 0.4rem 0;
  border-bottom: 1px solid var(--border-soft);
  font-family: var(--font-mono);
  font-size: 0.74rem;
}
.tuning-row:last-child { border-bottom: 0; }
.tuning-row .head {
  display: flex; justify-content: space-between; gap: 0.5rem;
  color: var(--fg);
}
.tuning-row .head .cluster {
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  flex: 1; min-width: 0;
}
.tuning-row .head .count { color: var(--warn); font-variant-numeric: tabular-nums; }
.tuning-row .example {
  margin-top: 0.2rem;
  color: var(--fg-soft);
  font-size: 0.68rem;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

.muted {
  color: var(--fg-faint);
  font-family: var(--font-mono);
  font-size: 0.72rem;
  padding: 0.3rem 0;
}

/* visually-hidden helper for sr-only text */
.sr-only {
  position: absolute; width: 1px; height: 1px;
  padding: 0; margin: -1px; overflow: hidden;
  clip: rect(0,0,0,0); white-space: nowrap; border: 0;
}
</style>
</head>
<body>

<header class="statusbar" role="banner">
  <span class="dots" aria-hidden="true">
    <span class="dot red"></span><span class="dot amber"></span><span class="dot green"></span>
  </span>
  <span class="path" id="log-path" aria-label="audit log location">~/.claude/guard/audit.jsonl</span>
  <span class="spacer"></span>
  <button class="notify-toggle" id="notify-toggle" type="button"
          aria-pressed="false" title="Browser notifications for ask / deny decisions">
    notify
  </button>
  <span class="live idle" id="live" aria-live="polite">
    <span class="live-pip" aria-hidden="true"></span>
    <span id="live-label">connecting…</span>
  </span>
  <span class="ver" aria-label="version">v4</span>
</header>

<aside class="pending-banner" id="pending-banner" role="region" aria-label="Pending decisions awaiting approval" aria-live="polite"></aside>

<main class="app" id="app">
  <section aria-labelledby="title">
    <h1 id="title">claude-guard</h1>
    <p class="subhead">Live decisions from Claude Code's PreToolUse hook. Click any row to expand the full signal breakdown.</p>

    <div class="window-bar" role="group" aria-label="Time window">
      <button data-window="1h"  aria-pressed="false">1h</button>
      <button data-window="24h" aria-pressed="true">24h</button>
      <button data-window="7d"  aria-pressed="false">7d</button>
      <button data-window="all" aria-pressed="false">all</button>
    </div>

    <div class="metrics" role="group" aria-label="Decision totals">
      <div class="metric" aria-label="Total decisions">
        <div class="label">Total</div>
        <div class="value" id="m-total">0</div>
        <div class="delta" id="m-window-label">last 24h</div>
      </div>
      <div class="metric allow" aria-label="Allow count">
        <div class="label">Allow</div>
        <div class="value" id="m-allow">0</div>
        <div class="delta" id="m-allow-pct">—</div>
      </div>
      <div class="metric ask" aria-label="Ask count">
        <div class="label">Ask</div>
        <div class="value" id="m-ask">0</div>
        <div class="delta" id="m-ask-pct">—</div>
      </div>
      <div class="metric deny" aria-label="Deny count">
        <div class="label">Deny</div>
        <div class="value" id="m-deny">0</div>
        <div class="delta" id="m-deny-pct">—</div>
      </div>
      <div class="metric" aria-label="Average score">
        <div class="label">Avg Score</div>
        <div class="value" id="m-avg">0</div>
        <div class="delta">0 = silent · 100 = denied</div>
      </div>
    </div>

    <div class="chart-row">
      <div class="card">
        <div class="card-head">
          <span>score distribution</span>
          <span class="spacer"></span>
          <span class="muted" id="hist-summary"></span>
        </div>
        <div class="card-body histogram-wrap">
          <div class="histogram" id="hist" role="img" aria-label="Score distribution histogram"></div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <span>decisions over window</span>
          <span class="spacer"></span>
          <span class="muted" id="ts-summary"></span>
        </div>
        <div class="card-body">
          <div class="spark-wrap">
            <svg class="spark" id="spark" viewBox="0 0 600 64" preserveAspectRatio="none"
                 role="img" aria-label="Decisions per time bucket"></svg>
            <div class="spark-overlay" aria-hidden="true">
              <span class="top-left"     id="spark-peak"></span>
              <span class="bottom-left"  id="spark-start"></span>
              <span class="bottom-right" id="spark-end">now</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="filters" role="group" aria-label="Filter the live feed">
      <button class="chip" data-filter="all"   aria-pressed="true">all</button>
      <button class="chip allow" data-filter="allow" aria-pressed="false">allow</button>
      <button class="chip ask"   data-filter="ask"   aria-pressed="false">ask</button>
      <button class="chip deny"  data-filter="deny"  aria-pressed="false">deny</button>
      <label class="sr-only" for="search">Search</label>
      <input class="search" id="search" type="search"
             placeholder="search command, tool, project, rule…"
             autocomplete="off" />
    </div>

    <div class="card">
      <div class="card-head">
        <span>live feed</span>
        <span class="spacer"></span>
        <span class="muted" id="feed-count">0 shown</span>
      </div>
      <div class="feed" id="feed">
        <div class="empty" id="empty">
          <div>waiting for activity…</div>
          <div class="hint">run any Bash, Edit, Write, WebFetch, WebSearch, or MCP tool in Claude Code to see it appear here.</div>
        </div>
      </div>
    </div>
  </section>

  <aside class="sidebar" aria-label="Aggregates">
    <div class="card">
      <div class="card-head"><span>top firing rules</span></div>
      <div class="card-body" id="top-rules"><div class="muted">no signals yet</div></div>
    </div>
    <div class="card">
      <div class="card-head"><span>tuning candidates</span></div>
      <div class="card-body" id="tuning">
        <div class="muted">no repeated ask-band clusters yet — the dashboard will surface command shapes that hit the ask band multiple times so you can promote them to allow or deny.</div>
      </div>
    </div>
    <div class="card" id="projects-card" hidden>
      <div class="card-head"><span>projects</span></div>
      <div class="card-body" id="projects"></div>
    </div>
  </aside>
</main>

<script>
const PENDING_POLL_MS = 1000;
const FEED_LIMIT = 200;
const RECONNECT_BACKOFF_MS = 1500;
const $ = (id) => document.getElementById(id);

// Persisted prefs (survives reloads). Default ON for ask/deny notifications
// — those are infrequent enough that pinging the user is useful, not noisy.
const PREFS = {
  notify: localStorage.getItem("cg.notify") !== "off",
};

const state = {
  window:  "24h",
  filter:  "all",
  search:  "",
  entries: [],
  stats:   null,
  open:    new Set(),     // expanded rows, keyed by ts+command
  lastOk:  0,
  pending: [],
  seenPendingIds: new Set(),
  acting: new Set(),      // pending uuids whose buttons are mid-action
  seenDecisionKeys: new Set(),  // rowKey strings we've already shown
  bootDone: false,        // first poll seeds seen-set without notifying
  lastMtime: 0,           // last-seen audit.jsonl mtime for long-poll
  longPollAbort: null,    // AbortController for the in-flight long-poll
  reconnectTimer: null,
};

const fmt = {
  ts(s) {
    try {
      const d = new Date(s);
      return d.toLocaleTimeString([], {hour:"2-digit", minute:"2-digit", second:"2-digit", hour12:false});
    } catch { return String(s); }
  },
  esc(s) {
    return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
  },
  shortCmd(s, n=110) {
    s = s || "";
    return s.length <= n ? s : s.slice(0, n - 1) + "…";
  },
  pct(n, total) {
    if (!total) return "—";
    return Math.round((n/total) * 100) + "%";
  },
  windowLabel(w) {
    return ({"1h":"last 1h","24h":"last 24h","7d":"last 7d","all":"all time"})[w] || w;
  },
};

function rowKey(e) { return (e.ts || "") + "|" + (e.tool || "") + "|" + (e.command || ""); }

// ─── rendering ─────────────────────────────────────────────────────────
function render() {
  renderStats();
  renderHistogram();
  renderSparkline();
  renderFeed();
  renderSidebar();
}

function renderStats() {
  const s = state.stats || {};
  const bd = s.by_decision || {allow:0, ask:0, deny:0};
  $("m-total").textContent = (s.total ?? 0).toLocaleString();
  $("m-window-label").textContent = fmt.windowLabel(state.window);
  $("m-allow").textContent = (bd.allow ?? 0).toLocaleString();
  $("m-ask").textContent   = (bd.ask ?? 0).toLocaleString();
  $("m-deny").textContent  = (bd.deny ?? 0).toLocaleString();
  $("m-avg").textContent   = (s.avg_score ?? 0).toFixed(1);
  $("m-allow-pct").textContent = fmt.pct(bd.allow, s.total);
  $("m-ask-pct").textContent   = fmt.pct(bd.ask,   s.total);
  $("m-deny-pct").textContent  = fmt.pct(bd.deny,  s.total);
  if (s.log_path) $("log-path").textContent = s.log_path;
}

function renderHistogram() {
  const hist = (state.stats && state.stats.histogram) || new Array(10).fill(0);
  const max  = Math.max(1, ...hist);
  const labels = ["0–9","10–19","20–29","30–39","40–49","50–59","60–69","70–79","80–89","90–100"];
  let html = "";
  for (let i = 0; i < 10; i++) {
    const h = Math.round((hist[i] / max) * 62);   // 62px of headroom in the 70px row
    const cls = i < 3 ? "lo" : (i < 6 ? "mid" : "hi");
    html += `
      <div class="bar ${cls}" style="height:${Math.max(2, h)}px"
           role="presentation"
           title="score ${labels[i]}: ${hist[i]} decisions">
        ${hist[i] > 0 ? `<span class="bar-count">${hist[i]}</span>` : ""}
        <span class="bar-label">${labels[i]}</span>
      </div>`;
  }
  $("hist").innerHTML = html;
  const total = hist.reduce((a,b)=>a+b, 0);
  $("hist-summary").textContent = `${total} scored decisions · 10 buckets`;
}

function renderSparkline() {
  const ts = (state.stats && state.stats.timeseries) || null;
  const W = 600, H = 64, padX = 6, padY = 6;
  if (!ts || !ts.buckets) {
    $("spark").innerHTML = "";
    $("spark-peak").textContent  = "no data in window";
    $("spark-start").textContent = "";
    $("spark-end").textContent   = "";
    $("ts-summary").textContent  = "";
    return;
  }
  const n = ts.buckets;
  const allow = ts.allow || new Array(n).fill(0);
  const ask   = ts.ask   || new Array(n).fill(0);
  const deny  = ts.deny  || new Array(n).fill(0);
  const stacked = allow.map((a, i) => a + ask[i] + deny[i]);
  const max = Math.max(1, ...stacked);
  const xStep = (W - padX*2) / Math.max(1, n - 1);

  const yFor = (v) => H - padY - (v / max) * (H - padY*2);

  // Build stacked-area paths: bottom -> allow top -> ask top -> deny top.
  function areaPath(values, baseline) {
    const top = values.map((v, i) => [padX + i*xStep, yFor(v + (baseline[i] || 0))]);
    const bot = baseline.map((v, i) => [padX + i*xStep, yFor(v)]).reverse();
    const all = top.concat(bot);
    return "M " + all.map(p => `${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(" L ") + " Z";
  }
  const base = new Array(n).fill(0);
  const allowPath = areaPath(allow, base);
  const baseAsk   = allow.slice();
  const askPath   = areaPath(ask, baseAsk);
  const baseDeny  = allow.map((a, i) => a + ask[i]);
  const denyPath  = areaPath(deny, baseDeny);

  $("spark").innerHTML = `
    <line class="spark-grid" x1="${padX}" y1="${H-padY}" x2="${W-padX}" y2="${H-padY}"/>
    <path class="spark-stack-allow" d="${allowPath}"></path>
    <path class="spark-stack-ask"   d="${askPath}"></path>
    <path class="spark-stack-deny"  d="${denyPath}"></path>
  `;
  $("spark-peak").textContent  = `peak ${max}/bucket`;
  $("spark-start").textContent = bucketLabel(ts.start);
  $("spark-end").textContent   = "now";
  const bucketMinutes = Math.round((ts.bucket_seconds || 0) / 60);
  $("ts-summary").textContent = `${n} buckets · ~${bucketMinutes}m each`;
}

function bucketLabel(startTs) {
  if (!startTs) return "";
  const d = new Date(startTs * 1000);
  return d.toLocaleString([], {month:"short", day:"numeric", hour:"2-digit", minute:"2-digit", hour12:false});
}

function renderFeed() {
  const feedEl = $("feed");
  const entries = state.entries || [];
  if (!entries.length) {
    // Don't reuse the boot-time #empty element; it gets wiped out the first
    // time we replace feedEl.innerHTML with rows, so subsequent lookups
    // would NPE. Always re-render the empty state from scratch.
    feedEl.innerHTML = `
      <div class="empty" id="empty">
        <div>waiting for activity…</div>
        <div class="hint">run any Bash, Edit, Write, WebFetch, WebSearch, or MCP tool in Claude Code to see it appear here.</div>
      </div>`;
    $("feed-count").textContent = "0 shown";
    return;
  }
  // Mark rows whose key is not in seenDecisionKeys yet — they'll flash in.
  // Seed runs on the first poll so we don't flash every row at boot.
  let html = "";
  for (const e of entries) {
    const dec = (e.decision || "ask").toLowerCase();
    const score = (typeof e.score === "number") ? e.score : 0;
    const key = rowKey(e);
    const open = state.open.has(key);
    const isNew = state.bootDone && !state.seenDecisionKeys.has(key);
    html += `
      <div class="row ${dec}${isNew ? " flash-in" : ""}" tabindex="0" role="button"
           aria-expanded="${open ? "true" : "false"}"
           data-key="${fmt.esc(key)}">
        <span class="ts">${fmt.esc(fmt.ts(e.ts))}</span>
        <span class="decision" aria-label="decision ${dec}">${dec.toUpperCase()}</span>
        <span class="tool">${fmt.esc(e.tool || "?")}</span>
        <span class="summary">${fmt.esc(fmt.shortCmd(e.command || ""))}</span>
        <span class="score">${score}</span>
      </div>
      <div class="row-detail">${detailHtml(e)}</div>
    `;
  }
  feedEl.innerHTML = html;
  $("feed-count").textContent = `${entries.length} shown`;

  // Wire up click + keyboard expand.
  feedEl.querySelectorAll(".row").forEach(row => {
    row.addEventListener("click", () => toggleRow(row));
    row.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        toggleRow(row);
      }
    });
  });
}

function toggleRow(row) {
  const key = row.dataset.key;
  if (state.open.has(key)) {
    state.open.delete(key);
    row.setAttribute("aria-expanded", "false");
  } else {
    state.open.add(key);
    row.setAttribute("aria-expanded", "true");
  }
}

function detailHtml(e) {
  const sigs = (e.signals || []).map(s => {
    const pts = s.points || 0;
    const cls = pts > 0 ? "pos" : (pts < 0 ? "neg" : "zero");
    const sign = pts > 0 ? "+" : "";
    return `
      <div class="signal">
        <span class="signal-pts ${cls}">${sign}${pts}</span>
        <span class="signal-name">${fmt.esc(s.name || "")}</span>
        <span class="signal-reason">${fmt.esc(s.reason || "")}</span>
      </div>`;
  }).join("");
  const paths = (e.paths || []).join("\n");
  const oos = (e.out_of_scope_paths || []).join("\n");
  const nets = (e.network_targets || []).join("\n");
  const shell = e.is_powershell ? "powershell" : "bash / posix";
  const timing = e.timing ? `parse ${e.timing.parse_ms}ms · evaluate ${e.timing.evaluate_ms}ms · llm ${e.timing.llm_ms}ms` : "";
  return `
    <div class="field"><div class="field-label">command</div><pre>${fmt.esc(e.command || "")}</pre></div>
    <div class="field"><div class="field-label">project</div><pre>${fmt.esc(e.project_dir || "")}</pre></div>
    <div class="field"><div class="field-label">shell</div><pre>${fmt.esc(shell)}</pre></div>
    ${paths ? `<div class="field"><div class="field-label">paths (${(e.paths||[]).length})</div><pre>${fmt.esc(paths)}</pre></div>` : ""}
    ${oos ? `<div class="field"><div class="field-label">out-of-scope paths</div><pre>${fmt.esc(oos)}</pre></div>` : ""}
    ${nets ? `<div class="field"><div class="field-label">network targets</div><pre>${fmt.esc(nets)}</pre></div>` : ""}
    <div class="field"><div class="field-label">signals</div>${sigs || '<div class="muted">no signals matched</div>'}</div>
    ${timing ? `<div class="field"><div class="field-label">timing</div><pre>${fmt.esc(timing)}</pre></div>` : ""}
  `;
}

function renderSidebar() {
  const s = state.stats || {};
  // Top rules
  const rules = s.top_rules || [];
  $("top-rules").innerHTML = rules.length
    ? rules.map(r => `<div class="list-row"><span class="name">${fmt.esc(r.name)}</span><span class="count">${r.count}</span></div>`).join("")
    : `<div class="muted">no signals yet</div>`;

  // Tuning candidates
  const tc = s.tuning_candidates || [];
  $("tuning").innerHTML = tc.length
    ? tc.map(t => `
        <div class="tuning-row">
          <div class="head"><span class="cluster">${fmt.esc(t.cluster)}</span><span class="count">×${t.count}</span></div>
          <div class="example">${fmt.esc(t.example || "")}</div>
        </div>`).join("")
    : `<div class="muted">no repeated ask-band clusters yet — the dashboard will surface command shapes that hit the ask band multiple times so you can promote them to allow or deny.</div>`;

  // Projects (only if >1)
  const projs = s.projects || [];
  if (projs.length > 1) {
    $("projects-card").hidden = false;
    $("projects").innerHTML = projs.map(p => {
      const short = (p.path || "").replace(/^.*[\\/]/, "");
      return `<div class="list-row"><span class="name" title="${fmt.esc(p.path)}">${fmt.esc(short || p.path)}</span><span class="count">${p.count}</span></div>`;
    }).join("");
  } else {
    $("projects-card").hidden = true;
  }
}

// ─── long-poll ────────────────────────────────────────────────────────
// The feed is push-style: a long-running GET hangs until audit.jsonl mtime
// changes server-side, then the browser fires the next request. Worst-case
// latency from hook-writes-log to dashboard-updates is the round-trip plus
// the server's 100ms mtime tick — typically <150ms.

async function loadInitial() {
  // First-paint: fetch stats + a snapshot of decisions so the page isn't
  // empty while we wait for the first long-poll response.
  try {
    const win = encodeURIComponent(state.window);
    const filt = encodeURIComponent(state.filter);
    const q = encodeURIComponent(state.search);
    const [statsRes, decsRes] = await Promise.all([
      fetch(`/api/stats?window=${win}`, {cache: "no-store"}),
      fetch(`/api/decisions?window=${win}&filter=${filt}&q=${q}&limit=${FEED_LIMIT}`, {cache: "no-store"}),
    ]);
    if (!statsRes.ok || !decsRes.ok) throw new Error("initial fetch failed");
    const [stats, decs] = await Promise.all([statsRes.json(), decsRes.json()]);
    state.stats = stats;
    state.entries = decs.entries || [];
    // Seed seenDecisionKeys so the boot doesn't fire notifications for the
    // existing backlog. notifyOnNewDecisions also handles this via bootDone.
    notifyOnNewDecisions(state.entries);
    state.lastOk = Date.now();
    setLive("live", "live");
    render();
  } catch (e) {
    setLive("stale", "reconnecting…");
  }
}

async function refreshStats() {
  try {
    const win = encodeURIComponent(state.window);
    const r = await fetch(`/api/stats?window=${win}`, {cache: "no-store"});
    if (r.ok) state.stats = await r.json();
  } catch (e) { /* leave stale stats in place */ }
}

// Cancel any in-flight long-poll. Used when filter / window / search
// changes so the next loop iteration uses the new params.
function abortLongPoll() {
  if (state.longPollAbort) {
    try { state.longPollAbort.abort(); } catch (e) {}
    state.longPollAbort = null;
  }
  if (state.reconnectTimer) {
    clearTimeout(state.reconnectTimer);
    state.reconnectTimer = null;
  }
}

async function longPoll() {
  abortLongPoll();
  state.longPollAbort = new AbortController();
  const params = new URLSearchParams({
    since: String(state.lastMtime),
    window: state.window,
    filter: state.filter,
    q: state.search,
    limit: String(FEED_LIMIT),
  });
  try {
    const r = await fetch(`/api/decisions-wait?${params.toString()}`, {
      cache: "no-store",
      signal: state.longPollAbort.signal,
    });
    if (!r.ok) throw new Error("api error " + r.status);
    const data = await r.json();
    if (typeof data.mtime === "number") {
      state.lastMtime = data.mtime;
    }
    if (!data.timeout && Array.isArray(data.entries)) {
      // Real change: update entries, fire notifications, refresh aggregates.
      state.entries = data.entries;
      notifyOnNewDecisions(state.entries);
      render();
      // Aggregates fire in the background; rendering the feed first keeps
      // perceived latency low.
      refreshStats().then(render);
    }
    state.lastOk = Date.now();
    setLive("live", "live");
    // Immediately reconnect.
    longPoll();
  } catch (e) {
    if (e && e.name === "AbortError") return;  // intentional cancel
    setLive("stale", "reconnecting…");
    state.reconnectTimer = setTimeout(longPoll, RECONNECT_BACKOFF_MS);
  }
}

// Called from input handlers when the user changes window / filter / search.
// Drops the in-flight long-poll (which was waiting with the old params),
// refreshes stats + a snapshot, then restarts the long-poll loop.
async function refilterAndRestart() {
  abortLongPoll();
  state.lastMtime = 0;  // force the next long-poll to return immediately
  await loadInitial();
  longPoll();
}

function notifyOnNewDecisions(entries) {
  const newAskDeny = [];
  for (const e of entries) {
    const key = rowKey(e);
    if (state.seenDecisionKeys.has(key)) continue;
    state.seenDecisionKeys.add(key);
    const dec = (e.decision || "").toLowerCase();
    if (state.bootDone && (dec === "ask" || dec === "deny")) {
      newAskDeny.push(e);
    }
  }
  state.bootDone = true;

  if (!PREFS.notify) return;
  if (!("Notification" in window)) return;
  if (Notification.permission !== "granted") return;
  // Cap to 3 notifications per poll so a burst doesn't spam the OS tray.
  for (const e of newAskDeny.slice(0, 3)) {
    fireDecisionNotification(e);
  }
}

function fireDecisionNotification(e) {
  const dec = (e.decision || "").toUpperCase();
  const tool = e.tool || "?";
  const cmd = (e.command || "").slice(0, 140);
  try {
    const n = new Notification(`claude-guard: ${dec}`, {
      body: `${tool} · score ${e.score ?? "?"}\n${cmd}`,
      tag: `cg-decision-${e.ts}-${tool}`,
    });
    n.onclick = () => { window.focus(); n.close(); };
  } catch (err) { /* noop */ }
}

function setLive(cls, label) {
  const el = $("live");
  el.classList.remove("live", "stale", "idle");
  el.classList.add(cls);
  $("live-label").textContent = label;
}

// ─── pending bridge ────────────────────────────────────────────────────
async function pollPending() {
  try {
    const r = await fetch("/api/pending", {cache: "no-store"});
    if (!r.ok) return;
    const data = await r.json();
    const items = data.pending || [];
    // Fire a browser notification for any new pending uuid we haven't seen.
    for (const item of items) {
      if (!state.seenPendingIds.has(item.uuid)) {
        state.seenPendingIds.add(item.uuid);
        firePendingNotification(item);
      }
    }
    state.pending = items;
    renderPending();
  } catch (e) {
    // Silent: pending polling failures should not disturb the rest of the UI.
  }
}

function renderPending() {
  const el = $("pending-banner");
  const items = state.pending || [];
  if (!items.length) {
    el.classList.remove("has-items");
    el.innerHTML = "";
    return;
  }
  el.classList.add("has-items");
  const cards = items.map(item => {
    const sigs = (item.signals || [])
      .map(s => `${s.points >= 0 ? "+" : ""}${s.points} ${s.name}`)
      .join(" · ");
    const acting = state.acting.has(item.uuid);
    const ageS = Math.round(item._age_s || 0);
    return `
      <div class="pending-card" data-uuid="${fmt.esc(item.uuid)}">
        <div class="pending-card__body">
          <div class="pending-card__head">
            <span>review needed</span>
            <span class="pending-card__age">${ageS}s ago · score ${item.score ?? "?"} · ${fmt.esc(item.tool || "?")}</span>
          </div>
          <div class="pending-card__cmd" title="${fmt.esc(item.command || "")}">${fmt.esc(fmt.shortCmd(item.command || "", 160))}</div>
          ${sigs ? `<div class="pending-card__sigs">${fmt.esc(sigs)}</div>` : ""}
        </div>
        <div class="pending-card__actions">
          <button class="pending-btn allow" data-verdict="allow" ${acting ? "disabled" : ""}>approve</button>
          <button class="pending-btn deny"  data-verdict="deny"  ${acting ? "disabled" : ""}>deny</button>
        </div>
      </div>`;
  }).join("");
  el.innerHTML = cards;
  el.querySelectorAll(".pending-btn").forEach(btn => {
    btn.addEventListener("click", () => respondPending(btn));
  });
}

async function respondPending(btn) {
  const card = btn.closest(".pending-card");
  if (!card) return;
  const uuid = card.dataset.uuid;
  const verdict = btn.dataset.verdict;
  if (!uuid || !verdict || state.acting.has(uuid)) return;
  state.acting.add(uuid);
  // Disable buttons immediately for snappy feedback.
  card.querySelectorAll(".pending-btn").forEach(b => { b.disabled = true; });
  try {
    const r = await fetch(`/api/pending/${encodeURIComponent(uuid)}/respond`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({verdict: verdict}),
    });
    if (!r.ok) throw new Error("respond failed");
    // Optimistically remove from our local list so the banner clears.
    state.pending = state.pending.filter(p => p.uuid !== uuid);
    renderPending();
  } catch (e) {
    state.acting.delete(uuid);
    renderPending();
  }
}

function firePendingNotification(item) {
  if (!("Notification" in window)) return;
  if (Notification.permission !== "granted") return;
  try {
    const body = `${item.tool || ""} · score ${item.score ?? "?"}\n${(item.command || "").slice(0, 120)}`;
    const n = new Notification("claude-guard: review needed", {
      body: body,
      tag: `cg-pending-${item.uuid}`,
      requireInteraction: false,
    });
    n.onclick = () => { window.focus(); n.close(); };
  } catch (e) {
    // Browser may throw if the page is hidden in some constrained contexts.
  }
}

function maybeRequestNotificationPermission() {
  if (!("Notification" in window)) return;
  if (Notification.permission === "default") {
    // Browsers require a user gesture in many cases; we still try once on
    // load. If it gets denied or stuck on default, notifications just won't
    // fire and the in-page banner is still the source of truth.
    try { Notification.requestPermission(); } catch (e) { /* noop */ }
  }
}

function refreshNotifyToggle() {
  const btn = $("notify-toggle");
  if (!btn) return;
  const granted = ("Notification" in window) && Notification.permission === "granted";
  const on = PREFS.notify && granted;
  btn.setAttribute("aria-pressed", on ? "true" : "false");
  if (!("Notification" in window)) {
    btn.textContent = "no notif";
    btn.title = "Browser does not support the Notification API";
    btn.disabled = true;
    return;
  }
  if (!PREFS.notify) {
    btn.textContent = "notify: off";
    btn.title = "Click to enable browser notifications for ask / deny";
  } else if (!granted) {
    btn.textContent = "notify: blocked";
    btn.title = "Browser hasn't granted permission. Click to request again.";
  } else {
    btn.textContent = "notify: on";
    btn.title = "Browser notifications enabled for ask / deny. Click to mute.";
  }
}

async function toggleNotify() {
  if (!("Notification" in window)) return;
  // Toggle the user preference.
  PREFS.notify = !PREFS.notify;
  localStorage.setItem("cg.notify", PREFS.notify ? "on" : "off");
  // If turning on and permission not granted yet, request it now (user
  // gesture, so browsers will actually show the prompt).
  if (PREFS.notify && Notification.permission !== "granted") {
    try { await Notification.requestPermission(); } catch (e) { /* noop */ }
  }
  refreshNotifyToggle();
}

// ─── input wiring ──────────────────────────────────────────────────────
document.querySelectorAll(".window-bar button").forEach(b => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".window-bar button").forEach(x => x.setAttribute("aria-pressed", "false"));
    b.setAttribute("aria-pressed", "true");
    state.window = b.dataset.window;
    refilterAndRestart();
  });
});
document.querySelectorAll(".chip[data-filter]").forEach(b => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".chip[data-filter]").forEach(x => x.setAttribute("aria-pressed", "false"));
    b.setAttribute("aria-pressed", "true");
    state.filter = b.dataset.filter;
    refilterAndRestart();
  });
});
let searchDebounce;
$("search").addEventListener("input", (e) => {
  state.search = e.target.value;
  clearTimeout(searchDebounce);
  searchDebounce = setTimeout(refilterAndRestart, 200);
});

// keyboard: "/" focuses search
document.addEventListener("keydown", (e) => {
  if (e.key === "/" && document.activeElement !== $("search")) {
    e.preventDefault();
    $("search").focus();
  }
});

// Boot: snapshot first, then start the long-poll loop. The snapshot paints
// instantly; the long-poll then hangs until audit.jsonl changes.
(async function boot() {
  await loadInitial();
  longPoll();
})();

// Pending bridge: 1s short-poll (different file system, different file per
// pending decision, no good mtime aggregate to long-poll on).
maybeRequestNotificationPermission();
refreshNotifyToggle();
pollPending();
setInterval(pollPending, PENDING_POLL_MS);

// When the tab is backgrounded then re-foregrounded, browsers may have
// suspended the long-poll. Kick it back to life on visibility return.
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" &&
      Date.now() - state.lastOk > 5000) {
    abortLongPoll();
    longPoll();
  }
});

// Notify-toggle wiring
$("notify-toggle").addEventListener("click", toggleNotify);

// Request notification permission on the first user interaction too — many
// browsers gate it on a user gesture and silently ignore the boot-time call.
document.addEventListener("click", function once() {
  maybeRequestNotificationPermission();
  refreshNotifyToggle();
  document.removeEventListener("click", once);
}, {once: true});

// Re-render the toggle if the permission state changes (some browsers
// expose this via the Permissions API).
if ("permissions" in navigator) {
  navigator.permissions.query({name: "notifications"})
    .then(p => { p.onchange = refreshNotifyToggle; })
    .catch(() => {});
}
</script>
</body>
</html>
"""


# ============================================================================
# --ensure-running: idempotent background launcher
# ============================================================================
# Wired in from Claude Code's SessionStart hook so the dashboard is always
# available without the user typing anything. The hook fires on every session
# start (startup, resume, /clear, /compact). Behavior:
#   - PID file alive AND port is accepting connections -> exit silently.
#   - Port bound by something else (not our PID) -> exit silently (don't
#     fight whatever owns the port).
#   - Nothing running -> spawn the foreground server as a detached child
#     process and exit. The child opens the browser on first launch.
#
# The child is the same dashboard.py invoked with --port/--log (and *without*
# --no-browser, so the user sees the dashboard pop the first time after a
# reboot / restart).

def _pid_file_for(log_path: Path) -> Path:
    return log_path.parent / "dashboard.pid"


def _read_pid(pid_file: Path) -> int | None:
    try:
        return int(pid_file.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _pid_alive(pid: int) -> bool:
    """Cross-platform liveness check.

    Windows: OpenProcess + GetExitCodeProcess via ctypes (stdlib).
    POSIX:   os.kill(pid, 0).
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid,
            )
            if not handle:
                return False
            try:
                exit_code = ctypes.c_ulong()
                ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
                if not ok:
                    return False
                STILL_ACTIVE = 259
                return exit_code.value == STILL_ACTIVE
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # process exists but we can't signal it; still alive
    except OSError:
        return False


def _port_listening(port: int) -> bool:
    """True if a TCP server is accepting connections on 127.0.0.1:port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def _spawn_detached(args: list[str]) -> subprocess.Popen | None:
    """Launch a detached background process. Stdio is fully suppressed."""
    kwargs = dict(
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        close_fds=True,
    )
    if os.name == "nt":
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        kwargs["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    try:
        return subprocess.Popen(args, **kwargs)
    except OSError:
        return None


def stop_running(log_path: Path) -> tuple[str, str]:
    """Idempotently stop a running dashboard. Returns (status, message).

    status is one of:
      not-running, stopped, kill-failed.
    """
    pid_file = _pid_file_for(log_path)
    pid = _read_pid(pid_file)
    if pid is None or not _pid_alive(pid):
        if pid_file.exists():
            try:
                pid_file.unlink()
            except OSError:
                pass
        return "not-running", "dashboard not running"

    # Graceful first: SIGTERM / taskkill.
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            import signal
            os.kill(pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass

    # Wait up to 3s for it to exit.
    for _ in range(30):
        if not _pid_alive(pid):
            break
        time.sleep(0.1)

    # Escalate if still alive.
    if _pid_alive(pid):
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=5,
                )
            except (OSError, subprocess.SubprocessError):
                pass
        else:
            try:
                import signal
                os.kill(pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
        for _ in range(20):
            if not _pid_alive(pid):
                break
            time.sleep(0.1)

    if _pid_alive(pid):
        return "kill-failed", f"could not stop dashboard (pid {pid})"

    try:
        pid_file.unlink()
    except OSError:
        pass
    return "stopped", f"stopped dashboard (pid {pid})"


def ensure_running(port: int, log_path: Path) -> tuple[str, str]:
    """Idempotently start the dashboard. Returns (status, message).

    status is one of:
      already-running, started, port-taken, failed.
    """
    pid_file = _pid_file_for(log_path)
    url = f"http://127.0.0.1:{port}"

    existing = _read_pid(pid_file)
    if existing and _pid_alive(existing) and _port_listening(port):
        return "already-running", f"dashboard already running (pid {existing}) at {url}"

    if _port_listening(port):
        # Something else owns the port. Don't fight it.
        return "port-taken", f"port {port} is in use by another process; dashboard not started"

    # Clean up stale PID file.
    if pid_file.exists():
        try:
            pid_file.unlink()
        except OSError:
            pass

    here = Path(__file__).resolve()
    cmd = [
        sys.executable, str(here),
        "--port", str(port),
        "--log", str(log_path),
    ]
    proc = _spawn_detached(cmd)
    if proc is None:
        return "failed", "could not spawn dashboard subprocess"

    # Wait up to 3s for the child to bind.
    for _ in range(30):
        if _port_listening(port):
            try:
                pid_file.write_text(str(proc.pid), encoding="utf-8")
            except OSError:
                pass
            return "started", f"dashboard started (pid {proc.pid}) at {url}"
        if proc.poll() is not None:
            return "failed", f"dashboard exited immediately (code {proc.returncode})"
        time.sleep(0.1)
    return "failed", "dashboard did not bind within 3 seconds"


# ============================================================================
# Entry point
# ============================================================================

def main() -> int:
    ap = argparse.ArgumentParser(description="claude-guard live dashboard")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help=f"port to bind on 127.0.0.1 (default {DEFAULT_PORT})")
    ap.add_argument("--log", type=str, default=None,
                    help="path to audit.jsonl (default: next to this script)")
    ap.add_argument("--no-browser", action="store_true",
                    help="do not auto-open the browser")
    ap.add_argument("--ensure-running", action="store_true",
                    help=(
                        "idempotent background launcher: if no dashboard is "
                        "running on this port, spawn one as a detached process "
                        "and exit immediately. Wired in from Claude Code's "
                        "SessionStart hook so the dashboard is always available."
                    ))
    ap.add_argument("--stop", action="store_true",
                    help=(
                        "stop a running dashboard. Sends a graceful terminate "
                        "first, escalates to a forced kill if still alive. "
                        "Idempotent — second call says 'dashboard not running'."
                    ))
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    log_path = (
        Path(args.log).expanduser().resolve()
        if args.log else here / "audit.jsonl"
    )

    if args.stop:
        status, msg = stop_running(log_path)
        print(msg)
        return 0

    if args.ensure_running:
        status, msg = ensure_running(args.port, log_path)
        # Print one line so it's discoverable when invoked manually. Claude
        # Code's SessionStart hook does not show stdout to the user, so this
        # is harmless inside the hook and useful when run from the terminal.
        print(msg)
        return 0

    if not log_path.exists():
        print(
            f"note: {log_path} does not exist yet. The dashboard will show an "
            "empty state and start populating the first time claude-guard "
            "logs a decision."
        )

    DashboardHandler.log_path = log_path
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DashboardHandler)
    url = f"http://127.0.0.1:{args.port}"

    print(f"claude-guard dashboard -> {url}")
    print(f"watching {log_path}")
    print("Press Ctrl-C to stop.")

    if not args.no_browser:
        def _open() -> None:
            time.sleep(0.4)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping…")
    finally:
        server.server_close()
        # Best-effort PID file cleanup so the next ensure-running starts fresh.
        try:
            pf = _pid_file_for(log_path)
            existing = _read_pid(pf)
            if existing == os.getpid():
                pf.unlink()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
