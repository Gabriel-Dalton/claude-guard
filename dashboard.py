#!/usr/bin/env python3
"""
claude-guard dashboard.

A single-file local web dashboard for the audit log. Streams new decisions
live via Server-Sent Events. Zero external dependencies (stdlib only).

Usage:
    python dashboard.py
    python dashboard.py --port 9000
    python dashboard.py --log /path/to/audit.jsonl
    python dashboard.py --no-open      # do not auto-open the browser

The default log path is the audit.jsonl next to this file.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import sys
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DEFAULT_PORT = 8787
HISTORY_LIMIT = 200
TAIL_POLL_SECS = 0.25


# ============================================================================
# State shared between the tailer thread and HTTP handlers
# ============================================================================

class Hub:
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.subscribers: list[queue.Queue] = []
        self.subscribers_lock = threading.Lock()
        self.shutdown_event = threading.Event()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=1000)
        with self.subscribers_lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.subscribers_lock:
            try:
                self.subscribers.remove(q)
            except ValueError:
                pass

    def broadcast(self, entry: dict) -> None:
        with self.subscribers_lock:
            dead = []
            for q in self.subscribers:
                try:
                    q.put_nowait(entry)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                try:
                    self.subscribers.remove(q)
                except ValueError:
                    pass

    def read_history(self, n: int) -> list[dict]:
        if not self.log_path.exists():
            return []
        # Reading the whole file is fine for a local dashboard — audit.jsonl
        # is short-lived data and typically a few MB at most.
        out: list[dict] = []
        try:
            with self.log_path.open("r", encoding="utf-8") as f:
                lines = f.readlines()
        except OSError:
            return []
        for line in lines[-n:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


def tail_thread(hub: Hub) -> None:
    """Watch the log file and broadcast new entries to subscribers.

    Handles: file not yet existing, file rotation (size shrinks), partial
    lines mid-write. Plain polling — no inotify dependency.
    """
    last_pos = 0
    if hub.log_path.exists():
        try:
            last_pos = hub.log_path.stat().st_size
        except OSError:
            last_pos = 0

    buffer = ""
    while not hub.shutdown_event.is_set():
        try:
            if not hub.log_path.exists():
                time.sleep(TAIL_POLL_SECS)
                continue
            size = hub.log_path.stat().st_size
            if size < last_pos:
                # Rotated or truncated.
                last_pos = 0
                buffer = ""
            if size > last_pos:
                with hub.log_path.open("r", encoding="utf-8", errors="replace") as f:
                    f.seek(last_pos)
                    chunk = f.read(size - last_pos)
                    last_pos = f.tell()
                buffer += chunk
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        hub.broadcast(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass
        time.sleep(TAIL_POLL_SECS)


# ============================================================================
# HTTP handler
# ============================================================================

class DashboardHandler(BaseHTTPRequestHandler):
    hub: Hub = None  # set on the class before serving

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        # Silence per-request stderr noise. Errors still surface elsewhere.
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/" or self.path.startswith("/?"):
            self._serve_html()
        elif self.path == "/history":
            self._serve_history()
        elif self.path == "/events":
            self._serve_sse()
        elif self.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def _serve_html(self) -> None:
        body = INDEX_HTML.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _serve_history(self) -> None:
        entries = self.hub.read_history(HISTORY_LIMIT)
        body = json.dumps({
            "entries": entries,
            "log_path": str(self.hub.log_path),
        }).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _serve_sse(self) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        q = self.hub.subscribe()
        try:
            # Initial ping so the browser fires onopen immediately.
            self._write_sse({"type": "hello", "ts": time.time()})
            while not self.hub.shutdown_event.is_set():
                try:
                    entry = q.get(timeout=15)
                except queue.Empty:
                    # Heartbeat keeps the connection alive through proxies.
                    try:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        return
                    continue
                if not self._write_sse(entry):
                    return
        finally:
            self.hub.unsubscribe(q)

    def _write_sse(self, payload: dict) -> bool:
        try:
            data = json.dumps(payload, default=str)
            self.wfile.write(b"data: " + data.encode("utf-8") + b"\n\n")
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError, OSError):
            return False


# ============================================================================
# Embedded frontend
# ============================================================================

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>claude-guard dashboard</title>
<meta name="color-scheme" content="dark">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400..900&family=IBM+Plex+Mono:wght@300;400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg:           #0b0c0e;
  --bg-elev:      #131418;
  --bg-elev-2:    #191b20;
  --bg-elev-3:    #20242a;
  --fg:           #e8e2d3;
  --fg-dim:       #b6b0a3;
  --fg-soft:      #8a8479;
  --fg-faint:     #5a554d;
  --accent:       #d4a05a;
  --accent-soft:  #b88847;
  --accent-tint:  rgba(212, 160, 90, 0.10);
  --good:         #8aa66f;
  --warn:         #d4a05a;
  --bad:          #b85847;
  --border:       #262a31;
  --border-soft:  #1b1e23;
  --border-strong:#3d434c;
  --font-display: 'Fraunces', Georgia, serif;
  --font-sans:    'IBM Plex Sans', system-ui, sans-serif;
  --font-mono:    'IBM Plex Mono', Menlo, Consolas, monospace;
}
*, *::before, *::after { box-sizing: border-box; }
html, body { background: var(--bg); color: var(--fg); margin: 0; min-height: 100vh; }
body {
  font-family: var(--font-sans); font-size: 14px; line-height: 1.5;
  background:
    radial-gradient(900px 500px at 20% -200px, rgba(212, 160, 90, 0.06), transparent 60%),
    radial-gradient(700px 350px at 90% 5%, rgba(138, 166, 111, 0.04), transparent 60%),
    var(--bg);
  background-attachment: fixed;
}

/* statusbar (matches landing page) */
.statusbar {
  position: sticky; top: 0; z-index: 50;
  display: flex; align-items: center; gap: 0.85rem;
  padding: 0.55rem 1.25rem;
  background: rgba(11, 12, 14, 0.85);
  backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--border-soft);
  font-family: var(--font-mono); font-size: 0.78rem; color: var(--fg-soft);
}
.statusbar .dots { display: inline-flex; gap: 0.4rem; }
.statusbar .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--fg-faint); }
.statusbar .dot.red { background: var(--bad); }
.statusbar .dot.amber { background: var(--accent); }
.statusbar .dot.green { background: var(--good); }
.statusbar .path { color: var(--fg-dim); }
.statusbar .spacer { flex: 1; }
.statusbar .ver { color: var(--accent); }
.statusbar .conn-dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--fg-faint);
  box-shadow: 0 0 0 0 transparent;
  transition: background 0.3s ease, box-shadow 0.3s ease;
}
.statusbar .conn-dot.live {
  background: var(--good);
  box-shadow: 0 0 0 3px rgba(138, 166, 111, 0.15);
}
.statusbar .conn-dot.stale { background: var(--bad); }

/* layout */
.app {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 320px;
  gap: 1.5rem;
  padding: 1.5rem;
  max-width: 1400px;
  margin: 0 auto;
}
@media (max-width: 900px) {
  .app { grid-template-columns: 1fr; }
}

h1 {
  font-family: var(--font-display);
  font-variation-settings: "opsz" 96, "wght" 500;
  font-size: 2rem;
  margin: 0 0 0.25rem;
  letter-spacing: -0.02em;
}
.subhead { color: var(--fg-dim); font-size: 0.95rem; margin: 0 0 1.5rem; }

/* metric cards */
.metrics {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 0.75rem;
  margin-bottom: 1.5rem;
}
.metric {
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.9rem 1rem;
  position: relative;
}
.metric .label {
  font-family: var(--font-mono);
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--fg-soft);
  margin-bottom: 0.4rem;
}
.metric .value {
  font-family: var(--font-display);
  font-variation-settings: "opsz" 48, "wght" 500;
  font-size: 1.75rem;
  line-height: 1;
  color: var(--fg);
}
.metric.allow .value { color: var(--good); }
.metric.ask .value { color: var(--warn); }
.metric.deny .value { color: var(--bad); }
.metric .delta {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--fg-faint);
  margin-top: 0.25rem;
}

/* filter bar */
.filters {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-bottom: 1rem;
  align-items: center;
}
.chip {
  font-family: var(--font-mono);
  font-size: 0.74rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  padding: 0.35rem 0.75rem;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--bg-elev);
  color: var(--fg-soft);
  cursor: pointer;
  transition: all 0.15s ease;
}
.chip:hover { color: var(--fg); border-color: var(--border-strong); }
.chip.active {
  background: var(--accent-tint);
  border-color: var(--accent-soft);
  color: var(--accent);
}
.search {
  flex: 1;
  min-width: 200px;
  padding: 0.45rem 0.75rem;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-elev);
  color: var(--fg);
  font-family: var(--font-mono);
  font-size: 0.82rem;
  outline: none;
}
.search:focus { border-color: var(--accent-soft); }

/* feed */
.feed-card {
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-radius: 10px;
  overflow: hidden;
}
.feed-head {
  padding: 0.65rem 1rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  border-bottom: 1px solid var(--border-soft);
  font-family: var(--font-mono);
  font-size: 0.74rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--fg-soft);
}
.feed-head .live-pip {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--good);
  animation: pulse 1.6s ease-in-out infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

.feed { max-height: 70vh; overflow-y: auto; }
.feed::-webkit-scrollbar { width: 8px; }
.feed::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 4px; }
.feed::-webkit-scrollbar-track { background: transparent; }

.row {
  display: grid;
  grid-template-columns: 80px 70px 70px 1fr 60px;
  gap: 0.75rem;
  align-items: center;
  padding: 0.55rem 1rem;
  border-bottom: 1px solid var(--border-soft);
  font-family: var(--font-mono);
  font-size: 0.82rem;
  cursor: pointer;
  transition: background 0.1s ease;
}
.row:hover { background: var(--bg-elev-2); }
.row.flash { animation: flash 1.2s ease-out; }
@keyframes flash {
  0% { background: var(--accent-tint); }
  100% { background: transparent; }
}
.row .ts { color: var(--fg-soft); font-size: 0.74rem; }
.row .decision {
  font-weight: 600;
  font-size: 0.72rem;
  letter-spacing: 0.08em;
}
.row.allow .decision { color: var(--good); }
.row.ask .decision   { color: var(--warn); }
.row.deny .decision  { color: var(--bad); }
.row .tool {
  color: var(--fg-dim);
  font-size: 0.74rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.row .summary {
  color: var(--fg);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.row .score {
  text-align: right;
  color: var(--fg-soft);
  font-variant-numeric: tabular-nums;
}
.row.allow .score { color: var(--good); }
.row.ask .score   { color: var(--warn); }
.row.deny .score  { color: var(--bad); }

.row-detail {
  display: none;
  padding: 1rem 1rem 1.25rem 1rem;
  background: var(--bg-elev-2);
  border-bottom: 1px solid var(--border-soft);
  font-family: var(--font-mono);
  font-size: 0.78rem;
  color: var(--fg-dim);
}
.row.open + .row-detail { display: block; }
.row-detail .field { margin-bottom: 0.5rem; }
.row-detail .field-label {
  color: var(--fg-soft);
  text-transform: uppercase;
  font-size: 0.68rem;
  letter-spacing: 0.1em;
  margin-bottom: 0.2rem;
}
.row-detail pre {
  margin: 0;
  padding: 0.5rem 0.75rem;
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
  padding: 0.25rem 0;
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
.row-detail .signal-name { color: var(--accent); min-width: 14rem; }
.row-detail .signal-reason { color: var(--fg-dim); flex: 1; }

.empty-state {
  padding: 3rem 1rem;
  text-align: center;
  color: var(--fg-soft);
  font-family: var(--font-mono);
  font-size: 0.85rem;
}

/* sidebar */
.sidebar { display: flex; flex-direction: column; gap: 1rem; }
.panel {
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1rem;
}
.panel h3 {
  font-family: var(--font-sans);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  font-weight: 500;
  color: var(--fg-soft);
  margin: 0 0 0.75rem;
}
.rule-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.3rem 0;
  font-family: var(--font-mono);
  font-size: 0.78rem;
  color: var(--fg-dim);
  border-bottom: 1px solid var(--border-soft);
}
.rule-row:last-child { border-bottom: 0; }
.rule-row .rule-name {
  color: var(--fg);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  margin-right: 0.5rem;
}
.rule-row .rule-count {
  font-variant-numeric: tabular-nums;
  color: var(--accent);
  min-width: 1.5rem;
  text-align: right;
}

.spark {
  width: 100%;
  height: 56px;
  display: block;
}
.spark-axis { stroke: var(--border); stroke-width: 1; }
.spark-line { fill: none; stroke: var(--accent); stroke-width: 1.5; }
.spark-area { fill: var(--accent-tint); }
.spark-label {
  font-family: var(--font-mono);
  font-size: 0.68rem;
  fill: var(--fg-soft);
}
</style>
</head>
<body>

<header class="statusbar">
  <span class="dots">
    <span class="dot red"></span><span class="dot amber"></span><span class="dot green"></span>
  </span>
  <span class="path" id="log-path">~/.claude/guard/audit.jsonl</span>
  <span class="spacer"></span>
  <span class="conn-dot" id="conn-dot"></span>
  <span id="conn-label">connecting…</span>
  <span class="ver">v3</span>
</header>

<main class="app">
  <section>
    <h1>claude-guard</h1>
    <p class="subhead">Live decisions from Claude Code's PreToolUse hook. Click any row to see the full signal breakdown.</p>

    <div class="metrics">
      <div class="metric allow">
        <div class="label">allow (last 200)</div>
        <div class="value" id="m-allow">0</div>
        <div class="delta" id="d-allow">—</div>
      </div>
      <div class="metric ask">
        <div class="label">ask</div>
        <div class="value" id="m-ask">0</div>
        <div class="delta" id="d-ask">—</div>
      </div>
      <div class="metric deny">
        <div class="label">deny</div>
        <div class="value" id="m-deny">0</div>
        <div class="delta" id="d-deny">—</div>
      </div>
      <div class="metric">
        <div class="label">per minute</div>
        <div class="value" id="m-rate">0</div>
        <div class="delta" id="d-rate">live</div>
      </div>
    </div>

    <div class="filters">
      <button class="chip active" data-filter="all">all</button>
      <button class="chip" data-filter="allow">allow</button>
      <button class="chip" data-filter="ask">ask</button>
      <button class="chip" data-filter="deny">deny</button>
      <input class="search" id="search" placeholder="filter by command, tool, rule…" />
    </div>

    <div class="feed-card">
      <div class="feed-head">
        <span class="live-pip"></span>
        <span>live feed</span>
        <span class="spacer" style="flex:1"></span>
        <span id="feed-count">0 shown</span>
      </div>
      <div class="feed" id="feed">
        <div class="empty-state" id="empty">waiting for activity… run any Bash/Edit/Write/Web/MCP tool in Claude Code to see it appear here.</div>
      </div>
    </div>
  </section>

  <aside class="sidebar">
    <div class="panel">
      <h3>decisions / min</h3>
      <svg class="spark" id="spark" viewBox="0 0 300 56" preserveAspectRatio="none"></svg>
    </div>
    <div class="panel">
      <h3>top firing rules</h3>
      <div id="top-rules"><div class="rule-row" style="color: var(--fg-faint)">no signals yet</div></div>
    </div>
    <div class="panel">
      <h3>top tools</h3>
      <div id="top-tools"><div class="rule-row" style="color: var(--fg-faint)">no tools yet</div></div>
    </div>
  </aside>
</main>

<script>
const state = {
  entries: [],          // newest-first
  filter: "all",
  search: "",
};
const MAX_ENTRIES = 500;

const $ = (id) => document.getElementById(id);
const feedEl = $("feed");
const emptyEl = $("empty");

function fmtTs(ts) {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  } catch { return String(ts); }
}

function shortSummary(e) {
  const cmd = e.command || "";
  if (cmd.length <= 90) return cmd;
  return cmd.slice(0, 87) + "…";
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
}

function rowHtml(e, idx) {
  const decision = (e.decision || "ask").toLowerCase();
  const score = (typeof e.score === "number") ? e.score : 0;
  const tool = e.tool || "?";
  return `
    <div class="row ${decision}" data-idx="${idx}">
      <span class="ts">${escapeHtml(fmtTs(e.ts))}</span>
      <span class="decision">${escapeHtml(decision.toUpperCase())}</span>
      <span class="tool">${escapeHtml(tool)}</span>
      <span class="summary">${escapeHtml(shortSummary(e))}</span>
      <span class="score">${score}</span>
    </div>
    <div class="row-detail" data-idx="${idx}">${detailHtml(e)}</div>
  `;
}

function detailHtml(e) {
  const sigs = (e.signals || []).map(s => {
    const pts = s.points || 0;
    const cls = pts > 0 ? "pos" : (pts < 0 ? "neg" : "zero");
    const sign = pts > 0 ? "+" : "";
    return `
      <div class="signal">
        <span class="signal-pts ${cls}">${sign}${pts}</span>
        <span class="signal-name">${escapeHtml(s.name || "")}</span>
        <span class="signal-reason">${escapeHtml(s.reason || "")}</span>
      </div>`;
  }).join("");
  const paths = (e.paths && e.paths.length) ? e.paths.join("\n") : "";
  const oos = (e.out_of_scope_paths && e.out_of_scope_paths.length) ? e.out_of_scope_paths.join("\n") : "";
  const nets = (e.network_targets && e.network_targets.length) ? e.network_targets.join("\n") : "";
  const timing = e.timing ? `parse ${e.timing.parse_ms}ms · evaluate ${e.timing.evaluate_ms}ms · llm ${e.timing.llm_ms}ms` : "";
  return `
    <div class="field"><div class="field-label">command</div><pre>${escapeHtml(e.command || "")}</pre></div>
    <div class="field"><div class="field-label">project dir</div><pre>${escapeHtml(e.project_dir || "")}</pre></div>
    ${paths ? `<div class="field"><div class="field-label">paths</div><pre>${escapeHtml(paths)}</pre></div>` : ""}
    ${oos ? `<div class="field"><div class="field-label">out-of-scope paths</div><pre>${escapeHtml(oos)}</pre></div>` : ""}
    ${nets ? `<div class="field"><div class="field-label">network targets</div><pre>${escapeHtml(nets)}</pre></div>` : ""}
    <div class="field"><div class="field-label">signals</div>${sigs || '<div style="color: var(--fg-faint)">no signals matched</div>'}</div>
    ${timing ? `<div class="field"><div class="field-label">timing</div><pre>${escapeHtml(timing)}</pre></div>` : ""}
  `;
}

function visible(e) {
  if (state.filter !== "all" && (e.decision || "").toLowerCase() !== state.filter) return false;
  if (state.search) {
    const q = state.search.toLowerCase();
    const hay = `${e.command || ""} ${e.tool || ""} ${(e.signals || []).map(s => s.name || "").join(" ")}`.toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

function render() {
  const visibleEntries = state.entries.map((e, i) => ({ e, i })).filter(x => visible(x.e));
  if (state.entries.length === 0) {
    emptyEl.style.display = "block";
    emptyEl.textContent = "waiting for activity… run any Bash/Edit/Write/Web/MCP tool in Claude Code to see it appear here.";
    feedEl.innerHTML = "";
    feedEl.appendChild(emptyEl);
  } else if (visibleEntries.length === 0) {
    feedEl.innerHTML = `<div class="empty-state">no entries match the current filter.</div>`;
  } else {
    feedEl.innerHTML = visibleEntries.map(x => rowHtml(x.e, x.i)).join("");
  }
  $("feed-count").textContent = `${visibleEntries.length} shown · ${state.entries.length} total`;

  // wire up click-to-expand
  feedEl.querySelectorAll(".row").forEach(row => {
    row.addEventListener("click", () => row.classList.toggle("open"));
  });

  updateMetrics();
  updateSidebar();
}

function updateMetrics() {
  let a = 0, k = 0, d = 0;
  for (const e of state.entries) {
    const dec = (e.decision || "").toLowerCase();
    if (dec === "allow") a++;
    else if (dec === "ask") k++;
    else if (dec === "deny") d++;
  }
  $("m-allow").textContent = a;
  $("m-ask").textContent = k;
  $("m-deny").textContent = d;

  // per-minute rate over the last 5 minutes
  const cutoff = Date.now() - 5 * 60 * 1000;
  const recent = state.entries.filter(e => {
    const t = Date.parse(e.ts);
    return !isNaN(t) && t >= cutoff;
  });
  const rate = recent.length / 5;
  $("m-rate").textContent = rate.toFixed(1);
}

function updateSidebar() {
  // top firing rules
  const ruleCount = {};
  for (const e of state.entries) {
    for (const s of (e.signals || [])) {
      ruleCount[s.name] = (ruleCount[s.name] || 0) + 1;
    }
  }
  const ruleRows = Object.entries(ruleCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, n]) => `<div class="rule-row"><span class="rule-name">${escapeHtml(name)}</span><span class="rule-count">${n}</span></div>`)
    .join("");
  $("top-rules").innerHTML = ruleRows || `<div class="rule-row" style="color: var(--fg-faint)">no signals yet</div>`;

  // top tools
  const toolCount = {};
  for (const e of state.entries) {
    const t = e.tool || "?";
    toolCount[t] = (toolCount[t] || 0) + 1;
  }
  const toolRows = Object.entries(toolCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([t, n]) => `<div class="rule-row"><span class="rule-name">${escapeHtml(t)}</span><span class="rule-count">${n}</span></div>`)
    .join("");
  $("top-tools").innerHTML = toolRows || `<div class="rule-row" style="color: var(--fg-faint)">no tools yet</div>`;

  // sparkline: decisions per minute over last 30 minutes (30 buckets)
  drawSparkline();
}

function drawSparkline() {
  const buckets = 30;
  const now = Date.now();
  const data = new Array(buckets).fill(0);
  for (const e of state.entries) {
    const t = Date.parse(e.ts);
    if (isNaN(t)) continue;
    const ageMin = Math.floor((now - t) / 60000);
    if (ageMin >= 0 && ageMin < buckets) {
      data[buckets - 1 - ageMin]++;
    }
  }
  const W = 300, H = 56, pad = 4;
  const max = Math.max(1, ...data);
  const xStep = (W - pad * 2) / (buckets - 1);
  const points = data.map((v, i) => {
    const x = pad + i * xStep;
    const y = H - pad - (v / max) * (H - pad * 2);
    return [x, y];
  });
  const linePath = "M " + points.map(p => `${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(" L ");
  const areaPath = linePath + ` L ${(W - pad).toFixed(1)} ${(H - pad).toFixed(1)} L ${pad.toFixed(1)} ${(H - pad).toFixed(1)} Z`;
  $("spark").innerHTML = `
    <path class="spark-area" d="${areaPath}"></path>
    <path class="spark-line" d="${linePath}"></path>
    <text class="spark-label" x="${pad}" y="${H - 2}" text-anchor="start">30m ago</text>
    <text class="spark-label" x="${W - pad}" y="${H - 2}" text-anchor="end">now</text>
    <text class="spark-label" x="${pad}" y="10">peak ${max}/min</text>
  `;
}

function pushEntry(e, fromHistory) {
  state.entries.unshift(e);
  if (state.entries.length > MAX_ENTRIES) state.entries.pop();
  if (!fromHistory) {
    render();
    // Flash the new row briefly.
    const row = feedEl.querySelector('.row[data-idx="0"]');
    if (row) {
      row.classList.add("flash");
      setTimeout(() => row.classList.remove("flash"), 1200);
    }
  }
}

// initial load
fetch("/history")
  .then(r => r.json())
  .then(data => {
    if (data.log_path) $("log-path").textContent = data.log_path;
    // /history returns oldest-first; we keep newest-first internally.
    const entries = (data.entries || []).slice().reverse();
    state.entries = entries.slice(0, MAX_ENTRIES);
    render();
  })
  .catch(() => render());

// SSE
let es;
function connect() {
  es = new EventSource("/events");
  es.onopen = () => {
    $("conn-dot").classList.add("live");
    $("conn-dot").classList.remove("stale");
    $("conn-label").textContent = "live";
  };
  es.onerror = () => {
    $("conn-dot").classList.remove("live");
    $("conn-dot").classList.add("stale");
    $("conn-label").textContent = "reconnecting…";
    es.close();
    setTimeout(connect, 1500);
  };
  es.onmessage = (ev) => {
    try {
      const payload = JSON.parse(ev.data);
      if (payload.type === "hello") return;
      pushEntry(payload, false);
    } catch (e) { /* ignore */ }
  };
}
connect();

// filter chips
document.querySelectorAll(".chip").forEach(chip => {
  chip.addEventListener("click", () => {
    document.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
    chip.classList.add("active");
    state.filter = chip.dataset.filter;
    render();
  });
});
$("search").addEventListener("input", (e) => {
  state.search = e.target.value;
  render();
});

// periodic re-render so the sparkline scrolls with time
setInterval(() => { if (state.entries.length) { updateMetrics(); drawSparkline(); } }, 30000);
</script>
</body>
</html>
"""


# ============================================================================
# Entry point
# ============================================================================

def main() -> int:
    ap = argparse.ArgumentParser(description="claude-guard live dashboard")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help=f"port to bind (default {DEFAULT_PORT})")
    ap.add_argument("--log", type=str, default=None,
                    help="path to audit.jsonl (default: next to this script)")
    ap.add_argument("--no-open", action="store_true",
                    help="do not auto-open the browser")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    log_path = Path(args.log).expanduser().resolve() if args.log else here / "audit.jsonl"

    if not log_path.exists():
        print(f"note: {log_path} does not exist yet — it will be created the first "
              f"time claude-guard logs a decision.")

    hub = Hub(log_path)
    DashboardHandler.hub = hub

    tailer = threading.Thread(target=tail_thread, args=(hub,), daemon=True)
    tailer.start()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), DashboardHandler)
    url = f"http://127.0.0.1:{args.port}"
    print(f"claude-guard dashboard -> {url}")
    print(f"watching {log_path}")
    print("Press Ctrl-C to stop.")

    if not args.no_open:
        def _open():
            time.sleep(0.4)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down…")
    finally:
        hub.shutdown_event.set()
        server.server_close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
