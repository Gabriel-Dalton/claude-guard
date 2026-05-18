"""
claude-guard anomaly detection (V2.4).

Tracks per-install behavioural baselines and flags first-time observations:
new interpreters, new domains, new write destinations, and off-hours activity.

Public API:
    score(ctx, baseline) -> (delta, signals)
    update(ctx, baseline) -> None
    load(project_dir) -> baseline dict
    save(project_dir, baseline) -> None

Baseline is stored alongside claude-guard.py as baseline.json. The project_dir
argument is accepted for forward compatibility (per-project baselines later)
but is currently unused for path anchoring.

Scoring is suppressed during warmup (command_count < 50) so that the first
batch of legitimate commands does not produce a wall of false positives while
the baseline is being seeded.

Standard library only. Python 3.9+.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, List, Dict, Any


# Caller decides when to call update(); we just expose a constant for clarity.
WARMUP_THRESHOLD = 50

# Cap on total anomaly points emitted per command.
SCORE_CAP = 15

# Schema version. If a baseline.json on disk reports a different version we
# treat it as incompatible and start fresh rather than risk schema confusion.
SCHEMA_VERSION = 1

# Write-verb heuristic mirrors rules._writes_outside_project. Kept here as a
# local copy on purpose: importing from rules.py would pull in the full rule
# pipeline (and its module-level side effects) just to read one regex.
_WRITE_VERB_RE = re.compile(
    r"\b(?:rm|mv|cp|Remove-Item|Move-Item|Copy-Item|"
    r"Set-Content|Add-Content|Out-File|New-Item|tee|touch)\b|"
    r">>?\s*[^&|<\s]",
    re.I,
)


# ----------------------------------------------------------------------------
# Path helpers
# ----------------------------------------------------------------------------

def _baseline_path() -> Path:
    """Anchor baseline.json next to this module (alongside claude-guard.py)."""
    return Path(__file__).resolve().parent / "baseline.json"


def _norm_dir(p: Any) -> str:
    """Normalise a path's parent directory to a forward-slash string.

    Returns an empty string when there is no meaningful parent (which the
    caller should skip).
    """
    try:
        parent = Path(str(p)).parent
    except (TypeError, ValueError):
        return ""
    s = str(parent).replace("\\", "/").rstrip("/")
    if s in ("", "."):
        return ""
    return s


def _norm_host(target: str) -> str:
    """Strip port and path suffix from a network target, return bare host."""
    if not target:
        return ""
    # Split on '/' first to drop any path; then split on ':' to drop port.
    host = target.split("/", 1)[0]
    host = host.split(":", 1)[0]
    return host.lower().strip()


def _command_writes(command: str) -> bool:
    return bool(_WRITE_VERB_RE.search(command or ""))


# ----------------------------------------------------------------------------
# Fresh baseline
# ----------------------------------------------------------------------------

def _fresh() -> Dict[str, Any]:
    return {
        "version": SCHEMA_VERSION,
        "command_count": 0,
        "interpreters": {},
        "write_dirs": {},
        "domains": {},
        "hour_histogram": [0] * 24,
    }


def _coerce(raw: Any) -> Dict[str, Any]:
    """Fill missing keys and validate shapes on a freshly loaded dict.

    Anything that does not look right is replaced with a default. We do not
    raise; the goal is for a corrupted baseline to silently reset rather than
    take down the hook.
    """
    if not isinstance(raw, dict):
        return _fresh()
    if raw.get("version") != SCHEMA_VERSION:
        return _fresh()

    base = _fresh()
    out: Dict[str, Any] = {"version": SCHEMA_VERSION}

    cc = raw.get("command_count", 0)
    out["command_count"] = cc if isinstance(cc, int) and cc >= 0 else 0

    for key in ("interpreters", "write_dirs", "domains"):
        v = raw.get(key)
        if isinstance(v, dict):
            # Filter to {str: int} pairs defensively.
            out[key] = {
                str(k): int(val)
                for k, val in v.items()
                if isinstance(val, (int, float)) and val >= 0
            }
        else:
            out[key] = dict(base[key])

    hh = raw.get("hour_histogram")
    if (
        isinstance(hh, list)
        and len(hh) == 24
        and all(isinstance(x, int) and x >= 0 for x in hh)
    ):
        out["hour_histogram"] = list(hh)
    else:
        out["hour_histogram"] = [0] * 24

    return out


# ----------------------------------------------------------------------------
# Public API: load / save
# ----------------------------------------------------------------------------

def load(project_dir: Path) -> Dict[str, Any]:
    """Read baseline.json from this module's directory. Defensive on errors."""
    path = _baseline_path()
    if not path.exists():
        return _fresh()
    try:
        with path.open("r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return _fresh()
    return _coerce(raw)


def save(project_dir: Path, baseline: Dict[str, Any]) -> None:
    """Atomic write via temp file + os.replace."""
    target = _baseline_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(baseline, indent=2)

    # NamedTemporaryFile in the same directory guarantees os.replace is atomic
    # on both POSIX and Windows (same volume).
    fd, tmp_path = tempfile.mkstemp(
        prefix="baseline.",
        suffix=".tmp",
        dir=str(target.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
        os.replace(tmp_path, target)
    except Exception:
        # Best-effort cleanup of the temp file; never raise from save().
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        raise


# ----------------------------------------------------------------------------
# Public API: score
# ----------------------------------------------------------------------------

def score(ctx, baseline: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
    """Return (delta, signals).

    During warmup (command_count < 50) returns (0, []) so the baseline can
    fill up without producing noisy first-sighting alerts.

    Each anomaly type fires at most once per command. Total delta is capped
    at SCORE_CAP (+15).
    """
    if not isinstance(baseline, dict):
        return 0, []
    if baseline.get("command_count", 0) < WARMUP_THRESHOLD:
        return 0, []

    interpreters_seen = baseline.get("interpreters", {}) or {}
    domains_seen = baseline.get("domains", {}) or {}
    write_dirs_seen = baseline.get("write_dirs", {}) or {}
    hour_hist = baseline.get("hour_histogram", [0] * 24)
    if not (isinstance(hour_hist, list) and len(hour_hist) == 24):
        hour_hist = [0] * 24

    signals: List[Dict[str, Any]] = []
    total = 0

    # --- New interpreter ----------------------------------------------------
    ctx_interpreters = getattr(ctx, "interpreters", None) or []
    novel_interp = next(
        (i for i in ctx_interpreters if i and i not in interpreters_seen),
        None,
    )
    if novel_interp is not None:
        signals.append({
            "name": "anomaly_new_interpreter",
            "points": 10,
            "reason": f"First time this install has seen interpreter '{novel_interp}'",
        })
        total += 10

    # --- New domain ---------------------------------------------------------
    # Imported lazily so that anomaly.py stays importable in isolation (e.g.
    # for testing) and so we never crash if rules.py is malformed.
    trusted_domains = set()
    try:
        from rules import DOMAINS  # type: ignore
        trusted_domains = set(DOMAINS.get("trusted", set()))
    except Exception:
        trusted_domains = set()

    ctx_targets = getattr(ctx, "network_targets", None) or []
    novel_domain = None
    for target in ctx_targets:
        host = _norm_host(target)
        if not host:
            continue
        if host in trusted_domains:
            continue
        if host not in domains_seen:
            novel_domain = host
            break
    if novel_domain is not None:
        signals.append({
            "name": "anomaly_new_domain",
            "points": 6,
            "reason": f"First time this install has contacted '{novel_domain}'",
        })
        total += 6

    # --- New write directory ------------------------------------------------
    command = getattr(ctx, "command", "") or ""
    if _command_writes(command):
        ctx_paths = getattr(ctx, "paths", None) or []
        novel_dir = None
        for p in ctx_paths:
            d = _norm_dir(p)
            if not d:
                continue
            if d not in write_dirs_seen:
                novel_dir = d
                break
        if novel_dir is not None:
            signals.append({
                "name": "anomaly_new_write_dir",
                "points": 4,
                "reason": f"First write to directory '{novel_dir}'",
            })
            total += 4

    # --- Off-hours ----------------------------------------------------------
    hour = datetime.now(timezone.utc).hour
    if hour_hist[hour] == 0:
        signals.append({
            "name": "anomaly_off_hours",
            "points": 3,
            "reason": f"No prior activity observed at UTC hour {hour:02d}",
        })
        total += 3

    if total > SCORE_CAP:
        total = SCORE_CAP

    return total, signals


# ----------------------------------------------------------------------------
# Public API: update
# ----------------------------------------------------------------------------

def update(ctx, baseline: Dict[str, Any]) -> None:
    """Mutate baseline in place to reflect this command.

    Only the caller knows whether the command was actually allowed, so this
    function blindly records whatever it is given. The hook is responsible
    for gating this on a final allow decision.
    """
    if not isinstance(baseline, dict):
        return

    # Ensure required keys exist (a caller might hand us a partial dict).
    baseline.setdefault("version", SCHEMA_VERSION)
    baseline.setdefault("command_count", 0)
    baseline.setdefault("interpreters", {})
    baseline.setdefault("write_dirs", {})
    baseline.setdefault("domains", {})
    hh = baseline.get("hour_histogram")
    if not (isinstance(hh, list) and len(hh) == 24):
        baseline["hour_histogram"] = [0] * 24

    baseline["command_count"] = int(baseline["command_count"]) + 1

    # Distinct interpreters.
    interp_seen_this_cmd = set()
    for name in (getattr(ctx, "interpreters", None) or []):
        if not name or name in interp_seen_this_cmd:
            continue
        interp_seen_this_cmd.add(name)
        baseline["interpreters"][name] = baseline["interpreters"].get(name, 0) + 1

    # Distinct hosts.
    host_seen_this_cmd = set()
    for target in (getattr(ctx, "network_targets", None) or []):
        host = _norm_host(target)
        if not host or host in host_seen_this_cmd:
            continue
        host_seen_this_cmd.add(host)
        baseline["domains"][host] = baseline["domains"].get(host, 0) + 1

    # Write directories: only if the command actually writes.
    command = getattr(ctx, "command", "") or ""
    if _command_writes(command):
        dir_seen_this_cmd = set()
        for p in (getattr(ctx, "paths", None) or []):
            d = _norm_dir(p)
            if not d or d in dir_seen_this_cmd:
                continue
            dir_seen_this_cmd.add(d)
            baseline["write_dirs"][d] = baseline["write_dirs"].get(d, 0) + 1

    # Hour histogram.
    hour = datetime.now(timezone.utc).hour
    baseline["hour_histogram"][hour] = baseline["hour_histogram"][hour] + 1
