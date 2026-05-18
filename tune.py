#!/usr/bin/env python3
"""
tune.py: feedback and tuning CLI for claude-guard.

Two subcommands:

    python tune.py review [--days N] [--no-color]
    python tune.py stats  [--days N] [--no-color]

review
    Walks the audit log for the last N days, clusters "ask"-band commands
    by structural shape, and offers to write tight allowlist regexes into
    rules_user.py. The rules.py merge mechanism then picks those up on the
    next hook invocation.

stats
    Prints a brief health snapshot for the same window: decision mix,
    most-fired rules, top ask-band commands, and parse/evaluate/llm
    latency percentiles.

Stdlib-only. Python 3.9+.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional


HERE = Path(__file__).resolve().parent
AUDIT_PATH = HERE / "audit.jsonl"
RULES_USER_PATH = HERE / "rules_user.py"

RULES_USER_TEMPLATE = (
    "# claude-guard user-tuned rules, written by tune.py. Hand-edit if you must,\n"
    "# but tune.py is the intended workflow.\n"
    "\n"
    "ALLOWLIST = [\n"
    "]\n"
)


# ============================================================================
# Color helpers
# ============================================================================

class Style:
    """ANSI styling that can be disabled at construction time."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def header(self, text: str) -> str:
        return self._wrap("1;36", text)

    def warn(self, text: str) -> str:
        return self._wrap("33", text)

    def ok(self, text: str) -> str:
        return self._wrap("32", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)


def make_style(no_color_flag: bool) -> Style:
    if no_color_flag:
        return Style(enabled=False)
    if not sys.stdout.isatty():
        return Style(enabled=False)
    return Style(enabled=True)


# ============================================================================
# Audit log loading
# ============================================================================

def parse_ts(ts: str) -> Optional[datetime]:
    """Tolerant ISO8601 parser. Accepts trailing Z."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def iter_audit_entries(path: Path, days: int, style: Style) -> Iterator[dict]:
    """
    Stream entries from audit.jsonl filtered to the last `days` days.

    Malformed lines are counted and reported as a single summary warning.
    """
    if not path.exists():
        print(style.warn(f"no audit log at {path}"))
        print("nothing to do yet. run Claude Code with claude-guard wired up first.")
        return

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    malformed = 0
    seen = 0

    try:
        f = path.open("r", encoding="utf-8")
    except OSError as e:
        print(style.warn(f"could not open {path}: {e}"))
        return

    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            ts = parse_ts(entry.get("ts", ""))
            if ts is None:
                malformed += 1
                continue
            # Compare in UTC; tolerate naive timestamps by assuming UTC.
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts < cutoff:
                continue
            seen += 1
            yield entry

    if malformed:
        print(style.warn(f"skipped {malformed} malformed line(s) in {path.name}"))


# ============================================================================
# Clustering for review mode
# ============================================================================

_HEX_RE = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)
_DIGIT_RE = re.compile(r"^\d+$")


def normalize_token(tok: str) -> str:
    """Normalize a single command token for structural clustering."""
    if not tok:
        return tok
    if _DIGIT_RE.match(tok):
        return "<N>"
    if _HEX_RE.match(tok):
        return "<HASH>"
    if "/" in tok or "\\" in tok:
        return "<PATH>"
    return tok


def tokenize(command: str) -> list:
    return command.split()


def cluster_key(command: str) -> str:
    toks = tokenize(command)
    if not toks:
        return ""
    normed = [normalize_token(t) for t in toks[:2]]
    return " ".join(normed)


def build_suggested_regex(commands: list) -> str:
    """
    Given a list of similar command strings, build a tight allowlist regex.

    Strategy: tokenize each command, normalize each token, then take the
    longest common prefix of normalized tokens across all commands. Escape
    literal tokens; map placeholders to regex.
    """
    token_lists = [tokenize(c) for c in commands if c.strip()]
    if not token_lists:
        return ""

    normed_lists = [[normalize_token(t) for t in toks] for toks in token_lists]

    # Longest common prefix across normalized token lists.
    prefix_len = min(len(nl) for nl in normed_lists)
    common: list = []
    for i in range(prefix_len):
        col = {nl[i] for nl in normed_lists}
        if len(col) == 1:
            common.append(next(iter(col)))
        else:
            break

    if not common:
        # Fall back to first normalized token of the first command.
        common = normed_lists[0][:1]

    parts = ["^\\s*"]
    placeholder_map = {
        "<N>": r"\d+",
        "<HASH>": r"[0-9a-f]+",
        "<PATH>": r"\S+",
    }
    for i, tok in enumerate(common):
        if i > 0:
            parts.append(r"\s+")
        if tok in placeholder_map:
            parts.append(placeholder_map[tok])
        else:
            parts.append(re.escape(tok))

    # Trailing: allow either end-of-string or more args.
    parts.append(r"(?:\s.*)?$")
    return "".join(parts)


# ============================================================================
# rules_user.py writer
# ============================================================================

def ensure_rules_user_file(path: Path) -> None:
    if path.exists():
        return
    path.write_text(RULES_USER_TEMPLATE, encoding="utf-8")


def append_to_allowlist(path: Path, regex: str, style: Style) -> bool:
    """
    Append `regex` (a raw pattern string) to the ALLOWLIST list in rules_user.py.

    Returns True on success, False on a structural problem the user must fix.
    """
    ensure_rules_user_file(path)

    try:
        source = path.read_text(encoding="utf-8")
    except OSError as e:
        print(style.warn(f"could not read {path}: {e}"))
        return False

    # Confirm there is an ALLOWLIST assignment we can recognise.
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(style.warn(
            f"rules_user.py has a syntax error: {e}. fix it by hand and rerun."
        ))
        return False

    found = False
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "ALLOWLIST":
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        found = True
                        break
            if found:
                break

    if not found:
        print(style.warn(
            "rules_user.py exists but does not define ALLOWLIST as a list. "
            "please add `ALLOWLIST = []` and rerun."
        ))
        return False

    # Build the new line. Use a raw string literal so backslashes survive.
    # Escape any embedded single quotes by switching to triple-quoted r-string
    # only when needed; the patterns we produce never contain a single quote.
    if "'" in regex:
        quote = '"'
        body = regex.replace('"', '\\"')
    else:
        quote = "'"
        body = regex
    new_entry = f"    r{quote}{body}{quote},\n"

    # Find the ALLOWLIST closing bracket and insert before it.
    # We do this textually because we want to preserve the user's comments
    # and ordering rather than rewriting via ast.unparse (which strips them).
    pattern = re.compile(r"(ALLOWLIST\s*=\s*\[)(.*?)(\])", re.DOTALL)
    match = pattern.search(source)
    if not match:
        print(style.warn(
            "could not locate ALLOWLIST = [...] block in rules_user.py. "
            "please fix it by hand."
        ))
        return False

    head, body_text, tail = match.group(1), match.group(2), match.group(3)
    # Ensure the existing body ends with a newline before our insertion.
    if body_text and not body_text.endswith("\n"):
        body_text = body_text + "\n"
    new_body = body_text + new_entry
    new_source = source[:match.start()] + head + new_body + tail + source[match.end():]

    try:
        path.write_text(new_source, encoding="utf-8")
    except OSError as e:
        print(style.warn(f"could not write {path}: {e}"))
        return False

    return True


# ============================================================================
# review mode
# ============================================================================

def cmd_review(args: argparse.Namespace) -> int:
    style = make_style(args.no_color)

    if not AUDIT_PATH.exists():
        print(style.warn(f"no audit log at {AUDIT_PATH}"))
        print("nothing to review yet.")
        return 0

    asks: list = []
    for entry in iter_audit_entries(AUDIT_PATH, args.days, style):
        if entry.get("decision") == "ask":
            asks.append(entry)

    if not asks:
        # Was the file just empty entirely?
        try:
            size = AUDIT_PATH.stat().st_size
        except OSError:
            size = 0
        if size == 0:
            print("no entries yet.")
        else:
            print(f"no ask-band entries in the last {args.days} day(s). nothing to tune.")
        return 0

    # Cluster.
    clusters: dict = defaultdict(list)
    for entry in asks:
        cmd = entry.get("command", "")
        key = cluster_key(cmd)
        if not key:
            continue
        clusters[key].append(entry)

    multi = [(k, v) for k, v in clusters.items() if len(v) >= 2]
    if not multi:
        print(
            f"found {len(asks)} ask-band decision(s) in the last {args.days} day(s), "
            "but none clustered (all singletons). nothing to auto-suggest."
        )
        return 0

    multi.sort(key=lambda kv: len(kv[1]), reverse=True)

    print(style.header(
        f"review: {len(asks)} ask-band decision(s) in the last {args.days} day(s), "
        f"{len(multi)} cluster(s) with >= 2 occurrences"
    ))
    print()

    added = 0
    skipped = 0
    quit_requested = False

    for key, entries in multi:
        if quit_requested:
            break

        scores = [int(e.get("score", 0)) for e in entries]
        commands = [e.get("command", "") for e in entries]
        score_lo, score_hi = min(scores), max(scores)

        regex = build_suggested_regex(commands)

        print(style.header(f"cluster: {key}"))
        print(f"  size: {len(entries)}    score range: {score_lo} to {score_hi}")
        print("  examples:")
        seen_examples = []
        for c in commands:
            if c in seen_examples:
                continue
            seen_examples.append(c)
            if len(seen_examples) > 3:
                break
            shown = c if len(c) <= 160 else c[:157] + "..."
            print(f"    {style.dim('|')} {shown}")
        print(f"  suggested allowlist regex:")
        print(f"    {style.ok(regex)}")

        while True:
            try:
                answer = input("  add to allowlist? [y/N/s(kip)/q(uit)] ").strip().lower()
            except EOFError:
                answer = "q"
            except KeyboardInterrupt:
                print()
                answer = "q"
            if answer in ("", "n", "no", "s", "skip"):
                skipped += 1
                break
            if answer in ("y", "yes"):
                if append_to_allowlist(RULES_USER_PATH, regex, style):
                    print(style.ok(f"  added to {RULES_USER_PATH.name}."))
                    added += 1
                break
            if answer in ("q", "quit"):
                quit_requested = True
                break
            print(style.warn("  please answer y, n, s, or q."))
        print()

    print(style.header("done."))
    print(f"  added: {added}   skipped: {skipped}")
    if added:
        print(
            "  rules.py picks up rules_user.py automatically. "
            "next hook invocation will use the new patterns."
        )
    return 0


# ============================================================================
# stats mode
# ============================================================================

def percentile(values: list, p: float) -> float:
    """Simple nearest-rank percentile. p in [0, 100]."""
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return float(s[0])
    k = (p / 100.0) * (len(s) - 1)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    frac = k - lo
    return float(s[lo] * (1.0 - frac) + s[hi] * frac)


def cmd_stats(args: argparse.Namespace) -> int:
    style = make_style(args.no_color)

    if not AUDIT_PATH.exists():
        print(style.warn(f"no audit log at {AUDIT_PATH}"))
        return 0

    try:
        size = AUDIT_PATH.stat().st_size
    except OSError:
        size = 0
    if size == 0:
        print("no entries yet.")
        return 0

    total = 0
    by_decision: Counter = Counter()
    rule_counts: Counter = Counter()
    ask_commands: Counter = Counter()
    parse_ms: list = []
    evaluate_ms: list = []
    llm_ms: list = []

    for entry in iter_audit_entries(AUDIT_PATH, args.days, style):
        total += 1
        decision = entry.get("decision", "")
        by_decision[decision] += 1
        signals = entry.get("signals") or []
        for sig in signals:
            name = sig.get("name") if isinstance(sig, dict) else None
            if name:
                rule_counts[name] += 1
        if decision == "ask":
            cmd = entry.get("command", "")
            if cmd:
                ask_commands[cmd] += 1
        timing = entry.get("timing") or {}
        if isinstance(timing, dict):
            parse_ms.append(float(timing.get("parse_ms") or 0))
            evaluate_ms.append(float(timing.get("evaluate_ms") or 0))
            llm_ms.append(float(timing.get("llm_ms") or 0))
        else:
            parse_ms.append(0.0)
            evaluate_ms.append(0.0)
            llm_ms.append(0.0)

    print(style.header(f"stats: last {args.days} day(s)"))
    print()
    print(style.header("decisions"))
    print(f"  total: {total}")
    if total == 0:
        print("  no entries in this window.")
        return 0
    for name in ("allow", "ask", "deny"):
        count = by_decision.get(name, 0)
        pct = (100.0 * count / total) if total else 0.0
        print(f"  {name:>5}: {count:>6}  ({pct:5.1f}%)")
    other = total - sum(by_decision.get(n, 0) for n in ("allow", "ask", "deny"))
    if other:
        print(f"  other: {other}")
    print()

    print(style.header("top rules by fire count"))
    if not rule_counts:
        print("  no signals recorded in this window.")
    else:
        for name, count in rule_counts.most_common(10):
            print(f"  {count:>6}  {name}")
    print()

    print(style.header("top ask-band commands"))
    if not ask_commands:
        print("  no ask-band commands in this window.")
    else:
        for cmd, count in ask_commands.most_common(5):
            shown = cmd if len(cmd) <= 120 else cmd[:117] + "..."
            print(f"  {count:>4}x  {shown}")
    print()

    print(style.header("latency (ms)"))
    rows = [
        ("parse_ms", parse_ms),
        ("evaluate_ms", evaluate_ms),
        ("llm_ms", llm_ms),
    ]
    print(f"  {'stage':<14} {'median':>10} {'p95':>10} {'p99':>10}")
    for name, values in rows:
        med = statistics.median(values) if values else 0.0
        p95 = percentile(values, 95)
        p99 = percentile(values, 99)
        print(f"  {name:<14} {med:>10.2f} {p95:>10.2f} {p99:>10.2f}")

    return 0


# ============================================================================
# argparse wiring
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tune.py",
        description="feedback and tuning CLI for claude-guard.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("review", help="cluster ask-band commands and suggest allowlist patterns")
    pr.add_argument("--days", type=int, default=7, help="window size in days (default 7)")
    pr.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    pr.set_defaults(func=cmd_review)

    ps = sub.add_parser("stats", help="summary stats for the audit log window")
    ps.add_argument("--days", type=int, default=7, help="window size in days (default 7)")
    ps.add_argument("--no-color", action="store_true", help="disable ANSI color output")
    ps.set_defaults(func=cmd_stats)

    return p


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
