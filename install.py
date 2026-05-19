#!/usr/bin/env python3
"""
claude-guard installer.

Copies the hook files into ~/.claude/guard (global) or <project>/.claude/guard
(per-project), then merges the PreToolUse hook into the matching settings.json.

Runs interactively by default. Use --yes / --global / --project to script it.

Python 3.9+, standard library only.

Usage:
    python install.py
    python install.py --global
    python install.py --project ~/code/myproject
    python install.py --global --yes --skip-feed
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Files copied into the install target. Keep this list in sync with the repo.
FILES = [
    "claude-guard.py",
    "rules.py",
    "llm_fallback.py",
    "anomaly.py",
    "tune.py",
    "update_threat_feed.py",
    "dashboard.py",
    "settings.example.json",
    "README.md",
]

# Included only if present in the source repo (no warning if missing).
OPTIONAL_FILES = [
    "compromised_packages_auto.py",  # saves ~30 sec download on install
    "CLAUDE.md",                     # agent-facing brief, only in some repos
    "ULTRAPLAN.md",                  # strategic doc, only in some repos
]

HOOK_COMMAND_TEMPLATE_GLOBAL = (
    'python "{install_dir}/claude-guard.py"'
)
HOOK_COMMAND_TEMPLATE_PROJECT = (
    'python "$CLAUDE_PROJECT_DIR/.claude/guard/claude-guard.py"'
)
DASHBOARD_COMMAND_TEMPLATE_GLOBAL = (
    'python "{install_dir}/dashboard.py" --ensure-running'
)
DASHBOARD_COMMAND_TEMPLATE_PROJECT = (
    'python "$CLAUDE_PROJECT_DIR/.claude/guard/dashboard.py" --ensure-running'
)


def color(s: str, code: str) -> str:
    if not sys.stdout.isatty():
        return s
    return f"\033[{code}m{s}\033[0m"


def info(msg: str) -> None:
    print(color("[info]", "36") + " " + msg)


def warn(msg: str) -> None:
    print(color("[warn]", "33") + " " + msg)


def ok(msg: str) -> None:
    print(color("[ok]", "32") + " " + msg)


def fail(msg: str) -> None:
    print(color("[err]", "31") + " " + msg, file=sys.stderr)


def confirm(prompt: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        a = input(f"{prompt} {suffix} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if not a:
        return default
    return a.startswith("y")


def detect_source_dir() -> Path:
    """Where this installer lives. The hook files should sit alongside it."""
    here = Path(__file__).resolve().parent
    if not (here / "claude-guard.py").exists():
        fail(
            "Could not find claude-guard.py next to install.py. "
            "Run this script from inside the cloned repo."
        )
        sys.exit(2)
    return here


def ask_install_target() -> tuple[str, Path]:
    """Returns (mode, install_dir). mode is 'global' or 'project'."""
    print()
    print("Where should claude-guard live?")
    print()
    print("  [1] " + color("global", "1") + "  ~/.claude/guard/  "
          "(fires for every Claude Code project on this machine)")
    print("  [2] " + color("project", "1") + " <project>/.claude/guard/  "
          "(fires only inside one project)")
    print()
    while True:
        try:
            a = input("Pick 1 or 2: ").strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit(1)
        if a == "1":
            return "global", Path.home() / ".claude" / "guard"
        if a == "2":
            try:
                p = input("Path to the project root: ").strip()
            except (EOFError, KeyboardInterrupt):
                sys.exit(1)
            if not p:
                continue
            root = Path(p).expanduser().resolve()
            if not root.exists():
                warn(f"{root} does not exist. Try again.")
                continue
            return "project", root / ".claude" / "guard"


def _same_dir(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return str(a).rstrip("\\/").lower() == str(b).rstrip("\\/").lower()


def copy_files(src: Path, dst: Path) -> int:
    dst.mkdir(parents=True, exist_ok=True)
    in_place = _same_dir(src, dst)
    if in_place:
        info("source and install directory are the same; "
             "skipping file copy (cloned in place).")
    copied = 0
    for name in FILES:
        s = src / name
        if not s.exists():
            warn(f"source file missing, skipping: {name}")
            continue
        if in_place:
            copied += 1
            continue
        shutil.copy2(s, dst / name)
        copied += 1
    for name in OPTIONAL_FILES:
        s = src / name
        if s.exists():
            if not in_place:
                shutil.copy2(s, dst / name)
            copied += 1
    return copied


def settings_path_for(mode: str, project_dir: Path = None) -> Path:
    if mode == "global":
        return Path.home() / ".claude" / "settings.json"
    return project_dir.parent / "settings.json"  # <project>/.claude/settings.json


def load_settings(path: Path) -> tuple[dict, bool]:
    """Returns (settings_dict, existed)."""
    if not path.exists():
        return {}, False
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            warn(f"{path} is not a JSON object. Will rewrite as fresh.")
            return {}, True
        return data, True
    except json.JSONDecodeError as e:
        fail(f"{path} has invalid JSON: {e}")
        fail("Fix it by hand, then re-run install.py.")
        sys.exit(2)


GUARD_MATCHER = "Bash|Edit|Write|MultiEdit|WebFetch|WebSearch|mcp__.*"
GUARD_TIMEOUT = 10


def merge_hook(settings: dict, hook_command: str) -> bool:
    """Returns True if we modified settings, False if our hook was already
    present and correct.

    Strategy: find any existing PreToolUse entry that already runs
    claude-guard.py (regardless of its matcher field — V2 installs used
    "Bash" only) and rewrite it to the V3 broad matcher. If none exists,
    create a fresh entry.
    """
    settings.setdefault("hooks", {})
    if not isinstance(settings["hooks"], dict):
        settings["hooks"] = {}
    pre = settings["hooks"].setdefault("PreToolUse", [])
    if not isinstance(pre, list):
        pre = []
        settings["hooks"]["PreToolUse"] = pre

    new_hook = {
        "type": "command",
        "command": hook_command,
        "timeout": GUARD_TIMEOUT,
    }

    # Find an existing entry that already runs claude-guard, no matter what
    # matcher it currently uses. This catches V2 installs (matcher: "Bash").
    guard_entry = None
    for entry in pre:
        if (
            isinstance(entry, dict)
            and isinstance(entry.get("hooks"), list)
            and any(
                isinstance(h, dict)
                and isinstance(h.get("command"), str)
                and "claude-guard.py" in h["command"]
                for h in entry["hooks"]
            )
        ):
            guard_entry = entry
            break

    if guard_entry is None:
        pre.append({"matcher": GUARD_MATCHER, "hooks": [new_hook]})
        return True

    changed = False
    if guard_entry.get("matcher") != GUARD_MATCHER:
        guard_entry["matcher"] = GUARD_MATCHER
        changed = True

    # Replace the claude-guard hook in place; leave any unrelated hooks alone.
    hooks_list = guard_entry["hooks"]
    for i, h in enumerate(hooks_list):
        if (
            isinstance(h, dict)
            and isinstance(h.get("command"), str)
            and "claude-guard.py" in h["command"]
        ):
            if h.get("command") != hook_command or h.get("timeout") != GUARD_TIMEOUT:
                hooks_list[i] = new_hook
                changed = True
            return changed
    hooks_list.append(new_hook)
    return True


def merge_session_hook(settings: dict, hook_command: str) -> bool:
    """Wire the dashboard launcher into SessionStart. Mirrors merge_hook but
    matches by "dashboard.py" in the command path."""
    settings.setdefault("hooks", {})
    if not isinstance(settings["hooks"], dict):
        settings["hooks"] = {}
    sess = settings["hooks"].setdefault("SessionStart", [])
    if not isinstance(sess, list):
        sess = []
        settings["hooks"]["SessionStart"] = sess

    new_hook = {
        "type": "command",
        "command": hook_command,
        "timeout": GUARD_TIMEOUT,
    }

    guard_entry = None
    for entry in sess:
        if (
            isinstance(entry, dict)
            and isinstance(entry.get("hooks"), list)
            and any(
                isinstance(h, dict)
                and isinstance(h.get("command"), str)
                and "dashboard.py" in h["command"]
                for h in entry["hooks"]
            )
        ):
            guard_entry = entry
            break

    if guard_entry is None:
        sess.append({"matcher": "*", "hooks": [new_hook]})
        return True

    changed = False
    if guard_entry.get("matcher") != "*":
        guard_entry["matcher"] = "*"
        changed = True

    hooks_list = guard_entry["hooks"]
    for i, h in enumerate(hooks_list):
        if (
            isinstance(h, dict)
            and isinstance(h.get("command"), str)
            and "dashboard.py" in h["command"]
        ):
            if h.get("command") != hook_command or h.get("timeout") != GUARD_TIMEOUT:
                hooks_list[i] = new_hook
                changed = True
            return changed
    hooks_list.append(new_hook)
    return True


def write_settings(path: Path, settings: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, sort_keys=False)
        f.write("\n")
    os.replace(tmp, path)


def maybe_run_feed(install_dir: Path, skip: bool, yes: bool) -> None:
    auto_file = install_dir / "compromised_packages_auto.py"
    if skip:
        return
    if auto_file.exists():
        info(f"threat feed already present ({_format_pkg_count(auto_file)}). "
             "Re-run `python update_threat_feed.py` later to refresh.")
        return
    print()
    print("The threat feed (OSV.dev malicious-package list) is a separate "
          "~30 second download.")
    print("It catches things like supply-chain attacks the moment Claude tries "
          "to install them.")
    if not (yes or confirm("Fetch the threat feed now?", default=True)):
        info("skipped. Run `python update_threat_feed.py` from "
             f"{install_dir} when you're ready.")
        return
    info("fetching threat feed (this may take 30 seconds)...")
    try:
        result = subprocess.run(
            [sys.executable, str(install_dir / "update_threat_feed.py"),
             "--verbose"],
            cwd=str(install_dir),
            timeout=180,
        )
        if result.returncode == 0:
            ok("threat feed installed.")
        else:
            warn(f"feed updater exited {result.returncode}. "
                 "You can re-run it later.")
    except subprocess.TimeoutExpired:
        warn("feed updater timed out. Retry with "
             "`python update_threat_feed.py`.")
    except OSError as e:
        warn(f"could not run feed updater: {e}")


def _format_pkg_count(auto_file: Path) -> str:
    """Best-effort: read counts from the file header without importing."""
    try:
        for line in auto_file.read_text(encoding="utf-8", errors="ignore").splitlines()[:10]:
            if line.startswith("# npm packages:"):
                return line[2:].strip()
        return f"{auto_file.stat().st_size // 1024} KB"
    except OSError:
        return "present"


def print_done(mode: str, install_dir: Path, settings_file: Path,
               settings_existed: bool, settings_changed: bool) -> None:
    print()
    print(color("=" * 60, "32"))
    ok("claude-guard installed.")
    print(color("=" * 60, "32"))
    print()
    print(f"  Files:    {install_dir}")
    if settings_changed:
        print(f"  Settings: {settings_file} "
              + color("(updated)" if settings_existed else "(created)", "32"))
    else:
        print(f"  Settings: {settings_file} "
              + color("(already configured)", "33"))
    print()
    print("Next steps:")
    print()
    print("  1. Open a new Claude Code session in any project. The hook fires "
          "on every Bash command.")
    print()
    print("  2. Optional, for the LLM second opinion on ambiguous commands:")
    print(color("       setx ANTHROPIC_API_KEY \"sk-ant-...\"", "36")
          + "   (PowerShell, persistent)")
    print(color("       export ANTHROPIC_API_KEY=\"sk-ant-...\"", "36")
          + "  (bash, current shell)")
    print()
    print("  3. After a week of real use, tune the noisy ask-band away:")
    print(color(f"       python \"{install_dir / 'tune.py'}\" review", "36"))
    print()
    print("  4. To refresh the malicious-package feed (run nightly via "
          "cron / Task Scheduler):")
    print(color(f"       python \"{install_dir / 'update_threat_feed.py'}\"", "36"))
    print()
    if mode == "global":
        print("Uninstall:")
        print(color(f"       rm -rf \"{install_dir}\"", "33")
              + "  and remove the PreToolUse block from " + str(settings_file))
        print()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Install claude-guard as a Claude Code PreToolUse hook."
    )
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--global", dest="global_mode", action="store_true",
                   help="install at ~/.claude/guard/ (no prompts)")
    g.add_argument("--project", metavar="PATH",
                   help="install at <PATH>/.claude/guard/ (no prompts)")
    ap.add_argument("--yes", "-y", action="store_true",
                    help="answer yes to all prompts")
    ap.add_argument("--skip-feed", action="store_true",
                    help="do not fetch the OSV.dev threat feed during install")
    args = ap.parse_args()

    src = detect_source_dir()

    if args.global_mode:
        mode = "global"
        install_dir = Path.home() / ".claude" / "guard"
    elif args.project:
        mode = "project"
        root = Path(args.project).expanduser().resolve()
        if not root.exists():
            fail(f"{root} does not exist.")
            return 2
        install_dir = root / ".claude" / "guard"
    else:
        mode, install_dir = ask_install_target()

    info(f"installing to {install_dir} ({mode})")

    if install_dir.exists() and any(install_dir.iterdir()):
        if not (args.yes or confirm(
            f"{install_dir} exists and is not empty. Overwrite hook files?",
            default=True,
        )):
            fail("aborted by user.")
            return 1

    copied = copy_files(src, install_dir)
    ok(f"copied {copied} file(s) to {install_dir}")

    if mode == "global":
        settings_file = settings_path_for("global")
        install_path_fwd = str(install_dir).replace("\\", "/")
        hook_cmd = HOOK_COMMAND_TEMPLATE_GLOBAL.format(install_dir=install_path_fwd)
        dash_cmd = DASHBOARD_COMMAND_TEMPLATE_GLOBAL.format(install_dir=install_path_fwd)
    else:
        settings_file = settings_path_for("project", install_dir)
        hook_cmd = HOOK_COMMAND_TEMPLATE_PROJECT
        dash_cmd = DASHBOARD_COMMAND_TEMPLATE_PROJECT

    settings, existed = load_settings(settings_file)
    pre_changed = merge_hook(settings, hook_cmd)
    sess_changed = merge_session_hook(settings, dash_cmd)
    changed = pre_changed or sess_changed
    if changed:
        write_settings(settings_file, settings)
        ok(f"{'updated' if existed else 'created'} {settings_file}")
    else:
        info(f"{settings_file} already wired up; left as is")

    maybe_run_feed(install_dir, skip=args.skip_feed, yes=args.yes)
    print_done(mode, install_dir, settings_file, existed, changed)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
