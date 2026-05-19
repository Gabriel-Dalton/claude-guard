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
    python install.py --update                # git pull + re-copy + re-verify
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# claude-guard.py uses Python 3.9+ runtime features (e.g. `list[dict]` as a
# runtime type). Check here so the user gets a clear message at install time
# rather than an obscure error the first time the hook fires.
if sys.version_info < (3, 9):
    sys.exit(
        f"claude-guard requires Python 3.9 or newer "
        f"(found {sys.version_info.major}.{sys.version_info.minor}). "
        f"Install a newer Python and re-run with that interpreter."
    )

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

# Hook commands are baked at install time with the absolute path to the
# Python interpreter that ran install.py (sys.executable). This avoids the
# "python" vs "py" vs "python3" PATH lottery, which is the #1 reason the hook
# silently fails on Windows. If you later switch interpreters, re-run install.
HOOK_COMMAND_TEMPLATE_GLOBAL = (
    '"{python_exe}" "{install_dir}/claude-guard.py"'
)
HOOK_COMMAND_TEMPLATE_PROJECT = (
    '"{python_exe}" "$CLAUDE_PROJECT_DIR/.claude/guard/claude-guard.py"'
)
DASHBOARD_COMMAND_TEMPLATE_GLOBAL = (
    '"{python_exe}" "{install_dir}/dashboard.py" --ensure-running'
)
DASHBOARD_COMMAND_TEMPLATE_PROJECT = (
    '"{python_exe}" "$CLAUDE_PROJECT_DIR/.claude/guard/dashboard.py" --ensure-running'
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


def copy_files(src: Path, dst: Path) -> tuple[int, bool]:
    """Copy hook files from src to dst.

    Returns (n, in_place). When in_place is True (src == dst, the one-liner
    case), nothing is actually copied — n is the count of recognised files
    already present so the caller can report something honest.
    """
    dst.mkdir(parents=True, exist_ok=True)
    in_place = _same_dir(src, dst)
    if in_place:
        info("source and install directory are the same; "
             "skipping file copy (in-place install).")
    n = 0
    for name in FILES:
        s = src / name
        if not s.exists():
            warn(f"source file missing, skipping: {name}")
            continue
        if in_place:
            n += 1
            continue
        try:
            shutil.copy2(s, dst / name)
        except OSError as e:
            fail(f"could not copy {name}: {e}")
            continue
        n += 1
    for name in OPTIONAL_FILES:
        s = src / name
        if not s.exists():
            continue
        if in_place:
            n += 1
            continue
        try:
            shutil.copy2(s, dst / name)
        except OSError as e:
            warn(f"could not copy optional file {name}: {e}")
            continue
        n += 1
    return n, in_place


def settings_path_for(mode: str, install_dir: Path = None) -> Path:
    """Resolve the Claude Code settings.json that the hook gets merged into.

    For global installs, that's ~/.claude/settings.json. For project installs
    we receive `install_dir` (i.e. <project>/.claude/guard) and walk up one
    level to land on <project>/.claude/settings.json.
    """
    if mode == "global":
        return Path.home() / ".claude" / "settings.json"
    return install_dir.parent / "settings.json"


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
GUARD_TIMEOUT_DEFAULT = 15  # bumped from 10s — leaves headroom for LLM fallback
# Matchers that previous installer versions wrote. If we see one of these on a
# re-install we silently upgrade. If we see anything else, the user customised
# it and we leave their matcher alone.
KNOWN_PRIOR_MATCHERS = {
    "Bash",                                              # V1 / V2
    "Bash|Edit|Write|MultiEdit",                         # V3 early
    "Bash|Edit|Write|MultiEdit|WebFetch|WebSearch|mcp__.*",  # V3 current
}


def merge_hook(settings: dict, hook_command: str, timeout: int) -> bool:
    """Returns True if we modified settings, False if our hook was already
    present and correct.

    Strategy: find any existing PreToolUse entry that already runs
    claude-guard.py (regardless of its matcher field). Upgrade the matcher
    only if it matches one of the previous installer defaults; otherwise leave
    the user's customisation in place.
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
        "timeout": timeout,
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
    current = guard_entry.get("matcher")
    if current != GUARD_MATCHER:
        if current in KNOWN_PRIOR_MATCHERS or not isinstance(current, str):
            guard_entry["matcher"] = GUARD_MATCHER
            changed = True
        else:
            warn(f"keeping your custom matcher {current!r} for claude-guard; "
                 f"installer default is {GUARD_MATCHER!r}.")

    # Replace the claude-guard hook in place; leave any unrelated hooks alone.
    hooks_list = guard_entry["hooks"]
    for i, h in enumerate(hooks_list):
        if (
            isinstance(h, dict)
            and isinstance(h.get("command"), str)
            and "claude-guard.py" in h["command"]
        ):
            if h.get("command") != hook_command or h.get("timeout") != timeout:
                hooks_list[i] = new_hook
                changed = True
            return changed
    hooks_list.append(new_hook)
    return True


def merge_session_hook(settings: dict, hook_command: str, timeout: int) -> bool:
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
        "timeout": timeout,
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
            if h.get("command") != hook_command or h.get("timeout") != timeout:
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
    info("fetching threat feed (streams progress below; ~30s on a normal link)...")
    try:
        proc = subprocess.Popen(
            [sys.executable, str(install_dir / "update_threat_feed.py"),
             "--verbose"],
            cwd=str(install_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as e:
        warn(f"could not run feed updater: {e}")
        return

    deadline = time.time() + 180
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            print("    " + line.rstrip())
            if time.time() > deadline:
                proc.kill()
                warn("feed updater timed out (3 min). Retry with "
                     "`python update_threat_feed.py`.")
                return
        proc.wait(timeout=5)
    except KeyboardInterrupt:
        proc.kill()
        raise
    except subprocess.TimeoutExpired:
        proc.kill()
        warn("feed updater did not exit cleanly. You can re-run it later.")
        return

    if proc.returncode == 0:
        ok("threat feed installed.")
    else:
        warn(f"feed updater exited {proc.returncode}. You can re-run it later.")


def verify_install(install_dir: Path) -> bool:
    """Run `python -c 'import rules'` inside install_dir. Returns True on a
    clean import. Catches the case where a hand-edit (or a corrupt
    compromised_packages_auto.py) would make the hook fall into FAIL_MODE
    "closed" and silently turn every command into an "ask" prompt — a
    regression the user has no easy way to discover at install time.
    """
    info("verifying rules.py imports cleanly...")
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import rules"],
            cwd=str(install_dir),
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        warn(f"could not run rules.py import check: {e}")
        return False
    if result.returncode == 0:
        ok("rules.py loads cleanly")
        return True
    fail("rules.py failed to import — the hook would force-ask every command:")
    for line in (result.stderr or "").strip().splitlines()[-6:]:
        print("    " + line)
    return False


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
               settings_existed: bool, settings_changed: bool,
               python_exe: str) -> None:
    is_windows = os.name == "nt"
    py = f'"{python_exe}"'  # always quote in case the path has spaces
    print()
    print(color("=" * 60, "32"))
    ok("claude-guard installed.")
    print(color("=" * 60, "32"))
    print()
    print(f"  Files:    {install_dir}")
    print(f"  Python:   {python_exe}")
    if settings_changed:
        print(f"  Settings: {settings_file} "
              + color("(updated)" if settings_existed else "(created)", "32"))
    else:
        print(f"  Settings: {settings_file} "
              + color("(already configured)", "33"))
    print()
    print("Next steps:")
    print()
    print("  1. Open a new Claude Code session in any project. Existing "
          "sessions don't reload settings.json.")
    print("     The hook fires on every Bash / Edit / Write / WebFetch / MCP "
          "tool call.")
    print()
    print("  2. Smoke test the hook any time:")
    print(color(f"       {py} \"{install_dir / 'claude-guard.py'}\" --test", "36"))
    print()
    print("  3. Optional: enable the LLM second opinion on ambiguous commands "
          "(deterministic scoring works without it):")
    if is_windows:
        print(color("       setx ANTHROPIC_API_KEY \"sk-ant-...\"", "36")
              + "   (persistent; new shells will see it)")
    else:
        print(color("       export ANTHROPIC_API_KEY=\"sk-ant-...\"", "36")
              + "  (current shell; add to ~/.bashrc or ~/.zshrc for persistence)")
    print()
    print("  4. After a week of real use, tune the noisy ask-band away:")
    print(color(f"       {py} \"{install_dir / 'tune.py'}\" review", "36"))
    print()
    print("  5. To refresh the malicious-package feed (run nightly via "
          "cron / Task Scheduler):")
    print(color(f"       {py} \"{install_dir / 'update_threat_feed.py'}\"", "36"))
    print()
    print("Uninstall:")
    if is_windows:
        print(color(f"       Remove-Item -Recurse -Force \"{install_dir}\"", "33")
              + "  (PowerShell)")
        print(color(f"       rmdir /s /q \"{install_dir}\"", "33")
              + "  (cmd.exe)")
    else:
        print(color(f"       rm -rf \"{install_dir}\"", "33"))
    print(f"  Then remove the PreToolUse and SessionStart blocks from")
    print(f"    {settings_file}")
    print()


def run_update(install_dir: Path) -> int:
    """`install.py --update`: git pull in the install dir, stop the dashboard,
    re-copy files (in-place), re-verify rules.py, and re-merge settings.

    This collapses the four-command update flow (stop dashboard, git pull,
    re-run install, restart) into one. Requires the install dir to be a git
    clone (the default for the README one-liner).
    """
    if not (install_dir / ".git").exists():
        fail(f"{install_dir} is not a git clone — `--update` only works on a "
             "clone. Re-run install.py from your source clone instead.")
        return 2
    info(f"stopping dashboard in {install_dir} (if running)...")
    try:
        subprocess.run(
            [sys.executable, str(install_dir / "dashboard.py"), "--stop"],
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        warn(f"could not stop dashboard cleanly: {e} (continuing anyway)")
    info(f"git pull in {install_dir}...")
    try:
        result = subprocess.run(
            ["git", "-C", str(install_dir), "pull", "--ff-only"],
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        fail(f"git pull failed: {e}")
        return 2
    if result.returncode != 0:
        fail(f"git pull exited {result.returncode}; resolve and retry.")
        return result.returncode
    # Detect global vs. project from the path so we can re-run install with
    # the right flags.
    home_guard = (Path.home() / ".claude" / "guard").resolve()
    if install_dir.resolve() == home_guard:
        return main(["--global", "--yes"])
    # Project case: install_dir is <project>/.claude/guard
    project_root = install_dir.parent.parent
    return main(["--project", str(project_root), "--yes"])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Install claude-guard as a Claude Code PreToolUse hook."
    )
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--global", dest="global_mode", action="store_true",
                   help="install at ~/.claude/guard/ (no prompts)")
    g.add_argument("--project", metavar="PATH",
                   help="install at <PATH>/.claude/guard/ (no prompts)")
    g.add_argument("--update", action="store_true",
                   help="git pull + re-install in the current install dir "
                        "(requires the install to be a git clone)")
    ap.add_argument("--yes", "-y", action="store_true",
                    help="answer yes to all prompts")
    ap.add_argument("--skip-feed", action="store_true",
                    help="do not fetch the OSV.dev threat feed during install")
    ap.add_argument("--timeout", type=int, default=GUARD_TIMEOUT_DEFAULT,
                    metavar="SECONDS",
                    help=f"per-tool-call hook timeout written into settings.json "
                         f"(default {GUARD_TIMEOUT_DEFAULT})")
    args = ap.parse_args(argv)

    src = detect_source_dir()

    if args.update:
        return run_update(src)

    if args.global_mode:
        mode = "global"
        install_dir = Path.home() / ".claude" / "guard"
    elif args.project:
        mode = "project"
        root = Path(args.project).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            fail(f"{root} does not exist or is not a directory.")
            return 2
        install_dir = root / ".claude" / "guard"
    else:
        mode, install_dir = ask_install_target()

    info(f"installing to {install_dir} ({mode})")
    info(f"using Python at {sys.executable}")

    if install_dir.exists() and any(install_dir.iterdir()):
        if not (args.yes or confirm(
            f"{install_dir} exists and is not empty. Overwrite hook files?",
            default=True,
        )):
            fail("aborted by user.")
            return 1

    copied, in_place = copy_files(src, install_dir)
    if in_place:
        ok(f"{copied} hook file(s) already present at {install_dir}")
    else:
        ok(f"copied {copied} file(s) to {install_dir}")

    # Validate the freshly-installed rules.py BEFORE we wire up settings.json.
    # A broken rules.py would make the hook return "ask" for every tool call,
    # so it's much better to fail loudly here than to install a broken hook.
    if not verify_install(install_dir):
        fail("settings.json was NOT modified. Fix rules.py and re-run install.")
        return 3

    python_exe = sys.executable.replace("\\", "/")

    if mode == "global":
        settings_file = settings_path_for("global")
        install_path_fwd = str(install_dir).replace("\\", "/")
        hook_cmd = HOOK_COMMAND_TEMPLATE_GLOBAL.format(
            python_exe=python_exe, install_dir=install_path_fwd,
        )
        dash_cmd = DASHBOARD_COMMAND_TEMPLATE_GLOBAL.format(
            python_exe=python_exe, install_dir=install_path_fwd,
        )
    else:
        settings_file = settings_path_for("project", install_dir)
        hook_cmd = HOOK_COMMAND_TEMPLATE_PROJECT.format(python_exe=python_exe)
        dash_cmd = DASHBOARD_COMMAND_TEMPLATE_PROJECT.format(python_exe=python_exe)

    settings, existed = load_settings(settings_file)
    pre_changed = merge_hook(settings, hook_cmd, args.timeout)
    sess_changed = merge_session_hook(settings, dash_cmd, args.timeout)
    changed = pre_changed or sess_changed
    if changed:
        write_settings(settings_file, settings)
        ok(f"{'updated' if existed else 'created'} {settings_file}")
    else:
        info(f"{settings_file} already wired up; left as is")

    maybe_run_feed(install_dir, skip=args.skip_feed, yes=args.yes)
    print_done(mode, install_dir, settings_file, existed, changed, sys.executable)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
