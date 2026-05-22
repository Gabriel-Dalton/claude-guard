# claude-guard

A numeric scoring engine that wraps Claude Code's `PreToolUse` hook. Every Bash command Claude wants to run is parsed, evaluated against a stack of independent risk signals, and assigned a score from 0 to 100. The score drives the decision: silent allow, fall through to a review prompt, or hard deny. Every decision is logged with its full breakdown so you can see why each command was rated the way it was.

The goal is to stop you clicking through the same low-risk prompts (compiling, running scripts in your project's `scripts/` folder, dry-runs) while still pausing for review on anything that touches the rest of your system, talks to the network in an unexpected way, or installs code you haven't pinned.

## Why scoring instead of allowlists

Most "auto-approve" setups for Claude Code work as flat allowlists: list every command you trust, anything else prompts you. That breaks the moment Claude writes a slightly different version of something safe (different flags, different quoting, paths with relative versus absolute prefixes). You end up either re-clicking the same prompts or widening the allowlist until you've effectively turned off the safety system.

A scoring model treats each command as a sum of independent signals. "Runs a script in `./scripts/`" is worth points. "Uses `-DryRun`" subtracts points. "Touches `.ssh/id_rsa`" adds a lot. "Installs an unpinned npm package" adds some. "Installs an unpinned npm package whose name is on the known-compromised list" adds enough to deny outright. New variants of safe commands score safe because they hit the same combination of signals. New variants of dangerous commands score dangerous for the same reason.

## How the pipeline runs

For every Bash tool call Claude makes, the hook does this:

1. **Parse the command.** Extract path tokens (Windows and POSIX), detect the shell flavour (bash vs PowerShell), find network targets and interpreters, flag dry-run flags, identify pipes into shells.
2. **Categorise paths.** Each extracted path is resolved (cross-platform, handles `\` and `/` both, resolves `..` lexically) and split into in-scope (inside `$CLAUDE_PROJECT_DIR`) and out-of-scope.
3. **Check the denylist.** If a hardcoded danger pattern matches, score is 100 and the decision is deny. Nothing else runs.
4. **Check the veto layer.** If the command touches anything in `VETO_PATTERNS` (SSH keys, AWS creds, `.env` files, sudo, Windows system paths) or has any out-of-scope path, the allowlist is bypassed and full scoring runs. This stops a generic `Get-Content` allowlist match from silently approving `Get-Content ~/.ssh/id_rsa`.
5. **Check the allowlist.** If no veto fired and a clear safe pattern matches (`git status`, `ls`, version checks, etc.), score is 0 and the command auto-allows.
6. **Run the scoring pipeline.** Four rule sets fire independently and their points sum into the final score: pattern rules (regex-matched), path rules (logic over `Context.paths`), network rules (per-network-call evaluation), context reducers (negative points for dry-runs, read-only verbs, output-discarded, etc.).
7. **Map score to decision.** Configurable thresholds (`allow_below`, `deny_at_or_above`) decide. Anything between thresholds falls through to Claude Code's normal prompt, but with the full signal breakdown attached so you can see exactly why it didn't auto-allow.
8. **Log.** Every decision goes into `audit.jsonl` next to the script. Tail it during a working session to spot rules that are misfiring.

## Install

### Option A — one-paste install (recommended)

**macOS / Linux**
```bash
curl -fsSL https://raw.githubusercontent.com/Gabriel-Dalton/claude-guard/main/bootstrap.sh | bash
```

**Windows (PowerShell)**
```powershell
iwr https://raw.githubusercontent.com/Gabriel-Dalton/claude-guard/main/bootstrap.ps1 -UseBasicParsing | iex
```

The bootstrap clones (or pulls) into the install directory, stops any running dashboard so files aren't held open, and runs `install.py --global --yes`. Re-run the same line any time to update. Yes, `curl | bash` for a security tool is ironic — [review the script first](https://github.com/Gabriel-Dalton/claude-guard/blob/main/bootstrap.sh) if you'd rather see what runs, or use Option B below to clone explicitly.

### Option B — explicit git clone

Paste-safe; running it twice does the right thing.

**macOS / Linux**
```bash
INSTALL_DIR="$HOME/.claude/guard"
[ -f "$INSTALL_DIR/dashboard.py" ] && python3 "$INSTALL_DIR/dashboard.py" --stop 2>/dev/null
[ -d "$INSTALL_DIR/.git" ] && git -C "$INSTALL_DIR" pull --ff-only || git clone https://github.com/Gabriel-Dalton/claude-guard "$INSTALL_DIR"
python3 "$INSTALL_DIR/install.py" --global --yes
```

**Windows (PowerShell)**
```powershell
$InstallDir = "$env:USERPROFILE\.claude\guard"
if (Test-Path "$InstallDir\dashboard.py") { python "$InstallDir\dashboard.py" --stop 2>$null }
if (Test-Path "$InstallDir\.git") {
  git -C "$InstallDir" pull --ff-only
} else {
  git clone https://github.com/Gabriel-Dalton/claude-guard $InstallDir
}
python "$InstallDir\install.py" --global --yes
```

The block clones (or fast-forwards) the repo into the install directory, then runs the installer. Files land in `$HOME/.claude/guard/` on POSIX and `$env:USERPROFILE\.claude\guard\` on Windows. The installer is idempotent and safe to re-run after every `git pull`.

### After install

Open a new Claude Code session. The `PreToolUse` hook fires automatically on every Bash, Edit, Write, WebFetch, WebSearch, and MCP tool call. The dashboard auto-launches at http://127.0.0.1:7475.

<details>
<summary><strong>Other install options</strong></summary>

- **Interactive (asked at each step):** drop `--yes` from any of the snippets above.
- **Per-project only (fires for one project, not the whole machine):**
  ```
  python install.py --project /path/to/project --yes
  ```
  Files land in `<project>/.claude/guard/`, the hook merges into `<project>/.claude/settings.json`.
- **Skip the threat feed download:** add `--skip-feed`. Fetch it later with:
  - POSIX: `python3 "$HOME/.claude/guard/update_threat_feed.py"`
  - PowerShell: `python "$env:USERPROFILE\.claude\guard\update_threat_feed.py"`

</details>

## Verify

Run the self-test from anywhere:

```bash
python ~/.claude/guard/claude-guard.py --test
```

You should see a fixture of commands and their scores. Then **open a new Claude Code session** (existing sessions don't reload `settings.json`). The next Bash / Edit / Write / MCP tool call routes through the hook. Watch decisions land in real time:

- **Live dashboard:** http://127.0.0.1:7475 (auto-launches on every session via the `SessionStart` hook)
- **Raw log:** `~/.claude/guard/audit.jsonl`

## How it runs after install

There's no daemon to start. The hook is invoked by Claude Code itself:

- `PreToolUse` fires on every `Bash`, `Edit`, `Write`, `MultiEdit`, `WebFetch`, `WebSearch`, and `mcp__*` call. The engine scores, decides `allow` / `ask` / `deny`, logs the result.
- `SessionStart` launches the dashboard once per session (idempotent — won't double-start if already running).
- Both are merged into `~/.claude/settings.json` by `install.py`.

## Updating

Source-code changes don't reach the live hook until you re-run the installer (the install dir is a separate copy of the files). The flow:

```bash
# 1. Stop the dashboard so it isn't holding files open
python ~/.claude/guard/dashboard.py --stop

# 2a. If your install dir is itself a git clone (the default):
git -C ~/.claude/guard pull && python ~/.claude/guard/install.py --global --yes

# 2b. Or if you keep a separate source clone:
git -C /path/to/your/claude-guard pull && python /path/to/your/claude-guard/install.py --global --yes
```

Open a new Claude Code session. The dashboard relaunches automatically.

## Troubleshooting

<details>
<summary><code>PermissionError: [WinError 32] The process cannot access the file because it is being used by another process</code> during install</summary>

The dashboard process is holding files open in the install dir. Stop it, then re-run the installer:

```powershell
python "$env:USERPROFILE\.claude\guard\dashboard.py" --stop
```

It relaunches on the next Claude Code session.
</details>

<details>
<summary><code>fatal: destination path '...\.claude\guard' already exists and is not an empty directory</code></summary>

You already have claude-guard installed at that path. Skip the `git clone` step and run `install.py` directly (see [Updating](#updating)).
</details>

<details>
<summary><code>python: can't open file 'claude-guard.py': No such file or directory</code></summary>

You don't run `claude-guard.py` from inside your project — it's a hook that fires automatically. To test it, use the absolute path:

```bash
python ~/.claude/guard/claude-guard.py --test
```
</details>

<details>
<summary>The hook isn't firing on tool calls</summary>

Existing Claude Code sessions don't reload `settings.json`. Close the session and start a fresh one. To confirm the hook is wired, check that `~/.claude/settings.json` contains a `PreToolUse` block with `claude-guard.py` in the command path.
</details>

<details>
<summary>Dashboard isn't loading at 127.0.0.1:7475</summary>

Check that it's running:

```bash
cat  ~/.claude/guard/dashboard.pid       # macOS / Linux
type %USERPROFILE%\.claude\guard\dashboard.pid    # Windows (cmd)
```

If empty or the process is dead, start it manually:

```bash
python ~/.claude/guard/dashboard.py --ensure-running
```
</details>

<details>
<summary>Getting too many "ask" prompts</summary>

After a week of real use, run `python ~/.claude/guard/tune.py review`. It clusters your noisy ask-band commands and offers to write allowlist patterns to `rules_user.py` (your base `rules.py` stays untouched, so future updates remain clean).
</details>

<details>
<summary>Something I expected to be blocked got allowed</summary>

Lower `THRESHOLDS["allow_below"]` in `rules.py`, or add a stricter pattern rule. Save — the next hook invocation picks it up. No restart, no rebuild.
</details>

## The worked example

The command in your screenshot was:

```
$env:Path = [Environment]::GetEnvironmentVariable('Path','User') + ';' +
[Environment]::GetEnvironmentVariable('Path','Machine');
pwsh -NoProfile -File .\scripts\create-issues.ps1 -DryRun 2>&1 |
Select-Object -Last 60
```

Claude Code's built-in check flagged "spawns a nested PowerShell process which cannot be validated" and asked you to approve. Here's how claude-guard scores it:

| Signal | Points | Reason |
|--------|:------:|--------|
| `nested_shell` | +5 | `pwsh -NoProfile -File ...` does spawn a child shell; mild signal |
| `dry_run_flag` | -15 | `-DryRun` is detected |
| (no allowlist match) | | Has variable assignment, doesn't match a clean read-only pattern |
| (no veto match) | | Doesn't touch SSH, AWS, `.env`, system paths, etc. |
| (no out-of-scope paths) | | `.\scripts\create-issues.ps1` resolves inside the project |
| **Total** | **0** | Clamped to floor (negative scores round up to 0) |

`0 < THRESHOLDS.allow_below` (which defaults to 25), so the decision is `allow`. The command runs silently. No more clicks for this category.

If the same command pointed at a script outside the project, or stripped the `-DryRun` flag and started touching `~/.ssh/`, the score would climb. You'd see it climb in the audit log even before you saw a prompt, because every signal is recorded whether or not it ended up changing the decision.

## Dashboard bridge (optional)

By default, ask-band decisions fall through to Claude Code's native permission prompt — the dashboard just shows you what happened. If you'd rather approve or deny from the dashboard tab instead of the terminal, flip the bridge on:

```python
# rules.py
DASHBOARD_BRIDGE_ENABLED = True   # default False
DASHBOARD_BRIDGE_TIMEOUT_S = 60   # how long the hook waits for your click
```

With the bridge on **and** the dashboard running, every ask-band decision pops a card at the top of the dashboard with the command, score, signal breakdown, and Approve / Deny buttons. Your click flows back to the waiting hook within ~1 second; Claude Code never shows its native prompt for that decision. If you grant browser-notification permission on first load, you also get a system notification for every new pending decision, so a backgrounded dashboard tab still pages you.

**Behavior when the dashboard isn't running.** The hook checks for a live dashboard PID before publishing to the bridge channel. If nothing's listening, the hook falls through to the native prompt immediately — no 60-second hang. So leaving the flag on across machines with and without the dashboard is safe.

**Timeout.** If you don't click within `DASHBOARD_BRIDGE_TIMEOUT_S`, the hook gives up and falls through to the native prompt. A note is printed to stderr so the audit trail records that the timeout happened. Increase or decrease as you like — the installer wires the hook's kill ceiling to 90 seconds, which leaves room for a 60-second bridge wait plus cold-start headroom.

**Security model.** The bridge channel is two files in `$HOME/.claude/guard/pending/` (or `$env:USERPROFILE\.claude\guard\pending\` on Windows) per pending decision: a request written by the hook, a response written by the dashboard. The directory is chmod 0700 on POSIX; on Windows the default user-profile ACLs already restrict it. This is a single-user design. Any process that can write to that directory can grant permission to a tool call, so don't enable the bridge on a shared host.

### How it works across terminals

The hook is wired into `~/.claude/settings.json` (or `$env:USERPROFILE\.claude\settings.json` on Windows), which Claude Code reads on every session start regardless of which terminal launched it. PowerShell, cmd, Windows Terminal, the VS Code integrated terminal, WSL — all of them route through the same hook script and write to the same `pending/` directory. One dashboard tab shows every active session's pending decisions in one place; the Approve / Deny you click resolves the correct session's hook because each pending record carries a unique UUID.

## Configuration

Everything you'll want to tune lives in `rules.py`. There's no separate config file; rules are Python data structures because they encode logic, not just values, and a Python module is the cleanest place to put both. Edit, save; the next hook invocation picks up the change. No restart, no rebuild.

### Thresholds

```python
THRESHOLDS = {
    "allow_below": 25,
    "deny_at_or_above": 60,
}
```

Lower `allow_below` to make the system more conservative (more things fall through to prompts). Raise `deny_at_or_above` to make hard-blocks rarer (more things become ask-the-human instead of auto-deny). The "ask" band between them is where Claude Code's normal prompt is used, with the full breakdown attached so you know why it didn't auto-allow.

### Denylist

`DENYLIST` is a list of regex patterns that force a deny regardless of any other signal. This is for things that should never happen no matter the context: `rm -rf /`, recursive force-delete of `C:\`, formatting volumes, disabling Defender, etc. Add to this list when you find yourself wanting "I never want this command run, period."

### Allowlist (with veto)

`ALLOWLIST` is a list of regex patterns that force an allow with score 0. But the veto layer (`VETO_PATTERNS`) bypasses the allowlist if the command touches sensitive things (SSH, AWS, `.env`, sudo, system paths, out-of-project paths). So allowlist + veto together give you: "trust this command pattern UNLESS it's pointed at something sensitive."

### Pattern rules

Each entry in `PATTERN_RULES` is `{name, pattern, points, reason}`. The regex is matched against the full command string. If it matches anywhere, the rule fires once and contributes its points. Order doesn't matter; rules don't interact.

To add a rule, append a dict. To raise the cost of an existing rule, edit its `points`. To turn a rule off, comment it out or set points to 0. Negative points are allowed in pattern rules but conventionally that lives in `CONTEXT_REDUCERS`.

### Path rules

`PATH_RULES` are callables that take the parsed `Context` and return points. Use these when the rule needs more than a regex (counting how many out-of-scope paths there are, checking whether all paths fall under `scripts/`, looking for path traversal patterns, etc.).

### Network rules

`NETWORK_RULES` cover everything that talks to the outside world. Per your request, none of these "blindly trust" common tools. Even npm installs from the official registry get scored on whether the package is pinned, whether it's on the compromised-package list, whether `--ignore-scripts` is set. Even GitHub URLs get scored on whether the request pipes into a shell.

The key data structures:

- `DOMAINS["trusted"]`: known dev-infrastructure domains. Hits here are neutral; they don't subtract points but they don't add as much as unknown domains.
- `DOMAINS["watched"]`: URL shorteners and pastebin-style hosts that hide the real destination.
- `COMPROMISED_PACKAGES`: seed list of known-bad package names. This is illustrative, not authoritative. See "Updating from real sources" below.

### Context reducers

`CONTEXT_REDUCERS` are the negative-point side. The `-DryRun` flag, read-only verbs only, output piped to `$null`, all paths under `scripts/`/`tools/`/`tests/`, all network targets on the trusted list — these all subtract points. This is what lets a slightly scary-looking command (nested PowerShell, multiple paths) net out to allow when the context shows it's benign.

## Tuning to your workflow

Start with the defaults. Run Claude Code normally for a session. Then read `audit.jsonl`:

```bash
# Last 10 decisions
tail -n 10 .claude/guard/audit.jsonl | jq

# Everything that scored above 50 (close to deny)
jq 'select(.score > 50)' .claude/guard/audit.jsonl

# Which rules fire most often (good signal for what's noisy)
jq -r '.signals[].name' .claude/guard/audit.jsonl | sort | uniq -c | sort -rn

# Decisions that were "ask" (you got prompted)
jq 'select(.decision == "ask") | {command, score, signals}' .claude/guard/audit.jsonl
```

If you find yourself approving the same kind of command over and over in the "ask" band, that's a candidate for either (a) lowering specific rules' points so the total drops below `allow_below`, or (b) adding a tight allowlist pattern that matches just that command shape. Prefer (a); it preserves the breakdown rather than hiding the command.

If you find a decision auto-allowed when you wish it had asked, look at which rules fired (or didn't) in `audit.jsonl` and add or strengthen the signal.

## Cross-platform notes

The path-scoping logic normalises backslashes to forward slashes before resolving traversal, so `..\..\..\foo` works the same way it would on Windows even when the hook is executed inside WSL or on macOS. Both `C:\Windows\System32` and `/etc/passwd` are matched by their respective system-path rules; the engine doesn't assume one operating system.

The shell detection is heuristic. A command containing `$env:` or `Get-`/`Set-`/`Invoke-` cmdlet style, or referencing `.ps1`, is treated as PowerShell. Otherwise bash. This affects only the read-only verb list used by the context reducer; rule scoring otherwise runs against the raw string.

## Audit log format

`audit.jsonl` is append-only JSON Lines. One decision per line. Schema:

```json
{
  "ts": "2026-05-18T12:34:56.789012+00:00",
  "decision": "allow|ask|deny",
  "score": 0,
  "tool": "Bash",
  "command": "<full command string>",
  "project_dir": "/path/to/project",
  "is_powershell": false,
  "paths": ["./scripts/foo.ps1"],
  "out_of_scope_paths": [],
  "network_targets": [],
  "signals": [
    {"name": "rule_name", "points": 5, "reason": "..."}
  ]
}
```

Rotate or archive whenever you like. Nothing in the engine depends on the log; it's purely for your review.

## Updating compromised packages

The `COMPROMISED_PACKAGES` list in `rules.py` is a seed. For real coverage, mirror against authoritative sources:

- GitHub Advisory Database: https://github.com/advisories (filter by ecosystem)
- OSV.dev: https://osv.dev (machine-readable feed at https://osv-vulnerabilities.storage.googleapis.com)
- Socket.dev: https://socket.dev/npm (commercial but has a free tier)

A future improvement is a sidecar script that pulls these weekly and merges them into `rules.py`. For now, treat the seed list as illustrative and add names from real incidents you encounter or read about.

## Known limitations

1. **Command parsing is regex-based, not a real shell parser.** This means edge cases (heredocs, complex quoting, escaped delimiters, very long commands) may not extract paths or interpreters correctly. The scoring degrades gracefully: failure to parse means failure to find risk signals, which leans toward allow. If you want stricter, lower `allow_below` to make the default ask rather than allow.

2. **No symlink protection.** Path scoping checks lexical containment, not resolved containment. An attacker who can plant a symlink inside your project pointing outside could read past the boundary. The mitigation is the credentials and system-path pattern rules, which fire on the destination name regardless of how it was reached.

3. **No semantic command understanding.** "rm important-file.txt" and "rm tempfile.txt" score the same. The system can't tell what a file means to you; it only knows where the file is and what shape the command is. Use `--dry-run` habits and the `WRITES_OUTSIDE_PROJECT` signal for protection on the destination side, not on the value-of-file side.

4. **Hooks fire per tool call, not per session.** If Claude runs a hundred small commands, the hook fires a hundred times. The engine is fast (no I/O, no network) but rule expansion has a cost. If you find latency, profile `rules.py` and consolidate regexes.

5. **The compromised-package list is small.** As shipped, it's illustrative. See "Updating from real sources" above before trusting it as comprehensive coverage.

## Roadmap (where to take this next)

In rough priority order:

1. **Sidecar updater** that fetches the GHSA + OSV feeds and writes a fresh `COMPROMISED_PACKAGES` block, run on a schedule.
2. **Project-aware allow rules.** Rather than one global rules.py, support a `.claude/guard/project.py` that adds project-specific allowlist patterns (e.g., per-client conventions) without forking the base rules.
3. **VS Code extension** as originally discussed: sidebar showing recent decisions from `audit.jsonl`, one-click "add to allowlist" buttons, a "tighten thresholds" toggle. This is polish on top of the engine, not a replacement.
4. **Decision feedback loop.** Track which "ask" prompts the human approved versus rejected; surface rules whose ask-approval rate is >95% as candidates for moving into the allow band.

## Files in this folder

- `claude-guard.py`: the hook entrypoint. Reads JSON on stdin, writes a `permissionDecision` JSON on stdout, appends to `audit.jsonl`. Also handles `--test` mode for tuning.
- `rules.py`: thresholds, denylist, allowlist, veto patterns, pattern rules, path rules, network rules, context reducers, domain reputation, compromised packages. Edit this to tune.
- `settings.example.json`: the snippet to merge into `.claude/settings.json` to wire the hook in.
- `audit.jsonl`: created on first run. Append-only decision log.
- `README.md`: this file.
