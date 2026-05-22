"""
claude-guard rules.

Edit this file to tune the system. Claude Code re-runs the hook on every
tool call, so changes take effect immediately, no restart needed.

Sections:
  1. Thresholds         - score -> decision boundaries
  2. Hard overrides     - DENYLIST (force deny), ALLOWLIST (force allow)
  3. Pattern rules      - regex-matched scoring rules
  4. Path rules         - logic-based rules that inspect Context paths
  5. Network rules      - per-network-call scoring (packages, domains, etc.)
  6. Context reducers   - negative-point rules (dry-run, read-only, etc.)
  7. Domain reputation  - trusted / watched domain sets
  8. Compromised packages - seed list, update from OSV / Socket / GHSA
"""

import re


# ============================================================================
# 1. THRESHOLDS
# ============================================================================
# How total score maps to decision:
#   score <  allow_below            -> "allow" (auto-approve, silent)
#   score >= deny_at_or_above       -> "deny"  (block with explanation)
#   anything in between             -> "ask"   (Claude Code shows prompt
#                                                with the full breakdown)

THRESHOLDS = {
    "allow_below": 25,
    "deny_at_or_above": 60,
}


# ============================================================================
# 2. HARD OVERRIDES
# ============================================================================

# Force DENY. If any regex matches, score is 100 and the command is blocked.
DENYLIST = [
    # Mass deletion
    r"\brm\s+-[rRf]+\s+/(?:\s|$|\*)",
    r"\brm\s+-[rRf]+\s+--no-preserve-root",
    r"\brm\s+-[rRf]+\s+~(?:/|\s|$)",
    r"Remove-Item\s+.*-Recurse.*-Force.*\b(?:C:\\?\\?|/|HKLM:)",

    # Disk-level destruction
    r"\bformat\s+[a-zA-Z]:",
    r"\bFormat-Volume\b",
    r"\bmkfs\.",
    r"\bdd\s+if=.*of=/dev/(?:sd|nvme|hd)",

    # Fork bomb
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",

    # Audit / security tampering
    r"\bcipher\s+/w:",
    r"\bwevtutil\s+cl\b",
    r"Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true",
    r"\bsc\s+(?:stop|delete)\s+(?:WinDefend|SecurityHealthService|Sense)",
    r"netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off",

    # System config destruction
    r">\s*/etc/(?:passwd|shadow|sudoers|hosts)\b",
    r"chmod\s+-R\s+777\s+/",
]

# VETO patterns: if any match, the ALLOWLIST is bypassed for this command.
# This is the safety belt: a plain "cat" command is normally fine, but
# "cat ~/.ssh/id_rsa" should be scored, not silently allowed. Anything here
# forces the full rule pipeline to run.
VETO_PATTERNS = [
    r"\.ssh[/\\]",                                          # SSH keys / config
    r"\.aws[/\\]",                                          # AWS credentials
    r"\b[\w.\-]*\.env(?:\.\w+)?\b",                         # any *.env file
    r"(?:^|[\s/\\])\.(?:npmrc|pypirc|netrc)\b",             # other dotfile secrets
    r"\.git-credentials\b",                                 # stored git creds
    r"\bHKLM:?\\",                                          # registry root
    r"C:\\Windows\\",                                       # Windows system
    r"/etc/(?:passwd|shadow|sudoers|hosts)\b",              # *nix sensitive
    r"(?:^|\s)sudo\s",                                      # elevation
    r"-Verb\s+RunAs\b",                                     # PS elevation
    r"--force\b|-Force\b",                                  # destructive flag
    r"--no-preserve-root\b",                                # rm safety bypass
]

# Force ALLOW. If any regex matches AND no VETO_PATTERN matches, score is 0
# and the command runs silently. Keep these tight.
ALLOWLIST = [
    # Read-only git
    r"^\s*git\s+(?:status|log|diff|branch|show|fetch|remote\s+-v|"
    r"config\s+--get|rev-parse|describe|tag\s*$|tag\s+-l|stash\s+list)\b",

    # Filesystem read-only POSIX
    r"^\s*(?:ls|pwd|whoami|hostname|date|uptime|uname)\s*(?:-\w+\s*)*$",
    r"^\s*(?:cat|less|head|tail|file|wc|stat)\s+[^\s|&;()<>]+\s*$",

    # PowerShell read-only Get-* (no pipe to dangerous cmdlets)
    r"^\s*Get-(?:ChildItem|Content|Location|Date|Process|Service|"
    r"Command|Module|Help|Item)\s+[^|;]*$",

    # Version checks
    r"^\s*(?:node|npm|python|pip|git|gh|claude)\s+(?:--version|-v|--help|-h)\s*$",

    # Echo / no-ops
    r"^\s*echo\s+",
    r"^\s*:\s*$",
]


# ============================================================================
# 3. PATTERN RULES (regex)
# ============================================================================
# Each rule fires at most once per command.

PATTERN_RULES = [
    # ---- Code injection / supply chain ----------------------------------
    {
        "name": "pipe_to_shell",
        "pattern": r"\|\s*(?:bash|sh|zsh|pwsh|powershell|iex|Invoke-Expression)\b",
        "points": 50,
        "reason": "Command piped directly into a shell interpreter "
                  "(classic 'curl | bash' supply-chain attack pattern)",
    },
    {
        "name": "dynamic_invoke_expression",
        "pattern": r"\b(?:Invoke-Expression|iex)\s+[\(\$\"'`]",
        "points": 30,
        "reason": "Invoke-Expression / iex evaluates a string as code "
                  "(injection vector if the string is built dynamically)",
    },
    {
        "name": "eval_dynamic",
        "pattern": r"\beval\s+[`\$\"']",
        "points": 30,
        "reason": "eval against dynamic input",
    },
    {
        "name": "download_then_execute",
        "pattern": r"(?:curl|wget|iwr|Invoke-WebRequest)[^|;&]*"
                   r"(?:&&|;)\s*(?:\./|bash|sh|pwsh|powershell|python|node)\b",
        "points": 40,
        "reason": "Downloads a file then executes it in the same command",
    },

    # ---- Credentials and secrets ---------------------------------------
    {
        "name": "ssh_keys",
        "pattern": r"\.ssh[/\\](?:id_|known_hosts|authorized_keys|config\b)",
        "points": 50,
        "reason": "Accesses SSH credential files",
    },
    {
        "name": "aws_credentials",
        "pattern": r"\.aws[/\\](?:credentials|config)\b",
        "points": 50,
        "reason": "Accesses AWS credentials",
    },
    {
        "name": "env_secrets_file",
        "pattern": r"\b[\w.\-]*\.env(?:\.\w+)?\b|"
                   r"(?:^|[\s/\\])\.(?:npmrc|pypirc|netrc|docker[/\\]config\.json)\b",
        "points": 30,
        "reason": "Reads or writes an environment / secrets / credentials file",
    },
    {
        "name": "git_credentials",
        "pattern": r"\.git-credentials|\bgit\s+config\s+credential\.helper",
        "points": 30,
        "reason": "Touches stored Git credentials",
    },
    {
        "name": "keychain_access",
        "pattern": r"\b(?:security\s+find-generic-password|"
                   r"Get-Credential|cmdkey\s+/list)\b",
        "points": 30,
        "reason": "Reads from a credential store / keychain",
    },

    # ---- System modification -------------------------------------------
    {
        "name": "hklm_registry_write",
        "pattern": r"\b(?:Set-ItemProperty|New-ItemProperty|reg\s+add)\s+[^|;]*HKLM",
        "points": 30,
        "reason": "Writes to HKEY_LOCAL_MACHINE (system-wide persistence)",
    },
    {
        "name": "hkcu_registry_write",
        "pattern": r"\b(?:Set-ItemProperty|New-ItemProperty|reg\s+add)\s+[^|;]*HKCU",
        "points": 10,
        "reason": "Writes to HKEY_CURRENT_USER (user-scope persistence)",
    },
    {
        "name": "scheduled_task",
        "pattern": r"\b(?:schtasks|Register-ScheduledTask|"
                   r"crontab\s+-e|at\s+\d+:\d+)\b",
        "points": 25,
        "reason": "Creates a scheduled task / cron job (persistence vector)",
    },
    {
        "name": "firewall_modify",
        "pattern": r"\bnetsh\s+advfirewall|\bNew-NetFirewallRule\b|\bufw\s+(?:allow|deny)",
        "points": 25,
        "reason": "Modifies host firewall rules",
    },
    {
        "name": "service_install",
        "pattern": r"\b(?:sc\s+create|New-Service|systemctl\s+enable|"
                   r"launchctl\s+load)\b",
        "points": 25,
        "reason": "Installs / enables a system service (persistence vector)",
    },
    {
        "name": "elevation",
        "pattern": r"(?:^|\s)(?:sudo\b|-Verb\s+RunAs\b|runas\s+/user:)",
        "points": 15,
        "reason": "Requests elevated privileges",
    },
    {
        "name": "permanent_path_change",
        "pattern": r"\bsetx\s+PATH\b|\[Environment\]::SetEnvironmentVariable\s*\(\s*['\"]Path",
        "points": 20,
        "reason": "Permanently modifies system PATH",
    },

    # ---- Destructive git -----------------------------------------------
    {
        "name": "git_force_push_protected",
        "pattern": r"\bgit\s+push\s+[^|;]*--force(?:-with-lease)?\s+\S+\s+"
                   r"(?:main|master|production|prod|release|develop)\b",
        "points": 50,
        "reason": "Force-push to a protected branch (rewrites shared history)",
    },
    {
        "name": "git_force_push",
        "pattern": r"\bgit\s+push\s+[^|;]*--force(?:-with-lease)?\b",
        "points": 10,
        "reason": "Force-push (lower risk on a feature branch, still rewrites history)",
    },
    {
        "name": "git_reset_hard",
        "pattern": r"\bgit\s+reset\s+--hard\b",
        "points": 10,
        "reason": "Hard reset discards uncommitted changes irreversibly",
    },
    {
        "name": "git_clean_force",
        "pattern": r"\bgit\s+clean\s+-[fdx]+",
        "points": 15,
        "reason": "git clean -fdx wipes untracked and ignored files",
    },
    {
        "name": "git_branch_delete",
        "pattern": r"\bgit\s+(?:branch\s+-D|push\s+\S+\s+--delete)\b",
        "points": 10,
        "reason": "Force-deletes a branch",
    },

    # ---- Process / shell -----------------------------------------------
    {
        "name": "nested_shell",
        "pattern": r"\b(?:pwsh(?:\.exe)?|powershell(?:\.exe)?|bash|sh|zsh|cmd(?:\.exe)?)\s+[-/]",
        "points": 5,
        "reason": "Spawns a nested shell process (often benign, slight signal)",
    },
    {
        "name": "encoded_command",
        "pattern": r"\b-Enc(?:odedCommand)?\b|\bbase64\s+-d\b|\bFromBase64String\b",
        "points": 35,
        "reason": "Uses encoded/base64 command (common malware obfuscation)",
    },
    {
        "name": "background_process",
        "pattern": r"\bStart-(?:Job|Process)\b|nohup\b|&\s*$",
        "points": 5,
        "reason": "Backgrounds a process",
    },
    {
        "name": "exec_replace",
        "pattern": r"\bexec\s+\S",
        "points": 10,
        "reason": "Replaces current shell with another process",
    },
]


# ============================================================================
# 4. PATH RULES (callable)
# ============================================================================

_WRITE_VERB_RE = re.compile(
    r"\b(?:rm|mv|cp|Remove-Item|Move-Item|Copy-Item|"
    r"Set-Content|Add-Content|Out-File|New-Item|tee|touch)\b|"
    r">>?\s*[^&|<\s]",
    re.I,
)
_READ_VERB_RE = re.compile(
    r"\b(?:cat|less|head|tail|Get-Content|Select-String|grep|rg|type|"
    r"strings|hexdump|xxd)\b",
    re.I,
)
_SYSTEM_PATHS_RES = [re.compile(p, re.I) for p in (
    r"C:\\Windows\\System32",
    r"C:\\Program Files",
    r"C:\\ProgramData",
    r"/etc/",
    r"/boot/",
    r"/sys/",
    r"/proc/",
    r"/var/log/",
    r"/usr/(?:local/)?(?:bin|sbin)/",
)]
_PATH_TRAVERSAL_RE = re.compile(r"(?:\.\.[/\\]){2,}")
_DOTFILE_WRITE_RE = re.compile(r"\b(?:Set-Content|Out-File|Add-Content|>>?)\b")
_DOTFILE_PATH_RE = re.compile(r"[/\\]\.[^/\\]")


def _writes_outside_project(ctx):
    if not ctx.out_of_scope_paths:
        return 0
    if _WRITE_VERB_RE.search(ctx.command):
        return 25 * min(len(ctx.out_of_scope_paths), 2)
    return 0


def _reads_outside_project(ctx):
    if not ctx.out_of_scope_paths:
        return 0
    if _READ_VERB_RE.search(ctx.command):
        return 5 * min(len(ctx.out_of_scope_paths), 3)
    return 0


def _touches_system_paths(ctx):
    for pat in _SYSTEM_PATHS_RES:
        if pat.search(ctx.command):
            return 30
    return 0


def _path_traversal(ctx):
    if _PATH_TRAVERSAL_RE.search(ctx.command):
        return 15
    return 0


def _writes_to_dotfile_outside_known(ctx):
    if not ctx.out_of_scope_paths:
        return 0
    if not _DOTFILE_WRITE_RE.search(ctx.command):
        return 0
    for p in ctx.out_of_scope_paths:
        if _DOTFILE_PATH_RE.search(str(p)):
            return 15
    return 0


PATH_RULES = [
    {"name": "writes_outside_project", "fn": _writes_outside_project,
     "reason": "Writes to a path outside the project directory"},
    {"name": "reads_outside_project", "fn": _reads_outside_project,
     "reason": "Reads from paths outside the project directory"},
    {"name": "touches_system_paths", "fn": _touches_system_paths,
     "reason": "Touches a system directory (Windows or *nix)"},
    {"name": "path_traversal", "fn": _path_traversal,
     "reason": "Multiple ../ traversal (could escape intended scope)"},
    {"name": "writes_dotfile_outside", "fn": _writes_to_dotfile_outside_known,
     "reason": "Writes to a dotfile / hidden config outside the project"},
]


# ============================================================================
# 5. NETWORK RULES
# ============================================================================

# Replace blind trust with a multi-signal evaluation per network operation.
# Even a "trusted" registry can serve a compromised package; even a known
# domain can host a malicious script. Domains are one signal, not a verdict.

DOMAINS = {
    # Well-known dev infrastructure. Hits here are neutral (small risk subtracted
    # in context reducers), not free passes.
    "trusted": {
        "github.com", "raw.githubusercontent.com", "api.github.com",
        "objects.githubusercontent.com", "codeload.github.com",
        "registry.npmjs.org", "registry.npmjs.com", "www.npmjs.com",
        "pypi.org", "files.pythonhosted.org",
        "crates.io", "static.crates.io", "index.crates.io",
        "rubygems.org",
        "docs.anthropic.com", "docs.claude.com", "claude.ai", "code.claude.com",
        "archive.ubuntu.com", "security.ubuntu.com",
        "packages.cloud.google.com", "deb.nodesource.com",
        "get.docker.com", "download.docker.com",
        "registry.yarnpkg.com", "yarnpkg.com",
    },
    # Domains we explicitly flag as higher-risk.
    "watched": {
        # URL shorteners (hide the real destination)
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
        "rebrand.ly", "buff.ly", "cutt.ly",
        # Pastebin / file-drop (often used for malware dropper or exfil)
        "pastebin.com", "paste.ee", "hastebin.com", "transfer.sh",
        "anonfiles.com", "send.exploit.in",
    },
}

# Seed list of known-compromised package names.
# This is illustrative, not exhaustive. Update from authoritative sources:
#   https://github.com/advisories
#   https://osv.dev
#   https://socket.dev
COMPROMISED_PACKAGES = {
    "npm": {
        "event-stream",       # 2018, bitcoin wallet drainer
        "flatmap-stream",     # 2018, paired with event-stream
        "ua-parser-js",       # 2021, specific versions
        "coa", "colors",      # 2022, protestware DoS
        "node-ipc",           # 2022, protestware file-wipe
        "rc",                 # impersonation incidents
        "@scope/various-typo", # placeholder for typosquats you want to block
    },
    "pypi": {
        "ctx",                # 2022, credential exfil
        "phpass",             # typosquat for passlib
        "colourama",          # typosquat for colorama
        "djanga",             # typosquat for django
    },
}


_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_NETWORK_VERB_RE = re.compile(
    r"\b(?:curl|wget|iwr|Invoke-WebRequest|fetch)\b", re.I,
)
_NPM_INSTALL_RE = re.compile(r"\bnpm\s+(?:install|i|add)\b(.*)", re.I | re.S)
_PIP_INSTALL_RE = re.compile(r"\bpip\d?\s+install\b(.*)", re.I | re.S)
_YARN_ADD_RE    = re.compile(r"\byarn\s+add\b(.*)",  re.I | re.S)
_NPM_LIFECYCLE_RE = re.compile(r"\bnpm\s+(?:install|i|ci)\b", re.I)
_NPM_IGNORE_SCRIPTS_RE = re.compile(r"--ignore-scripts\b", re.I)
_GIT_PUSH_URL_RE = re.compile(r"\bgit\s+push\s+(?:https?://|git@)", re.I)
_PACKAGE_FROM_URL_RES = [
    re.compile(p, re.I) for p in (
        r"\bnpm\s+(?:install|i|add)\s+(?:https?://|git\+|file:|\.\/|\.\\)",
        r"\byarn\s+add\s+(?:https?://|git\+|file:)",
        r"\bpip\s+install\s+(?:https?://|git\+)",
        r"\bpip\s+install\s+--index-url\s",
        r"\bpip\s+install\s+--extra-index-url\s",
    )
]
_PINNED_OPS = ("==", "~=", ">=", "<=", "===")
_PIP_FLAG_TAKES_ARG = {
    "-r", "--requirement", "-c", "--constraint",
    "--index-url", "-i", "--extra-index-url",
    "--find-links", "-f", "--target", "-t",
    "--python-version", "--platform", "--abi", "--implementation",
    "--prefix", "--src",
}


def _is_ip(s):
    return bool(_IP_RE.match(s))


def _network_fetch(ctx):
    if not ctx.network_targets:
        return 0
    if not _NETWORK_VERB_RE.search(ctx.command):
        return 0
    delta = 0
    for target in ctx.network_targets:
        domain = target.split("/")[0]
        if domain in DOMAINS["watched"]:
            delta += 30
        elif _is_ip(domain):
            delta += 25
        elif domain in DOMAINS["trusted"]:
            delta += 0
        else:
            delta += 15
    return delta


def _cut_at_command_break(rest: str) -> str:
    """Trim a tail-of-command string at the first |, ;, && or || boundary
    so we don't read tokens from the next command."""
    cuts = []
    for stop in ("|", ";", "&&", "||", "&"):
        i = rest.find(stop)
        if i >= 0:
            cuts.append(i)
    if cuts:
        rest = rest[:min(cuts)]
    return rest


def _normalize_pypi(name: str) -> str:
    """PEP 503: collapse runs of - _ . into - and lowercase."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _iter_npm_packages(command: str):
    """Yield (raw_token, normalized_pkg_name) for each non-flag arg after
    `npm install / i / add`. Skips URL/file specs."""
    m = _NPM_INSTALL_RE.search(command)
    if not m:
        return
    rest = _cut_at_command_break(m.group(1))
    skip_next = False
    for tok in rest.split():
        if skip_next:
            skip_next = False
            continue
        if tok.startswith("-"):
            # Flags like --save, -D; assume single-token unless we know better
            continue
        if "://" in tok or tok.startswith(("git+", "file:", "./", ".\\", "~/")):
            continue
        # Scoped: @scope/name[@version] -> "@scope/name"
        if tok.startswith("@"):
            body = tok[1:].split("@", 1)[0]
            pkg = "@" + body
        else:
            pkg = tok.split("@", 1)[0]
        if not pkg:
            continue
        yield tok, pkg.lower()


def _iter_pip_packages(command: str):
    """Yield (raw_token, normalized_pkg_name) for pip install args. Handles
    -r/--requirement, version pins, [extras]."""
    m = _PIP_INSTALL_RE.search(command)
    if not m:
        return
    rest = _cut_at_command_break(m.group(1))
    skip_next = False
    for tok in rest.split():
        if skip_next:
            skip_next = False
            continue
        if tok in _PIP_FLAG_TAKES_ARG:
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        if "://" in tok or tok.startswith(("git+", "./", ".\\", "file:")):
            continue
        # Strip [extras] and version specifier
        pkg = re.split(r"[\[=<>!~;@]", tok, 1)[0].strip()
        if not pkg:
            continue
        yield tok, _normalize_pypi(pkg)


def _unpinned_npm_install(ctx):
    saw_any = False
    for tok, _name in _iter_npm_packages(ctx.command):
        saw_any = True
        body = tok.lstrip("@")
        if "@" in body:
            return 0  # at least one pin present
    return 15 if saw_any else 0


def _unpinned_pip_install(ctx):
    saw_any = False
    for tok, _name in _iter_pip_packages(ctx.command):
        saw_any = True
        if any(op in tok for op in _PINNED_OPS):
            return 0  # at least one pin present
    return 15 if saw_any else 0


def _package_from_url(ctx):
    for pat in _PACKAGE_FROM_URL_RES:
        if pat.search(ctx.command):
            return 30
    return 0


def _compromised_package(ctx):
    """O(1) set lookup. With 200k+ entries in the auto feed, per-package
    regex was making the hook unusable."""
    npm_set = COMPROMISED_PACKAGES["npm"]
    if npm_set:
        for _tok, name in _iter_npm_packages(ctx.command):
            if name in npm_set:
                return 60
    pypi_set = COMPROMISED_PACKAGES["pypi"]
    if pypi_set:
        for _tok, name in _iter_pip_packages(ctx.command):
            if name in pypi_set:
                return 60
    return 0


def _git_push_explicit_url(ctx):
    if _GIT_PUSH_URL_RE.search(ctx.command):
        return 20
    return 0


def _npm_lifecycle_scripts(ctx):
    if _NPM_LIFECYCLE_RE.search(ctx.command) and \
       not _NPM_IGNORE_SCRIPTS_RE.search(ctx.command):
        return 5
    return 0


NETWORK_RULES = [
    {"name": "network_fetch", "fn": _network_fetch,
     "reason": "HTTP fetch evaluated against domain reputation"},
    {"name": "unpinned_npm", "fn": _unpinned_npm_install,
     "reason": "npm install without a version pin (supply-chain risk)"},
    {"name": "unpinned_pip", "fn": _unpinned_pip_install,
     "reason": "pip install without a version pin (supply-chain risk)"},
    {"name": "package_from_url", "fn": _package_from_url,
     "reason": "Package installed from URL / local file / alternate index "
               "(bypasses primary registry)"},
    {"name": "compromised_package", "fn": _compromised_package,
     "reason": "Package on the known-compromised list"},
    {"name": "git_push_url", "fn": _git_push_explicit_url,
     "reason": "git push to an explicit URL instead of a named remote"},
    {"name": "npm_lifecycle_scripts", "fn": _npm_lifecycle_scripts,
     "reason": "npm install runs postinstall scripts from dependencies; "
               "consider --ignore-scripts"},
]


# ============================================================================
# 6. CONTEXT REDUCERS (negative points)
# ============================================================================

_SEGMENT_SPLIT_RE = re.compile(r"[|;&]+")
_PS_VAR_ASSIGN_RE = re.compile(r"^\$\w+\s*=")
_OUTPUT_NULL_RE = re.compile(r">\s*(?:/dev/null|\$null)|\bOut-Null\b")
_SAFE_SUBDIR_RE = re.compile(
    r"[/\\](?:scripts|tools|tests|docs|\.claude)[/\\]"
)
_READ_ONLY_VERBS = {
    "ls", "pwd", "cat", "less", "head", "tail", "grep", "rg", "find",
    "file", "stat", "wc", "echo", "type", "where", "which",
    "Get-ChildItem", "Get-Content", "Get-Location", "Get-Date",
    "Get-Item", "Select-String", "Select-Object", "Where-Object",
    "Test-Path", "Format-List", "Format-Table", "Out-Host",
    "ForEach-Object",
}


def _dry_run(ctx):
    return -15 if ctx.has_dry_run else 0


def _read_only_verbs(ctx):
    for seg in _SEGMENT_SPLIT_RE.split(ctx.command):
        seg = seg.strip()
        if not seg:
            continue
        if _PS_VAR_ASSIGN_RE.match(seg):
            continue
        tokens = seg.split()
        if not tokens:
            continue
        if tokens[0] not in _READ_ONLY_VERBS:
            return 0
    return -10


def _output_to_null(ctx):
    if _OUTPUT_NULL_RE.search(ctx.command):
        return -3
    return 0


def _all_paths_in_safe_subdirs(ctx):
    if not ctx.paths or ctx.out_of_scope_paths:
        return 0
    if all(_SAFE_SUBDIR_RE.search(str(p)) for p in ctx.paths):
        return -5
    return 0


def _trusted_domain_only(ctx):
    if not ctx.network_targets:
        return 0
    for target in ctx.network_targets:
        domain = target.split("/")[0]
        if domain not in DOMAINS["trusted"]:
            return 0
    # All network targets are on the trusted list
    return -5


CONTEXT_REDUCERS = [
    {"name": "dry_run_flag", "fn": _dry_run,
     "reason": "Command uses a dry-run / what-if / simulate flag"},
    {"name": "read_only_only", "fn": _read_only_verbs,
     "reason": "Command uses only read-only / diagnostic verbs"},
    {"name": "output_discarded", "fn": _output_to_null,
     "reason": "Output discarded to /dev/null or $null"},
    {"name": "safe_subdirs_only", "fn": _all_paths_in_safe_subdirs,
     "reason": "All paths are under scripts/ tools/ tests/ docs/ or .claude/"},
    {"name": "trusted_domains_only", "fn": _trusted_domain_only,
     "reason": "All network targets are on the trusted-domain list"},
]


# ============================================================================
# 9. FAIL MODE (V2.5)
# ============================================================================
# "closed": on any unexpected exception, return permissionDecision="ask"
#           with an explanatory message (safe default; user gets prompted).
# "open":   on exception, exit silently and let Claude Code use its own
#           permission system (the V1 behavior).

FAIL_MODE = "closed"


# ============================================================================
# 10. AUTO THREAT FEED MERGE (V2.1)
# ============================================================================
# Union compromised_packages_auto.py (written by update_threat_feed.py) into
# COMPROMISED_PACKAGES. Curated entries in this file always remain in effect.

# Normalize the seed list so lookups are case-insensitive and PEP 503-aware
# for PyPI. npm package names are lowercase by spec but be defensive.
COMPROMISED_PACKAGES["npm"] = {str(n).lower() for n in COMPROMISED_PACKAGES["npm"]}
COMPROMISED_PACKAGES["pypi"] = {
    re.sub(r"[-_.]+", "-", str(n)).lower() for n in COMPROMISED_PACKAGES["pypi"]
}

try:
    from compromised_packages_auto import COMPROMISED_PACKAGES_AUTO as _AUTO
    _npm_auto = _AUTO.get("npm")
    if isinstance(_npm_auto, (set, frozenset, list, tuple)):
        COMPROMISED_PACKAGES["npm"] |= {str(n).lower() for n in _npm_auto}
    _pypi_auto = _AUTO.get("pypi")
    if isinstance(_pypi_auto, (set, frozenset, list, tuple)):
        COMPROMISED_PACKAGES["pypi"] |= {
            re.sub(r"[-_.]+", "-", str(n)).lower() for n in _pypi_auto
        }
    del _AUTO, _npm_auto, _pypi_auto
except ImportError:
    pass
except Exception:
    # Auto file may be malformed (partial write, manual edit). Never let
    # that break the hook. Curated seed continues to apply.
    pass


# ============================================================================
# 11. USER RULES MERGE (V2.3)
# ============================================================================
# rules_user.py is written by tune.py (review mode). Its allowlist entries
# extend the base ALLOWLIST. Pattern, path, network, and reducer rules are
# also merged if present. Keeps personal customisations out of base rules.py
# so updates to claude-guard don't clobber tuning.

try:
    import rules_user as _user
    for _name, _target in (
        ("ALLOWLIST", ALLOWLIST),
        ("DENYLIST", DENYLIST),
        ("VETO_PATTERNS", VETO_PATTERNS),
        ("PATTERN_RULES", PATTERN_RULES),
        ("PATH_RULES", PATH_RULES),
        ("NETWORK_RULES", NETWORK_RULES),
        ("CONTEXT_REDUCERS", CONTEXT_REDUCERS),
    ):
        _extra = getattr(_user, _name, None)
        if isinstance(_extra, list):
            _target.extend(_extra)
    del _user, _name, _target, _extra
except ImportError:
    pass
except Exception:
    pass


# ============================================================================
# 12. PER-TOOL RULES (V3.0)
# ============================================================================
# These data structures parallel the Bash rules above but apply to other
# Claude Code tools. The dispatcher in claude-guard.py routes each tool to the
# right rule set.

# File-path denylist: paths that should NEVER be written/edited. Match against
# the resolved absolute path string. Case-insensitive.
FILE_PATH_DENYLIST = [
    # POSIX system paths
    r"^/etc/(?:passwd|shadow|sudoers|hosts|fstab|ssh/sshd_config)\b",
    r"^/(?:bin|sbin|usr/bin|usr/sbin|boot|System)/",
    r"^/Library/LaunchDaemons/",
    r"^~?/Library/LaunchAgents/",

    # Windows system paths (forward-slash normalized)
    r"^[A-Za-z]:/Windows/(?:System32|SysWOW64|WinSxS)/",
    r"^[A-Za-z]:/Program Files(?: \(x86\))?/Windows ",
    r"^[A-Za-z]:/Windows/System32/drivers/etc/hosts",
]

# Sensitive file patterns: writing/editing these is high-risk regardless of
# where they live. Match against the file's basename or trailing path segment.
FILE_PATH_SENSITIVE_PATTERNS = [
    # Credentials and keys
    {"name": "ssh_key",          "pattern": r"\.ssh[/\\](?:id_[a-z0-9]+|authorized_keys|known_hosts|config)$",
     "points": 70, "reason": "Modifying SSH key or config"},
    {"name": "aws_creds",        "pattern": r"\.aws[/\\](?:credentials|config)$",
     "points": 70, "reason": "Modifying AWS credentials"},
    {"name": "gcloud_creds",     "pattern": r"\.config[/\\]gcloud[/\\]",
     "points": 60, "reason": "Modifying gcloud auth state"},
    {"name": "dotenv",           "pattern": r"(?:^|[/\\])\.env(?:\.[\w-]+)?$",
     "points": 30, "reason": "Modifying .env file (likely contains secrets)"},
    {"name": "private_key_file", "pattern": r"\.(?:pem|key|p12|pfx|jks)$",
     "points": 60, "reason": "Modifying a private-key file"},
    {"name": "git_credentials",  "pattern": r"\.git-credentials$|\.netrc$|\.npmrc$|\.pypirc$",
     "points": 40, "reason": "Modifying stored credential file"},

    # CI/CD and dependency manifests — medium signal (allowed in-project, but
    # called out so combinations push toward ask).
    {"name": "ci_workflow",      "pattern": r"(?:^|[/\\])\.github[/\\]workflows[/\\][^/\\]+\.ya?ml$",
     "points": 10, "reason": "Modifying GitHub Actions workflow"},
    {"name": "ci_other",         "pattern": r"(?:^|[/\\])\.(?:gitlab-ci|circleci|drone|travis)\.ya?ml$",
     "points": 10, "reason": "Modifying CI configuration"},
    {"name": "dep_manifest",     "pattern": r"(?:^|[/\\])(?:package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|requirements\.txt|Pipfile|poetry\.lock|Cargo\.toml|Cargo\.lock|go\.mod|go\.sum)$",
     "points": 5,  "reason": "Modifying a dependency manifest"},

    # Shell profile rewrites — visible to every future shell.
    {"name": "shell_profile",    "pattern": r"(?:^|[/\\])\.(?:bashrc|zshrc|bash_profile|zprofile|profile)$|[/\\]PowerShell[/\\]Microsoft\.PowerShell_profile\.ps1$",
     "points": 50, "reason": "Modifying shell startup profile"},
]

# MCP servers whose tool calls should be auto-allowed regardless of score.
# These are first-party / well-known integrations whose calls are otherwise
# noisy in the ask-band. The decision is allow with score 0 and a single
# `trusted_mcp_server` signal recorded in the audit log, so the user can see
# why the call skipped scoring. To revoke trust for one, remove its slug.
# The check runs after DENYLIST so a compromised trusted server still can't
# bypass hardcoded blocks.
TRUSTED_MCP_SERVERS = {
    "playwright",
    "figma",
    "canva",
    "notion",
    "asana",
    "intercom",
    "hubspot",
    "atlassian",
    "box",
    "linear",
    "google-calendar",
    "google-cloud-bigquery",
    "gmail",
    "monday-com",
    "ide",
    # Add more as Anthropic ships official integrations.
    #
    # Matching: the MCP tool name is `mcp__<server>__<action>`; the server
    # segment is lowercased, has any leading `claude-ai-` stripped, and `_`
    # converted to `-`, then the result is checked against this set. So
    # `mcp__claude_ai_Figma__get_design_context` looks up "figma", and
    # `mcp__playwright__browser_click` looks up "playwright".
}


# Read-only / safe MCP tool name patterns. Matched against the full tool_name
# (e.g. "mcp__claude_ai_Linear__authenticate"). Server names can contain single
# underscores, so the server segment is matched non-greedily up to `__`.
# Anything matching auto-allows.
MCP_READONLY_PATTERNS = [
    r"^mcp__.+?__get_",
    r"^mcp__.+?__list_",
    r"^mcp__.+?__search_",
    r"^mcp__.+?__read_",
    r"^mcp__.+?__whoami$",
    r"^mcp__.+?__authenticate$",
    r"^mcp__.+?__complete_authentication$",
    # Playwright observation-only operations
    r"^mcp__playwright__browser_(?:snapshot|take_screenshot|console_messages|network_requests?|wait_for|tabs)$",
    # Figma read operations
    r"^mcp__claude_ai_Figma__(?:get_|search_|use_figma$|whoami$)",
    # IDE diagnostics
    r"^mcp__ide__getDiagnostics$",
]

# MCP tool name patterns considered higher-risk: writes data to an external
# system, sends a message, uploads, executes code. These force ask.
MCP_HIGH_RISK_PATTERNS = [
    r"^mcp__.+?__(?:send_|post_|delete_|remove_|upload_|create_|update_)",
    r"^mcp__playwright__browser_(?:click|drag|drop|type|press_key|fill_form|select_option|file_upload|navigate(?:_back)?|evaluate|run_code_unsafe|handle_dialog|hover|resize|close)$",
    r"^mcp__ide__executeCode$",
    r"^mcp__claude_ai_Figma__(?:create_new_file|upload_assets|use_figma$|send_code_connect_mappings|add_code_connect_map)$",
]

# Domains we proactively block for WebFetch (in addition to anything caught by
# the watched list). Empty by default — populate from incident data.
DOMAINS["denied"] = set()


# ============================================================================
# 13. PRE-COMPILED PATTERNS (V2.5)
# ============================================================================
# Module-level compiled regex for hot paths. Python's re module caches up to
# 512 compiled patterns automatically, but explicit compilation makes the
# behaviour deterministic and shaves a bit of overhead per call.

DENYLIST_COMPILED = [re.compile(p, re.I) for p in DENYLIST]
ALLOWLIST_COMPILED = [re.compile(p, re.I) for p in ALLOWLIST]
VETO_PATTERNS_COMPILED = [re.compile(p, re.I) for p in VETO_PATTERNS]

FILE_PATH_DENYLIST_COMPILED = [re.compile(p, re.I) for p in FILE_PATH_DENYLIST]
MCP_READONLY_COMPILED = [re.compile(p, re.I) for p in MCP_READONLY_PATTERNS]
MCP_HIGH_RISK_COMPILED = [re.compile(p, re.I) for p in MCP_HIGH_RISK_PATTERNS]

for _r in FILE_PATH_SENSITIVE_PATTERNS:
    if "pattern" in _r and "compiled" not in _r:
        try:
            _r["compiled"] = re.compile(_r["pattern"], re.I)
        except re.error:
            _r["compiled"] = None
try:
    del _r
except NameError:
    pass

for _r in PATTERN_RULES:
    if "pattern" in _r and "compiled" not in _r:
        try:
            _r["compiled"] = re.compile(_r["pattern"], re.I)
        except re.error:
            _r["compiled"] = None
try:
    del _r
except NameError:
    pass
